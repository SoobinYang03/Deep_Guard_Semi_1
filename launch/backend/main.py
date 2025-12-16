import hashlib
import uuid
import re
import requests
import urllib3
import os
import tempfile
import json
import pandas as pd
from datetime import datetime
from pymongo import MongoClient
from fastapi import FastAPI, HTTPException, UploadFile, File, Form
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from elasticsearch import Elasticsearch, helpers
from app.notifications.email import send_leak_alert  # 이메일 알림
from typing import Optional
from bson import ObjectId
import deepguard_analyzer as dga


# ---------------------------------------------------------
# [NEW] 크롤러 모듈 임포트 (추가된 부분)
# ---------------------------------------------------------
try:
    from deepguard_crawl_b2b import main_controller, project_keywords
except ImportError:
    print("⚠️ 경고: 'deepguard_crawl_b2b' 모듈을 찾을 수 없습니다.")
    print("⚠️ 임시 테스트용 함수로 대체합니다.")


    async def main_controller(target):
        return {
            "id": str(uuid.uuid4()),
            "target_email": target,
            "status": "Test Mode (Crawler Not Found)",
            "leaked_date": str(datetime.now()),
            "source": "Test Source"
        }

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "http://127.0.0.1:3000"
    ],  # React 개발 서버
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

es_url = os.getenv("elasticsearch_url", "http://elasticsearch:9200")
es = Elasticsearch(
    es_url,
    verify_certs=False
)

# MongoDB 연결
mongo_url = os.getenv("mongodb_url", "mongodb://admin:admin123@mongodb:27017/")
mongo_client = MongoClient(mongo_url)
db = mongo_client["leak_database"]
# 크롤러 전용 컬렉션 추가 (호환성 확보)
mongo_collection = db["leaked_data"]


# ObjectId를 문자열로 변환하는 헬퍼 함수
def serialize_doc(doc):
    if doc and '_id' in doc:
        doc['_id'] = str(doc['_id'])
    if doc and 'source_id' in doc:
        doc['source_id'] = str(doc['source_id'])
    if doc and 'leak_id' in doc:
        doc['leak_id'] = str(doc['leak_id'])
    return doc


def load_file_to_dataframe(file_path, content_type):
    """파일을 DataFrame으로 변환"""
    _, ext = os.path.splitext(file_path)
    ext = ext.lower()

    if ext == '.csv' or content_type == 'text/csv':
        df = pd.read_csv(file_path)
    elif ext == '.tsv' or content_type == 'text/tab-separated-values':
        df = pd.read_csv(file_path, sep='\t')
    elif ext == '.json' or content_type == 'application/json':
        df = pd.read_json(file_path)
    elif ext == '.ndjson':
        df = pd.read_json(file_path, lines=True)
    else:
        # 빈 데이터프레임 반환 (에러 방지)
        return pd.DataFrame()

    return df.fillna('')


def doc_generator(df, index_name):
    """Bulk API를 위한 Generator"""
    for index, row in df.iterrows():
        yield {
            "_index": index_name,
            "_source": row.to_dict()
        }


# ---------------------------------------------------------
# 기존 API 엔드포인트들 (100% 유지)
# ---------------------------------------------------------

@app.get("/api/sources")
async def get_sources():
    """모든 출처 목록 가져오기"""
    try:
        sources = list(db.sources.find())
        return {"total": len(sources), "sources": [serialize_doc(s) for s in sources]}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/upload")
async def upload_leak_file(
        file: UploadFile = File(...),
        source_id: Optional[str] = Form(None),
        source_name: Optional[str] = Form(None),
        source_type: Optional[str] = Form(None),
        source_description: Optional[str] = Form(None),
        original_link: Optional[str] = Form(None),
        leak_description: str = Form(...),
        leak_date: str = Form(...),
        severity: str = Form(...),
        file_name: str = Form(...)
):
    """유출 파일 업로드 및 Elasticsearch 인덱싱"""
    try:
        # 1. Source 처리
        if source_id:
            source = db.sources.find_one({"_id": ObjectId(source_id)})
            if not source:
                raise HTTPException(status_code=404, detail="Source not found")
            final_source_id = source['_id']
        else:
            if not source_name or not source_type:
                raise HTTPException(status_code=400, detail="source_name and source_type are required for new source")
            source_doc = {
                "name": source_name,
                "type": source_type,
                "description": source_description,
                "status": "active",
                "created_at": datetime.now()
            }
            result = db.sources.insert_one(source_doc)
            final_source_id = result.inserted_id

        # 2. Leak 생성
        leak_doc = {
            "source_id": final_source_id,
            "original_link": original_link,
            "description": leak_description,
            "leak_date": datetime.fromisoformat(leak_date),
            "severity": severity,
            "created_at": datetime.now(),
            "updated_at": datetime.now()
        }
        leak_result = db.leaks.insert_one(leak_doc)
        leak_id = leak_result.inserted_id

        index_name = f"leak_{str(leak_id)}"

        # 3. 파일 처리
        with tempfile.NamedTemporaryFile(delete=False, suffix=os.path.splitext(file.filename)[1]) as tmp_file:
            content = await file.read()
            tmp_file.write(content)
            tmp_file_path = tmp_file.name

        df = load_file_to_dataframe(tmp_file_path, file.content_type)

        # 4. Elasticsearch 업로드
        success, failed = helpers.bulk(es, doc_generator(df, index_name))

        # 5. File 메타데이터 저장
        file_doc = {
            "leak_id": leak_id,
            "file_name": file_name,
            "index_name": index_name,
            "file_type": os.path.splitext(file.filename)[1],
            "uploaded_at": datetime.now()
        }
        db.files.insert_one(file_doc)

        os.unlink(tmp_file_path)

        return {
            "message": "업로드 성공",
            "source_id": str(final_source_id),
            "leak_id": str(leak_id),
            "index_name": index_name,
            "success": success,
            "failed": failed,
            "total_records": len(df)
        }

    except Exception as e:
        if 'tmp_file_path' in locals():
            os.unlink(tmp_file_path)
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/")
async def root():
    """API 상태 확인"""
    return {"message": "DeepGuard Backend Running", "status": "running"}


@app.get("/health")
async def health_check():
    """Elasticsearch 연결 상태 확인"""
    try:
        return {"status": "ok", "elasticsearch": "connected" if es.ping() else "disconnected"}
    except Exception as e:
        return {"status": "error", "detail": str(e)}


@app.get("/indices")
async def get_indices():
    """모든 인덱스 목록 가져오기"""
    try:
        indices = es.indices.get_alias(index="*")
        index_list = [
            {"name": index_name, "aliases": list(info.get("aliases", {}).keys())}
            for index_name, info in indices.items() if not index_name.startswith(".")
        ]
        return {"total": len(index_list), "indices": index_list}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/fields/{index_name}")
async def get_fields(index_name: str):
    """지정한 인덱스의 필드(칼럼) 목록 가져오기"""
    try:
        if not es.indices.exists(index=index_name):
            raise HTTPException(status_code=404, detail=f"인덱스 '{index_name}'를 찾을 수 없습니다")

        mapping = es.indices.get_mapping(index=index_name)
        fields = []
        properties = mapping[index_name]['mappings'].get('properties', {})

        for field_name, field_info in properties.items():
            fields.append({
                "name": field_name,
                "type": field_info.get('type', 'object')
            })

        return {"index_name": index_name, "total_fields": len(fields), "fields": fields}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/data/{index_name}")
async def get_data(index_name: str, size: int = 100, from_: int = 0):
    """지정한 인덱스에서 데이터 가져오기"""
    try:
        if not es.indices.exists(index=index_name):
            raise HTTPException(status_code=404, detail=f"인덱스 '{index_name}'를 찾을 수 없습니다")

        response = es.search(
            index=index_name,
            body={"query": {"match_all": {}}, "size": size, "from": from_}
        )
        hits = response['hits']['hits']
        documents = [hit['_source'] for hit in hits]

        return {
            "index_name": index_name,
            "total": response['hits']['total']['value'],
            "size": len(documents),
            "from": from_,
            "documents": documents
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/search/{index_name}")
async def search_data(index_name: str, query: str, field: str = None, size: int = 100, min_score: float = None):
    """지정한 인덱스에서 검색"""
    try:
        if not es.indices.exists(index=index_name):
            raise HTTPException(status_code=404, detail=f"인덱스 '{index_name}'를 찾을 수 없습니다")

        search_query = {"query": {}, "size": size}
        if field:
            search_query["query"] = {"match": {field: query}}
        else:
            search_query["query"] = {"multi_match": {"query": query, "type": "best_fields"}}

        if min_score is not None:
            search_query["min_score"] = min_score

        response = es.search(index=index_name, body=search_query)
        hits = response['hits']['hits']
        documents = [hit['_source'] for hit in hits]
        scores = [hit['_score'] for hit in hits]

        return {
            "index_name": index_name,
            "query": query,
            "total": response['hits']['total']['value'],
            "size": len(documents),
            "documents": documents,
            "scores": scores
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/search-all-indices")
async def search_all_indices(email: str, size: int = 100):
    """모든 인덱스에서 이메일 검색"""
    try:
        all_indices = es.indices.get_alias(index="*")
        index_names = [name for name in all_indices.keys() if not name.startswith(".")]

        if not index_names:
            return {"email": email, "total_indices_searched": 0, "results": []}

        search_query = {"query": {"multi_match": {"query": email, "type": "phrase", "fields": ["*"]}}, "size": size}
        results = []
        total_found = 0

        for index_name in index_names:
            try:
                response = es.search(index=index_name, body=search_query)
                hits = response['hits']['hits']
                if hits:
                    documents = [{**hit['_source'], "_score": hit['_score']} for hit in hits]
                    results.append({
                        "index_name": index_name,
                        "total_hits": response['hits']['total']['value'],
                        "returned_hits": len(documents),
                        "documents": documents
                    })
                    total_found += response['hits']['total']['value']
            except:
                continue

        return {
            "email": email,
            "total_indices_searched": len(index_names),
            "total_documents_found": total_found,
            "indices_with_results": len(results),
            "results": results
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


def mask_text(text: str):
    """마스킹"""
    if not text or len(text) <= 2: return text
    return text[0] + "*" * (len(text) - 2) + text[-1]


def get_sha256(text: str):
    """해싱"""
    return hashlib.sha256(text.encode()).hexdigest()


@app.post("/parse-file")
async def parse_user_file(file: UploadFile = File(...)):
    """파일 파싱 및 마스킹 (기존 기능 유지)"""
    content = await file.read()
    try:
        text_data = content.decode("utf-8")
    except:
        text_data = content.decode("cp949", errors="ignore")

    results = []
    lines = text_data.splitlines()

    for line in lines:
        line = line.strip()
        if not line: continue

        if ":" in line:
            parts = line.split(":")
            target_email = ""
            target_pw = ""

            for i, part in enumerate(parts):
                if "@" in part and "." in part:
                    target_email = part.strip()
                    if i + 1 < len(parts):
                        target_pw = parts[i + 1].strip()
                    break

            if target_email:
                try:
                    email_id, email_domain = target_email.split("@", 1)
                except:
                    email_id = target_email
                    email_domain = ""

                entry = {
                    "id": str(uuid.uuid4()),
                    "original_hash": get_sha256(target_email),
                    "masked_email": f"{mask_text(email_id)}@{email_domain}",
                    "masked_password": mask_text(target_pw),
                    "raw_text": line,
                    "status": "Ready for Crawling"
                }
                results.append(entry)

    return {"status": "success", "file_name": file.filename, "total_parsed": len(results), "data": results}


def check_ransomware_risk(domain_keyword: str):
    """OSINT 랜섬웨어 체크 (기존 기능 유지)"""
    url = "https://api.ransomware.live/v2/recentvictims"
    headers = {"User-Agent": "Mozilla/5.0"}
    try:
        response = requests.get(url, headers=headers, verify=False, timeout=5)
        if response.status_code != 200:
            return {"status": "Error", "message": "API Error"}

        data = response.json()
        for item in data:
            victim = item.get('victim', '').lower()
            if domain_keyword.lower() in victim:
                return {
                    "is_leaked": True,
                    "victim_name": item.get('victim'),
                    "group": item.get('group'),
                    "date": item.get('attackdate'),
                    "screenshot": item.get('screenshot', ''),
                    "risk_level": "Critical"
                }
        return {"is_leaked": False, "risk_level": "Safe"}
    except Exception as e:
        return {"is_leaked": False, "error": str(e)}


# ---------------------------------------------------------
# [UPDATED] 크롤러가 연동된 Analyze File (기능 업그레이드)
# ---------------------------------------------------------
@app.post("/analyze-file")
async def analyze_uploaded_file(file: UploadFile = File(...)):
    print(f"📂 [DEBUG] 파일 업로드 및 분석 시작: {file.filename}")

    # 1. 파일 읽기
    content = await file.read()
    try:
        text_data = content.decode("utf-8")
    except:
        text_data = content.decode("cp949", errors="ignore")

    final_results = []


    try:
        dga_results = dga.analyze_text(
            text=text_data,
            filename=file.filename,
            mask=True  # 마스킹 적용
        )

        if dga_results:
            for item in dga_results:
                # DGA 결과 스키마 매핑
                formatted_dga = {
                    "id": item.get("id", str(uuid.uuid4())),
                    "keyword_type": item.get("keyword_type", "asset"),  # 분석기는 주로 자산/키 발견

                    # [스키마 준수] 파일 분석이므로 Source ID는 'File Analysis' 또는 파일명
                    "source_id": f"File: {file.filename}",

                    "original_link": file.filename,
                    "raw_text": item.get("raw_text", ""),
                    "leak_date": item.get("leak_date", str(datetime.now())),

                    # [스키마 준수] 분석기가 계산한 severity 사용
                    "severity": item.get("severity", "High")
                }
                final_results.append(formatted_dga)
            print(f"✅ [Analyzer] 파일 내부 분석 완료: {len(dga_results)}건 발견")
    except Exception as e:
        print(f"⚠️ [Analyzer] 분석 중 오류 (Skip): {e}")

    # -----------------------------------------------------
    # [STEP B] 기존 크롤러 (Crawler Controller) 실행
    # 목적: 파일 내 이메일을 추출하여 외부(텔레그램/다크웹) 검색
    # -----------------------------------------------------
    lines = text_data.splitlines()
    print(f"🔢 [Crawler] 텍스트 라인 스캔 시작 ({len(lines)}줄)")

    for line in lines:
        line = line.strip()
        if not line: continue

        target_email = ""
        target_pw = ""  # (필요시 사용)

        # 간단 파싱 로직 (이메일 추출)
        if ":" in line:
            parts = line.split(":")
            for idx, part in enumerate(parts):
                if "@" in part and "." in part:
                    target_email = part.strip()
                    if idx + 1 < len(parts):
                        target_pw = parts[idx + 1].strip()
                    break
        elif "@" in line and "." in line:
            target_email = line.strip()

        # 이메일 발견 시 크롤러 호출
        if target_email:
            try:
                clean_email = target_email.replace('"', '').replace(',', '').strip()
                # 비밀번호는 필요시 clean_pw 변수에 저장하여 전달

                print(f"📡 [Crawler] 외부 검색 요청: {clean_email}")

                # (1) 크롤러 호출 (비동기)
                crawled_data = await main_controller(clean_email)
                # 만약 main_controller가 인자 2개를 받는다면 main_controller(clean_email, target_pw)로 수정

                # 데이터 리스트화
                data_to_process = []
                if isinstance(crawled_data, list):
                    data_to_process = crawled_data
                elif isinstance(crawled_data, dict):
                    data_to_process = [crawled_data]

                # (2) 스키마 매핑 및 병합
                if data_to_process:
                    for item in data_to_process:
                        # ====================================================
                        # ★ [핵심] 프론트엔드 표준 스키마 적용 (준기님 요청)
                        # ====================================================
                        formatted_crawl = {
                            "id": item.get("id", str(uuid.uuid4())),

                            # 위협 유형 (기본값 credential)
                            "keyword_type": item.get("keyword_type", "credential"),

                            # ★ [Source ID 변경] 플랫폼명이 아니라 '검색한 키워드(Input)' 입력
                            "source_id": clean_email,

                            # 원본 링크 (없으면 파일명이라도 넣음)
                            "original_link": item.get("original_link", item.get("url", file.filename)),

                            # 원본 텍스트
                            "raw_text": item.get("raw_text", item.get("text", line)),

                            # 유출 시점
                            "leak_date": str(item.get("leak_date", datetime.now())),

                            # ★ [Severity] 크롤러가 계산한 값 그대로 전달 (없으면 Critical)
                            "severity": item.get("severity", "Critical")
                        }
                        # ====================================================

                        final_results.append(formatted_crawl)

                    print(f"   └─ ✅ 크롤링 완료: {len(data_to_process)}건")

            except Exception as e:
                print(f"   └─ ❌ 크롤링 에러: {clean_email} - {e}")

    # -----------------------------------------------------
    # [STEP C] 통합 데이터 DB 저장 및 반환
    # -----------------------------------------------------
    saved_count = 0
    if final_results:
        for item in final_results:
            try:
                # Elasticsearch 저장
                es.index(index="leaked_data", body=item)

                # MongoDB 저장
                if 'mongo_collection' in globals():
                    mongo_collection.insert_one(item.copy())

                saved_count += 1
            except Exception as e:
                print(f"⚠️ DB 저장 실패 (Skip): {e}")

            # MongoDB _id 객체 제거 (JSON 반환 위해)
            if "_id" in item: del item["_id"]

    print(f"🏆 [최종] 총 {len(final_results)}건 처리 완료 (DB 저장: {saved_count}건)")

    return {
        "status": "success",
        "file_name": file.filename,
        "total_processed": len(final_results),
        "data": final_results
    }


@app.patch("/api/leaks/{leak_id}/status")
async def update_leak_status(leak_id: str, status: str):
    """유출 정보 상태 업데이트"""
    try:
        valid_statuses = ["new", "processing", "investigating", "resolved"]
        if status not in valid_statuses:
            raise HTTPException(status_code=400, detail=f"Invalid status")
        result = db.leaks.update_one(
            {"_id": ObjectId(leak_id)},
            {"$set": {"status": status, "updated_at": datetime.now()}}
        )
        if result.matched_count == 0:
            raise HTTPException(status_code=404, detail="Leak not found")
        return {"message": "Status updated successfully", "status": status}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/leaks")
async def get_leaks(
        severity: Optional[str] = None,
        source_id: Optional[str] = None,
        limit: int = 100,
        skip: int = 0
):
    """유출 정보 목록 가져오기"""
    try:
        query = {}
        if severity: query["severity"] = severity
        if source_id: query["source_id"] = ObjectId(source_id)

        leaks = list(db.leaks.find(query).sort("leak_date", -1).skip(skip).limit(limit))
        total = db.leaks.count_documents(query)

        for leak in leaks:
            if 'source_id' in leak:
                source = db.sources.find_one({"_id": leak['source_id']})
                leak['source'] = serialize_doc(source) if source else None

            files = list(db.files.find({"leak_id": leak['_id']}))
            leak['files'] = [serialize_doc(f) for f in files]

        return {
            "total": total,
            "limit": limit,
            "skip": skip,
            "leaks": [serialize_doc(l) for l in leaks]
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ---------------------------------------------------------
# [누락된 기능 복구] 상세 조회 및 개인정보 통합 검색
# ---------------------------------------------------------

@app.get("/api/leaks/by-index/{index_name}")
async def get_leak_by_index(index_name: str):
    """인덱스 이름으로 유출 정보 가져오기"""
    try:
        # 파일에서 해당 index_name을 가진 파일 찾기
        file = db.files.find_one({"index_name": index_name})
        if not file:
            raise HTTPException(status_code=404, detail=f"Index '{index_name}'에 대한 파일을 찾을 수 없습니다")

        # 해당 파일의 leak 정보 가져오기
        leak = db.leaks.find_one({"_id": file['leak_id']})
        if not leak:
            raise HTTPException(status_code=404, detail="Leak not found")

        # source 정보 조인
        if 'source_id' in leak:
            source = db.sources.find_one({"_id": leak['source_id']})
            leak['source'] = serialize_doc(source) if source else None

        # 파일 정보 조인 및 칼럼 정보 추가
        files = list(db.files.find({"leak_id": leak['_id']}))
        for f in files:
            if 'index_name' in f:
                try:
                    if es.indices.exists(index=f['index_name']):
                        mapping = es.indices.get_mapping(index=f['index_name'])
                        properties = mapping[f['index_name']]['mappings'].get('properties', {})
                        f['columns'] = [
                            {
                                'name': field_name,
                                'type': field_info.get('type', 'object')
                            }
                            for field_name, field_info in properties.items()
                        ]

                        count_response = es.count(index=f['index_name'])
                        f['record_count'] = count_response['count']
                except Exception as e:
                    f['columns'] = []
                    f['record_count'] = 0
        leak['files'] = [serialize_doc(f) for f in files]

        return serialize_doc(leak)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/search/personal-info")
async def search_personal_info(query: str, project_keyword: str = None, size: int = 100):
    """
    개인정보 유출 검색 (이메일 + 프로젝트 키워드)
    - [수정] 검색 시작 전, 해당 쿼리(이메일)에 대한 기존 데이터를 삭제하여 중복 방지
    """
    try:
        print(f"🔎 [Search] 검색 요청: 이메일={query}, 프로젝트키워드={project_keyword}")

        # -----------------------------------------------------
        # [STEP 0] 기존 데이터 삭제 (중복 누적 방지)
        # -----------------------------------------------------
        try:
            # Elasticsearch에서 해당 이메일로 된 이전 기록 삭제
            es.delete_by_query(
                index="leaked_data",
                body={
                    "query": {
                        "match": {"target_email": query}
                    }
                },
                refresh=True  # 삭제 즉시 반영
            )
            print(f"🧹 [Clean] '{query}'에 대한 기존 검색 결과 초기화 완료")
        except Exception as e:
            print(f"⚠️ 기존 데이터 삭제 중 경미한 오류 (무시 가능): {e}")

        # -----------------------------------------------------
        # [STEP 1] 실시간 크롤러 작동
        # -----------------------------------------------------
        try:
            crawled_data = await main_controller(query, project_keyword)

            data_to_process = []
            if isinstance(crawled_data, list):
                data_to_process = crawled_data
            elif isinstance(crawled_data, dict):
                data_to_process = [crawled_data]

            print(f"🕷️ [Crawler] 크롤링 완료: {len(data_to_process)}건 발견")

            if data_to_process:
                for item in data_to_process:
                    formatted_item = {
                        "id": item.get("id", str(uuid.uuid4())),
                        # [수정] 크롤러가 준 keyword_type을 우선 사용, 없으면 credential
                        "keyword_type": item.get("keyword_type", "credential"),
                        "source_id": query,
                        "source": item.get("source_id", "Unknown"),
                        "original_link": item.get("original_link", ""),
                        "raw_text": item.get("raw_text", ""),
                        "leak_date": str(item.get("leak_date", datetime.now())),
                        "target_email": item.get("target_email", query),
                        "found_keyword": item.get("found_keyword", query),
                        "severity": "Critical",
                        "status": "new",
                        "created_at": datetime.now()
                    }

                    es.index(index="leaked_data", body=formatted_item)

                    if 'mongo_collection' in globals():
                        mongo_collection.insert_one(formatted_item.copy())

                import time
                time.sleep(1)

        except TypeError as te:
            print(f"⚠️ 크롤러 호출 파라미터 오류: {te}")
        except Exception as e:
            print(f"⚠️ 크롤링 실행 중 오류: {e}")

        # -----------------------------------------------------
        # [STEP 2] 저장된 데이터 검색 (Elasticsearch)
        # -----------------------------------------------------
        all_indices = es.indices.get_alias(index="*")
        index_names = [name for name in all_indices.keys() if not name.startswith(".")]

        should_conditions = [
            {"match_phrase": {"target_email": query}},
            {"match_phrase": {"raw_text": query}}
        ]

        if project_keyword:
            should_conditions.append({"match_phrase": {"raw_text": project_keyword}})

        search_query = {
            "query": {
                "bool": {
                    "should": should_conditions,
                    "minimum_should_match": 1
                }
            },
            "size": size,
            "sort": [{"_score": "desc"}, {"created_at": "desc"}]
        }

        es_results = []

        for index_name in index_names:
            try:
                response = es.search(index=index_name, body=search_query)
                hits = response['hits']['hits']

                if hits:
                    for hit in hits:
                        es_results.append({
                            "index": index_name,
                            "score": hit['_score'],
                            "data": hit['_source']
                        })
            except:
                continue

        return {
            "query": query,
            "elasticsearch_results": es_results,
            "total_es_results": len(es_results)
        }

    except Exception as e:
        print(f"❌ 검색 API 치명적 오류: {e}")
        raise HTTPException(status_code=500, detail=str(e))
    # try:
    #     # Elasticsearch에서 검색
    #     all_indices = es.indices.get_alias(index="*")
    #     index_names = [name for name in all_indices.keys() if not name.startswith(".")]
    #
    #     search_query = {
    #         "query": {
    #             "multi_match": {
    #                 "query": query,
    #                 "type": "best_fields",
    #                 "fields": ["*"]
    #             }
    #         },
    #         "min_score": 0.8,
    #         "size": size
    #     }
    #
    #     es_results = []
    #     index_info_map = {}
    #
    #     for index_name in index_names:
    #         try:
    #             response = es.search(index=index_name, body=search_query)
    #             hits = response['hits']['hits']
    #
    #             if hits:
    #                 # 인덱스 정보 가져오기 (한 번만)
    #                 if index_name not in index_info_map:
    #                     try:
    #                         # MongoDB에서 파일 정보 찾기
    #                         file_doc = db.files.find_one({"index_name": index_name})
    #
    #                         mapping = es.indices.get_mapping(index=index_name)
    #                         properties = mapping[index_name]['mappings'].get('properties', {})
    #                         columns = [
    #                             {
    #                                 'name': field_name,
    #                                 'type': field_info.get('type', 'object')
    #                             }
    #                             for field_name, field_info in properties.items()
    #                         ]
    #
    #                         # 인덱스의 문서 개수
    #                         count_response = es.count(index=index_name)
    #
    #                         index_info_map[index_name] = {
    #                             'index_name': index_name,
    #                             'file_name': file_doc['file_name'] if file_doc else index_name,
    #                             'columns': columns,
    #                             'total_records': count_response['count']
    #                         }
    #                     except:
    #                         index_info_map[index_name] = {
    #                             'index_name': index_name,
    #                             'file_name': index_name,
    #                             'columns': [],
    #                             'total_records': 0
    #                         }
    #
    #                 for hit in hits:
    #                     # score가 0.8 이상인 결과만 추가
    #                     if hit['_score'] >= 0.8:
    #                         es_results.append({
    #                             "index": index_name,
    #                             "score": hit['_score'],
    #                             "data": hit['_source'],
    #                             "index_info": index_info_map[index_name]
    #                         })
    #         except:
    #             continue
    #
    #     return {
    #         "query": query,
    #         "elasticsearch_results": es_results,
    #         "total_es_results": len(es_results),
    #         "indices_info": list(index_info_map.values())
    #     }
    # except Exception as e:
    #     raise HTTPException(status_code=500, detail=str(e))

if __name__ == "__main__":
    import uvicorn

    # 0.0.0.0은 외부 접속 허용, port는 8000번 포트 사용
    uvicorn.run(app, host="0.0.0.0", port=8000)