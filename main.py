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

es = Elasticsearch(
    "http://localhost:9200",
    verify_certs=False
)

# MongoDB 연결
mongo_client = MongoClient("mongodb://admin:admin123@localhost:27017/")
db = mongo_client["leak_database"]

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
        raise ValueError(f"지원하지 않는 파일 형식입니다: {ext}")
    
    return df.fillna('')

def doc_generator(df, index_name):
    """Bulk API를 위한 Generator"""
    for index, row in df.iterrows():
        yield {
            "_index": index_name,
            "_source": row.to_dict()
        }
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
    """
    유출 파일 업로드 및 Elasticsearch 인덱싱
    """
    try:
        # 1. Source 처리 (기존 출처 사용 또는 새로 생성)
        if source_id:
            # 기존 출처 사용
            source = db.sources.find_one({"_id": ObjectId(source_id)})
            if not source:
                raise HTTPException(status_code=404, detail="Source not found")
            final_source_id = source['_id']
        else:
            # 새 출처 생성
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
        
        # 인덱스 이름을 leak_id 기반으로 생성 (고유성 보장)
        index_name = f"leak_{str(leak_id)}"
        
        # 3. 파일을 임시 저장하고 DataFrame으로 변환
        with tempfile.NamedTemporaryFile(delete=False, suffix=os.path.splitext(file.filename)[1]) as tmp_file:
            content = await file.read()
            tmp_file.write(content)
            tmp_file_path = tmp_file.name
        
        df = load_file_to_dataframe(tmp_file_path, file.content_type)
        
        # 4. Elasticsearch에 업로드
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
        
        # 임시 파일 삭제
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
        # 임시 파일이 있다면 삭제
        if 'tmp_file_path' in locals():
            os.unlink(tmp_file_path)
        
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/")
async def root():
    """API 상태 확인"""
    return {"message": "Elasticsearch Upload API", "status": "running"}

@app.get("/health")
async def health_check():
    """Elasticsearch 연결 상태 확인"""
    try:
        info = es.info()
        return {
            "elasticsearch": "connected",
            "cluster_name": info['cluster_name'],
            "version": info['version']['number']
        }
    except Exception as e:
        raise HTTPException(status_code=503, detail=f"Elasticsearch 연결 실패: {str(e)}")

@app.get("/indices")
async def get_indices():
    """모든 인덱스 목록 가져오기"""
    try:
        indices = es.indices.get_alias(index="*")
        index_list = [
            {
                "name": index_name,
                "aliases": list(info.get("aliases", {}).keys())
            }
            for index_name, info in indices.items()
            if not index_name.startswith(".")  # 시스템 인덱스 제외
        ]
        
        return {
            "total": len(index_list),
            "indices": index_list
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/fields/{index_name}")
async def get_fields(index_name: str):
    """
    지정한 인덱스의 필드(칼럼) 목록 가져오기
    - index_name: Elasticsearch 인덱스 이름
    """
    try:
        # 인덱스 존재 여부 확인
        if not es.indices.exists(index=index_name):
            raise HTTPException(status_code=404, detail=f"인덱스 '{index_name}'를 찾을 수 없습니다")
        
        # 매핑 정보 가져오기
        mapping = es.indices.get_mapping(index=index_name)
        
        # 필드 목록 추출
        fields = []
        properties = mapping[index_name]['mappings'].get('properties', {})
        
        for field_name, field_info in properties.items():
            fields.append({
                "name": field_name,
                "type": field_info.get('type', 'object')
            })
        
        return {
            "index_name": index_name,
            "total_fields": len(fields),
            "fields": fields
        }
    
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/data/{index_name}")
async def get_data(
    index_name: str,
    size: int = 100,
    from_: int = 0
):
    """
    지정한 인덱스에서 데이터 가져오기
    - index_name: Elasticsearch 인덱스 이름
    - size: 가져올 문서 개수 (기본값: 100)
    - from_: 시작 위치 (기본값: 0, 페이지네이션용)
    """
    try:
        # 인덱스 존재 여부 확인
        if not es.indices.exists(index=index_name):
            raise HTTPException(status_code=404, detail=f"인덱스 '{index_name}'를 찾을 수 없습니다")
        
        # 데이터 조회
        response = es.search(
            index=index_name,
            body={
                "query": {"match_all": {}},
                "size": size,
                "from": from_
            }
        )
        
        # 결과 추출
        hits = response['hits']['hits']
        documents = [hit['_source'] for hit in hits]
        
        return {
            "index_name": index_name,
            "total": response['hits']['total']['value'],
            "size": len(documents),
            "from": from_,
            "documents": documents
        }
    
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/search/{index_name}")
async def search_data(
    index_name: str,
    query: str,
    field: str = None,
    size: int = 100,
    min_score: float = None
):
    """
    지정한 인덱스에서 검색
    - index_name: Elasticsearch 인덱스 이름
    - query: 검색어
    - field: 검색할 필드명 (선택, 없으면 모든 필드 검색)
    - size: 가져올 문서 개수 (기본값: 100)
    - min_score: 최소 관련성 점수 (선택, 이 점수 이상인 결과만 반환)
    """
    try:
        # 인덱스 존재 여부 확인
        if not es.indices.exists(index=index_name):
            raise HTTPException(status_code=404, detail=f"인덱스 '{index_name}'를 찾을 수 없습니다")
        
        # 검색 쿼리 구성
        if field:
            search_query = {
                "query": {
                    "match": {field: query}
                },
                "size": size
            }
        else:
            # 모든 필드에서 검색 (multi_match 사용)
            search_query = {
                "query": {
                    "multi_match": {
                        "query": query,
                        "type": "best_fields"
                    }
                },
                "size": size
            }
        
        # 최소 점수 설정. 안하면 모든 결과 반환함
        if min_score is not None:
            search_query["min_score"] = min_score
        
        # 검색 실행
        response = es.search(index=index_name, body=search_query)
        # 결과 추출
        hits = response['hits']['hits']
        documents = [hit['_source'] for hit in hits]
        scores = [hit['_score'] for hit in hits]
        
        return {
            "index_name": index_name,
            "query": query,
            "field": field,
            "min_score": min_score,
            "total": response['hits']['total']['value'],
            "size": len(documents),
            "documents": documents,
            "scores": scores
        }
    
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/search-all-indices")
async def search_all_indices(
    email: str,
    size: int = 100
):
    """
    모든 인덱스에서 이메일 검색
    - email: 검색할 이메일 주소
    - size: 각 인덱스에서 가져올 최대 문서 개수 (기본값: 100)
    """
    try:
        # 모든 인덱스 목록 가져오기 (시스템 인덱스 제외)
        all_indices = es.indices.get_alias(index="*")
        index_names = [name for name in all_indices.keys() if not name.startswith(".")]
        
        if not index_names:
            return {
                "email": email,
                "total_indices_searched": 0,
                "results": []
            }
        
        # 모든 인덱스에서 검색
        search_query = {
            "query": {
                "multi_match": {
                    "query": email,
                    "type": "phrase",
                    "fields": ["*"]
                }
            },
            "size": size
        }
        
        # 각 인덱스별 결과 저장
        results = []
        total_found = 0
        
        for index_name in index_names:
            try:
                response = es.search(index=index_name, body=search_query)
                hits = response['hits']['hits']
                
                if hits:  # 결과가 있는 인덱스만 포함
                    documents = [
                        {
                            **hit['_source'],
                            "_score": hit['_score']
                        } for hit in hits
                    ]
                    
                    results.append({
                        "index_name": index_name,
                        "total_hits": response['hits']['total']['value'],
                        "returned_hits": len(documents),
                        "documents": documents
                    })
                    
                    total_found += response['hits']['total']['value']
                    
            except Exception as index_error:
                # 개별 인덱스 검색 실패는 무시하고 계속 진행
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
    """
    [기능] 맨 앞/뒤 글자 제외하고 나머지 * 처리 (예: admin -> a***n)
    """
    if not text or len(text) <= 2:
        return text 
    return text[0] + "*" * (len(text) - 2) + text[-1]

def get_sha256(text: str):
    """
    [기능] 텍스트의 해시값(SHA-256) 생성
    """
    return hashlib.sha256(text.encode()).hexdigest()


@app.post("/parse-file")
async def parse_user_file(file: UploadFile = File(...)):
    """
    [기능] 파일(txt)을 읽어서 'email:password' 파싱 -> 마스킹 -> 해싱 -> JSON 반환
    """
    # 1. 파일 읽기
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
        
        # 2. 파싱 
        # 예: email:password 또는 url:email:password
        if ":" in line:
            parts = line.split(":")
            
            target_email = ""
            target_pw = ""
            
            # 이메일 형식을 찾음 (@와 .이 있는 것)
            for i, part in enumerate(parts):
                if "@" in part and "." in part:
                    target_email = part.strip()
                    # 이메일 바로 뒤에 있는게 비밀번호일 확률 높음
                    if i + 1 < len(parts):
                        target_pw = parts[i+1].strip()
                    break
            
            # 이메일을 찾았다면 처리 시작
            if target_email:
                # ID 부분만 추출 (admin@gmail.com -> admin)
                try:
                    email_id, email_domain = target_email.split("@", 1)
                except:
                    email_id = target_email
                    email_domain = ""

                # 3. 마스킹 & 해싱 (민정님 요청)
                masked_id = mask_text(email_id)
                masked_pw = mask_text(target_pw)
                email_hash = get_sha256(target_email)

                # 4. JSON 구조 만들기
                entry = {
                    "id": str(uuid.uuid4()),                        # 고유 ID
                    "original_hash": email_hash,                    # 식별용 해시
                    "masked_email": f"{masked_id}@{email_domain}",  # 보여주기용
                    "masked_password": masked_pw,                   # 보여주기용
                    "raw_text": line,                               # 원본 데이터
                    "status": "Ready for Crawling"                  # 상태 표시
                }
                results.append(entry)

    # 5. 최종 결과 반환
    return {
        "status": "success",
        "file_name": file.filename,
        "total_parsed": len(results),
        "data": results
    }

def check_ransomware_risk(domain_keyword: str):
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

def mask_text(text: str):
    if not text or len(text) <= 2: return text 
    return text[0] + "*" * (len(text) - 2) + text[-1]

def get_sha256(text: str):
    return hashlib.sha256(text.encode()).hexdigest()

@app.post("/analyze-file")
async def analyze_uploaded_file(file: UploadFile = File(...)):
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
                        target_pw = parts[i+1].strip()
                    break
            
            if target_email:
                try:
                    email_id, email_domain = target_email.split("@", 1)
                    company_keyword = email_domain.split('.')[0]
                except:
                    email_id = target_email
                    email_domain = ""
                    company_keyword = target_email

                osint_result = check_ransomware_risk(company_keyword)

                entry = {
                    "id": str(uuid.uuid4()),
                    "original_hash": get_sha256(target_email),
                    "masked_email": f"{mask_text(email_id)}@{email_domain}",
                    "masked_password": mask_text(target_pw),
                    "domain": email_domain,
                    "osint_result": osint_result,
                    "raw_text": line,
                    "status": "Analyzed",
                    "created_at": str(datetime.now())
                }
                
                try:
                    es.index(index="leaked_data", body=entry)
                    if 'mongo_collection' in globals():
                        mongo_collection.insert_one(entry.copy())
                except Exception as e:
                    print(f"DB Error: {e}")
                # 이메일 알림 트리거 (domain 기반 간단 알림)
                try:
                    await send_leak_alert(
                        domain=email_domain,
                        masked_email=entry["masked_email"],
                        risk_level=entry["osint_result"].get("risk_level", "Unknown")
                    )
                except Exception as e:
                    print(f"Email Error: {e}")

                if "_id" in entry: del entry["_id"]
                results.append(entry)

    return {
        "status": "success",
        "file_name": file.filename,
        "total_parsed": len(results),
        "data": results
    }

@app.patch("/api/leaks/{leak_id}/status")
async def update_leak_status(leak_id: str, status: str):
    """유출 정보 상태 업데이트"""
    try:
        valid_statuses = ["new", "processing", "investigating", "resolved"]
        if status not in valid_statuses:
            raise HTTPException(status_code=400, detail=f"Invalid status. Must be one of: {valid_statuses}")
        
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
    """유출 정보 목록 가져오기 (필터링 지원)"""
    try:
        query = {}
        if severity:
            query["severity"] = severity
        if source_id:
            query["source_id"] = ObjectId(source_id)
        
        leaks = list(db.leaks.find(query).sort("leak_date", -1).skip(skip).limit(limit))
        total = db.leaks.count_documents(query)
        
        # source 정보 조인
        for leak in leaks:
            if 'source_id' in leak:
                source = db.sources.find_one({"_id": leak['source_id']})
                leak['source'] = serialize_doc(source) if source else None
            
            # 파일 정보 조인 및 칼럼 정보 추가
            files = list(db.files.find({"leak_id": leak['_id']}))
            for file in files:
                if 'index_name' in file:
                    try:
                        # Elasticsearch 인덱스에서 필드 정보 및 문서 개수 가져오기
                        if es.indices.exists(index=file['index_name']):
                            mapping = es.indices.get_mapping(index=file['index_name'])
                            properties = mapping[file['index_name']]['mappings'].get('properties', {})
                            file['columns'] = [
                                {
                                    'name': field_name,
                                    'type': field_info.get('type', 'object')
                                }
                                for field_name, field_info in properties.items()
                            ]
                            
                            # 인덱스의 문서 개수 가져오기
                            count_response = es.count(index=file['index_name'])
                            file['record_count'] = count_response['count']
                    except Exception as e:
                        file['columns'] = []
                        file['record_count'] = 0
            leak['files'] = [serialize_doc(f) for f in files]
        
        return {
            "total": total,
            "limit": limit,
            "skip": skip,
            "leaks": [serialize_doc(l) for l in leaks]
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

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
async def search_personal_info(query: str, size: int = 100):
    """
    개인정보 유출 검색 (Elasticsearch + MongoDB 통합)
    - query: 검색어 (이메일, 전화번호, 사용자명 등)
    - size: 결과 개수
    """
    try:
        # Elasticsearch에서 검색
        all_indices = es.indices.get_alias(index="*")
        index_names = [name for name in all_indices.keys() if not name.startswith(".")]
        
        search_query = {
            "query": {
                "multi_match": {
                    "query": query,
                    "type": "best_fields",
                    "fields": ["*"]
                }
            },
            "min_score": 0.8,
            "size": size
        }
        
        es_results = []
        index_info_map = {}
        
        for index_name in index_names:
            try:
                response = es.search(index=index_name, body=search_query)
                hits = response['hits']['hits']
                
                if hits:
                    # 인덱스 정보 가져오기 (한 번만)
                    if index_name not in index_info_map:
                        try:
                            # MongoDB에서 파일 정보 찾기
                            file_doc = db.files.find_one({"index_name": index_name})
                            
                            mapping = es.indices.get_mapping(index=index_name)
                            properties = mapping[index_name]['mappings'].get('properties', {})
                            columns = [
                                {
                                    'name': field_name,
                                    'type': field_info.get('type', 'object')
                                }
                                for field_name, field_info in properties.items()
                            ]
                            
                            # 인덱스의 문서 개수
                            count_response = es.count(index=index_name)
                            
                            index_info_map[index_name] = {
                                'index_name': index_name,
                                'file_name': file_doc['file_name'] if file_doc else index_name,
                                'columns': columns,
                                'total_records': count_response['count']
                            }
                        except:
                            index_info_map[index_name] = {
                                'index_name': index_name,
                                'file_name': index_name,
                                'columns': [],
                                'total_records': 0
                            }
                    
                    for hit in hits:
                        # score가 0.8 이상인 결과만 추가
                        if hit['_score'] >= 0.8:
                            es_results.append({
                                "index": index_name,
                                "score": hit['_score'],
                                "data": hit['_source'],
                                "index_info": index_info_map[index_name]
                            })
            except:
                continue
        
        return {
            "query": query,
            "elasticsearch_results": es_results,
            "total_es_results": len(es_results),
            "indices_info": list(index_info_map.values())
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))