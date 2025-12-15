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
from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.responses import JSONResponse
from elasticsearch import Elasticsearch, helpers


try:
    from deepguard_crawl_b2b import main_controller
except ImportError:
    
    print("⚠️ 경고: 'deepguard_crawl_b2b' 모듈을 찾을 수 없습니다.")
    print("⚠️ 임시 테스트용 함수로 대체합니다.")
    
    def main_controller(target):
        # 크롤러 파일이 없을 때 에러 안 나게 해주는 가짜 응답
        return {
            "id": str(uuid.uuid4()),
            "target_email": target,
            "status": "Test Mode (Crawler Not Found)",
            "leaked_date": str(datetime.now()),
            "source": "Test Source"
        }

app = FastAPI()

# ---------------------------------------------------------
# DB 연결 설정
# ---------------------------------------------------------
# Elasticsearch 연결
es = Elasticsearch(
    "http://localhost:9200",
    verify_certs=False
)

# MongoDB 연결
try:
    mongo_client = MongoClient("mongodb://localhost:27017/")
    mongo_db = mongo_client["deepguard_db"]
    mongo_collection = mongo_db["leaked_data"]
    print("✅ MongoDB Connected")
except Exception as e:
    print(f"⚠️ MongoDB Connection Failed: {e}")



def load_file_to_dataframe(file_path, content_type):
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
        return pd.DataFrame() # 빈 데이터프레임 반환
    
    return df.fillna('')

def doc_generator(df, index_name):
    for index, row in df.iterrows():
        yield {
            "_index": index_name,
            "_source": row.to_dict()
        }

@app.post("/upload")
async def upload_to_elasticsearch(
    file: UploadFile = File(...),
    index_name: str = None
):
    """일반 파일 업로드 API (기존 유지)"""
    try:
        if index_name is None:
            index_name = os.path.splitext(file.filename)[0]
        
        with tempfile.NamedTemporaryFile(delete=False, suffix=os.path.splitext(file.filename)[1]) as tmp_file:
            content = await file.read()
            tmp_file.write(content)
            tmp_file_path = tmp_file.name
        
        df = load_file_to_dataframe(tmp_file_path, file.content_type)
        
        success, failed = helpers.bulk(es, doc_generator(df, index_name))
        os.unlink(tmp_file_path)
        
        return JSONResponse(
            status_code=200,
            content={"message": "업로드 성공", "success": success, "failed": failed}
        )
    except Exception as e:
        if 'tmp_file_path' in locals(): os.unlink(tmp_file_path)
        raise HTTPException(status_code=500, detail=str(e))



@app.post("/analyze-file")
async def analyze_uploaded_file(file: UploadFile = File(...)):
  
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
        
        # 2. 파일 파싱 (이메일:비번 형식 분리)
        if ":" in line:
            parts = line.split(":")
            target_email = ""
            
            # 이메일 찾기
            for part in parts:
                if "@" in part and "." in part:
                    target_email = part.strip()
                    break
            
            # 이메일이 존재하면 크롤러 가동
            if target_email:
                try:
                    # =========================================================
                    
                    # 가짜 entry 생성 로직 삭제 -> 크롤러 결과값(JSON) 수신
                    # =========================================================
                    print(f"📡 크롤러 분석 요청: {target_email}")
                    
                    # 여기서 deepguard_crawl_b2b.py의 함수가 실행됩니다.
                    crawled_data = main_controller(target_email)
                    
                    # 크롤러가 데이터를 잘 줬는지 확인 (딕셔너리 형태여야 함)
                    if isinstance(crawled_data, dict):
                        # 원본 라인 정보가 필요하면 추가 (선택사항)
                        crawled_data["raw_line_text"] = line
                        
                        # -----------------------------------------------------
                        
                        # -----------------------------------------------------
                        
                        # 1. MongoDB 적재
                        if 'mongo_collection' in globals():
                            # _id 충돌 방지를 위해 copy() 사용
                            mongo_collection.insert_one(crawled_data.copy())
                        
                        # 2. Elasticsearch 적재
                        # ES는 _id가 본문 안에 있으면 에러가 날 수 있으므로 분리
                        es_body = crawled_data.copy()
                        es_id = es_body.pop("_id", str(uuid.uuid4())) # _id가 있으면 빼서 쓰고, 없으면 만듦
                        
                        es.index(index="leaked_data", id=str(es_id), body=es_body)
                        
                        # 결과 리스트에 추가
                        results.append(crawled_data)
                    else:
                        print(f"⚠️ 크롤러 반환 데이터 오류: {crawled_data}")

                except Exception as e:
                    print(f"❌ 처리 중 에러 발생: {e}")
                    # 에러가 나도 멈추지 않고 다음 줄로 넘어감

    return {
        "status": "success",
        "file_name": file.filename,
        "total_processed": len(results),
        "data": results
    }

# ---------------------------------------------------------
# 상태 확인용 API (프론트엔드 연동용)
# ---------------------------------------------------------
@app.get("/")
async def root():
    return {"message": "DeepGuard Backend Running"}

@app.get("/health")
async def health_check():
    return {"status": "ok", "elasticsearch": "connected" if es.ping() else "disconnected"}

# 검색 기능들 (기존 유지)
@app.get("/search/{index_name}")
async def search_data(index_name: str, query: str):
    res = es.search(index=index_name, body={"query": {"multi_match": {"query": query, "fields": ["*"]}}})
    return res['hits']['hits']