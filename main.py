from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.responses import JSONResponse
import pandas as pd
import json
import os
import tempfile
from elasticsearch import Elasticsearch, helpers

app = FastAPI()

es = Elasticsearch(
    "http://localhost:9200",
    verify_certs=False
)

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

@app.post("/upload")
async def upload_to_elasticsearch(
    file: UploadFile = File(...),
    index_name: str = None
):
    """
    파일을 Elasticsearch에 업로드
    - file: CSV, TSV, JSON, NDJSON 파일
    - index_name: Elasticsearch 인덱스 이름 (기본값: 파일명)
    """
    try:
        # index_name이 없으면 파일명(확장자 제외)을 사용
        if index_name is None:
            index_name = os.path.splitext(file.filename)[0]
        
        # 임시 파일 생성
        with tempfile.NamedTemporaryFile(delete=False, suffix=os.path.splitext(file.filename)[1]) as tmp_file:
            content = await file.read()
            tmp_file.write(content)
            tmp_file_path = tmp_file.name
        
        # DataFrame으로 변환
        df = load_file_to_dataframe(tmp_file_path, file.content_type)
        
        # Elasticsearch에 업로드
        success, failed = helpers.bulk(es, doc_generator(df, index_name))
        
        # 임시 파일 삭제
        os.unlink(tmp_file_path)
        
        return JSONResponse(
            status_code=200,
            content={
                "message": "업로드 성공",
                "index_name": index_name,
                "success": success,
                "failed": failed,
                "total_records": len(df)
            }
        )
    
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
