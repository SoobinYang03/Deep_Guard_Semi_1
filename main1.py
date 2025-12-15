from fastapi import FastAPI, UploadFile, File, HTTPException, Query
from fastapi.responses import JSONResponse
import pandas as pd
import os
import tempfile
from elasticsearch import Elasticsearch, helpers

# ✅ 추가: analyzer import
import deepguard_analyzer

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
    for _, row in df.iterrows():
        yield {
            "_index": index_name,
            "_source": row.to_dict()
        }

def docs_from_list(records, index_name: str):
    """list[dict] -> bulk docs"""
    for r in records:
        yield {
            "_index": index_name,
            "_source": r
        }

@app.post("/upload")
async def upload_to_elasticsearch(
    file: UploadFile = File(...),
    index_name: str = None
):
    """
    (기존 그대로) 파일을 Elasticsearch에 업로드
    - file: CSV, TSV, JSON, NDJSON 파일
    - index_name: Elasticsearch 인덱스 이름 (기본값: 파일명)
    """
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
            content={
                "message": "업로드 성공",
                "index_name": index_name,
                "success": success,
                "failed": failed,
                "total_records": len(df)
            }
        )

    except Exception as e:
        if 'tmp_file_path' in locals() and os.path.exists(tmp_file_path):
            os.unlink(tmp_file_path)
        raise HTTPException(status_code=500, detail=str(e))


# ✅ 추가 엔드포인트: deepguard analyzer 연동
@app.post("/deepguard/analyze-upload")
async def analyze_upload_and_index(
    file: UploadFile = File(...),
    index_name: str = Query(default="deepguard_hits", description="Elasticsearch index name"),
    mask: bool = Query(default=True, description="Mask/hash sensitive patterns in raw_text"),
):
    """
    업로드된 파일을 deepguard_analyzer로 분석 후,
    표준 포맷(list[dict]) 결과를 ES에 적재.
    """
    try:
        content = await file.read()

        # analyzer 실행 (filename이 original_link로 들어감)
        records = deepguard_analyzer.analyze_bytes(
            file_bytes=content,
            filename=file.filename,
            mask=mask
        )

        if not records:
            return JSONResponse(
                status_code=200,
                content={
                    "message": "분석 결과 없음 (저장 조건 미달)",
                    "index_name": index_name,
                    "saved": 0,
                    "mask": mask
                }
            )

        success, failed = helpers.bulk(es, docs_from_list(records, index_name))

        return JSONResponse(
            status_code=200,
            content={
                "message": "분석 및 적재 성공",
                "index_name": index_name,
                "saved": success,
                "failed": failed,
                "records_returned": len(records),
                "mask": mask,
                "keyword_types": sorted(list({r.get("keyword_type") for r in records}))
            }
        )

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/")
async def root():
    return {"message": "Elasticsearch Upload API", "status": "running"}

@app.get("/health")
async def health_check():
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
    try:
        indices = es.indices.get_alias(index="*")
        index_list = [
            {
                "name": index_name,
                "aliases": list(info.get("aliases", {}).keys())
            }
            for index_name, info in indices.items()
            if not index_name.startswith(".")
        ]
        return {"total": len(index_list), "indices": index_list}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/fields/{index_name}")
async def get_fields(index_name: str):
    try:
        if not es.indices.exists(index=index_name):
            raise HTTPException(status_code=404, detail=f"인덱스 '{index_name}'를 찾을 수 없습니다")

        mapping = es.indices.get_mapping(index=index_name)
        fields = []
        properties = mapping[index_name]['mappings'].get('properties', {})

        for field_name, field_info in properties.items():
            fields.append({"name": field_name, "type": field_info.get('type', 'object')})

        return {"index_name": index_name, "total_fields": len(fields), "fields": fields}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/data/{index_name}")
async def get_data(index_name: str, size: int = 100, from_: int = 0):
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
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
