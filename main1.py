from fastapi import FastAPI, UploadFile, File, HTTPException, Query
from fastapi.responses import JSONResponse
import pandas as pd
import os
import tempfile
from datetime import datetime, timezone, date
from elasticsearch import Elasticsearch, helpers

# ✅ DeepGuard Analyzer import
# deepguard_analyzer.py 에 analyze_file_content 가 있어야 함
from deepguard_analyzer import analyze_file_content

app = FastAPI()

es = Elasticsearch(
    "http://localhost:9200",
    verify_certs=False
)

# ----------------------------
# 기존: 파일 → DataFrame 로딩
# ----------------------------
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
        raise ValueError(f"지원하지 않는 파일 형식입니다: {ext}")

    return df.fillna('')

def doc_generator_from_df(df, index_name):
    for _, row in df.iterrows():
        yield {"_index": index_name, "_source": row.to_dict()}

# ----------------------------
# ✅ Analyzer 결과 → Bulk 제너레이터
# ----------------------------
def doc_generator_from_records(records, index_name):
    for r in records:
        yield {"_index": index_name, "_source": r}

def guess_leak_date() -> str:
    # 기본값: 오늘(UTC). 필요하면 파일명/내용에서 파싱 로직 추가 가능
    return str(date.today())

@app.post("/upload")
async def upload_to_elasticsearch(
    file: UploadFile = File(...),
    index_name: str = None,

    # ✅ analyze=true면 deepguard_analyzer 실행
    analyze: bool = Query(default=False),

    # ✅ mask=false면 마스킹/해싱 OFF (원문 저장)
    mask: bool = Query(default=True),

    # ✅ keyword_type을 라벨링(없으면 analyzer가 추론한 값 사용)
    keyword_type: str = Query(default="leak_indicator"),

    # ✅ leak_date 수동 지정 (없으면 기본 today)
    leak_date: str = Query(default=None),
):
    """
    파일을 Elasticsearch에 업로드

    - analyze=false: 기존처럼 CSV/TSV/JSON/NDJSON → DataFrame → bulk 적재
    - analyze=true : deepguard_analyzer로 분석 → 결과 레코드(list[dict]) → bulk 적재

    쿼리 예시:
      /upload?analyze=true&mask=true&index_name=deepguard_hits
      /upload?analyze=true&mask=false
    """
    tmp_file_path = None
    try:
        if index_name is None:
            index_name = os.path.splitext(file.filename)[0]

        # 임시 파일 생성
        suffix = os.path.splitext(file.filename)[1]
        with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp_file:
            content = await file.read()
            tmp_file.write(content)
            tmp_file_path = tmp_file.name

        # ----------------------------
        # ✅ Analyzer 모드
        # ----------------------------
        if analyze:
            # 텍스트 읽기(분석용). 바이너리면 decode 실패할 수 있으니 errors=ignore
            with open(tmp_file_path, "rb") as f:
                raw = f.read()
            text = raw.decode("utf-8", errors="ignore")

            leak_date_final = leak_date or guess_leak_date()

            # ✅ Analyzer 호출 (여기서 여러 건으로 쪼개짐)
            # analyze_file_content는 list[dict] 반환하도록 만들어둔 버전 기준
            records = analyze_file_content(
                file_text=text,
                filename=file.filename,     # original_link에 파일명 넣기 위함
                leak_date=leak_date_final,
                keyword_type=keyword_type,
                mask=mask,
            )

            if not records:
                return JSONResponse(
                    status_code=200,
                    content={
                        "message": "분석 결과 저장할 레코드가 없습니다(조건 미달).",
                        "index_name": index_name,
                        "total_records": 0,
                        "mask": mask
                    }
                )

            success, failed = helpers.bulk(
                es,
                doc_generator_from_records(records, index_name),
                raise_on_error=False
            )

            return JSONResponse(
                status_code=200,
                content={
                    "message": "분석+업로드 성공",
                    "mode": "analyzer",
                    "index_name": index_name,
                    "success": success,
                    "failed": failed,
                    "total_records": len(records),
                    "mask": mask,
                }
            )

        # ----------------------------
        # 기존 업로드 모드 (DataFrame)
        # ----------------------------
        df = load_file_to_dataframe(tmp_file_path, file.content_type)
        success, failed = helpers.bulk(es, doc_generator_from_df(df, index_name), raise_on_error=False)

        return JSONResponse(
            status_code=200,
            content={
                "message": "업로드 성공",
                "mode": "raw_upload",
                "index_name": index_name,
                "success": success,
                "failed": failed,
                "total_records": len(df)
            }
        )

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        if tmp_file_path and os.path.exists(tmp_file_path):
            os.unlink(tmp_file_path)

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
            {"name": index_name, "aliases": list(info.get("aliases", {}).keys())}
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
        properties = mapping[index_name]['mappings'].get('properties', {})

        fields = [{"name": field_name, "type": field_info.get('type', 'object')}
                  for field_name, field_info in properties.items()]

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

@app.get("/search/{index_name}")
async def search_data(index_name: str, query: str, field: str = None, size: int = 100, min_score: float = None):
    try:
        if not es.indices.exists(index=index_name):
            raise HTTPException(status_code=404, detail=f"인덱스 '{index_name}'를 찾을 수 없습니다")

        if field:
            search_query = {"query": {"match": {field: query}}, "size": size}
        else:
            search_query = {"query": {"multi_match": {"query": query, "type": "best_fields", "fields": ["*"]}}, "size": size}

        if min_score is not None:
            search_query["min_score"] = min_score

        response = es.search(index=index_name, body=search_query)
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
