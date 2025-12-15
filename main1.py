from fastapi import FastAPI, UploadFile, File, HTTPException, Query
from fastapi.responses import JSONResponse
import pandas as pd
import json
import os
import tempfile
from elasticsearch import Elasticsearch, helpers

import deepguard_analyzer as dga  # ✅ analyzer import

app = FastAPI()

es = Elasticsearch(
    "http://localhost:9200",
    verify_certs=False
)

# -------------------------
# 파일을 DataFrame으로 변환
# -------------------------
def load_file_to_dataframe(file_path, content_type):
    _, ext = os.path.splitext(file_path)
    ext = ext.lower()

    if ext == ".csv" or content_type == "text/csv":
        df = pd.read_csv(file_path)
    elif ext == ".tsv" or content_type == "text/tab-separated-values":
        df = pd.read_csv(file_path, sep="\t")
    elif ext == ".json" or content_type == "application/json":
        df = pd.read_json(file_path)
    elif ext in (".ndjson", ".jsonl"):
        df = pd.read_json(file_path, lines=True)
    else:
        raise ValueError(f"지원하지 않는 파일 형식입니다: {ext}")

    return df.fillna("")

def doc_generator(docs, index_name):
    for doc in docs:
        yield {"_index": index_name, "_source": doc}

def df_to_text_rows(df: pd.DataFrame, max_rows: int = 2000) -> list[str]:
    rows = []
    for i, row in df.head(max_rows).iterrows():
        parts = []
        for k, v in row.items():
            parts.append(f"{k}: {v}")
        rows.append("\n".join(parts))
    return rows

# -------------------------
# Upload -> (Analyzer optional) -> ES bulk
# -------------------------
@app.post("/upload")
async def upload_to_elasticsearch(
    file: UploadFile = File(...),
    index_name: str = None,
    analyze: bool = Query(True, description="true면 analyzer 실행 후 적재, false면 원본 그대로 적재"),
    mask: bool = Query(True, description="analyze=true일 때 마스킹 적용 여부"),
    row_mode: bool = Query(True, description="csv/tsv/json/ndjson이면 row 단위 분석할지 여부"),
):
    """
    - analyze=false: 기존처럼 파일 내용을 그대로 ES에 업로드
    - analyze=true: 업로드 파일을 text로 읽어 deepguard_analyzer로 분석 후, 저장 대상만 ES bulk 적재
      * 저장 미달이어도 verdict/reason을 API 응답에 포함
    """
    tmp_file_path = None

    # 마지막 판정/사유 (저장 0건일 때도 응답에 넣기)
    last_verdict = None
    last_reason = None

    try:
        if index_name is None:
            index_name = os.path.splitext(file.filename)[0]

        # 임시 파일 생성
        suffix = os.path.splitext(file.filename)[1]
        with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp_file:
            content = await file.read()
            tmp_file.write(content)
            tmp_file_path = tmp_file.name

        ext = suffix.lower()

        # -------------------------
        # analyze = false (원본 그대로 업로드)
        # -------------------------
        if not analyze:
            df = load_file_to_dataframe(tmp_file_path, file.content_type)
            success, failed = helpers.bulk(es, (
                {"_index": index_name, "_source": row.to_dict()} for _, row in df.iterrows()
            ))
            return JSONResponse(
                status_code=200,
                content={
                    "message": "업로드 성공 (analyze=false, raw ingest)",
                    "index_name": index_name,
                    "success": success,
                    "failed": failed,
                    "total_records": len(df),
                    "analyze": analyze
                }
            )

        # -------------------------
        # analyze = true (Analyzer -> docs -> bulk ingest)
        # -------------------------
        docs_to_ingest = []
        analyzed_rows = 0
        skipped_rows = 0

        # 1) 텍스트 파일인 경우: 전체를 text로 분석
        if ext in (".txt", ".log", ".md"):
            text = content.decode("utf-8", errors="ignore")
            meta = dga.analyze_text_with_meta(
                text=text,
                filename=file.filename,
                mask=mask,
                extra_meta={"file_mode": "full_text"}
            )
            docs_to_ingest.extend(meta["saved_rows"])
            analyzed_rows = 1
            last_verdict = meta["verdict"]
            last_reason = meta["reason"]

        # 2) 테이블 파일인 경우: df 로딩 후 row 단위 분석 or 전체 합쳐 분석
        else:
            df = load_file_to_dataframe(tmp_file_path, file.content_type)

            if row_mode:
                rows = df_to_text_rows(df, max_rows=5000)
                for i, row_text in enumerate(rows):
                    meta = dga.analyze_text_with_meta(
                        text=row_text,
                        filename=file.filename,
                        mask=mask,
                        extra_meta={"file_row": i}
                    )
                    if meta["saved_rows"]:
                        docs_to_ingest.extend(meta["saved_rows"])
                        analyzed_rows += 1
                    else:
                        skipped_rows += 1
                        last_verdict = meta["verdict"]
                        last_reason = meta["reason"]
            else:
                # 전체를 하나의 text로 합쳐서 분석
                big_text = "\n\n".join(df_to_text_rows(df, max_rows=5000))
                meta = dga.analyze_text_with_meta(
                    text=big_text,
                    filename=file.filename,
                    mask=mask,
                    extra_meta={"file_mode": "merged_rows"}
                )
                docs_to_ingest.extend(meta["saved_rows"])
                analyzed_rows = 1
                last_verdict = meta["verdict"]
                last_reason = meta["reason"]

        # 실제 bulk 적재
        if docs_to_ingest:
            success, failed = helpers.bulk(es, doc_generator(docs_to_ingest, index_name))
            return JSONResponse(
                status_code=200,
                content={
                    "message": "분석+적재 성공",
                    "index_name": index_name,
                    "uploaded_file": file.filename,
                    "analyze": analyze,
                    "mask": mask,
                    "analyzer_docs": len(docs_to_ingest),
                    "bulk_success": success,
                    "bulk_failed": failed,
                    "analyzed_rows": analyzed_rows,
                    "skipped_rows": skipped_rows,
                    "reason": last_reason,
                    "verdict": last_verdict,
                }
            )

        # 저장(적재) 대상이 0건인 경우도 reason/verdict 포함
        return JSONResponse(
            status_code=200,
            content={
                "message": "분석 완료 - 저장 조건 미달(적재 없음)",
                "index_name": index_name,
                "uploaded_file": file.filename,
                "analyze": analyze,
                "mask": mask,
                "analyzer_docs": 0,
                "analyzed_rows": analyzed_rows,
                "skipped_rows": skipped_rows,
                "reason": last_reason,
                "verdict": last_verdict,
            }
        )

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

    finally:
        if tmp_file_path and os.path.exists(tmp_file_path):
            try:
                os.unlink(tmp_file_path)
            except Exception:
                pass


# -------------------------
# API 상태 확인
# -------------------------
@app.get("/")
async def root():
    return {"message": "Elasticsearch Upload API", "status": "running"}

@app.get("/health")
async def health_check():
    try:
        info = es.info()
        return {
            "elasticsearch": "connected",
            "cluster_name": info.get("cluster_name"),
            "version": info.get("version", {}).get("number")
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
        props = mapping[index_name]["mappings"].get("properties", {})
        fields = [{"name": k, "type": v.get("type", "object")} for k, v in props.items()]
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
        hits = response["hits"]["hits"]
        documents = [h["_source"] for h in hits]
        return {
            "index_name": index_name,
            "total": response["hits"]["total"]["value"],
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
            search_query = {"query": {"multi_match": {"query": query, "type": "best_fields"}}, "size": size}

        if min_score is not None:
            search_query["min_score"] = min_score

        response = es.search(index=index_name, body=search_query)
        hits = response["hits"]["hits"]
        documents = [hit["_source"] for hit in hits]
        scores = [hit["_score"] for hit in hits]

        return {
            "index_name": index_name,
            "query": query,
            "field": field,
            "min_score": min_score,
            "total": response["hits"]["total"]["value"],
            "size": len(documents),
            "documents": documents,
            "scores": scores
        }

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/search-all-indices")
async def search_all_indices(email: str, size: int = 100):
    try:
        all_indices = es.indices.get_alias(index="*")
        index_names = [n for n in all_indices.keys() if not n.startswith(".")]

        if not index_names:
            return {"email": email, "total_indices_searched": 0, "results": []}

        search_query = {
            "query": {"multi_match": {"query": email, "type": "phrase", "fields": ["*"]}},
            "size": size
        }

        results = []
        total_found = 0

        for idx in index_names:
            try:
                resp = es.search(index=idx, body=search_query)
                hits = resp["hits"]["hits"]
                if hits:
                    docs = [{**h["_source"], "_score": h["_score"]} for h in hits]
                    results.append({
                        "index_name": idx,
                        "total_hits": resp["hits"]["total"]["value"],
                        "returned_hits": len(docs),
                        "documents": docs
                    })
                    total_found += resp["hits"]["total"]["value"]
            except Exception:
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
