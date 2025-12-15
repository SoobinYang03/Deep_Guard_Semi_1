from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.responses import JSONResponse
import pandas as pd
import os
import tempfile
from typing import List, Dict, Any, Optional

from elasticsearch import Elasticsearch, helpers

# ✅ analyzer import
import deepguard_analyzer as dga

app = FastAPI()

ES_URL = os.getenv("ES_URL", "http://localhost:9200").strip()
DEFAULT_INDEX = os.getenv("DG_ES_INDEX", "deepguard_hits").strip()

# 테이블 파일(CSV/TSV/JSON/NDJSON)일 때 row 단위 분석 최대치
DG_MAX_ROWS = int(os.getenv("DG_MAX_ROWS", "2000"))

es = Elasticsearch(
    ES_URL,
    verify_certs=False
)

def load_file_to_dataframe(file_path: str, content_type: Optional[str]) -> pd.DataFrame:
    """파일을 DataFrame으로 변환"""
    _, ext = os.path.splitext(file_path)
    ext = ext.lower()
    ct = (content_type or "").lower()

    if ext == ".csv" or ct == "text/csv":
        df = pd.read_csv(file_path)
    elif ext == ".tsv" or ct == "text/tab-separated-values":
        df = pd.read_csv(file_path, sep="\t")
    elif ext == ".json" or ct == "application/json":
        df = pd.read_json(file_path)
    elif ext == ".ndjson":
        df = pd.read_json(file_path, lines=True)
    else:
        raise ValueError(f"지원하지 않는 파일 형식입니다: {ext}")

    return df.fillna("")

def dataframe_row_to_text(row: pd.Series) -> str:
    """DataFrame row를 analyzer에 넣을 텍스트로 변환"""
    # key=value 형태로 만들면 탐지에 유리함
    parts = []
    for k, v in row.to_dict().items():
        s = str(v)
        if not s:
            continue
        parts.append(f"{k}={s}")
    return "\n".join(parts)

def bulk_actions(index_name: str, docs: List[Dict[str, Any]]):
    """ES bulk actions generator"""
    for d in docs:
        _id = d.get("id")
        action = {
            "_index": index_name,
            "_source": d
        }
        if _id:
            action["_id"] = _id
        yield action

@app.post("/upload")
async def upload_to_elasticsearch(
    file: UploadFile = File(...),
    index_name: str = None,
    analyze: bool = True,
    mask: Optional[bool] = None
):
    """
    파일 업로드 → (옵션) DeepGuard Analyzer 분석 → ES bulk 적재
    - file: TXT/CSV/TSV/JSON/NDJSON
    - index_name: 없으면 DEFAULT_INDEX 사용
    - analyze: True면 analyzer 호출해서 "통일 포맷" docs 생성 후 적재
    - mask: True/False 지정 시 analyzer 마스킹 강제, None이면 DG_MASK 환경변수 따름
    """
    tmp_file_path = None
    try:
        if index_name is None:
            index_name = DEFAULT_INDEX

        # 임시 파일 생성
        suffix = os.path.splitext(file.filename)[1]
        with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp_file:
            content = await file.read()
            tmp_file.write(content)
            tmp_file_path = tmp_file.name

        ext = suffix.lower()
        ct = (file.content_type or "").lower()

        docs_to_ingest: List[Dict[str, Any]] = []
        analyzed_rows = 0
        skipped_rows = 0

        # 1) 테이블류: row 단위 분석(여러건 저장에 유리)
        if ext in (".csv", ".tsv", ".json", ".ndjson") or ct in ("text/csv", "text/tab-separated-values", "application/json"):
            df = load_file_to_dataframe(tmp_file_path, file.content_type)

            if not analyze:
                # analyze=False면 그냥 원본을 그대로 적재(기존 기능 유지)
                # (주의: 원본 스키마 그대로 들어감)
                success, failed = helpers.bulk(es, ({"_index": index_name, "_source": r} for r in df.to_dict(orient="records")))
                return JSONResponse(
                    status_code=200,
                    content={
                        "message": "업로드 성공 (analyze=False, raw ingest)",
                        "index_name": index_name,
                        "success": success,
                        "failed": failed,
                        "total_records": len(df),
                    }
                )

            # analyze=True: row 단위로 analyzer 호출
            max_rows = min(len(df), DG_MAX_ROWS)
            for i in range(max_rows):
                row_text = dataframe_row_to_text(df.iloc[i])
                extra = {"file_row": i}
                rows = dga.analyze_text(
                    row_text,
                    filename=file.filename,   # original_link는 파일명으로 고정
                    mask=mask,
                    extra_meta=extra
                )
                if rows:
                    docs_to_ingest.extend(rows)
                    analyzed_rows += 1
                else:
                    skipped_rows += 1

        # 2) 텍스트류: 파일 전체를 한번에 분석
        else:
            # 텍스트 추정 (binary면 깨질 수 있으니 errors=ignore)
            with open(tmp_file_path, "r", encoding="utf-8", errors="ignore") as f:
                text = f.read()

            if not analyze:
                # analyze=False면 "한 문서"로 원본 텍스트 적재
                doc = {
                    "id": file.filename,
                    "source_id": "File",
                    "original_link": file.filename,
                    "raw_text": text[:20000],
                    "ts": dga.utc_now_iso(),
                    "note": "raw_ingest(analyze=False)"
                }
                success, failed = helpers.bulk(es, bulk_actions(index_name, [doc]))
                return JSONResponse(
                    status_code=200,
                    content={
                        "message": "업로드 성공 (analyze=False, raw text ingest)",
                        "index_name": index_name,
                        "success": success,
                        "failed": failed,
                        "ingested": 1
                    }
                )

            rows = dga.analyze_text(
                text,
                filename=file.filename,
                mask=mask,
                extra_meta={"file_mode": "full_text"}
            )
            docs_to_ingest.extend(rows)
            analyzed_rows = 1 if rows else 0

        # analyzer 결과가 없으면 적재 없음
        if not docs_to_ingest:
            return JSONResponse(
                status_code=200,
                content={
                    "message": "분석 완료 - 저장 조건 미달(적재 없음)",
                    "hint": "DG_DEBUG=1로 실행하면 analyzer가 왜 스킵했는지 로그로 출력합니다.",
                    "index_name": index_name,
                    "uploaded_file": file.filename,
                    "analyze": analyze,
                    "mask": mask,
                    "analyzer_docs": 0,
                    "analyzed_rows": analyzed_rows,
                    "skipped_rows": skipped_rows
                }
            )

        # ES bulk 적재
        success, failed = helpers.bulk(es, bulk_actions(index_name, docs_to_ingest))

        return JSONResponse(
            status_code=200,
            content={
                "message": "업로드+분석+적재 성공",
                "index_name": index_name,
                "uploaded_file": file.filename,
                "analyze": analyze,
                "mask": mask,
                "success": success,
                "failed": failed,
                "analyzer_docs": len(docs_to_ingest),
                "analyzed_rows": analyzed_rows,
                "skipped_rows": skipped_rows
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

@app.get("/")
async def root():
    return {"message": "DeepGuard Upload+Analyzer API", "status": "running"}

@app.get("/health")
async def health_check():
    try:
        info = es.info()
        return {
            "elasticsearch": "connected",
            "cluster_name": info.get("cluster_name"),
            "version": info.get("version", {}).get("number"),
            "es_url": ES_URL,
            "default_index": DEFAULT_INDEX
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
