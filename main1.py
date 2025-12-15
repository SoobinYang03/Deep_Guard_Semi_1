from fastapi import FastAPI, UploadFile, File, HTTPException, Query
from fastapi.responses import JSONResponse
import pandas as pd
import os
import tempfile
from elasticsearch import Elasticsearch, helpers

# ✅ analyzer import
import deepguard_analyzer as dga

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

def file_to_text(tmp_file_path: str, content_type: str) -> str:
    """
    업로드된 파일을 analyzer가 먹을 수 있는 'text'로 변환
    - CSV/TSV/JSON/NDJSON: DataFrame -> TSV 문자열
    - 그 외(텍스트): 그대로 읽기
    """
    _, ext = os.path.splitext(tmp_file_path)
    ext = ext.lower()

    # 데이터 파일이면 표를 텍스트로 만들어 분석
    if ext in (".csv", ".tsv", ".json", ".ndjson"):
        df = load_file_to_dataframe(tmp_file_path, content_type)
        # ✅ analyzer가 패턴(이메일, user:pass 등) 잘 잡도록 "탭 구분 텍스트"로 변환
        return df.to_csv(sep="\t", index=False)
    else:
        # 일반 텍스트로 처리
        with open(tmp_file_path, "r", encoding="utf-8", errors="ignore") as f:
            return f.read()

def doc_generator(rows, index_name):
    """Bulk API를 위한 Generator"""
    for row in rows:
        yield {
            "_index": index_name,
            "_source": row
        }

@app.post("/upload")
async def upload_analyze_and_ingest(
    file: UploadFile = File(...),
    index_name: str = None,
    analyze: bool = Query(True, description="True면 deepguard_analyzer로 분석 후 적재"),
    mask: bool = Query(True, description="True면 analyzer raw_text에 마스킹 적용"),
    leak_date: str = Query(None, description="원하면 수동 leak_date 지정(없으면 UTC now)"),
):
    """
    ✅ 업로드 → (옵션) analyzer 분석 → ES bulk 적재
    - analyze=True: analyzer 결과만 ES에 적재
    - analyze=False: 기존처럼 파일 전체를 DataFrame으로 읽어 그대로 적재(원하면 유지)
    """
    tmp_file_path = None
    try:
        if index_name is None:
            index_name = os.path.splitext(file.filename)[0]

        # 임시 파일 생성
        suffix = os.path.splitext(file.filename)[1] or ".tmp"
        with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp_file:
            content = await file.read()
            tmp_file.write(content)
            tmp_file_path = tmp_file.name

        # ✅ (1) analyze=True 이면 analyzer로 분석
        if analyze:
            text = file_to_text(tmp_file_path, file.content_type)

            # analyzer 호출 (✅ 여기서 filename은 original_link로 들어감)
            rows = dga.analyze_text(
                text=text,
                filename=file.filename,
                leak_date=leak_date,
                mask=mask,
            )

            # 저장 조건 미달이면 rows가 [] 일 수 있음
            if not rows:
                return JSONResponse(
                    status_code=200,
                    content={
                        "message": "분석 완료 - 저장 조건 미달(적재 없음)",
                        "index_name": index_name,
                        "uploaded_file": file.filename,
                        "analyze": True,
                        "mask": mask,
                        "ingested": 0,
                    },
                )

            # ES bulk 적재
            success, failed = helpers.bulk(es, doc_generator(rows, index_name))

            return JSONResponse(
                status_code=200,
                content={
                    "message": "분석 + 적재 성공",
                    "index_name": index_name,
                    "uploaded_file": file.filename,
                    "analyze": True,
                    "mask": mask,
                    "success": success,
                    "failed": failed,
                    "total_docs": len(rows),
                },
            )

        # ✅ (2) analyze=False면 기존 방식(그대로 적재)
        df = load_file_to_dataframe(tmp_file_path, file.content_type)
        success, failed = helpers.bulk(es, doc_generator(df.to_dict(orient="records"), index_name))

        return JSONResponse(
            status_code=200,
            content={
                "message": "원본 적재 성공(분석 없이)",
                "index_name": index_name,
                "uploaded_file": file.filename,
                "analyze": False,
                "success": success,
                "failed": failed,
                "total_records": len(df),
            },
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
