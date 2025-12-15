from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.responses import JSONResponse
import pandas as pd
import json
import os
import tempfile
from typing import List, Dict, Any, Optional
from elasticsearch import Elasticsearch, helpers

# ✅ analyzer import
from deepguard_analyzer import analyze_text  # deepguard_analyzer.py와 같은 폴더에 있어야 함

app = FastAPI()

es = Elasticsearch(
    "http://localhost:9200",
    verify_certs=False
)

def load_file_to_dataframe(file_path, content_type):
    """파일을 DataFrame으로 변환 (기존 로직 유지)"""
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
    """Bulk API를 위한 Generator (원본 업로드용)"""
    for _, row in df.iterrows():
        yield {
            "_index": index_name,
            "_source": row.to_dict()
        }

def bulk_docs(index_name: str, docs: List[Dict[str, Any]]):
    """분석 결과 docs를 ES Bulk로 적재"""
    def gen():
        for d in docs:
            yield {"_index": index_name, "_source": d}
    return helpers.bulk(es, gen())

def file_to_text_for_analyzer(file_path: str, content_type: str) -> str:
    """
    Analyzer용 텍스트로 변환:
    - CSV/TSV/JSON/NDJSON은 DataFrame -> 문자열로 펼쳐서 분석
    - (원하면 여기서 '특정 컬럼만' 분석하도록 개선 가능)
    """
    _, ext = os.path.splitext(file_path)
    ext = ext.lower()

    # 텍스트 파일이면 그냥 읽기
    if ext in (".txt", ".log"):
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            return f.read()

    # 구조화 파일은 DF로 읽고, "행 단위 문자열"로 변환
    df = load_file_to_dataframe(file_path, content_type)
    lines = []
    cols = list(df.columns)

    for _, row in df.iterrows():
        # key=value 형태로 펼침 (정규식 탐지에 잘 걸림)
        parts = []
        for c in cols:
            v = row.get(c, "")
            if v is None:
                v = ""
            parts.append(f"{c}={v}")
        lines.append(" | ".join(parts))

    return "\n".join(lines)

@app.post("/upload")
async def upload_to_elasticsearch(
    file: UploadFile = File(...),
    index_name: str = None,
    analyze: bool = True,                 # ✅ 분석할지 여부
    hits_index: str = None,               # ✅ 분석 결과 인덱스 이름 (기본: {index_name}_hits)
    leak_date: Optional[str] = None,      # ✅ 유출 시점(없으면 analyzer가 now로 넣음)
    mask: Optional[bool] = None           # ✅ 마스킹 on/off (None이면 env(DG_MASK) 따름)
):
    """
    파일을 Elasticsearch에 업로드 + (옵션) DeepGuard Analyzer로 분석 후 hits도 적재
    - file: CSV, TSV, JSON, NDJSON, TXT, LOG
    - index_name: 원본 업로드 인덱스(기본: 파일명)
    - analyze: True면 analyzer 실행
    - hits_index: 분석 결과 인덱스명(기본: {index_name}_hits)
    """
    tmp_file_path = None
    try:
        if index_name is None:
            index_name = os.path.splitext(file.filename)[0]

        if hits_index is None:
            hits_index = f"{index_name}_hits"

        suffix = os.path.splitext(file.filename)[1]
        with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp_file:
            content = await file.read()
            tmp_file.write(content)
            tmp_file_path = tmp_file.name

        # 1) 원본 업로드 (기존 기능 유지)
        df = load_file_to_dataframe(tmp_file_path, file.content_type)
        success_raw, failed_raw = helpers.bulk(es, doc_generator(df, index_name))

        # 2) Analyzer 실행 + hits 업로드
        saved_hits = 0
        if analyze:
            text = file_to_text_for_analyzer(tmp_file_path, file.content_type)
            docs = analyze_text(
                text=text,
                filename=file.filename,
                leak_date=leak_date,
                mask=mask
            )
            if docs:
                success_hits, failed_hits = bulk_docs(hits_index, docs)
                saved_hits = len(docs)
            else:
                success_hits, failed_hits = 0, 0
        else:
            success_hits, failed_hits = 0, 0

        os.unlink(tmp_file_path)

        return JSONResponse(
            status_code=200,
            content={
                "message": "업로드 성공",
                "raw_index": index_name,
                "hits_index": hits_index,
                "raw": {
                    "success": success_raw,
                    "failed": failed_raw,
                    "total_records": len(df)
                },
                "hits": {
                    "analyzed": analyze,
                    "saved_hits": saved_hits,
                    "success": success_hits,
                    "failed": failed_hits
                }
            }
        )

    except Exception as e:
        if tmp_file_path and os.path.exists(tmp_file_path):
            os.unlink(tmp_file_path)
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/")
async def root():
    return {"message": "Elasticsearch Upload API (+DeepGuard Analyzer)", "status": "running"}

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
