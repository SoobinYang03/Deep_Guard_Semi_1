#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
hashed_analyzer.py
입력: 로컬 텍스트 파일 / STDIN(파이프) / JSONL에서 text 필드
처리: 이메일/계정(이메일:패스) / 토큰 / 카드 / IP 패턴 매칭
출력: 원문 미저장, 해시 + 카운트 + threat_type + severity (JSONL)
용도: 과제용 통계/중복 제거/정확도 평가

사용 예:
  1) 파일 입력:
     python3 hashed_analyzer.py --in sample.txt --out output/hashed_results.jsonl

  2) 파이프 입력:
     cat sample.txt | python3 hashed_analyzer.py --stdin --out output/hashed_results.jsonl

  3) JSONL(text 필드) 입력:
     python3 hashed_analyzer.py --jsonl input_pages.jsonl --text-key text --out output/hashed_results.jsonl
"""

import argparse
import hashlib
import json
import os
import re
import sys
from dataclasses import dataclass
from datetime import datetime, UTC
from typing import Any, Dict, Iterable, List, Optional, Tuple

# -------------------------
# Patterns (과제/리포트용 기본셋)
# -------------------------

EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
EMAIL_PASS_RE = re.compile(
    r"(?P<email>[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,})\s*[:;]\s*(?P<pw>[^\s:;]{3,})"
)

# 범용 토큰 예시(과제용): AWS/GitHub/Stripe + JWT
AWS_KEY_RE = re.compile(r"\bAKIA[0-9A-Z]{16}\b")
GITHUB_PAT_RE = re.compile(r"\bghp_[0-9A-Za-z]{36}\b")
STRIPE_SK_RE = re.compile(r"\bsk_live_[0-9A-Za-z]{24,}\b")
JWT_RE = re.compile(r"\beyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{5,}\b")

# 카드(단순 패턴, Luhn 검증은 과제에서 굳이 안해도 됨)
CARD_RE = re.compile(
    r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b"
)

IPV4_RE = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}"
    r"(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"
)

# -------------------------
# Hashing
# -------------------------

def sha256_hex(s: str, salt: str) -> str:
    return hashlib.sha256((salt + s).encode("utf-8", errors="ignore")).hexdigest()

def uniq_hashes(values: Iterable[str], salt: str, limit: int) -> List[str]:
    seen = set()
    out: List[str] = []
    for v in values:
        hv = sha256_hex(v, salt)
        if hv not in seen:
            seen.add(hv)
            out.append(hv)
            if len(out) >= limit:
                break
    return out

# -------------------------
# Classification
# -------------------------

def classify_and_score(counts: Dict[str, int]) -> Tuple[str, str]:
    """
    threat_type: credential_leak / token_leak / financial_leak / email_dump / none
    severity: low / medium / high / critical
    """
    creds = counts.get("credentials", 0)
    tokens = counts.get("tokens", 0)
    cards = counts.get("cards", 0)
    emails = counts.get("emails", 0)

    if creds > 0:
        threat = "credential_leak"
        if creds >= 100 or emails >= 500:
            sev = "critical"
        elif creds >= 20 or emails >= 100:
            sev = "high"
        else:
            sev = "medium"
        return threat, sev

    if tokens > 0:
        threat = "token_leak"
        sev = "critical" if tokens >= 3 else "high"
        return threat, sev

    if cards > 0:
        threat = "financial_leak"
        sev = "critical" if cards >= 10 else "high"
        return threat, sev

    if emails >= 20:
        threat = "email_dump"
        if emails >= 1000:
            sev = "critical"
        elif emails >= 100:
            sev = "high"
        else:
            sev = "medium"
        return threat, sev

    return "none", "low"

# -------------------------
# Analyze
# -------------------------

def analyze_text(text: str, salt: str) -> Dict[str, Any]:
    emails = EMAIL_RE.findall(text)

    creds_pairs = []
    for m in EMAIL_PASS_RE.finditer(text):
        # 원문을 저장하지 않고 (email:pw)를 하나의 토큰처럼 취급해서 해시만 남긴다
        creds_pairs.append(f"{m.group('email')}:{m.group('pw')}")

    tokens = []
    tokens += AWS_KEY_RE.findall(text)
    tokens += GITHUB_PAT_RE.findall(text)
    tokens += STRIPE_SK_RE.findall(text)
    tokens += JWT_RE.findall(text)

    cards = CARD_RE.findall(text)
    ips = IPV4_RE.findall(text)

    counts = {
        "emails": len(emails),
        "credentials": len(creds_pairs),
        "tokens": len(tokens),
        "cards": len(cards),
        "ips": len(ips),
    }

    threat_type, severity = classify_and_score(counts)

    # “원문 미저장” 원칙: 아래에는 해시만 남김
    hashed = {
        "emails": uniq_hashes(emails, salt, limit=500),
        "credentials": uniq_hashes(creds_pairs, salt, limit=500),
        "tokens": uniq_hashes(tokens, salt, limit=200),
        "cards": uniq_hashes(cards, salt, limit=200),
        "ips": uniq_hashes(ips, salt, limit=200),
    }

    return {
        "created_at": datetime.now(UTC).isoformat(),
        "threat_type": threat_type,
        "severity": severity,
        "counts": counts,
        "hashes": hashed,
    }

# -------------------------
# IO
# -------------------------

def read_text_file(path: str) -> str:
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        return f.read()

def iter_jsonl_text(path: str, text_key: str) -> Iterable[Tuple[int, str, Dict[str, Any]]]:
    """
    yields: (line_no, text, raw_obj)
    """
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for i, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except Exception:
                continue
            text = obj.get(text_key)
            if isinstance(text, str) and text:
                yield i, text, obj

def write_jsonl(path: str, obj: Dict[str, Any]) -> None:
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "a", encoding="utf-8") as f:
        f.write(json.dumps(obj, ensure_ascii=False) + "\n")

# -------------------------
# Main
# -------------------------

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--in", dest="infile", help="input text file path")
    ap.add_argument("--stdin", action="store_true", help="read input from stdin")
    ap.add_argument("--jsonl", help="input jsonl file (each line is JSON)")
    ap.add_argument("--text-key", default="text", help="json key holding text (default: text)")
    ap.add_argument("--out", required=True, help="output jsonl file path")
    ap.add_argument("--source-id", default=None, help="optional source identifier (file/url/etc)")
    ap.add_argument("--salt", default=None, help="optional salt (default: run_id)")
    args = ap.parse_args()

    run_id = datetime.now(UTC).strftime("%Y%m%d_%H%M%S")
    salt = args.salt or run_id

    if args.infile:
        text = read_text_file(args.infile)
        row = analyze_text(text, salt=salt)
        row.update({"run_id": run_id, "source": args.source_id or args.infile})
        write_jsonl(args.out, row)
        print(f"[ok] wrote 1 record -> {args.out}")
        return

    if args.stdin:
        text = sys.stdin.read()
        row = analyze_text(text, salt=salt)
        row.update({"run_id": run_id, "source": args.source_id or "stdin"})
        write_jsonl(args.out, row)
        print(f"[ok] wrote 1 record -> {args.out}")
        return

    if args.jsonl:
        wrote = 0
        for line_no, text, raw in iter_jsonl_text(args.jsonl, args.text_key):
            row = analyze_text(text, salt=salt)
            # 원문을 저장하지 않고, 출처/라인/URL 같은 메타만 보존
            meta = {
                "run_id": run_id,
                "source": args.source_id or args.jsonl,
                "line_no": line_no,
            }
            # url 같은 비민감 메타는 있으면 보존
            if isinstance(raw.get("url"), str):
                meta["url"] = raw["url"]
            row.update(meta)
            write_jsonl(args.out, row)
            wrote += 1

        print(f"[ok] wrote {wrote} records -> {args.out}")
        return

    print("Choose one input: --in OR --stdin OR --jsonl")
    sys.exit(2)

if __name__ == "__main__":
    main()
