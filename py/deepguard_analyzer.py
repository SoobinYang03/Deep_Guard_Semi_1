#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
DeepGuard Analyzer (file-based)
- Input: file_text (string), filename
- Output: list[format_database] records, split by leak type
- Default: mask/hash sensitive indicators before storing raw_text
"""

import re
import uuid
import hashlib
from dataclasses import dataclass
from datetime import date
from typing import Dict, List, Tuple, Any, Optional


# -------------------------
# Regex indicators
# -------------------------
EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,255}\.[A-Za-z]{2,24}\b")
EMAIL_PASS_RE = re.compile(
    r"(?P<email>[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,255}\.[A-Za-z]{2,24})"
    r"\s*[:;]\s*(?P<pw>[^\s:;]{3,})"
)
USER_PASS_RE = re.compile(
    r"(?i)(user(name)?|login)\s*[:=]\s*(?P<user>[^\s,;]+).{0,60}?"
    r"(pass(word)?|pwd)\s*[:=]\s*(?P<pw>[^\s,;]+)"
)

HASH_RE = re.compile(r"\b[0-9a-f]{32,64}\b", re.IGNORECASE)
CARD_RE = re.compile(
    r"\b(?:4[0-9]{12}(?:[0-9]{3})?"
    r"|5[1-5][0-9]{14}"
    r"|3[47][0-9]{13}"
    r"|6(?:011|5[0-9]{2})[0-9]{12})\b"
)

AWS_KEY_RE = re.compile(r"\bAKIA[0-9A-Z]{16}\b")
GITHUB_PAT_RE = re.compile(r"\bghp_[0-9A-Za-z]{36}\b")
STRIPE_SK_RE = re.compile(r"\bsk_live_[0-9A-Za-z]{24,}\b")
SLACK_TOKEN_RE = re.compile(r"\bxox[abp]-[0-9A-Za-z-]{10,}\b")
JWT_RE = re.compile(r"\beyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{5,}\b")

SSH_PUBKEY_RE = re.compile(r"\bssh-(rsa|ed25519|dss)\s+[A-Za-z0-9+/=]{20,}\b")

DB_URI_RE = re.compile(
    r"(?i)\b(?:postgres|mysql|mssql|oracle)://"
    r"(?P<user>[^:@\s]+):(?P<pw>[^:@\s]+)@(?P<host>[^:/\s]+)"
)
CONFIG_LINE_RE = re.compile(
    r"(?i)\b(pass(word)?|pwd|secret|api[_-]?key|token)\s*=\s*['\"]?([^'\"\s]{4,})['\"]?"
)

IPV4_RE = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
)


# -------------------------
# Format (fixed spec)
# -------------------------
def format_database(keyword_type: str, text: str, filename: str, leak_date: date) -> Dict[str, Any]:
    return {
        "id": str(uuid.uuid4()),
        "keyword_type": keyword_type,
        "source_id": "File",                 # 고정
        "original_link": filename,           # 분석 프로그램이므로 파일명
        "raw_text": text,                    # (가능하면 원문 / 또는 마스킹된 원문)
        "leak_date": str(leak_date),
    }


# -------------------------
# Masking helpers
# -------------------------
def _sha256(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8", errors="ignore")).hexdigest()

def mask_email(email: str) -> str:
    # user@domain.com -> user#<sha12>@domain.com 형태
    try:
        local, domain = email.split("@", 1)
        return f"{local}#sha12:{_sha256(email)[:12]}@{domain}"
    except Exception:
        return f"email#sha12:{_sha256(email)[:12]}"

def mask_token(tok: str) -> str:
    return f"token#sha12:{_sha256(tok)[:12]}"

def mask_secret(val: str) -> str:
    return f"secret#sha12:{_sha256(val)[:12]}"

def apply_masking(line: str) -> str:
    # 이메일/토큰/키 등을 라인에서 찾아서 해시 치환
    line2 = line

    # emails
    for e in set(EMAIL_RE.findall(line2)):
        line2 = line2.replace(e, mask_email(e))

    # tokens/keys
    for rgx in [AWS_KEY_RE, GITHUB_PAT_RE, STRIPE_SK_RE, SLACK_TOKEN_RE, JWT_RE]:
        for t in set(rgx.findall(line2)):
            # JWT_RE는 findall이 전체 매치 문자열 반환, 나머지도 동일
            line2 = line2.replace(t, mask_token(t))

    # 카드번호
    for c in set(CARD_RE.findall(line2)):
        line2 = line2.replace(c, f"card#sha12:{_sha256(c)[:12]}")

    # db uri user/pw
    m = DB_URI_RE.search(line2)
    if m:
        line2 = line2.replace(m.group("pw"), mask_secret(m.group("pw")))

    # config line 값
    m2 = CONFIG_LINE_RE.search(line2)
    if m2:
        val = m2.group(3)
        if val:
            line2 = line2.replace(val, mask_secret(val))

    return line2


# -------------------------
# Analyzer core
# -------------------------
@dataclass
class HitBucket:
    lines: List[str]
    count: int

def _push(bucket: Dict[str, List[str]], key: str, line: str, limit: int = 200) -> None:
    if key not in bucket:
        bucket[key] = []
    if len(bucket[key]) < limit:
        bucket[key].append(line)

def analyze_file_content(
    file_text: str,
    filename: str,
    leak_date: date,
    *,
    mask: bool = True,
    max_lines_scan: int = 200000,
    email_dump_threshold: int = 20
) -> List[Dict[str, Any]]:
    """
    Returns: list of formatted records (split by type)
    - mask=True: 저장 raw_text에 민감값(이메일/토큰/카드/시크릿)을 해시치환
    """

    # 1) 라인 스캔
    buckets: Dict[str, List[str]] = {}
    emails_found: List[str] = []

    lines = file_text.splitlines()
    if len(lines) > max_lines_scan:
        lines = lines[:max_lines_scan]

    for raw in lines:
        s = raw.strip()
        if not s:
            continue

        # collect emails for email_dump
        for e in EMAIL_RE.findall(s):
            emails_found.append(e)

        # classify by type, store lines
        if EMAIL_PASS_RE.search(s) or USER_PASS_RE.search(s):
            _push(buckets, "credential_leak", s)
            continue

        if any(r.search(s) for r in [AWS_KEY_RE, GITHUB_PAT_RE, STRIPE_SK_RE, SLACK_TOKEN_RE, JWT_RE]):
            _push(buckets, "token_leak", s)
            continue

        if CARD_RE.search(s):
            _push(buckets, "financial_leak", s)
            continue

        if DB_URI_RE.search(s) or CONFIG_LINE_RE.search(s):
            _push(buckets, "config_leak", s)
            continue

        if SSH_PUBKEY_RE.search(s):
            _push(buckets, "infra_leak", s)
            continue

        # (원하면 IP도 별도 타입으로 저장 가능)
        if IPV4_RE.search(s):
            _push(buckets, "ip_indicator", s)
            continue

    # 2) email_dump 타입 추가 (조건 충족 시)
    uniq_emails = list(dict.fromkeys(emails_found))
    if len(uniq_emails) >= email_dump_threshold:
        # 이메일 덤프는 이메일 자체를 저장하면 위험하니, 라인 대신 이메일 목록을 만들되 마스킹
        if mask:
            email_lines = [mask_email(e) for e in uniq_emails[:500]]
        else:
            email_lines = uniq_emails[:500]
        buckets["email_dump"] = email_lines

    # 3) 타입별 레코드 생성
    records: List[Dict[str, Any]] = []
    for leak_type, hit_lines in buckets.items():
        if not hit_lines:
            continue

        # 저장 텍스트 만들기 (너무 길어지면 컷)
        out_lines = hit_lines[:200]
        if mask:
            out_lines = [apply_masking(x) for x in out_lines]

        raw_text = "\n".join(out_lines)
        records.append(format_database(leak_type, raw_text, filename, leak_date))

    return records
