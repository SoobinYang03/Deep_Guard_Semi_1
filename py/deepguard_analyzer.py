# deepguard_analyzer.py
#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
DeepGuard Analyzer (import-friendly)

- Designed to be imported from FastAPI main.py
- Analyze uploaded file content (text/csv/tsv/json/ndjson...)
- Return results in unified crawler DB format (multiple records)
- Masking/Hashing is optional (mask=True/False)

Output format:
{
  "id": "<uuid4>",
  "keyword_type": "<threat category>",
  "source_id": "File",
  "original_link": "<filename>",
  "raw_text": "<evidence text (optionally masked)>",
  "leak_date": "<iso datetime>"
}
"""

from __future__ import annotations

import hashlib
import json
import re
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple


# -------------------------
# Regex indicators (safe subset)
# -------------------------
EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,255}\.[A-Za-z]{2,24}")
IPV4_RE = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
)

# credentials patterns
EMAIL_PASS_RE = re.compile(
    r"(?P<email>[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,255}\.[A-Za-z]{2,24})"
    r"\s*[:;]\s*(?P<pw>[^\s:;]{3,})"
)
USER_PASS_RE = re.compile(
    r"(?i)(user(name)?|login)\s*[:=]\s*(?P<user>[^\s,;]+).{0,40}?"
    r"(pass(word)?|pwd)\s*[:=]\s*(?P<pw>[^\s,;]+)"
)

# token-ish patterns (대표만)
AWS_KEY_RE = re.compile(r"\bAKIA[0-9A-Z]{16}\b")
GITHUB_PAT_RE = re.compile(r"\bghp_[0-9A-Za-z]{36}\b")
STRIPE_SK_RE = re.compile(r"\bsk_live_[0-9A-Za-z]{24,}\b")
JWT_RE = re.compile(r"\beyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{5,}\b")
SLACK_TOKEN_RE = re.compile(r"\bxox[abp]-[0-9A-Za-z-]{10,}\b")
TELEGRAM_BOT_RE = re.compile(r"\b[0-9]{7,10}:[A-Za-z0-9_-]{20,}\b")

# infra/config patterns
SSH_PUBKEY_RE = re.compile(r"\bssh-(rsa|ed25519|dss)\s+[A-Za-z0-9+/=]{20,}\b")
DB_URI_RE = re.compile(
    r"(?i)\b(?:postgres|mysql|mssql|oracle)://"
    r"(?P<user>[^:@\s]+):(?P<pw>[^:@\s]+)@(?P<host>[^:/\s]+)"
)
CONFIG_LINE_RE = re.compile(
    r"(?i)\b(pass(word)?|pwd|secret|api_key|token)\s*=\s*['\"]?([^'\"\s]{4,})['\"]?"
)

# light PII patterns
PHONE_KR_RE = re.compile(r"\b01[016789]-?\d{3,4}-?\d{4}\b")
SSN_RE = re.compile(r"\b[0-9]{3}-[0-9]{2}-[0-9]{4}\b")  # US SSN (예시)


# -------------------------
# Utilities
# -------------------------
def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()

def sha256_hex(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8", errors="ignore")).hexdigest()

def unique_list(items: List[str], limit: Optional[int] = None) -> List[str]:
    seen = set()
    out = []
    for x in items:
        if x not in seen:
            seen.add(x)
            out.append(x)
        if limit is not None and len(out) >= limit:
            break
    return out

def format_database(keyword_type: str, raw_text: str, filename: str, leak_date: str) -> Dict[str, Any]:
    return {
        "id": str(uuid.uuid4()),
        "keyword_type": keyword_type,
        "source_id": "File",
        "original_link": filename,   # 분석이므로 URL 대신 파일명
        "raw_text": raw_text,
        "leak_date": str(leak_date),
    }


# -------------------------
# Extraction + classification
# -------------------------
@dataclass
class Indicators:
    credentials: int
    tokens: int
    financial: int
    config: int
    infra: int
    email_count: int
    pii: int
    sample_lines: List[str]
    matched_emails: List[str]
    matched_ips: List[str]
    matched_tokens: List[str]


def _extract_indicators(text: str) -> Indicators:
    lines = text.splitlines()

    creds = 0
    tokens = 0
    financial = 0  # 카드패턴은 여기선 생략(원하면 추가 가능)
    config = 0
    infra = 0
    pii = 0

    sample_lines: List[str] = []
    emails: List[str] = []
    ips: List[str] = []
    token_hits: List[str] = []

    for line in lines:
        s = line.strip()
        if not s:
            continue

        # emails / ips (counts + list)
        for m in EMAIL_RE.findall(s):
            emails.append(m)
        for m in IPV4_RE.findall(s):
            ips.append(m)

        # credentials
        if EMAIL_PASS_RE.search(s) or USER_PASS_RE.search(s):
            creds += 1
            if len(sample_lines) < 30:
                sample_lines.append(s)

        # tokens
        found_tok = False
        for rx in (AWS_KEY_RE, GITHUB_PAT_RE, STRIPE_SK_RE, JWT_RE, SLACK_TOKEN_RE, TELEGRAM_BOT_RE):
            for m in rx.findall(s):
                found_tok = True
                token_hits.append(m if isinstance(m, str) else str(m))
        if found_tok:
            tokens += 1
            if len(sample_lines) < 30:
                sample_lines.append(s)

        # infra/config
        if SSH_PUBKEY_RE.search(s):
            infra += 1
            if len(sample_lines) < 30:
                sample_lines.append(s)

        if DB_URI_RE.search(s) or CONFIG_LINE_RE.search(s):
            config += 1
            if len(sample_lines) < 30:
                sample_lines.append(s)

        # PII-ish
        if PHONE_KR_RE.search(s) or SSN_RE.search(s):
            pii += 1
            if len(sample_lines) < 30:
                sample_lines.append(s)

    email_unique = unique_list(emails)
    ip_unique = unique_list(ips)
    token_unique = unique_list(token_hits)

    return Indicators(
        credentials=creds,
        tokens=tokens,
        financial=financial,
        config=config,
        infra=infra,
        email_count=len(email_unique),
        pii=pii,
        sample_lines=unique_list(sample_lines, limit=30),
        matched_emails=email_unique[:200],
        matched_ips=ip_unique[:200],
        matched_tokens=token_unique[:200],
    )


def _decide_keyword_types(ind: Indicators) -> List[str]:
    """
    '여러건으로 쪼개서 저장' 요구 반영:
    발견된 성격별로 keyword_type 여러 개를 반환할 수 있음.
    """
    types: List[str] = []

    if ind.credentials > 0:
        types.append("credential_leak")
    if ind.tokens > 0:
        types.append("token_leak")
    if ind.config > 0:
        types.append("config_leak")
    if ind.infra > 0:
        types.append("infrastructure_leak")
    if ind.pii > 0:
        types.append("identity_leak")
    if ind.email_count >= 50:
        types.append("email_dump")

    # 아무것도 없으면 빈 리스트
    return types


# -------------------------
# Masking (optional)
# -------------------------
def _mask_text(text: str) -> str:
    """
    원문을 완전히 없애는 게 아니라,
    이메일/IP/토큰 문자열을 sha256로 치환하는 방식(가벼운 마스킹).
    """
    # 이메일 마스킹
    def repl_email(m: re.Match) -> str:
        return f"email_sha256:{sha256_hex(m.group(0))}"

    # IPv4 마스킹
    def repl_ip(m: re.Match) -> str:
        return f"ip_sha256:{sha256_hex(m.group(0))}"

    text = EMAIL_RE.sub(repl_email, text)
    text = IPV4_RE.sub(repl_ip, text)

    # 토큰류 마스킹 (패턴이 길어서 line 단위보다 전체 치환)
    for rx in (AWS_KEY_RE, GITHUB_PAT_RE, STRIPE_SK_RE, JWT_RE, SLACK_TOKEN_RE, TELEGRAM_BOT_RE):
        text = rx.sub(lambda m: f"token_sha256:{sha256_hex(m.group(0))}", text)

    return text


# -------------------------
# Public API: main.py에서 부를 함수
# -------------------------
def analyze_bytes(
    file_bytes: bytes,
    filename: str,
    leak_date: Optional[str] = None,
    mask: bool = True,
    max_text_chars: int = 2_000_000,
) -> List[Dict[str, Any]]:
    """
    FastAPI에서 업로드 받은 bytes를 넣으면,
    표준 포맷(list[dict])으로 결과를 반환.
    """
    if leak_date is None:
        leak_date = utc_now_iso()

    # decode (깨져도 진행)
    text = file_bytes.decode("utf-8", errors="ignore")
    if len(text) > max_text_chars:
        text = text[:max_text_chars]

    ind = _extract_indicators(text)
    keyword_types = _decide_keyword_types(ind)

    if not keyword_types:
        # 저장할 게 없으면 빈 리스트 반환(=ES 적재도 안함)
        return []

    # 근거(raw_text): “원문이 있다면 원문” 요구를 최대한 반영하되,
    # 너무 길어지면 sample_lines + 요약으로 구성
    evidence = []
    evidence.append(f"[DeepGuardAnalyzer] filename={filename}")
    evidence.append(f"- emails(unique)={ind.email_count}, creds_lines={ind.credentials}, tokens_lines={ind.tokens}, config_lines={ind.config}, infra_lines={ind.infra}, pii_lines={ind.pii}")
    if ind.sample_lines:
        evidence.append("\n[examples]")
        evidence.extend(ind.sample_lines[:20])

    # 원문 그대로 쓰고 싶다면 아래 주석 해제 가능(권장 X: 너무 큼)
    # evidence.append("\n[raw_text_begin]\n" + text[:5000] + "\n[raw_text_end]")

    raw_text = "\n".join(evidence)
    if mask:
        raw_text = _mask_text(raw_text)

    # keyword_type 별로 “여러 건” 생성
    out: List[Dict[str, Any]] = []
    for kt in keyword_types:
        out.append(format_database(
            keyword_type=kt,
            raw_text=raw_text,
            filename=filename,
            leak_date=leak_date
        ))
    return out


def analyze_file_path(
    file_path: str,
    filename_for_link: Optional[str] = None,
    leak_date: Optional[str] = None,
    mask: bool = True
) -> List[Dict[str, Any]]:
    """
    로컬 파일 경로로 분석할 때(테스트/CLI 용).
    """
    with open(file_path, "rb") as f:
        b = f.read()
    return analyze_bytes(
        file_bytes=b,
        filename=filename_for_link or file_path,
        leak_date=leak_date,
        mask=mask
    )
