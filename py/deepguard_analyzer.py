#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
DeepGuard Analyzer (file-based)
- main.py에서 import해서 업로드된 파일(텍스트/CSV/TSV/JSON/NDJSON)을 분석
- ✅ extract_indicators / classify_threat / score_severity "필수 3함수" 포함
- score_page 기반으로 (leak_type, severity, score, confidence) 산출
- ✅ threat_type(=leak_type)별 저장 기준 맵 적용
- ✅ 마스킹 on/off 토글 지원 (DG_MASK=1/0)
- ✅ 디버그 로그 토글 (DG_DEBUG=1)
- 출력 포맷: format_database() 기반 + 부가 필드(severity/score/counts/signals 등) 추가
- 여러건 저장: 대표 1건 + examples N건
"""

import os
import re
import uuid
import hashlib
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

# =========================
# Env toggles / defaults
# =========================
DG_MASK_DEFAULT = os.getenv("DG_MASK", "1").strip()  # 1=mask on, 0=off
DG_DEBUG = os.getenv("DG_DEBUG", "0").strip()        # 1=debug on

# Optional overrides
DG_SAVE_MAP = os.getenv("DG_SAVE_MAP", "").strip()   # e.g. "email_dump=high,credential_leak=medium"
DG_SAVE_MIN_SEVERITY = os.getenv("DG_SAVE_MIN_SEVERITY", "").strip().lower()  # global override: low/medium/high/critical

# =========================
# severity ordering
# =========================
_SEV_RANK = {"low": 0, "medium": 1, "high": 2, "critical": 3}

def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()

def sha256_hex(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8", errors="ignore")).hexdigest()

def _dbg(msg: str) -> None:
    if DG_DEBUG == "1":
        print(f"[DG_ANALYZER][DEBUG] {msg}")

# =========================
# Regex indicators (필요 최소)
# =========================
EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,255}\.[A-Za-z]{2,24}\b")
EMAIL_PASS_RE = re.compile(
    r"(?P<email>[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,255}\.[A-Za-z]{2,24})\s*[:;]\s*(?P<pw>[^\s:;]{3,})"
)
USER_PASS_RE = re.compile(
    r"(?i)(user(name)?|login)\s*[:=]\s*(?P<user>[^\s,;]+).{0,40}?(pass(word)?|pwd)\s*[:=]\s*(?P<pw>[^\s,;]+)"
)
HASH_RE = re.compile(r"\b[0-9a-f]{32,64}\b", re.IGNORECASE)
CARD_RE = re.compile(
    r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b"
)
AWS_KEY_RE = re.compile(r"\bAKIA[0-9A-Z]{16}\b")
GITHUB_PAT_RE = re.compile(r"\bghp_[0-9A-Za-z]{36}\b")
STRIPE_SK_RE = re.compile(r"\bsk_live_[0-9A-Za-z]{24,}\b")
JWT_RE = re.compile(r"\beyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{5,}\b")
SSH_PUBKEY_RE = re.compile(r"\bssh-(rsa|ed25519|dss)\s+[A-Za-z0-9+/=]{20,}\b")
DB_URI_RE = re.compile(
    r"(?i)\b(?:postgres|mysql|mssql|oracle)://(?P<user>[^:@\s]+):(?P<pw>[^:@\s]+)@(?P<host>[^:/\s]+)"
)
CONFIG_LINE_RE = re.compile(
    r"(?i)\b(pass(word)?|pwd|secret|api_key|token)\s*=\s*['\"]?([^'\"\s]{4,})['\"]?"
)

LEAK_HINT_WORDS = [
    "database dump", "db dump", "full dump", "combo list", "credentials",
    "stolen data", "leaked data", "exfiltrated", "data leak", "ransomware",
    "password list", "email:pass", "user:pass", "stealer log", "infostealer",
    "config leak", "api key", "private key"
]

FORUM_HINT_WORDS = [
    "forum", "thread", "board", "posts", "reply", "replies", "members",
    "registration", "register", "profile", "subforum"
]

NEWS_HINT_WORDS = [
    "newsletter", "press", "blog", "announcement", "news", "article",
    "copyright", "terms of service", "privacy policy"
]

LOGIN_PATTERNS = [
    "login", "log-in", "sign in", "signin", "/login", "/signin", "account/login"
]

def looks_like_login(text: str) -> bool:
    lower = text[:900].lower()
    return any(p in lower for p in LOGIN_PATTERNS)

def _unique(items: List[str]) -> List[str]:
    seen = set()
    out = []
    for x in items:
        if x not in seen:
            seen.add(x)
            out.append(x)
    return out

# ==========================================================
# ✅ (필수 1) extract_indicators(text)
# ==========================================================
def extract_indicators(text: str) -> Dict[str, Any]:
    lines = text.splitlines()

    creds: List[Dict[str, str]] = []
    emails, hashes, cards, tokens = [], [], [], []
    ssh_keys, db_uris, config_lines = [], [], []
    hit_examples = []

    for line in lines:
        s = line.strip()
        if not s:
            continue

        for m in EMAIL_RE.findall(s):
            emails.append(m)

        for m in EMAIL_PASS_RE.finditer(s):
            creds.append({"email": m.group("email"), "password": m.group("pw"), "pattern": "email:password"})
            hit_examples.append(s)

        for m in USER_PASS_RE.finditer(s):
            creds.append({"username": m.group("user"), "password": m.group("pw"), "pattern": "user/pass"})
            hit_examples.append(s)

        for h in HASH_RE.findall(s):
            hashes.append(h)

        for c in CARD_RE.findall(s):
            cards.append(c)

        for t in AWS_KEY_RE.findall(s):
            tokens.append(t)
        for t in GITHUB_PAT_RE.findall(s):
            tokens.append(t)
        for t in STRIPE_SK_RE.findall(s):
            tokens.append(t)
        for t in JWT_RE.findall(s):
            tokens.append(t)

        if SSH_PUBKEY_RE.search(s):
            ssh_keys.append(s)

        for m in DB_URI_RE.finditer(s):
            db_uris.append({"user": m.group("user"), "password": m.group("pw"), "host": m.group("host")})

        if CONFIG_LINE_RE.search(s):
            config_lines.append(s)

    return {
        "credentials": creds,
        "emails": _unique(emails),
        "hashes": _unique(hashes),
        "cards": _unique(cards),
        "tokens": _unique(tokens),
        "ssh_keys": _unique(ssh_keys),
        "db_uri": db_uris,
        "config": _unique(config_lines),
        "examples": _unique(hit_examples)[:30],
    }

# ==========================================================
# ✅ (필수 2) classify_threat(indicators)
# ==========================================================
def classify_threat(ind: Dict[str, Any]) -> str:
    if ind.get("credentials"):
        return "credential_leak"
    if ind.get("cards"):
        return "financial_leak"
    if ind.get("tokens"):
        return "token_leak"
    if ind.get("db_uri") or ind.get("config"):
        return "config_leak"
    if ind.get("ssh_keys"):
        return "infra_leak"
    if len(ind.get("emails", [])) >= 50:
        return "email_dump"
    return "none"

# ==========================================================
# ✅ (필수 3) score_severity(threat_type, indicators)
# ==========================================================
def score_severity(threat_type: str, ind: Dict[str, Any]) -> str:
    creds = len(ind.get("credentials", []))
    emails = len(ind.get("emails", []))
    cards = len(ind.get("cards", []))
    tokens = len(ind.get("tokens", []))

    if threat_type == "none":
        return "low"

    if threat_type == "credential_leak":
        if creds >= 100 or emails >= 500:
            return "critical"
        if creds >= 20 or emails >= 100:
            return "high"
        return "medium"

    if threat_type == "financial_leak":
        return "critical" if cards >= 10 else "high"

    if threat_type == "token_leak":
        return "critical" if tokens >= 3 else "high"

    if threat_type == "config_leak":
        return "critical"

    if threat_type == "infra_leak":
        return "high"

    if threat_type == "email_dump":
        if emails >= 1000:
            return "critical"
        if emails >= 200:
            return "high"
        return "medium"

    return "low"

# =========================
# score_page 기반 verdict
# =========================
@dataclass
class Verdict:
    leak_type: str
    severity: str
    score: int
    confidence: str
    signals: Dict[str, Any]

def _score_page(text: str, ind: Dict[str, Any]) -> Verdict:
    t = text[:3500].lower()

    has_leak_words = any(w in t for w in LEAK_HINT_WORDS)
    forumish = any(w in t for w in FORUM_HINT_WORDS)
    newsish = any(w in t for w in NEWS_HINT_WORDS)
    loginish = looks_like_login(text)

    creds = len(ind.get("credentials", []))
    cards = len(ind.get("cards", []))
    tokens = len(ind.get("tokens", []))
    emails = len(ind.get("emails", []))
    config = len(ind.get("config", []))
    dburi = len(ind.get("db_uri", []))
    sshk = len(ind.get("ssh_keys", []))

    score = 0
    score += min(10, creds * 2)
    score += min(10, cards * 2)
    score += min(10, tokens * 3)
    score += min(6, dburi * 3)
    score += min(6, config * 2)
    score += min(6, sshk * 2)

    if emails >= 50:
        score += 2
    if emails >= 200:
        score += 3
    if has_leak_words:
        score += 3

    # FP reducers
    if forumish and not (creds or cards or tokens or dburi or config or sshk):
        score -= 5
    if newsish and not (creds or cards or tokens or dburi or config or sshk):
        score -= 4
    if loginish:
        score -= 8

    leak_type = classify_threat(ind)
    severity = score_severity(leak_type, ind)

    if score >= 8:
        conf = "high"
    elif score >= 4:
        conf = "medium"
    else:
        conf = "low"

    signals = {
        "has_leak_words": has_leak_words,
        "is_forumish": forumish,
        "is_newsish": newsish,
        "is_loginish": loginish,
        "counts": {
            "credentials": creds,
            "cards": cards,
            "tokens": tokens,
            "emails": emails,
            "config": config,
            "db_uri": dburi,
            "ssh_keys": sshk,
        }
    }

    if leak_type == "none":
        severity = "low"

    return Verdict(leak_type=leak_type, severity=severity, score=score, confidence=conf, signals=signals)

# =========================
# 저장 기준: threat_type별 맵
# =========================
DEFAULT_SAVE_MIN_BY_TYPE = {
    # 민감 타입은 medium부터 저장 권장
    "token_leak": "medium",
    "config_leak": "medium",
    "infra_leak": "medium",
    "credential_leak": "medium",

    # 노이즈 큰 타입은 high부터 권장
    "email_dump": "high",
    "financial_leak": "high",
}

def _parse_save_map(env_s: str) -> Dict[str, str]:
    out: Dict[str, str] = {}
    if not env_s:
        return out
    for part in env_s.split(","):
        part = part.strip()
        if not part or "=" not in part:
            continue
        k, v = part.split("=", 1)
        k = k.strip()
        v = v.strip().lower()
        if v in _SEV_RANK:
            out[k] = v
    return out

def get_min_severity_for_type(leak_type: str) -> str:
    if DG_SAVE_MIN_SEVERITY in _SEV_RANK:
        return DG_SAVE_MIN_SEVERITY
    custom = _parse_save_map(DG_SAVE_MAP)
    return custom.get(leak_type) or DEFAULT_SAVE_MIN_BY_TYPE.get(leak_type, "high")

def should_save_by_type(verdict: Verdict) -> bool:
    if verdict.leak_type == "none":
        return False
    min_sev = get_min_severity_for_type(verdict.leak_type)
    return _SEV_RANK.get(verdict.severity, 0) >= _SEV_RANK.get(min_sev, 2)

# =========================
# Masking (on/off)
# =========================
def _mask_email_line(line: str) -> str:
    # a***@domain.com 형태(라인 내 첫 이메일만 처리)
    m = EMAIL_RE.search(line)
    if not m:
        return line
    e = m.group(0)
    local, _, domain = e.partition("@")
    if len(local) <= 1:
        masked = "*" + "@" + domain
    else:
        masked = local[0] + "***@" + domain
    return line.replace(e, masked)

def _mask_secret_like(line: str) -> str:
    # 토큰/키/패스워드류를 sha256:xxxx 형태로 축약 치환
    def repl(_m):
        raw = _m.group(0)
        return "sha256:" + sha256_hex(raw)[:16]
    line = AWS_KEY_RE.sub(repl, line)
    line = GITHUB_PAT_RE.sub(repl, line)
    line = STRIPE_SK_RE.sub(repl, line)
    line = JWT_RE.sub(repl, line)
    return line

def apply_masking(text: str, enabled: bool) -> str:
    if not enabled:
        return text
    out = []
    for line in text.splitlines():
        x = _mask_email_line(line)
        x = _mask_secret_like(x)
        out.append(x)
    return "\n".join(out)

# =========================
# Output formatter (요구 포맷 + 추가필드)
# =========================
def format_database(keyword_type: str, raw_text: str, original_link: str, leak_date: str) -> Dict[str, Any]:
    return {
        "id": str(uuid.uuid4()),
        "keyword_type": keyword_type,
        "source_id": "File",
        "original_link": original_link,  # analyzer니까 파일명
        "raw_text": raw_text,
        "leak_date": str(leak_date),
    }

# =========================
# Public API: analyze_text
# =========================
def analyze_text(
    text: str,
    filename: str,
    leak_date: Optional[str] = None,
    mask: Optional[bool] = None,
    extra_meta: Optional[Dict[str, Any]] = None,
) -> List[Dict[str, Any]]:
    """
    main.py에서 호출:
      rows = analyze_text(text, filename=file.filename, leak_date=..., mask=..., extra_meta=...)
    반환: ES에 그대로 넣을 수 있는 dict 리스트(여러 건)
    """
    if leak_date is None:
        leak_date = utc_now_iso()

    if mask is None:
        mask = (DG_MASK_DEFAULT != "0")

    if extra_meta is None:
        extra_meta = {}

    ind = extract_indicators(text)
    verdict = _score_page(text, ind)
    min_sev = get_min_severity_for_type(verdict.leak_type)

    counts = verdict.signals.get("counts", {})
    _dbg(f"file={filename} leak_type={verdict.leak_type} severity={verdict.severity} score={verdict.score} conf={verdict.confidence}")
    _dbg(f"counts={counts}")
    _dbg(f"save_min_for_type={min_sev} (global_override={DG_SAVE_MIN_SEVERITY or 'none'})")

    reason = None
    if verdict.leak_type == "none":
        reason = "threat_type=none (no strong indicators)"
    elif _SEV_RANK.get(verdict.severity, 0) < _SEV_RANK.get(min_sev, 2):
        reason = f"severity_too_low (got={verdict.severity}, need>={min_sev})"

    if reason:
        _dbg(f"SKIP reason={reason}")
        return []

    _dbg("SAVE decision=pass")

    masked_text = apply_masking(text, enabled=mask)
    base_raw = (masked_text[:4000]).strip() or "(empty)"

    rows: List[Dict[str, Any]] = []

    # 대표 1건
    doc = format_database(
        keyword_type=verdict.leak_type,
        raw_text=base_raw,
        original_link=filename,
        leak_date=leak_date,
    )
    doc.update({
        "ts": utc_now_iso(),
        "severity": verdict.severity,
        "score": verdict.score,
        "confidence": verdict.confidence,
        "counts": counts,
        "signals": {k: v for k, v in verdict.signals.items() if k != "counts"},
        "mask_applied": bool(mask),
        "save_min_severity": min_sev,
        "analyzer_version": "deepguard_analyzer_v1",
        **extra_meta,
    })
    rows.append(doc)

    # example 여러 건
    examples = ind.get("examples", []) or []
    for ex in examples[:10]:
        ex_text = apply_masking(ex, enabled=mask)
        ex_doc = format_database(
            keyword_type=f"{verdict.leak_type}_example",
            raw_text=ex_text[:1000],
            original_link=filename,
            leak_date=leak_date,
        )
        ex_doc.update({
            "ts": utc_now_iso(),
            "severity": verdict.severity,
            "score": verdict.score,
            "confidence": verdict.confidence,
            "mask_applied": bool(mask),
            "save_min_severity": min_sev,
            "analyzer_version": "deepguard_analyzer_v1",
            **extra_meta,
        })
        rows.append(ex_doc)

    _dbg(f"SAVED docs={len(rows)}")
    return rows
