#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
DeepGuard Crawler (restored + safer + monitored)

Key goals:
- Keep original crawl capability (BFS + seed loading + Tor for .onion)
- Reduce false positives (forum/news/discussion pages)
- Avoid aggressive precheck behavior (bounded HEAD)
- Always flush JSONL safely, even on Ctrl+C
- Write monitoring events to output/events.jsonl

Notes:
- This script stores NO full raw body. It stores only counts + small redacted samples.
- Masking/Hashing should be done in FastAPI layer (recommended).
"""

import argparse
import concurrent.futures as cf
import hashlib
import json
import os
import random
import re
import sys
import time
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse, urljoin

import requests
from bs4 import BeautifulSoup

# -------------------------
# Paths / output
# -------------------------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
OUTPUT_DIR = os.path.join(BASE_DIR, "output")
STATE_DIR = os.path.join(BASE_DIR, "state")
os.makedirs(OUTPUT_DIR, exist_ok=True)
os.makedirs(STATE_DIR, exist_ok=True)

RUN_ID = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
RESULTS_PATH = os.path.join(OUTPUT_DIR, f"deepguard_results_{RUN_ID}.jsonl")
EVENTS_PATH = os.path.join(OUTPUT_DIR, "events.jsonl")
ALIVE_SEEDS_PATH = os.path.join(STATE_DIR, "alive_seeds.jsonl")
SEEN_FP_PATH = os.path.join(STATE_DIR, "seen_fingerprints.json")

# -------------------------
# Crawl tuning (safer defaults)
# -------------------------
MAX_PAGES = 3000
MAX_DEPTH = 2
BATCH_SIZE = 50

# Networking
REQUEST_TIMEOUT = 45
HEAD_TIMEOUT = 8
MAX_RETRIES_GET = 2
MAX_RETRIES_HEAD = 1

BASE_DELAY = 0.35
JITTER = 1.0
BACKOFF_FACTOR = 1.8

# HEAD precheck control (major speed lever)
HEAD_ENABLED = True
HEAD_MAX = 700          # do not HEAD-check all seeds (prevents hours-long precheck)
HEAD_WORKERS = 8        # low concurrency to avoid Tor overload
HEAD_ONION_ONLY = True  # default: only precheck .onion via HEAD, skip clearweb HEAD

# Progress heartbeat
HEARTBEAT_EVERY_SEC = 20

# -------------------------
# Tor proxy
# -------------------------
TOR_PROXIES = {
    "http": "socks5h://127.0.0.1:9050",
    "https": "socks5h://127.0.0.1:9050",
}

DEFAULT_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (X11; Linux x86_64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/120.0 Safari/537.36"
    )
}

# -------------------------
# Seed loading (GitHub deepdarkCTI)
# -------------------------
GITHUB_REPO_URL = "https://raw.githubusercontent.com/fastfire/deepdarkCTI/main"
SEED_FILES = [
    "forum.md",
    "markets.md",
    "commercial_services.md",
    "counterfeit_goods.md",
    "defacement.md",
    "discord.md",
    "exploits.md",
    "maas.md",
    "malware_samples.md",
    "methods.md",
    "others.md",
    "phishing.md",
    "ransomware_gang.md",
    "rat.md",
    "search_engines.md",
    "telegram_infostealer.md",
    "telegram_threat_actors.md",
    "twitter.md",
    "twitter_threat_actors.md",
]

# -------------------------
# Leak & FP signals
# -------------------------
LEAK_HINT_WORDS = [
    "database dump", "db dump", "full dump", "combo list", "credentials",
    "stolen data", "leaked data", "exfiltrated", "data leak", "ransomware",
    "password list", "email:pass", "user:pass", "stealer log", "infostealer",
    "config leak", "api key", "private key"
]

FORUM_HINT_WORDS = [
    "forum", "thread", "board", "posts", "reply", "replies", "members",
    "registration", "register", "profile", "user cp", "subforum"
]

NEWS_HINT_WORDS = [
    "newsletter", "press", "blog", "announcement", "news", "article",
    "copyright", "terms of service", "privacy policy"
]

LOGIN_PATTERNS = [
    "login", "log-in", "sign in", "signin", "/login", "/signin", "account/login"
]

# -------------------------
# Regex indicators (keep what you already had)
# -------------------------
EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
EMAIL_PASS_RE = re.compile(
    r"(?P<email>[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,})"
    r"\s*[:;]\s*(?P<pw>[^\s:;]{3,})"
)
USER_PASS_RE = re.compile(
    r"(?i)(user(name)?|login)\s*[:=]\s*(?P<user>[^\s,;]+).{0,40}?"
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
IPV4_RE = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}"
    r"(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"
)
JWT_RE = re.compile(r"\beyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{5,}\b")
SSH_PUBKEY_RE = re.compile(r"\bssh-(rsa|ed25519|dss)\s+[A-Za-z0-9+/=]{20,}\b")
DB_URI_RE = re.compile(
    r"(?i)\b(?:postgres|mysql|mssql|oracle)://"
    r"(?P<user>[^:@\s]+):(?P<pw>[^:@\s]+)@(?P<host>[^:/\s]+)"
)
CONFIG_LINE_RE = re.compile(
    r"(?i)\b(pass(word)?|pwd|secret|api_key|token)\s*=\s*['\"]?([^'\"\s]{4,})['\"]?"
)

# -------------------------
# Utilities
# -------------------------
def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()

def log_event(obj: Dict[str, Any]) -> None:
    obj = dict(obj)
    obj.setdefault("ts", utc_now_iso())
    obj.setdefault("run_id", RUN_ID)
    with open(EVENTS_PATH, "a", encoding="utf-8") as f:
        f.write(json.dumps(obj, ensure_ascii=False) + "\n")

def sleep_with_jitter() -> None:
    time.sleep(BASE_DELAY + random.uniform(0, JITTER))

def is_onion(url: str) -> bool:
    try:
        host = urlparse(url).hostname or ""
        return host.endswith(".onion")
    except Exception:
        return False

def is_ipv6_literal_host(url: str) -> bool:
    try:
        host = urlparse(url).hostname or ""
        return ":" in host and not host.endswith(".onion")
    except Exception:
        return False

def looks_like_login(url: str, text: str) -> bool:
    lower = (url + " " + text[:600]).lower()
    return any(p in lower for p in LOGIN_PATTERNS)

def sha256_hex(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8", errors="ignore")).hexdigest()

def stable_fingerprint(url: str, title: str, snippet: str) -> str:
    base = f"{url}\n{title}\n{snippet[:400]}"
    return sha256_hex(base)

def load_seen_fps() -> Set[str]:
    if not os.path.exists(SEEN_FP_PATH):
        return set()
    try:
        with open(SEEN_FP_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, list):
            return set(data)
        return set()
    except Exception:
        return set()

def save_seen_fps(fps: Set[str]) -> None:
    tmp = SEEN_FP_PATH + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(sorted(list(fps)), f, ensure_ascii=False)
    os.replace(tmp, SEEN_FP_PATH)

# -------------------------
# Indicator extraction
# -------------------------
def unique_list(items: List[str]) -> List[str]:
    seen = set()
    out = []
    for x in items:
        if x not in seen:
            seen.add(x)
            out.append(x)
    return out

def extract_indicators(text: str) -> Dict[str, Any]:
    lines = text.splitlines()

    creds = []
    emails, hashes, cards, tokens, ips = [], [], [], [], []
    ssh_keys = []
    db_uris = []
    config_lines = []

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

        for ip in IPV4_RE.findall(s):
            ips.append(ip)

        if SSH_PUBKEY_RE.search(s):
            ssh_keys.append(s)

        for m in DB_URI_RE.finditer(s):
            db_uris.append({"user": m.group("user"), "password": m.group("pw"), "host": m.group("host")})

        if CONFIG_LINE_RE.search(s):
            config_lines.append(s)

    return {
        "credentials": creds,
        "emails": unique_list(emails),
        "hashes": unique_list(hashes),
        "cards": unique_list(cards),
        "tokens": unique_list(tokens),
        "ips": unique_list(ips),
        "ssh_keys": unique_list(ssh_keys),
        "db_uri": db_uris,
        "config": unique_list(config_lines),
        "examples": unique_list(hit_examples)[:30],
    }

# -------------------------
# Classification + scoring (FP reduction)
# -------------------------
@dataclass
class Verdict:
    leak_type: str         # credential_leak / token_leak / financial_leak / config_leak / infra_leak / email_dump / none
    severity: str          # low / medium / high / critical
    score: int
    confidence: str        # low / medium / high
    signals: Dict[str, Any]

def classify_type(ind: Dict[str, Any]) -> str:
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

def severity_for(leak_type: str, ind: Dict[str, Any]) -> str:
    creds = len(ind.get("credentials", []))
    emails = len(ind.get("emails", []))
    cards = len(ind.get("cards", []))
    tokens = len(ind.get("tokens", []))

    if leak_type == "none":
        return "low"
    if leak_type == "credential_leak":
        if creds >= 100 or emails >= 500:
            return "critical"
        if creds >= 20 or emails >= 100:
            return "high"
        return "medium"
    if leak_type == "financial_leak":
        return "critical" if cards >= 10 else "high"
    if leak_type == "token_leak":
        return "critical" if tokens >= 3 else "high"
    if leak_type == "config_leak":
        return "critical"
    if leak_type == "infra_leak":
        return "high"
    if leak_type == "email_dump":
        if emails >= 1000:
            return "critical"
        if emails >= 200:
            return "high"
        return "medium"
    return "low"

def score_page(url: str, title: str, text: str, ind: Dict[str, Any]) -> Verdict:
    t = (title + "\n" + text[:2000]).lower()

    has_leak_words = any(w in t for w in LEAK_HINT_WORDS)
    forumish = any(w in t for w in FORUM_HINT_WORDS) or any(x in url.lower() for x in ["/forum", "viewtopic", "showthread", "thread", "board"])
    newsish = any(w in t for w in NEWS_HINT_WORDS) or any(x in url.lower() for x in ["/blog", "/news", "/article", "/press"])

    creds = len(ind.get("credentials", []))
    cards = len(ind.get("cards", []))
    tokens = len(ind.get("tokens", []))
    emails = len(ind.get("emails", []))
    config = len(ind.get("config", []))
    dburi = len(ind.get("db_uri", []))
    sshk = len(ind.get("ssh_keys", []))

    signals = {
        "has_leak_words": has_leak_words,
        "is_forum": forumish,
        "is_news": newsish,
        "credentials": creds,
        "cards": cards,
        "tokens": tokens,
        "emails": emails,
        "config_lines": config,
        "db_uri": dburi,
        "ssh_keys": sshk,
    }

    score = 0

    # Strong positive signals
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
    if looks_like_login(url, text):
        score -= 8

    leak_type = classify_type(ind)
    severity = severity_for(leak_type, ind)

    # Confidence mapping
    if score >= 8:
        conf = "high"
    elif score >= 4:
        conf = "medium"
    else:
        conf = "low"

    # If type is none but score is low/negative, treat as none
    if leak_type == "none":
        severity = "low"

    return Verdict(leak_type=leak_type, severity=severity, score=score, confidence=conf, signals=signals)

def should_save(verdict: Verdict) -> bool:
    # Save only if we have real indicators OR strong score
    if verdict.leak_type in ("credential_leak", "token_leak", "financial_leak", "config_leak", "infra_leak"):
        return verdict.score >= 2
    if verdict.leak_type == "email_dump":
        return verdict.score >= 3
    return False

# -------------------------
# Fetch (HEAD/GET)
# -------------------------
class FetchError(Exception):
    pass

def _proxies_for(url: str) -> Optional[Dict[str, str]]:
    return TOR_PROXIES if is_onion(url) else None

def http_head(url: str) -> Optional[int]:
    if is_ipv6_literal_host(url):
        return None
    proxies = _proxies_for(url)
    for attempt in range(1, MAX_RETRIES_HEAD + 1):
        sleep_with_jitter()
        try:
            resp = requests.head(
                url,
                headers=DEFAULT_HEADERS,
                timeout=HEAD_TIMEOUT,
                proxies=proxies,
                allow_redirects=True,
            )
            return resp.status_code
        except requests.RequestException:
            time.sleep(BACKOFF_FACTOR ** attempt)
    return None

def http_get(url: str) -> Optional[requests.Response]:
    if is_ipv6_literal_host(url):
        return None
    proxies = _proxies_for(url)

    for attempt in range(1, MAX_RETRIES_GET + 1):
        sleep_with_jitter()
        try:
            resp = requests.get(
                url,
                headers=DEFAULT_HEADERS,
                timeout=REQUEST_TIMEOUT,
                proxies=proxies,
                allow_redirects=True,
            )
            if resp.status_code in (429, 503):
                time.sleep(BACKOFF_FACTOR ** attempt)
                continue
            resp.raise_for_status()
            return resp
        except requests.RequestException:
            time.sleep(BACKOFF_FACTOR ** attempt)
    return None

# -------------------------
# HTML parsing + link extraction
# -------------------------
def html_to_text(html: str) -> Tuple[str, str]:
    soup = BeautifulSoup(html, "html.parser")
    title_tag = soup.find("title")
    title = title_tag.text.strip() if title_tag else ""

    for tag in soup(["script", "style", "meta", "noscript", "head"]):
        tag.decompose()
    text = soup.get_text(separator="\n", strip=True)
    return title, text

def extract_links(base_url: str, html: str) -> List[str]:
    soup = BeautifulSoup(html, "html.parser")
    out = set()

    parsed_base = urlparse(base_url)
    base_host = parsed_base.netloc

    for a in soup.find_all("a", href=True):
        href = a["href"].strip()
        if not href or href.startswith("#") or href.startswith("mailto:"):
            continue

        full = urljoin(base_url, href)
        p = urlparse(full)

        if p.scheme not in ("http", "https"):
            continue

        # Follow same-site links; allow onion external within onion
        if p.netloc != base_host:
            if not (is_onion(base_url) and is_onion(full)):
                continue

        out.add(full)

    return sorted(out)

# -------------------------
# Writer (JSONL)
# -------------------------
RESULT_BATCH: List[Dict[str, Any]] = []

def flush_batch(final: bool = False) -> None:
    global RESULT_BATCH
    if not RESULT_BATCH:
        return
    with open(RESULTS_PATH, "a", encoding="utf-8") as f:
        for row in RESULT_BATCH:
            f.write(json.dumps(row, ensure_ascii=False) + "\n")
    log_event({"stage": "save", "count": len(RESULT_BATCH), "final": final, "path": RESULTS_PATH})
    RESULT_BATCH = []

def add_result(row: Dict[str, Any]) -> None:
    RESULT_BATCH.append(row)
    if len(RESULT_BATCH) >= BATCH_SIZE:
        flush_batch(final=False)

# -------------------------
# Seed loading
# -------------------------
def extract_urls_from_markdown(md_text: str) -> List[str]:
    urls = set()
    for line in md_text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        for match in re.findall(r"(https?://[^\s)]+|http://[a-z0-9]+\.onion[^\s)]*)", line):
            urls.add(match.strip())
    return sorted(urls)

def load_seed_urls_from_github() -> List[str]:
    all_urls: Set[str] = set()
    log_event({"stage": "seed", "msg": "loading_seeds_github"})
    for fname in SEED_FILES:
        url = f"{GITHUB_REPO_URL}/{fname}"
        try:
            resp = requests.get(url, headers=DEFAULT_HEADERS, timeout=20)
            resp.raise_for_status()
            urls = extract_urls_from_markdown(resp.text)
            before = len(all_urls)
            all_urls.update(urls)
            added = len(all_urls) - before
            log_event({"stage": "seed_file", "file": fname, "added": added, "unique_total": len(all_urls)})
        except requests.RequestException as e:
            log_event({"stage": "seed_file", "file": fname, "error": str(e)})
    log_event({"stage": "seed", "unique_total": len(all_urls)})
    return sorted(all_urls)

# -------------------------
# Alive precheck (bounded)
# -------------------------
def precheck_alive_hosts(seed_urls: List[str]) -> List[str]:
    if not HEAD_ENABLED:
        return seed_urls

    # Optionally only HEAD-check onion, keep clearweb as-is
    candidates = []
    for u in seed_urls:
        if HEAD_ONION_ONLY and not is_onion(u):
            continue
        candidates.append(u)

    # Bound HEAD count
    to_check = candidates[:HEAD_MAX]
    not_checked = [u for u in seed_urls if u not in set(to_check)]

    log_event({"stage": "head_precheck", "total_seeds": len(seed_urls), "to_check": len(to_check), "skipped": len(not_checked)})

    alive_set: Set[str] = set()

    def _one(u: str) -> Tuple[str, Optional[int]]:
        st = http_head(u)
        return u, st

    with cf.ThreadPoolExecutor(max_workers=HEAD_WORKERS) as ex:
        futs = [ex.submit(_one, u) for u in to_check]
        for fut in cf.as_completed(futs):
            u, st = fut.result()
            if st is not None and 200 <= st < 400:
                alive_set.add(u)

    # Keep not-checked seeds too (so we don't lose coverage)
    alive = sorted(list(alive_set)) + not_checked

    # Persist minimal audit
    with open(ALIVE_SEEDS_PATH, "a", encoding="utf-8") as f:
        for u in sorted(list(alive_set)):
            f.write(json.dumps({"ts": utc_now_iso(), "url": u, "http_status": 200}) + "\n")

    log_event({"stage": "head_precheck_done", "alive_checked": len(alive_set), "alive_total_after_merge": len(alive)})
    return alive

# -------------------------
# Main crawl loop (BFS)
# -------------------------
def crawl(seeds: List[str], max_pages: int, max_depth: int) -> None:
    visited: Set[str] = set()
    queue: List[Tuple[str, int]] = [(s, 0) for s in seeds]
    page_count = 0
    seen_fps = load_seen_fps()

    last_hb = time.time()

    log_event({"stage": "crawl_start", "seed_count": len(seeds), "max_pages": max_pages, "max_depth": max_depth})

    while queue and page_count < max_pages:
        now = time.time()
        if now - last_hb >= HEARTBEAT_EVERY_SEC:
            log_event({"stage": "heartbeat", "processed": page_count, "queued": len(queue), "visited": len(visited)})
            last_hb = now

        url, depth = queue.pop(0)
        if url in visited:
            continue
        visited.add(url)

        log_event({"stage": "crawl_page", "n": page_count + 1, "depth": depth, "url": url})

        resp = http_get(url)
        if not resp:
            log_event({"stage": "fetch_fail", "url": url})
            continue

        title, text = html_to_text(resp.text)
        if looks_like_login(url, text):
            log_event({"stage": "skip_login", "url": url})
            page_count += 1
            continue

        ind = extract_indicators(text)
        verdict = score_page(url, title, text, ind)

        # fingerprint for dedup (avoid re-saving same content)
        snippet = (text[:450] or "").replace("\n", " ")
        fp = stable_fingerprint(url, title, snippet)

        if fp in seen_fps:
            log_event({"stage": "dedup_skip", "url": url, "fp": fp, "score": verdict.score, "type": verdict.leak_type})
        else:
            if should_save(verdict):
                row = {
                    "run_id": RUN_ID,
                    "ts": utc_now_iso(),
                    "url": url,
                    "source_host": urlparse(url).hostname or "",
                    "source_type": "onion" if is_onion(url) else "clearweb",
                    "depth": depth,
                    "title": title,
                    "snippet": snippet,
                    "leak_type": verdict.leak_type,
                    "severity": verdict.severity,
                    "score": verdict.score,
                    "confidence": verdict.confidence,
                    "signals": verdict.signals,
                    "counts": {
                        "credentials": len(ind.get("credentials", [])),
                        "emails": len(ind.get("emails", [])),
                        "cards": len(ind.get("cards", [])),
                        "tokens": len(ind.get("tokens", [])),
                        "hashes": len(ind.get("hashes", [])),
                        "ips": len(ind.get("ips", [])),
                        "config": len(ind.get("config", [])),
                        "db_uri": len(ind.get("db_uri", [])),
                        "ssh_keys": len(ind.get("ssh_keys", [])),
                    },
                    # Keep only small samples (no full raw)
                    "samples": {
                        "example_lines": ind.get("examples", [])[:10],
                    },
                    "fingerprint": fp,
                }
                add_result(row)
                seen_fps.add(fp)
                log_event({"stage": "saved", "url": url, "fp": fp, "type": verdict.leak_type, "severity": verdict.severity, "score": verdict.score})
            else:
                log_event({"stage": "fp_skip", "url": url, "score": verdict.score, "type": verdict.leak_type, "signals": verdict.signals})

        page_count += 1

        if depth < max_depth:
            try:
                links = extract_links(url, resp.text)
            except Exception as e:
                log_event({"stage": "link_extract_error", "url": url, "error": str(e)})
                links = []

            # Light queue control: avoid explosion
            for link in links[:120]:
                if link not in visited:
                    queue.append((link, depth + 1))

    save_seen_fps(seen_fps)
    log_event({"stage": "crawl_done", "pages": page_count, "visited": len(visited), "queued_left": len(queue)})

# -------------------------
# CLI
# -------------------------
def parse_args():
    p = argparse.ArgumentParser(description="DeepGuard crawler (restored + monitored + FP-reduced)")
    p.add_argument("--mode", choices=["broad"], default="broad")
    p.add_argument("--max-pages", type=int, default=MAX_PAGES)
    p.add_argument("--max-depth", type=int, default=MAX_DEPTH)

    # precheck knobs
    p.add_argument("--head", action="store_true", default=HEAD_ENABLED, help="Enable bounded HEAD precheck.")
    p.add_argument("--no-head", action="store_false", dest="head", help="Disable HEAD precheck.")
    p.add_argument("--head-max", type=int, default=HEAD_MAX)
    p.add_argument("--head-workers", type=int, default=HEAD_WORKERS)
    p.add_argument("--head-onion-only", action="store_true", default=HEAD_ONION_ONLY)
    p.add_argument("--head-all", action="store_false", dest="head_onion_only")

    return p.parse_args()

def main():
    global HEAD_ENABLED, HEAD_MAX, HEAD_WORKERS, HEAD_ONION_ONLY

    args = parse_args()
    HEAD_ENABLED = bool(args.head)
    HEAD_MAX = int(args.head_max)
    HEAD_WORKERS = int(args.head_workers)
    HEAD_ONION_ONLY = bool(args.head_onion_only)

    log_event({"stage": "start", "mode": args.mode, "results_path": RESULTS_PATH})

    try:
        seed_urls = load_seed_urls_from_github()
        if not seed_urls:
            log_event({"stage": "fatal", "error": "no_seeds"})
            return 1

        alive_seeds = precheck_alive_hosts(seed_urls)
        if not alive_seeds:
            log_event({"stage": "fatal", "error": "no_alive_seeds"})
            return 1

        crawl(alive_seeds, max_pages=args.max_pages, max_depth=args.max_depth)

    except KeyboardInterrupt:
        log_event({"stage": "interrupt", "msg": "KeyboardInterrupt"})
    except Exception as e:
        log_event({"stage": "fatal", "error": str(e)})
    finally:
        flush_batch(final=True)
        log_event({"stage": "end", "msg": "done"})
    return 0

if __name__ == "__main__":
    sys.exit(main())
