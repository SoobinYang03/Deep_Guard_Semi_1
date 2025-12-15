#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
DeepGuard crawler v7 + Leak detector (extended)
 - Memory-safe batch saving (JSONL, auto flush)
 - Alive-host pre-check (HEAD) before deep crawling
 - Tor support for .onion
 - Pattern-based leak detection (credentials / cards / tokens / IDs / config / infra)
 - threat_type + severity auto classification
 - Only pages that look like *real leaks* are saved
"""

import argparse
import json
import os
import random
import re
import sys
import time
from datetime import datetime
from typing import Dict, List, Optional, Set, Tuple, Any
from urllib.parse import urlparse, urljoin

import requests
from bs4 import BeautifulSoup

# =========================
# Config: paths / output
# =========================

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
OUTPUT_DIR = os.path.join(BASE_DIR, "output")
os.makedirs(OUTPUT_DIR, exist_ok=True)

RUN_ID = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
RESULTS_PATH = os.path.join(OUTPUT_DIR, f"deepguard_results_{RUN_ID}.jsonl")

# batch flush (for memory-saving)
BATCH_SIZE = 50           # save to disk after N findings
MAX_PAGES = 3000          # overall crawl page limit
MAX_DEPTH = 2             # BFS depth

# global batch buffer
RESULT_BATCH: List[Dict] = []

# =========================
# Networking / Tor config
# =========================

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

REQUEST_TIMEOUT = 90      # GET timeout
HEAD_TIMEOUT = 15         # HEAD timeout
MAX_RETRIES = 3

BASE_DELAY = 0.5
JITTER = 1.5
BACKOFF_FACTOR = 2.0

# =========================
# Broad leak keywords (for quick heuristics)
# =========================

LEAK_KEYWORDS = [
    "ransomware", "leak", "leaked", "dump", "db dump", "database",
    "password", "pwd", "credential", "login", "account", "combo",
    "email:pass", "id:pass", "stealer", "infostealer", "token",
    "api key", "apikey", "ssh key",
]

LOGIN_PATTERNS = [
    "login", "log-in", "sign in", "signin",
    "/login", "/signin", "account/login"
]

# =========================
# Regexes for leak_detector
# =========================

EMAIL_RE = re.compile(
    r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"
)

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
    r"\b(?:4[0-9]{12}(?:[0-9]{3})?"            # Visa
    r"|5[1-5][0-9]{14}"                        # MasterCard
    r"|3[47][0-9]{13}"                         # Amex
    r"|6(?:011|5[0-9]{2})[0-9]{12})\b"         # Discover
)

SSN_RE = re.compile(r"\b[0-9]{3}-[0-9]{2}-[0-9]{4}\b")

AWS_KEY_RE = re.compile(r"\bAKIA[0-9A-Z]{16}\b")
GITHUB_PAT_RE = re.compile(r"\bghp_[0-9A-Za-z]{36}\b")
STRIPE_SK_RE = re.compile(r"\bsk_live_[0-9A-Za-z]{24,}\b")

IPV4_RE = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}"
    r"(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"
)

# =========================
# Additional leak patterns
# =========================

# Phone numbers
PHONE_INTL_RE = re.compile(r"\+?[0-9]{1,3}[- ]?(?:[0-9]{2,4}[- ]?){2,4}")
PHONE_KR_RE = re.compile(r"\b01[016789]-?\d{3,4}-?\d{4}\b")

# Domain dump
DOMAIN_RE = re.compile(r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b")

# SSH public keys
SSH_PUBKEY_RE = re.compile(r"\bssh-(rsa|ed25519|dss)\s+[A-Za-z0-9+/=]{20,}\b")

# JWT tokens
JWT_RE = re.compile(r"\beyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{5,}\b")

# Slack tokens
SLACK_TOKEN_RE = re.compile(r"\bxox[abp]-[0-9A-Za-z-]{10,}\b")

# Telegram Bot token
TELEGRAM_BOT_RE = re.compile(r"\b[0-9]{7,10}:[A-Za-z0-9_-]{20,}\b")

# Discord webhook
DISCORD_WEBHOOK_RE = re.compile(
    r"https://discord(?:app)?\.com/api/webhooks/[0-9]+/[A-Za-z0-9_-]+"
)

# Database connectivity leaks
DB_URI_RE = re.compile(
    r"(?i)\b(?:postgres|mysql|mssql|oracle)://"
    r"(?P<user>[^:@\s]+):(?P<pw>[^:@\s]+)@(?P<host>[^:/\s]+)"
)

# Config leak (settings file)
CONFIG_LINE_RE = re.compile(
    r"(?i)\b(pass(word)?|pwd|secret|api_key|token)\s*=\s*['\"]?([^'\"\s]{4,})['\"]?"
)

# Leak metadata phrases
LEAK_META_RE = re.compile(
    r"(?i)(database dump|db dump|full dump|combo list|"
    r"user dump|password dump|credential dump|mailing list)"
)

# =========================
# Leak detector helpers
# =========================

def _unique(seq: List[str]) -> List[str]:
    seen = set()
    out = []
    for x in seq:
        if x not in seen:
            seen.add(x)
            out.append(x)
    return out


def extract_indicators(text: str) -> Dict[str, Any]:
    """
    Extract possible leak indicators from raw text.
    Returns a dict with lists of credentials, emails, hashes, cards, tokens, etc.
    """
    lines = text.splitlines()

    credentials: List[Dict[str, str]] = []
    emails: List[str] = []
    hashes: List[str] = []
    cards: List[str] = []
    ssn_list: List[str] = []
    tokens: List[str] = []
    ips: List[str] = []

    phones: List[str] = []
    domains: List[str] = []
    ssh_keys: List[str] = []
    db_uri_list: List[Dict[str, str]] = []
    config_leaks: List[str] = []
    leak_meta_hits: List[str] = []
    hit_lines: List[str] = []

    for line in lines:
        stripped = line.strip()
        if not stripped:
            continue

        # emails
        for m in EMAIL_RE.findall(stripped):
            emails.append(m)

        # email:password
        for m in EMAIL_PASS_RE.finditer(stripped):
            credentials.append(
                {
                    "email": m.group("email"),
                    "password": m.group("pw"),
                    "pattern": "email:password",
                }
            )
            hit_lines.append(stripped)

        # username / password pairs
        for m in USER_PASS_RE.finditer(stripped):
            credentials.append(
                {
                    "username": m.group("user"),
                    "password": m.group("pw"),
                    "pattern": "user/pass line",
                }
            )
            hit_lines.append(stripped)

        # hashes
        for h in HASH_RE.findall(stripped):
            hashes.append(h)
            hit_lines.append(stripped)

        # cards
        for c in CARD_RE.findall(stripped):
            cards.append(c)
            hit_lines.append(stripped)

        # SSN
        for s in SSN_RE.findall(stripped):
            ssn_list.append(s)
            hit_lines.append(stripped)

        # cloud / token style
        for t in AWS_KEY_RE.findall(stripped):
            tokens.append(t)
            hit_lines.append(stripped)
        for t in GITHUB_PAT_RE.findall(stripped):
            tokens.append(t)
            hit_lines.append(stripped)
        for t in STRIPE_SK_RE.findall(stripped):
            tokens.append(t)
            hit_lines.append(stripped)

        # IPs
        for ip in IPV4_RE.findall(stripped):
            ips.append(ip)

        # Phone numbers
        for p in PHONE_INTL_RE.findall(stripped):
            phones.append(p)
        for p in PHONE_KR_RE.findall(stripped):
            phones.append(p)

        # Domains
        for d in DOMAIN_RE.findall(stripped):
            domains.append(d)

        # SSH Keys
        for _ in SSH_PUBKEY_RE.findall(stripped):
            ssh_keys.append(stripped)

        # JWT
        for j in JWT_RE.findall(stripped):
            tokens.append(j)

        # Slack
        for s in SLACK_TOKEN_RE.findall(stripped):
            tokens.append(s)

        # Telegram bot
        for tb in TELEGRAM_BOT_RE.findall(stripped):
            tokens.append(tb)

        # Discord webhook
        for dw in DISCORD_WEBHOOK_RE.findall(stripped):
            tokens.append(dw)

        # DB URI
        for db in DB_URI_RE.finditer(stripped):
            db_uri_list.append({
                "user": db.group("user"),
                "password": db.group("pw"),
                "host": db.group("host")
            })

        # config leaks
        if CONFIG_LINE_RE.search(stripped):
            config_leaks.append(stripped)

        # leak metadata phrases
        if LEAK_META_RE.search(stripped):
            leak_meta_hits.append(stripped)

    indicators: Dict[str, Any] = {
        "credentials": credentials,
        "emails": _unique(emails),
        "phones": _unique(phones),
        "domains": _unique(domains),
        "ssh_keys": _unique(ssh_keys),
        "hashes": _unique(hashes),
        "cards": _unique(cards),
        "ssn": _unique(ssn_list),
        "tokens": _unique(tokens),
        "db_uri": db_uri_list,
        "config": _unique(config_leaks),
        "meta": _unique(leak_meta_hits),
        "ips": _unique(ips),
        "examples": _unique(hit_lines)[:50],
    }

    return indicators


# =========================
# Threat classifier
# =========================

def classify_threat(indicators: Dict[str, Any]) -> str:
    """
    Decide high-level threat_type based on what was found.
    Returns one of:
      credential_leak, financial_leak, token_leak,
      identity_leak, config_leak, asset_leak, infrastructure_leak,
      email_dump, none
    """
    creds = indicators.get("credentials", []) or []
    cards = indicators.get("cards", []) or []
    tokens = indicators.get("tokens", []) or []
    ssn_list = indicators.get("ssn", []) or []
    emails = indicators.get("emails", []) or []
    domains = indicators.get("domains", []) or []
    ssh_keys = indicators.get("ssh_keys", []) or []

    if creds:
        return "credential_leak"
    if cards:
        return "financial_leak"
    if tokens:
        return "token_leak"
    if ssn_list:
        return "identity_leak"
    if indicators.get("db_uri"):
        return "config_leak"
    if indicators.get("config"):
        return "config_leak"
    if ssh_keys:
        return "infrastructure_leak"
    if len(domains) >= 50:
        return "asset_leak"
    if indicators.get("phones") and emails:
        return "identity_leak"
    if len(emails) >= 20:
        return "email_dump"
    return "none"


def score_severity(threat_type: str, indicators: Dict[str, Any]) -> str:
    """
    Rough severity scoring: low / medium / high / critical.
    """
    creds = indicators.get("credentials", []) or []
    cards = indicators.get("cards", []) or []
    tokens = indicators.get("tokens", []) or []
    ssn_list = indicators.get("ssn", []) or []
    emails = indicators.get("emails", []) or []
    domains = indicators.get("domains", []) or []

    if threat_type == "none":
        return "low"

    if threat_type == "credential_leak":
        count = len(creds)
        if count >= 100 or len(emails) >= 500:
            return "critical"
        if count >= 20 or len(emails) >= 100:
            return "high"
        return "medium"

    if threat_type == "financial_leak":
        return "critical" if len(cards) >= 10 else "high"

    if threat_type == "token_leak":
        return "critical" if len(tokens) >= 3 else "high"

    if threat_type == "identity_leak":
        return "critical" if len(ssn_list) >= 50 else "high"

    if threat_type == "email_dump":
        if len(emails) >= 1000:
            return "critical"
        if len(emails) >= 100:
            return "high"
        return "medium"

    if threat_type == "config_leak":
        return "critical"

    if threat_type == "asset_leak":
        return "medium" if len(domains) < 200 else "high"

    if threat_type == "infrastructure_leak":
        return "high"

    return "low"


# =========================
# Helpers
# =========================

def is_onion(url: str) -> bool:
    try:
        host = urlparse(url).hostname or ""
        return host.endswith(".onion")
    except Exception:
        return False


def is_ipv6_host(url: str) -> bool:
    try:
        host = urlparse(url).hostname or ""
        # very rough filter: IPv6 literals contain ":"
        return ":" in host and not host.endswith(".onion")
    except Exception:
        return False


def looks_like_login(url: str, text: str) -> bool:
    lower = (url + " " + text[:500]).lower()
    return any(p in lower for p in LOGIN_PATTERNS)


def sleep_with_jitter():
    delay = BASE_DELAY + random.uniform(0, JITTER)
    time.sleep(delay)


# =========================
# HTTP helpers
# =========================

def http_head(url: str) -> Optional[int]:
    """
    Pre-check: quick HEAD request to see if host is alive.
    We use short timeout and fewer retries.
    """
    if is_ipv6_host(url):
        print(f"[HEAD] Skip IPv6 URL: {url}")
        return None

    use_tor = is_onion(url)
    proxies = TOR_PROXIES if use_tor else None

    for attempt in range(1, 3):  # small retries for head
        sleep_with_jitter()
        try:
            print(f"[HEAD] attempt {attempt}/2 {url}")
            resp = requests.head(
                url,
                headers=DEFAULT_HEADERS,
                timeout=HEAD_TIMEOUT,
                proxies=proxies,
                allow_redirects=True,
            )
            print(f"[HEAD] {resp.status_code} {resp.url}")
            return resp.status_code
        except requests.RequestException as e:
            print(f"[HEAD] error on {url}: {e} (retry in {BACKOFF_FACTOR ** attempt:.1f}s)")
            time.sleep(BACKOFF_FACTOR ** attempt)

    print(f"[HEAD] giving up on {url}")
    return None


def http_get(url: str) -> Optional[requests.Response]:
    """
    GET with Tor support, retry and backoff.
    """
    if is_ipv6_host(url):
        print(f"[HTTP] Skip IPv6 URL: {url}")
        return None

    use_tor = is_onion(url)
    proxies = TOR_PROXIES if use_tor else None

    for attempt in range(1, MAX_RETRIES + 1):
        sleep_with_jitter()
        try:
            print(f"[*] GET attempt {attempt}/{MAX_RETRIES}: {url}")
            resp = requests.get(
                url,
                headers=DEFAULT_HEADERS,
                timeout=REQUEST_TIMEOUT,
                proxies=proxies,
                allow_redirects=True,
            )
            print(f"[HTTP] {resp.status_code} {resp.url}")

            if resp.status_code in (429, 503):
                backoff = BACKOFF_FACTOR ** attempt
                print(f"[HTTP] server busy ({resp.status_code}), backoff {backoff:.1f}s")
                time.sleep(backoff)
                continue

            resp.raise_for_status()
            return resp
        except requests.RequestException as e:
            backoff = BACKOFF_FACTOR ** attempt
            print(f"[HTTP] Error on {url}: {e} (retry in {backoff:.1f}s)")
            time.sleep(backoff)

    print(f"[HTTP] giving up on {url}")
    return None


# =========================
# Result batching / saving
# =========================

def flush_batch(final: bool = False):
    """
    Write RESULT_BATCH to JSONL and clear the in-memory list.
    """
    global RESULT_BATCH
    if not RESULT_BATCH:
        return

    with open(RESULTS_PATH, "a", encoding="utf-8") as f:
        for row in RESULT_BATCH:
            f.write(json.dumps(row, ensure_ascii=False) + "\n")

    print(f"[SAVE] flushed {len(RESULT_BATCH)} findings "
          f"{'(final)' if final else ''} -> {RESULTS_PATH}")
    RESULT_BATCH = []


def add_finding(data: Dict):
    """
    Append one finding to batch and auto-flush if BATCH_SIZE reached.
    """
    RESULT_BATCH.append(data)
    if len(RESULT_BATCH) >= BATCH_SIZE:
        flush_batch(final=False)


# =========================
# Seed loading (GitHub deepdarkCTI)
# =========================

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


def extract_urls_from_markdown(md_text: str) -> List[str]:
    urls = set()
    for line in md_text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        # very rough: find http/https/onion URLs
        for match in re.findall(r"(https?://[^\s)]+|http://[a-z0-9]+\.onion[^\s)]*)", line):
            urls.add(match.strip())
    return sorted(urls)


def load_seed_urls_from_github() -> List[str]:
    """
    Download MD files from deepdarkCTI and extract URLs.
    """
    all_urls: Set[str] = set()

    print(f"[GITHUB] Loading seed URLs from https://github.com/fastfire/deepdarkCTI")

    for fname in SEED_FILES:
        url = f"{GITHUB_REPO_URL}/{fname}"
        try:
            resp = requests.get(url, headers=DEFAULT_HEADERS, timeout=30)
            resp.raise_for_status()
            urls = extract_urls_from_markdown(resp.text)
            before = len(all_urls)
            all_urls.update(urls)
            added = len(all_urls) - before
            print(f"[GITHUB] {fname}: +{added} entries (unique total={len(all_urls)})")
        except requests.RequestException as e:
            print(f"[GITHUB] error loading {fname}: {e}")

    print(f"[GITHUB] Total unique seed URLs: {len(all_urls)}")
    return sorted(all_urls)


# =========================
# Alive host pre-check
# =========================

def precheck_alive_hosts(seed_urls: List[str]) -> List[str]:
    """
    Do a quick HEAD to filter out dead / unreachable hosts.
    This massively reduces crawl time and timeouts.
    """
    print("[SEEDS] Starting pre-check for alive hosts")

    alive: List[str] = []
    for url in seed_urls:
        status = http_head(url)
        if status and 200 <= status < 400:
            alive.append(url)
        else:
            print(f"[SEEDS] Dead/unreachable seed: {url}")

    print(f"[SEEDS] Alive seeds: {len(alive)} / {len(seed_urls)}")
    return alive


# =========================
# Leak detection in page
# =========================

def analyze_page(url: str, html: str, depth: int):
    """
    Inspect page text for leak-looking content and add findings.
    Only saves if pattern-based indicators show a real leak.
    """
    soup = BeautifulSoup(html, "html.parser")

    # remove noisy tags
    for tag in soup(["script", "style", "meta", "noscript", "head"]):
        tag.decompose()

    text = soup.get_text(separator="\n", strip=True)
    lower = text.lower()

    # Pattern-based indicators
    indicators = extract_indicators(text)
    threat_type = classify_threat(indicators)

    # Strong filter: only keep if we have a classified leak
    if threat_type == "none":
        return

    severity = score_severity(threat_type, indicators)

    title_tag = soup.find("title")
    title = title_tag.text.strip() if title_tag else ""

    snippet = text[:400].replace("\n", " ")

    emails = indicators.get("emails", [])
    ips = indicators.get("ips", [])

    indicator_counts = {
        "credentials": len(indicators.get("credentials", [])),
        "cards": len(indicators.get("cards", [])),
        "tokens": len(indicators.get("tokens", [])),
        "ssn": len(indicators.get("ssn", [])),
        "emails": len(emails),
        "ips": len(ips),
        "hashes": len(indicators.get("hashes", [])),
        "phones": len(indicators.get("phones", [])),
        "domains": len(indicators.get("domains", [])),
        "ssh_keys": len(indicators.get("ssh_keys", [])),
        "db_uri": len(indicators.get("db_uri", [])),
        "config": len(indicators.get("config", [])),
    }

    # ===== 추가 메타 필드: run_id, scan_mode, host, type =====
    parsed = urlparse(url)
    source_host = parsed.hostname or ""
    source_type = "onion" if is_onion(url) else "clearweb"

    finding = {
        "run_id": RUN_ID,
        "scan_mode": "broad",           # later can be extended: targeted, osint, etc.
        "url": url,
        "source_host": source_host,
        "source_type": source_type,
        "depth": depth,
        "title": title,
        "snippet": snippet,
        "created_at": datetime.utcnow().isoformat(),
        "threat_type": threat_type,
        "severity": severity,
        "indicator_counts": indicator_counts,
        # keep limited indicators for size control
        "indicators": {
            "credentials": indicators.get("credentials", [])[:200],
            "cards": indicators.get("cards", [])[:200],
            "tokens": indicators.get("tokens", [])[:200],
            "ssn": indicators.get("ssn", [])[:200],
            "emails": emails[:500],
            "ips": ips[:200],
            "phones": indicators.get("phones", [])[:200],
            "domains": indicators.get("domains", [])[:200],
            "ssh_keys": indicators.get("ssh_keys", [])[:200],
            "db_uri": indicators.get("db_uri", [])[:200],
            "config": indicators.get("config", [])[:200],
            "examples": indicators.get("examples", [])[:50],
        },
    }

    print(
        f"[CRAWL] LEAK detected at {url} "
        f"host={source_host} type={threat_type} severity={severity} "
        f"creds={indicator_counts['credentials']} "
        f"emails={indicator_counts['emails']} "
        f"cards={indicator_counts['cards']} "
        f"tokens={indicator_counts['tokens']}"
    )

    add_finding(finding)


def extract_links(base_url: str, html: str) -> List[str]:
    soup = BeautifulSoup(html, "html.parser")
    out = set()

    parsed_base = urlparse(base_url)
    base_host = parsed_base.netloc

    for a in soup.find_all("a", href=True):
        href = a["href"].strip()
        if href.startswith("#") or href.startswith("mailto:"):
            continue

        full = urljoin(base_url, href)
        p = urlparse(full)

        # keep same-site links + obvious interesting external ones
        if p.scheme not in ("http", "https"):
            continue
        if p.netloc != base_host and not is_onion(full):
            # ignore random external clearweb spam
            continue

        out.add(full)

    return sorted(out)


# =========================
# Main crawl loop
# =========================

def crawl(seeds: List[str], max_pages: int = MAX_PAGES, max_depth: int = MAX_DEPTH):
    """
    BFS-style crawl starting from alive seed URLs.
    Only .onion and same-site links are followed.
    """
    visited: Set[str] = set()
    queue: List[Tuple[str, int]] = []

    for s in seeds:
        queue.append((s, 0))

    page_count = 0

    while queue and page_count < max_pages:
        url, depth = queue.pop(0)
        if url in visited:
            continue
        visited.add(url)

        print(f"[CRAWL] ({page_count+1}/{max_pages}) depth={depth} url={url}")

        resp = http_get(url)
        if not resp:
            continue

        html = resp.text

        if looks_like_login(url, html):
            print(f"[LOGIN SKIP] login-looking page detected, skipping: {url}")
        else:
            analyze_page(url, html, depth)

        page_count += 1

        if depth < max_depth:
            try:
                links = extract_links(url, html)
            except Exception as e:
                print(f"[CRAWL] link extraction error on {url}: {e}")
                links = []

            for link in links:
                if link not in visited:
                    queue.append((link, depth + 1))

    print(f"[CRAWL] Finished. pages={page_count}, visited={len(visited)}")


# =========================
# CLI / main
# =========================

def parse_args():
    parser = argparse.ArgumentParser(
        description="DeepGuard crawler v7 (alive-host precheck + JSONL leak-only saver)"
    )
    parser.add_argument(
        "--mode",
        choices=["broad"],
        default="broad",
        help="Currently only 'broad' is implemented.",
    )
    return parser.parse_args()


def main():
    args = parse_args()
    print(f"[MAIN] mode={args.mode}")
    print(f"[MAIN] output file: {RESULTS_PATH}")

    try:
        seed_urls = load_seed_urls_from_github()
        alive_seeds = precheck_alive_hosts(seed_urls)
        if not alive_seeds:
            print("[MAIN] No alive seeds. Nothing to crawl.")
            return

        crawl(alive_seeds, max_pages=MAX_PAGES, max_depth=MAX_DEPTH)

    except KeyboardInterrupt:
        print("\n[MAIN] KeyboardInterrupt: stopping early.")
    except Exception as e:
        print(f"[MAIN] Fatal error: {e}")
    finally:
        flush_batch(final=True)
        print("[MAIN] Done.")


if __name__ == "__main__":
    sys.exit(main())
