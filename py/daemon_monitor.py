# daemon_monitor.py
from __future__ import annotations
import json
import time
import os
from typing import Dict, List

from core.net import fetch, FetchError
from core.leak_scoring import evaluate
from core.storage import append_jsonl, utc_now_iso

ALIVE_IN   = "state/alive_seeds.jsonl"
SEEN_FP    = "state/seen_fingerprints.json"
EVENTS_OUT = "output/events.jsonl"

INTERVAL_SEC = 300        # 5분
TIMEOUT = 15
MAX_PER_CYCLE = 200       # 한 사이클에 너무 많이 돌지 않게

CLEARNET_VIA_TOR = False  # onion만 tor, clearnet은 direct 우선(권장)

def load_seen() -> Dict[str, str]:
    if not os.path.exists(SEEN_FP):
        return {}
    with open(SEEN_FP, "r", encoding="utf-8") as f:
        return json.load(f)

def save_seen(d: Dict[str, str]) -> None:
    os.makedirs(os.path.dirname(SEEN_FP), exist_ok=True)
    with open(SEEN_FP, "w", encoding="utf-8") as f:
        json.dump(d, f, ensure_ascii=False, indent=2)

def iter_alive_urls(path: str) -> List[str]:
    if not os.path.exists(path):
        return []
    urls = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
                u = obj.get("url")
                if u:
                    urls.append(u)
            except Exception:
                continue
    return urls

def main():
    seen = load_seen()

    while True:
        urls = iter_alive_urls(ALIVE_IN)
        if not urls:
            append_jsonl(EVENTS_OUT, {
                "ts": utc_now_iso(),
                "stage": "daemon",
                "status": "no_alive_seeds",
                "message": f"{ALIVE_IN} not found or empty"
            })
            time.sleep(INTERVAL_SEC)
            continue

        checked = 0
        changed = 0

        for url in urls[:MAX_PER_CYCLE]:
            checked += 1
            try:
                status, body, meta = fetch(
                    url,
                    timeout=TIMEOUT,
                    allow_get_fallback=True,
                    clearnet_via_tor=CLEARNET_VIA_TOR
                )
            except FetchError as e:
                append_jsonl(EVENTS_OUT, {
                    "ts": utc_now_iso(),
                    "stage": "daemon_check",
                    "url": url,
                    "status": "error",
                    "error": str(e),
                })
                continue

            # 접근 자체가 안 되면 기록만 남기고 다음
            if not (200 <= status < 400):
                append_jsonl(EVENTS_OUT, {
                    "ts": utc_now_iso(),
                    "stage": "daemon_check",
                    "url": url,
                    "status": "non_2xx_3xx",
                    "http_status": status,
                    "route": meta.get("route"),
                })
                continue

            verdict = evaluate(url, body or "")
            fp_prev = seen.get(url)

            # fingerprint 변화가 있으면 "delta" 이벤트로 저장
            if fp_prev != verdict.fingerprint:
                changed += 1
                seen[url] = verdict.fingerprint

                append_jsonl(EVENTS_OUT, {
                    "ts": utc_now_iso(),
                    "stage": "daemon_delta",
                    "url": url,
                    "http_status": status,
                    "route": meta.get("route"),
                    "score": verdict.score,
                    "confidence": verdict.confidence,
                    "leak_type": verdict.leak_type,
                    "signals": verdict.signals.__dict__,
                    "fingerprint": verdict.fingerprint,
                    "prev_fingerprint": fp_prev,
                })

        save_seen(seen)

        append_jsonl(EVENTS_OUT, {
            "ts": utc_now_iso(),
            "stage": "daemon_summary",
            "checked": checked,
            "changed": changed,
            "sleep_sec": INTERVAL_SEC,
        })

        time.sleep(INTERVAL_SEC)

if __name__ == "__main__":
    main()
