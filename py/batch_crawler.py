# batch_crawler.py
from __future__ import annotations
import time
from urllib.parse import urlparse

from core.fp_rules import is_probably_junk
from core.net import fetch, FetchError
from core.leak_scoring import evaluate
from core.storage import append_jsonl, utc_now_iso

SEEDS_FILE = "seeds.txt"
ALIVE_OUT  = "state/alive_seeds.jsonl"
EVENTS_OUT = "output/events.jsonl"

MAX_RUNTIME_SEC = 60 * 60        # 1시간 컷
MAX_SEEDS = 3000                 # 이번 배치에서 처리할 seed 상한
TIMEOUT = 15

# clearnet을 tor로 보낼지 여부: 기본 False(권장)
CLEARNET_VIA_TOR = False

def iter_seeds(path: str):
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            u = line.strip()
            if not u or u.startswith("#"):
                continue
            yield u

def main():
    start = time.time()
    processed = 0
    alive_count = 0
    total_count = 0

    for url in iter_seeds(SEEDS_FILE):
        total_count += 1
        if processed >= MAX_SEEDS:
            break
        if time.time() - start > MAX_RUNTIME_SEC:
            break

        junk, reason = is_probably_junk(url)
        if junk:
            append_jsonl(EVENTS_OUT, {
                "ts": utc_now_iso(), "stage": "seed_filter",
                "url": url, "status": "skipped", "reason": reason
            })
            continue

        processed += 1

        # 1) HEAD/GET으로 접근성 + 콘텐츠 일부 확인
        try:
            status, body, meta = fetch(
                url,
                timeout=TIMEOUT,
                allow_get_fallback=True,
                clearnet_via_tor=CLEARNET_VIA_TOR
            )
        except FetchError as e:
            append_jsonl(EVENTS_OUT, {
                "ts": utc_now_iso(), "stage": "seed_check",
                "url": url, "status": "dead", "error": str(e)
            })
            continue

        # 2) 404는 즉시 dead
        if status == 404:
            append_jsonl(EVENTS_OUT, {
                "ts": utc_now_iso(), "stage": "seed_check",
                "url": url, "status": "dead", "http_status": 404, "meta": meta
            })
            continue

        # 3) alive 판정 (200~399 정도만)
        if 200 <= status < 400:
            alive_count += 1
            append_jsonl(ALIVE_OUT, {
                "ts": utc_now_iso(),
                "url": url,
                "http_status": status,
                "route": meta.get("route"),
            })

            # 4) leak scoring (body가 비어있으면 낮게 나옴 → 괜찮)
            verdict = evaluate(url, body or "")
            event = {
                "ts": utc_now_iso(),
                "stage": "leak_eval",
                "url": url,
                "http_status": status,
                "route": meta.get("route"),
                "score": verdict.score,
                "confidence": verdict.confidence,
                "leak_type": verdict.leak_type,
                "signals": verdict.signals.__dict__,
                "fingerprint": verdict.fingerprint,
            }
            append_jsonl(EVENTS_OUT, event)
        else:
            # 401/403/405/503 등은 blocked로 두고, dead로 치지 않음
            append_jsonl(EVENTS_OUT, {
                "ts": utc_now_iso(), "stage": "seed_check",
                "url": url, "status": "blocked_or_error",
                "http_status": status, "meta": meta
            })

    append_jsonl(EVENTS_OUT, {
        "ts": utc_now_iso(),
        "stage": "batch_summary",
        "processed": processed,
        "total_seen": total_count,
        "alive_count": alive_count,
        "runtime_sec": round(time.time() - start, 2),
    })

if __name__ == "__main__":
    main()
