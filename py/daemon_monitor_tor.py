#!/usr/bin/env python3
import subprocess, time, os, re
from collections import deque

PAUSE_FLAG = "state/pause.flag"
PAUSE_SECS = 60
WINDOW_SECS = 30
THRESH = 8

os.makedirs("state", exist_ok=True)
err_times = deque()

pat = re.compile(r"(Invalid hostname|Circuit.*fail|Resetting timeout|timeout)", re.I)

p = subprocess.Popen(
    ["journalctl", "-u", "tor@default.service", "-f", "-o", "short-iso"],
    stdout=subprocess.PIPE,
    stderr=subprocess.STDOUT,
    text=True,
    bufsize=1
)

print("[+] Tor monitor started")

for line in p.stdout:
    now = time.time()
    if pat.search(line):
        err_times.append(now)
        print("[TOR-ERR]", line.strip())

    while err_times and now - err_times[0] > WINDOW_SECS:
        err_times.popleft()

    if len(err_times) >= THRESH:
        print("[!] Tor unstable → pause crawler")
        with open(PAUSE_FLAG, "w") as f:
            f.write(f"errors={len(err_times)} window={WINDOW_SECS}s\n")

        time.sleep(PAUSE_SECS)

        try:
            os.remove(PAUSE_FLAG)
            print("[+] Resume crawler")
        except FileNotFoundError:
            pass

        err_times.clear()
