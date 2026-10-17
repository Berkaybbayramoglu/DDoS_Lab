"""Benign users for the lab dataset (run inside a client container by record_lab_sessions.sh).

Each client container runs one role, so the benign side of the capture holds several hosts with
different, realistic behaviour instead of one uniform request loop:
  browse     a person browsing: a page, then a burst of 2-6 parallel requests for its assets
             (small files), then 0.3-3 s of reading
  api        an application polling a service: tiny requests every 0.1-0.6 s
  keepalive  a client reusing one HTTP/1.1 connection for 3-10 requests before closing it
  download   large downloads (50-300 kB), 1-4 s apart
  slow       a slow link: reads a large file in small chunks, so the flow lasts a few seconds
The victim serves s0..s29 (small pages, 0.2-8 kB) and l0..l9 (large files, 50-300 kB).
Timing is random (seeded per host, seed 42 + last address byte), so a re-recording gives the same
kind of traffic, not the same packets.

usage: python3 benign_clients.py <role> <victim ip> <my ip>
"""
import http.client
import random
import sys
import threading
import time

ROLE, VICTIM, ME = sys.argv[1], sys.argv[2], sys.argv[3]
rng = random.Random(42 + int(ME.rsplit(".", 1)[1]))


def get(path, conn=None, chunk=None, pause=0.0):
    """One GET; with conn the request goes over that (kept-alive) connection."""
    own = conn is None
    try:
        c = conn or http.client.HTTPConnection(VICTIM, 80, timeout=5)
        c.request("GET", path)
        r = c.getresponse()
        while True:
            data = r.read(chunk) if chunk else r.read()
            if not data or not chunk:
                break
            time.sleep(pause)
        if own:
            c.close()
    except (OSError, http.client.HTTPException):
        pass


def small():
    return f"/s{rng.randrange(30)}"


def large():
    return f"/l{rng.randrange(10)}"


while True:
    if ROLE == "browse":
        get(small())
        assets = [threading.Thread(target=get, args=(small(),)) for _ in range(rng.randint(2, 6))]
        for t in assets:
            t.start()
        for t in assets:
            t.join()
        time.sleep(rng.uniform(0.3, 3.0))
    elif ROLE == "api":
        get(small())
        time.sleep(rng.uniform(0.1, 0.6))
    elif ROLE == "keepalive":
        try:
            conn = http.client.HTTPConnection(VICTIM, 80, timeout=5)
            for _ in range(rng.randint(3, 10)):
                get(small(), conn=conn)
                time.sleep(rng.uniform(0.05, 0.5))
            conn.close()
        except OSError:
            pass
        time.sleep(rng.uniform(0.3, 1.5))
    elif ROLE == "download":
        get(large())
        time.sleep(rng.uniform(1.0, 4.0))
    elif ROLE == "slow":
        get(large(), chunk=8192, pause=rng.uniform(0.02, 0.1))
        time.sleep(rng.uniform(0.5, 2.0))
    else:
        sys.exit(f"unknown role {ROLE}")
