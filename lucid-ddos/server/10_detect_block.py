"""Step 10 (post-lab) – Detect and block attack traffic with the trained model.

This is the defensive side: the server monitors its own interface, applies exactly the same
pipeline the model was trained with (window -> flows -> normalization -> features -> shape),
classifies every flow, and for each flow classified as DDoS it drops further traffic from the
other endpoint with an iptables rule. Every decision is written to a log that the incident report
(step 11) reads. Nothing is sent to the network; only an input DROP rule is added locally.

The model file already carries the pipeline settings, so inference needs only the model.

Live mode re-classifies the open window every --interval seconds, so an attack is reported and
blocked while it is still going on (not only when the window of t seconds closes). Before the
window closes, a flow is judged only once it looks finished (no packet for --idle seconds), as
flow exporters do with an inactive timeout. Every flow
classified as DDoS is printed once as an ALERT line; once an address has --min-alerts flagged flows
it is blocked (BLOCK line), so a single false alarm does not cut a legitimate host off. When the window closes, the final classification of all its flows is written to the
log (with the time each address was blocked) for the incident report.

usage (offline, on a recorded pcap, no blocking):
    python3 10_detect_block.py --model models/global_lucid.pt --pcap data/validation_replay.pcap \
            --victim 172.30.0.10 --out results/incident_offline.csv
usage (live on the server interface, with blocking):
    python3 10_detect_block.py --model models/global_lucid.pt --iface eth0 --victim 172.30.0.10 \
            --block --seconds 150 --out results/incident_live.csv
"""
import argparse
import csv
import os
import queue
import subprocess
import threading
import time

import numpy as np

import lablib


def block_ip(ip):
    """Drop further input from this address (idempotent)."""
    chk = subprocess.run(["iptables", "-C", "INPUT", "-s", ip, "-j", "DROP"], capture_output=True)
    if chk.returncode != 0:
        subprocess.run(["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"], capture_output=True)


def classify_window(model, pipe, packets, victim_int, threshold):
    import torch
    X, keys, first_ts = lablib.apply_pipeline(packets, pipe)
    if len(X) == 0:
        return []
    with torch.no_grad():
        prob = torch.sigmoid(lablib.predict_logits(model, X)).numpy()
    n_pk = (np.abs(X).sum(axis=2) > 0).sum(axis=1)               # packets in the sample (max n)
    out = []
    for key, pv, t, k in zip(keys, prob, first_ts, n_pk):
        peer_first = key[0] != victim_int                            # key = (ip, port, ip, port, proto)
        peer, peer_pt, vic_pt = (key[0], key[1], key[3]) if peer_first else (key[2], key[3], key[1])
        out.append({"key": key, "time": float(t), "peer_ip": lablib.int_to_ip(peer), "peer_port": peer_pt,
                    "victim_port": vic_pt, "proto": PROTO.get(key[4], str(key[4])), "packets": int(k),
                    "prob": float(pv), "pred": int(pv >= threshold)})
    return out


PROTO = {1: "icmp", 6: "tcp", 17: "udp"}


def clock(x):
    return time.strftime("%H:%M:%S", time.gmtime(x))                # UTC, as in the incident report


def main():
    a = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    a.add_argument("--model", required=True)
    src = a.add_mutually_exclusive_group(required=True)
    src.add_argument("--pcap"); src.add_argument("--iface")
    a.add_argument("--victim", required=True, help="the server's own IP (the protected host)")
    a.add_argument("--threshold", type=float, default=0.5)
    a.add_argument("--block", action="store_true", help="add an iptables DROP rule per attacker IP (live mode)")
    a.add_argument("--seconds", type=float, default=0, help="live capture duration (0 = until interrupted)")
    a.add_argument("--interval", type=float, default=5,
                   help="live: re-classify the open window every N seconds (0 = only when it closes)")
    a.add_argument("--min-alerts", type=int, default=3,
                   help="block an address only after this many of its flows were flagged (1 = at once)")
    a.add_argument("--idle", type=float, default=2,
                   help="live: a flow is judged before its window closes only after N s without packets")
    a.add_argument("--out", required=True)
    args = a.parse_args()
    lablib.set_seed()
    import torch

    ck = torch.load(args.model, map_location="cpu")
    pipe = ck["pipeline"]
    model = lablib.build_model(pipe["n_features"], pipe["train"]["kernels"], batchnorm=pipe.get("batchnorm", False))
    model.load_state_dict(ck["state"]); model.eval()
    victim_int = lablib.ip_to_int(args.victim)
    t_win = pipe["window_s"]

    os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)
    fh = open(args.out, "w", newline="")
    writer = csv.writer(fh)
    writer.writerow(["window", "time", "peer_ip", "peer_port", "victim_port", "proto", "packets",
                     "prob_ddos", "pred", "alert_time", "blocked", "block_time"])
    blocked, n_flows, n_attack = {}, 0, 0          # blocked: ip -> time the DROP rule was added
    alerted = {}                                   # (window, flow key) -> time of its ALERT line
    n_alerts = {}                                  # ip -> number of flagged flows so far
    live = args.pcap is None
    print(f"model {args.model}: window t = {t_win:g} s, victim {args.victim}, "
          f"{'blocking enabled' if args.block else 'offline (no blocking)'}"
          + (f", re-check every {args.interval:g} s (flows idle >= {args.idle:g} s)" if live and args.interval else "")
          + (f", block after {args.min_alerts} alerts" if args.block else ""))

    def alert(w, r, when):
        """Print one flagged flow once; block its source on the first alert."""
        if (w, r["key"]) in alerted or r["peer_ip"] == args.victim:
            return
        alerted[(w, r["key"])] = when
        print(f"{clock(when)}  ALERT  {r['peer_ip']}:{r['peer_port']} -> {args.victim}:{r['victim_port']} "
              f"{r['proto']}  {r['packets']} pkts  p(DDoS) {100 * r['prob']:.1f} %", flush=True)
        n_alerts[r["peer_ip"]] = n_alerts.get(r["peer_ip"], 0) + 1
        if r["peer_ip"] not in blocked and n_alerts[r["peer_ip"]] >= args.min_alerts:
            blocked[r["peer_ip"]] = when
            if args.block:
                block_ip(r["peer_ip"])
            print(f"{clock(when)}  {'BLOCK' if args.block else 'FLAG '}  {r['peer_ip']}"
                  + ("  (iptables -A INPUT -s %s -j DROP)" % r["peer_ip"] if args.block else ""), flush=True)

    def check_open_window(w, packets, now):
        # only flows that look finished (no packet for --idle seconds) are judged early; a flow that
        # is still running (e.g. a download) would otherwise be judged on its first few packets
        last = {}
        for p in packets:
            last[lablib.flow_key(p[2], p[5], p[3], p[6], p[4])] = p[1]
        for r in classify_window(model, pipe, packets, victim_int, args.threshold):
            if r["pred"] and now - last.get(r["key"], now) >= args.idle:
                alert(w, r, now)

    def handle_window(w, packets, now=None):
        nonlocal n_flows, n_attack
        res = classify_window(model, pipe, packets, victim_int, args.threshold)
        attack = sum(r["pred"] for r in res)
        n_flows += len(res); n_attack += attack
        for r in sorted(res, key=lambda r: r["time"]):
            if r["pred"]:
                alert(w, r, now if now is not None else r["time"])
        for r in res:
            at = alerted.get((w, r["key"]))
            bt = blocked.get(r["peer_ip"])
            writer.writerow([w, f"{r['time']:.3f}", r["peer_ip"], r["peer_port"], r["victim_port"], r["proto"],
                             r["packets"], f"{r['prob']:.6f}", r["pred"], f"{at:.3f}" if at else "",
                             "yes" if bt is not None and args.block else "", f"{bt:.3f}" if bt else ""])
        fh.flush()
        print(f"[window {w} closed] {len(res)} flows, {attack} classified DDoS", flush=True)

    if args.pcap:
        packets = lablib.read_pcap_packets(args.pcap)
        packets.sort(key=lambda p: (p[1], p[0]))
        if packets:
            win = lablib.assign_windows(np.array([p[1] for p in packets]), t_win)
            for w in range(int(win.max()) + 1):
                handle_window(w, [packets[i] for i in np.flatnonzero(win == w)])
    else:
        proc = subprocess.Popen(lablib.tshark_command(iface=args.iface), stdout=subprocess.PIPE,
                                stderr=subprocess.DEVNULL, text=True, bufsize=1)
        lines = queue.Queue()
        threading.Thread(target=lambda: ([lines.put(x) for x in proc.stdout], lines.put(None)), daemon=True).start()
        buf, start, w, t_end = [], None, 0, time.time() + args.seconds if args.seconds else None
        next_check = None
        while True:
            if t_end and time.time() >= t_end:
                break
            try:
                line = lines.get(timeout=0.2)
            except queue.Empty:
                line = ""
            if line is None:
                break
            now = time.time()
            if line:
                p = lablib.parse_tshark_line(line)
                if p:
                    if start is None:
                        start, next_check = now, now + args.interval
                    buf.append(p)
            if start is not None and now >= start + t_win:
                handle_window(w, buf, now); w += 1; buf, start, next_check = [], None, None
            elif args.interval and next_check is not None and now >= next_check and buf:
                check_open_window(w, buf, now)
                next_check = now + args.interval
        if buf:
            handle_window(w, buf, time.time())
        proc.terminate()

    fh.close()
    print(f"\n{n_flows} flows seen, {n_attack} classified as DDoS, {len(blocked)} distinct attacker IP(s) "
          f"{'blocked' if args.block else 'identified'}")
    print(f"-> {args.out}")


if __name__ == "__main__":
    main()
