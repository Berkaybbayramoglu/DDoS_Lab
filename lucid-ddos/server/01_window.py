"""Step 1 – Capture packets and cut them into time windows.

Learning outcome: why traffic is processed in time windows and how LUCID builds them.
  * A window starts at a packet and lasts t seconds (paper: t = 100 s).
  * The next window starts at the FIRST packet that arrives after the previous window ended,
    no matter how long the network was silent in between.
  * Working window by window keeps memory bounded and gives a detection decision every t seconds.
Several captures can be read together (the lab uses the CIC-DDoS2019 sample of the LUCID authors and
the recording of the lab network); their packets are put in time order and cut into windows in
the same way. Every packet keeps the number of the capture it came from.

usage:  python3 01_window.py --pcap data/cic_ddos2019_sample.pcap.gz data/lab_traffic.pcap.gz \
                             -t 100 --out work/01_window
output: <out>/packets.npz  one row per IPv4 packet (time, addresses, ports, 10 header features, window id,
                           capture number and frame number in that capture)
        <out>/pipeline.json the settings of this step, read by 02_flows.py
"""
import argparse
import os
import time

import numpy as np

import lablib


def main():
    a = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    a.add_argument("--pcap", nargs="+", required=True, help="pcap file(s) to read (.pcap or .pcap.gz)")
    a.add_argument("-t", "--window", type=float, default=100.0, help="window length in seconds (paper: 100)")
    a.add_argument("--out", default="work/01_window")
    args = a.parse_args()

    t0 = time.perf_counter()
    parts, per_file = [], []
    for i, path in enumerate(args.pcap):
        part = lablib.read_pcap_columns(path)
        part["capture"] = np.full(len(part["ts"]), i, dtype=np.int64)
        parts.append(part)
        span = part["ts"].max() - part["ts"].min() if len(part["ts"]) else 0.0
        per_file.append([i, os.path.basename(path), len(part["ts"]), f"{span:.1f}"])
    pk = {c: np.concatenate([q[c] for q in parts]) for c in parts[0]}
    if len(pk["ts"]) == 0:
        raise SystemExit("no IPv4 packets found in " + " ".join(args.pcap))
    order = np.lexsort((pk["frame"], pk["capture"], pk["ts"]))  # time order (capture, frame break ties)
    pk = {c: v[order] for c, v in pk.items()}
    ts = pk["ts"]
    win = lablib.assign_windows(ts, args.window)

    os.makedirs(args.out, exist_ok=True)
    np.savez_compressed(os.path.join(args.out, "packets.npz"), window=win, **pk)

    rows, windows = [], []
    names = [os.path.basename(x) for x in args.pcap]
    for w in range(int(win.max()) + 1):
        m = win == w
        first, last = ts[m][0], ts[m][-1]
        gap = first - windows[-1]["last_packet"] if windows else 0.0
        src = ", ".join(names[i] for i in np.unique(pk["capture"][m]))
        windows.append({"window": w, "start": float(first), "end": float(first + args.window),
                        "last_packet": float(last), "packets": int(m.sum()), "idle_before_s": float(gap),
                        "capture": src})
        t_cap = ts[pk["capture"] == pk["capture"][m][0]][0]   # times relative to the start of its capture
        rows.append([w, src, f"{first - t_cap:.1f}", f"{first - t_cap + args.window:.1f}", int(m.sum()),
                     f"{gap:.1f}" if w else "-"])
    lablib.save_pipeline(args.out, {"step": "01_window", "pcap": [os.path.abspath(x) for x in args.pcap],
                                    "window_s": args.window, "packets": len(ts), "windows": windows,
                                    "packets_id": lablib.packets_id({"capture": pk["capture"], "frame": pk["frame"], "ts": ts, "window": win})})

    print(f"read {len(ts)} IPv4 packets from {len(args.pcap)} capture(s) in {time.perf_counter() - t0:.1f} s")
    lablib.print_table(per_file, ["capture", "file", "packets", "duration (s)"])
    shown = rows if len(rows) <= 16 else rows[:8] + [["...", "", "", "", "", ""]] + rows[-6:]
    lablib.print_table(shown, ["window", "capture", "start (s)", "end (s)", "packets", "silence before (s)"])
    print(f"-> {len(windows)} windows of t = {args.window:g} s written to {args.out}")


if __name__ == "__main__":
    main()
