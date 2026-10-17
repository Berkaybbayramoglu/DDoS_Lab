"""Step 1 – Capture packets and cut them into time windows.

Learning outcome: why traffic is processed in time windows and how LUCID builds them.
  * A window starts at a packet and lasts t seconds (paper: t = 100 s).
  * The next window starts at the FIRST packet that arrives after the previous window ended,
    no matter how long the network was silent in between.
  * Working window by window keeps memory bounded and gives a detection decision every t seconds.

usage:  python3 01_window.py --pcap data/lab_traffic.pcap.gz -t 100 --out work/01_window
output: <out>/packets.npz  one row per IPv4 packet (time, addresses, ports, 10 header features, window id)
        <out>/pipeline.json the settings of this step, read by 02_flows.py
"""
import argparse
import os
import time

import numpy as np

import lablib


def main():
    a = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    a.add_argument("--pcap", required=True, help="pcap file to read")
    a.add_argument("-t", "--window", type=float, default=100.0, help="window length in seconds (paper: 100)")
    a.add_argument("--out", default="work/01_window")
    args = a.parse_args()

    t0 = time.perf_counter()
    pk = lablib.read_pcap_columns(args.pcap)
    if len(pk["ts"]) == 0:
        raise SystemExit("no IPv4 packets found in " + args.pcap)
    order = np.lexsort((pk["frame"], pk["ts"]))             # time order (frame number breaks ties)
    pk = {c: v[order] for c, v in pk.items()}
    ts = pk["ts"]
    win = lablib.assign_windows(ts, args.window)

    os.makedirs(args.out, exist_ok=True)
    np.savez_compressed(os.path.join(args.out, "packets.npz"), window=win, **pk)

    rows, windows = [], []
    for w in range(int(win.max()) + 1):
        m = win == w
        first, last = ts[m][0], ts[m][-1]
        gap = first - windows[-1]["last_packet"] if windows else 0.0
        windows.append({"window": w, "start": float(first), "end": float(first + args.window),
                        "last_packet": float(last), "packets": int(m.sum()), "idle_before_s": float(gap)})
        rows.append([w, f"{first - ts[0]:.1f}", f"{first - ts[0] + args.window:.1f}", int(m.sum()),
                     f"{gap:.1f}" if w else "-"])
    lablib.save_pipeline(args.out, {"step": "01_window", "pcap": os.path.abspath(args.pcap),
                                    "window_s": args.window, "packets": len(ts), "windows": windows})

    print(f"read {len(ts)} IPv4 packets in {time.perf_counter() - t0:.1f} s, capture spans {ts[-1] - ts[0]:.1f} s")
    lablib.print_table(rows, ["window", "start (s)", "end (s)", "packets", "silence before (s)"])
    print(f"-> {len(windows)} windows of t = {args.window:g} s written to {args.out}")


if __name__ == "__main__":
    main()
