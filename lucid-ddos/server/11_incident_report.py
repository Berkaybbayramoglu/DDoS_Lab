"""Step 11 (post-lab) – Write a post-incident report from the detection log.

Learning outcome: turning raw detections into an analyst's report.
Reads the log written by 10_detect_block.py and summarises:
  * the attack window: first and last detection, duration,
  * every source IP that was flagged, with its flow count and the model's confidence
    (mean / median / 95 % bootstrap CI of the DDoS probability on its flagged flows),
  * which IPs were blocked, when, and how long after that address's first flow (time to block),
  * if the attacker IPs are given (--attackers), the detection rate (recall) and the false-alarm
    rate with 95 % CIs, so the analyst can state how reliable the detector was.
The same tables are printed and written to a text file for submission.

usage:  python3 11_incident_report.py --log results/incident_live.csv --victim 172.30.0.10 \
                --attackers 172.30.0.66 172.30.0.67 --out results/incident_report.txt
"""
import argparse
import csv
import os
from datetime import datetime, timezone

import numpy as np

import lablib
import progress


def ci(values, fn, n=1000):
    rng = np.random.default_rng(lablib.SEED)
    v = np.array(values, float)
    boot = [fn(v[rng.integers(0, len(v), len(v))]) for _ in range(n)]
    return fn(v), float(np.mean(boot)), float(np.median(boot)), float(np.percentile(boot, 2.5)), float(np.percentile(boot, 97.5))


def ts(x):
    return datetime.fromtimestamp(x, timezone.utc).strftime("%H:%M:%S")


def main():
    a = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    a.add_argument("--log", required=True, help="CSV written by 10_detect_block.py")
    a.add_argument("--victim", required=True)
    a.add_argument("--attackers", nargs="*", default=[], help="true attacker IPs (optional, enables accuracy)")
    a.add_argument("--out", default="results/incident_report.txt")
    args = a.parse_args()
    lablib.set_seed()

    with open(args.log) as fh:
        rows = list(csv.DictReader(fh))
    if not rows:
        raise SystemExit("empty detection log")
    for r in rows:
        r["prob"] = float(r["prob_ddos"]); r["pred"] = int(r["pred"]); r["time"] = float(r["time"])
    attack = [r for r in rows if r["pred"] == 1]

    lines = []

    def out(*a):
        s = " ".join(str(x) for x in a)
        print(s); lines.append(s)

    def table(data, header):
        lablib.print_table(data, header)
        w = [max(len(str(x)) for x in [header[i]] + [r[i] for r in data]) for i in range(len(header))]
        for r in [header] + data:
            lines.append("  " + "  ".join(str(c).ljust(w[i]) for i, c in enumerate(r)))

    out("=" * 78)
    out("POST-INCIDENT REPORT - DDoS detection (LUCID CNN)")
    out(f"Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}")
    out(f"Protected host (victim): {args.victim}")
    out("=" * 78)

    out("\n1. SUMMARY")
    if attack:
        t0, t1 = min(r["time"] for r in attack), max(r["time"] for r in attack)
        out(f"   Flows inspected ........ {len(rows)}")
        out(f"   Flows flagged as DDoS .. {len(attack)}")
        out(f"   Attack window .......... {ts(t0)} - {ts(t1)} ({t1 - t0:.0f} s)")
        out(f"   Distinct source IPs .... {len({r['peer_ip'] for r in attack})}")
        out(f"   IPs blocked ............ {len({r['peer_ip'] for r in rows if r['blocked'] == 'yes'})}")
        bt = [float(r["block_time"]) for r in rows if r.get("block_time") and r["blocked"] == "yes"]
        if bt:
            out(f"   First block ............ {ts(min(bt))} ({min(bt) - t0:.0f} s after the first attack flow)")
    else:
        out("   No DDoS flows were detected.")

    out("\n2. SOURCES (per attacking IP, model confidence on its flagged flows)")
    per = {}
    for r in attack:
        per.setdefault(r["peer_ip"], []).append(r)
    data = []
    for ip, rs in sorted(per.items(), key=lambda x: -len(x[1])):
        probs = [r["prob"] for r in rs]
        _, mean, _, lo, hi = ci(probs, np.mean)
        mine = [r for r in rows if r["peer_ip"] == ip]
        bts = [float(r["block_time"]) for r in mine if r.get("block_time") and r["blocked"] == "yes"]
        start = min(r["time"] for r in mine)
        blocked = f"{ts(min(bts))} (+{min(bts) - start:.0f} s)" if bts else "-"
        data.append([ip, len(rs), ts(min(r["time"] for r in rs)), ts(max(r["time"] for r in rs)),
                     f"{100 * np.mean(probs):.1f}", f"{100 * np.median(probs):.1f}",
                     f"{100 * lo:.1f} - {100 * hi:.1f}", blocked])
    if data:
        table(data, ["source IP", "flows", "first", "last", "mean conf %", "median %", "95 % CI %",
                     "blocked at (time to block)"])
    else:
        out("   (none)")

    if args.attackers:
        out("\n3. DETECTION QUALITY (ground truth known in the lab)")
        att = set(args.attackers)
        y = np.array([1 if r["peer_ip"] in att else 0 for r in rows])
        p = np.array([r["pred"] for r in rows])
        tp = int(((p == 1) & (y == 1)).sum()); fn = int(((p == 0) & (y == 1)).sum())
        fp = int(((p == 1) & (y == 0)).sum()); tn = int(((p == 0) & (y == 0)).sum())

        def recall(idx):
            yy, pp = y[idx], p[idx]
            d = (yy == 1).sum()
            return (pp[yy == 1] == 1).mean() if d else 0.0

        def fpr(idx):
            yy, pp = y[idx], p[idx]
            d = (yy == 0).sum()
            return (pp[yy == 0] == 1).mean() if d else 0.0

        rng = np.random.default_rng(lablib.SEED)
        rec_b = [recall(rng.integers(0, len(y), len(y))) for _ in range(1000)]
        fpr_b = [fpr(rng.integers(0, len(y), len(y))) for _ in range(1000)]
        out(f"   True attacker flows caught (recall): {100 * tp / max(tp + fn, 1):.1f} % "
            f"(95 % CI {100 * np.percentile(rec_b, 2.5):.1f} - {100 * np.percentile(rec_b, 97.5):.1f} %)")
        out(f"   Benign flows wrongly flagged (FPR):  {100 * fp / max(fp + tn, 1):.1f} % "
            f"(95 % CI {100 * np.percentile(fpr_b, 2.5):.1f} - {100 * np.percentile(fpr_b, 97.5):.1f} %)")
        out(f"   Confusion: TP={tp}  FN={fn}  FP={fp}  TN={tn}")

    out("\n4. ACTION TAKEN")
    bl = sorted({r["peer_ip"] for r in rows if r["blocked"] == "yes"})
    if bl:
        out("   An iptables INPUT DROP rule was added for each of the following source IPs:")
        for ip in bl:
            out(f"     - {ip}")
    else:
        out("   No addresses were blocked (offline analysis, or --block was not set).")

    os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)
    with open(args.out, "w") as fh:
        fh.write("\n".join(lines) + "\n")
    print(f"\n-> report written to {args.out}")

    if args.attackers:                             # expected outcome of the lab incident (screen only)
        rec = 100 * tp / max(tp + fn, 1); fp_rate = 100 * fp / max(fp + tn, 1)
        checks = [("both attackers blocked", set(args.attackers) <= set(bl)),
                  ("no other address blocked (the legitimate client keeps its access)", set(bl) <= set(args.attackers)),
                  (f"recall {rec:.1f} %, expected 100 %", rec >= 99),
                  (f"false-positive rate {fp_rate:.1f} %, expected 0 %", fp_rate <= 1)]
        print("\nExpected outcome of this incident:")
        for name, ok in checks:
            print(f"   {'PASS' if ok else 'FAIL'}  {name}")
        n_ok = sum(ok for _, ok in checks)
        print(f"   -> {n_ok} of {len(checks)} expected results reached ({100 * n_ok / len(checks):.0f} %)")
        progress.checkpoint("incident", n_ok == len(checks), score=int(round(100 * n_ok / len(checks))))
    # the last script of the lab: its first completion is the end time of the lab (stoplab is not used,
    # the student may stop the lab much later)
    progress.lab_finish()


if __name__ == "__main__":
    main()
