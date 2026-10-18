"""Step 14 – A classical threshold detector, for comparison with LUCID.

Learning outcome: how classical DDoS detection works, where it breaks, and how it compares with
a learned model.
Classical detectors do not look at single flows. They count traffic per source address in a time
window and raise an alarm when a counter passes a fixed threshold, e.g. "more than 10 SYN packets
per second from one address". Here the counters are computed over every packet sent to the
protected host in each window (as a monitoring system would see them):
  syn   TCP SYN packets without ACK per second (connection attempts; SYN flood, HTTP flood)
  pps   packets per second
Every flow of a source that passes the threshold in a window is classified as DDoS, so the result
can be evaluated per sample exactly like the CNN (08_evaluate.py, 09_plot.py --groups classical).

The threshold is chosen on the TRAINING split (the value that best separates attacking and benign
sources there, max F1) and then applied unchanged, like any tuned rule in production.

--bots K simulates a distributed attack: the same attack flows are sent from K bot addresses
instead of one (flow by flow, seed 42), as botnets do. The traffic of every flow stays the same;
only the per-source counters shrink. LUCID never sees addresses, so its decision on every flow is
unchanged; a per-source threshold sees K small sources.

usage:  python3 14_classical.py --flows work/02_flows --rule syn --split test --out results/classical_syn.csv
        python3 14_classical.py --flows work/02_flows --rule syn --split test --bots 50 \
                                --out results/classical_syn_bots50.csv
output: CSV like 07_infer.py (sample, label, prob_ddos, pred, score) and <out>.sweep.json, the
        recall / false-positive rate of every threshold on the evaluated split (drawn by 09_plot.py)
"""
import argparse
import csv
import json
import os

import numpy as np

import lablib

RULES = {"syn": "TCP SYN packets per second from one source",
         "pps": "packets per second from one source"}
SYN, ACK = 0x02, 0x10


def source_counters(p, f, victims, window_s, rule, bots, attackers):
    """Counter of every (window, source) towards the victims, and the key of every sample.
    With bots > 1 the packets of each attack flow are moved to one of `bots` bot addresses."""
    to_victim = np.isin(p["dst_ip"], list(victims))
    src = p["src_ip"].copy()
    sample_of_packet = f["sample_of_packet"]
    k = f["key"]
    peer = np.where(np.isin(k[:, 0], list(victims)), k[:, 2], k[:, 0])     # non-victim end of every sample
    touches = np.isin(k[:, 0], list(victims)) | np.isin(k[:, 2], list(victims))
    if bots > 1:
        rng = np.random.default_rng(lablib.SEED)
        bot_of_sample = rng.integers(0, bots, len(peer))                    # one bot per (window, flow)
        attack = np.isin(peer, list(attackers)) & touches
        base = (1 << 31) + (bot_of_sample << 8)                             # private bot address space
        peer = np.where(attack, base + (peer & 0xFF), peer)
        moved = attack[sample_of_packet] & np.isin(src, list(attackers))
        src = np.where(moved, peer[sample_of_packet], src)
    if rule == "syn":
        fl = p["feats"][:, 6]
        count = (p["proto"] == 6) & ((fl & SYN) != 0) & ((fl & ACK) == 0)
    else:
        count = np.ones(len(src), dtype=bool)
    m = to_victim & count
    key = p["window"][m].astype(np.int64) * (1 << 40) + src[m]
    uniq, n = np.unique(key, return_counts=True)
    rate = dict(zip(uniq.tolist(), (n / window_s).tolist()))
    sample_key = f["window"].astype(np.int64) * (1 << 40) + peer
    score = np.array([rate.get(int(s), 0.0) if t else 0.0 for s, t in zip(sample_key, touches)])
    return score


def scores_by_threshold(score, y, thresholds):
    out = []
    for t in thresholds:
        pred = score >= t
        tp = int((pred & (y == 1)).sum()); fp = int((pred & (y == 0)).sum())
        fn = int((~pred & (y == 1)).sum()); tn = int((~pred & (y == 0)).sum())
        rec = tp / (tp + fn) if tp + fn else 0.0
        prec = tp / (tp + fp) if tp + fp else 0.0
        out.append({"threshold": float(t), "recall": rec, "fpr": fp / (fp + tn) if fp + tn else 0.0,
                    "f1": 2 * prec * rec / (prec + rec) if prec + rec else 0.0})
    return out


def main():
    a = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    a.add_argument("--flows", default="work/02_flows", help="output folder of 02_flows.py")
    a.add_argument("--rule", choices=sorted(RULES), default="syn")
    a.add_argument("--split", choices=["train", "test"], default="test")
    a.add_argument("--threshold", type=float, help="fixed threshold (default: chosen on the training split)")
    a.add_argument("--bots", type=int, default=1, help="spread every attack over this many bot addresses")
    a.add_argument("--out", required=True)
    args = a.parse_args()
    if args.bots < 1:
        raise SystemExit("--bots must be at least 1")
    lablib.set_seed()

    pipe = lablib.load_pipeline(args.flows)
    f = lablib.load_npz(os.path.join(args.flows, "flows.npz"))
    p = lablib.load_npz(os.path.join(pipe["window_dir"], "packets.npz"))
    lablib.require_same(pipe, "packets_id", lablib.packets_id(p), pipe["window_dir"], "02_flows.py")
    victims = {lablib.ip_to_int(v) for v in pipe["victims"]}
    attackers = {lablib.ip_to_int(v) for v in pipe["attackers"]}
    label, split = f["label"], f["split"]

    # threshold: tuned on the training split with the attack as recorded (one address per attacker)
    train_score = source_counters(p, f, victims, pipe["window_s"], args.rule, 1, attackers)
    tr = split == "train"
    if args.threshold is None:
        vals = np.unique(train_score[tr])
        cands = (vals[:-1] + vals[1:]) / 2 if len(vals) > 1 else vals
        res = scores_by_threshold(train_score[tr], label[tr], cands)
        best = max(r["f1"] for r in res)
        thr = [r["threshold"] for r in res if r["f1"] == best][0]
        how = "chosen on the training split (best F1)"
    else:
        thr, how = args.threshold, "given with --threshold"
    ben_max = float(train_score[tr & (label == 0)].max())
    att_train = train_score[tr & (label == 1)]
    att_med = float(np.median(att_train))

    score = source_counters(p, f, victims, pipe["window_s"], args.rule, args.bots, attackers)
    sel = split == args.split
    ids, y, s = np.flatnonzero(sel), label[sel], score[sel]
    pred = (s >= thr).astype(int)

    os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)
    with open(args.out, "w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["sample", "label", "prob_ddos", "pred", "score"])
        for i, yv, pv, sv in zip(ids, y, pred, s):
            w.writerow([int(i), int(yv), f"{float(pv):.6f}", int(pv), f"{sv:.4f}"])

    grid = np.unique(np.r_[np.geomspace(0.05, max(float(s.max()), 1.0) * 1.2, 40), thr])
    sweep = scores_by_threshold(s, y, grid)
    with open(args.out + ".sweep.json", "w") as fh:
        json.dump({"rule": args.rule, "unit": RULES[args.rule], "threshold": thr, "bots": args.bots,
                   "points": sweep}, fh, indent=1)

    att_src = s[y == 1]
    print(f"classical detector, rule '{args.rule}': {RULES[args.rule]}, window t = {pipe['window_s']:g} s")
    print(f"threshold {thr:.2f} /s, {how}; on the training split benign sources reach at most "
          f"{ben_max:.2f} /s, attacking sources {att_med:.2f} /s (median)")
    if args.bots > 1:
        print(f"distributed attack: every attack spread over {args.bots} bot addresses "
              f"(per-source rate of the attack flows now {np.median(att_src):.2f} /s median)")
    lablib.print_table([["attack flows (DDoS)", int((y == 1).sum()), int(pred[y == 1].sum()),
                         f"{np.median(att_src) if len(att_src) else 0:.2f}"],
                        ["benign flows", int((y == 0).sum()), int(pred[y == 0].sum()),
                         f"{np.median(s[y == 0]) if (y == 0).any() else 0:.2f}"]],
                       [f"{args.split} samples", "count", "flagged as DDoS", "median rate of their source /s"])
    shown = [r for r in sweep if r["threshold"] == thr] + \
            [r for r in sweep[::max(1, len(sweep) // 8)] if r["threshold"] != thr]
    shown.sort(key=lambda r: r["threshold"])
    lablib.print_table([[f"{r['threshold']:.2f}" + ("  <- chosen" if r["threshold"] == thr else ""),
                         f"{100 * r['recall']:.1f} %", f"{100 * r['fpr']:.1f} %"] for r in shown],
                       ["threshold /s", "recall", "false-positive rate"])
    print(f"-> {args.out} (evaluate with 08_evaluate.py --group classical) and {args.out}.sweep.json")


if __name__ == "__main__":
    main()
