"""Step 8 – Evaluate predictions.

Learning outcome: reading classification metrics and their uncertainty.
  accuracy   share of all samples classified correctly
  precision  of the samples flagged as DDoS, how many really were DDoS
  recall     of the real DDoS samples, how many were caught (TPR)
  F1         harmonic mean of precision and recall (the paper's main metric)
  FPR        share of benign samples wrongly flagged as DDoS
95 % confidence intervals come from a bootstrap: the test samples are resampled 1000 times
(seed 42) and the metric is recomputed each time; the interval holds the middle 95 % of values.
The result is also appended to results/registry.json so that 09_plot.py can compare runs.

usage:  python3 08_evaluate.py --pred results/theoretical_lucid_test.csv --name theoretical \
                               --group normalization --model models/theoretical_lucid.pt
"""
import argparse
import csv
import json
import os

import numpy as np

import lablib

METRICS = ["accuracy", "precision", "recall", "f1", "fpr"]


def metrics(y, p):
    tp = int(((p == 1) & (y == 1)).sum()); fp = int(((p == 1) & (y == 0)).sum())
    tn = int(((p == 0) & (y == 0)).sum()); fn = int(((p == 0) & (y == 1)).sum())
    prec = tp / (tp + fp) if tp + fp else 0.0
    rec = tp / (tp + fn) if tp + fn else 0.0
    return {"accuracy": (tp + tn) / len(y), "precision": prec, "recall": rec,
            "f1": 2 * prec * rec / (prec + rec) if prec + rec else 0.0,
            "fpr": fp / (fp + tn) if fp + tn else 0.0, "tp": tp, "fp": fp, "tn": tn, "fn": fn}


def bootstrap(y, p, n=1000):
    rng = np.random.default_rng(lablib.SEED)
    vals = {m: [] for m in METRICS}
    for _ in range(n):
        i = rng.integers(0, len(y), len(y))
        r = metrics(y[i], p[i])
        for m in METRICS:
            vals[m].append(r[m])
    return {m: {"mean": float(np.mean(v)), "median": float(np.median(v)),
                "ci_low": float(np.percentile(v, 2.5)), "ci_high": float(np.percentile(v, 97.5))}
            for m, v in vals.items()}


def main():
    a = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    a.add_argument("--pred", required=True, help="CSV written by 07_infer.py (or 14_classical.py)")
    a.add_argument("--name", required=True, help="name of this run (shown in plots)")
    a.add_argument("--group", default="other", help="experiment group, e.g. normalization, features, shape, classical")
    a.add_argument("--model", help="model file the predictions came from (links its training log for 09_plot.py)")
    a.add_argument("--registry", default="results/registry.json")
    args = a.parse_args()
    lablib.set_seed()

    with open(args.pred) as fh:
        rows = list(csv.DictReader(fh))
    y = np.array([int(r["label"]) for r in rows]); p = np.array([int(r["pred"]) for r in rows])
    point, ci = metrics(y, p), bootstrap(y, p)

    table = [[m, f"{100 * point[m]:.1f} %", f"{100 * ci[m]['mean']:.1f} %", f"{100 * ci[m]['median']:.1f} %",
              f"{100 * ci[m]['ci_low']:.1f} - {100 * ci[m]['ci_high']:.1f} %"] for m in METRICS]
    print(f"run '{args.name}' ({args.group}): {len(y)} samples, {int(y.sum())} DDoS / {int(len(y) - y.sum())} benign")
    lablib.print_table(table, ["metric", "value", "bootstrap mean", "median", "95 % CI"])
    lablib.print_table([["true DDoS", point["tp"], point["fn"]], ["true benign", point["fp"], point["tn"]]],
                       ["", "predicted DDoS", "predicted benign"])

    reg = []
    if os.path.exists(args.registry):
        with open(args.registry) as fh:
            reg = json.load(fh)
    reg = [r for r in reg if not (r["name"] == args.name and r["group"] == args.group)]   # re-run replaces
    log = os.path.splitext(args.model)[0] + "_train_log.json" if args.model else None
    sweep_file = args.pred + ".sweep.json"                    # written by 14_classical.py
    sweep = json.load(open(sweep_file)) if os.path.exists(sweep_file) else None
    reg.append({"name": args.name, "group": args.group, "pred": args.pred, "samples": len(y),
                "train_log": log if log and os.path.exists(log) else None, "sweep": sweep,
                "point": {m: point[m] for m in METRICS}, "ci": ci,
                "confusion": {k: point[k] for k in ("tp", "fp", "tn", "fn")}})
    os.makedirs(os.path.dirname(args.registry) or ".", exist_ok=True)
    with open(args.registry, "w") as fh:
        json.dump(reg, fh, indent=1)
    print(f"-> added to {args.registry} (group '{args.group}', {sum(r['group'] == args.group for r in reg)} runs)")

    # the lab is deterministic: compare this run with its expected result and show the progress
    import check
    entry = reg[-1]
    if (args.group, args.name) in check.REFERENCE:
        acc, f1, fpr = check.REFERENCE[(args.group, args.name)][:3]
        ok, note = check.compare_run(entry)
        print(f"expected result of this run: accuracy {acc:.1f} %, F1 {f1:.1f} %, false-positive rate {fpr:.1f} %"
              + (" (on the reference computer; this run varies between computers)" if (args.group, args.name) in check.VARIES
                 else f" (within {check.RUN_TOLERANCE[(args.group, args.name)]:g} points: this run varies a little between computers)"
                 if (args.group, args.name) in check.RUN_TOLERANCE else ""))
        print(f"your run: {'OK - ' if ok else 'CHECK - '}{note}")
    else:
        print(f"no expected result for '{args.name}' in group '{args.group}' (not a run of the lab sheet)")
    done = sum(1 for r in reg if (r["group"], r["name"]) in check.REFERENCE and check.compare_run(r)[0])
    total = len(check.REFERENCE)
    print(f"progress: {done} of {total} runs of the lab sheet match the reference ({100 * done / total:.0f} %)")


if __name__ == "__main__":
    main()
