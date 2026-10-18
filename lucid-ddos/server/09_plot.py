"""Step 9 – Compare runs in a figure (for the written analysis).

Learning outcome: reading a chart with confidence intervals and explaining a difference.
For every experiment group (normalization, features, shape, classical, ...) one figure is drawn from
results/registry.json (written by 08_evaluate.py):
  left    test accuracy, F1 and false-positive rate of every run; the error bars are the 95 %
          bootstrap confidence intervals
  middle  training loss per epoch (log scale), if the run was linked to its model; for the
          classical rules of 14_classical.py the recall and false-positive rate of every threshold
  right   table: mean, median and 95 % CI of accuracy, F1 and FPR for every run
The same table is printed on the screen. Figures are numbered in the order the groups are given.

usage:  python3 09_plot.py --groups normalization features shape
output: results/plots/figure1_normalization.png, figure2_features.png, ...
"""
import argparse
import json
import os

import lablib

SHOW = [("accuracy", "accuracy"), ("f1", "F1"), ("fpr", "false-positive rate")]


def figure(k, group, runs, out_dir):
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    names = [r["name"].replace(" (", "\n(") for r in runs]          # "lucid (test_newaddr)" on two lines
    fig = plt.figure(figsize=(18, 5.6))
    gs = fig.add_gridspec(1, 3, width_ratios=[1.25, 1.0, 1.35])
    ax = fig.add_subplot(gs[0])
    width = 0.8 / len(SHOW)
    for j, (m, label) in enumerate(SHOW):
        xs = [i + (j - (len(SHOW) - 1) / 2) * width for i in range(len(runs))]
        vals = [100 * r["point"][m] for r in runs]
        lo = [100 * (r["point"][m] - r["ci"][m]["ci_low"]) for r in runs]
        hi = [100 * (r["ci"][m]["ci_high"] - r["point"][m]) for r in runs]
        ax.bar(xs, vals, width, yerr=[lo, hi], capsize=3, label=label)
        for x, v in zip(xs, vals):
            ax.text(x, v + 2, f"{v:.0f}" if v in (0, 100) else f"{v:.1f}", ha="center", fontsize=7)
    ax.set_xticks(range(len(runs)))
    ax.set_xticklabels(names, fontsize=8)
    ax.set_ylim(0, 125)
    ax.set_ylabel("% (test set)")
    ax.set_title(f"Figure {k}a – {group}: test metrics with 95 % CI")
    ax.legend(fontsize=8, loc="upper center", ncol=3, frameon=False)

    ax2 = fig.add_subplot(gs[1])
    drew, seen = False, set()
    sweeps = [r for r in runs if r.get("sweep")]
    if sweeps:                                         # classical rules: recall / FPR for every threshold
        for i, r in enumerate(sweeps):
            sw = r["sweep"]; pts = sw["points"]; c = f"C{i}"
            ax2.plot([q["threshold"] for q in pts], [100 * q["recall"] for q in pts], color=c, label=f"{r['name']}: recall")
            ax2.plot([q["threshold"] for q in pts], [100 * q["fpr"] for q in pts], color=c, ls="--", label=f"{r['name']}: FPR")
            ax2.axvline(sw["threshold"], color=c, ls=":", lw=1)
        ax2.set_xscale("log")
        ax2.set_xlabel("threshold (per source, per second; dotted = chosen)")
        ax2.set_ylabel("% (evaluated split)")
        ax2.set_title(f"Figure {k}b – threshold sweep of the classical rules")
        ax2.legend(fontsize=7)
    for r in ([] if sweeps else runs):                 # one curve per model (several runs may share one)
        log = r.get("train_log")
        if log and os.path.exists(log) and log not in seen:
            seen.add(log)
            ep = json.load(open(log))["epochs"]
            label = os.path.basename(log).replace("_train_log.json", "")
            ax2.plot([e[0] for e in ep], [max(float(e[1]), 1e-6) for e in ep], marker="o", ms=3, label=label)
            drew = True
    if not sweeps:
        ax2.set_yscale("log")
        ax2.set_xlabel("epoch")
        ax2.set_ylabel("training loss (log scale)")
        ax2.set_title(f"Figure {k}b – training loss")
        if drew:
            ax2.legend(fontsize=8)
        else:
            ax2.text(0.5, 0.5, "no training logs linked", ha="center", transform=ax2.transAxes)

    ax3 = fig.add_subplot(gs[2])
    ax3.axis("off")
    cells = []
    for r in runs:
        for m, label in SHOW:
            c = r["ci"][m]
            cells.append([r["name"], label, f"{100 * c['mean']:.1f}", f"{100 * c['median']:.1f}",
                          f"{100 * c['ci_low']:.1f} – {100 * c['ci_high']:.1f}"])
    t = ax3.table(cellText=cells, colLabels=["run", "metric", "mean %", "median %", "95 % CI %"],
                  loc="center", cellLoc="center")
    t.auto_set_font_size(False)
    t.set_fontsize(7.5)
    t.auto_set_column_width(list(range(5)))
    t.scale(1, 1.15)
    sizes = sorted({r["samples"] for r in runs})
    size = f"{sizes[0]} test samples per run" if len(sizes) == 1 else f"{' or '.join(map(str, sizes))} test samples per run"
    ax3.set_title(f"Table {k} – bootstrap statistics ({size})")
    fig.tight_layout()
    path = os.path.join(out_dir, f"figure{k}_{group}.png")
    fig.savefig(path, dpi=130)
    plt.close(fig)
    return path, cells


def main():
    a = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    a.add_argument("--groups", nargs="+", required=True)
    a.add_argument("--registry", default="results/registry.json")
    a.add_argument("--out", default="results/plots")
    args = a.parse_args()
    lablib.set_seed()
    reg = json.load(open(args.registry))
    os.makedirs(args.out, exist_ok=True)
    for k, g in enumerate(args.groups, 1):
        runs = [r for r in reg if r["group"] == g]
        if not runs:
            print(f"group '{g}': no runs in {args.registry} (run 08_evaluate.py with --group {g})")
            continue
        path, cells = figure(k, g, runs, args.out)
        print(f"Figure {k} / Table {k}: {g}")
        lablib.print_table(cells, ["run", "metric", "mean %", "median %", "95 % CI %"])
        print(f"-> {path}")


if __name__ == "__main__":
    main()
