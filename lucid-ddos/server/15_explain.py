"""Step 15 – Explain the decisions of a trained model and find its limits.

Learning outcome: judging what a model has learned and where it fails, instead of trusting a score.
  * Permutation importance: the values of ONE feature are shuffled between the packets of the
    split (padding rows stay zero), so that feature no longer carries information, and the model
    is evaluated again. The larger the drop in accuracy, the more the model relies on that
    feature. This is repeated --repeats times (seed 42); the table shows the mean drop and the
    range over the repeats.
  * Errors by flow length: the error rate of the model for short and long flows (packets of the
    flow in its window, before shaping). With a small n, flows longer than n packets are cut, and
    the packets that would show the difference may be missing.
A model trained with IP addresses (lucid_ids) shows its shortcut here: the address features are
the most important ones.

usage:  python3 15_explain.py --model models/global_lucid.pt --data work/05_shape_global_lucid --split test
output: table on screen, results/explain_<model>.csv and results/plots/explain_<model>.png
"""
import argparse
import csv
import os

import numpy as np

import lablib


def accuracy_f1(y, p):
    tp = int(((p == 1) & (y == 1)).sum()); fp = int(((p == 1) & (y == 0)).sum())
    fn = int(((p == 0) & (y == 1)).sum())
    prec = tp / (tp + fp) if tp + fp else 0.0
    rec = tp / (tp + fn) if tp + fn else 0.0
    return float((p == y).mean()), 2 * prec * rec / (prec + rec) if prec + rec else 0.0


def main():
    a = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    a.add_argument("--model", required=True)
    a.add_argument("--data", required=True, help="output folder of 05_shape.py")
    a.add_argument("--split", choices=["test", "test_newaddr", "val"], default="test")
    a.add_argument("--repeats", type=int, default=5)
    a.add_argument("--out", help="CSV (default results/explain_<model>.csv)")
    args = a.parse_args()
    lablib.set_seed()
    import torch

    ck = torch.load(args.model, map_location="cpu")
    pipe = ck["pipeline"]
    data_pipe = lablib.load_pipeline(args.data)
    differ = [k for k in ("window_s", "flows_id", "norm_mode", "features", "n_packets")
              if k in pipe and k in data_pipe and pipe[k] != data_pipe[k]]
    if differ:
        raise SystemExit(f"the model was trained on data prepared differently ({', '.join(differ)})")
    d = lablib.load_npz(os.path.join(args.data, f"{args.split}.npz"))
    X, y = d["X"], d["y"].astype(int)
    model = lablib.build_model(pipe["n_features"], pipe["train"]["kernels"], batchnorm=pipe.get("batchnorm", False))
    model.load_state_dict(ck["state"])
    model.eval()

    def predict(M):
        return (torch.sigmoid(lablib.predict_logits(model, torch.from_numpy(M))).numpy() >= 0.5).astype(int)

    pred = predict(X)
    acc0, f10 = accuracy_f1(y, pred)
    real = np.abs(X).sum(axis=2) > 0                     # packet rows (padding rows are all zero)
    rng = np.random.default_rng(lablib.SEED)
    rows = []
    for j, name in enumerate(pipe["features"]):
        drops_acc, drops_f1 = [], []
        for _ in range(args.repeats):
            M = X.copy()
            v = M[:, :, j][real]
            M[:, :, j][real] = rng.permutation(v)
            acc, f1 = accuracy_f1(y, predict(M))
            drops_acc.append(acc0 - acc); drops_f1.append(f10 - f1)
        rows.append((name, float(np.mean(drops_acc)), float(np.min(drops_acc)), float(np.max(drops_acc)),
                     float(np.mean(drops_f1))))
    rows.sort(key=lambda r: -r[1])

    # errors by flow length (packets of the flow in its window, before shaping)
    f = lablib.load_npz(os.path.join(pipe["flow_dir"], "flows.npz"))
    length = f["packets"][d["sample"]]
    n = pipe["n_packets"]
    bins = [(1, 2), (3, 3), (4, 10), (11, n), (n + 1, None)] if n > 10 else [(1, 2), (3, n), (n + 1, 10), (11, None)]
    err_rows = []
    for lo, hi in bins:
        m = (length >= lo) & (length <= (hi if hi is not None else length.max()))
        if lo > (hi if hi is not None else lo) or not m.any():
            continue
        e = pred[m] != y[m]
        label = f"{lo}" if hi == lo else (f"{lo}-{hi}" if hi is not None else f"> {lo - 1}")
        err_rows.append([label + (" (cut after n)" if lo > n else ""), int(m.sum()), int((y[m] == 1).sum()),
                         int(e.sum()), f"{100 * e.mean():.1f} %"])

    tag = os.path.splitext(os.path.basename(args.model))[0]
    out = args.out or os.path.join("results", f"explain_{tag}.csv")
    os.makedirs(os.path.dirname(out) or ".", exist_ok=True)
    with open(out, "w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["feature", "accuracy_drop", "drop_min", "drop_max", "f1_drop"])
        for r in rows:
            w.writerow([r[0]] + [f"{v:.6f}" for v in r[1:]])

    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    fig, ax = plt.subplots(figsize=(8, 0.42 * len(rows) + 1.4))
    names = [r[0] for r in rows][::-1]
    mean = [100 * r[1] for r in rows][::-1]
    err = [[100 * (r[1] - r[2]) for r in rows][::-1], [100 * (r[3] - r[1]) for r in rows][::-1]]
    ax.barh(names, mean, xerr=err, capsize=3, color=["#B85450" if nm in lablib.ID_FEATURES else "#6C8EBF" for nm in names])
    ax.set_xlabel("drop in accuracy when the feature is shuffled (percentage points)")
    ax.set_title(f"Permutation importance – {tag} ({args.split}, accuracy {100 * acc0:.1f} %)")
    fig.tight_layout()
    plot = os.path.join("results", "plots", f"explain_{tag}.png")
    os.makedirs(os.path.dirname(plot), exist_ok=True)
    fig.savefig(plot, dpi=130)
    plt.close(fig)

    print(f"model {args.model} on {args.split}: {len(y)} samples, accuracy {100 * acc0:.1f} %, F1 {100 * f10:.1f} %")
    print(f"permutation importance ({args.repeats} shuffles per feature, seed {lablib.SEED}):")
    lablib.print_table([[r[0], "identifier" if r[0] in lablib.ID_FEATURES else "header",
                         f"{100 * r[1]:.1f}", f"{100 * r[2]:.1f} .. {100 * r[3]:.1f}", f"{100 * r[4]:.1f}"] for r in rows],
                       ["feature", "kind", "accuracy drop (pp)", "range", "F1 drop (pp)"])
    print(f"errors by flow length (n = {n} packets per sample):")
    lablib.print_table(err_rows, ["packets in flow", "samples", "DDoS", "errors", "error rate"])
    print(f"-> {out}, {plot}")


if __name__ == "__main__":
    main()
