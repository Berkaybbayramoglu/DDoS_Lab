"""Checks the output of a preprocessing step against an independent re-computation.

Run it after each step to see whether the step did what the lab sheet describes:
  python3 check.py --stage window    --dir work/01_window
  python3 check.py --stage flows     --dir work/02_flows
  python3 check.py --stage normalize --dir work/03_norm_global
  python3 check.py --stage features  --dir work/04_feat_global_lucid
  python3 check.py --stage shape     --dir work/05_shape_global_lucid
Every rule is recomputed from the previous step's files and compared. The table shows how many
items satisfy each rule; the score is the share of rules that pass completely.
"""
import argparse
import os

import numpy as np

import lablib


def ratio(ok, total):
    return f"{ok}/{total}", ok == total


def check_window(d):
    pipe = lablib.load_pipeline(d)
    p = lablib.load_npz(os.path.join(d, "packets.npz"))
    ts, win, t = p["ts"], p["window"], pipe["window_s"]
    rules = []
    rules.append(("packets in time order", *ratio(int((np.diff(ts) >= 0).sum()) + 1, len(ts))))
    # independent rule: a new window starts exactly when a packet is later than start + t
    starts = {}
    for w, x in zip(win, ts):
        starts.setdefault(int(w), x)
    inside = sum(int(x <= starts[int(w)] + t) for w, x in zip(win, ts))
    rules.append(("every packet within [window start, start + t]", *ratio(inside, len(ts))))
    ws = sorted(starts)
    good = sum(1 for a, b in zip(ws, ws[1:]) if starts[b] > starts[a] + t
               and not np.any((ts > starts[a] + t) & (ts < starts[b])))
    rules.append(("next window starts at the first packet after the previous window ended",
                  *ratio(good, max(len(ws) - 1, 0))))
    rules.append(("window ids are consecutive", *ratio(int(np.all(np.diff(ws) == 1)), 1)))
    return rules


def check_flows(d):
    pipe = lablib.load_pipeline(d)
    f = lablib.load_npz(os.path.join(d, "flows.npz"))
    p = lablib.load_npz(os.path.join(pipe["window_dir"], "packets.npz"))
    s = f["sample_of_packet"]
    rules = [("every packet belongs to a sample", *ratio(int((s >= 0).sum()), len(s)))]
    same_win = int((p["window"] == f["window"][s]).sum())
    rules.append(("packet window == sample window", *ratio(same_win, len(s))))
    # independent check: the sample key must equal the packet's 5-tuple read in ONE of the two directions
    k = f["key"][s]
    fwd = np.stack([p["src_ip"], p["src_port"], p["dst_ip"], p["dst_port"], p["proto"]], axis=1)
    bwd = np.stack([p["dst_ip"], p["dst_port"], p["src_ip"], p["src_port"], p["proto"]], axis=1)
    same_key = int(((k == fwd).all(axis=1) | (k == bwd).all(axis=1)).sum())
    rules.append(("packet 5-tuple (either direction) == sample key", *ratio(same_key, len(s))))
    first = f["first_packet"]
    rules.append(("sample 'time' feature == 0 at its first packet",
                  *ratio(int((f["rel_time"][first] == 0).sum()), len(first))))
    att = np.array([lablib.ip_to_int(x) for x in pipe["attackers"]])
    vic = np.array([lablib.ip_to_int(x) for x in pipe["victims"]])
    a_, b_ = f["key"][:, 0], f["key"][:, 2]
    lab = ((np.isin(a_, att) & np.isin(b_, vic)) | (np.isin(b_, att) & np.isin(a_, vic))).astype(int)
    rules.append(("label == attacker<->victim rule", *ratio(int((lab == f["label"]).sum()), len(lab))))
    sel = f["selected"]
    if pipe.get("balanced", True):
        rules.append(("selected samples balanced (DDoS == benign)",
                      *ratio(int((f["label"][sel] == 1).sum() == (f["label"][sel] == 0).sum()), 1)))
    by_split = {sp: {tuple(k) for k in f["key"][f["split"] == sp]} for sp in ("train", "val", "test")}
    overlap = len(by_split["train"] & by_split["test"]) + len(by_split["train"] & by_split["val"]) + \
        len(by_split["val"] & by_split["test"])
    rules.append(("no flow appears in two splits", *ratio(int(overlap == 0), 1)))
    return rules


def check_normalize(d):
    pipe = lablib.load_pipeline(d)
    n = lablib.load_npz(os.path.join(d, "features.npz"))
    f = lablib.load_npz(os.path.join(pipe["flow_dir"], "flows.npz"))
    p = lablib.load_npz(os.path.join(pipe["window_dir"], "packets.npz"))
    keep = np.flatnonzero(f["selected"][f["sample_of_packet"]])
    raw = np.column_stack([f["rel_time"][keep], p["feats"][keep], p["src_ip"][keep], p["dst_ip"][keep],
                           p["src_port"][keep], p["dst_port"][keep]]).astype(np.float64)
    mins, maxs = np.array(pipe["norm_min"]), np.array(pipe["norm_max"])
    span = np.where(maxs > mins, maxs - mins, 1.0)
    expect = (raw - mins) / span
    close = int(np.isclose(n["X"], expect, rtol=1e-5, atol=1e-6).all(axis=1).sum())
    rules = [("every value == (raw - min) / (max - min)", *ratio(close, len(raw)))]
    split = f["split"][n["sample"]]
    tr = n["X"][split == "train"]
    if pipe["norm_mode"] == "global":
        rules.append(("train values inside [0, 1]", *ratio(int(((tr >= 0) & (tr <= 1 + 1e-6)).all(axis=1).sum()), len(tr))))
        fitted = np.allclose(mins, raw[split == "train"].min(axis=0)) and np.allclose(maxs, raw[split == "train"].max(axis=0))
        rules.append(("min/max fitted on the TRAIN split only", *ratio(int(fitted), 1)))
    if pipe["norm_mode"] == "theoretical":
        rules.append(("all values inside [0, 1]", *ratio(int(((n["X"] >= 0) & (n["X"] <= 1)).all(axis=1).sum()), len(raw))))
    return rules


def check_features(d):
    pipe = lablib.load_pipeline(d)
    x = lablib.load_npz(os.path.join(d, "features.npz"))
    src = lablib.load_npz(os.path.join(pipe["norm_dir"], "features.npz"))
    idx = [list(src["columns"]).index(c) for c in pipe["features"]]
    rules = [("columns == requested features", *ratio(int(list(x["columns"]) == pipe["features"]), 1)),
             ("values copied unchanged", *ratio(int(np.array_equal(x["X"], src["X"][:, idx])), 1))]
    ids = [c for c in x["columns"] if c in lablib.ID_FEATURES]
    rules.append((f"identifier features used: {', '.join(ids) or 'none'}", "info", True))
    return rules


def check_shape(d):
    pipe = lablib.load_pipeline(d)
    x = lablib.load_npz(os.path.join(pipe["feature_dir"], "features.npz"))
    f = lablib.load_npz(os.path.join(pipe["flow_dir"], "flows.npz"))
    n, rules = pipe["n_packets"], []
    rows_of = {}
    for i, s in enumerate(x["sample"]):
        rows_of.setdefault(int(s), []).append(i)
    for split in ("train", "val", "test"):
        z = lablib.load_npz(os.path.join(d, f"{split}.npz"))
        ok_shape = z["X"].shape[1:] == (n, len(pipe["features"]))
        good = 0
        for M, s, yv in zip(z["X"], z["sample"], z["y"]):
            r = rows_of[int(s)][:n]
            k = len(r)
            good += int(np.array_equal(M[:k], x["X"][r]) and not M[k:].any() and yv == f["label"][s])
        rules.append((f"{split}: shape (n, f) and first n packets + zero padding + label",
                      *ratio(good if ok_shape else 0, len(z["y"]))))
    return rules


def main():
    a = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    a.add_argument("--stage", choices=["window", "flows", "normalize", "features", "shape"], required=True)
    a.add_argument("--dir", required=True)
    args = a.parse_args()
    rules = {"window": check_window, "flows": check_flows, "normalize": check_normalize,
             "features": check_features, "shape": check_shape}[args.stage](args.dir)
    scored = [r for r in rules if r[1] != "info"]
    lablib.print_table([[name, val, "PASS" if ok else "FAIL"] for name, val, ok in rules], ["rule", "result", ""])
    score = 100 * sum(ok for _, _, ok in scored) / len(scored)
    print(f"{args.stage} stage - {score:.0f} % of the rules pass")     # graded by Labtainer (no colon)


if __name__ == "__main__":
    main()
