"""Checks the output of a preprocessing step against an independent re-computation.

Run it after each step to see whether the step did what the lab sheet describes:
  python3 check.py --stage window    --dir work/01_window
  python3 check.py --stage flows     --dir work/02_flows
  python3 check.py --stage normalize --dir work/03_norm_global
  python3 check.py --stage features  --dir work/04_feat_global_lucid
  python3 check.py --stage shape     --dir work/05_shape_global_lucid
Every rule is recomputed from the previous step's files and compared. The table shows how many
items satisfy each rule; the score is the share of rules that pass completely.

After the experiments, compare your runs with the reference results of the lab:
  python3 check.py --stage results   --dir results
The lab is deterministic (seed 42), so every run of the lab sheet has one expected result. For
every reference run in results/registry.json the settings (normalization, features, n, or the
classical rule) and the metrics (within 0.5 percentage points) are compared with the reference.
"""
import argparse
import os

import numpy as np

import lablib
import progress


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
        if pipe.get("fit_on", "all") != "all":
            tr = n["X"][(split == "train") & (lablib.sample_source(f["key"][n["sample"]]) == pipe["fit_on"])]
        rules.append(("train values inside [0, 1]", *ratio(int(((tr >= 0) & (tr <= 1 + 1e-6)).all(axis=1).sum()), len(tr))))
        fit = split == "train"
        if pipe.get("fit_on", "all") != "all":
            fit &= lablib.sample_source(f["key"][n["sample"]]) == pipe["fit_on"]
        fitted = np.allclose(mins, raw[fit].min(axis=0)) and np.allclose(maxs, raw[fit].max(axis=0))
        rules.append(("min/max fitted on the TRAIN split only" + ("" if pipe.get("fit_on", "all") == "all"
                      else f" ({pipe['fit_on']} samples)"), *ratio(int(fitted), 1)))
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


# Reference results of the lab sheet (Labtainer, seed 42), in percent:
# (group, name): (accuracy, F1, false-positive rate, recall, expected settings)
# Test split: 4,551 samples of both networks (447 CIC-DDoS2019 sample, 4,104 lab network); the
# feature runs and the "test lab"/"test cic" runs use only the samples of one network (SAMPLES).
REFERENCE = {
    ("normalization", "global"):                (99.96, 99.96, 0.04, 99.96, {"norm_mode": "global", "features": "lucid", "n_packets": 100, "fit_on": "all", "train_on": "all"}),
    ("normalization", "none"):                  (97.69, 97.65, 0.00, 95.41, {"norm_mode": "none", "features": "lucid", "n_packets": 100, "fit_on": "all", "train_on": "all"}),
    ("normalization", "theoretical"):           (99.89, 99.89, 0.18, 99.96, {"norm_mode": "theoretical", "features": "lucid", "n_packets": 100, "fit_on": "all", "train_on": "all"}),
    ("normalization", "batchnorm"):             (99.98, 99.98, 0.00, 99.96, {"norm_mode": "batchnorm", "features": "lucid", "n_packets": 100, "fit_on": "all", "train_on": "all"}),
    ("features", "lucid (test)"):               (100.00, 100.00, 0.00, 100.00, {"norm_mode": "global", "features": "lucid", "n_packets": 100, "fit_on": "lab", "train_on": "lab"}),
    ("features", "lucid (test_newaddr)"):       (100.00, 100.00, 0.00, 100.00, {"norm_mode": "global", "features": "lucid", "n_packets": 100, "fit_on": "lab", "train_on": "lab"}),
    ("features", "lucid_ids (test)"):           (100.00, 100.00, 0.00, 100.00, {"norm_mode": "global", "features": "lucid_ids", "n_packets": 100, "fit_on": "lab", "train_on": "lab"}),
    ("features", "lucid_ids (test_newaddr)"):   (40.42, 5.27, 24.63, 3.41, {"norm_mode": "global", "features": "lucid_ids", "n_packets": 100, "fit_on": "lab", "train_on": "lab"}),
    ("features", "ids_only (test)"):            (100.00, 100.00, 0.00, 100.00, {"norm_mode": "global", "features": "ids_only", "n_packets": 100, "fit_on": "lab", "train_on": "lab"}),
    ("features", "ids_only (test_newaddr)"):    (1.75, 0.00, 96.59, 0.00, {"norm_mode": "global", "features": "ids_only", "n_packets": 100, "fit_on": "lab", "train_on": "lab"}),
    ("shape", "n=3"):                           (79.28, 74.04, 0.09, 58.84, {"norm_mode": "global", "features": "lucid", "n_packets": 3, "fit_on": "all", "train_on": "all"}),
    ("shape", "n=10"):                          (99.91, 99.91, 0.00, 99.83, {"norm_mode": "global", "features": "lucid", "n_packets": 10, "fit_on": "all", "train_on": "all"}),
    ("shape", "n=50"):                          (99.96, 99.96, 0.04, 99.96, {"norm_mode": "global", "features": "lucid", "n_packets": 50, "fit_on": "all", "train_on": "all"}),
    ("shape", "n=100"):                         (99.96, 99.96, 0.04, 99.96, {"norm_mode": "global", "features": "lucid", "n_packets": 100, "fit_on": "all", "train_on": "all"}),
    ("classical", "LUCID CNN"):                 (99.96, 99.96, 0.04, 99.96, {"norm_mode": "global", "features": "lucid", "n_packets": 100, "fit_on": "all", "train_on": "all"}),
    ("classical", "syn threshold"):             (96.95, 96.86, 0.00, 93.92, {"rule": "syn", "bots": 1}),
    ("classical", "syn threshold (50 bots)"):   (49.77, 0.00, 0.00, 0.00, {"rule": "syn", "bots": 50}),
    ("shift", "cic only (test cic)"):           (99.78, 99.83, 0.00, 99.66, {"norm_mode": "global", "features": "lucid", "n_packets": 100, "fit_on": "cic", "train_on": "cic"}),
    ("shift", "lab only (test cic)"):           (54.59, 49.38, 5.84, 33.79, {"norm_mode": "global", "features": "lucid", "n_packets": 100, "fit_on": "lab", "train_on": "lab"}),
    ("shift", "cic + lab (test cic)"):          (99.55, 99.66, 0.65, 99.66, {"norm_mode": "global", "features": "lucid", "n_packets": 100, "fit_on": "all", "train_on": "all"}),
    ("shift", "cic only (test lab)"):           (42.76, 0.00, 16.86, 0.00, {"norm_mode": "global", "features": "lucid", "n_packets": 100, "fit_on": "cic", "train_on": "cic"}),
    ("shift", "lab only (test lab)"):           (100.00, 100.00, 0.00, 100.00, {"norm_mode": "global", "features": "lucid", "n_packets": 100, "fit_on": "lab", "train_on": "lab"}),
    ("shift", "cic + lab (test lab)"):          (100.00, 100.00, 0.00, 100.00, {"norm_mode": "global", "features": "lucid", "n_packets": 100, "fit_on": "all", "train_on": "all"}),
}
SAMPLES = {"default": 4551,
    ("features", "lucid (test)"): 4104,
    ("features", "lucid (test_newaddr)"): 4104,
    ("features", "lucid_ids (test)"): 4104,
    ("features", "lucid_ids (test_newaddr)"): 4104,
    ("features", "ids_only (test)"): 4104,
    ("features", "ids_only (test_newaddr)"): 4104,
    ("shift", "cic only (test cic)"): 447,
    ("shift", "lab only (test cic)"): 447,
    ("shift", "cic + lab (test cic)"): 447,
    ("shift", "cic only (test lab)"): 4104,
    ("shift", "lab only (test lab)"): 4104,
    ("shift", "cic + lab (test lab)"): 4104,
}
HINT = {"norm_mode": "the --mode of 03_normalize.py", "features": "the --set of 04_features.py",
        "n_packets": "the -n of 05_shape.py", "rule": "the --rule of 14_classical.py",
        "bots": "the --bots of 14_classical.py", "fit_on": "the --fit-on of 03_normalize.py",
        "train_on": "the --train-on of 06_train.py",
        "result": "the --split and --source of 07_infer.py or the input files"}
# Runs whose metrics depend on the computer: training on raw values is numerically unstable, so tiny
# rounding differences between CPUs lead to different models (76.8 % and 97.7 % accuracy were
# measured on two machines). Only their settings and sample count are compared.
VARIES = {("normalization", "none")}
TOLERANCE = 0.5                                                   # percentage points
# A model applied to a network it was not trained on extrapolates far outside its training range, so
# its result also differs a little between computers (accuracy 40.0-43.8 %, false-positive rate
# 14.8-22.2 % measured on four machines; recall always 0 %). It is compared with a wider tolerance.
RUN_TOLERANCE = {("shift", "cic only (test lab)"): 10.0}


def run_settings(r):
    """Settings a registry entry was produced with: from its model file or its classical sweep."""
    if r.get("sweep"):
        return {"rule": r["sweep"]["rule"], "bots": r["sweep"]["bots"]}
    log = r.get("train_log")
    model = log[:-len("_train_log.json")] + ".pt" if log else None
    if not model or not os.path.exists(model):
        return {}
    import torch
    pipe = torch.load(model, map_location="cpu")["pipeline"]
    sets = {"lucid": lablib.LUCID_FEATURES, "lucid_ids": lablib.LUCID_FEATURES + lablib.ID_FEATURES,
            "ids_only": lablib.ID_FEATURES}
    feats = next((k for k, v in sets.items() if list(v) == list(pipe.get("features", []))), "custom")
    return {"norm_mode": pipe.get("norm_mode"), "features": feats, "n_packets": pipe.get("n_packets"),
            "fit_on": pipe.get("fit_on", "all"), "train_on": pipe.get("train", {}).get("train_on", "all")}


def compare_run(r):
    """(matches, note) for one registry entry that has a reference (REFERENCE[(group, name)])."""
    *ref, want = REFERENCE[(r["group"], r["name"])]
    got = [100 * r["point"][m] for m in ("accuracy", "f1", "fpr", "recall")]
    have = run_settings(r)
    wrong = [k for k, v in want.items() if k in have and have[k] != v]
    samples = SAMPLES.get((r["group"], r["name"]), SAMPLES["default"])
    tol = RUN_TOLERANCE.get((r["group"], r["name"]), TOLERANCE)
    off = any(abs(g - e) > tol for g, e in zip(got, ref))
    if wrong:
        return False, "; ".join(f"{k} is {have[k]}, expected {want[k]}: check {HINT[k]}" for k in wrong)
    if r["samples"] != samples:
        return False, f"{r['samples']} test samples, expected {samples}: check {HINT['result']}"
    if off and (r["group"], r["name"]) in VARIES:
        return True, "settings match (the result of raw values varies between computers)"
    if off:
        return False, f"different result (F1 {got[1]:.1f}, expected {ref[1]:.1f}): check {HINT['result']}"
    return True, "matches the reference" + ("" if have else " (settings not linked: use --model in 08_evaluate.py)")


def load_registry(d):
    import json
    path = os.path.join(d, "registry.json")
    if not os.path.exists(path):
        raise SystemExit(f"{path} not found: evaluate your runs with 08_evaluate.py first")
    return {(r["group"], r["name"]): r for r in json.load(open(path))}


def check_results(d):
    reg = load_registry(d)
    rows, ok_count = [], 0
    for (group, name), (*ref, want) in REFERENCE.items():
        r = reg.get((group, name))
        if r is None:
            rows.append([group, name, "-", f"{ref[0]:.1f}", "not run yet (run it with this --name and --group)"])
            continue
        ok, note = compare_run(r)
        ok_count += ok
        rows.append([group, name, f"{100 * r['point']['accuracy']:.1f}", f"{ref[0]:.1f}", note])
    extra = sorted(k for k in reg if k not in REFERENCE)
    return rows, ok_count, extra


def main():
    a = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    a.add_argument("--stage", choices=["window", "flows", "normalize", "features", "shape", "results"], required=True)
    a.add_argument("--dir", required=True)
    args = a.parse_args()
    if args.stage == "results":
        rows, ok_count, extra = check_results(args.dir)
        lablib.print_table(rows, ["group", "run", "your accuracy %", "expected %", "check"])
        if extra:
            print("runs that are not part of the lab sheet (not checked): " + ", ".join(f"{g}/{n}" for g, n in extra))
        score = 100 * ok_count / len(REFERENCE)
        print(f"{ok_count} of {len(REFERENCE)} reference runs match")
        print(f"results stage - {score:.0f} % of the reference runs match")   # graded by Labtainer
        progress.checkpoint("results", ok_count == len(REFERENCE), score=int(round(score)))
        return
    rules = {"window": check_window, "flows": check_flows, "normalize": check_normalize,
             "features": check_features, "shape": check_shape}[args.stage](args.dir)
    scored = [r for r in rules if r[1] != "info"]
    lablib.print_table([[name, val, "PASS" if ok else "FAIL"] for name, val, ok in rules], ["rule", "result", ""])
    score = 100 * sum(ok for _, _, ok in scored) / len(scored)
    print(f"{args.stage} stage - {score:.0f} % of the rules pass")     # graded by Labtainer (no colon)
    progress.checkpoint(args.stage, score == 100, score=int(round(score)))


if __name__ == "__main__":
    main()
