"""Step 5 – Shape every sample into the matrix the CNN reads.

Learning outcome: how variable-length flows become fixed-size inputs.
  * A sample (one flow in one window) becomes an n x f matrix: one row per packet, one column per
    feature (paper: n = 100 packets).
  * The first n packets are kept in time order. A flow with fewer packets is padded with rows of
    zeros; a longer flow is cut after n packets (those packets are never seen by the model).
  * The CNN slides a filter of h = 3 rows over the packet axis, so the order of the rows matters.

It also writes test_newaddr.npz: the same test flows, but the attacker and the benign client(s)
have swapped addresses (the attacker now uses an address that was benign in training, e.g. a
compromised workstation). The normalization of the pipeline is applied unchanged. If the chosen
features contain no IP address, this file equals test.npz. Used by the feature-selection
experiment (04_features.py) to see what a model learned from addresses.

usage:  python3 05_shape.py --in work/04_feat_theoretical_lucid -n 100 --out work/05_shape_theoretical_lucid
output: <out>/train.npz, val.npz, test.npz, test_newaddr.npz with X (samples, n, f), y, sample ids
"""
import argparse
import os

import numpy as np

import lablib


def swapped_address_features(pipe, f, sample_sorted_order, columns):
    """Per-row values of the chosen features for the 'new address' test copy, or None if no
    address is among the features. Rows follow the same (sorted) order as X in main()."""
    ip_cols = [j for j, c in enumerate(columns) if c in ("src_ip", "dst_ip")]
    if not ip_cols:
        return None
    p = lablib.load_npz(os.path.join(pipe["window_dir"], "packets.npz"))
    keep = np.flatnonzero(f["selected"][f["sample_of_packet"]])[sample_sorted_order]  # as in 03_normalize.py
    victims = {lablib.ip_to_int(x) for x in pipe["victims"]}
    attackers = sorted({lablib.ip_to_int(x) for x in pipe["attackers"]})
    test = f["split"] == "test"
    ends = np.concatenate([f["key"][test, 0], f["key"][test, 2]])
    benign = sorted({int(x) for x in ends} - victims - set(attackers))
    swap = {}
    for i, a in enumerate(attackers):                 # attacker -> a benign client's address ...
        swap[a] = benign[i % len(benign)]
    for i, b in enumerate(benign):                    # ... and that client -> an attacker address
        swap[b] = attackers[i % len(attackers)]
    names = lablib.ALL_FEATURES
    mins, maxs = np.array(pipe["norm_min"]), np.array(pipe["norm_max"])
    span = np.where(maxs > mins, maxs - mins, 1.0)
    vals = {}
    for c in ("src_ip", "dst_ip"):
        raw = p[c][keep].astype(np.int64)
        new = np.array([swap.get(int(v), int(v)) for v in raw], dtype=np.float64)
        j = names.index(c)
        vals[c] = ((new - mins[j]) / span[j]).astype(np.float32)
    return vals, swap


def main():
    a = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    a.add_argument("--in", dest="inp", required=True, help="output folder of 04_features.py")
    a.add_argument("-n", "--packets", type=int, default=100, help="packets per sample (paper: 100)")
    a.add_argument("--out", required=True)
    args = a.parse_args()
    if args.packets < 3:                          # the CNN kernel covers 3 consecutive packets
        raise SystemExit("-n must be at least 3 (the convolution kernel is 3 packets high)")
    lablib.set_seed()

    pipe = lablib.load_pipeline(args.inp)
    d = lablib.load_npz(os.path.join(args.inp, "features.npz"))
    f = lablib.load_npz(os.path.join(pipe["flow_dir"], "flows.npz"))
    X, sample = d["X"], d["sample"]
    n, nf = args.packets, X.shape[1]

    # rows of one sample are consecutive in time order inside each sample
    order = np.argsort(sample, kind="stable")
    X, sample = X[order], sample[order]
    starts = np.flatnonzero(np.r_[True, sample[1:] != sample[:-1]])
    ids = sample[starts]
    lengths = np.diff(np.r_[starts, len(sample)])

    columns = [str(c) for c in d["columns"]]
    swapped = swapped_address_features(pipe, f, order, columns)
    X_new = X.copy()
    if swapped:
        for c, v in swapped[0].items():
            X_new[:, columns.index(c)] = v

    os.makedirs(args.out, exist_ok=True)
    rows = []
    for split, src in (("train", X), ("val", X), ("test", X), ("test_newaddr", X_new)):
        sel = np.flatnonzero(f["split"][ids] == split.replace("_newaddr", ""))
        M = np.zeros((len(sel), n, nf), dtype=np.float32)          # zero padding by construction
        for r, j in enumerate(sel):
            k = min(lengths[j], n)                                   # truncation after n packets
            M[r, :k] = src[starts[j]:starts[j] + k]
        y = f["label"][ids[sel]]
        np.savez_compressed(os.path.join(args.out, f"{split}.npz"), X=M, y=y, sample=ids[sel])
        L = lengths[sel]
        rows.append([split, f"{M.shape}", int(y.sum()), int(len(y) - y.sum()),
                     f"{100 * (1 - np.minimum(L, n).sum() / (len(sel) * n)):.1f} %",
                     int(np.maximum(L - n, 0).sum()), f"{M.nbytes / 2**20:.2f} MB"])
    pipe.update({"step": "05_shape", "feature_dir": args.inp, "n_packets": n, "n_features": nf})
    lablib.save_pipeline(args.out, pipe)

    lablib.print_table(rows, ["split", "shape (samples, n, f)", "DDoS", "benign", "zero padding",
                              "packets cut", "memory"])
    if swapped:
        pairs = ", ".join(f"{lablib.int_to_ip(a)} -> {lablib.int_to_ip(b)}" for a, b in swapped[1].items())
        print(f"test_newaddr: addresses swapped ({pairs})")
    else:
        print("test_newaddr: no IP address among the features -> identical to test")
    print(f"-> written to {args.out}")


if __name__ == "__main__":
    main()
