"""Step 3 – Normalize the packet features.

Learning outcome: why the scale of the inputs matters and how the choice of scaling changes results.
Modes:
  none         raw header values (packet length ~1e3, TCP ack ~1e9, flags ~1e1 ...)
  theoretical  LUCID's choice: min-max with the THEORETICAL range of every field
               (e.g. window size 0..65535, ack 0..2^32, time 0..t). Same scale for any network
               -> a "super-global" normalization that needs no data at all.
  global       min-max with the range seen in the TRAINING data (fitted on train, applied to
               val/test). Uses the full [0, 1] range, but values outside the training range
               appear on new traffic.
  batchnorm    values stay raw here; a BatchNorm layer inside the CNN learns the scaling
               (mean/variance per feature) during training (see 06_train.py).

usage:  python3 03_normalize.py --in work/02_flows --mode theoretical --out work/03_norm_theoretical
"""
import argparse
import os

import numpy as np

import lablib


def build_packet_matrix(win_dir, flow_dir):
    """Packets of the selected samples, columns = lablib.ALL_FEATURES (unscaled)."""
    p = lablib.load_npz(os.path.join(win_dir, "packets.npz"))
    f = lablib.load_npz(os.path.join(flow_dir, "flows.npz"))
    keep = np.flatnonzero(f["selected"][f["sample_of_packet"]])     # packets of selected samples, time order
    X = np.column_stack([f["rel_time"][keep], p["feats"][keep],
                         p["src_ip"][keep], p["dst_ip"][keep], p["src_port"][keep], p["dst_port"][keep]])
    return X.astype(np.float64), f["sample_of_packet"][keep], f, p


def main():
    a = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    a.add_argument("--in", dest="inp", default="work/02_flows")
    a.add_argument("--mode", choices=["none", "theoretical", "global", "batchnorm"], required=True)
    a.add_argument("--fit-on", dest="fit_on", choices=["all", "cic", "lab"], default="all",
                   help="global mode: fit min/max on the training samples of this network only "
                        "(cic = CIC-DDoS2019 sample, lab = lab network, all = both)")
    a.add_argument("--out", default=None)
    args = a.parse_args()
    out = args.out or f"work/03_norm_{args.mode}"
    lablib.set_seed()

    pipe = lablib.load_pipeline(args.inp)
    X, sample, f, p = build_packet_matrix(pipe["window_dir"], args.inp)
    lablib.require_same(pipe, "packets_id", lablib.packets_id(p), pipe["window_dir"], "02_flows.py and the later steps")
    lablib.require_same(pipe, "flows_id", lablib.flows_id(f), args.inp, "the steps after 02_flows.py")
    split = f["split"][sample]
    names = lablib.ALL_FEATURES

    if args.mode == "theoretical":
        mins = np.zeros(len(names))
        maxs = np.array([pipe["window_s"] if n == "time" else lablib.THEORETICAL_MAX[n] for n in names], float)
    elif args.mode == "global":
        fit = split == "train"
        if args.fit_on != "all":
            fit &= lablib.sample_source(f["key"][sample]) == args.fit_on
        tr = X[fit]
        mins, maxs = tr.min(axis=0), tr.max(axis=0)
    else:
        mins, maxs = np.zeros(len(names)), np.ones(len(names))     # identity (none / batchnorm)
    span = np.where(maxs > mins, maxs - mins, 1.0)                  # constant column -> leave at 0
    Xn = ((X - mins) / span).astype(np.float32)

    os.makedirs(out, exist_ok=True)
    np.savez_compressed(os.path.join(out, "features.npz"), X=Xn, sample=sample, columns=np.array(names))
    pipe.update({"step": "03_normalize", "flow_dir": args.inp, "norm_mode": args.mode,
                 "norm_min": mins.tolist(), "norm_max": maxs.tolist(), "batchnorm": args.mode == "batchnorm",
                 "fit_on": args.fit_on if args.mode == "global" else "all"})
    lablib.save_pipeline(out, pipe)

    rows = []
    for j, n in enumerate(names):
        tr, te = Xn[split == "train", j], Xn[split == "test", j]
        outside = int(((te < 0) | (te > 1)).sum()) if args.mode in ("theoretical", "global") else "-"
        rows.append([n, f"{X[split == 'train', j].min():.4g} .. {X[split == 'train', j].max():.4g}",
                     f"{tr.min():.4g} .. {tr.max():.4g}", f"{tr.mean():.4g}", outside])
    print(f"mode = {args.mode}: {len(X)} packets of {len(np.unique(sample))} selected samples")
    lablib.print_table(rows, ["feature", "raw range (train)", "scaled range (train)", "scaled mean (train)",
                              "test values outside [0,1]"])
    print(f"-> written to {out}")


if __name__ == "__main__":
    main()
