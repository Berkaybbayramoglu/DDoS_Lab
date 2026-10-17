"""Step 4 – Choose the features the model may see.

Learning outcome: feature selection and shortcut learning.
LUCID keeps 11 header features and leaves out IP addresses and ports: "We intuitively exclude
those attributes that would be detrimental to the generalization of the model, such as IP
addresses and TCP/UDP ports" (Doriguzzi-Corin et al., 2020). In a lab capture the attacker always
has the same IP, so a model that sees IPs can score perfectly on the test split by memorising the
address - and fails as soon as the attacker comes from another address. 05_shape.py therefore
also writes test_newaddr (attacker and benign client addresses swapped): test every model on both
`--split test` and `--split test_newaddr` in 07_infer.py and compare them in 09_plot.py.

Feature sets:
  lucid      the 11 LUCID features (default)
  lucid_ids  the 11 features + src_ip, dst_ip, src_port, dst_port
  ids_only   only the identifiers (shows how far a model gets by memorising addresses)
  --features time packet_len tcp_flags ...   any custom list (names from lablib.ALL_FEATURES)

usage:  python3 04_features.py --in work/03_norm_theoretical --set lucid --out work/04_feat_theoretical_lucid
"""
import argparse
import os

import numpy as np

import lablib

SETS = {"lucid": lablib.LUCID_FEATURES, "lucid_ids": lablib.LUCID_FEATURES + lablib.ID_FEATURES,
        "ids_only": lablib.ID_FEATURES}


def main():
    a = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    a.add_argument("--in", dest="inp", required=True, help="output folder of 03_normalize.py")
    a.add_argument("--set", choices=sorted(SETS), default="lucid")
    a.add_argument("--features", nargs="+", help="custom feature list (overrides --set)")
    a.add_argument("--out", required=True)
    args = a.parse_args()
    lablib.set_seed()

    pipe = lablib.load_pipeline(args.inp)
    d = lablib.load_npz(os.path.join(args.inp, "features.npz"))
    cols = list(d["columns"])
    chosen = args.features or SETS[args.set]
    unknown = [c for c in chosen if c not in cols]
    if unknown:
        raise SystemExit(f"unknown feature(s) {unknown}; choose from {cols}")
    idx = [cols.index(c) for c in chosen]

    os.makedirs(args.out, exist_ok=True)
    np.savez_compressed(os.path.join(args.out, "features.npz"), X=d["X"][:, idx], sample=d["sample"],
                        columns=np.array(chosen))
    pipe.update({"step": "04_features", "norm_dir": args.inp, "feature_set": "custom" if args.features else args.set,
                 "features": chosen, "feature_index": idx})
    lablib.save_pipeline(args.out, pipe)

    rows = [[c, "yes" if c in chosen else "-", "identifier" if c in lablib.ID_FEATURES else "header"] for c in cols]
    lablib.print_table(rows, ["feature", "used", "kind"])
    print(f"{len(chosen)} features selected ({pipe['feature_set']}) -> written to {args.out}")


if __name__ == "__main__":
    main()
