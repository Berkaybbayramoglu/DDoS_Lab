"""Step 7 – Use a trained model (inference).

Learning outcome: a saved model carries everything needed to apply it; only parameters are given.
The model file contains the weights and the pipeline settings (normalization, features, n), so
inference needs only the model and the shaped data.

usage:  python3 07_infer.py --model models/theoretical_lucid.pt --data work/05_shape_theoretical_lucid \
                            --split test --out results/theoretical_lucid_test.csv
output: CSV with one row per sample: sample id, true label, probability of DDoS, predicted label
"""
import argparse
import csv
import os
import time

import numpy as np

import lablib


def main():
    a = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    a.add_argument("--model", required=True)
    a.add_argument("--data", required=True, help="output folder of 05_shape.py")
    a.add_argument("--split", choices=["train", "val", "test", "test_newaddr"], default="test",
                   help="test_newaddr: test flows with attacker/client addresses swapped (05_shape.py)")
    a.add_argument("--threshold", type=float, default=0.5)
    a.add_argument("--out", required=True)
    args = a.parse_args()
    lablib.set_seed()
    import torch

    ck = torch.load(args.model, map_location="cpu")
    pipe = ck["pipeline"]
    d = lablib.load_npz(os.path.join(args.data, f"{args.split}.npz"))
    X = torch.from_numpy(d["X"])
    if X.shape[2] != pipe["n_features"] or X.shape[1] != pipe["n_packets"]:
        raise SystemExit(f"data shape {tuple(X.shape[1:])} does not match the model "
                         f"({pipe['n_packets']}, {pipe['n_features']}): use data prepared the same way")
    model = lablib.build_model(pipe["n_features"], pipe["train"]["kernels"], batchnorm=pipe.get("batchnorm", False))
    model.load_state_dict(ck["state"])
    model.eval()
    t0 = time.perf_counter()
    with torch.no_grad():
        prob = torch.sigmoid(lablib.predict_logits(model, X)).numpy()
    dt = time.perf_counter() - t0

    os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)
    with open(args.out, "w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["sample", "label", "prob_ddos", "pred"])
        for s, yv, pv in zip(d["sample"], d["y"], prob):
            w.writerow([int(s), int(yv), f"{pv:.6f}", int(pv >= args.threshold)])
    print(f"{len(prob)} {args.split} samples classified in {1000 * dt:.1f} ms "
          f"({1e6 * dt / max(len(prob), 1):.0f} us/sample) -> {args.out}")


if __name__ == "__main__":
    main()
