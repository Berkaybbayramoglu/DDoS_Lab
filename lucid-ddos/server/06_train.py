"""Step 6 – Train the LUCID CNN.

Learning outcome: training a CNN with fixed, known-good settings on one CPU.
  * Architecture (paper): a 2D CNN on the n x f sample matrix - Conv2d (kernel h = 3 rows x
    f features, k = 64 filters) -> ReLU -> global max pooling -> Dense(1) -> sigmoid. The kernel
    is as wide as the matrix, so it slides only along the packets (the input is still 2D). With the 'batchnorm' normalization a BatchNorm layer is added
    in front of the convolution.
  * Settings are fixed (no hyper-parameter search, no validation set): the paper's optimizer
    (Adam, learning rate 0.01) with a number of epochs that fits a 1-vCPU lab session.
    The validation split is kept aside for the live attack replay.
  * Seed 42, one CPU thread and deterministic algorithms: the same data gives the same model.

usage:  python3 06_train.py --data work/05_shape_theoretical_lucid --model models/theoretical_lucid.pt
"""
import argparse
import json
import os
import time

import numpy as np

import lablib
import progress


def main():
    a = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    a.add_argument("--data", required=True, help="output folder of 05_shape.py")
    a.add_argument("--model", required=True, help="where to save the trained model (.pt)")
    a.add_argument("--train-on", dest="train_on", choices=["all", "cic", "lab"], default="all",
                   help="train on the samples of this network only (cic = CIC-DDoS2019 sample, lab = lab network)")
    a.add_argument("--epochs", type=int, default=10)
    a.add_argument("--batch", type=int, default=64)
    a.add_argument("--lr", type=float, default=0.01)
    a.add_argument("--kernels", type=int, default=64)
    args = a.parse_args()
    t_start = progress.now()
    lablib.set_seed()
    import torch
    import torch.nn.functional as F

    pipe = lablib.load_pipeline(args.data)
    d = lablib.load_npz(os.path.join(args.data, "train.npz"))
    keep = np.ones(len(d["y"]), bool) if args.train_on == "all" else d["source"] == args.train_on
    if not keep.any():
        raise SystemExit(f"no training samples of the {args.train_on} network")
    X, y = torch.from_numpy(d["X"][keep]), torch.from_numpy(d["y"][keep].astype(np.float32))
    model = lablib.build_model(X.shape[2], args.kernels, batchnorm=pipe.get("batchnorm", False))
    opt = torch.optim.Adam(model.parameters(), lr=args.lr, eps=1e-7)
    gen = torch.Generator().manual_seed(lablib.SEED)

    rows, t0 = [], time.perf_counter()
    for ep in range(1, args.epochs + 1):
        model.train()
        perm = torch.randperm(len(X), generator=gen)
        total = 0.0
        for i in range(0, len(X), args.batch):
            idx = perm[i:i + args.batch]
            loss = F.binary_cross_entropy_with_logits(model(X[idx]), y[idx])
            opt.zero_grad(set_to_none=True)
            loss.backward()
            opt.step()
            total += loss.item() * len(idx)
        model.eval()
        acc = ((lablib.predict_logits(model, X) > 0).float() == y).float().mean().item()
        rows.append([ep, f"{total / len(X):.4f}", f"{100 * acc:.1f} %", f"{time.perf_counter() - t0:.1f}"])

    os.makedirs(os.path.dirname(args.model) or ".", exist_ok=True)
    pipe.update({"step": "06_train", "shape_dir": args.data,
                 "train": {"train_on": args.train_on, "epochs": args.epochs, "batch": args.batch, "lr": args.lr, "kernels": args.kernels,
                           "seed": lablib.SEED, "samples": len(X), "seconds": time.perf_counter() - t0}})
    torch.save({"state": model.state_dict(), "pipeline": pipe}, args.model)
    with open(os.path.splitext(args.model)[0] + "_train_log.json", "w") as fh:
        json.dump({"epochs": rows}, fh, indent=1)

    progress.run("training", "06_train.py", t_start, model=args.model, data=args.data, train_on=args.train_on,
                 epochs=args.epochs, samples=len(X))

    shown = rows if len(rows) <= 6 else rows[:3] + [["...", "", "", ""]] + rows[-3:]
    lablib.print_table(shown, ["epoch", "train loss", "train accuracy", "elapsed (s)"])
    print(f"{len(X)} training samples ({lablib.SOURCES.get(args.train_on, 'both networks')}), {args.epochs} epochs in {time.perf_counter() - t0:.1f} s -> {args.model}")


if __name__ == "__main__":
    main()
