"""Step 2 – Group the packets of every window into flows, label them and split the data.

Learning outcome: what a (bidirectional) flow is and how labelled training data is built.
  * Inside each window, packets are grouped by the 5-tuple (IP A, port A, IP B, port B, protocol).
    Both directions of a conversation belong to the same flow. One (window, flow) pair = one sample.
  * The 5-tuple is only a grouping key; it is not a model input (see 04_features.py).
  * Label: a flow between an attacker IP and a victim IP is DDoS (1), everything else benign (0).
  * Balance: as many DDoS samples as benign samples (random choice, seed 42).
  * Split by flow (paper): 90 % train / 10 % test, then 10 % of train becomes validation.
    All windows of one flow go to the same split, so no flow is seen in training and test.
    In this lab the validation split is not used for training; it is the traffic that is
    replayed as a live attack later.

usage:  python3 02_flows.py --in work/01_window --attackers 172.30.0.66 --victims 172.30.0.10 --out work/02_flows
"""
import argparse
import os

import numpy as np

import lablib


def main():
    a = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    a.add_argument("--in", dest="inp", default="work/01_window")
    a.add_argument("--attackers", nargs="+", required=True, help="attacker IP addresses")
    a.add_argument("--victims", nargs="+", required=True, help="victim IP addresses")
    a.add_argument("--test", type=float, default=0.10, help="test share (paper 0.10)")
    a.add_argument("--val", type=float, default=0.10, help="validation share of the rest (paper 0.10)")
    a.add_argument("--no_balance", action="store_true", help="keep every sample (no benign/DDoS balancing)")
    a.add_argument("--out", default="work/02_flows")
    args = a.parse_args()
    lablib.set_seed()

    pipe = lablib.load_pipeline(args.inp)
    p = lablib.load_npz(os.path.join(args.inp, "packets.npz"))
    attackers = {lablib.ip_to_int(x) for x in args.attackers}
    victims = {lablib.ip_to_int(x) for x in args.victims}

    # bidirectional 5-tuple per packet: put the smaller (IP, port) endpoint first, so both
    # directions of a conversation get the same key (lablib.flow_key does the same for one packet)
    s_ip, s_pt, d_ip, d_pt = p["src_ip"], p["src_port"], p["dst_ip"], p["dst_port"]
    swap = (s_ip > d_ip) | ((s_ip == d_ip) & (s_pt > d_pt))
    ip_a, pt_a = np.where(swap, d_ip, s_ip), np.where(swap, d_pt, s_pt)
    ip_b, pt_b = np.where(swap, s_ip, d_ip), np.where(swap, s_pt, d_pt)
    rows = np.stack([p["window"], ip_a, pt_a, ip_b, pt_b, p["proto"]], axis=1)

    # one sample = one (window, flow); samples are numbered in order of their first packet
    _, first_idx, inverse = np.unique(rows, axis=0, return_index=True, return_inverse=True)
    inverse = inverse.ravel()
    order = np.argsort(first_idx, kind="stable")             # unique() sorts by key; renumber by time
    rank = np.empty_like(order); rank[order] = np.arange(len(order))
    sample_of_packet = rank[inverse]
    s_first = first_idx[order]
    n = len(s_first)
    s_window, s_key = p["window"][s_first], rows[s_first, 1:]
    s_npk = np.bincount(sample_of_packet, minlength=n)
    rel_time = p["ts"] - p["ts"][s_first][sample_of_packet]  # LUCID 'time' feature: relative to the flow start
    is_att = np.isin(s_key[:, 0], list(attackers)), np.isin(s_key[:, 2], list(attackers))
    is_vic = np.isin(s_key[:, 0], list(victims)), np.isin(s_key[:, 2], list(victims))
    s_label = ((is_att[0] & is_vic[1]) | (is_att[1] & is_vic[0])).astype(np.int64)

    # balance (sample level, seed 42): all samples of the smaller class, the same number of the other
    rng = np.random.default_rng(lablib.SEED)
    ddos, benign = np.flatnonzero(s_label == 1), np.flatnonzero(s_label == 0)
    if len(ddos) == 0 or len(benign) == 0:
        ips, counts = np.unique(np.concatenate([s_key[:, 0], s_key[:, 2]]), return_counts=True)
        busiest = ", ".join(f"{lablib.int_to_ip(int(i))} ({c})" for i, c in
                            sorted(zip(ips, counts), key=lambda x: -x[1])[:6])
        raise SystemExit(f"no {'DDoS' if len(ddos) == 0 else 'benign'} samples: no flow is "
                         f"{'between' if len(ddos) == 0 else 'outside'} --attackers {' '.join(args.attackers)} and "
                         f"--victims {' '.join(args.victims)}. Check the addresses; the busiest hosts in the "
                         f"capture (flows) are: {busiest}")
    if args.no_balance:
        selected = np.ones(n, dtype=bool)
    else:
        k = min(len(ddos), len(benign))
        selected = np.zeros(n, dtype=bool)
        selected[rng.choice(ddos, k, replace=False)] = True
        selected[rng.choice(benign, k, replace=False)] = True

    # split by flow key: every window of one 5-tuple lands in the same split
    keys = [tuple(k) for k in s_key[selected]]
    uniq = sorted(set(keys))
    order = rng.permutation(len(uniq))
    per_key = {}
    for k in keys:
        per_key[k] = per_key.get(k, 0) + 1
    total, test_target = len(keys), args.test * len(keys)
    split_of_key, acc = {}, 0
    for j in order:                                         # first fill test, then val, the rest is train
        k = uniq[j]
        if acc < test_target:
            split_of_key[k] = "test"
        elif acc < test_target + args.val * (total - test_target):
            split_of_key[k] = "val"
        else:
            split_of_key[k] = "train"
        acc += per_key[k]
    s_split = np.array(["none"] * n, dtype="<U5")
    for j in np.flatnonzero(selected):
        s_split[j] = split_of_key[tuple(s_key[j])]

    os.makedirs(args.out, exist_ok=True)
    np.savez_compressed(os.path.join(args.out, "flows.npz"), window=s_window, key=s_key, label=s_label,
                        packets=s_npk, first_packet=s_first, selected=selected, split=s_split,
                        sample_of_packet=sample_of_packet, rel_time=rel_time)
    pipe["flows_id"] = lablib.flows_id({"key": s_key, "split": s_split, "label": s_label, "selected": selected})
    pipe.update({"step": "02_flows", "window_dir": args.inp, "attackers": args.attackers,
                 "victims": args.victims, "split": {"test": args.test, "val": args.val},
                 "balanced": not args.no_balance, "seed": lablib.SEED})
    lablib.save_pipeline(args.out, pipe)

    print(f"{len(p['ts'])} packets -> {n} samples (window, flow); "
          f"{len(set(map(tuple, s_key)))} distinct bidirectional flows")
    rows = []
    for name, m in [("all samples", np.ones(n, bool)), ("selected (balanced)", selected)] + \
                   [(f"  {sp}", s_split == sp) for sp in ("train", "val", "test")]:
        rows.append([name, int(m.sum()), int((s_label[m] == 1).sum()), int((s_label[m] == 0).sum()),
                     f"{np.median(s_npk[m]):.0f}" if m.any() else "-", int(s_npk[m].max()) if m.any() else "-"])
    lablib.print_table(rows, ["samples", "total", "DDoS", "benign", "median packets", "max packets"])
    over = int((s_npk[selected] > 100).sum())
    print(f"samples with more than 100 packets (will be cut in 05_shape.py): {over}")
    print(f"-> written to {args.out}")


if __name__ == "__main__":
    main()
