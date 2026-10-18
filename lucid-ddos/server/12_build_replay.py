"""Step 12 (post-lab) – Build the replay traffic from the VALIDATION split.

Why: in this lab the number of epochs comes from the paper, so we do not need the validation split
to pick a model. Instead we reuse it as held-out traffic that was never seen in training, and replay
it against the server to simulate a real incident. The student's own model then has to detect and
block it live (steps 10 and 11).

This script extracts the packets of the validation flows from the recorded capture (.pcap or .pcap.gz) and splits them
into pcap files for the post-lab containers:
  replay/attacker1.pcap  half of the validation DDoS flows
  replay/attacker2.pcap  the other half (its source IP is remapped to the 2nd attacker at replay time)
  replay/benign.pcap     the validation benign flows (a legitimate client)
Addresses are kept as captured; 13_launch_replay.sh remaps attacker2's peer address and replays each
file from its own container, so the server sees two attacking IPs and one benign client.

The validation flows come from the whole recording (about 20 minutes of sessions). Their start
times are scaled into --duration seconds (default 90, so the incident fits one detection window),
in the recorded order; the packets inside each flow keep their original spacing. Two things would
otherwise make replayed flows differ from recorded ones, so the replay keeps one sample per flow
as the server will see it:
  * the same 5-tuple recorded in several windows (e.g. a SYN flood reusing source ports in two
    sessions) would merge into one flow inside the 90 s;
  * the benign clients all replay from the one client container, so two clients that used the same
    source port would become one flow.
Samples that do not involve the victim (e.g. multicast announcements) are left out.

usage:  python3 12_build_replay.py --flows work/02_flows --victim 172.30.0.10 --out replay
"""
import argparse
import gzip
import os
import struct

import numpy as np

import lablib


def split_by_frames(pcap, frame_shift, out_paths):
    """One pass over a classic pcap: copy each selected record to the output of its part, with its
    timestamp moved by the shift of its flow, then write every output in time order.
    frame_shift: {frame_number (1-based) -> (part name, shift in seconds)}."""
    with (gzip.open if pcap.endswith(".gz") else open)(pcap, "rb") as fh:
        gh = fh.read(24)
        magic = gh[:4]
        if magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"):
            end = "<"
        elif magic in (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"):
            end = ">"
        else:
            raise SystemExit("not a classic pcap file (run mergecap -F pcap)")
        unit = 1e9 if magic in (b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d") else 1e6
        records = {name: [] for name in out_paths}
        frame = 0
        while True:
            rh = fh.read(16)
            if len(rh) < 16:
                break
            sec, frac, incl, orig = struct.unpack(end + "IIII", rh)
            data = fh.read(incl)
            frame += 1
            hit = frame_shift.get(frame)
            if hit is not None:
                part, shift = hit
                ts = round((sec + frac / unit + shift) * unit)      # integer ticks: no float drift
                records[part].append((ts, frame, incl, orig, data))
    counts = {}
    for name, recs in records.items():
        recs.sort()                                                # time order (frame breaks ties)
        with open(out_paths[name], "wb") as o:
            o.write(gh)
            for ts, _, incl, orig, data in recs:
                o.write(struct.pack(end + "IIII", int(ts // unit), int(ts % unit), incl, orig))
                o.write(data)
        counts[name] = len(recs)
    return counts


def main():
    a = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    a.add_argument("--flows", default="work/02_flows")
    a.add_argument("--victim", required=True)
    a.add_argument("--out", default="replay")
    a.add_argument("--duration", type=float, default=90,
                   help="seconds over which the flow starts are spread (flows keep their own timing)")
    args = a.parse_args()
    lablib.set_seed()

    pipe = lablib.load_pipeline(args.flows)
    f = lablib.load_npz(os.path.join(args.flows, "flows.npz"))
    p = lablib.load_npz(os.path.join(pipe["window_dir"], "packets.npz"))
    lablib.require_same(pipe, "packets_id", lablib.packets_id(p), pipe["window_dir"], "02_flows.py")
    os.makedirs(args.out, exist_ok=True)

    victim = lablib.ip_to_int(args.victim)
    key = f["key"]
    involves_victim = (key[:, 0] == victim) | (key[:, 2] == victim)
    val = (f["split"] == "val") & involves_victim
    attack_samples = np.flatnonzero(val & (f["label"] == 1))
    benign_samples = np.flatnonzero(val & (f["label"] == 0))
    rng = np.random.default_rng(lablib.SEED)
    rng.shuffle(attack_samples)
    half = len(attack_samples) // 2
    parts = {"attacker1": attack_samples[:half], "attacker2": attack_samples[half:], "benign": benign_samples}

    # one sample per flow as the server will see it: the peer address is replaced by the replaying
    # container's single address, so a flow is identified by (victim port, peer port, protocol)
    first_ts = p["ts"][f["first_packet"]]
    dropped = {}
    for name, samples in parts.items():
        samples = samples[np.argsort(first_ts[samples], kind="stable")]
        k = key[samples]
        vic_first = k[:, 0] == victim
        seen = np.stack([np.where(vic_first, k[:, 1], k[:, 3]), np.where(vic_first, k[:, 3], k[:, 1]), k[:, 4]], axis=1)
        _, first = np.unique(seen, axis=0, return_index=True)
        dropped[name] = len(samples) - len(first)
        parts[name] = samples[np.sort(first)]

    # map every packet's original frame number to the output file of its sample
    names = list(parts)
    part_of_sample = np.full(len(f["split"]), -1)
    for k, name in enumerate(names):
        part_of_sample[parts[name]] = k
    part_of_packet = part_of_sample[f["sample_of_packet"]]
    keep = part_of_packet >= 0
    # the replayed flows all come from one capture (the lab network); read that one
    captures = pipe["pcap"] if isinstance(pipe["pcap"], list) else [pipe["pcap"]]
    files = np.unique(p["capture"][keep]) if "capture" in p else np.array([0])
    if len(files) != 1:
        raise SystemExit("the replayed flows come from several captures; give the --victim of one network")
    pcap = captures[int(files[0])]
    if not os.path.exists(pcap):                                 # stored path may be from another mount
        pcap = os.path.join("data", os.path.basename(pcap))
    if not os.path.exists(pcap):
        raise SystemExit(f"capture not found ({captures[int(files[0])]} or {pcap})")

    # spread the flow starts over --duration seconds in recorded order; a flow's own packets move together
    val_samples = np.flatnonzero(part_of_sample >= 0)
    start = p["ts"][f["first_packet"][val_samples]]
    t0, span = start.min(), max(start.max() - start.min(), 1e-9)
    shift_of_sample = np.zeros(len(part_of_sample))
    shift_of_sample[val_samples] = (start - t0) * (args.duration / span) - (start - t0)
    shift = shift_of_sample[f["sample_of_packet"][keep]]
    frame_shift = dict(zip(p["frame"][keep].tolist(),
                           zip([names[k] for k in part_of_packet[keep]], shift.tolist())))

    out_paths = {name: os.path.join(args.out, name + ".pcap") for name in parts}
    counts = split_by_frames(pcap, frame_shift, out_paths)
    victim = lablib.ip_to_int(args.victim)
    rows, peers = [], {}
    for name, samples in parts.items():
        first = f["first_packet"][samples]
        ends = np.concatenate([p["src_ip"][first], p["dst_ip"][first]])
        unicast = {int(x) for x in ends if int(x) != victim and not 224 <= int(x) >> 24 <= 239}   # no multicast
        peers[name] = sorted(lablib.int_to_ip(x) for x in unicast)                   # non-victim hosts
        shown = ", ".join(peers[name][:3]) + (f" (+{len(peers[name]) - 3} more)" if len(peers[name]) > 3 else "")
        rows.append([name, len(samples), counts[name], shown])

    with open(os.path.join(args.out, "manifest.txt"), "w") as fh:
        fh.write(f"victim={args.victim}\nwindow_s={pipe['window_s']}\nduration_s={args.duration:g}\n")
        for r in rows:
            fh.write(f"{r[0]}: samples={r[1]} packets={r[2]} peers={r[3]}\n")
        for name in parts:                                       # read by 13_launch_replay.sh
            fh.write(f"peers_{name}={','.join(peers[name])}\n")
    print(f"validation split replay built from {os.path.basename(pcap)} (victim {args.victim})")
    print("one sample per flow as the server sees it; left out as duplicates: "
          + ", ".join(f"{name} {n}" for name, n in dropped.items()))
    lablib.print_table(rows, ["file", "flows", "packets", "peer IP(s)"])
    print(f"-> {args.out}/  (attacker1.pcap, attacker2.pcap, benign.pcap, manifest.txt)")


if __name__ == "__main__":
    main()
