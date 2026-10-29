"""Shared helpers for the LUCID DDoS lab scripts (01_window.py ... 13_launch_replay.sh).

Every script imports this module first. It fixes the random seeds (42), keeps PyTorch on one
CPU thread with deterministic algorithms, and provides the pieces that several stages share:
packet field extraction with tshark, the 11 LUCID packet features, the CNN, and small file
helpers. Each stage writes its output folder with a pipeline.json that records every choice made
so far (window length, split, normalization, features, n); the next stage reads it, so the
whole pipeline can be replayed from parameters alone.
"""
import hashlib
import ipaddress
import json
import os
import random
import subprocess

SEED = 42
os.environ.setdefault("PYTHONHASHSEED", str(SEED))
os.environ.setdefault("CUBLAS_WORKSPACE_CONFIG", ":4096:8")
os.environ.setdefault("OMP_NUM_THREADS", "1")
# The same computation kernels on every processor: PyTorch, oneDNN and Intel MKL (PyTorch's matrix
# library) use AVX-512 code on processors that have it, which rounds differently than the AVX2 code of
# other processors (one training of the lab, lucid_ids, got stuck on an AVX-512 machine; on an Intel
# AVX-512 processor the models differed slightly, enough to change the permutation importance of
# Experiment 5). Limit all three to AVX2 when the processor has it; the settings are upper limits and
# change nothing on AVX2 processors. MKL reads its setting when PyTorch is loaded, after lablib.
try:
    with open("/proc/cpuinfo") as _fh:
        _has_avx2 = " avx2" in _fh.read()
except OSError:
    _has_avx2 = False
if _has_avx2:
    os.environ.setdefault("ATEN_CPU_CAPABILITY", "avx2")
    os.environ.setdefault("MKL_ENABLE_INSTRUCTIONS", "AVX2")
os.environ.setdefault("ONEDNN_MAX_CPU_ISA", "AVX2")

import numpy as np  # noqa: E402


def set_seed(seed=SEED):
    """Python, NumPy and (if loaded) PyTorch seeds + deterministic, single-threaded PyTorch.
    The Python hash seed (PYTHONHASHSEED) must be set before Python starts; the lab image sets it."""
    os.environ.setdefault("PYTHONHASHSEED", str(seed))     # inherited by subprocesses
    random.seed(seed)
    np.random.seed(seed)
    try:
        import torch
        torch.manual_seed(seed)
        torch.set_num_threads(1)
        torch.use_deterministic_algorithms(True)
        torch.backends.cudnn.deterministic = True
        torch.backends.cudnn.benchmark = False
    except ImportError:
        pass


set_seed()

# ---------------------------------------------------------------------------------------------
# Packet fields
# ---------------------------------------------------------------------------------------------
TSHARK_FIELDS = ["frame.number", "frame.time_epoch", "ip.src", "ip.dst", "ip.proto", "ip.len", "ip.flags",
                 "frame.protocols", "tcp.srcport", "tcp.dstport", "tcp.len", "tcp.ack", "tcp.flags",
                 "tcp.window_size_value", "udp.srcport", "udp.dstport", "udp.length", "icmp.type"]

# The 11 per-packet features of LUCID (Doriguzzi-Corin et al., IEEE TNSM 2020) ...
LUCID_FEATURES = ["time", "packet_len", "highest_layer", "ip_flags", "protocols", "tcp_len", "tcp_ack",
                  "tcp_flags", "tcp_win", "udp_len", "icmp_type"]
# ... and the identifiers LUCID deliberately leaves out (used only for grouping / the feature lab).
ID_FEATURES = ["src_ip", "dst_ip", "src_port", "dst_port"]
ALL_FEATURES = LUCID_FEATURES + ID_FEATURES

# Theoretical ranges used by LUCID's static min-max scaling (util_functions.feature_list);
# "time" is bounded by the window length t. Identifier ranges follow the same idea.
THEORETICAL_MAX = {"time": None, "packet_len": 1 << 16, "highest_layer": 1 << 32, "ip_flags": 1 << 16,
                   "protocols": 1 << 12, "tcp_len": 1 << 16, "tcp_ack": 1 << 32, "tcp_flags": 1 << 16,
                   "tcp_win": 1 << 16, "udp_len": 1 << 16, "icmp_type": 1 << 8,
                   "src_ip": 1 << 32, "dst_ip": 1 << 32, "src_port": 1 << 16, "dst_port": 1 << 16}

PROTOCOLS = ["arp", "data", "dns", "ftp", "http", "icmp", "ip", "ssdp", "ssl", "telnet", "tcp", "udp"]


def _first(v):
    return v.split(",")[0] if v else ""


def _protocols_mask(protos):
    names = set(protos.split(":"))
    return sum(1 << i for i, p in enumerate(PROTOCOLS) if p in names)


_hl_cache = {}


def _highest_layer(protos):
    last = protos.split(":")[-1].upper()
    if last not in _hl_cache:
        _hl_cache[last] = int(hashlib.sha256(last.encode()).hexdigest(), 16) % 10 ** 8
    return _hl_cache[last]


def ip_to_int(s):
    return int(ipaddress.IPv4Address(s))


def int_to_ip(i):
    return str(ipaddress.IPv4Address(int(i)))


def tshark_command(pcap=None, iface=None, reset=None):
    """reset: let tshark drop its per-packet state every N packets (memory stays flat on big files);
    tshark then restarts frame.number, so the caller numbers the lines itself."""
    # live: the lab's SSH channel (server -> traffic containers, 13_launch_replay.sh) is not monitored
    src = ["-r", pcap] if pcap else ["-i", iface, "-l", "-f", "not tcp port 22"]
    src += ["-M", str(reset)] if reset else []
    cmd = ["tshark", "-n", "-Q"] + src + ["-T", "fields", "-E", "separator=\t", "-E", "occurrence=a"]
    for f in TSHARK_FIELDS:
        cmd += ["-e", f]
    return cmd


def parse_tshark_line(line):
    """One tshark line -> (frame_no, ts, src_ip, dst_ip, proto, src_port, dst_port, [10 raw features])
    or None for non-IPv4 packets. The 'time' feature is computed later (relative to the flow)."""
    c = line.rstrip("\n").split("\t")
    if len(c) < len(TSHARK_FIELDS) or not c[2] or not c[5]:
        return None
    (frame, ts, src, dst, proto, iplen, ipflags, protos, tsp, tdp, tlen, tack, tflags, twin,
     usp, udp_, ulen, itype) = c[:18]
    try:
        proto = int(_first(proto))
        sport = dport = 0
        tcp_len = tcp_ack = tcp_flags = tcp_win = udp_len = icmp_type = 0
        if proto == 6 and tsp:
            sport, dport = int(_first(tsp)), int(_first(tdp))
            tcp_len, tcp_ack = int(_first(tlen) or 0), int(_first(tack) or 0)
            tcp_flags, tcp_win = int(_first(tflags), 16), int(_first(twin) or 0)
        elif proto == 17 and usp:
            sport, dport, udp_len = int(_first(usp)), int(_first(udp_)), int(_first(ulen) or 0)
        elif proto == 1 and itype:
            icmp_type = int(_first(itype))
        elif proto in (1, 6, 17):
            return None                                    # truncated transport header
        else:
            proto = 0
        feats = [int(_first(iplen)), _highest_layer(protos), int(_first(ipflags), 16), _protocols_mask(protos),
                 tcp_len, tcp_ack, tcp_flags, tcp_win, udp_len, icmp_type]
        return (int(frame), float(ts), ip_to_int(_first(src)), ip_to_int(_first(dst)), proto, sport, dport, feats)
    except ValueError:
        return None


def read_pcap_packets(pcap):
    """All IPv4 packets of a pcap file (.pcap or .pcap.gz), in file order, as tuples (small files)."""
    out = subprocess.run(tshark_command(pcap=pcap), capture_output=True, text=True, check=True).stdout
    return [p for p in map(parse_tshark_line, out.splitlines()) if p is not None]


def read_pcap_columns(pcap):
    """All IPv4 packets of a pcap file (.pcap or .pcap.gz) as numpy columns, streamed from tshark
    line by line so that a capture of millions of packets fits in a few hundred MB."""
    from array import array
    cols = {c: array("q") for c in ("frame", "src_ip", "dst_ip", "proto", "src_port", "dst_port")}
    ts, feats = array("d"), array("q")
    proc = subprocess.Popen(tshark_command(pcap=pcap, reset=200000), stdout=subprocess.PIPE,
                            stderr=subprocess.DEVNULL, text=True, bufsize=1 << 20)
    for frame, line in enumerate(proc.stdout, 1):           # one line per frame: line number = frame
        p = parse_tshark_line(line)
        if p is None:
            continue
        cols["frame"].append(frame); ts.append(p[1]); cols["src_ip"].append(p[2]); cols["dst_ip"].append(p[3])
        cols["proto"].append(p[4]); cols["src_port"].append(p[5]); cols["dst_port"].append(p[6])
        feats.extend(p[7])
    if proc.wait() != 0:
        raise SystemExit(f"tshark could not read {pcap}")
    out = {c: np.frombuffer(a, dtype=np.int64).copy() for c, a in cols.items()}
    out["ts"] = np.frombuffer(ts, dtype=np.float64).copy()
    out["feats"] = np.frombuffer(feats, dtype=np.int64).reshape(len(ts), -1).copy()
    return out


# ---------------------------------------------------------------------------------------------
# Windows and flows (the two rules students learn in 01 and 02)
# ---------------------------------------------------------------------------------------------
def assign_windows(ts, t):
    """LUCID windowing: a window starts at a packet and lasts t seconds; the next window starts at
    the first packet AFTER the end of the previous one, however long the idle gap was."""
    win = np.empty(len(ts), dtype=np.int64)
    start, w = None, -1
    for i, x in enumerate(ts):
        if start is None or x > start + t:
            start, w = x, w + 1
        win[i] = w
    return win


def flow_key(src_ip, src_port, dst_ip, dst_port, proto):
    """Bidirectional 5-tuple: both directions of a conversation give the same key."""
    a, b = (src_ip, src_port), (dst_ip, dst_port)
    return (a + b + (proto,)) if a <= b else (b + a + (proto,))


def apply_pipeline(packets, pipe):
    """Turn raw packets (from read_pcap_packets) into the model's input, exactly as the training
    pipeline did: window -> bidirectional flows -> the stored features, scaling and n.
    Returns (X, keys, first_ts) where X is (samples, n, f), keys[j] = the 5-tuple of sample j and
    first_ts[j] its first packet time. Used by the live/offline detector so inference reshapes the
    same way training did."""
    if not packets:
        return np.zeros((0, pipe["n_packets"], pipe["n_features"]), np.float32), [], []
    packets = sorted(packets, key=lambda p: (p[1], p[0]))
    ts = np.array([p[1] for p in packets], np.float64)
    win = assign_windows(ts, pipe["window_s"])
    sip = np.array([p[2] for p in packets]); dip = np.array([p[3] for p in packets])
    spt = np.array([p[5] for p in packets]); dpt = np.array([p[6] for p in packets])
    pro = np.array([p[4] for p in packets])
    swap = (sip > dip) | ((sip == dip) & (spt > dpt))
    a_ip, a_pt = np.where(swap, dip, sip), np.where(swap, dpt, spt)
    b_ip, b_pt = np.where(swap, sip, dip), np.where(swap, spt, dpt)
    rows = np.stack([win, a_ip, a_pt, b_ip, b_pt, pro], axis=1)
    _, first_idx, inv = np.unique(rows, axis=0, return_index=True, return_inverse=True)
    inv = inv.ravel()
    order = np.argsort(first_idx, kind="stable")
    rank = np.empty_like(order); rank[order] = np.arange(len(order))
    sample = rank[inv]
    first = first_idx[order]
    n_samples = len(first)
    feats = np.array([p[7] for p in packets], np.float64)
    rel = ts - ts[first][sample]
    full = np.column_stack([rel, feats, sip, dip, spt, dpt])         # order == ALL_FEATURES
    col = {c: i for i, c in enumerate(ALL_FEATURES)}
    full = full[:, [col[c] for c in pipe.get("features", LUCID_FEATURES)]]
    if pipe.get("norm_mode") in ("theoretical", "global"):
        idx = pipe["feature_index"]
        mins = np.array(pipe["norm_min"])[idx]; maxs = np.array(pipe["norm_max"])[idx]
        full = (full - mins) / np.where(maxs > mins, maxs - mins, 1.0)
    n, f = pipe["n_packets"], full.shape[1]
    X = np.zeros((n_samples, n, f), np.float32)
    counts = np.zeros(n_samples, int)
    for i in range(len(sample)):
        s = sample[i]
        if counts[s] < n:
            X[s, counts[s]] = full[i]
            counts[s] += 1
    keys = [tuple(int(v) for v in rows[first[j], 1:]) for j in range(n_samples)]
    return X, keys, ts[first]


# ---------------------------------------------------------------------------------------------
# Files
# ---------------------------------------------------------------------------------------------
def load_npz(path):
    """All arrays of a .npz file, loaded once. (Indexing np.load()'s lazy NpzFile inside a loop
    decompresses the whole array again on every access.)"""
    with np.load(path) as z:
        return {k: z[k] for k in z.files}


def fingerprint(*arrays):
    """Short content id of some arrays (to notice that an earlier step was re-run)."""
    h = hashlib.sha1()
    for a in arrays:
        h.update(np.ascontiguousarray(a).tobytes())
    return h.hexdigest()[:16]


def packets_id(p):
    if "capture" in p:
        return fingerprint(p["capture"], p["frame"], p["ts"], p["window"])
    return fingerprint(p["frame"], p["ts"], p["window"])


# The two networks of the lab dataset: the lab network (recorded for this lab, the network of the
# post-lab) and the CIC-DDoS2019 testbed (sample of the LUCID authors). A sample belongs to the lab
# network when one of its endpoints is in LAB_NET.
LAB_NET = ("172.30.0.0", 24)
SOURCES = {"cic": "CIC-DDoS2019 sample", "lab": "lab network"}


def sample_source(key):
    """'lab' or 'cic' for every sample key (rows of flows.npz 'key': ip_a, port_a, ip_b, port_b, proto)."""
    net, bits = ip_to_int(LAB_NET[0]) >> (32 - LAB_NET[1]), 32 - LAB_NET[1]
    lab = ((key[:, 0] >> bits) == net) | ((key[:, 2] >> bits) == net)
    return np.where(lab, "lab", "cic")


def network_of(ip):
    """'lab' or 'cic' for one address (as int)."""
    return "lab" if ip >> (32 - LAB_NET[1]) == ip_to_int(LAB_NET[0]) >> (32 - LAB_NET[1]) else "cic"


def is_private(ip):
    """True for a private unicast address (10/8, 172.16/12, 192.168/16)."""
    return ip >> 24 == 10 or ip >> 20 == 0xAC1 or ip >> 16 == 0xC0A8


def flows_id(f):
    return fingerprint(f["key"], f["split"], f["label"], f["selected"])


def require_same(pipe, key, value, what, rerun):
    """Stop when the output of an earlier step changed after this pipeline was built from it."""
    if key in pipe and pipe[key] != value:
        raise SystemExit(f"{what} changed after this pipeline was built from it (an earlier step was "
                         f"re-run). Run {rerun} again.")


def load_pipeline(folder):
    with open(os.path.join(folder, "pipeline.json")) as f:
        return json.load(f)


def save_pipeline(folder, pipe):
    os.makedirs(folder, exist_ok=True)
    with open(os.path.join(folder, "pipeline.json"), "w") as f:
        json.dump(pipe, f, indent=1)


def print_table(rows, header=None):
    rows = [[str(c) for c in r] for r in rows]
    if header:
        rows = [list(header)] + rows
    w = [max(len(r[i]) for r in rows) for i in range(len(rows[0]))]
    line = "+" + "+".join("-" * (x + 2) for x in w) + "+"
    print(line)
    for k, r in enumerate(rows):
        print("| " + " | ".join(c.ljust(w[i]) for i, c in enumerate(r)) + " |")
        if k == 0 and header:
            print(line)
    print(line)


# ---------------------------------------------------------------------------------------------
# Model (LUCID CNN, PyTorch). Imported lazily so the preprocessing scripts do not need torch.
# ---------------------------------------------------------------------------------------------
def predict_logits(model, X, batch=2048):
    """Model output for many samples, in chunks (a 2D CNN on tens of thousands of 100 x f matrices
    at once would need gigabytes for the intermediate feature maps)."""
    import torch
    X = torch.as_tensor(X)
    with torch.no_grad():
        return torch.cat([model(X[i:i + batch]) for i in range(0, len(X), batch)]) if len(X) else torch.zeros(0)


def build_model(n_features, kernels=64, kernel_rows=3, batchnorm=False):
    import torch
    import torch.nn as nn
    import torch.nn.functional as F

    class LucidCNN(nn.Module):
        """2D CNN (LUCID): the input sample is an n x f matrix (packets x features).
        Conv2d(1 -> k kernels, kernel h x f) -> ReLU -> global max pooling -> Dense(1) -> sigmoid.
        The kernel is as wide as the matrix, so it only slides along the packet axis; it is still a
        2D convolution over a 2D input (the paper's "1D" wording refers to that sliding only).
        With batchnorm=True a BatchNorm layer normalises every input feature first."""

        def __init__(self):
            super().__init__()
            self.bn = nn.BatchNorm1d(n_features) if batchnorm else nn.Identity()
            self.conv = nn.Conv2d(1, kernels, (kernel_rows, n_features))
            self.fc = nn.Linear(kernels, 1)
            limit = (6 / (kernel_rows * n_features + kernel_rows * n_features * kernels)) ** 0.5
            nn.init.uniform_(self.conv.weight, -limit, limit)      # Keras glorot_uniform, as in LUCID
            nn.init.xavier_uniform_(self.fc.weight)
            nn.init.zeros_(self.conv.bias)
            nn.init.zeros_(self.fc.bias)

        def forward(self, x):                       # x: (batch, n packets, f features)
            x = self.bn(x.transpose(1, 2)).transpose(1, 2)   # per-feature BatchNorm (or nothing)
            x = F.relu(self.conv(x.unsqueeze(1)))   # (batch, 1, n, f) -> (batch, k, n-h+1, 1)
            return self.fc(torch.amax(x, dim=(2, 3))).squeeze(1)   # global max pooling -> logits

    torch.manual_seed(SEED)
    return LucidCNN()
