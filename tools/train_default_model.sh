#!/bin/bash
# Trains the model the post-lab uses by default (global min-max, LUCID features, n = 100) with the
# lab scripts in the lucid-server developer image, on 1 CPU, seed 42:
#   lucid-ddos/server/models/global_lucid.pt  (+ work/ with the intermediate steps)
#   usage: train_default_model.sh
set -eu
D="docker --context default"
SRV=$(cd "$(dirname "$0")/../lucid-ddos/server" && pwd)
mkdir -p "$SRV/data"; trap 'rmdir "$SRV/data" 2>/dev/null' EXIT    # mount point for home_tar/data
$D run --rm --cpus=1 -u "$(id -u):$(id -g)" -e HOME=/tmp -e PYTHONHASHSEED=42 -e PYTHONDONTWRITEBYTECODE=1 \
   -v "$SRV":/srv -v "$SRV/home_tar/data":/srv/data:ro -w /srv lucid-server sh -c '
set -e
python3 01_window.py --pcap data/lab_traffic.pcap.gz -t 100 --out work/01_window > /dev/null
python3 02_flows.py --in work/01_window --attackers 172.30.0.66 172.30.0.67 --victims 172.30.0.10 --out work/02_flows > /dev/null
python3 03_normalize.py --in work/02_flows --mode global > /dev/null
python3 04_features.py --in work/03_norm_global --set lucid --out work/04_feat_global_lucid > /dev/null
python3 05_shape.py --in work/04_feat_global_lucid -n 100 --out work/05_shape_global_lucid > /dev/null
python3 06_train.py --data work/05_shape_global_lucid --model models/global_lucid.pt | tail -1'
