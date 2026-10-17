#!/bin/bash
# Builds the lab dataset (lucid-ddos/server/home_tar/data/lab_traffic.pcap.gz):
# records six sessions with record_lab_sessions.sh (benign, SYN flood, HTTP flood, twice each) and
# merges them into one capture with 400 s of silence between sessions (so the time windows of
# 01_window.py never span two sessions). About 25 minutes.
#   usage: build_lab_dataset.sh [sessions dir]
set -eu
N=$(cd "$(dirname "$0")/.." && pwd)
OUT=${1:-$N/data/lab_sessions}
D="docker --context default"
mkdir -p "$OUT"
docker --context default image inspect lucid-ethtool >/dev/null 2>&1 || printf 'FROM debian:bookworm-slim\nRUN apt-get update && apt-get install -y --no-install-recommends ethtool && rm -rf /var/lib/apt/lists/*\n' | $D build -q -t lucid-ethtool - >/dev/null
for s in s1_none s2_syn s3_http s4_none s5_syn s6_http; do
  "$N/tools/record_lab_sessions.sh" "${s#*_}" "$OUT/$s.pcap"
done
$D run --rm -u "$(id -u):$(id -g)" -v "$OUT":/m -w /m lucid-server sh -c '
start=1700000000; i=0; list=""
for f in s1_none s2_syn s3_http s4_none s5_syn s6_http; do
  first=$(capinfos -a -S -T -r -m $f.pcap | tail -1 | cut -d, -f2 | cut -d. -f1)
  last=$(capinfos -e -S -T -r -m $f.pcap | tail -1 | cut -d, -f2 | cut -d. -f1)
  editcap -t $((start - first)) $f.pcap /tmp/t$i.pcap; list="$list /tmp/t$i.pcap"
  echo "$f -> starts at +$((start - 1700000000)) s, length $((last - first)) s"
  start=$((start + last - first + 400)); i=$((i + 1))
done
mergecap -F pcap -w lab_traffic.pcap $list
echo "largest frame: $(tshark -r lab_traffic.pcap -T fields -e frame.len | sort -n | tail -1) bytes"
capinfos -c -u lab_traffic.pcap'
mkdir -p "$N/lucid-ddos/server/home_tar/data"
# the payload of the served files is zeros, so the capture compresses ~20x; tshark reads .pcap.gz directly
gzip -6 -c "$OUT/lab_traffic.pcap" > "$N/lucid-ddos/server/home_tar/data/lab_traffic.pcap.gz"
echo "-> lucid-ddos/server/home_tar/data/lab_traffic.pcap.gz (uncompressed copy kept in $OUT)"
