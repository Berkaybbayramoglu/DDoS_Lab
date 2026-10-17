#!/bin/bash
# Records one traffic session of the lab dataset (lucid-ddos/server/home_tar/data). Uses the developer
# images from build_images.sh (lucid-server, lucid-attacker, lucid-ethtool).
# Isolated Docker network: victim web server 172.30.0.10 (HTTP/1.1, no CPU limit), 17 benign
# users 172.30.0.20-36 with different behaviour (benign_clients.py: 3x browse, 2x api, 4x keepalive,
# 4x download, 4x slow), attacker 172.30.0.66 running the lab attacker scripts. tcpdump runs in the
# victim's namespace. The victim serves 30 small pages (0.2-8 kB) and 10 large files (50-300 kB).
# Session timeline: 60 s benign, 60 s attack (or none) on top of the benign traffic, 60 s benign.
# Segmentation/receive offloads (TSO/GSO/GRO) are switched off in every container before traffic
# starts, so the capture holds wire-sized packets (<= 1514 bytes) as a physical link would carry.
# With offloads on, the virtual bridge passes 40+ kB "super packets" that no real network carries
# and that cannot be replayed onto the lab LAN in the post-lab. Needs the small lucid-ethtool image.
# usage: record_lab_sessions.sh <none|syn|http> <output pcap>
set -u
ATTACK=$1; OUTPCAP=$2
D="docker --context default"
ROOT=$(cd "$(dirname "$0")/.." && pwd); ATT=$ROOT/lucid-ddos/attacker1      # syn_flood.sh, http_flood.sh
TMP=$(mktemp -d)
nooffload() { $D run --rm --network container:$1 --cap-add NET_ADMIN lucid-ethtool \
                ethtool -K eth0 tso off gso off gro off >/dev/null 2>&1 || { echo "ethtool failed on $1"; exit 1; }; }
# 3 browse + 2 api (many short flows) and 4 each of keepalive / download / slow (fewer, longer flows),
# so long benign connections are well represented, not just a few dozen samples
CLIENTS="20:browse 21:browse 22:browse 23:api 24:api 25:keepalive 26:keepalive 27:keepalive 28:keepalive
         29:download 30:download 31:download 32:download 33:slow 34:slow 35:slow 36:slow"
EXP=$(cd "$(dirname "$0")" && pwd)
$D rm -f rec-victim rec-cap rec-attacker $(for c in $CLIENTS; do echo rec-c${c%%:*}; done) >/dev/null 2>&1
$D network rm recnet >/dev/null 2>&1
$D network create --subnet 172.30.0.0/24 recnet >/dev/null
$D run -d --name rec-victim --network recnet --ip 172.30.0.10 lucid-server sh -c \
  'mkdir -p /srv && cd /srv && for i in $(seq 0 29); do head -c $(( 200 + (i * 2731) % 8000 )) /dev/zero > s$i; done &&
   for i in $(seq 0 9); do head -c $(( 50000 + (i * 27007) % 250000 )) /dev/zero > l$i; done &&
   python3 -m http.server 80 --protocol HTTP/1.1' >/dev/null
nooffload rec-victim
$D run -d --name rec-cap --network container:rec-victim --cap-add NET_RAW --cap-add NET_ADMIN -v "$TMP":/out lucid-server \
  tcpdump -i eth0 -w /out/capture.pcap >/dev/null 2>&1
for c in $CLIENTS; do                               # start idle, offloads off first, then go
  $D run -d --name rec-c${c%%:*} --network recnet --ip 172.30.0.${c%%:*} -v "$EXP/benign_clients.py":/b.py:ro \
     lucid-attacker sh -c "sleep 4; exec python3 /b.py ${c#*:} 172.30.0.10 172.30.0.${c%%:*}" >/dev/null
done
$D run -d --name rec-attacker --network recnet --ip 172.30.0.66 --cap-add NET_RAW -v "$ATT":/home/student -w /home/student lucid-attacker sleep infinity >/dev/null
for c in $CLIENTS; do nooffload rec-c${c%%:*}; done; nooffload rec-attacker
sleep 60
case $ATTACK in
  syn)  $D exec -d rec-attacker ./syn_flood.sh 172.30.0.10 u2000 ;;
  http) $D exec -d rec-attacker ./http_flood.sh 172.30.0.10 10 ;;   # 10 parallel loops
esac
sleep 60; $D rm -f rec-attacker >/dev/null; sleep 60
ALL="rec-cap rec-victim $(for c in $CLIENTS; do echo rec-c${c%%:*}; done)"
$D stop -t 3 $ALL >/dev/null 2>&1
$D rm -f $ALL >/dev/null 2>&1; $D network rm recnet >/dev/null
$D run --rm -v "$TMP":/out lucid-server chown -R "$(id -u):$(id -g)" /out
mv "$TMP/capture.pcap" "$OUTPCAP"; rmdir "$TMP"
echo "recorded $ATTACK -> $OUTPCAP"
