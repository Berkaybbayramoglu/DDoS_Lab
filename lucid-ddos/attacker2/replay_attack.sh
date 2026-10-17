#!/bin/bash
# Post-lab: replay this container's share of the held-out validation traffic toward the server.
# The pcap was produced by the server (12_build_replay.py) from the validation split and copied
# here by 13_launch_replay.sh. It holds both directions of every flow as recorded, including the
# server's original answers.
#   - MAP (optional, "old_ip[,old_ip...]:new_ip") moves the recorded peer address(es) to a new one,
#     in source and destination alike (tcprewrite --pnat), so a second attacker container can
#     replay with its own address while the server's own address stays untouched.
#   - The destination MAC is set to the server so the frames are delivered on the lab bridge.
#   - Packets larger than the link MTU (captured with segmentation offload) are cut to 1500 bytes.
#   - Packet timing is replayed as in the file (12_build_replay.py already packed the flows into
#     about 90 s). MAXSLEEP (ms, optional) caps idle gaps if a file still has long pauses.
#   usage: replay_attack.sh <pcap> <victim ip> [old_ip[,old_ip...]:new_ip]
set -eu
PCAP=$1; VICTIM=$2; MAP=${3:-}
MAXSLEEP=${MAXSLEEP:-0}
IFACE=$(ip -o route get "$VICTIM" | sed -n 's/.* dev \([^ ]*\).*/\1/p')   # lab LAN has no default route
VMAC=$(ping -c1 -W2 "$VICTIM" >/dev/null 2>&1; ip neigh show "$VICTIM" | awk '{print $5; exit}')
SMAC=$(cat /sys/class/net/"$IFACE"/address)
PLAY=/tmp/replay.pcap
REWRITE=(--enet-smac="$SMAC" --enet-dmac="$VMAC" --mtu-trunc --fixcsum)
if [ -n "$MAP" ]; then
  NEW=${MAP#*:}; OLDS=${MAP%%:*}; PNAT=""
  for old in ${OLDS//,/ }; do PNAT="$PNAT${PNAT:+,}$old/32:$NEW/32"; done
  REWRITE+=(--pnat="$PNAT")
fi
tcprewrite --infile="$PCAP" --outfile="$PLAY" "${REWRITE[@]}"
echo "replaying $(basename "$PCAP") -> $VICTIM on $IFACE${MAP:+ (mapped $MAP)}"
CAP=(); [ "$MAXSLEEP" -gt 0 ] && CAP=(--maxsleep="$MAXSLEEP")
exec tcpreplay "${CAP[@]}" --intf1="$IFACE" "$PLAY"
