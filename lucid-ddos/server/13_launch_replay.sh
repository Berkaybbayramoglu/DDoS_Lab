#!/bin/bash
# Step 13 (post-lab) – Start the simulated incident.
#
# Copies the replay files built by 12_build_replay.py to the traffic containers over SSH (with the
# student's own key, post-lab step 0) and starts them all at once:
#           attacker1 <- replay/attacker1.pcap
#           attacker2 <- replay/attacker2.pcap  (peer address moved to attacker2's own)
#           client    <- replay/benign.pcap     (legitimate traffic mixed in)
# Start the live detector first (10_detect_block.py, other terminal), then run this script.
# Once the detector blocks an attacker the server can no longer reach it either, so this script
# does not talk to the containers after the start; it follows the replay schedule instead.
#   usage:  ./13_launch_replay.sh [replay dir]
set -eu
DIR=${1:-replay}
SUDO=$([ "$(id -u)" = 0 ] || echo sudo)
USER_AT=ubuntu@                    # lab user on the traffic containers
SSHO="-o BatchMode=yes -o StrictHostKeyChecking=accept-new -o ConnectTimeout=5 -o LogLevel=ERROR"
MAXSLEEP=0                         # ms; 0 = replay the timing as built by 12_build_replay.py
[ -f "$DIR/manifest.txt" ] || { echo "no $DIR/manifest.txt - run 12_build_replay.py first"; exit 1; }
VICTIM=$(sed -n 's/^victim=//p' "$DIR/manifest.txt")

# The replay files already hold the server's recorded answers. This server must therefore stay
# silent towards the replayed flows: its kernel would otherwise answer every replayed packet that
# has no open socket with a TCP RST / ICMP unreachable, adding packets to each flow that were never
# part of the recording (and changing what the detector sees).
for host in attacker1 attacker2 client; do
  ip=$(getent hosts $host | awk '{print $1}')
  # a new incident starts clean: remove the DROP rules a previous detector run added for this host
  while $SUDO iptables -C INPUT -s "$ip" -j DROP 2>/dev/null; do
    $SUDO iptables -D INPUT -s "$ip" -j DROP && echo "  removed the block of $host ($ip) from a previous run"
  done
  for rule in "-p tcp --tcp-flags RST RST" "-p icmp --icmp-type destination-unreachable"; do
    $SUDO iptables -C OUTPUT -d "$ip" $rule -j DROP 2>/dev/null || $SUDO iptables -I OUTPUT -d "$ip" $rule -j DROP
  done
done

# The server reaches the traffic containers over SSH with the student's own key (post-lab step 0:
# ssh-keygen + ssh-copy-id ubuntu@attacker1 / attacker2 / client). Check that first.
for host in attacker1 attacker2 client; do
  if ! err=$(ssh $SSHO "$USER_AT$host" true 2>&1); then
    if echo "$err" | grep -qi "permission denied"; then
      echo "cannot log in to $host without a password. Set up SSH access first (post-lab step 0):"
      echo "  ssh-keygen -t ed25519            # once, accept the defaults"
      echo "  ssh-copy-id ubuntu@attacker1     # password: ubuntu"
      echo "  ssh-copy-id ubuntu@attacker2"
      echo "  ssh-copy-id ubuntu@client"
    else
      echo "cannot reach $host over SSH: ${err:-no answer}"
      echo "  is the lab running (labtainer lucid-ddos)? check with: ping -c1 $host"
    fi
    exit 1
  fi
done

# each container replays its file with the recorded peer address(es) moved to its own address:
# first every file is copied, then all three replays are started together
for pair in attacker1:attacker1 attacker2:attacker2 client:benign; do
  scp -q $SSHO "$DIR/${pair#*:}.pcap" "$USER_AT${pair%%:*}:${pair#*:}.pcap"
done
# this server's MAC address on the lab network, so the senders need no ping to find it
MYMAC=$(cat /sys/class/net/"$(ip -o route get "$(getent hosts attacker1 | awk '{print $1}')" | sed -n 's/.* dev \([^ ]*\).*/\1/p')"/address)
for pair in attacker1:attacker1 attacker2:attacker2 client:benign; do
  host=${pair%%:*}; name=${pair#*:}
  ip=$(getent hosts $host | awk '{print $1}')
  peers=$(sed -n "s/^peers_$name=//p" "$DIR/manifest.txt")
  ssh $SSHO "$USER_AT$host" \
    "VMAC=$MYMAC MAXSLEEP=$MAXSLEEP sudo -E nohup bash replay_attack.sh $name.pcap $VICTIM ${peers:+$peers:$ip} > replay.log 2>&1 &"
  echo "  $host ($ip) <- $name.pcap   (recorded peer(s) ${peers:--})"
done

# Follow the replay on this screen: every flow is shown when its first packet goes out, on the
# same schedule tcpreplay uses (the file's timing, idle gaps capped at MAXSLEEP if set). The lines are
# computed here from the replay files - the server cannot ask the senders once it has blocked them.
python3 - "$DIR" "$MAXSLEEP" "$(getent hosts attacker1 | awk '{print $1}')" \
          "$(getent hosts attacker2 | awk '{print $1}')" "$(getent hosts client | awk '{print $1}')" <<'PY'
import struct, sys, time
d, cap = sys.argv[1], (int(sys.argv[2]) / 1000) or float("inf")
own = {"attacker1": sys.argv[3], "attacker2": sys.argv[4], "benign": sys.argv[5]}
man = dict(l.strip().split("=", 1) for l in open(f"{d}/manifest.txt") if "=" in l)
PROTO = {1: "icmp", 6: "tcp", 17: "udp"}
ip = lambda x: ".".join(map(str, x))
events = []                                       # (offset s, sender, flow text)
for name, sender in (("attacker1", "attacker1"), ("attacker2", "attacker2"), ("benign", "client")):
    peers = set(man.get(f"peers_{name}", "").split(","))
    b = open(f"{d}/{name}.pcap", "rb").read()
    end = "<" if b[:4] in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1") else ">"
    nano = b[:4] in (b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d")
    o, prev, off, seen = 24, None, 0.0, set()
    while o + 16 <= len(b):
        s, frac, incl, _ = struct.unpack(end + "IIII", b[o:o + 16])
        t = s + frac / (1e9 if nano else 1e6)
        off = 0.0 if prev is None else off + min(t - prev, cap)
        prev, pkt, o = t, b[o + 16:o + 16 + incl], o + 16 + incl
        if len(pkt) < 34 or pkt[12:14] != b"\x08\x00":
            continue                              # IPv4 over Ethernet only
        ihl, proto = (pkt[14] & 15) * 4, pkt[23]
        src, dst = ip(pkt[26:30]), ip(pkt[30:34])
        src = own[name] if src in peers else src    # the address this container replays from
        dst = own[name] if dst in peers else dst
        sp = dp = 0
        if proto in (6, 17) and len(pkt) >= 14 + ihl + 4:
            sp, dp = struct.unpack(">HH", pkt[14 + ihl:18 + ihl])
        key = tuple(sorted([(src, sp), (dst, dp)])) + (proto,)
        if key not in seen:                       # first packet of a new flow
            seen.add(key)
            events.append((off, sender, f"{src}:{sp} -> {dst}:{dp} {PROTO.get(proto, proto)}"))
events.sort()
last = int(events[-1][0]) + 1 if events else 0
print(f"replay started -> {man.get('victim', '')}: {len(events)} flows in about {last} s "
      f"(lines follow the replay schedule; the senders start within a few seconds)", flush=True)
count, t0 = {}, time.time()
for off, sender, flow in events:
    wait = t0 + off - time.time()
    if wait > 0:
        time.sleep(wait)
    kind = "ATTACK" if sender.startswith("attacker") else "benign"
    count[sender] = count.get(sender, 0) + 1
    print(f"{time.strftime('%H:%M:%S', time.gmtime())}  SEND  {sender:<9} {kind:<6} {flow}", flush=True)
time.sleep(5)
print("\nreplay finished: " + ", ".join(f"{s} {n} flows" for s, n in sorted(count.items())))
print("see the detector terminal, then write the report (11_incident_report.py)")
PY
