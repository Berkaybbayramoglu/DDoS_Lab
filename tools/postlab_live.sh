#!/bin/bash
# Post-lab end-to-end test, driven from the lab folders:
#   server   runs the student's model live (10_detect_block.py --block) on its own interface
#   attacker1/2 replay their share of the held-out validation traffic (12_build_replay.py output)
#   a benign client replays the validation benign traffic at the same time
# After the replay the server writes the post-incident report (11_incident_report.py) and the result
# is checked: both attackers blocked, the client not blocked, recall >= 90 %, FPR <= 5 %; and the
# progress record: the live detection timed, the incident checkpoint passed and the end of the lab set
# by the report (the last script), and the post-lab quiz graded.
# The traffic containers start replay_attack.sh directly; the SSH hand-over of 13_launch_replay.sh
# (student's own key) is exercised in Labtainer, not here.
# Everything runs on an isolated Docker bridge; the only state changed is the server's own
# iptables INPUT chain inside its container.
#   usage: postlab_live.sh [model]      (exit code 0 = all checks passed)
set -u
MODEL=${1:-models/global.pt}
D="docker --context default"
SRV=$(cd "$(dirname "$0")/../lucid-ddos/server" && pwd)
DATA="-v $SRV/home_tar/data:/srv/data:ro"                      # Labtainer keeps the capture in home_tar/
mkdir -p "$SRV/data"; trap 'rmdir "$SRV/data" 2>/dev/null' EXIT    # mount point for home_tar/data
ATT=$(cd "$(dirname "$0")/../lucid-ddos" && pwd)
VIC=172.30.0.10; A1=172.30.0.66; A2=172.30.0.67; CL=172.30.0.20
$D rm -f pl-server pl-att1 pl-att2 pl-client >/dev/null 2>&1; $D network rm plnet >/dev/null 2>&1
$D network create --subnet 172.30.0.0/24 plnet >/dev/null

# the student first builds the replay traffic from the validation split (safe to re-run)
$D run --rm --cpus=1 -u "$(id -u):$(id -g)" -e HOME=/tmp -e PYTHONDONTWRITEBYTECODE=1 -v "$SRV":/srv $DATA -w /srv \
   lucid-server python3 12_build_replay.py --flows work/02_flows --victim $VIC --out replay >/dev/null

peer() { sed -n "s/^peers_$1=//p" "$SRV/replay/manifest.txt"; }

# server: live detection + blocking for ~150 s. As in 13_launch_replay.sh, the server's kernel is
# kept from answering the replayed packets (the replay already holds the recorded answers).
QUIET=""
for ip in $A1 $A2 $CL; do
  QUIET="$QUIET iptables -I OUTPUT -d $ip -p tcp --tcp-flags RST RST -j DROP;"
  QUIET="$QUIET iptables -I OUTPUT -d $ip -p icmp --icmp-type destination-unreachable -j DROP;"
done
$D run -d --name pl-server --network plnet --ip $VIC --cpus=2 --cap-add NET_RAW --cap-add NET_ADMIN -e PYTHONDONTWRITEBYTECODE=1 \
   -v "$SRV":/srv $DATA -w /srv lucid-server sh -c \
   "$QUIET mkdir -p results && python3 10_detect_block.py --model $MODEL --iface eth0 --victim $VIC --block \
    --seconds 150 --out results/incident_live.csv > results/detect.log 2>&1" >/dev/null
sleep 60                                            # a late start: the capture time counts from the first packet
VMAC="-e VMAC=$($D inspect -f '{{range .NetworkSettings.Networks}}{{.MacAddress}}{{end}}' pl-server)"  # no ARP ping
REP="-v $SRV/replay:/srv_replay:ro"                 # the replay pcaps, shared read-only
# each container mounts only its own lab folder and runs its own replay_attack.sh, with the
# recorded peer address(es) moved to its own address
$D run -d --name pl-att1 --network plnet --ip $A1 --cap-add NET_RAW --cap-add NET_ADMIN $VMAC -v "$ATT/attacker1":/home/student $REP \
   -w /home/student lucid-attacker bash replay_attack.sh /srv_replay/attacker1.pcap $VIC "$(peer attacker1):$A1" >/dev/null
$D run -d --name pl-att2 --network plnet --ip $A2 --cap-add NET_RAW --cap-add NET_ADMIN $VMAC -v "$ATT/attacker2":/home/student $REP \
   -w /home/student lucid-attacker bash replay_attack.sh /srv_replay/attacker2.pcap $VIC "$(peer attacker2):$A2" >/dev/null
$D run -d --name pl-client --network plnet --ip $CL --cap-add NET_RAW --cap-add NET_ADMIN $VMAC -v "$ATT/client":/home/student $REP \
   -w /home/student lucid-attacker bash replay_attack.sh /srv_replay/benign.pcap $VIC "$(peer benign):$CL" >/dev/null

echo "replay started (attacker1=$A1, attacker2=$A2, client=$CL -> victim=$VIC); waiting for the server window..."
$D wait pl-server >/dev/null
$D exec pl-server sh -c "iptables -L INPUT -n | grep DROP || echo 'no DROP rules'" 2>/dev/null | sed 's/^/  iptables: /' || true
$D run --rm -v "$SRV":/srv lucid-server chown -R "$(id -u):$(id -g)" /srv/results   # detector ran as root
$D run --rm --cpus=1 -u "$(id -u):$(id -g)" -e HOME=/tmp -e PYTHONDONTWRITEBYTECODE=1 -v "$SRV":/srv $DATA -w /srv lucid-server \
   python3 11_incident_report.py --log results/incident_live.csv --victim $VIC --attackers $A1 $A2 \
   --out results/incident_report.txt
$D run --rm --cpus=1 -u "$(id -u):$(id -g)" -e HOME=/tmp -e PYTHONDONTWRITEBYTECODE=1 -v "$SRV":/srv -w /srv -i lucid-server \
   sh -c "printf 'T\nF\nT\nF\nT\nF\nT\nF\n' | python3 quiz.py postlab" | tail -2
$D logs pl-server 2>/dev/null | tail -0
$D rm -f pl-server pl-att1 pl-att2 pl-client >/dev/null 2>&1; $D network rm plnet >/dev/null
echo "done -> server/results/incident_live.csv, server/results/incident_report.txt"
grep -E "IPs blocked|First block|recall|FPR" "$SRV/results/incident_report.txt"
python3 - "$SRV/results/incident_report.txt" "$A1" "$A2" "$CL" <<'PY'
import re, sys
text = open(sys.argv[1]).read()
blocked = set(re.findall(r"^\s+- (\S+)$", text, re.M))
recall = float(re.search(r"recall\): ([\d.]+) %", text).group(1))
fpr = float(re.search(r"\(FPR\):\s+([\d.]+) %", text).group(1))
checks = [("attacker1 blocked", sys.argv[2] in blocked), ("attacker2 blocked", sys.argv[3] in blocked),
          ("client not blocked", sys.argv[4] not in blocked), (f"recall {recall} % >= 90 %", recall >= 90),
          (f"FPR {fpr} % <= 5 %", fpr <= 5)]
for name, ok in checks:
    print(("PASS  " if ok else "FAIL  ") + name)
rec = __import__("json").load(open(sys.argv[1].replace("incident_report.txt", "time_result.json")))
cp = rec["checkpoints"]
checks += [("live detection timed", any(r["script"] == "10_detect_block.py" for r in rec.get("inference", []))),
           ("incident checkpoint passed", "passed" in cp.get("incident", {})),
           ("end of the lab set by the report", "lab_finish" in rec),
           ("gradelab lab_minutes written", sum(1 for _ in open(sys.argv[1].replace("incident_report.txt", "gradelab/lab_minutes.txt"))) == rec["lab_minutes"]),
           ("post-lab quiz graded 8 of 8", open(sys.argv[1].replace("incident_report.txt", "quiz_postlab.txt")).read().count("- RIGHT") == 8)]
for name, ok in checks[-5:]:
    print(("PASS  " if ok else "FAIL  ") + name)
sys.exit(0 if all(ok for _, ok in checks) else 1)
PY
