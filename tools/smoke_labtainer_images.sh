#!/bin/bash
# Checks the contents of the four Labtainer images built by build_labtainer_images.sh (or by
# Labtainer itself) without starting the lab:
#   server     lab scripts, dataset, Python packages, seed and tools in place; a lab script runs
#   traffic    replay_attack.sh, tcpreplay and hping3 in place
#   all        lab user with passwordless sudo, no SSH key shipped in the home directory
#   usage: smoke_labtainer_images.sh      (exit code 0 = all checks passed)
set -u
D="docker --context default"
FAIL=0
run() {   # run <image> <user> <command>
  $D run --rm --entrypoint bash -u "$2" -w /home/ubuntu -e HOME=/home/ubuntu "$1" -c "$3"
}
check() {  # check <name> <image> <user> <command>
  if out=$(run "$2" "$3" "$4" 2>&1); then echo "PASS  $1"; else echo "FAIL  $1"; echo "$out" | tail -5 | sed 's/^/      /'; FAIL=1; fi
}
S=lucid-ddos.server.student
check "server: lab scripts and dataset" $S ubuntu \
  'for f in 01_window.py 06_train.py 10_detect_block.py 13_launch_replay.sh 14_classical.py 15_explain.py check.py lablib.py data/lab_traffic.pcap.gz data/cic_ddos2019_sample.pcap.gz data/README.txt; do test -e "$f" || { echo "missing $f"; exit 1; }; done'
check "server: torch 2.6 / numpy / matplotlib, PYTHONHASHSEED=42" $S ubuntu \
  'python3 -c "import torch, numpy, matplotlib; assert torch.__version__.startswith(\"2.6\"), torch.__version__" && test "$PYTHONHASHSEED" = 42'
check "server: model is a 2D CNN with 2241 parameters" $S ubuntu \
  'python3 -c "import lablib; m = lablib.build_model(11); assert sum(p.numel() for p in m.parameters()) == 2241; print(m.conv)"'
check "server: tshark reads the dataset" $S ubuntu \
  'for f in data/lab_traffic.pcap.gz data/cic_ddos2019_sample.pcap.gz; do tshark -r $f -c 5 -T fields -e frame.number | wc -l | grep -qx 5 || exit 1; done'
check "server: iptables, ssh client, feh" $S root 'which iptables ssh ssh-keygen ssh-copy-id feh >/dev/null'
for c in attacker1 attacker2 client; do
  check "$c: replay_attack.sh, tcpreplay, hping3, sshd" lucid-ddos.$c.student ubuntu \
    'test -x replay_attack.sh && which tcpreplay tcprewrite hping3 >/dev/null && test -x /usr/sbin/sshd'
done
for c in server attacker1 attacker2 client; do
  check "$c: lab user with passwordless sudo, no SSH key shipped" lucid-ddos.$c.student ubuntu \
    'id ubuntu >/dev/null && sudo -n true && ! ls -A ~/.ssh 2>/dev/null | grep -q .'
done
for c in server attacker1 attacker2 client; do
  label=$($D inspect --format '{{index .Config.Labels "base"}}' lucid-ddos.$c.student 2>/dev/null)
  if [[ "$label" =~ ^[a-z0-9]+/labtainer\.[a-z0-9.]+\.[0-9a-f]{12}$ ]]; then echo "PASS  $c: Labtainer base label ($label)"
  else echo "FAIL  $c: Labtainer base label missing or malformed ('$label')"; FAIL=1; fi
done
[ $FAIL -eq 0 ] && echo "all checks passed" || echo "some checks failed"
exit $FAIL
