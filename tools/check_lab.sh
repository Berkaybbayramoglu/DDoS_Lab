#!/bin/bash
# End-to-end check of the staged LUCID lab (lucid-ddos/server), all on 1 CPU, seed 42.
# Runs the pipeline once, verifies every preprocessing stage with check.py, confirms the
# normalization experiment produces the expected ordering, and checks that training is
# deterministic (same model twice) and inference deterministic (same predictions twice).
# Prints PASS/FAIL per check. Needs the lucid-server image.
set -u
SRV=$(cd "$(dirname "$0")/../lucid-ddos/server" && pwd)
D="docker --context default"
mkdir -p "$SRV/data"; trap 'rmdir "$SRV/data" 2>/dev/null' EXIT    # mount point for home_tar/data
R="$D run --rm --cpus=1 -u $(id -u):$(id -g) -e PYTHONHASHSEED=42 -e HOME=/tmp -e MPLCONFIGDIR=/tmp -e PYTHONDONTWRITEBYTECODE=1 -v $SRV:/srv -v $SRV/home_tar/data:/srv/data:ro -w /srv lucid-server"
W=work/.check; PASS=0; FAIL=0
ok()  { echo "PASS  $1"; PASS=$((PASS+1)); }
bad() { echo "FAIL  $1"; FAIL=$((FAIL+1)); }

echo "== pipeline (window -> flows -> normalize -> features -> shape), stage checks"
$R sh -c "
  python3 01_window.py --pcap data/lab_traffic.pcap.gz -t 100 --out $W/01 &&
  python3 02_flows.py --in $W/01 --attackers 172.30.0.66 172.30.0.67 --victims 172.30.0.10 --out $W/02 &&
  python3 03_normalize.py --in $W/02 --mode global --out $W/03 &&
  python3 04_features.py --in $W/03 --set lucid --out $W/04 &&
  python3 05_shape.py --in $W/04 -n 100 --out $W/05 " >/dev/null 2>&1 || bad "pipeline ran"
for st in "window $W/01" "flows $W/02" "normalize $W/03" "features $W/04" "shape $W/05"; do
  set -- $st
  if $R python3 check.py --stage $1 --dir $2 2>/dev/null | grep -q "100 % of the rules pass"; then
    ok "check $1 = 100 %"; else bad "check $1 = 100 %"; fi
done

echo "== train / infer / evaluate"
$R sh -c "python3 06_train.py --data $W/05 --model $W/m.pt >/dev/null &&
          python3 06_train.py --data $W/05 --model $W/m2.pt >/dev/null &&
          python3 07_infer.py --model $W/m.pt --data $W/05 --split test --out $W/p1.csv >/dev/null &&
          python3 07_infer.py --model $W/m.pt --data $W/05 --split test --out $W/p2.csv >/dev/null" 2>/dev/null
$R python3 - <<'PY' 2>/dev/null && ok "training deterministic (same weights twice)" || bad "training deterministic"
import torch;a=torch.load("/srv/work/.check/m.pt")["state"];b=torch.load("/srv/work/.check/m2.pt")["state"]
import sys;sys.exit(0 if all(torch.equal(a[k],b[k]) for k in a) else 1)
PY
$R sh -c "cmp -s $W/p1.csv $W/p2.csv" && ok "inference deterministic (same predictions twice)" || bad "inference deterministic"

echo "== normalization experiment: final training loss raw > theoretical > global"
rm -f "$SRV/results/registry_check.json"
for m in none theoretical global batchnorm; do
  $R sh -c "python3 03_normalize.py --in $W/02 --mode $m --out $W/n_$m >/dev/null &&
            python3 04_features.py --in $W/n_$m --set lucid --out $W/f_$m >/dev/null &&
            python3 05_shape.py --in $W/f_$m -n 100 --out $W/s_$m >/dev/null &&
            python3 06_train.py --data $W/s_$m --model $W/m_$m.pt >/dev/null &&
            python3 07_infer.py --model $W/m_$m.pt --data $W/s_$m --split test --out $W/e_$m.csv >/dev/null &&
            python3 08_evaluate.py --pred $W/e_$m.csv --name $m --group norm --model $W/m_$m.pt --registry results/registry_check.json" >/dev/null 2>&1
done
$R python3 - <<'PY' 2>/dev/null && ok "training loss raw > theoretical > global, global accuracy >= 99 %" || bad "normalization ordering"
import json, sys
loss = {m: float(json.load(open(f"/srv/work/.check/m_{m}_train_log.json"))["epochs"][-1][1]) for m in ("none", "theoretical", "global")}
acc = {x["name"]: x["point"]["accuracy"] for x in json.load(open("/srv/results/registry_check.json"))}
sys.exit(0 if loss["none"] > loss["theoretical"] > loss["global"] and acc["global"] >= 0.99 else 1)
PY
rm -f "$SRV/results/registry_check.json"

echo "== Summary: $PASS passed, $FAIL failed"
[ $FAIL -eq 0 ]

rm -rf "$SRV/work/.check"
