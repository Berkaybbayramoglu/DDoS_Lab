#!/bin/bash
# Runs every command of the lab sheet (the student manual) in order, in the lucid-server developer
# image on 1 CPU, and checks that all runs match the reference results (check.py --stage results).
# Shows on another computer whether the results of the lab are the same there.
#   usage: lab_sheet.sh            (needs the lucid-server image; replaces work/, models/, results/)
set -u
SRV=$(cd "$(dirname "$0")/../lucid-ddos/server" && pwd)
echo "CPU: $(grep -m1 'model name' /proc/cpuinfo | cut -d: -f2 | xargs); $(grep -m1 -o 'avx512f' /proc/cpuinfo || echo 'no avx512')"
D="docker --context default"
mkdir -p "$SRV/data"; trap 'rmdir "$SRV/data" 2>/dev/null' EXIT    # mount point for home_tar/data
$D run --rm --cpus=1 -u "$(id -u):$(id -g)" -e PYTHONHASHSEED=42 -e HOME=/tmp -e MPLCONFIGDIR=/tmp \
   -e PYTHONDONTWRITEBYTECODE=1 -v "$SRV":/srv -v "$SRV/home_tar/data":/srv/data:ro -w /srv -i lucid-server bash -s <<'SHEET' \
   > "$SRV/results_sheet.log" 2>&1
set -e
rm -rf work models results
L() { echo "### $*"; "$@"; }
L python3 01_window.py --pcap data/cic_ddos2019_sample.pcap.gz data/lab_traffic.pcap.gz -t 100 --out work/01_window
L python3 check.py --stage window --dir work/01_window
L python3 02_flows.py --in work/01_window --attackers 172.16.0.5 172.30.0.66 172.30.0.67 --victims 192.168.50.1 192.168.50.4 172.30.0.10 --out work/02_flows
L python3 check.py --stage flows --dir work/02_flows
L python3 03_normalize.py --in work/02_flows --mode global
L python3 check.py --stage normalize --dir work/03_norm_global
L python3 04_features.py --in work/03_norm_global --set lucid --out work/04_feat_global_lucid
L python3 check.py --stage features --dir work/04_feat_global_lucid
L python3 05_shape.py --in work/04_feat_global_lucid -n 100 --out work/05_shape_global_lucid
L python3 check.py --stage shape --dir work/05_shape_global_lucid
L python3 06_train.py --data work/05_shape_global_lucid --model models/global.pt
L python3 07_infer.py --model models/global.pt --data work/05_shape_global_lucid --split test --out results/global.csv
L python3 08_evaluate.py --pred results/global.csv --name global --group normalization --model models/global.pt
for m in none theoretical batchnorm; do
  L python3 03_normalize.py --in work/02_flows --mode $m
  L python3 04_features.py --in work/03_norm_$m --set lucid --out work/04_feat_${m}_lucid
  L python3 05_shape.py --in work/04_feat_${m}_lucid -n 100 --out work/05_shape_${m}_lucid
  L python3 06_train.py --data work/05_shape_${m}_lucid --model models/${m}.pt
  L python3 07_infer.py --model models/${m}.pt --data work/05_shape_${m}_lucid --split test --out results/${m}.csv
  L python3 08_evaluate.py --pred results/${m}.csv --name $m --group normalization --model models/${m}.pt
done
# experiment 3: features, on the lab network (scaling fitted on it, trained on it, tested on it)
L python3 03_normalize.py --in work/02_flows --mode global --fit-on lab --out work/03_norm_global_lab
L python3 check.py --stage normalize --dir work/03_norm_global_lab
for s in lucid lucid_ids ids_only; do
  L python3 04_features.py --in work/03_norm_global_lab --set $s --out work/04_feat_lab_$s
  L python3 05_shape.py --in work/04_feat_lab_$s -n 100 --out work/05_shape_lab_$s
  L python3 06_train.py --data work/05_shape_lab_$s --train-on lab --model models/lab_$s.pt
  for sp in test test_newaddr; do
    L python3 07_infer.py --model models/lab_$s.pt --data work/05_shape_lab_$s --split $sp --source lab --out results/lab_${s}_$sp.csv
    L python3 08_evaluate.py --pred results/lab_${s}_$sp.csv --name "$s ($sp)" --group features --model models/lab_$s.pt
  done
done
for n in 3 10 50 100; do
  L python3 05_shape.py --in work/04_feat_global_lucid -n $n --out work/05_shape_global_lucid_n$n
  L python3 06_train.py --data work/05_shape_global_lucid_n$n --model models/global_lucid_n$n.pt
  L python3 07_infer.py --model models/global_lucid_n$n.pt --data work/05_shape_global_lucid_n$n --split test --out results/global_lucid_n$n.csv
  L python3 08_evaluate.py --pred results/global_lucid_n$n.csv --name n=$n --group shape --model models/global_lucid_n$n.pt
done
L python3 14_classical.py --flows work/02_flows --rule syn --split test --out results/classical_syn.csv
L python3 14_classical.py --flows work/02_flows --rule syn --split test --bots 50 --out results/classical_syn_bots50.csv
L python3 08_evaluate.py --pred results/global.csv --name "LUCID CNN" --group classical --model models/global.pt
L python3 08_evaluate.py --pred results/classical_syn.csv --name "syn threshold" --group classical
L python3 08_evaluate.py --pred results/classical_syn_bots50.csv --name "syn threshold (50 bots)" --group classical
L python3 15_explain.py --model models/global.pt --data work/05_shape_global_lucid
L python3 15_explain.py --model models/lab_lucid_ids.pt --data work/05_shape_lab_lucid_ids --source lab
L python3 15_explain.py --model models/global_lucid_n3.pt --data work/05_shape_global_lucid_n3
# experiment 6: training on another network
L python3 03_normalize.py --in work/02_flows --mode global --fit-on cic --out work/03_norm_global_cic
L python3 check.py --stage normalize --dir work/03_norm_global_cic
L python3 04_features.py --in work/03_norm_global_cic --set lucid --out work/04_feat_cic_lucid
L python3 05_shape.py --in work/04_feat_cic_lucid -n 100 --out work/05_shape_cic_lucid
L python3 06_train.py --data work/05_shape_cic_lucid --train-on cic --model models/cic_lucid.pt
for src in cic lab; do
  L python3 07_infer.py --model models/cic_lucid.pt --data work/05_shape_cic_lucid --split test --source $src --out results/cic_only_test_$src.csv
  L python3 08_evaluate.py --pred results/cic_only_test_$src.csv --name "cic only (test $src)" --group shift --model models/cic_lucid.pt
  L python3 07_infer.py --model models/lab_lucid.pt --data work/05_shape_lab_lucid --split test --source $src --out results/lab_only_test_$src.csv
  L python3 08_evaluate.py --pred results/lab_only_test_$src.csv --name "lab only (test $src)" --group shift --model models/lab_lucid.pt
  L python3 07_infer.py --model models/global.pt --data work/05_shape_global_lucid --split test --source $src --out results/both_test_$src.csv
  L python3 08_evaluate.py --pred results/both_test_$src.csv --name "cic + lab (test $src)" --group shift --model models/global.pt
done
L python3 09_plot.py --groups normalization features shape classical shift
L python3 check.py --stage results --dir results
SHEET
status=$?
mv "$SRV/results_sheet.log" "$SRV/results/lab_sheet.log" 2>/dev/null
LOG="$SRV/results/lab_sheet.log"
sed -n '/^### python3 check.py --stage results/,$p' "$LOG"
[ $status -eq 0 ] && grep -q "results stage - 100 % of the reference runs match" "$LOG"
