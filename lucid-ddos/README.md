# lucid-ddos – a staged LUCID DDoS lab (Labtainer)

Every script is responsible for one learning outcome. It writes its output to a folder (and a
`pipeline.json`) that the next script reads, so the whole pipeline can be reproduced from its
parameters. Training and evaluation run single-threaded with seed 42 and deterministic PyTorch.

This folder is a standard Labtainer lab. Students add it once with
`imodule https://github.com/Berkaybbayramoglu/DDoS_Lab/releases/download/imodule/imodule.tar`
(built by `../tools/build_imodule.sh`, published by CI) and start it with `labtainer lucid-ddos`;
the images are pulled from Docker Hub (`REGISTRY berkaybbayramoglu` in `config/start.config`, published by CI).
To work on the lab, copy it into a Labtainer VM with `../tools/push_to_vm.sh` and build it there with
`rebuild lucid-ddos` (or labedit: Run → Build and run).

## Labtainer layout

| Path | Content |
| --- | --- |
| `config/start.config` | Network `LAB_LAN` 172.30.0.0/24; `server` .10 (2 CPUs, 2 terminals, X11), `attacker1` .66, `attacker2` .67, `client` .20 (1 CPU each, no terminal). All with `NO_GW` and `ADD-HOST LAB_LAN` |
| `dockerfiles/` | Based on `labtainer.network3` (Ubuntu 24.04, Python 3.12). Server: tshark, iptables, feh, PyTorch 2.6.0 CPU, numpy 1.26.4, matplotlib 3.11.2, `PYTHONHASHSEED=42`. Traffic containers: tcpreplay, hping3, curl |
| `server/` | Scripts copied into the student's home directory (01–13, `check.py`, `lablib.py`) |
| `server/home_tar/data/lab_traffic.pcap.gz` | The lab dataset (44 MB compressed, 947 MB uncompressed; tshark reads it directly). Kept in `home_tar/` so it is not collected as a student artifact |
| `instr_config/` | Automatic assessment (`checkwork`) |
| `docs/` | Student manual (to be written) |

Every step records a fingerprint of its input in `pipeline.json`; if an earlier step is re-run with
other parameters, the later steps stop and say which steps to run again, and `07_infer.py` refuses
a model prepared differently from the data (window, flows, normalization, features, n).

## Lab workflow (server terminal)

| # | Script | Learning outcome | Output |
| --- | --- | --- | --- |
| 1 | `01_window.py` | Capturing packets in time windows (t = 100 s; the next window starts at the first packet after the previous window ended) | `work/01_window/` |
| 2 | `02_flows.py` | Bidirectional 5-tuple flows, labelling, train/val/test split by flow | `work/02_flows/` |
| 3 | `03_normalize.py` | Scaling: `none` / `theoretical` (paper) / `global` (from the data) / `batchnorm` | `work/03_norm_*/` |
| 4 | `04_features.py` | Feature selection; IP addresses and ports invite shortcut learning | `work/04_feat_*/` |
| 5 | `05_shape.py` | n × f matrix per sample; zero padding if shorter, cut if longer | `work/05_shape_*/` |
| 6 | `06_train.py` | Training the 2D CNN (fixed epochs, no validation) | `models/*.pt` |
| 7 | `07_infer.py` | Inference with a saved model (only parameters are given) | `results/*.csv` |
| 8 | `08_evaluate.py` | Metrics + 95 % bootstrap confidence intervals; appends to a registry | `results/registry.json` |
| 9 | `09_plot.py` | Comparison figure per experiment + confidence interval table (view with `feh -. results/plots/figure1_normalization.png`; `-.` fits the figure to the window) | `results/plots/` |
| 14 | `14_classical.py` | Classical detection: a per-source threshold (SYN or packets per second in a window), tuned on the training split; `--bots K` spreads the attack over K bot addresses | `results/classical_*.csv` (+ `.sweep.json`) |
| 15 | `15_explain.py` | What the model relies on (permutation importance) and where it fails (errors by flow length) | `results/explain_*.csv`, `results/plots/explain_*.png` |
| – | `check.py` | Checks the rules of every preprocessing step independently; `--stage results` compares every run of the lab sheet with the reference results (settings and metrics) | table on screen |

```bash
python3 01_window.py --pcap data/lab_traffic.pcap.gz -t 100 --out work/01_window
python3 02_flows.py  --in work/01_window --attackers 172.30.0.66 172.30.0.67 --victims 172.30.0.10 --out work/02_flows

# Normalization experiment
for m in none theoretical global batchnorm; do
  python3 03_normalize.py --in work/02_flows --mode $m
  python3 04_features.py  --in work/03_norm_$m --set lucid --out work/04_feat_${m}_lucid
  python3 05_shape.py     --in work/04_feat_${m}_lucid -n 100 --out work/05_shape_${m}_lucid
  python3 06_train.py     --data work/05_shape_${m}_lucid --model models/${m}.pt
  python3 07_infer.py     --model models/${m}.pt --data work/05_shape_${m}_lucid --split test --out results/${m}.csv
  python3 08_evaluate.py  --pred results/${m}.csv --name $m --group normalization --model models/${m}.pt
done

# Feature selection experiment (IP/port = risk of memorising addresses). Every model is tested twice:
#   test          the normal test split
#   test_newaddr  the same flows with the attacker and benign client addresses swapped
for s in lucid lucid_ids ids_only; do
  python3 04_features.py --in work/03_norm_global --set $s --out work/04_feat_global_$s
  python3 05_shape.py    --in work/04_feat_global_$s -n 100 --out work/05_shape_global_$s
  python3 06_train.py    --data work/05_shape_global_$s --model models/global_$s.pt
  for sp in test test_newaddr; do
    python3 07_infer.py    --model models/global_$s.pt --data work/05_shape_global_$s --split $sp --out results/global_${s}_$sp.csv
    python3 08_evaluate.py --pred results/global_${s}_$sp.csv --name "$s ($sp)" --group features --model models/global_$s.pt
  done
done

# Shaping experiment (n packets per sample; zero padding if shorter, cut if longer; n >= 3)
for n in 3 10 50 100; do
  python3 05_shape.py    --in work/04_feat_global_lucid -n $n --out work/05_shape_global_lucid_n$n
  python3 06_train.py    --data work/05_shape_global_lucid_n$n --model models/global_lucid_n$n.pt
  python3 07_infer.py    --model models/global_lucid_n$n.pt --data work/05_shape_global_lucid_n$n --split test --out results/global_lucid_n$n.csv
  python3 08_evaluate.py --pred results/global_lucid_n$n.csv --name n=$n --group shape --model models/global_lucid_n$n.pt
done

# Classical detection vs. LUCID (results/global_lucid_test.csv comes from the feature experiment;
# the rule is tuned on the training split; --bots 50 = the same attack from 50 bots)
python3 08_evaluate.py  --pred results/global_lucid_test.csv --name "LUCID CNN" --group classical --model models/global_lucid.pt
python3 14_classical.py --flows work/02_flows --rule syn --split test --out results/classical_syn.csv
python3 08_evaluate.py  --pred results/classical_syn.csv --name "syn threshold" --group classical
python3 14_classical.py --flows work/02_flows --rule syn --split test --bots 50 --out results/classical_syn_bots50.csv
python3 08_evaluate.py  --pred results/classical_syn_bots50.csv --name "syn threshold (50 bots)" --group classical

# Comparison figures + confidence interval tables
python3 09_plot.py --groups normalization features shape classical

# Every run compared with the reference results of the lab (settings + metrics within 0.5 points)
python3 check.py --stage results --dir results

# What the models rely on and where they fail
python3 15_explain.py --model models/global_lucid.pt     --data work/05_shape_global_lucid
python3 15_explain.py --model models/global_lucid_ids.pt --data work/05_shape_global_lucid_ids
python3 15_explain.py --model models/global_lucid_n3.pt  --data work/05_shape_global_lucid_n3
```

Measured (test split of 4,260 samples): normalization raw 99.9 % · theoretical / global / batchnorm
100 % (the difference shows in the training loss, see below); shaping n = 3 75.2 % · n = 10 / 50 / 100
100 %. Feature selection (accuracy, test → test_newaddr): `lucid` 100 % → 100 % · `lucid_ids` 100 % →
52.9 % · `ids_only` 100 % → 1.4 %. On the normal test split all three look perfect; once the addresses
change, only the address-free LUCID features hold up (shortcut learning).

Classical detection (test split): the SYN-rate threshold chosen on the training split (54 SYN/s; benign
sources reach at most 3.4 SYN/s, the attacker at least 105) is perfect while the attack comes from one
address. Spread over 50 bots, every bot stays near 3 SYN/s, inside the benign range: the tuned threshold
catches nothing (recall 0 %) and no threshold separates the two (best: recall 51 % at 10.5 % FPR, see
the sweep in Figure 4b). LUCID judges each flow without addresses, so its decisions do not change.

Explanation (`15_explain.py`): the LUCID model relies on tcp_win, packet_len, tcp_len and highest_layer
(accuracy drop 14–19 points each when shuffled); the lucid_ids model relies only on src_ip (36 points);
the n = 3 model misses all 1,056 HTTP-flood flows longer than 10 packets, whose first 3 packets look like
benign HTTP.

## Post-lab (server + attacker1 + attacker2 + client)

The validation split is not used for training (the number of epochs is fixed from the paper).
Instead it is used to simulate an attack with traffic never seen in training: the student's own
model detects and blocks it live, and the student writes a post-incident report.

| Order | Script | Job |
| --- | --- | --- |
| 0 | `ssh-keygen -t ed25519`, then `ssh-copy-id ubuntu@attacker1` / `attacker2` / `client` (password `ubuntu`) | The student sets up key-based SSH access from the server to the traffic containers, as an incident response team prepares its tooling. No key is shipped with the lab; `13_launch_replay.sh` checks the access and prints these commands if it is missing |
| 1 | `12_build_replay.py` | Splits the validation flows into `attacker1` / `attacker2` / `benign` pcaps and writes `manifest.txt`. The flow start times are spread over 90 s in recorded order; the packets inside each flow keep their recorded timing |
| 2 | `sudo python3 10_detect_block.py ... --iface eth0 --block --seconds 150` (terminal 1) | The server watches its own interface, classifies the flows and blocks attacker addresses with iptables. One `ALERT` line per attack flow, one `BLOCK` line per blocked address |
| 3 | `./13_launch_replay.sh` (terminal 2) | Copies the pcaps to the three traffic containers over SSH (the student's key from step 0), starts them together and shows every flow sent as a `SEND` line |
| 4 | `11_incident_report.py` | Post-incident report from the detection log: addresses, confidence intervals, recall/FPR, blocked addresses and time to block |

Detector settings (`10_detect_block.py`):

- `--interval 5`: the open window is re-classified every 5 s, so an attacker is blocked while the
  attack is running, not only when the 100 s window closes.
- `--idle 2`: before the window closes, only flows without a packet for 2 s (finished flows) are
  judged. Otherwise half-open benign connections look like a SYN flood and get blocked.
- `--min-alerts 3`: an address is blocked only after 3 of its flows were flagged, so a single false
  alarm does not cut a legitimate host off; the alarm still appears in the report.
- Only flows of the protected host are judged; the lab's SSH channel (port 22, used by
  `13_launch_replay.sh`) is not captured. Live capture and blocking need `sudo`; `--block` is
  refused with `--pcap` (offline analysis never changes the firewall).
- `--seconds` counts from the first packet the detector sees: it waits for the attack, so
  `13_launch_replay.sh` can be started at any time (CI starts it 60 s after the detector).
- Re-running the incident: `13_launch_replay.sh` first removes the DROP rules a previous detector
  run left for attacker1, attacker2 and client.

Replay details (`13_launch_replay.sh`, `*/replay_attack.sh`):

- **The server stays silent towards the replay.** The pcaps already contain the server's recorded
  answers. If the live kernel answered every replayed packet with a TCP RST / ICMP unreachable, the
  flows would get packets that were never recorded (recall dropped to 64 %). The launcher drops
  those answers with `iptables OUTPUT` rules.
- **Address mapping works in both directions** (`tcprewrite --pnat`): the recorded peer addresses
  move to the replaying container's own address, the server's address stays the same.
- **No gap capping by default.** Because `12_build_replay.py` already packs the flows into about 90 s,
  tcpreplay plays the file's timing as it is (`MAXSLEEP=0`).
- **One sample per flow.** `12_build_replay.py` keeps one sample per flow as the server will see it,
  so samples of the same 5-tuple from different recorded windows, and benign clients that used the
  same source port, do not merge into one flow in the 90 s replay.
- **No extra packets.** The launcher passes the server's MAC address to the senders, so they do not
  ping it (which would add ICMP flows).

## Dataset

`server/home_tar/data/lab_traffic.pcap.gz` holds six sessions: 2 benign, 2 SYN flood, 2 HTTP flood
(10 parallel loops). Each session lasts about 185 s (60 s benign, 60 s attack on top of the benign
traffic, 60 s benign), with 400 s of silence between sessions. The benign side has 17 users with
different behaviour (172.30.0.20–36, `../tools/benign_clients.py`): 3 browse (a page + 2–6 parallel
requests), 2 api (frequent small requests), 4 keepalive (3–10 requests on one connection),
4 download (50–300 kB) and 4 slow (a large file read in small chunks). Offloads (TSO/GSO/GRO) are off
while recording, so every frame is at most 1514 bytes, as on a physical link.

| | Count |
|---|---|
| Packets | 1.8 million (947 MB; 44 MB with gzip because the served files are zero bytes) |
| Samples (window × flow) | 135,154 (113,854 DDoS, 21,300 benign) |
| Balanced set | 42,600 → train 34,506 · val 3,834 · test 4,260 |
| Attack types (selected) | SYN ~50 % · HTTP ~50 % |
| Benign user types | browse 46.5 % · api 28.8 % · download 8.4 % · slow 8.1 % · keepalive 8.0 % |

Every benign user type has 150+ test samples, so errors can be measured per type (currently 0 in
every type). To regenerate: `../tools/build_lab_dataset.sh` (about 20 minutes).

## Measured results (inside the Labtainer VM, clean build, 1 vCPU per step)

- Preprocessing checks (`check.py`): 100 % for window, flows, normalize, features and shape.
- Normalization: test accuracy is about 100 % for all modes (raw 99.9 %); the difference is in the
  training loss (Figure 1b). Raw values make the loss jump between 10^2 and 10^5 without
  converging; theoretical (super-global) min-max learns smoothly but slowly (0.3 → 0.002); global
  and batchnorm learn fast (about 10^-6 within 5–9 epochs). The question for students is not
  "which is more accurate" but "which learns better and more stably, and why".
- The same results come out on the host (plain Docker) and in the VM, run for run.
- Time: one training (34,506 samples, 10 epochs) about 1 min, about 500 MB; `01_window` about 1 min,
  about 700 MB (tshark resets its state every 200,000 packets; otherwise it used 2 GB). The whole
  lab part takes about 13 min of machine time, the post-lab about 3 min.
- Post-lab (run twice in a row in Labtainer): replay of about 3,500 validation flows (one sample per
  flow; 45 + 46 + 241 duplicate samples left out) in about 70 s; both attackers blocked a few seconds
  after the first attack flow, the benign client not blocked. Recall 100 %, FPR 0 %; no flow of the
  SSH channel in the detection log; the second run removed the blocks of the first one.

## Assessment (`instr_config/`)

| Goal | Source |
| --- | --- |
| `window_check` … `shape_check` | `check.py` stdout contains "`<stage> stage - 100 % of the rules pass`" |
| `results_check` | `check.py --stage results`: all 17 runs of the lab sheet match the reference |
| `normalization_compared`, `features_compared`, `shape_compared` | `09_plot.py` stdout (one figure per experiment) |
| `address_swap_tested` | `07_infer.py` was run on the `test_newaddr` split |
| `classical_tested`, `classical_compared` | `14_classical.py` was run with `--bots`; `09_plot.py` drew the classical figure |
| `decisions_explained` | `15_explain.py` printed a permutation importance |
| `incident_report`, `attacker1_blocked`, `attacker2_blocked` | `results/incident_report.txt` |
| `only_attackers_blocked` | Both attackers listed and exactly 2 addresses blocked (the client was not) |

## labedit

The lab opens in labedit (File → Open Lab → `labs/lucid-ddos`):

- 4 containers and `LAB_LAN 172.30.0.0/24`; the container settings (user/password, terminals, X11,
  no external gateway, IP, add-hosts, number of CPUs) are read correctly.
- Pressing OK in the Results and Goals editors writes files identical to the ones in this folder.
- `config/start.config` and `config/parameter.config` are kept in the format labedit's "Save Lab"
  writes (no comments, labedit's field order), so saving in labedit produces no diff.
- **Rule:** values in `results.config` must not contain `:` – labedit splits fields on it.
- `config/about.txt` and `config/keywords.txt` are the lab description and keywords labedit asks
  for. The lab manual (`docs/lucid-ddos.pdf`) will be added with the student document.

## Developer checks and CI (plain Docker, see `../tools/` and `../.github/workflows/ci.yml`)

- `static_checks.py`: syntax, no secrets, no Turkish text, Labtainer layout, labedit rules, dataset.
- `check_lab.sh`: runs the whole pipeline on 1 CPU and checks the stage scores, determinism and the
  normalization ordering, classical rule, explanation and the reference results (11/11, about 9 minutes).
- `train_default_model.sh` + `postlab_live.sh`: the post-lab with plain Docker containers; checks that
  both attackers and only they are blocked, recall >= 90 %, FPR <= 5 %. The SSH hand-over of step 0 is
  exercised in Labtainer, not here.
- `build_labtainer_images.sh` + `smoke_labtainer_images.sh`: builds the four images the way Labtainer
  does and checks their contents; on `main` CI then publishes them with `publish_images.sh`.
