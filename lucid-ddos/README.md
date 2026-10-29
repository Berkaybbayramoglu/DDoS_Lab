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
| `server/` | Scripts copied into the student's home directory (01–15, `check.py`, `lablib.py`, `progress.py`, `quiz.py` with `quiz/`) |
| `server/_bin/` | `fixlocal.sh` (runs once when the lab is opened: records the start time), `prestop` (runs on `checkwork` and `stoplab`: the progress table) |
| `server/home_tar/data/` | The lab dataset: `cic_ddos2019_sample.pcap.gz` (the CIC-DDoS2019 sample of the LUCID authors, 7 MB) and `lab_traffic.pcap.gz` (recorded on the lab network, 44 MB compressed, 947 MB uncompressed), with `README.txt` (source, citation) and `LICENSE-lucid-ddos.txt`. tshark reads the files directly. Kept in `home_tar/` so they are not collected as a student artifact |
| `instr_config/` | Automatic assessment (`gradelab` for the instructor, `checkwork` for the student) |
| `config/prelab.quiz`, `config/postlab.quiz` | The pre-lab and post-lab quizzes (Labtainer quiz format; `server/quiz/` holds identical copies) |
| `docs/` | Student manual `lucid-ddos.pdf` (built from the LaTeX source of the manual) and `read_first.txt`, which Labtainer shows when the lab starts, with a link to the manual |

After every evaluation, `08_evaluate.py` prints the expected result of the run, whether the run matches it (or which
parameter to check) and the progress over the 23 runs of the lab sheet; `15_explain.py` and
`11_incident_report.py` print their expected results in the same way.

Every step records a fingerprint of its input in `pipeline.json`; if an earlier step is re-run with
other parameters, the later steps stop and say which steps to run again, and `07_infer.py` refuses
a model prepared differently from the data (window, flows, normalization, features, n).

## Lab workflow (server terminal)

| # | Script | Learning outcome | Output |
| --- | --- | --- | --- |
| 1 | `01_window.py` | Capturing packets in time windows (t = 100 s; the next window starts at the first packet after the previous window ended) | `work/01_window/` |
| 2 | `02_flows.py` | Bidirectional 5-tuple flows, labelling, train/val/test split by flow | `work/02_flows/` |
| 3 | `03_normalize.py` | Scaling: `none` / `theoretical` (paper) / `global` (from the data; `--fit-on cic/lab` fits it on one network) / `batchnorm` | `work/03_norm_*/` |
| 4 | `04_features.py` | Feature selection; IP addresses and ports invite shortcut learning | `work/04_feat_*/` |
| 5 | `05_shape.py` | n × f matrix per sample; zero padding if shorter, cut if longer | `work/05_shape_*/` |
| 6 | `06_train.py` | Training the 2D CNN (fixed epochs, no validation; `--train-on cic/lab` uses one network only) | `models/*.pt` |
| 7 | `07_infer.py` | Inference with a saved model (only parameters are given; `--source cic/lab` tests on one network) | `results/*.csv` |
| 8 | `08_evaluate.py` | Metrics + 95 % bootstrap confidence intervals; appends to a registry | `results/registry.json` |
| 9 | `09_plot.py` | Comparison figure per experiment + confidence interval table (view with `feh -. results/plots/figure1_normalization.png`; `-.` fits the figure to the window) | `results/plots/` |
| 14 | `14_classical.py` | Classical detection: a per-source threshold (SYN or packets per second in a window), tuned on the training split; `--bots K` spreads the attack over K bot addresses | `results/classical_*.csv` (+ `.sweep.json`) |
| 15 | `15_explain.py` | What the model relies on (permutation importance) and where it fails (errors by flow length) | `results/explain_*.csv`, `results/plots/explain_*.png` |
| – | `check.py` | Checks the rules of every preprocessing step independently; `--stage results` compares every run of the lab sheet with the reference results (settings and metrics) | table on screen |
| – | `progress.py` | The checkpoints of the lab: passed or not, when, how many attempts, and the next one to do | `results/time_result.json` |
| – | `quiz.py prelab` / `quiz.py postlab` | Pre-lab and post-lab quiz (True/False); the first attempt is graded | `results/quiz_*.txt`, `results/quiz_*.json` |

```bash
python3 01_window.py --pcap data/cic_ddos2019_sample.pcap.gz data/lab_traffic.pcap.gz -t 100 --out work/01_window
python3 02_flows.py  --in work/01_window --attackers 172.16.0.5 172.30.0.66 172.30.0.67 \
                     --victims 192.168.50.1 192.168.50.4 172.30.0.10 --out work/02_flows

# Normalization experiment (the global run is steps 3-8 of the manual; models/global.pt is the model of the post-lab)
for m in global none theoretical batchnorm; do
  python3 03_normalize.py --in work/02_flows --mode $m
  python3 04_features.py  --in work/03_norm_$m --set lucid --out work/04_feat_${m}_lucid
  python3 05_shape.py     --in work/04_feat_${m}_lucid -n 100 --out work/05_shape_${m}_lucid
  python3 06_train.py     --data work/05_shape_${m}_lucid --model models/${m}.pt
  python3 07_infer.py     --model models/${m}.pt --data work/05_shape_${m}_lucid --split test --out results/${m}.csv
  python3 08_evaluate.py  --pred results/${m}.csv --name $m --group normalization --model models/${m}.pt
done

# Feature selection experiment (IP/port = risk of memorising addresses), on the lab network: min-max
# fitted on its training samples (--fit-on lab), trained on them (--train-on lab), tested on them
# (--source lab). Every model is tested twice:
#   test          the normal test split
#   test_newaddr  the same flows with the attacker and benign client addresses swapped
python3 03_normalize.py --in work/02_flows --mode global --fit-on lab --out work/03_norm_global_lab
for s in lucid lucid_ids ids_only; do
  python3 04_features.py --in work/03_norm_global_lab --set $s --out work/04_feat_lab_$s
  python3 05_shape.py    --in work/04_feat_lab_$s -n 100 --out work/05_shape_lab_$s
  python3 06_train.py    --data work/05_shape_lab_$s --train-on lab --model models/lab_$s.pt
  for sp in test test_newaddr; do
    python3 07_infer.py    --model models/lab_$s.pt --data work/05_shape_lab_$s --split $sp --source lab --out results/lab_${s}_$sp.csv
    python3 08_evaluate.py --pred results/lab_${s}_$sp.csv --name "$s ($sp)" --group features --model models/lab_$s.pt
  done
done

# Shaping experiment (n packets per sample; zero padding if shorter, cut if longer; n >= 3)
for n in 3 10 50 100; do
  python3 05_shape.py    --in work/04_feat_global_lucid -n $n --out work/05_shape_global_lucid_n$n
  python3 06_train.py    --data work/05_shape_global_lucid_n$n --model models/global_lucid_n$n.pt
  python3 07_infer.py    --model models/global_lucid_n$n.pt --data work/05_shape_global_lucid_n$n --split test --out results/global_lucid_n$n.csv
  python3 08_evaluate.py --pred results/global_lucid_n$n.csv --name n=$n --group shape --model models/global_lucid_n$n.pt
done

# Classical detection vs. LUCID (the rule is tuned on the training split; --bots 50 = the same
# attack from 50 bots)
python3 08_evaluate.py  --pred results/global.csv --name "LUCID CNN" --group classical --model models/global.pt
python3 14_classical.py --flows work/02_flows --rule syn --split test --out results/classical_syn.csv
python3 08_evaluate.py  --pred results/classical_syn.csv --name "syn threshold" --group classical
python3 14_classical.py --flows work/02_flows --rule syn --split test --bots 50 --out results/classical_syn_bots50.csv
python3 08_evaluate.py  --pred results/classical_syn_bots50.csv --name "syn threshold (50 bots)" --group classical

# What the models rely on and where they fail
python3 15_explain.py --model models/global.pt          --data work/05_shape_global_lucid
python3 15_explain.py --model models/lab_lucid_ids.pt   --data work/05_shape_lab_lucid_ids --source lab
python3 15_explain.py --model models/global_lucid_n3.pt --data work/05_shape_global_lucid_n3

# Training on another network: a model trained on one network only, tested on both networks
python3 03_normalize.py --in work/02_flows --mode global --fit-on cic --out work/03_norm_global_cic
python3 04_features.py  --in work/03_norm_global_cic --set lucid --out work/04_feat_cic_lucid
python3 05_shape.py     --in work/04_feat_cic_lucid -n 100 --out work/05_shape_cic_lucid
python3 06_train.py     --data work/05_shape_cic_lucid --train-on cic --model models/cic_lucid.pt
for src in cic lab; do
  python3 07_infer.py    --model models/cic_lucid.pt --data work/05_shape_cic_lucid --split test --source $src --out results/cic_only_test_$src.csv
  python3 08_evaluate.py --pred results/cic_only_test_$src.csv --name "cic only (test $src)" --group shift --model models/cic_lucid.pt
  python3 07_infer.py    --model models/lab_lucid.pt --data work/05_shape_lab_lucid --split test --source $src --out results/lab_only_test_$src.csv
  python3 08_evaluate.py --pred results/lab_only_test_$src.csv --name "lab only (test $src)" --group shift --model models/lab_lucid.pt
  python3 07_infer.py    --model models/global.pt --data work/05_shape_global_lucid --split test --source $src --out results/both_test_$src.csv
  python3 08_evaluate.py --pred results/both_test_$src.csv --name "cic + lab (test $src)" --group shift --model models/global.pt
done

# Comparison figures + confidence interval tables
python3 09_plot.py --groups normalization features shape classical shift

# Every run compared with the reference results of the lab (settings + metrics within 0.5 points)
python3 check.py --stage results --dir results
```

Measured (test split of 4,551 samples: 447 of the CIC-DDoS2019 sample, 4,104 of the lab network):
normalization raw 97.7 % · theoretical 99.9 % · global 100.0 % · batchnorm 100.0 % (the difference also
shows in the training loss, see below); shaping n = 3 79.3 % · n = 10 / 50 / 100 99.9–100 %.

Feature selection (lab network, accuracy, test → test_newaddr): `lucid` 100 % → 100 % · `lucid_ids`
100 % → 40.4 % · `ids_only` 100 % → 1.8 %. On the normal test split all three look perfect; once the
addresses change, only the address-free LUCID features hold up (shortcut learning). The experiment runs
on the lab network because, with one min-max scaling for both networks (172.16.x to 192.168.x), the
addresses of one /24 differ by less than 10^-6 after scaling and the shortcut cannot be seen; the
address swap stays inside each network.

Classical detection (test split): the SYN-rate threshold chosen on the training split (54 SYN/s;
benign sources reach at most 3.4 SYN/s) catches every SYN and HTTP flood of the lab network (recall
93.9 %, FPR 0 %); 131 of the 139 flows it misses are the UDP attacks (DNS reflection, UDP-Lag) of the CIC sample, whose source sends
almost no SYN in those windows (0.3/s). Spread over 50 bots, every bot stays near 3 SYN/s, inside the benign range: the tuned
threshold catches nothing (recall 0 %) and no threshold separates the two (best: recall 39 % at 8.6 %
FPR, see the sweep in Figure 4b). LUCID judges each flow without addresses, so its decisions do not change.

Explanation (`15_explain.py`): the LUCID model relies on tcp_win, highest_layer and tcp_len (accuracy
drop 9–15 points each when shuffled); the lucid_ids model relies only on src_ip (38 points); the
n = 3 model misses 943 of the 950 attack flows longer than 10 packets (HTTP floods), whose first 3
packets look like benign HTTP.

Training on another network (accuracy, tested on CIC sample / lab network): trained on the CIC
sample only 99.8 % / 42.8 % (no lab attack found) · on the lab network only 54.6 % / 100 % · on both
99.6 % / 100 %. A model detects the attacks of the networks it was trained on; the lab therefore
trains on both, and the post-lab defends the lab network.

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

Two captures, read together by `01_window.py` (`server/home_tar/data/README.txt` has the source and
citation of each):

- `cic_ddos2019_sample.pcap.gz`: the CIC-DDoS2019 sample that the LUCID authors publish with their code
  (https://github.com/doriguzzi/lucid-ddos, `sample-dataset`, Apache-2.0): benign traffic and DNS
  reflection, SYN flood, UDP-Lag and Web DDoS, merged in time order. Attacker 172.16.0.5, victims
  192.168.50.1 and 192.168.50.4 (I. Sharafaldin et al., ICCST 2019).
- `lab_traffic.pcap.gz`: recorded for this lab on the lab network. Six sessions: 2 benign, 2 SYN
  flood, 2 HTTP flood (10 parallel loops). Each session lasts about 185 s (60 s benign, 60 s attack on
  top of the benign traffic, 60 s benign), with 400 s of silence between sessions. The benign side has
  17 users with different behaviour (172.30.0.20–36, `../tools/benign_clients.py`): 3 browse (a page +
  2–6 parallel requests), 2 api (frequent small requests), 4 keepalive (3–10 requests on one
  connection), 4 download (50–300 kB) and 4 slow (a large file read in small chunks). Offloads
  (TSO/GSO/GRO) are off while recording, so every frame is at most 1514 bytes, as on a physical link.

| | CIC-DDoS2019 sample | Lab network | Both |
|---|---|---|---|
| Packets | 80,100 | 1,805,644 | 1,885,744 |
| Samples (window × flow) | 18,556 (17,104 DDoS) | 135,154 (113,854 DDoS) | 153,710 |
| Balanced set | 4,455 | 41,049 | 45,504 → train 36,858 · val 4,095 · test 4,551 |
| Test split | 447 | 4,104 | 4,551 |

The balanced set takes every benign sample of both networks and as many DDoS samples, drawn from both.
The post-lab replays only validation flows of the lab network. To regenerate both captures:
`../tools/build_lab_dataset.sh` (about 20 minutes; it downloads the CIC sample from the LUCID repository).

## Measured results (inside the Labtainer VM, clean build, 1 vCPU per step)

- Preprocessing checks (`check.py`): 100 % for window, flows, normalize, features and shape.
- Normalization: raw values reach 97.7 % and their loss stays large (about 3·10^4 after 10 epochs,
  Figure 1b); theoretical (super-global) min-max learns smoothly but more slowly (final loss 0.005)
  than global (0.002) and batchnorm (0.0016), which reach 99.96–99.98 %. The question for students is not
  "which is more accurate" but "which learns better and more stably, and why".
- The same results come out on the host (plain Docker) and in the VM, run for run. One run depends
  on the computer: training on raw values (`none`) is numerically unstable, and tiny rounding
  differences between CPUs give different models (97.7 % here, 76.8 % on a GitHub runner).
  `check.py` therefore compares only the settings of that run (`VARIES`), and `08_evaluate.py` says so.
  The CIC-only model tested on the lab network (`cic only (test lab)`) extrapolates far outside its
  training range and varies a little as well (accuracy 40.0–43.8 %, FPR 14.8–22.2 % on four machines,
  recall always 0 %); it is compared within 10 points (`RUN_TOLERANCE`). On processors with AVX-512,
  PyTorch and oneDNN would use AVX-512 code that rounds differently (the `lucid_ids` training got
  stuck on an AMD EPYC 9V45); `lablib.py` therefore limits both to AVX2 (`ATEN_CPU_CAPABILITY`,
  `ONEDNN_MAX_CPU_ISA`) on every processor that has it. Every other run agreed within
  0.2 points on the host, the VM, PyTorch's generic CPU kernels and two GitHub runners.
- Time: one training (36,858 samples, 10 epochs) about 1 min, about 500 MB; `01_window` about 1 min,
  about 700 MB (tshark resets its state every 200,000 packets; otherwise it used 2 GB). The whole
  lab part (23 evaluated runs) takes about 11 min of machine time on 1 CPU, the post-lab about 3 min.
- Post-lab (run twice in a row in Labtainer): replay of 3,348 validation flows of the lab network (one sample per
  flow; 33 + 48 + 246 duplicate samples left out) in about 70 s; both attackers blocked 5 seconds
  after the first attack flow, the benign client not blocked. Recall 100 %, FPR 0 %; no flow of the
  SSH channel in the detection log; the second run removed the blocks of the first one.

## Assessment (`instr_config/`)

`gradelab lucid-ddos` (instructor) and `checkwork lucid-ddos` (student) show one line per checkpoint of
the lab sheet: `Y` = passed. `checkwork` also says, when not every checkpoint is passed yet, to run
`python3 progress.py`, which lists the checkpoints with their state and the command for the next one.

| Goal | Source |
| --- | --- |
| `prelab_quiz`, `postlab_quiz` | Correct answers in the first attempt of `quiz.py prelab` (10 questions) / `quiz.py postlab` (8) |
| `lab_minutes`, `dataset_min`, `results_min`, `training_min` | Minutes from opening the lab to its end, to the end of Steps 1-5, to all runs matching the reference; minutes of all trainings (`results/gradelab/*.txt`, one line per minute, written by `progress.py`) |
| `window_check` … `shape_check` | `check.py` stdout contains "`<stage> stage - 100 % of the rules pass`" |
| `baseline_match` | Steps 6–8: the run `global` matches the reference |
| `exp1_match` … `exp6_match` | Every run of the experiment matches the reference (Experiment 5: the three explanations) |
| `results_check` | `check.py --stage results`: all 23 runs of the lab sheet match the reference |
| `normalization_compared`, `features_compared`, `shape_compared` | `09_plot.py` stdout (one figure per experiment) |
| `address_swap_tested` | `07_infer.py` was run on the `test_newaddr` split |
| `classical_tested`, `classical_compared` | `14_classical.py` was run with `--bots`; `09_plot.py` drew the classical figure |
| `decisions_explained` | `15_explain.py` printed a permutation importance |
| `network_shift_tested`, `shift_compared` | `07_infer.py` tested a model trained on the CIC sample on the lab network; `09_plot.py` drew the shift figure |
| `incident_report`, `attacker1_blocked`, `attacker2_blocked` | `results/incident_report.txt` |
| `only_attackers_blocked` | Both attackers listed and exactly 2 addresses blocked (the client was not) |
| `incident_match` | Every expected result of the live test: both attackers blocked, the client not, recall 100 %, no false positives |
| `lab_finished` | The last script of the lab, `11_incident_report.py`, completed |
| `cw_all_passed` | `checkwork` only: all checkpoints passed (from the `prestop` output) |

The `*_match`, `incident_match` and `lab_finished` goals read `results/time_result.json`, which the lab
scripts write through `progress.py`:

| Entry | Written by |
| --- | --- |
| `lab_start` | `_bin/fixlocal.sh` (`progress.py --start`), once, when Labtainer creates the server container, i.e. when the student first opens the lab |
| `lab_finish`, `lab_minutes` | The first completion of `11_incident_report.py`, the last script of the lab. The end is triggered by the last script, not by `stoplab`, which may come much later |
| `checkpoints` | Each checkpoint: the first time it was passed (`passed`, `minutes` after `lab_start`), `attempts` and `last_score`. Written by `check.py`, `08_evaluate.py`, `09_plot.py`, `15_explain.py`, `11_incident_report.py`, `quiz.py` |
| `training`, `inference` | Start, end and seconds of every `06_train.py` and of every `07_infer.py` / `10_detect_block.py` run, with model and data |

Labtainer's report shows only `Y`/`N` and whole numbers: `progress.py` therefore also writes the four
times above as files of one line per minute, which `results.config` counts (`LINE_COUNT`). All times
(every checkpoint, every run) are collected separately:
`../tools/time_report.py <folder with the submissions> --out times.csv --runs runs.csv` reads
`results/time_result.json` and the quiz answers of every submitted archive and writes one row per
student (start, end, minutes per checkpoint, attempts, quiz scores, training and inference time).

`results/time_result.json` lies in the student's home directory and could be edited. `time_report.py`
therefore cross-checks it (`../tools/capture_check.py`) against what Labtainer records by itself: every
command typed in a lab terminal is captured in `.local/result/<program>.stdout.<start time>` with its
command line, its screen output and its end time, and `.local/.seed` is created when the lab is opened.
The columns `verified` (`yes` / `NO`) and `issues` show the result:

| Checked | Against the capture |
| --- | --- |
| `lab_start` | the creation of `.local/.seed` (within 2 minutes), not after the first command |
| every passed checkpoint | the end of a captured run of the script that passes it, with its success line on the screen (e.g. `window stage - 100 % of the rules pass`, `your run: OK`); its minutes |
| every training / inference run | one captured run of the same script that it starts just after and ends just before; its seconds; no completed captured run missing from the record |
| `lab_finish`, `lab_minutes` | the first completed `11_incident_report.py` run |
| quizzes | the graded first attempt has the score that the first completed quiz run showed on the screen; the number of attempts |

`lab_start_capture`, `lab_finish_capture` and `lab_minutes_capture` give the times from the capture
alone. A command not typed in a lab terminal (e.g. run from a script file) is not captured, so it is
reported as "not found in Labtainer's capture": a reason to look, not proof of editing. The capture
files are in the student's home directory too, so this makes editing much harder, not impossible.

The quizzes are also Labtainer quizzes: `quiz -l lucid-ddos -q prelab` on the VM asks the same questions
as a self-check, without saving the answers. To change a quiz, edit `config/<quiz>.quiz` and copy it to
`server/quiz/` (the static checks require both to be identical); only `TrueFalse` and `Preface` entries
exist in Labtainer's quiz format.

## labedit

The lab opens in labedit (File → Open Lab → `labs/lucid-ddos`):

- 4 containers and `LAB_LAN 172.30.0.0/24`; the container settings (user/password, terminals, X11,
  no external gateway, IP, add-hosts, number of CPUs) are read correctly.
- Pressing OK in the Results and Goals editors writes files identical to the ones in this folder.
- `config/start.config` and `config/parameter.config` are kept in the format labedit's "Save Lab"
  writes (no comments, labedit's field order), so saving in labedit produces no diff.
- **Rule:** values in `results.config` must not contain `:` – labedit splits fields on it.
- `config/about.txt` and `config/keywords.txt` are the lab description and keywords labedit asks
  for. The lab manual is `docs/lucid-ddos.pdf`; the imodule ships it with the lab.

## Developer checks and CI (plain Docker, see `../tools/` and `../.github/workflows/ci.yml`)

- `static_checks.py`: syntax, no secrets, no Turkish text, Labtainer layout, labedit rules, the
  assessment (checkpoints, prestop, quizzes), dataset, the student manual in `docs/`.
- `test_capture_check.py`: the cross-check of the progress record on a synthetic submission: an
  unchanged one passes, every kind of edit (times, runs, quiz answers, deleted files) is found.
- `lab_sheet.sh`: runs every command of the lab sheet on 1 CPU and requires all 23 runs to match
  the reference results (`check.py --stage results`), so CI shows whether another computer gets the
  same results (about 12 minutes). It also takes the pre-lab quiz and checks the progress record: every
  checkpoint of the lab sheet passed, every training and inference run timed.
- `check_lab.sh`: runs the whole pipeline on 1 CPU and checks the stage scores, determinism and the
  normalization ordering, classical rule, explanation and the reference results (11/11, about 9 minutes).
- `train_default_model.sh` + `postlab_live.sh`: the post-lab with plain Docker containers; checks that
  both attackers and only they are blocked, recall >= 90 %, FPR <= 5 %, the live detection timed, the
  incident checkpoint passed, the end of the lab recorded, and the post-lab quiz graded. The SSH
  hand-over of step 0 is exercised in Labtainer, not here.
- `build_labtainer_images.sh` + `smoke_labtainer_images.sh`: builds the four images the way Labtainer
  does and checks their contents; on `main` CI then publishes them with `publish_images.sh`.
