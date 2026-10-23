# DDoS_Lab

A [Labtainer](https://nps.edu/web/c3o/labtainers) lab that teaches DDoS detection with the LUCID
CNN (Doriguzzi-Corin et al., "LUCID: A Practical, Lightweight Deep Learning Solution for DDoS
Attack Detection", IEEE TNSM 2020), step by step, on one CPU.

Students go through the detection pipeline one script at a time – time windows, bidirectional flows,
normalization, feature selection, shaping, training, inference and evaluation – and compare the
results of their choices in figures with 95 % confidence intervals. Six experiments compare the
normalization (none, theoretical as in the paper, global, batchnorm), the feature set (shortcut
learning on IP addresses), the number of packets per sample, a classical threshold detector, an
explanation of the model's decisions (permutation importance) and training on another network.
In the post-lab, their own model watches a server live while two attackers and a benign client
replay held-out traffic; it detects and blocks the attackers, and the student writes a
post-incident report.

The dataset is the CIC-DDoS2019 sample that the LUCID authors publish with their code
([doriguzzi/lucid-ddos](https://github.com/doriguzzi/lucid-ddos), Apache-2.0; Sharafaldin et al.,
ICCST 2019) together with a recording of the lab network (benign users, SYN and HTTP floods), the
network the post-lab defends. Source, citation and licence: `lucid-ddos/server/home_tar/data/README.txt`.

The student manual is [`lucid-ddos/docs/lucid-ddos.pdf`](lucid-ddos/docs/lucid-ddos.pdf): theory,
setup, every command with its expected output, the experiments, the post-lab and the
post-incident report. Labtainer links to it when the lab starts.

## Repository layout

| Path | Content |
| --- | --- |
| `lucid-ddos/` | The Labtainer lab (config, Dockerfiles, container home directories, assessment). See [`lucid-ddos/README.md`](lucid-ddos/README.md) |
| `tools/` | Developer tools (plain Docker): dataset recording, end-to-end checks, copying the lab into a Labtainer VM |

## Requirements

| | Minimum | Tested with |
| --- | --- | --- |
| Processor | 64-bit x86 (Intel or AMD) with VT-x / AMD-V enabled; ARM computers (e.g. Apple M-series) cannot run the Labtainer VM directly | Intel Core i9-14900HX |
| VM | 2 cores, 4 GB RAM (the computer: 8 GB RAM) | whole lab: 4 cores, 4.7 GB; heaviest parts: 2 cores, 4 GB (peak 2.1 GB used) |
| Disk | 40 GB free: the Labtainer VM (6.3 GB download, about 30 GB in use) and this lab (about 3.5 GB) | |
| Network | once, to download the VM and the lab images (about 1 GB); the lab itself runs offline | |
| Software | VirtualBox (or VMware) with the [Labtainer VM](https://nps.edu/web/c3o/virtual-machine-images) | VirtualBox 7.2, Labtainer VM 24 |

## Using the lab

Students, in the `labtainer-student` terminal of a Labtainer VM:

```bash
imodule https://github.com/Berkaybbayramoglu/DDoS_Lab/releases/download/imodule/imodule.tar   # once
labtainer lucid-ddos           # the container images come from Docker Hub
```

Labtainer does not refresh images it has already downloaded. After a new version was published,
students get it with:

```bash
stoplab lucid-ddos
for c in server attacker1 attacker2 client; do docker pull berkaybbayramoglu/lucid-ddos.$c.student; done
labtainer -r lucid-ddos        # -r: start from fresh containers
```

Instructors put the submitted archives (`<student>.lucid-ddos.lab`) in `~/labtainer_xfer/lucid-ddos` and run,
in the `labtainer-instructor` terminal:

```bash
gradelab lucid-ddos            # one Y/N column per checkpoint of the lab, and the quiz scores
python3 tools/time_report.py ~/labtainer_xfer/lucid-ddos --out times.csv --runs runs.csv
                               # start and end of the lab, minutes to every checkpoint, training/inference time;
                               # 'verified' compares them with Labtainer's own record of every command
```

Lab developers, to work on the lab in a Labtainer VM:

```bash
tools/push_to_vm.sh            # copy lucid-ddos/ into the VM's labtainer/trunk/labs
# inside the VM:
cd $LABTAINER_DIR/scripts/labtainer-student && rebuild lucid-ddos
```

## Developer tools (plain Docker, also run by CI)

```bash
tools/static_checks.py         # syntax, secrets, English only, Labtainer layout, labedit rules, dataset
tools/build_images.sh          # developer images lucid-server, lucid-attacker, lucid-ethtool
tools/check_lab.sh             # whole pipeline on 1 CPU: stage checks, determinism, normalization, classical, explanation
tools/lab_sheet.sh             # every command of the manual on 1 CPU; all 23 runs must match the reference results
tools/train_default_model.sh   # model for the post-lab test
tools/postlab_live.sh          # post-lab: detection, blocking and report checks
tools/build_labtainer_images.sh   # the four Labtainer images, built as Labtainer builds them
tools/smoke_labtainer_images.sh   # checks their contents
tools/publish_images.sh <user>    # pushes them to Docker Hub (CI does this on main)
tools/time_report.py <folder>     # instructor: times, checkpoints and quiz scores of all submissions -> CSV,
                                  #   cross-checked against Labtainer's own capture (column verified)
tools/build_lab_dataset.sh     # downloads the CIC-DDoS2019 sample, re-records the lab network (about 20 minutes)
```

## Continuous integration

`.github/workflows/ci.yml` runs on every push and pull request: static checks, the lab pipeline,
the whole lab sheet against the reference results (and the CPU it ran on), the post-lab, and the
Labtainer image build with content checks. On `main`, once everything passed,
it publishes the images to Docker Hub:

| Image | Used by |
| --- | --- |
| `berkaybbayramoglu/lucid-ddos.<container>.student:latest` | Labtainer (`REGISTRY berkaybbayramoglu` in `config/start.config`) |
| `berkaybbayramoglu/ddos_lab:<container>` | the same images in one repository |

Like Labtainer's own `distrib/relabel.sh`, every published image carries the label
`base=labtainers/labtainer.network3.<id>` (a student's Labtainer refuses an image without it) and is
also tagged `:base_image<id>`. The id is the base image's config digest, read from Docker Hub by
`tools/base_image_id.py`, so it matches `docker images -q` on the Labtainer VM whatever Docker
version builds the images.

Publishing needs the repository variable `DOCKERHUB_USERNAME` and the secret `DOCKERHUB_TOKEN`.
The tools use `docker --context default`.
