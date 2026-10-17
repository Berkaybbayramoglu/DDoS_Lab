# DDoS_Lab

A [Labtainer](https://nps.edu/web/c3o/labtainers) lab that teaches DDoS detection with the LUCID
CNN (Doriguzzi-Corin et al., "LUCID: A Practical, Lightweight Deep Learning Solution for DDoS
Attack Detection", IEEE TNSM 2020), step by step, on one CPU.

Students go through the detection pipeline one script at a time – time windows, bidirectional flows,
normalization, feature selection, shaping, training, inference and evaluation – and compare the
results of their choices in figures with 95 % confidence intervals. In the post-lab, their own model
watches a server live while two attackers and a benign client replay held-out traffic; it detects
and blocks the attackers, and the student writes a post-incident report.

## Repository layout

| Path | Content |
| --- | --- |
| `lucid-ddos/` | The Labtainer lab (config, Dockerfiles, container home directories, assessment). See [`lucid-ddos/README.md`](lucid-ddos/README.md) |
| `tools/` | Developer tools (plain Docker): dataset recording, end-to-end checks, copying the lab into a Labtainer VM |

## Quick start (Labtainer VM)

```bash
tools/make_lab_key.sh          # once: lab-only SSH key for the post-lab replay (never committed)
tools/push_to_vm.sh            # copy lucid-ddos/ into the VM's labtainer/trunk/labs
# inside the VM:
cd $LABTAINER_DIR/scripts/labtainer-student && rebuild lucid-ddos
```

## Developer tools

```bash
tools/build_images.sh          # lucid-server, lucid-attacker, lucid-ethtool (plain Docker)
tools/make_lab_key.sh
tools/check_lab.sh             # whole pipeline on 1 CPU: stage checks, determinism, normalization ordering
tools/postlab_live.sh          # post-lab with plain Docker (needs a trained models/global_lucid.pt)
tools/build_lab_dataset.sh     # re-records the six sessions (about 20 minutes)
```

The tools use `docker --context default`.
