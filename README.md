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

## Using the lab

Students, in a Labtainer VM: `labtainer lucid-ddos` (the images come from Docker Hub).

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
tools/check_lab.sh             # whole pipeline on 1 CPU: stage checks, determinism, normalization ordering
tools/train_default_model.sh   # model for the post-lab test
tools/postlab_live.sh          # post-lab: detection, blocking and report checks
tools/build_labtainer_images.sh   # the four Labtainer images, built as Labtainer builds them
tools/smoke_labtainer_images.sh   # checks their contents
tools/publish_images.sh <user>    # pushes them to Docker Hub (CI does this on main)
tools/build_lab_dataset.sh     # re-records the six sessions (about 20 minutes)
```

## Continuous integration

`.github/workflows/ci.yml` runs on every push and pull request: static checks, the lab pipeline,
the post-lab, and the Labtainer image build with content checks. On `main`, once everything passed,
it publishes the images to Docker Hub:

| Image | Used by |
| --- | --- |
| `berkaybbayramoglu/lucid-ddos.<container>.student:latest` | Labtainer (`REGISTRY berkaybbayramoglu` in `config/start.config`) |
| `berkaybbayramoglu/ddos_lab:<container>` | the same images in one repository |

Publishing needs the repository variable `DOCKERHUB_USERNAME` and the secret `DOCKERHUB_TOKEN`.
The tools use `docker --context default`.
