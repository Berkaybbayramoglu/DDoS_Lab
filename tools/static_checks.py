#!/usr/bin/env python3
"""Fast checks of the repository (no Docker). Run by CI on every push; exit code 0 = all passed.

  syntax       every shell script parses (bash -n), every Python file compiles
  secrets      no private keys or access tokens are committed
  english      no Turkish characters in code, configuration or documentation
  labtainer    the lab follows Labtainer's layout: one folder and one Dockerfile per container in
               start.config, Dockerfiles based on a Labtainer image, executable _bin/fixlocal.sh
  labedit      results.config values contain no ':' (labedit splits fields on it), goals refer to
               existing results
  dataset      the lab dataset is a valid gzip file below GitHub's 100 MB limit
"""
import glob
import gzip
import os
import re
import subprocess
import sys

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
LAB = os.path.join(ROOT, "lucid-ddos")
failures = []


def check(name, ok, detail=""):
    print(("PASS  " if ok else "FAIL  ") + name + (f"  ({detail})" if detail and not ok else ""))
    if not ok:
        failures.append(name)


def files(*patterns):
    out = []
    for p in patterns:
        out += glob.glob(os.path.join(ROOT, "**", p), recursive=True)
    return sorted(f for f in out if "/.git/" not in f)


# syntax
bad = [f for f in files("*.sh") if subprocess.run(["bash", "-n", f], capture_output=True).returncode]
check("shell scripts parse", not bad, ", ".join(bad))
bad = []
for f in files("*.py"):
    try:
        compile(open(f).read(), f, "exec")
    except SyntaxError as e:
        bad.append(f"{f}: {e}")
check("python files compile", not bad, "; ".join(bad))

# secrets
text_files = [f for f in files("*") if os.path.isfile(f) and not f.endswith((".gz", ".pcap", ".png"))]
secret = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----|ghp_[A-Za-z0-9]{20,}|dckr_pat_[A-Za-z0-9_-]{10,}")
bad = [f for f in text_files if secret.search(open(f, errors="ignore").read())]
check("no private keys or tokens", not bad, ", ".join(bad))
check("no .ssh folders in the lab", not glob.glob(os.path.join(LAB, "*", ".ssh")))

# english
turkish = re.compile("[\u011f\u00fc\u015f\u0131\u00f6\u00e7\u011e\u00dc\u015e\u0130\u00d6\u00c7]")  # Turkish letters
bad = [f for f in text_files if turkish.search(open(f, errors="ignore").read())]
check("no Turkish text", not bad, ", ".join(os.path.relpath(f, ROOT) for f in bad))

# labtainer layout
start = open(os.path.join(LAB, "config", "start.config")).read()
containers = re.findall(r"^\s*CONTAINER\s+(\S+)", start, re.M)
check("start.config defines containers", bool(containers))
for c in containers:
    df = os.path.join(LAB, "dockerfiles", f"Dockerfile.lucid-ddos.{c}.student")
    check(f"{c}: folder, Dockerfile and executable _bin/fixlocal.sh",
          os.path.isdir(os.path.join(LAB, c)) and os.path.isfile(df)
          and os.access(os.path.join(LAB, c, "_bin", "fixlocal.sh"), os.X_OK))
    check(f"{c}: Dockerfile is based on a Labtainer image",
          os.path.isfile(df) and re.search(r"^FROM \$registry/labtainer\.", open(df).read(), re.M) is not None)
check("server scripts executable where run directly",
      os.access(os.path.join(LAB, "server", "13_launch_replay.sh"), os.X_OK))

# labedit
results = [l for l in open(os.path.join(LAB, "instr_config", "results.config")) if "=" in l and not l.startswith("#")]
bad = [l.split("=")[0].strip() for l in results if ":" in l.split(" : ")[-1]]
check("results.config values have no ':'", not bad, ", ".join(bad))
tags = {l.split("=")[0].strip() for l in results}
goals = [l for l in open(os.path.join(LAB, "instr_config", "goals.config")) if "=" in l and not l.startswith("#")]
used = set()
for g in goals:
    m = re.search(r"\(([^)]*)\)", g)
    if m:
        used |= {x.strip() for x in m.group(1).split(",")}
check("goals refer to existing results", used <= tags, ", ".join(sorted(used - tags)))

# dataset
for name in ("lab_traffic.pcap.gz", "cic_ddos2019_sample.pcap.gz"):
    pcap = os.path.join(LAB, "server", "home_tar", "data", name)
    ok = os.path.isfile(pcap)
    if ok:
        with gzip.open(pcap, "rb") as fh:
            ok = fh.read(4) in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d")
    check(f"dataset {name} is a gzip'ed classic pcap", ok)
    check(f"dataset {name} below 100 MB", os.path.isfile(pcap) and os.path.getsize(pcap) < 100 * 2**20)
check("dataset source and licence documented",
      all(os.path.isfile(os.path.join(LAB, "server", "home_tar", "data", f)) for f in ("README.txt", "LICENSE-lucid-ddos.txt")))

print(f"\n{len(failures)} check(s) failed" if failures else "\nall checks passed")
sys.exit(1 if failures else 0)
