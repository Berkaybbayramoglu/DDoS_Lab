#!/usr/bin/env python3
"""Tests capture_check.py and time_report.py on a synthetic submission (no Docker; run by CI).

The submission is built in the format of a real one (a .lab archive holding the server container zip,
with Labtainer's capture files in .local/result, .local/.seed and the lab's results/ files, as found in
a submission of the Labtainer VM). An unchanged submission must pass; every kind of editing of the
progress record must be found, also when the student keeps the record self-consistent.
"""
import copy
import io
import json
import os
import subprocess
import sys
import tempfile
import zipfile
from datetime import datetime, timezone

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path[:0] = [HERE, os.path.join(HERE, "..", "lucid-ddos", "server")]
import capture_check  # noqa: E402
import progress  # noqa: E402
import time_report  # noqa: E402

T0 = datetime(2026, 10, 23, 8, 27, 8, tzinfo=timezone.utc).timestamp()   # the lab is opened
STUDENT = "student1_at_lab.test"


def stamp(t):
    return datetime.fromtimestamp(t, timezone.utc).strftime(capture_check.STAMP)


def iso(t):
    return capture_check.iso(t)


# (start, end, command, screen output) of the captured runs, seconds after T0
RUNS = [
    (40, 61, "python3 quiz.py prelab", "prelab quiz - 9 of 10 correct\n-> results/quiz_prelab.json"),
    (150, 160, "python3 check.py --stage window --dir work/01_window", "window stage - 100 % of the rules pass"),
    (300, 380, "python3 06_train.py --data work/05_shape_global_lucid --model models/global.pt",
     "36858 training samples (both networks), 10 epochs in 76.0 s -> models/global.pt"),
    (390, 393, "python3 07_infer.py --model models/global.pt --data work/05_shape_global_lucid --split test --out results/global.csv",
     "4551 test samples classified in 210.0 ms (46 us/sample) -> results/global.csv"),
    (400, 402, "python3 08_evaluate.py --pred results/global.csv --name global --group normalization --model models/global.pt",
     "your run: OK - matches the reference\nprogress: 1 of 23 runs of the lab sheet match the reference (4 %)"),
    (2600, 2770, "sudo python3 10_detect_block.py --model models/global.pt --iface eth0 --victim 172.30.0.10 --block --seconds 150 --out results/incident_live.csv",
     "3348 flows seen, 3346 classified as DDoS, 2 distinct attacker IP(s) blocked\n-> results/incident_live.csv"),
    (2780, 2782, "python3 11_incident_report.py --log results/incident_live.csv --victim 172.30.0.10 --attackers 172.30.0.66 172.30.0.67 --out results/incident_report.txt",
     "-> report written to results/incident_report.txt\n   -> 4 of 4 expected results reached (100 %)"),
]
ANSWERS = "".join(f"question {i} answer T - {'WRONG' if i == 8 else 'RIGHT'}\n" for i in range(1, 11))


def record():
    """The progress record the lab scripts write for RUNS."""
    rec = {"lab_start": iso(T0), "lab_finish": iso(T0 + 2782), "checkpoints": {
        "prelab_quiz": {"passed": iso(T0 + 61), "attempts": 1, "last_score": 90},
        "window": {"passed": iso(T0 + 160), "attempts": 1, "last_score": 100},
        "baseline": {"passed": iso(T0 + 402), "attempts": 1},
        "incident": {"passed": iso(T0 + 2782), "attempts": 1, "last_score": 100}},
        "training": [{"script": "06_train.py", "model": "models/global.pt", "start": iso(T0 + 302),
                      "end": iso(T0 + 379), "seconds": 77.0}],
        "inference": [{"script": "07_infer.py", "model": "models/global.pt", "start": iso(T0 + 391),
                       "end": iso(T0 + 393), "seconds": 2.0},
                      {"script": "10_detect_block.py", "model": "models/global.pt", "start": iso(T0 + 2615),
                       "end": iso(T0 + 2769), "seconds": 154.0}]}
    return consistent(rec)


def consistent(rec):
    """Minutes and totals recomputed, as the scripts (or a careful student) would."""
    st = capture_check.iso_time(rec["lab_start"])
    for cp in rec["checkpoints"].values():
        if "passed" in cp:
            cp["minutes"] = int(round((capture_check.iso_time(cp["passed"]) - st) / 60))
    for k in ("training", "inference"):
        rec[f"{k}_runs"] = len(rec[k])
        rec[f"{k}_seconds"] = round(sum(r["seconds"] for r in rec[k]), 1)
    if "lab_finish" in rec:
        rec["lab_minutes"] = int(round((capture_check.iso_time(rec["lab_finish"]) - st) / 60))
    return rec


def submission(folder, rec, answers=ANSWERS, drop=(), zip_offset=0):
    """Writes <folder>/<student>.lucid-ddos.lab; zip_offset: zip file times in another time zone."""
    def member(z, name, data, t):
        info = zipfile.ZipInfo(name, datetime.fromtimestamp(t + zip_offset, timezone.utc).timetuple()[:6])
        z.writestr(info, data)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        member(z, ".local/.seed", "seed", T0)
        for start, end, cmd, out in RUNS:
            prog = cmd.split()[2] if cmd.startswith("sudo ") else cmd.split()[1]
            if prog in drop:
                continue
            fin = f"PROGRAM:FINISH {stamp(T0 + end)}"
            member(z, f".local/result/{prog}.stdin.{stamp(T0 + start)}", f"PROGRAM_ARGUMENTS is {cmd}\n{fin}", T0 + end)
            member(z, f".local/result/{prog}.stdout.{stamp(T0 + start)}", f"{out}\n{fin}", T0 + end)
        member(z, ".local/result/prestop.stdout.20261023021818", "host clock", T0)
        if rec is not None:
            member(z, "results/time_result.json", rec if isinstance(rec, str) else progress._dump(rec), T0 + 2782)
        if answers is not None:
            member(z, "results/quiz_prelab.txt", answers, T0 + 61)
            member(z, "results/quiz_prelab.json", json.dumps({"attempts": [{"correct": 9}]}), T0 + 61)
    path = os.path.join(folder, f"{STUDENT}.lucid-ddos.lab")
    with zipfile.ZipFile(path, "w") as outer:
        outer.writestr(f"{STUDENT}.lucid-ddos=lucid-ddos.server.student.zip", buf.getvalue())
    return path


def issues_of(folder, **kw):
    files, runs, seed = time_report.server_files(submission(folder, **kw))
    try:
        rec = json.loads(files["time_result.json"]) if "time_result.json" in files else {}
    except ValueError:
        rec = {}
    return capture_check.check(rec, runs, seed, files)


def shifted(path, sec):
    """record() with one value moved by sec seconds; path: ("lab_start",), ("checkpoints", name, "passed"), ..."""
    rec = record()
    d = rec
    for k in path[:-1]:
        d = d[k]
    d[path[-1]] = iso(capture_check.iso_time(d[path[-1]]) + sec)
    return consistent(rec)


def main():
    cases = []
    r = record(); del r["training"][0]
    cases += [("unchanged", dict(rec=record()), None),
              ("zip times in another time zone", dict(rec=record(), zip_offset=-7 * 3600), None),
              ("lab opened 30 min earlier", dict(rec=shifted(("lab_start",), -1800)), "lab_start"),
              ("finished 10 min earlier", dict(rec=shifted(("lab_finish",), -600)), "lab_finish"),
              ("checkpoint 60 s earlier", dict(rec=shifted(("checkpoints", "window", "passed"), -60)), "checkpoint window"),
              ("training removed", dict(rec=consistent(r)), "missing from the record")]
    r = record(); r["training"].append(dict(r["training"][0], start=iso(T0 + 1000), end=iso(T0 + 1077)))
    cases.append(("training invented", dict(rec=consistent(r)), "not found in Labtainer's capture"))
    r = record(); r["training"][0]["seconds"] = 20.0
    cases.append(("training shortened", dict(rec=consistent(r)), "does not match its start and end"))
    r = record(); r["inference"][1]["end"] = iso(T0 + 2700); r["inference"][1]["seconds"] = 85.0
    cases.append(("live detection shortened", dict(rec=consistent(r)), "not found in Labtainer's capture"))
    r = record(); r["checkpoints"]["window"]["minutes"] = 0
    cases.append(("minutes edited", dict(rec=r), "minutes 0 do not match"))
    cases += [("quiz answer corrected", dict(rec=record(), answers=ANSWERS.replace("WRONG", "RIGHT")), "graded 10/10"),
              ("quiz file deleted", dict(rec=record(), answers=None), "quiz_prelab.txt is missing"),
              ("record deleted", dict(rec=None), "no results/time_result.json"),
              ("record damaged", dict(rec="{ not json"), "no results/time_result.json"),
              ("report capture removed", dict(rec=record(), drop=("11_incident_report.py",)), "11_incident_report")]
    failed = 0
    with tempfile.TemporaryDirectory() as tmp:
        for name, kw, expect in cases:
            issues, derived = issues_of(tmp, **kw)
            ok = not issues if expect is None else any(expect in i for i in issues)
            if expect is None:
                ok = ok and derived.get("lab_minutes_capture") == 46 and derived.get("lab_start_capture") == iso(T0)
            failed += not ok
            print(("PASS  " if ok else "FAIL  ") + name + ("" if ok else f"  -> {issues} {derived}"))
        # the command-line tool on a folder with one clean and one edited submission
        os.makedirs(os.path.join(tmp, "class"))
        submission(os.path.join(tmp, "class"), shifted(("lab_start",), -1800))
        out = os.path.join(tmp, "times.csv")
        p = subprocess.run([sys.executable, os.path.join(HERE, "time_report.py"), os.path.join(tmp, "class"), "--out", out],
                           capture_output=True, text=True)
        rows = list(__import__("csv").DictReader(open(out))) if p.returncode == 0 else []
        ok = len(rows) == 1 and rows[0]["verified"] == "NO" and "lab_start" in rows[0]["issues"]
        failed += not ok
        print(("PASS  " if ok else "FAIL  ") + "time_report.py marks an edited submission" + ("" if ok else f"  -> {p.stderr}"))
    print(f"\n{failed} test(s) failed" if failed else "\nall tests passed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
