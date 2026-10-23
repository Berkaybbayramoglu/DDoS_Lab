#!/usr/bin/env python3
"""Times and checkpoints of a whole class, from the students' submitted archives (instructor tool).

Every submission (<student>.lucid-ddos.lab, what stoplab writes to labtainer_xfer/lucid-ddos) holds the
progress record of the lab, results/time_result.json (server/progress.py), and the quiz answers. This
tool reads them all and writes one row per student:
  lab_start, lab_finish, lab_minutes     opening of the lab, completion of its last script
                                         (11_incident_report.py), minutes in between
  <checkpoint>_min                       minutes after lab_start when the checkpoint was first passed
                                         (empty: not passed); <checkpoint>_tries: attempts
  prelab_quiz, postlab_quiz              correct answers / questions in the first attempt
  training_*, inference_*                number of runs and total seconds
  verified, issues                       the record cross-checked against Labtainer's own capture of
                                         every command (capture_check.py): "yes", or "NO" with the
                                         problems found; lab_*_capture: the times from the capture alone
With --runs, every training and inference run (script, model, start, end, seconds) goes to a second CSV.
gradelab shows the same checkpoints as Y/N; Labtainer's report cannot show times, hence this tool.

usage:  python3 time_report.py ~/labtainer_xfer/lucid-ddos --out times.csv [--runs runs.csv]
"""
import argparse
import csv
import glob
import json
import os
import sys
import tempfile
import zipfile

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "lucid-ddos", "server"))
import progress  # noqa: E402

import capture_check  # noqa: E402


def server_files(archive):
    """results/time_result.json, the quiz files, Labtainer's captured runs and the creation time of the
    lab (.local/.seed) of the server container of one submission."""
    found, runs, seed = {}, [], None
    with zipfile.ZipFile(archive) as outer:
        inner = [n for n in outer.namelist() if n.endswith(".server.student.zip")]
        if not inner:
            return found, runs, seed
        with tempfile.TemporaryFile() as tmp:              # the server zip can be large: not in memory
            with outer.open(inner[0]) as src:
                while chunk := src.read(1 << 20):
                    tmp.write(chunk)
            tmp.seek(0)
            with zipfile.ZipFile(tmp) as z:
                for name in z.namelist():
                    base = name.split("/")[-1]
                    if name.endswith("results/" + base) and base in (
                            "time_result.json", "quiz_prelab.txt", "quiz_postlab.txt",
                            "quiz_prelab.json", "quiz_postlab.json"):
                        found[base] = z.read(name).decode(errors="replace")
                runs, offset = capture_check.read_captures(z)
                seed = capture_check.seed_time(z, offset)
    return found, runs, seed


def quiz_score(text):
    if text is None:
        return ""
    lines = [l for l in text.splitlines() if l.strip()]
    return f"{sum(l.endswith('- RIGHT') for l in lines)}/{len(lines)}"


def main():
    a = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    a.add_argument("folder", help="folder with the submissions (*.lab), e.g. ~/labtainer_xfer/lucid-ddos")
    a.add_argument("--out", default="times.csv")
    a.add_argument("--runs", help="also write every training and inference run to this CSV")
    args = a.parse_args()
    archives = sorted(glob.glob(os.path.join(args.folder, "*.lab")) + glob.glob(os.path.join(args.folder, "*.zip")))
    if not archives:
        sys.exit(f"no submissions (*.lab) in {args.folder}")
    head = ["student", "lab_start", "lab_finish", "lab_minutes", "prelab_quiz", "postlab_quiz",
            "checkpoints_passed"]
    for name in progress.NAMES:
        head += [f"{name}_min", f"{name}_tries"]
    head += ["training_runs", "training_seconds", "inference_runs", "inference_seconds",
             "verified", "lab_start_capture", "lab_finish_capture", "lab_minutes_capture", "issues"]
    rows, runs = [], []
    for path in archives:
        student = os.path.basename(path).split(".lucid-ddos")[0]
        try:
            files, captured, seed = server_files(path)
        except zipfile.BadZipFile:
            print(f"{student}: not a valid archive, skipped", file=sys.stderr)
            continue
        try:
            rec = json.loads(files["time_result.json"]) if "time_result.json" in files else {}
        except ValueError:
            rec = {}
            print(f"{student}: results/time_result.json is not valid JSON", file=sys.stderr)
        cps = rec.get("checkpoints", {})
        row = {"student": student, "lab_start": rec.get("lab_start", ""), "lab_finish": rec.get("lab_finish", ""),
               "lab_minutes": rec.get("lab_minutes", ""),
               "prelab_quiz": quiz_score(files.get("quiz_prelab.txt")),
               "postlab_quiz": quiz_score(files.get("quiz_postlab.txt")),
               "checkpoints_passed": f"{sum('passed' in cps.get(n, {}) for n in progress.NAMES)}/{len(progress.NAMES)}"}
        for name in progress.NAMES:
            cp = cps.get(name, {})
            row[f"{name}_min"] = cp.get("minutes", "") if "passed" in cp else ""
            row[f"{name}_tries"] = cp.get("attempts", "")
        for kind in ("training", "inference"):
            row[f"{kind}_runs"] = rec.get(f"{kind}_runs", "")
            row[f"{kind}_seconds"] = rec.get(f"{kind}_seconds", "")
            runs += [{"student": student, "kind": kind, **r} for r in rec.get(kind, [])]
        try:
            issues, derived = capture_check.check(rec, captured, seed, files)
        except (KeyError, ValueError, TypeError) as e:       # a damaged record
            issues, derived = [f"the record could not be read ({e.__class__.__name__}: {e})"], {}
        row.update({"lab_start_capture": "", "lab_finish_capture": "", "lab_minutes_capture": ""}, **derived)
        row["verified"] = "NO" if issues else "yes"
        row["issues"] = "; ".join(issues)
        if not rec:
            print(f"{student}: no results/time_result.json in the submission", file=sys.stderr)
        for i in issues:
            print(f"{student}: {i}", file=sys.stderr)
        rows.append(row)

    with open(args.out, "w", newline="") as fh:
        w = csv.DictWriter(fh, head)
        w.writeheader()
        w.writerows(rows)
    if args.runs:
        keys = ["student", "kind", "script", "model", "data", "split", "source", "train_on", "epochs", "samples",
                "live", "flows", "blocked", "start", "end", "seconds"]
        with open(args.runs, "w", newline="") as fh:
            w = csv.DictWriter(fh, keys, extrasaction="ignore")
            w.writeheader()
            w.writerows(runs)

    short = ["student", "lab_minutes", "lab_minutes_capture", "prelab_quiz", "postlab_quiz", "checkpoints_passed",
             "training_seconds", "verified"]
    widths = [max(len(str(r[k])) for r in rows + [dict(zip(short, short))]) for k in short]
    for r in [dict(zip(short, short))] + rows:
        print("  ".join(str(r[k]).ljust(wd) for k, wd in zip(short, widths)))
    print(f"-> {args.out} ({len(rows)} students)" + (f", {args.runs} ({len(runs)} runs)" if args.runs else ""))


if __name__ == "__main__":
    main()
