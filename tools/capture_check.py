"""Cross-checks a student's progress record against Labtainer's own capture of the lab (instructor tool).

results/time_result.json is written by the lab scripts (server/progress.py) into the student's home
directory, so a student could edit it. Labtainer itself independently records every command typed in a
lab terminal: for each run of a program it writes .local/result/<program>.stdin.<start> and
.local/result/<program>.stdout.<start>, where <start> is the start time (YYYYMMDDHHMMSS, the container
clock, the same clock as time_result.json), the stdin file begins with "PROGRAM_ARGUMENTS is <command>",
and both end with "PROGRAM:FINISH <end>". When the container is created, Labtainer writes .local/.seed,
so its file time in the archive is the opening of the lab.

check() compares the record with this evidence:
  lab start      lab_start within LAB_START_TOLERANCE of the creation of .local/.seed, and not after
                 the first captured command
  checkpoints    every passed checkpoint at the end of a captured run of the script that passes it
                 (within CHECKPOINT_GAP), with the expected success line in its output (e.g. "window stage - 100 % of
                 the rules pass"); its minutes consistent with lab_start
  runs           every recorded training/inference run matches a captured run of the same script (starts
                 within START_GAP after it, ends within END_GAP before it; one recorded run per captured
                 run), its seconds match its start and end, and no successful captured run is missing
  lab end        lab_finish inside the first captured 11_incident_report.py run that wrote the report
  quizzes        the graded first attempt (results/quiz_<name>.txt) has the score that Labtainer
                 captured on the screen of the first completed quiz run
  gradelab       the minute files gradelab counts (results/gradelab/*.txt) give the minutes of the
                 record, so lines added to them by hand are found
It returns the problems found and the times derived from the capture alone. Commands not typed in a lab
terminal (e.g. started from a script file) are not captured; they show up as "not found in Labtainer's
capture", which is a reason to look, not proof of tampering.
"""
import json
import os
import re
import statistics
import sys
from datetime import datetime, timezone

STAMP = "%Y%m%d%H%M%S"
CAPTURE = re.compile(r"(?:^|/)\.local/result/(.+)\.(stdin|stdout)\.(\d{14})$")
FINISH = re.compile(r"PROGRAM:FINISH (\d{14})")
ARGS = re.compile(r"PROGRAM_ARGUMENTS is (.*)")
SLACK = 2                     # seconds: both clocks are read with one-second resolution
# A script records its run right after it starts (Python imports first: 1-4 s measured in the VM) and
# right before it ends (0-1 s measured); a checkpoint is recorded near the end of the run that passes it.
START_GAP = 30                # seconds; not for sudo commands, which wait for the password first
END_GAP = 10
CHECKPOINT_GAP = 30
LAB_START_TOLERANCE = 120     # seconds between the creation of .local/.seed and fixlocal.sh
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "lucid-ddos", "server"))
import progress  # noqa: E402  (gradelab_minutes: the times gradelab shows)

SUCCESS = {"06_train.py": "training samples", "07_infer.py": "samples classified in",
           "10_detect_block.py": "flows seen"}


def stamp_time(s):
    return datetime.strptime(s, STAMP).replace(tzinfo=timezone.utc).timestamp()


def iso_time(s):
    return datetime.strptime(s, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc).timestamp()


def iso(t):
    return datetime.fromtimestamp(t, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def zip_time(info):
    """File time of a zip member, read as UTC (the clock offset is estimated separately)."""
    return datetime(*info.date_time, tzinfo=timezone.utc).timestamp()


def read_captures(z):
    """Captured runs of one server zip: {program, start, finish, args, out}, sorted by start; and
    the zip-time offset (zip time minus container time) estimated from the captured files."""
    parts, offsets = {}, []
    for info in z.infolist():
        m = CAPTURE.search(info.filename)
        if not m:
            continue
        prog, kind, start = m.groups()
        if prog == "prestop":             # written with the host clock, not the container clock
            continue
        text = z.read(info).decode(errors="replace")
        run = parts.setdefault((prog, start), {"program": prog, "start": stamp_time(start), "finish": None,
                                               "args": "", "out": ""})
        f = FINISH.search(text)
        if f:
            run["finish"] = stamp_time(f.group(1))
            offsets.append(zip_time(info) - run["finish"])   # a capture file is last written at the end
        if kind == "stdin":
            a = ARGS.search(text)
            run["args"] = a.group(1).strip() if a else ""
        else:
            run["out"] = text
    offset = round(statistics.median(offsets) / 900) * 900 if offsets else 0   # whole time zones
    return sorted(parts.values(), key=lambda r: r["start"]), offset


def seed_time(z, offset):
    for info in z.infolist():
        if info.filename.endswith(".local/.seed"):
            return zip_time(info) - offset
    return None


def during(t, run):
    return run["finish"] is not None and run["start"] - SLACK <= t <= run["finish"] + SLACK


def near_end(t, run, gap):
    return during(t, run) and run["finish"] - t <= gap + SLACK


def same_run(start, end, run):
    """A recorded run (start, end) is the captured run: starts just after it, ends just before it."""
    late_start = start - run["start"] <= START_GAP + SLACK or run["args"].startswith("sudo ")
    return during(start, run) and near_end(end, run, END_GAP) and late_start


def _arg(args, opt, value):
    return re.search(rf"{re.escape(opt)}[ =]['\"]?{re.escape(value)}\b", args) is not None


def evidence(name, run):
    """Does this captured run pass the checkpoint `name`?"""
    p, a, o = run["program"], run["args"], run["out"]
    if name in ("window", "flows", "normalize", "features", "shape"):
        return p == "check.py" and _arg(a, "--stage", name) and f"{name} stage - 100 % of the rules pass" in o
    if name == "results":
        return p == "check.py" and "results stage - 100 % of the reference runs match" in o
    if name == "baseline":
        return (p == "08_evaluate.py" and _arg(a, "--name", "global") and _arg(a, "--group", "normalization")
                and "your run: OK" in o)
    group = {"exp1_normalization": "normalization", "exp2_features": "features", "exp3_shape": "shape",
             "exp4_classical": "classical", "exp6_shift": "shift"}.get(name)
    if group:
        return p == "08_evaluate.py" and _arg(a, "--group", group) and "your run: OK" in o
    if name == "exp5_explain":
        return p == "15_explain.py" and "OK - matches the reference" in o
    if name == "figures":
        return p == "09_plot.py" and "-> results/plots/figure" in o
    if name == "incident":
        return p == "11_incident_report.py" and "4 of 4 expected results reached" in o
    if name in ("prelab_quiz", "postlab_quiz"):
        q = name.split("_")[0]
        return p == "quiz.py" and re.search(rf"\b{q}\b", a) is not None and f"{q} quiz - " in o
    raise ValueError(name)


def quiz_capture_score(run, q):
    m = re.search(rf"{q} quiz - (\d+) of (\d+) correct", run["out"])
    return (int(m.group(1)), int(m.group(2))) if m else None


def check(rec, runs, seed, quiz_files):
    """Problems of one submission (list of strings) and the times derived from the capture alone."""
    issues, derived = [], {}
    if not runs:
        return ["no Labtainer capture files (.local/result) in the submission"], derived
    first_cmd = min(r["start"] for r in runs)
    reports = [r for r in runs if r["program"] == "11_incident_report.py" and r["finish"] is not None
               and "report written to" in r["out"]]
    if seed is not None:
        derived["lab_start_capture"] = iso(seed)
    if reports:
        derived["lab_finish_capture"] = iso(reports[0]["finish"])
        if seed is not None:
            derived["lab_minutes_capture"] = int(round((reports[0]["finish"] - seed) / 60))
    if not rec:
        issues.append("no results/time_result.json although Labtainer captured the lab")
        return issues, derived

    # lab start
    start = None
    if "lab_start" not in rec:
        issues.append("lab_start missing")
    else:
        start = iso_time(rec["lab_start"])
        if seed is not None and abs(start - seed) > LAB_START_TOLERANCE:
            issues.append(f"lab_start {rec['lab_start']} differs from the creation of the lab ({iso(seed)})")
        if start > first_cmd + SLACK:
            issues.append(f"lab_start {rec['lab_start']} is after the first captured command ({iso(first_cmd)})")

    # checkpoints
    for name, cp in rec.get("checkpoints", {}).items():
        if "passed" not in cp:
            continue
        t = iso_time(cp["passed"])
        if not any(near_end(t, r, CHECKPOINT_GAP) and evidence(name, r) for r in runs):
            issues.append(f"checkpoint {name} passed at {cp['passed']}: no captured run that passes it at that time")
        if start is not None and cp.get("minutes") != int(round((t - start) / 60)):
            issues.append(f"checkpoint {name}: minutes {cp.get('minutes')} do not match its time")

    # training and inference runs: one recorded run inside one captured run, and none missing
    for kind, scripts in (("training", ("06_train.py",)), ("inference", ("07_infer.py", "10_detect_block.py"))):
        used = set()
        for entry in rec.get(kind, []):
            s, e = iso_time(entry["start"]), iso_time(entry["end"])
            match = [i for i, r in enumerate(runs) if i not in used and r["program"] == entry["script"]
                     and same_run(s, e, r)]
            if not match or entry["script"] not in scripts:
                issues.append(f"{kind} run {entry['script']} {entry['start']}: not found in Labtainer's capture")
                continue
            used.add(match[0])
            if abs(entry["seconds"] - (e - s)) > SLACK:
                issues.append(f"{kind} run {entry['script']} {entry['start']}: {entry['seconds']} s does not match "
                              f"its start and end ({e - s:.0f} s)")
        for script in scripts:
            done = [i for i, r in enumerate(runs) if r["program"] == script and r["finish"] is not None
                    and SUCCESS[script] in r["out"]]
            missing = [runs[i] for i in done if i not in used]
            if missing:
                issues.append(f"{len(missing)} completed {script} run(s) missing from the record "
                              f"(first at {iso(missing[0]['start'])})")
        for key in (f"{kind}_runs", f"{kind}_seconds"):
            if key in rec:
                want = len(rec.get(kind, [])) if key.endswith("_runs") else round(sum(r["seconds"] for r in rec.get(kind, [])), 1)
                if rec[key] != want:
                    issues.append(f"{key} {rec[key]} does not match the listed runs ({want})")

    # lab end: the first completed report
    if "lab_finish" in rec:
        t = iso_time(rec["lab_finish"])
        if not reports:
            issues.append(f"lab_finish {rec['lab_finish']}: Labtainer captured no completed 11_incident_report.py")
        elif not near_end(t, reports[0], END_GAP):
            issues.append(f"lab_finish {rec['lab_finish']} is not the first completed report ({iso(reports[0]['finish'])})")
        if start is not None and rec.get("lab_minutes") != int(round((t - start) / 60)):
            issues.append(f"lab_minutes {rec.get('lab_minutes')} do not match lab_start and lab_finish")
    elif reports:
        issues.append(f"lab_finish missing although the report was written at {iso(reports[0]['finish'])}")

    # the minutes gradelab shows (results/gradelab/*.txt, one line per minute) must be those of the record;
    # a submission without them (a lab version before them, or deleted) shows empty columns in gradelab
    has_gradelab = any(k.startswith("gradelab/") for k in quiz_files)
    for name, minutes in (progress.gradelab_minutes(rec).items() if has_gradelab else []):
        text = quiz_files.get(f"gradelab/{name}.txt")
        lines = None if text is None else len(text.splitlines())
        if lines != minutes:
            issues.append(f"gradelab {name}: {lines} line(s) in results/gradelab/{name}.txt, "
                          f"but the record gives {minutes} minute(s)")

    # quizzes: the graded first attempt against the first completed quiz run on the screen
    for q in ("prelab", "postlab"):
        text = quiz_files.get(f"quiz_{q}.txt")
        done = [r for r in runs if r["program"] == "quiz.py" and r["finish"] is not None and quiz_capture_score(r, q)]
        if text is None:
            if done:
                issues.append(f"{q} quiz taken at {iso(done[0]['start'])} but results/quiz_{q}.txt is missing")
            continue
        lines = [l for l in text.splitlines() if l.strip()]
        graded = (sum(l.endswith("- RIGHT") for l in lines), len(lines))
        if not done:
            issues.append(f"{q} quiz: results/quiz_{q}.txt exists but Labtainer captured no completed quiz")
        elif graded != quiz_capture_score(done[0], q):
            issues.append(f"{q} quiz: graded {graded[0]}/{graded[1]}, but the first captured attempt scored "
                          f"{'/'.join(map(str, quiz_capture_score(done[0], q)))}")
        log = quiz_files.get(f"quiz_{q}.json")
        if log is not None:
            try:
                n = len(json.loads(log)["attempts"])
            except (ValueError, KeyError, TypeError):
                n = None
            if n != len(done):
                issues.append(f"{q} quiz: {n} attempts in results/quiz_{q}.json, {len(done)} captured")
    return issues, derived
