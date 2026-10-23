"""Progress record of the lab: when each checkpoint was passed, and how long training and inference took.

The lab scripts write results/time_result.json while the student works (this module has no other
dependencies, so it is safe to import anywhere):
  lab_start      when the lab was first opened: _bin/fixlocal.sh runs `progress.py --start` once,
                 when Labtainer creates the server container
  checkpoints    every checkpoint of the lab sheet (CHECKPOINTS below): the first time it was passed,
                 minutes after lab_start, number of attempts and the last score
  training       start, end and duration of every 06_train.py run
  inference      start, end and duration of every 07_infer.py and 10_detect_block.py run
  lab_finish     the first time the last script of the lab, 11_incident_report.py, completed (not the
                 time the lab was stopped); lab_minutes = lab_finish - lab_start
The file goes to the instructor with the student's work (stoplab); tools/time_report.py collects
the files of a whole class into one table.

Students see their progress at any time:
  python3 progress.py
Writing the record never stops a lab script: if the file cannot be written, a warning is printed.
"""
import fcntl
import json
import os
import sys
import time
from datetime import datetime, timezone

HOME = os.path.dirname(os.path.abspath(__file__))
TIME_FILE = os.path.join(HOME, "results", "time_result.json")
LOCK_FILE = os.path.join(HOME, "results", ".time_result.lock")

# (id, what passes it, the command that checks it) in the order of the lab sheet
CHECKPOINTS = [
    ("prelab_quiz", "Pre-lab quiz answered", "python3 quiz.py prelab"),
    ("window", "Step 1 - time windows pass every rule of check.py", "python3 check.py --stage window --dir work/01_window"),
    ("flows", "Step 2 - flows, labels and splits pass every rule of check.py", "python3 check.py --stage flows --dir work/02_flows"),
    ("normalize", "Step 3 - normalization passes every rule of check.py", "python3 check.py --stage normalize --dir work/03_norm_global"),
    ("features", "Step 4 - feature selection passes every rule of check.py", "python3 check.py --stage features --dir work/04_feat_global_lucid"),
    ("shape", "Step 5 - shaping passes every rule of check.py", "python3 check.py --stage shape --dir work/05_shape_global_lucid"),
    ("baseline", "Steps 6-8 - the model 'global' trained, applied and evaluated with the expected result", "08_evaluate.py --name global --group normalization"),
    ("exp1_normalization", "Experiment 1 - all normalization runs match the reference", "08_evaluate.py --group normalization"),
    ("exp2_features", "Experiment 2 - all feature selection runs match the reference", "08_evaluate.py --group features"),
    ("exp3_shape", "Experiment 3 - all shaping runs match the reference", "08_evaluate.py --group shape"),
    ("exp4_classical", "Experiment 4 - all classical detection runs match the reference", "08_evaluate.py --group classical"),
    ("exp5_explain", "Experiment 5 - the three explanations match the reference", "15_explain.py"),
    ("exp6_shift", "Experiment 6 - all runs of training on another network match the reference", "08_evaluate.py --group shift"),
    ("results", "All runs of the lab sheet match the reference", "python3 check.py --stage results --dir results"),
    ("figures", "The five comparison figures were drawn", "python3 09_plot.py --groups normalization features shape classical shift"),
    ("incident", "Post-lab - live test: both attackers blocked, the client not, recall 100 %, no false positives", "11_incident_report.py"),
    ("postlab_quiz", "Post-lab quiz answered", "python3 quiz.py postlab"),
]
NAMES = [c[0] for c in CHECKPOINTS]
# the experiment checkpoints, by the --group of 08_evaluate.py
GROUP_CHECKPOINT = {"normalization": "exp1_normalization", "features": "exp2_features", "shape": "exp3_shape",
                    "classical": "exp4_classical", "shift": "exp6_shift"}


def now():
    return time.time()


def stamp(t):
    return datetime.fromtimestamp(t, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _dump(rec):
    """JSON with one line per checkpoint and per run (the grader's results.config reads single lines)."""
    out = ["{"]
    for key in ("lab_start", "lab_finish", "lab_minutes", "training_runs", "training_seconds",
                "inference_runs", "inference_seconds"):
        if key in rec:
            out.append(f" {json.dumps(key)}: {json.dumps(rec[key])},")
    cps = rec.get("checkpoints", {})
    out.append(' "checkpoints": {')
    items = [f"  {json.dumps(k)}: {json.dumps(cps[k])}" for k in NAMES if k in cps]
    out.append(",\n".join(items))
    out.append(" },")
    for i, key in enumerate(("training", "inference")):
        runs = rec.get(key, [])
        out.append(f" {json.dumps(key)}: [")
        out.append(",\n".join(f"  {json.dumps(r)}" for r in runs))
        out.append(" ]" + ("," if i == 0 else ""))
    out.append("}")
    return "\n".join(line for line in out if line) + "\n"


def _update(change):
    """Read, change and write the record under a lock; never raises."""
    try:
        os.makedirs(os.path.dirname(TIME_FILE), exist_ok=True)
        with open(LOCK_FILE, "a") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            rec = load()
            change(rec)
            for kind in ("training", "inference"):
                runs = rec.get(kind, [])
                rec[f"{kind}_runs"] = len(runs)
                rec[f"{kind}_seconds"] = round(sum(r["seconds"] for r in runs), 1)
            if "lab_start" in rec and "lab_finish" in rec:
                rec["lab_minutes"] = _minutes(rec, rec["lab_finish"])
            tmp = TIME_FILE + ".tmp"
            with open(tmp, "w") as fh:
                fh.write(_dump(rec))
            os.replace(tmp, TIME_FILE)
            _give_back(os.path.dirname(TIME_FILE), TIME_FILE, LOCK_FILE)
    except Exception as e:  # the record must never break a lab step
        print(f"(note: the progress record {TIME_FILE} could not be updated: {e})", file=sys.stderr)


def _give_back(*paths):
    """Scripts run with sudo (10_detect_block.py) must leave the files to the student."""
    uid, gid = os.environ.get("SUDO_UID"), os.environ.get("SUDO_GID")
    if os.geteuid() == 0 and uid and gid:
        for p in paths:
            os.chown(p, int(uid), int(gid))


def load():
    try:
        with open(TIME_FILE) as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return {}


def _parse(s):
    return datetime.strptime(s, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc).timestamp()


def _minutes(rec, when):
    return int(round((_parse(when) - _parse(rec["lab_start"])) / 60))


def lab_start():
    """Called once when the lab is first opened; a second call keeps the first time."""
    def change(rec):
        rec.setdefault("lab_start", stamp(now()))
    _update(change)


def checkpoint(name, passed, score=None, part=None, parts=None):
    """One attempt at a checkpoint; the first passing attempt fixes its time.

    A checkpoint made of several parts (the three explanations of Experiment 5, the five figures)
    is passed when all `parts` part names have passed at least once: part = (part name, passed).
    """
    assert name in NAMES, name

    def change(rec):
        cp = rec.setdefault("checkpoints", {}).setdefault(name, {})
        cp["attempts"] = cp.get("attempts", 0) + 1
        ok = passed
        if part is not None:
            done = set(cp.get("parts", []))
            if part[1]:
                done.add(part[0])
            cp["parts"] = sorted(done)
            ok = set(parts) <= done
            cp["last_score"] = int(round(100 * len(done & set(parts)) / len(parts)))
        elif score is not None:
            cp["last_score"] = score
        if ok and "passed" not in cp:
            cp["passed"] = stamp(now())
            if "lab_start" in rec:
                cp["minutes"] = _minutes(rec, cp["passed"])
        # keep the keys in a fixed order
        rec["checkpoints"][name] = {k: cp[k] for k in ("passed", "minutes", "attempts", "last_score", "parts") if k in cp}
    _update(change)


def lab_finish():
    """The last script of the lab completed: the first completion is the end of the lab."""
    def change(rec):
        rec.setdefault("lab_finish", stamp(now()))
    _update(change)


def run(kind, script, t0, **info):
    """A completed training or inference run that started at t0 (progress.now()) and ends now."""
    assert kind in ("training", "inference"), kind
    t1 = now()
    entry = {"script": script, **info, "start": stamp(t0), "end": stamp(t1), "seconds": round(t1 - t0, 1)}
    _update(lambda rec: rec.setdefault(kind, []).append(entry))


def show():
    rec = load()
    cps = rec.get("checkpoints", {})
    print(f"lab opened: {rec.get('lab_start', 'not recorded')}"
          + (f", finished: {rec['lab_finish']} ({rec['lab_minutes']} minutes)" if "lab_minutes" in rec else ""))
    rows, nxt = [], None
    for i, (name, what, how) in enumerate(CHECKPOINTS, 1):
        cp = cps.get(name, {})
        if "passed" in cp:
            state = "PASSED" + (f" after {cp['minutes']} min" if "minutes" in cp else "")
        else:
            state = "not passed yet" if cp.get("attempts") else "not started"
            nxt = nxt or (what, how)
        tries = f"{cp['attempts']}" if cp.get("attempts") else "-"
        rows.append((str(i), name, state, tries, what))
    widths = [max(len(r[c]) for r in rows + [("#", "checkpoint", "state", "tries", "")]) for c in range(4)]
    print("  ".join(h.ljust(w) for h, w in zip(("#", "checkpoint", "state", "tries"), widths)) + "  what passes it")
    for r in rows:
        print("  ".join(v.ljust(w) for v, w in zip(r, widths)) + "  " + r[4])
    done = sum("passed" in cps.get(n, {}) for n in NAMES)
    print(f"training: {rec.get('training_runs', 0)} runs, {rec.get('training_seconds', 0)} s; "
          f"inference: {rec.get('inference_runs', 0)} runs, {rec.get('inference_seconds', 0)} s")
    print(f"{done} of {len(NAMES)} checkpoints passed ({100 * done / len(NAMES):.0f} %)")
    if nxt:
        print(f"next: {nxt[0]}  ->  {nxt[1]}")
    print(f"all checkpoints passed - {'yes' if done == len(NAMES) else 'no'}")   # read by checkwork (prestop, no colon)


if __name__ == "__main__":
    if sys.argv[1:] == ["--start"]:
        lab_start()
    elif sys.argv[1:] in ([], ["--show"]):
        show()
    else:
        sys.exit("usage: python3 progress.py        (show your progress)")
