"""Pre-lab and post-lab quiz, answered in the server terminal so that the answers reach the instructor.

The questions are the lab's Labtainer quizzes (quiz/prelab.quiz, quiz/postlab.quiz, the same files as
config/*.quiz). They use the format of the Labtainer quiz module (github.com/CRADLEUM/Labtainer-quiz_module),
whose `quiz` command on the VM asks the same questions: Preface, TrueFalse, MultipleChoice (graded; the
student types the letter of one option) and Survey (not graded; an option or free text). A question with
a prerequisite is asked only when the student answered that question incorrectly. After each graded
answer the right answer is explained.

usage:  python3 quiz.py prelab        (before the lab)
        python3 quiz.py postlab       (after the post-incident report)
output: results/quiz_<name>.txt   your first attempt, one line per question (graded by Labtainer)
        results/quiz_<name>.json  every attempt with its answers and time
The quiz can be repeated to learn from it; the instructor sees the first attempt (and the number of
attempts).
"""
import argparse
import csv
import json
import os
import re
import signal
import sys
import termios
import textwrap

import progress

progress.require_captured()               # the graded first attempt must be recorded by Labtainer

HERE = os.path.dirname(os.path.abspath(__file__))
LETTERS = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"


def fill(text, **kw):
    """textwrap.fill that keeps "79 %" and "CIC-DDoS2019" on one line."""
    return textwrap.fill(text.replace(" %", "\0%"), break_on_hyphens=False, **kw).replace("\0%", " %")


def read_quiz(path):
    """Questions of a Labtainer .quiz file: a line that ends with ',' or '\\' continues on the next line."""
    items, quest = [], ""
    with open(path) as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if line.endswith("\\"):
                quest += line[:-1]
                continue
            quest += line
            if line.endswith(","):
                continue
            fields = [f.strip() for f in next(csv.reader([re.sub(r', *"', ',"', quest)]))]
            quest = ""
            kind, qid = fields[1].upper(), fields[0].lower()
            prereq = lambda f: f.lower() if f else None
            if kind == "PREFACE":
                items.append({"type": "preface", "text": fields[2]})
            elif kind == "TRUEFALSE" and len(fields) >= 6:
                items.append({"type": "tf", "id": qid, "question": fields[2], "answer": fields[3].upper(),
                              "right": fields[4], "wrong": fields[5], "prereq": prereq(fields[6]) if len(fields) > 6 else None})
            elif kind == "MULTIPLECHOICE" and len(fields) >= 9:      # the module requires at least two options
                options = fields[7:]
                if fields[3].upper() not in LETTERS[:len(options)]:
                    raise SystemExit(f"{path}: answer {fields[3]} of question {qid} is not one of its options")
                items.append({"type": "mc", "id": qid, "question": fields[2], "answer": fields[3].upper(),
                              "right": fields[4], "wrong": fields[5], "prereq": prereq(fields[6]), "options": options})
            elif kind == "SURVEY" and len(fields) >= 4:
                items.append({"type": "survey", "id": qid, "question": fields[2], "prereq": prereq(fields[3]),
                              "options": fields[4:]})
            else:
                raise SystemExit(f"{path}: question {qid}: unknown type {fields[1]!r} or not enough fields")
    return items


# The terminal settings at the start: read_answer() switches the echo off while reading, and Ctrl+C makes
# Labtainer's recorder end the quiz at once, so they are restored on Ctrl+C and on termination too.
TTY_START = termios.tcgetattr(0) if os.isatty(0) else None


def stop(signum, frame):
    if TTY_START is not None:
        termios.tcsetattr(0, termios.TCSADRAIN, TTY_START)
    print("\nquiz stopped: nothing was saved; run it again to answer it", flush=True)
    os._exit(1)


def read_answer():
    """One line from the keyboard, shown once. Labtainer runs the command on a terminal that echoes
    the input while the student's terminal echoes it too, so every answer would appear twice: the
    echo is switched off while reading and the answer is printed here instead."""
    tty = os.isatty(0)
    if tty:
        old = termios.tcgetattr(0)
        new = old[:]
        new[3] &= ~termios.ECHO
        termios.tcsetattr(0, termios.TCSADRAIN, new)
    try:
        line = sys.stdin.readline()
    finally:
        if tty:
            termios.tcsetattr(0, termios.TCSADRAIN, old)
    if not line:
        raise SystemExit("\nquiz stopped (no input); nothing was saved")
    print(line.strip())
    return line.strip()


def ask(question):
    while True:
        print(fill(question, initial_indent="Question: ", subsequent_indent="          ") + " (T/F)? ",
              end="", flush=True)
        a = read_answer().upper()
        if a in ("T", "TRUE", "F", "FALSE"):
            return a[0]
        print("Please answer T or F.")


def choose(question, options):
    """The letter of one option; a typing error is asked again (as in the quiz module)."""
    print(fill(question, initial_indent="Question: ", subsequent_indent="          "))
    for letter, option in zip(LETTERS, options):
        print(fill(option, initial_indent=f"  {letter}) ", subsequent_indent="     "))
    valid = LETTERS[:len(options)]
    while True:
        print(f"Your answer ({valid[0]}-{valid[-1]})? ", end="", flush=True)
        a = read_answer().upper()
        if len(a) == 1 and a in valid:
            return a
        print(f"Please type one letter, {valid[0]} to {valid[-1]}.")


def main():
    a = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    a.add_argument("quiz", choices=["prelab", "postlab"])
    args = a.parse_args()
    signal.signal(signal.SIGINT, stop)
    signal.signal(signal.SIGTERM, stop)
    items = read_quiz(os.path.join(HERE, "quiz", f"{args.quiz}.quiz"))
    t_start = progress.now()
    answers, wrong = [], set()
    for it in items:
        if it["type"] == "preface":
            print(fill(it["text"]) + "\n")
            continue
        if it["prereq"] and it["prereq"] not in wrong:       # Labtainer: skipped when the prerequisite was right
            continue
        if it["type"] == "survey":                           # not graded: one option, or free text
            if it["options"]:
                given = choose(it["question"], it["options"])
                text = it["options"][LETTERS.index(given)]
            else:
                print(fill(it["question"], initial_indent="Question: ", subsequent_indent="          ") + " ",
                      end="", flush=True)
                given, text = None, read_answer()
            print()
            answers.append({"id": it["id"], "type": "survey", "answer": given, "answer_text": text, "correct": None})
            continue
        if it["type"] == "mc":
            given = choose(it["question"], it["options"])
        else:
            given = ask(it["question"])
        ok = given == it["answer"]
        print(fill(("Correct. " if ok else "Incorrect. ") + (it["right"] if ok else it["wrong"])) + "\n")
        if not ok:
            wrong.add(it["id"])
        answers.append({"id": it["id"], "type": it["type"], "answer": given, "expected": it["answer"], "correct": ok,
                        **({"answer_text": it["options"][LETTERS.index(given)]} if it["type"] == "mc" else {})})
    graded = [x for x in answers if x["correct"] is not None]
    n_ok, total = sum(x["correct"] for x in graded), len(graded)
    print(f"{args.quiz} quiz - {n_ok} of {total} correct")

    res = os.path.join(HERE, "results")
    os.makedirs(res, exist_ok=True)
    log_path = os.path.join(res, f"quiz_{args.quiz}.json")
    try:
        with open(log_path) as fh:
            log = json.load(fh)
    except (OSError, ValueError):
        log = {"attempts": []}
    log["attempts"].append({"start": progress.stamp(t_start), "end": progress.stamp(progress.now()),
                            "correct": n_ok, "questions": total, "answers": answers})
    with open(log_path, "w") as fh:
        json.dump(log, fh, indent=1)
    first = os.path.join(res, f"quiz_{args.quiz}.txt")
    if not os.path.exists(first):                       # the graded first attempt
        with open(first, "w") as fh:
            for x in graded:
                fh.write(f"question {x['id']} answer {x['answer']} - {'RIGHT' if x['correct'] else 'WRONG'}\n")
    progress.checkpoint(f"{args.quiz}_quiz", True, score=int(round(100 * n_ok / max(total, 1))))
    attempts = len(log["attempts"])
    print(f"-> {os.path.relpath(log_path, HERE)}" + (" (first attempt, sent to the instructor)" if attempts == 1
                              else f" (attempt {attempts}; the instructor sees your first attempt)"))


if __name__ == "__main__":
    sys.exit(main())
