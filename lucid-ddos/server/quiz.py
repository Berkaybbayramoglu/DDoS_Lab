"""Pre-lab and post-lab quiz, answered in the server terminal so that the answers reach the instructor.

The questions are the lab's Labtainer quizzes (quiz/prelab.quiz, quiz/postlab.quiz, the same files as
config/*.quiz, which Labtainer's own `quiz` command shows on the VM without saving the answers).
Every question is True/False. After each answer the right answer is explained.

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
import sys
import termios
import textwrap

import progress

HERE = os.path.dirname(os.path.abspath(__file__))


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
            kind = fields[1].upper()
            if kind == "PREFACE":
                items.append({"type": "preface", "text": fields[2]})
            elif kind == "TRUEFALSE":
                items.append({"type": "tf", "id": fields[0], "question": fields[2], "answer": fields[3].upper(),
                              "right": fields[4], "wrong": fields[5], "prereq": fields[6].lower() if len(fields) > 6 and fields[6] else None})
            else:
                raise SystemExit(f"{path}: unknown question type {fields[1]!r} (only TrueFalse and Preface)")
    return items


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
        print(textwrap.fill(question, initial_indent="Question: ", subsequent_indent="          ") + " (T/F)? ",
              end="", flush=True)
        a = read_answer().upper()
        if a in ("T", "TRUE", "F", "FALSE"):
            return a[0]
        print("Please answer T or F.")


def main():
    a = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    a.add_argument("quiz", choices=["prelab", "postlab"])
    args = a.parse_args()
    items = read_quiz(os.path.join(HERE, "quiz", f"{args.quiz}.quiz"))
    t_start = progress.now()
    answers, wrong = [], set()
    for it in items:
        if it["type"] == "preface":
            print(textwrap.fill(it["text"]) + "\n")
            continue
        if it["prereq"] and it["prereq"] not in wrong:       # Labtainer: skipped when the prerequisite was right
            continue
        given = ask(it["question"])
        ok = given == it["answer"]
        print(textwrap.fill(("Correct. " if ok else "Incorrect. ") + (it["right"] if ok else it["wrong"])) + "\n")
        if not ok:
            wrong.add(it["id"])
        answers.append({"id": it["id"], "answer": given, "expected": it["answer"], "correct": ok})
    n_ok, total = sum(x["correct"] for x in answers), len(answers)
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
            for x in answers:
                fh.write(f"question {x['id']} answer {x['answer']} - {'RIGHT' if x['correct'] else 'WRONG'}\n")
    progress.checkpoint(f"{args.quiz}_quiz", True, score=int(round(100 * n_ok / max(total, 1))))
    attempts = len(log["attempts"])
    print(f"-> {os.path.relpath(log_path, HERE)}" + (" (first attempt, sent to the instructor)" if attempts == 1
                              else f" (attempt {attempts}; the instructor sees your first attempt)"))


if __name__ == "__main__":
    sys.exit(main())
