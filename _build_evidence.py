#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Extract sanitized evidence slices from the WW2 activity-claim agent logs.

Inputs  : $WW2_RUNS/{_agent16448.log, _run.log, _agent_live.log}  (default: runs/ww2app_pro)
Outputs : ./evidence/*.log, ./evidence/*.tsv

Sanitization rules (applied to every emitted line):
  - player nicknames inside [welcome:...]   -> [welcome:***]
  - process ids (pid=NNN, #NNN after pkg)   -> ***
  - every line naming the unrelated game package guopan.liuliu is dropped
  - packet-capture plumbing lines are dropped (tcpdump / grab / capture)
Nothing else is altered: activity ids, task ids, item ids, item names,
response codes and timestamps are emitted verbatim.
"""
import os
import re
import sys
from pathlib import Path

# point WW2_RUNS at the directory holding the raw agent logs
RUNS = Path(os.environ.get("WW2_RUNS", "runs/ww2app_pro"))
OUT = Path(__file__).resolve().parent / "evidence"

AGENT = RUNS / "_agent16448.log"
RUNLOG = RUNS / "_run.log"
LIVE = RUNS / "_agent_live.log"

NICK = re.compile(r"\[welcome:[^\]]*\]")
PID1 = re.compile(r"pid=[^\s|]+")
PID2 = re.compile(r"(running=[^\s#|]*)#[0-9]{2,}")
DROP = ("liuliu", "tcpdump", "grab(", "capture(")


def sanitize(line):
    if any(tok in line for tok in DROP):
        return None
    line = NICK.sub("[welcome:***]", line)
    line = PID1.sub("pid=***", line)
    line = PID2.sub(r"\1#***", line)
    return line.rstrip("\n")


def read_lines(path):
    with path.open("r", encoding="utf-8", errors="replace") as fh:
        for raw in fh:
            yield raw


def emit(rows, path):
    kept = [s for s in (sanitize(r) for r in rows) if s]
    path.write_text("\n".join(kept) + "\n", encoding="utf-8", newline="\n")
    print(f"{path.name}: {len(kept)} lines, {path.stat().st_size} bytes")


def day_slice(line, day):
    return line.startswith(day + " ")


def keep_kind(line, kinds):
    body = line[16:] if len(line) > 16 else line
    return any(k in body for k in kinds)


def main():
    OUT.mkdir(parents=True, exist_ok=True)

    # ---- 01: full day of successful claims (2026-10-19) -------------------
    kinds = ("HIT ", "poll#", "codes=", "plan=")
    rows = [ln for ln in read_lines(AGENT)
            if day_slice(ln, "10-19") and keep_kind(ln, kinds)]
    emit(rows, OUT / "01-before-fix-2026-10-19.log")

    # ---- 02: freeze boundary and aftermath (2026-10-21 09:50 -> end) ------
    kinds2 = ("poll#", "codes=", "HIT ", "plan=", "target", "\u76ee\u6807")
    rows = []
    for ln in read_lines(LIVE):
        if not day_slice(ln, "10-21"):
            continue
        hhmm = ln[6:11]
        if hhmm < "09:50":
            continue
        if keep_kind(ln, kinds2):
            rows.append(ln)
    emit(rows, OUT / "02-freeze-boundary-2026-10-21.log")

    # ---- 03: hourly aggregates -------------------------------------------
    # `codes=` lines are the authoritative per-round counter: for 2026-10-19
    # the sum of their hits= field (5055) matches the HIT row count exactly.
    # `poll#` lines are sparse summaries and are therefore not used here.
    out = ["# source\tday\thour\trounds\trsp_sum\thit_rows"]
    for tag, path in (("agent16448", AGENT), ("live", LIVE)):
        rounds, rsp, hitrows = {}, {}, {}
        for ln in read_lines(path):
            if len(ln) < 14 or ln[2:3] != "-" or ln[5:6] != " ":
                continue
            key = (ln[0:5], ln[6:8])
            if "codes=" in ln:
                rounds[key] = rounds.get(key, 0) + 1
                m = re.search(r"hits=(\d+)", ln)
                if m:
                    rsp[key] = rsp.get(key, 0) + int(m.group(1))
            elif "HIT " in ln:
                hitrows[key] = hitrows.get(key, 0) + 1
        for key in sorted(set(rounds) | set(hitrows)):
            out.append("\t".join([
                tag, key[0], key[1],
                str(rounds.get(key, 0)),
                str(rsp.get(key, 0)),
                str(hitrows.get(key, 0)),
            ]))
    p = OUT / "03-hourly-aggregate.tsv"
    p.write_text("\n".join(out) + "\n", encoding="utf-8", newline="\n")
    print(f"{p.name}: {len(out) - 1} rows, {p.stat().st_size} bytes")


if __name__ == "__main__":
    sys.exit(main())
