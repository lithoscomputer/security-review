#!/usr/bin/env python3
"""Update the support-file hashes the workflows verify before they run.

Each graph pins the SHA-256 of every file it executes or renders from. Editing
one of those files means updating its pin, or the run refuses to start. This
rewrites the pins from the files on disk.

The two workflows pin differently, on purpose. `security-review` is read-only,
so one check in `prepare` covers the whole run. `suggest-security-patches` lets
its generator write to the checkout, so every deterministic node re-checks the
files it executes, and the same pin appears once per node.

Usage:
  repin_support_files.py            report which pins are stale
  repin_support_files.py --write    rewrite the stale pins
"""

from __future__ import annotations

import hashlib
import re
import sys
from pathlib import Path
from typing import Dict, List, Sequence, Tuple


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]

# graph path -> the files it pins
GRAPHS: Tuple[Tuple[str, Tuple[str, ...]], ...] = (
    (
        ".fabro/workflows/security-review/security-review.fabro",
        (
            ".fabro/workflows/security-review/scripts/security_review.py",
            ".fabro/workflows/security-review/scripts/git_readonly.py",
            ".fabro/workflows/security-review/scripts/render_report.py",
            ".fabro/workflows/security-review/specs/report-spec.md",
            ".fabro/workflows/security-review/templates/report.html",
        ),
    ),
    (
        ".fabro/workflows/suggest-security-patches/suggest-security-patches.fabro",
        (
            ".fabro/workflows/suggest-security-patches/scripts/suggest_patches.py",
            ".fabro/workflows/suggest-security-patches/scripts/git_readonly.py",
            ".fabro/workflows/suggest-security-patches/specs/patch-spec.md",
        ),
    ),
)

# A pin is 64 hex characters, or a PIN_NAME placeholder in a graph that has
# never been pinned.
PIN = r"(?:[0-9a-f]{64}|PIN_[A-Z_]+)"


def repin(graph_relative: str, pinned: Sequence[str]) -> Tuple[str, List[str], int]:
    path = REPOSITORY_ROOT / graph_relative
    graph = path.read_text(encoding="utf-8")
    stale: List[str] = []
    for relative in pinned:
        actual = hashlib.sha256((REPOSITORY_ROOT / relative).read_bytes()).hexdigest()
        pattern = re.compile(re.escape(relative) + r" (" + PIN + r")")
        matches = pattern.findall(graph)
        if not matches:
            print(
                f"{relative} has no pin in {graph_relative}",
                file=sys.stderr,
            )
            return graph, stale, 2
        if any(found != actual for found in matches):
            stale.append(Path(relative).name)
            graph = pattern.sub(lambda _: f"{relative} {actual}", graph)
    return graph, stale, 0


def main(argv: Sequence[str]) -> int:
    write = "--write" in argv
    updated: Dict[str, str] = {}
    report: List[str] = []

    for graph_relative, pinned in GRAPHS:
        graph, stale, code = repin(graph_relative, pinned)
        if code != 0:
            return code
        if stale:
            updated[graph_relative] = graph
            report.append(f"{Path(graph_relative).name}: " + ", ".join(stale))

    if not report:
        print("every support-file pin is current")
        return 0
    if not write:
        for line in report:
            print("stale pins — " + line)
        print("run repin_support_files.py --write")
        return 1
    for graph_relative, graph in updated.items():
        (REPOSITORY_ROOT / graph_relative).write_text(graph, encoding="utf-8")
    for line in report:
        print("re-pinned — " + line)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
