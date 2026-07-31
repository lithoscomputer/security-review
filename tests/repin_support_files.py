#!/usr/bin/env python3
"""Update the support-file hashes `prepare` verifies before a run.

`security-review.fabro` pins the SHA-256 of every file the workflow executes or
renders from. Editing one of those files means updating its pin, or `prepare`
refuses to start. This rewrites the pins from the files on disk.

Usage:
  repin_support_files.py            report which pins are stale
  repin_support_files.py --write    rewrite the stale pins
"""

from __future__ import annotations

import hashlib
import re
import sys
from pathlib import Path


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
GRAPH_PATH = (
    REPOSITORY_ROOT / ".fabro/workflows/security-review/security-review.fabro"
)
PINNED_PATHS = (
    ".fabro/workflows/security-review/scripts/security_review.py",
    ".fabro/workflows/security-review/scripts/git_readonly.py",
    ".fabro/workflows/security-review/scripts/render_report.py",
    ".fabro/workflows/security-review/specs/report-spec.md",
    ".fabro/workflows/security-review/templates/report.html",
)


def main(argv) -> int:
    graph = GRAPH_PATH.read_text(encoding="utf-8")
    stale = []
    for path in PINNED_PATHS:
        actual = hashlib.sha256(
            (REPOSITORY_ROOT / path).read_bytes()
        ).hexdigest()
        match = re.search(re.escape(path) + r" ([0-9a-f]{64})", graph)
        if match is None:
            print(f"{path} has no pin in the graph", file=sys.stderr)
            return 2
        if match.group(1) == actual:
            continue
        stale.append(Path(path).name)
        graph = graph[: match.start(1)] + actual + graph[match.end(1) :]

    if not stale:
        print("every support-file pin is current")
        return 0
    if "--write" not in argv:
        print("stale pins: " + ", ".join(stale))
        print("run repin_support_files.py --write")
        return 1
    GRAPH_PATH.write_text(graph, encoding="utf-8")
    print("re-pinned: " + ", ".join(stale))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
