#!/usr/bin/env python3
"""Build the goal file for one suggest-security-patches run.

Takes a report directory and a finding id, and writes that finding as JSON on
standard output. It refuses anything the run itself would refuse later, so the
operator learns at the terminal rather than after a sandbox has started.

    python3 make_goal.py SECURITY-REVIEW-20260826-101500 F3 > finding.json
    fabro run --goal-file finding.json \\
      .fabro/workflows/suggest-security-patches/workflow.toml

Python 3.9-compatible. Standard library only.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence


FINDING_ID_PATTERN = re.compile(r"^F[0-9]{1,9}$")
RESULTS_NAME = "SECURITY-REVIEW-RESULTS.jsonl"

# Fabro renders the goal as a MiniJinja template, so a finding carrying any of
# these cannot be passed through unchanged. Editing the finding to remove them
# is not a workaround: it changes the evidence the patch is judged against and
# can break the exact snippet match the run needs to locate the code.
TEMPLATE_DELIMITERS = ("{{", "{%", "{#")

# The fields the workflow reads. Everything else in a report line is dropped,
# so the goal carries only what the run acts on.
CARRIED_FIELDS = (
    "id",
    "title",
    "file",
    "line",
    "snippet",
    "symbol",
    "impact",
    "description",
    "recommendation",
    "severity",
    "ruleId",
    "findingId",
    "occurrenceId",
)


class GoalError(RuntimeError):
    """Something the operator must fix before running."""


def resolve_results_path(target: str) -> Path:
    path = Path(target)
    if path.is_dir():
        candidate = path / RESULTS_NAME
        if not candidate.is_file():
            raise GoalError(f"{candidate} does not exist")
        return candidate
    if path.is_file():
        return path
    raise GoalError(f"{target} is neither a report directory nor a results file")


def load_findings(path: Path) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as error:
        raise GoalError(f"could not read {path}: {error}") from error
    for number, line in enumerate(text.splitlines(), start=1):
        line = line.strip()
        if not line:
            continue
        try:
            value = json.loads(line)
        except json.JSONDecodeError as error:
            raise GoalError(f"{path}:{number} is not valid JSON: {error}") from error
        if isinstance(value, dict):
            findings.append(value)
    if not findings:
        raise GoalError(f"{path} holds no findings")
    return findings


def select(findings: Sequence[Dict[str, Any]], identifier: str) -> Dict[str, Any]:
    if not FINDING_ID_PATTERN.match(identifier):
        raise GoalError(
            f"{identifier!r} is not a finding id — ids look like F1, and the id is "
            "the only report-derived value this workflow acts on"
        )
    for finding in findings:
        if finding.get("id") == identifier:
            return finding
    available = ", ".join(
        str(f.get("id")) for f in findings if isinstance(f.get("id"), str)
    )
    raise GoalError(f"{identifier} is not in the report. It holds: {available}")


def find_delimiter(finding: Dict[str, Any]) -> Optional[str]:
    for key, value in finding.items():
        if not isinstance(value, str):
            continue
        for delimiter in TEMPLATE_DELIMITERS:
            index = value.find(delimiter)
            if index >= 0:
                return (
                    f"field {key!r} contains the template delimiter "
                    f"{delimiter!r} at offset {index}"
                )
    return None


def build(finding: Dict[str, Any]) -> Dict[str, Any]:
    carried = {
        key: finding[key]
        for key in CARRIED_FIELDS
        if key in finding and finding[key] not in (None, "")
    }
    for required in ("id", "title", "file"):
        if required not in carried:
            raise GoalError(f"the finding has no {required!r}")
    if "snippet" not in carried and "symbol" not in carried:
        print(
            f"make_goal.py: warning: {carried['id']} carries neither a snippet nor "
            "a symbol, so the run can only confirm the file still exists — it "
            "cannot confirm the flagged code survived.",
            file=sys.stderr,
        )
    problem = find_delimiter(carried)
    if problem:
        raise GoalError(
            f"this finding cannot be passed to Fabro: {problem}. Fabro renders the "
            "goal as a template, and there is no escape that survives its double "
            "render. Do not edit the finding to remove it — that changes the "
            "evidence. Patch this one by hand, and follow fabro-sh/fabro for a "
            "render-free goal path."
        )
    return carried


def main(argv: Sequence[str]) -> int:
    parser = argparse.ArgumentParser(
        description="Build the goal file for one suggest-security-patches run."
    )
    parser.add_argument(
        "report",
        help="a SECURITY-REVIEW-<ts>/ directory, or a results .jsonl file",
    )
    parser.add_argument("finding", help="the finding id, for example F3")
    args = parser.parse_args(argv)

    try:
        findings = load_findings(resolve_results_path(args.report))
        goal = build(select(findings, args.finding))
    except GoalError as error:
        print(f"make_goal.py: {error}", file=sys.stderr)
        return 2

    print(json.dumps(goal, ensure_ascii=False, indent=2, sort_keys=True))
    print(
        f"make_goal.py: {goal['id']} ready. If its evidence quotes a live "
        "credential, rotate it and do not run with pull-request creation "
        "enabled — a draft pull request is not private.",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
