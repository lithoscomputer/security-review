#!/usr/bin/env python3
"""Render `sample.html` from the workflow's own report template.

The example report is not hand-written. This program builds a canonical scan
bundle from `sample_report_data.py`, hands it to the workflow's deterministic
renderer, and copies the resulting HTML to `sample.html`. A change to the
template, the payload mapping, or the sample data therefore shows up in the
committed example, and a test fails when the two drift apart.

Usage:
  build_sample_report.py            print whether sample.html is current
  build_sample_report.py --write    rewrite sample.html
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import sys
import tempfile
from pathlib import Path
from typing import Any, Dict, List


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
WORKFLOW_ROOT = REPOSITORY_ROOT / ".fabro/workflows/security-review"
RENDERER_PATH = WORKFLOW_ROOT / "scripts/render_report.py"
SAMPLE_PATH = REPOSITORY_ROOT / "sample.html"

sys.path.insert(0, str(Path(__file__).resolve().parent))
import sample_report_data as SOURCE  # noqa: E402


def load_renderer():
    spec = importlib.util.spec_from_file_location(
        "sample_report_renderer",
        RENDERER_PATH,
    )
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def target_id() -> str:
    digest = hashlib.sha256(
        SOURCE.TARGET_IDENTITY_MATERIAL.encode("utf-8")
    ).hexdigest()
    return f"security-review-target/v1:sha256:{digest}"


def canonical_code(source: Dict[str, Any]) -> Dict[str, Any]:
    lines = source["lines"]
    first = lines[0]["number"]
    last = lines[-1]["number"]
    return {
        "language": source["language"],
        "label": "",  # replaced by build_finding, which knows the file
        "lines": [dict(line) for line in lines],
        "_range": (first, last),
    }


def build_finding(renderer, index: int, source: Dict[str, Any]) -> Dict[str, Any]:
    identity = renderer.expected_identity(
        {"ruleId": source["ruleId"], "identity": {"anchor": source["anchor"]}},
        target_id(),
        SOURCE.SCAN_ID,
        f"sample finding {index}",
    )
    code = canonical_code(source["code"])
    first, last = code.pop("_range")
    code["label"] = f"{source['file']}:{first}-{last}"
    return {
        "id": f"F{index}",
        **identity,
        "title": source["title"],
        "impact": source["impact"],
        "file": source["file"],
        "line": source["line"],
        "description": source["description"],
        "evidence": list(source["evidence"]),
        "exploit_scenarios": list(source["exploit_scenarios"]),
        "preconditions": list(source["preconditions"]),
        "category": source["ruleId"].split(".", 1)[0],
        "severity": source["severity"],
        "difficulty": source["difficulty"],
        "confidence": source["confidence"],
        "recommendations": list(source["recommendations"]),
        "cwe_id": source["cwe_id"],
        "snippet": source["snippet"],
        "symbol": source["symbol"],
        "duplicate_of": None,
        "duplicate_reasoning": "",
        "code": code,
    }


def build_ledger(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    ledger = []
    for rank, (finding, source) in enumerate(zip(findings, SOURCE.FINDINGS), 1):
        candidate = {
            key: value
            for key, value in finding.items()
            if key not in ("id", "code")
        }
        ledger.append(
            {
                "schemaVersion": 1,
                "rank": rank,
                "disposition": "reportable",
                "dispositionReason": "verified-panel-quorum",
                "displayId": finding["id"],
                "selectedForPanel": True,
                "withinCandidateBudget": True,
                "reports": source["reports"],
                "reporters": list(source["reporters"]),
                "candidate": candidate,
            }
        )
    return ledger


def build_votes(
    findings: List[Dict[str, Any]],
    ledger: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """Three lens votes per finding, unanimous only where confidence is high."""
    votes = []
    for finding, source, entry in zip(findings, SOURCE.FINDINGS, ledger):
        claim = {
            "file": finding["file"],
            "line": finding["line"],
            "category": finding["category"],
            "severityAsReported": finding["severity"],
            "title": finding["title"],
            "rationale": finding["description"],
            "evidenceAsCited": "\n".join(finding["evidence"]) or "(none)",
            "snippetAsQuoted": finding["snippet"] or "(none)",
            "symbol": finding["symbol"] or "(none)",
            "reports": entry["reports"],
        }
        confirmations = 3 if source["confidence"] == "high" else 2
        for position, lens in enumerate(("REACHABILITY", "IMPACT", "DEFENSES")):
            confirmed = position < confirmations
            votes.append(
                {
                    "schemaVersion": 1,
                    "voteId": (
                        f"panel:{finding['occurrenceId']}:{lens.lower()}"
                    ),
                    "findingId": finding["findingId"],
                    "occurrenceId": finding["occurrenceId"],
                    "candidateRank": entry["rank"],
                    "round": "panel",
                    "lens": lens,
                    "claim": claim,
                    "status": "completed",
                    "verdict": (
                        "TRUE_POSITIVE" if confirmed else "FALSE_POSITIVE"
                    ),
                    "reasoning": (
                        f"Confirmed from {finding['file']}:{finding['line']} "
                        f"under the {lens.lower()} lens."
                        if confirmed
                        else (
                            "The cited path is real but this lens found the "
                            "impact narrower than reported."
                        )
                    ),
                }
            )
    return votes


def build_coverage() -> Dict[str, Any]:
    return {
        "droppedComponents": [],
        "skippedComponents": [dict(item) for item in SOURCE.SKIPPED_COMPONENTS],
        "components": [dict(item) for item in SOURCE.COMPONENTS],
        "effort": SOURCE.REQUEST["effort"],
        "focus": SOURCE.REQUEST["focus"],
        "diffFiles": None,
        "diffLines": None,
        "diffSizeRejected": None,
        "scopeFiles": None,
        "scopeSizeRejected": None,
        "collapsed": None,
        "completenessCheckOutcome": "checked",
        "topLevelCount": 6,
        "topLevelRejected": None,
        "unaccountedTopLevelDirs": [],
        "inventoryRejected": [],
        "inventoryFallback": None,
        "emptyDiff": False,
        "emptyScope": False,
        "mode": SOURCE.REQUEST["mode"],
        "scope": None,
        "range": None,
        "researchersPerCell": SOURCE.RESEARCHERS_PER_CELL,
        "researchersDispatched": SOURCE.RESEARCHERS_DISPATCHED,
        "researchersReturned": SOURCE.RESEARCHERS_RETURNED,
        "prunedBuckets": [],
        "adversarialCasualties": [],
        "candidatesDroppedByCap": 0,
        "unverifiedByCap": 0,
        "invalidResearchResults": [],
        "rejectedFindingReports": [],
    }


def build_manifest(
    findings: List[Dict[str, Any]],
    ledger: List[Dict[str, Any]],
    votes: List[Dict[str, Any]],
) -> Dict[str, Any]:
    return {
        "schemaVersion": 1,
        "kind": "security-review.completed-scan",
        "scanId": SOURCE.SCAN_ID,
        "target": {
            "id": target_id(),
            "idSource": "git-origin",
            "scanRoot": "/workspace/acme-portal",
        },
        "startedAt": SOURCE.STARTED_AT,
        "completedAt": SOURCE.COMPLETED_AT,
        "workflow": {"name": "security-review", "stateVersion": 6},
        "request": dict(SOURCE.REQUEST),
        "revision": dict(SOURCE.REVISION),
        "completion": {
            "status": "complete",
            "reasons": [],
            "verificationStatus": "verified",
            "rawCandidateReports": sum(
                entry["reports"] for entry in ledger
            ),
            "uniqueCandidates": len(ledger),
            "dispositions": {"reportable": len(ledger)},
            "findings": len(findings),
            "panelVoteRecords": len(votes),
            "completedVoteRecords": len(votes),
            "missingVoteRecords": 0,
        },
        "canonicalFiles": [
            "scan-manifest.json",
            "candidate-ledger.jsonl",
            "findings.json",
            "coverage.json",
            "panel-votes.jsonl",
        ],
    }


def render_sample() -> str:
    renderer = load_renderer()
    findings = [
        build_finding(renderer, index, source)
        for index, source in enumerate(SOURCE.FINDINGS, 1)
    ]
    ledger = build_ledger(findings)
    votes = build_votes(findings, ledger)
    with tempfile.TemporaryDirectory() as directory:
        products = Path(directory)
        bundle = products / "evidence"
        metadata = products / "metadata"
        bundle.mkdir()
        metadata.mkdir()
        (bundle / "scan-manifest.json").write_text(
            json.dumps(build_manifest(findings, ledger, votes), indent=2) + "\n",
            encoding="utf-8",
        )
        (bundle / "findings.json").write_text(
            json.dumps(findings, indent=2) + "\n",
            encoding="utf-8",
        )
        (bundle / "coverage.json").write_text(
            json.dumps(build_coverage(), indent=2) + "\n",
            encoding="utf-8",
        )
        (bundle / "candidate-ledger.jsonl").write_text(
            "".join(json.dumps(entry) + "\n" for entry in ledger),
            encoding="utf-8",
        )
        (bundle / "panel-votes.jsonl").write_text(
            "".join(json.dumps(vote) + "\n" for vote in votes),
            encoding="utf-8",
        )
        renderer.render(str(bundle), str(products), str(metadata))
        return (products / renderer.HTML_REPORT_NAME).read_text(encoding="utf-8")


def main(argv) -> int:
    html = render_sample()
    if "--write" in argv:
        SAMPLE_PATH.write_text(html, encoding="utf-8")
        print(f"wrote {SAMPLE_PATH.relative_to(REPOSITORY_ROOT)}")
        return 0
    current = (
        SAMPLE_PATH.read_text(encoding="utf-8")
        if SAMPLE_PATH.is_file()
        else ""
    )
    if current == html:
        print("sample.html is current")
        return 0
    print("sample.html is stale; run build_sample_report.py --write")
    return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
