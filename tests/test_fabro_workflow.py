#!/usr/bin/env python3
"""Parity and transition tests for the Fabro security-review workflow."""

from __future__ import annotations

import contextlib
import hashlib
import importlib.util
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from argparse import Namespace
from pathlib import Path
from unittest import mock


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
WORKFLOW_ROOT = REPOSITORY_ROOT / ".fabro/workflows/security-review"
DRIVER_PATH = WORKFLOW_ROOT / "scripts/security_review.py"
GIT_WRAPPER_PATH = WORKFLOW_ROOT / "scripts/git_readonly.py"
RENDERER_PATH = WORKFLOW_ROOT / "scripts/render_report.py"
REPORT_SPEC_PATH = WORKFLOW_ROOT / "specs/report-spec.md"
TEMPLATE_PATH = WORKFLOW_ROOT / "templates/report.html"
GRAPH_PATH = WORKFLOW_ROOT / "security-review.fabro"


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


sys.dont_write_bytecode = True
DRIVER = load_module("fabro_security_review_driver", DRIVER_PATH)


def run(*args: str, cwd: Path) -> subprocess.CompletedProcess:
    return subprocess.run(
        args,
        cwd=cwd,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )


def html_payload(html: str) -> dict:
    """The report data an HTML page embeds for its own script."""
    match = re.search(
        r"window\.securityReportData = Object\.freeze\((\{.*?^\})\);",
        html,
        re.S | re.M,
    )
    assert match, "the HTML report embeds no report data"
    return json.loads(match.group(1))


def read_jsonl(path: Path) -> list[dict]:
    return [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line
    ]


class FabroWorkflowDriverTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        (self.root / "src").mkdir()
        (self.root / "src" / "app.py").write_text(
            "import os\n\n\ndef run(value):\n    os.system(value)\n",
            encoding="utf-8",
        )
        run("git", "init", "-q", cwd=self.root)
        run("git", "config", "user.email", "test@example.com", cwd=self.root)
        run("git", "config", "user.name", "Test", cwd=self.root)
        run("git", "add", "src/app.py", cwd=self.root)
        run("git", "commit", "-qm", "fixture", cwd=self.root)

        renderer = self.root / DRIVER.RENDERER_PATH
        renderer.parent.mkdir(parents=True)
        shutil.copy(
            RENDERER_PATH,
            renderer,
        )
        # The renderer reads its HTML template relative to its own location.
        template = renderer.parent.parent / "templates/report.html"
        template.parent.mkdir(parents=True)
        shutil.copy(TEMPLATE_PATH, template)
        self.previous_cwd = Path.cwd()
        os.chdir(self.root)

    def tearDown(self) -> None:
        os.chdir(self.previous_cwd)
        self.temporary.cleanup()

    def call(self, function, *args):
        with contextlib.redirect_stdout(io.StringIO()):
            return function(*args)

    def prepare(
        self,
        *,
        mode: str = "scan",
        effort: str = "max",
        scope: str = "",
        base: str = "",
        commit: str = "",
        revision_range: str = "",
        focus: str = "",
        scan_id: str = "test-scan-01",
    ) -> dict:
        self.call(
            DRIVER.prepare,
            Namespace(
                mode=mode,
                effort=effort,
                scope=scope,
                base=base,
                commit=commit,
                range=revision_range,
                focus=focus,
                scan_id=scan_id,
                scan_id_stdin=False,
            ),
        )
        return DRIVER.load_state()

    def save(self, state: dict) -> None:
        DRIVER.save_state(state)

    def parallel_results(self, phase: str, jobs: list[dict], values: list[object]):
        output_key = DRIVER.PHASE_OUTPUT_KEYS[phase]
        return [
            {
                "id": output_key.split(".", 1)[1],
                "index": index,
                "item_label": job["name"],
                "status": "succeeded",
                "context_updates": {output_key: value},
            }
            for index, (job, value) in enumerate(zip(jobs, values))
        ]

    def merge_success(
        self,
        phase: str,
        values: list[object],
    ) -> dict:
        state = DRIVER.load_state()
        jobs = state["phase_jobs"][phase]
        updates = DRIVER.merge_phase(
            state,
            phase,
            self.parallel_results(phase, jobs, values),
        )
        self.save(state)
        self.assertEqual(updates[f"{phase}_results_merged"], len(jobs))
        return DRIVER.load_state()

    @staticmethod
    def finding() -> dict:
        return {
            "file": "src/app.py",
            "line": 5,
            "ruleId": "command-injection.shell-command",
            "identity": {"anchor": "run-command-dispatch"},
            "category": "command-injection",
            "severity": "HIGH",
            "difficulty": "LOW",
            "confidence": "HIGH",
            "title": "Untrusted command reaches the shell",
            "rationale": "The caller supplies value and os.system executes it.",
            "evidence": "src/app.py:4-5",
            "snippet": "os.system(value)",
            "symbol": "run",
            "impact": "Arbitrary command execution.",
            "exploitScenarios": ["An attacker supplies a shell command."],
            "preconditions": [],
            "recommendations": ["Replace the shell call with a fixed argv."],
            "cweId": "CWE-78",
        }

    def dedup_findings(self, findings: list[dict]) -> dict:
        self.prepare(effort="low")
        self.call(DRIVER.plan_matrix)
        self.merge_success("research", [{"findings": findings}])
        self.call(DRIVER.dedup_rank)
        return DRIVER.load_state()

    def test_full_max_effort_transition_chain_uses_merged_outputs(self) -> None:
        state = self.prepare()
        inventory = {
            "components": [
                {
                    "name": "app",
                    "paths": ["src"],
                    "language": "Python",
                    "role": "command runner",
                    "internetFacing": True,
                }
            ],
            "securityScanSkippedComponents": [],
        }
        updates = DRIVER.merge_inventory(state, inventory)
        self.assertTrue(updates["inventory_done"])
        self.save(state)

        self.call(DRIVER.plan_matrix)
        state = DRIVER.load_state()
        threat_jobs = state["phase_jobs"]["threat"]
        self.assertEqual(len(threat_jobs), 1)
        self.merge_success(
            "threat",
            [
                {
                    "entryPoints": ["src/app.py:4"],
                    "sinks": ["src/app.py:5"],
                    "assumptions": [],
                    "trustBoundaries": ["src/app.py:4"],
                    "hotFiles": ["src/app.py"],
                }
            ],
        )
        self.call(DRIVER.zip_cells)

        state = DRIVER.load_state()
        research_jobs = state["phase_jobs"]["research"]
        sweep_jobs = state["phase_jobs"]["sweep"]
        self.assertEqual(len(research_jobs), 6)
        self.assertEqual(len(sweep_jobs), 2)
        finding = self.finding()
        self.merge_success(
            "research",
            [
                {"findings": [finding]} if index < 2 else {"findings": []}
                for index in range(len(research_jobs))
            ],
        )
        self.merge_success(
            "sweep",
            [{"findings": []} for _ in sweep_jobs],
        )
        self.call(DRIVER.dedup_rank)

        state = DRIVER.load_state()
        self.assertEqual(state["raw_candidate_count"], 2)
        self.assertEqual(len(state["deduplicated_candidates"]), 1)
        panel_jobs = state["phase_jobs"]["panel"]
        self.assertEqual(len(panel_jobs), 3)
        self.merge_success(
            "panel",
            [
                {
                    "verdict": verdict,
                    "reasoning": "src/app.py:4-5 confirms the path.",
                }
                for verdict in (
                    "TRUE_POSITIVE",
                    "TRUE_POSITIVE",
                    "FALSE_POSITIVE",
                )
            ],
        )
        self.call(DRIVER.tally)

        state = DRIVER.load_state()
        self.assertTrue(state["max_effort"])
        self.assertEqual(len(state["repanel_jobs"]), 3)
        self.assertNotIn("confidence", state["repanel_jobs"][0]["finding"])
        self.merge_success(
            "repanel",
            [
                {
                    "verdict": "TRUE_POSITIVE",
                    "reasoning": "src/app.py:4-5 confirms the path.",
                }
                for _ in state["repanel_jobs"]
            ],
        )
        self.call(DRIVER.adversarial_plan)

        state = DRIVER.load_state()
        self.assertEqual(len(state["redteam_jobs"]), 1)
        self.assertNotIn("confidence", state["redteam_jobs"][0]["finding"])
        self.merge_success(
            "redteam",
            [
                {
                    "verdict": "TRUE_POSITIVE",
                    "reasoning": "No defense exists at src/app.py:5.",
                }
            ],
        )
        self.call(DRIVER.final_tally)
        final = DRIVER.load_state()["final"]
        self.assertEqual(final["verification"]["status"], "verified")
        self.assertEqual([item["id"] for item in final["findings"]], ["F1"])
        self.assertEqual(final["votes"]["panel_votes"], 7)
        stable = final["findings"][0]
        self.assertRegex(stable["findingId"], r"^csf_[0-9a-f]{24}$")
        self.assertRegex(stable["occurrenceId"], r"^occ_[0-9a-f]{24}$")
        self.assertRegex(
            stable["fingerprints"]["primary"],
            r"^codex-security/v1:sha256:[0-9a-f]{64}$",
        )
        self.assertEqual(stable["ruleId"], finding["ruleId"])
        self.assertEqual(stable["identity"], finding["identity"])

        state = DRIVER.load_state()
        products = Path(state["products_dir"])
        evidence = Path(state["evidence_dir"])
        metadata = Path(state["metadata_dir"])
        manifest = json.loads(
            (evidence / "scan-manifest.json").read_text(encoding="utf-8")
        )
        ledger = read_jsonl(evidence / "candidate-ledger.jsonl")
        canonical_findings = json.loads(
            (evidence / "findings.json").read_text(encoding="utf-8")
        )
        coverage = json.loads(
            (evidence / "coverage.json").read_text(encoding="utf-8")
        )
        panel_votes = read_jsonl(evidence / "panel-votes.jsonl")
        self.assertEqual(manifest["schemaVersion"], 1)
        self.assertEqual(manifest["scanId"], "test-scan-01")
        self.assertEqual(manifest["workflow"]["stateVersion"], 6)
        self.assertEqual(manifest["completion"]["status"], "complete")
        self.assertEqual(
            manifest["completion"]["dispositions"],
            {"reportable": 1},
        )
        self.assertEqual(manifest["completion"]["rawCandidateReports"], 2)
        self.assertEqual(manifest["completion"]["uniqueCandidates"], 1)
        self.assertEqual(manifest["completion"]["panelVoteRecords"], 7)
        self.assertEqual(manifest["completion"]["completedVoteRecords"], 7)
        self.assertEqual(manifest["completion"]["missingVoteRecords"], 0)
        self.assertEqual(
            manifest["canonicalFiles"],
            list(DRIVER.CANONICAL_FILES),
        )
        self.assertEqual(len(ledger), 1)
        self.assertEqual(ledger[0]["disposition"], "reportable")
        self.assertEqual(ledger[0]["displayId"], "F1")
        self.assertEqual(ledger[0]["reports"], 2)
        self.assertEqual(canonical_findings, final["findings"])
        self.assertEqual(coverage, final["coverage"])
        self.assertEqual(len(panel_votes), 7)
        self.assertEqual(
            [vote["round"] for vote in panel_votes],
            ["panel", "panel", "panel", "repanel", "repanel", "repanel", "redteam"],
        )
        self.assertEqual(
            {vote["lens"] for vote in panel_votes[:3]},
            {"REACHABILITY", "IMPACT", "DEFENSES"},
        )
        for vote in panel_votes:
            self.assertEqual(vote["findingId"], stable["findingId"])
            self.assertEqual(vote["occurrenceId"], stable["occurrenceId"])
            self.assertTrue(
                vote["voteId"].startswith(
                    f"{vote['round']}:{stable['occurrenceId']}:"
                )
            )
            self.assertEqual(
                vote["claim"]["evidenceAsCited"],
                finding["evidence"],
            )
            self.assertEqual(vote["status"], "completed")

        self.call(DRIVER.render_report)
        state = DRIVER.load_state()
        self.assertTrue((products / "SECURITY-REVIEW-RESULTS.md").is_file())
        self.assertTrue((products / "SECURITY-REVIEW-RESULTS.jsonl").is_file())
        self.assertTrue(metadata.is_dir(), "run metadata must be retained")
        self.assertTrue(DRIVER.STATE_PATH.is_symlink())
        self.assertEqual(
            DRIVER.STATE_PATH.resolve(),
            (metadata / "state.json").resolve(),
        )
        markdown = (products / "SECURITY-REVIEW-RESULTS.md").read_text(
            encoding="utf-8"
        )
        self.assertIn(stable["findingId"], markdown)
        self.assertIn(stable["occurrenceId"], markdown)
        self.assertIn("7 dispatched verification votes", markdown)
        revision = json.loads(
            Path(state["revision_path"]).read_text(encoding="utf-8")
        )
        self.assertEqual(revision["verification"]["status"], "verified")
        self.assertEqual(
            revision["verification"]["completion_status"],
            "complete",
        )
        self.assertEqual(revision["findings"]["total"], 1)
        self.assertEqual(revision["scan_id"], "test-scan-01")
        self.assertEqual(revision["target_id"], state["target_id"])
        self.assertEqual(
            Path(state["revision_path"]).resolve(),
            (metadata / "revision.json").resolve(),
        )
        self.assertEqual(revision["products_dir"], state["products_rel"])
        self.assertEqual(
            revision["canonical_bundle"]["directory"],
            state["evidence_rel"],
        )
        output_finding = read_jsonl(
            products / "SECURITY-REVIEW-RESULTS.jsonl"
        )[0]
        self.assertEqual([output_finding], canonical_findings)
        self.assertEqual(output_finding["findingId"], stable["findingId"])
        self.assertEqual(output_finding["occurrenceId"], stable["occurrenceId"])
        self.assertEqual(
            {
                path.relative_to(products).as_posix()
                for path in products.rglob("*")
                if path.is_file()
            },
            {
                ".gitignore",
                "SECURITY-REVIEW-RESULTS.html",
                "SECURITY-REVIEW-RESULTS.jsonl",
                "SECURITY-REVIEW-RESULTS.md",
                "evidence/candidate-ledger.jsonl",
                "evidence/coverage.json",
                "evidence/findings.json",
                "evidence/panel-votes.jsonl",
                "evidence/scan-manifest.json",
                "metadata/revision.json",
                "metadata/scan-meta.json",
                "metadata/state.json",
            },
        )

        derived_paths = (
            products / "SECURITY-REVIEW-RESULTS.md",
            products / "SECURITY-REVIEW-RESULTS.jsonl",
            Path(state["revision_path"]),
        )
        derived_before = {
            path: path.read_bytes() for path in derived_paths
        }
        (metadata / "findings.json").write_text(
            json.dumps([{"id": "scratch-data-must-not-be-read"}]) + "\n",
            encoding="utf-8",
        )
        state["final"] = {"findings": [{"id": "state-is-not-a-report-input"}]}
        self.save(state)
        self.call(DRIVER.render_report)
        self.assertEqual(
            derived_before,
            {path: path.read_bytes() for path in derived_paths},
        )

    def test_merge_leaves_exhausted_native_retry_results_missing(self) -> None:
        self.prepare(effort="low")
        self.call(DRIVER.plan_matrix)
        state = DRIVER.load_state()
        jobs = state["phase_jobs"]["research"]
        self.assertEqual(len(jobs), 1)

        updates = DRIVER.merge_phase(state, "research", [])
        self.assertEqual(updates["research_results_merged"], 0)
        self.assertEqual(state["phase_results"]["research"], {})
        self.assertEqual(
            state["phase_jobs"]["research"][0]["job_id"],
            jobs[0]["job_id"],
        )

    def test_inventory_merge_defensively_handles_missing_direct_output(self) -> None:
        state = self.prepare(effort="high")
        updates = DRIVER.merge_inventory(state, None)
        self.assertTrue(updates["inventory_done"])
        self.assertEqual(state["inventory_fallback"], "inventory-failed")

    def test_inventory_agent_failure_falls_back_and_continues(self) -> None:
        self.prepare(effort="high")
        self.call(DRIVER.inventory_failed)
        state = DRIVER.load_state()
        self.assertEqual(state["inventory_fallback"], "inventory-failed")
        self.assertIsNone(state["components"])

        self.call(DRIVER.plan_matrix)
        state = DRIVER.load_state()
        self.assertEqual(
            [component["name"] for component in state["planned_components"]],
            ["repository"],
        )
        self.assertTrue(state["run_threat_models"])
        self.assertEqual(
            DRIVER.coverage_from_state(state)["inventoryFallback"],
            "inventory-failed",
        )

    def grow_repository(self, file_count: int) -> None:
        bulk = self.root / "bulk"
        bulk.mkdir()
        for index in range(file_count):
            (bulk / f"file{index}.py").write_text("x = 1\n", encoding="utf-8")
        run("git", "add", "bulk", cwd=self.root)
        run("git", "commit", "-qm", "bulk", cwd=self.root)

    def test_large_repository_focuses_on_the_attack_surface(self) -> None:
        self.grow_repository(DRIVER.LARGE_REPOSITORY_FILES + 1)
        state = self.prepare(effort="medium")
        self.assertEqual(state["focus"], "attack-surface")
        # The plugin couples the secrets pass to focus.
        self.assertTrue(state["secrets_sweep"])

    def test_small_repository_reads_the_whole_tree(self) -> None:
        state = self.prepare(effort="medium")
        self.assertIsNone(state["focus"])
        self.assertFalse(state["secrets_sweep"])

    def test_change_scans_are_never_focused(self) -> None:
        self.grow_repository(DRIVER.LARGE_REPOSITORY_FILES + 1)
        state = self.prepare(mode="changes", effort="medium", base="HEAD^")
        self.assertIsNone(state["focus"])

    def test_focus_can_be_requested_or_declined_explicitly(self) -> None:
        declined = self.prepare(effort="low", focus="none")
        self.assertIsNone(declined["focus"])
        shutil.rmtree(declined["products_dir"])

        requested = self.prepare(effort="low", focus="attack-surface")
        self.assertEqual(requested["focus"], "attack-surface")

    def test_top_level_directories_count_tracked_gitlinks(self) -> None:
        # A submodule lists as a tracked top-level path that is a directory
        # on disk; approximate one without submodule plumbing.
        (self.root / "vendored").write_text("placeholder\n", encoding="utf-8")
        run("git", "add", "vendored", cwd=self.root)
        run("git", "commit", "-qm", "add vendored", cwd=self.root)
        (self.root / "vendored").unlink()
        (self.root / "vendored").mkdir()

        self.assertEqual(DRIVER.top_level_directories(), ["src", "vendored"])

    def test_unknown_effort_tier_is_coerced_with_notice(self) -> None:
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            DRIVER.prepare(
                Namespace(
                    mode="scan",
                    effort="turbo",
                    scope="",
                    base="",
                    commit="",
                    range="",
                    focus="",
                    scan_id="test-scan-01",
                    scan_id_stdin=False,
                )
            )
        self.assertEqual(DRIVER.load_state()["effort"], "medium")
        self.assertIn(
            'unknown effort "turbo" -- using medium (tiers: low, medium, '
            "high, max)",
            buffer.getvalue(),
        )

    def test_inventory_correction_coaches_like_the_plugin(self) -> None:
        state = self.prepare(effort="high")
        inventory = {
            "components": [
                {
                    "name": f"component-{index}",
                    "paths": ["docs"],
                    "language": "Python",
                }
                for index in range(25)
            ],
            "securityScanSkippedComponents": [
                {"name": "everything-else", "paths": ["."], "reason": "rest"}
            ],
        }
        updates = DRIVER.merge_inventory(state, inventory)
        self.assertTrue(updates["inventory_correction"])
        feedback = updates["inventory_feedback"]
        self.assertIn(
            "YOUR PREVIOUS ANSWER WAS REJECTED and must be resubmitted "
            "COMPLETE:",
            feedback,
        )
        self.assertIn("A skip must NAME the directories it skips", feedback)
        self.assertIn(
            "<untrusted-directories>\nsrc\n</untrusted-directories>",
            feedback,
        )
        self.assertIn(
            "Only your first 24 components are used (you returned 25)",
            feedback,
        )
        self.assertIn("This is your one correction", feedback)
        self.assertIn("broad shared-parent paths", feedback)

    def test_verifiers_see_only_the_reported_claim(self) -> None:
        self.prepare(effort="low")
        self.call(DRIVER.plan_matrix)
        state = DRIVER.load_state()
        self.assertTrue(state["run_research"])
        self.merge_success("research", [{"findings": [self.finding()]}])
        self.call(DRIVER.dedup_rank)

        state = DRIVER.load_state()
        self.assertTrue(state["run_panel"])
        job = state["phase_jobs"]["panel"][0]
        self.assertEqual(job["candidate_id"], "F1")
        self.assertEqual(
            set(job["finding"]),
            {
                "file",
                "line",
                "category",
                "severityAsReported",
                "title",
                "rationale",
                "evidenceAsCited",
                "snippetAsQuoted",
                "symbol",
                "reports",
            },
        )
        self.assertEqual(job["finding"]["severityAsReported"], "HIGH")
        self.assertEqual(job["finding"]["reports"], 1)

    def test_stable_identity_survives_line_moves_and_scopes_occurrences(self) -> None:
        state = self.prepare(scan_id="scan-one")
        finding = DRIVER.normalize_finding(self.finding())
        self.assertIsNotNone(finding)
        assert finding is not None
        first = DRIVER.derive_finding_identity(
            state["target_id"],
            "scan-one",
            finding,
        )
        moved = dict(finding)
        moved["line"] = 500
        second = DRIVER.derive_finding_identity(
            state["target_id"],
            "scan-two",
            moved,
        )
        expected_fingerprint = (
            "codex-security/v1:sha256:"
            + hashlib.sha256(
                "\0".join(
                    [
                        "codex-security/v1",
                        state["target_id"],
                        finding["ruleId"],
                        finding["identity"]["anchor"],
                        "",
                    ]
                ).encode("utf-8")
            ).hexdigest()
        )

        self.assertEqual(first["findingId"], second["findingId"])
        self.assertEqual(first["fingerprints"], second["fingerprints"])
        self.assertNotEqual(first["occurrenceId"], second["occurrenceId"])
        self.assertEqual(
            first["fingerprints"]["primary"],
            expected_fingerprint,
        )
        self.assertEqual(
            first["findingId"],
            "csf_"
            + hashlib.sha256(expected_fingerprint.encode("utf-8")).hexdigest()[
                :24
            ],
        )

    def test_prepare_reads_fabro_run_id_from_stdin(self) -> None:
        input_stream = type(
            "InputStream",
            (),
            {"buffer": io.BytesIO(b"01KYSTABLERUNID1234567890\n")},
        )()
        with mock.patch.object(DRIVER.sys, "stdin", input_stream):
            scan_id = DRIVER.scan_id_from_args(
                Namespace(scan_id="", scan_id_stdin=True)
            )
        self.assertEqual(scan_id, "01KYSTABLERUNID1234567890")

        empty_stream = type(
            "InputStream",
            (),
            {"buffer": io.BytesIO(b"")},
        )()
        with mock.patch.object(DRIVER.sys, "stdin", empty_stream):
            with self.assertRaisesRegex(
                DRIVER.WorkflowDataError,
                "did not supply",
            ):
                DRIVER.scan_id_from_args(
                    Namespace(scan_id="", scan_id_stdin=True)
                )

    def test_sibling_instances_on_one_line_do_not_merge(self) -> None:
        first = self.finding()
        first["identity"] = {
            "anchor": "run-command-dispatch",
            "instance": "primary",
        }
        second = self.finding()
        second["title"] = "A second untrusted command reaches the shell"
        second["identity"] = {
            "anchor": "run-command-dispatch",
            "instance": "fallback",
        }

        state = self.dedup_findings([first, second])

        self.assertEqual(len(state["deduplicated_candidates"]), 2)
        self.assertEqual(
            len(
                {
                    item["findingId"]
                    for item in state["deduplicated_candidates"]
                }
            ),
            2,
        )

    def test_ambiguous_identity_across_root_controls_fails_closed(self) -> None:
        first = self.finding()
        second = self.finding()
        second["file"] = "src/other.py"
        second["symbol"] = "run_other"
        self.prepare(effort="low")
        self.call(DRIVER.plan_matrix)
        self.merge_success("research", [{"findings": [first, second]}])

        with self.assertRaisesRegex(
            DRIVER.WorkflowDataError,
            "ambiguous across root controls",
        ):
            self.call(DRIVER.dedup_rank)

    def test_invalid_identity_slugs_are_rejected(self) -> None:
        invalid_rule = self.finding()
        invalid_rule["ruleId"] = "Command Injection at line 5"
        self.assertIsNone(DRIVER.normalize_finding(invalid_rule))

        invalid_anchor = self.finding()
        invalid_anchor["identity"] = {"anchor": "src/app.py:5"}
        self.assertIsNone(DRIVER.normalize_finding(invalid_anchor))

        extra_field = self.finding()
        extra_field["identity"] = {
            "anchor": "run-command-dispatch",
            "line": "5",
        }
        self.assertIsNone(DRIVER.normalize_finding(extra_field))

    def test_target_identity_strips_remote_secrets_and_url_form(self) -> None:
        secret_remote = (
            "https://alice:password@example.com/org/repo.git"
            "?access_token=topsecret#fragment"
        )
        run("git", "remote", "add", "origin", secret_remote, cwd=self.root)
        state = self.prepare()
        scan_meta = json.loads(
            (
                Path(state["metadata_dir"]) / "scan-meta.json"
            ).read_text(encoding="utf-8")
        )
        persisted = json.dumps({"state": state, "scan_meta": scan_meta})
        for secret in ("alice", "password", "access_token", "topsecret"):
            self.assertNotIn(secret, persisted)
        self.assertEqual(state["target_id_source"], "git-origin")

        run(
            "git",
            "remote",
            "set-url",
            "origin",
            "git@example.com:org/repo.git",
            cwd=self.root,
        )
        equivalent_target, source = DRIVER.stable_target_identity()
        self.assertEqual(equivalent_target, state["target_id"])
        self.assertEqual(source, "git-origin")

    def test_renderer_rejects_tampered_stable_identity(self) -> None:
        state = self.dedup_findings([self.finding()])
        self.merge_success(
            "panel",
            [
                {
                    "verdict": "TRUE_POSITIVE",
                    "reasoning": "The source reaches the shell.",
                }
                for _ in state["phase_jobs"]["panel"]
            ],
        )
        self.call(DRIVER.tally)
        self.call(DRIVER.final_tally)
        state = DRIVER.load_state()
        findings_path = Path(state["evidence_dir"]) / "findings.json"
        findings = json.loads(findings_path.read_text(encoding="utf-8"))
        findings[0]["findingId"] = "csf_" + "0" * 24
        findings_path.write_text(
            json.dumps(findings) + "\n",
            encoding="utf-8",
        )
        with self.assertRaisesRegex(
            DRIVER.WorkflowDataError,
            "invalid derived findingId",
        ):
            self.call(DRIVER.render_report)

    def test_renderer_rejects_a_vote_claim_that_differs_from_the_ledger(
        self,
    ) -> None:
        state = self.dedup_findings([self.finding()])
        self.merge_success(
            "panel",
            [
                {
                    "verdict": "TRUE_POSITIVE",
                    "reasoning": "The source reaches the shell.",
                }
                for _ in state["phase_jobs"]["panel"]
            ],
        )
        self.call(DRIVER.tally)
        self.call(DRIVER.final_tally)
        evidence = Path(DRIVER.load_state()["evidence_dir"])
        votes_path = evidence / "panel-votes.jsonl"
        votes = read_jsonl(votes_path)
        votes[0]["claim"]["evidenceAsCited"] = "different evidence"
        votes_path.write_text(
            "".join(json.dumps(vote) + "\n" for vote in votes),
            encoding="utf-8",
        )

        with self.assertRaisesRegex(
            DRIVER.WorkflowDataError,
            "claim differs from the candidate evidence",
        ):
            self.call(DRIVER.render_report)

    def test_renderer_escapes_model_authored_markdown_and_html(self) -> None:
        finding = self.finding()
        finding["title"] = "Shell bug <script>alert(1)</script> [click](bad)"
        finding["evidence"] = (
            "src/app.py:5\n"
            "# injected heading\n"
            "- injected list\n"
            "1. injected number\n"
            "====\n"
            "    injected code"
        )
        state = self.dedup_findings([finding])
        self.merge_success(
            "panel",
            [
                {
                    "verdict": "TRUE_POSITIVE",
                    "reasoning": "The source reaches the shell.",
                }
                for _ in state["phase_jobs"]["panel"]
            ],
        )
        self.call(DRIVER.tally)
        self.call(DRIVER.final_tally)
        self.call(DRIVER.render_report)
        products = Path(DRIVER.load_state()["products_dir"])
        markdown = (products / "SECURITY-REVIEW-RESULTS.md").read_text(
            encoding="utf-8"
        )
        self.assertNotIn("<script>", markdown)
        self.assertIn("&lt;script&gt;", markdown)
        self.assertIn(r"\# injected heading", markdown)
        self.assertIn(r"\[click\](bad)", markdown)
        self.assertIn("<br>\n\\- injected list", markdown)
        self.assertIn("<br>\n1\\. injected number", markdown)
        self.assertIn("<br>\n\\====", markdown)
        self.assertIn("<br>\n&#32;&#32;&#32;&#32;injected code", markdown)

    def test_candidate_ledger_preserves_unique_candidates_beyond_budgets(
        self,
    ) -> None:
        self.prepare(effort="low")
        self.call(DRIVER.plan_matrix)
        findings = []
        for index in range(DRIVER.CANDIDATE_CAP + 1):
            finding = self.finding()
            finding["identity"] = {
                "anchor": "run-command-dispatch",
                "instance": f"candidate-{index + 1}",
            }
            finding["title"] = f"Candidate {index + 1}"
            findings.append(finding)
        findings.append(dict(findings[0]))
        self.merge_success("research", [{"findings": findings}])
        self.call(DRIVER.dedup_rank)
        state = DRIVER.load_state()
        self.assertEqual(
            state["raw_candidate_count"],
            DRIVER.CANDIDATE_CAP + 2,
        )
        self.assertEqual(
            len(state["deduplicated_candidates"]),
            DRIVER.CANDIDATE_CAP + 1,
        )
        self.assertEqual(
            len(state["phase_jobs"]["panel"]),
            DRIVER.VERIFICATION_CAP * 3,
        )

        self.call(DRIVER.tally)
        self.call(DRIVER.final_tally)
        state = DRIVER.load_state()
        products = Path(state["products_dir"])
        evidence = Path(state["evidence_dir"])
        ledger = read_jsonl(evidence / "candidate-ledger.jsonl")
        votes = read_jsonl(evidence / "panel-votes.jsonl")
        manifest = json.loads(
            (evidence / "scan-manifest.json").read_text(encoding="utf-8")
        )
        self.assertEqual(len(ledger), DRIVER.CANDIDATE_CAP + 1)
        self.assertEqual(
            [entry["disposition"] for entry in ledger[: DRIVER.VERIFICATION_CAP]],
            ["verification-incomplete"] * DRIVER.VERIFICATION_CAP,
        )
        self.assertTrue(
            all(
                entry["disposition"] == "deferred"
                and entry["dispositionReason"] == "verification-budget"
                for entry in ledger[
                    DRIVER.VERIFICATION_CAP : DRIVER.CANDIDATE_CAP
                ]
            )
        )
        self.assertEqual(ledger[-1]["disposition"], "deferred")
        self.assertEqual(
            ledger[-1]["dispositionReason"],
            "candidate-budget",
        )
        self.assertEqual(
            sum(entry["reports"] for entry in ledger),
            DRIVER.CANDIDATE_CAP + 2,
        )
        self.assertEqual(len(votes), DRIVER.VERIFICATION_CAP * 3)
        self.assertTrue(all(vote["status"] == "missing" for vote in votes))
        self.assertEqual(manifest["completion"]["status"], "partial")
        self.assertEqual(manifest["completion"]["completedVoteRecords"], 0)
        self.assertEqual(
            manifest["completion"]["missingVoteRecords"],
            DRIVER.VERIFICATION_CAP * 3,
        )
        self.assertTrue(
            any(
                "verification vote(s) did not complete" in reason
                for reason in manifest["completion"]["reasons"]
            )
        )
        self.assertEqual(
            manifest["completion"]["uniqueCandidates"],
            DRIVER.CANDIDATE_CAP + 1,
        )
        self.call(DRIVER.render_report)
        self.assertEqual(
            read_jsonl(products / "SECURITY-REVIEW-RESULTS.jsonl"),
            [],
        )

    def test_rejected_candidate_remains_in_the_canonical_ledger(self) -> None:
        state = self.dedup_findings([self.finding()])
        self.merge_success(
            "panel",
            [
                {
                    "verdict": "FALSE_POSITIVE",
                    "reasoning": "The cited value cannot reach the shell.",
                }
                for _ in state["phase_jobs"]["panel"]
            ],
        )
        self.call(DRIVER.tally)
        self.call(DRIVER.final_tally)
        state = DRIVER.load_state()
        products = Path(state["products_dir"])
        evidence = Path(state["evidence_dir"])
        ledger = read_jsonl(evidence / "candidate-ledger.jsonl")
        findings = json.loads(
            (evidence / "findings.json").read_text(encoding="utf-8")
        )
        manifest = json.loads(
            (evidence / "scan-manifest.json").read_text(encoding="utf-8")
        )
        self.assertEqual(len(ledger), 1)
        self.assertEqual(ledger[0]["disposition"], "rejected")
        self.assertEqual(ledger[0]["dispositionReason"], "panel-rejected")
        self.assertIsNone(ledger[0]["displayId"])
        self.assertEqual(findings, [])
        self.assertEqual(manifest["completion"]["status"], "complete")
        self.assertEqual(
            manifest["completion"]["dispositions"],
            {"rejected": 1},
        )
        self.call(DRIVER.render_report)
        self.assertEqual(
            read_jsonl(products / "SECURITY-REVIEW-RESULTS.jsonl"),
            [],
        )

    def test_parallel_job_context_is_an_array_not_a_file_reference(self) -> None:
        jobs = [{"name": "one", "job_id": "research:one"}]
        updates = DRIVER.phase_jobs_context({}, "research", jobs)
        self.assertEqual(updates["research_jobs"], jobs)
        self.assertIsInstance(updates["research_jobs"], list)

    def test_all_research_failure_is_unverified_and_never_clean(self) -> None:
        self.prepare(effort="low")
        self.call(DRIVER.plan_matrix)
        state = DRIVER.load_state()
        updates = DRIVER.merge_phase(state, "research", [])
        self.assertEqual(updates["research_results_merged"], 0)
        self.save(state)

        self.call(DRIVER.dedup_rank)
        self.call(DRIVER.tally)
        self.call(DRIVER.final_tally)
        final = DRIVER.load_state()["final"]
        self.assertEqual(final["findings"], [])
        self.assertEqual(final["verification"]["status"], "unverified")
        self.assertIn("none returned", final["verification"]["reason"])

    def test_empty_scope_creates_no_report_directory(self) -> None:
        state = self.prepare(effort="medium", scope="does-not-exist")
        self.assertTrue(state["empty_scope"])
        self.assertIsNone(state["products_dir"])
        self.assertEqual(list(self.root.glob("SECURITY-REVIEW-*")), [])

    def test_scoped_and_change_full_scans_still_inventory(self) -> None:
        scoped = self.prepare(effort="high", scope="src")
        self.assertTrue(scoped["use_inventory"])
        self.assertEqual(scoped["completeness"], "not-applicable")

        shutil.rmtree(scoped["products_dir"])
        (self.root / "src/app.py").write_text(
            "import os\n\n\ndef run(value):\n    os.system(value + ' changed')\n",
            encoding="utf-8",
        )
        run("git", "add", "src/app.py", cwd=self.root)
        run("git", "commit", "-qm", "change", cwd=self.root)
        changed = self.prepare(mode="changes", effort="high", base="HEAD^")
        self.assertTrue(changed["use_inventory"])
        self.assertEqual(changed["changed_files"], ["src/app.py"])
        self.assertRegex(changed["range"], r"^[0-9a-f]+\.\.HEAD$")

    def test_changes_scope_sizes_only_committed_files_in_scope(self) -> None:
        (self.root / "docs").mkdir()
        (self.root / "docs/readme.md").write_text("before\n", encoding="utf-8")
        run("git", "add", "docs/readme.md", cwd=self.root)
        run("git", "commit", "-qm", "add docs", cwd=self.root)
        (self.root / "src/app.py").write_text("changed source\n", encoding="utf-8")
        (self.root / "docs/readme.md").write_text("changed docs\n", encoding="utf-8")
        run("git", "add", "src/app.py", "docs/readme.md", cwd=self.root)
        run("git", "commit", "-qm", "two changes", cwd=self.root)
        (self.root / "src/app.py").write_text(
            "uncommitted work is not in the diff\n",
            encoding="utf-8",
        )

        state = self.prepare(
            mode="changes",
            effort="medium",
            base="HEAD^",
            scope="src",
        )
        self.assertEqual(state["diff_files"], 1)
        self.assertEqual(state["changed_files"], ["src/app.py"])
        self.assertEqual(state["collapsed"], "small-diff")

    def test_source_change_fails_closed_at_publication(self) -> None:
        self.prepare(effort="low")
        self.call(DRIVER.plan_matrix)
        (self.root / "src/app.py").write_text("changed\n", encoding="utf-8")
        # Intermediate steps proceed; the digest gates publication only.
        self.call(DRIVER.dedup_rank)
        self.call(DRIVER.tally)
        with self.assertRaisesRegex(DRIVER.WorkflowDataError, "source tree changed"):
            self.call(DRIVER.final_tally)

    def verified_bundle(self, findings: list[dict]) -> Path:
        state = self.dedup_findings(findings)
        self.merge_success(
            "panel",
            [
                {
                    "verdict": "TRUE_POSITIVE",
                    "reasoning": "The source reaches the shell.",
                }
                for _ in state["phase_jobs"]["panel"]
            ],
        )
        self.call(DRIVER.tally)
        self.call(DRIVER.final_tally)
        return Path(DRIVER.load_state()["products_dir"])

    def test_a_dropped_finding_is_recorded_rather_than_lost(self) -> None:
        # The failure this guards: a researcher reports real findings, every
        # one fails the contract, and the report says nothing was found.
        missing_difficulty = self.finding()
        del missing_difficulty["difficulty"]
        bad_rule = self.finding()
        bad_rule["identity"] = {"anchor": "second-control"}
        bad_rule["ruleId"] = "Command Injection"
        self.prepare(effort="low")
        self.call(DRIVER.plan_matrix)
        self.merge_success(
            "research",
            [{"findings": [self.finding(), missing_difficulty, bad_rule]}],
        )
        self.call(DRIVER.dedup_rank)
        state = DRIVER.load_state()
        self.assertEqual(len(state["deduplicated_candidates"]), 1)
        reports = DRIVER.rejected_finding_reports(state)
        self.assertEqual(len(reports), 2)
        self.assertTrue(
            any("difficulty is not LOW, MEDIUM, or HIGH" in r for r in reports),
            reports,
        )
        self.assertTrue(
            any("ruleId is not" in r for r in reports),
            reports,
        )
        # The reason names the researcher and the position, never the model's
        # own text.
        for report in reports:
            self.assertIn("repository:all", report)
            self.assertNotIn("os.system", report)

        self.merge_success(
            "panel",
            [
                {
                    "verdict": "TRUE_POSITIVE",
                    "reasoning": "The source reaches the shell.",
                }
                for _ in state["phase_jobs"]["panel"]
            ],
        )
        self.call(DRIVER.tally)
        self.call(DRIVER.final_tally)
        self.call(DRIVER.render_report)
        state = DRIVER.load_state()
        products = Path(state["products_dir"])
        evidence = Path(state["evidence_dir"])
        coverage = json.loads(
            (evidence / "coverage.json").read_text(encoding="utf-8")
        )
        self.assertEqual(len(coverage["rejectedFindingReports"]), 2)
        manifest = json.loads(
            (evidence / "scan-manifest.json").read_text(encoding="utf-8")
        )
        # A dropped finding is incomplete coverage, like an agent that never
        # returned, so the scan cannot call itself complete.
        self.assertEqual(manifest["completion"]["status"], "partial")
        self.assertTrue(
            any(
                "failed the finding contract" in reason
                for reason in manifest["completion"]["reasons"]
            ),
            manifest["completion"]["reasons"],
        )
        markdown = (products / "SECURITY-REVIEW-RESULTS.md").read_text(
            encoding="utf-8"
        )
        self.assertIn("Reported findings dropped for failing the contract: 2", markdown)
        self.assertIn("difficulty is not LOW, MEDIUM, or HIGH", markdown)

    def test_difficulty_is_required_and_keeps_the_easier_report(self) -> None:
        missing = self.finding()
        del missing["difficulty"]
        self.assertIsNone(DRIVER.normalize_finding(missing))
        unknown = self.finding()
        unknown["difficulty"] = "TRIVIAL"
        self.assertIsNone(DRIVER.normalize_finding(unknown))

        hard = self.finding()
        hard["difficulty"] = "HIGH"
        easy = self.finding()
        easy["difficulty"] = "MEDIUM"
        state = self.dedup_findings([hard, easy])
        candidates = state["deduplicated_candidates"]
        self.assertEqual(len(candidates), 1)
        self.assertEqual(candidates[0]["difficulty"], "MEDIUM")

    def test_excerpt_is_read_from_the_tree_not_from_the_agent(self) -> None:
        products = self.verified_bundle([self.finding()])
        evidence = products / "evidence"
        finding = json.loads(
            (evidence / "findings.json").read_text(encoding="utf-8")
        )[0]
        code = finding["code"]
        self.assertEqual(code["language"], "Python")
        self.assertEqual(code["label"], "src/app.py:1-5")
        self.assertEqual(
            [line["number"] for line in code["lines"]],
            [1, 2, 3, 4, 5],
        )
        highlighted = [line for line in code["lines"] if line.get("highlight")]
        self.assertEqual(len(highlighted), 1)
        self.assertEqual(highlighted[0]["number"], finding["line"])
        self.assertEqual(highlighted[0]["text"], "    os.system(value)")
        # The excerpt is presentation only: the judged candidate has none.
        ledger = read_jsonl(evidence / "candidate-ledger.jsonl")
        self.assertNotIn("code", ledger[0]["candidate"])

    def test_an_unconfirmed_quoted_line_yields_no_excerpt(self) -> None:
        moved = self.finding()
        moved["line"] = 1
        products = self.verified_bundle([moved])
        evidence = products / "evidence"
        finding = json.loads(
            (evidence / "findings.json").read_text(encoding="utf-8")
        )[0]
        self.assertEqual(finding["code"]["lines"], [])
        self.assertEqual(finding["code"]["label"], "src/app.py:1")

    def test_excerpt_text_is_reduced_to_displayable_characters(self) -> None:
        (self.root / "src/app.py").write_text(
            "import os\n\n\ndef run(value):\n"
            "    os.system(value)\t# ‮trailing\n",
            encoding="utf-8",
        )
        run("git", "add", "src/app.py", cwd=self.root)
        run("git", "commit", "-qm", "control characters", cwd=self.root)
        products = self.verified_bundle([self.finding()])
        evidence = products / "evidence"
        finding = json.loads(
            (evidence / "findings.json").read_text(encoding="utf-8")
        )[0]
        text = [
            line["text"]
            for line in finding["code"]["lines"]
            if line.get("highlight")
        ][0]
        self.assertNotIn("‮", text)
        self.assertNotIn("", text)
        self.assertNotIn("\t", text)
        self.assertIn("os.system(value)", text)
        # The renderer would refuse either character, so it must be gone.
        self.call(DRIVER.render_report)

    def test_html_report_carries_a_mapped_and_escaped_payload(self) -> None:
        finding = self.finding()
        finding["title"] = "Shell bug <script>alert(1)</script>"
        finding["recommendations"] = [
            "Use an argument array.",
            "Add a regression test.",
        ]
        finding["exploitScenarios"] = [
            "An attacker submits a shell command.",
            "The worker runs it.",
        ]
        products = self.verified_bundle([finding])
        self.call(DRIVER.render_report)
        html = (products / "SECURITY-REVIEW-RESULTS.html").read_text(
            encoding="utf-8"
        )
        self.assertNotIn("<script>alert(1)</script>", html)
        self.assertIn("\\u003cscript\\u003ealert(1)", html)
        self.assertNotIn("__REPORT_DATA__", html)

        payload = html_payload(html)
        self.assertEqual(payload["severityOrder"], ["High", "Medium", "Low"])
        self.assertEqual(payload["difficultyOrder"], ["Low", "Medium", "High"])
        self.assertEqual(payload["scan"]["modeLabel"], "Whole repository")
        entry = payload["findings"][0]
        self.assertEqual(entry["id"], "F-001")
        self.assertEqual(entry["severity"], "High")
        self.assertEqual(entry["difficulty"], "Low")
        self.assertEqual(entry["category"], "Data Validation")
        self.assertNotIn("target", entry)
        self.assertEqual(entry["verification"], "3/3 review lenses confirmed.")
        self.assertEqual(len(entry["exploitScenarios"]), 2)
        self.assertEqual(len(entry["recommendations"]), 2)
        # Every non-ASCII codepoint is escaped, so no separator can end a
        # JavaScript statement inside the data block.
        block = html.split("window.securityReportData", 1)[1].split(
            "</script>",
            1,
        )[0]
        self.assertFalse([character for character in block if ord(character) > 127])

    def test_evidence_is_a_citation_list_in_either_reported_shape(self) -> None:
        cited = self.finding()
        cited["evidence"] = [
            "src/app.py:4 reads value from the caller.",
            "src/app.py:5 passes it to os.system.",
        ]
        self.assertEqual(
            DRIVER.normalize_finding(cited)["evidence"],
            cited["evidence"],
        )
        # The retired single-blob shape still normalizes, so a researcher that
        # has not caught up does not lose its finding.
        legacy = self.finding()
        legacy["evidence"] = "src/app.py:4-5 one blob of proof"
        self.assertEqual(
            DRIVER.normalize_finding(legacy)["evidence"],
            ["src/app.py:4-5 one blob of proof"],
        )
        blank = self.finding()
        blank["evidence"] = ""
        self.assertEqual(DRIVER.normalize_finding(blank)["evidence"], [])

        products = self.verified_bundle([cited])
        self.call(DRIVER.render_report)
        html = (products / "SECURITY-REVIEW-RESULTS.html").read_text(
            encoding="utf-8"
        )
        entry = html_payload(html)["findings"][0]
        # The claim is the description; the citations are their own field, no
        # longer a second paragraph of it.
        self.assertEqual(entry["description"], [self.finding()["rationale"]])
        self.assertEqual(entry["evidence"], cited["evidence"])
        self.assertIn('element("details", { className: "finding-evidence" })', html)
        self.assertIn('createFindingBlock("Source code")', html)
        self.assertNotIn("Source evidence", html)
        markdown = (products / "SECURITY-REVIEW-RESULTS.md").read_text(
            encoding="utf-8"
        )
        self.assertIn(
            "**Evidence.**\n\n- src/app.py:4 reads value from the caller.\n"
            "- src/app.py:5 passes it to os.system.",
            markdown,
        )

    def test_code_spans_in_finding_text_become_code_nodes(self) -> None:
        finding = self.finding()
        finding["impact"] = "The `repo` path reaches `os.system` unquoted."
        finding["evidence"] = "src/app.py:5 passes `value` to the shell."
        finding["recommendations"] = ["Call `subprocess.run` with a list."]
        products = self.verified_bundle([finding])
        self.call(DRIVER.render_report)
        html = (products / "SECURITY-REVIEW-RESULTS.html").read_text(
            encoding="utf-8"
        )
        # The payload keeps the author's text verbatim; the page turns the
        # spans into nodes, so no markup is ever assembled from finding text.
        payload = html_payload(html)
        self.assertIn("`repo`", payload["findings"][0]["impact"])
        self.assertIn("inlineText", html)
        self.assertIn('fragment.append(element("code", { text: match[2] }))', html)
        for forbidden in ("innerHTML", "insertAdjacentHTML", "outerHTML"):
            self.assertNotIn(forbidden, html)

    def test_identity_names_the_repository_and_location_omits_the_line(
        self,
    ) -> None:
        products = self.verified_bundle([self.finding()])
        self.call(DRIVER.render_report)
        html = (products / "SECURITY-REVIEW-RESULTS.html").read_text(
            encoding="utf-8"
        )
        payload = html_payload(html)
        # The identity line names the repository; the full path stays in the
        # coverage facts.
        self.assertEqual(payload["scan"]["repository"], self.root.name)
        self.assertEqual(
            payload["scan"]["root"],
            str(self.root.resolve()),
        )
        self.assertIn('id="report-repository"', html)
        self.assertNotIn('id="report-target"', html)
        # A single examined component names every finding, so it is not shown.
        self.assertNotIn("target", payload["findings"][0])
        # The excerpt carries the line numbers, so the location need not. The
        # code frame still uses finding.line for its own header and fallback.
        self.assertIn('element("code", { text: finding.file })', html)
        self.assertNotIn("text: `${finding.file}:${finding.line}`", html)

    def test_a_component_is_named_only_when_it_localizes_a_finding(self) -> None:
        one = [{"name": "repository", "paths": ["."]}]
        many = [
            {"name": "Web application", "paths": ["app/routes"]},
            {"name": "Worker", "paths": ["src/reports"]},
        ]
        renderer = load_module("renderer_for_targets", RENDERER_PATH)
        # One component covers everything, so its name says nothing.
        self.assertIsNone(
            renderer.component_for_file("app/routes/a.ts", one)
        )
        self.assertEqual(
            renderer.component_for_file("app/routes/a.ts", many),
            "Web application",
        )
        self.assertEqual(
            renderer.component_for_file("src/reports/b.ts", many),
            "Worker",
        )
        # A whole-tree path among several components localizes nothing either.
        self.assertIsNone(
            renderer.component_for_file(
                "docs/x.md",
                [*many, {"name": "Everything", "paths": ["."]}],
            )
        )
        for scan_root, expected in (
            ("/home/daytona/repos/fabro-sh/quarry", "quarry"),
            ("/workspace/acme-portal/", "acme-portal"),
            ("quarry", "quarry"),
            ("/", "repository"),
        ):
            self.assertEqual(renderer.repository_name(scan_root), expected)

    def test_markdown_lists_the_exploit_steps_and_recommendations(self) -> None:
        finding = self.finding()
        finding["exploitScenarios"] = ["First step.", "Second step."]
        finding["recommendations"] = ["Root fix.", "Hardening.", "Regression."]
        products = self.verified_bundle([finding])
        self.call(DRIVER.render_report)
        markdown = (products / "SECURITY-REVIEW-RESULTS.md").read_text(
            encoding="utf-8"
        )
        self.assertIn("(HIGH, difficulty LOW, confidence high)", markdown)
        self.assertIn("**Exploit scenario.**\n\n1. First step.\n2. Second step.", markdown)
        self.assertIn(
            "**Fix.**\n\n1. Root fix.\n2. Hardening.\n3. Regression.",
            markdown,
        )

    def test_renderer_rejects_confidence_a_split_panel_did_not_earn(
        self,
    ) -> None:
        state = self.dedup_findings([self.finding()])
        # A 2-of-3 keep earns medium confidence at most.
        self.merge_success(
            "panel",
            [
                {
                    "verdict": verdict,
                    "reasoning": "The source reaches the shell."
                    if verdict == "TRUE_POSITIVE"
                    else "This lens found a guard.",
                }
                for verdict in (
                    "TRUE_POSITIVE",
                    "TRUE_POSITIVE",
                    "FALSE_POSITIVE",
                )
            ],
        )
        self.call(DRIVER.tally)
        self.call(DRIVER.final_tally)
        evidence = Path(DRIVER.load_state()["evidence_dir"])
        findings_path = evidence / "findings.json"
        findings = json.loads(findings_path.read_text(encoding="utf-8"))
        # The engine already capped it. Prove the renderer independently
        # refuses a bundle edited afterwards to claim more -- consistently, so
        # the ledger-equality check cannot be what catches it.
        self.assertEqual(findings[0]["confidence"], "medium")
        findings[0]["confidence"] = "high"
        findings_path.write_text(json.dumps(findings) + "\n", encoding="utf-8")
        ledger_path = evidence / "candidate-ledger.jsonl"
        ledger = read_jsonl(ledger_path)
        ledger[0]["candidate"]["confidence"] = "high"
        ledger_path.write_text(
            "".join(json.dumps(entry) + "\n" for entry in ledger),
            encoding="utf-8",
        )
        with self.assertRaisesRegex(
            DRIVER.WorkflowDataError,
            "which earns at most medium",
        ):
            self.call(DRIVER.render_report)

    def test_renderer_rejects_an_excerpt_that_highlights_another_line(
        self,
    ) -> None:
        products = self.verified_bundle([self.finding()])
        findings_path = products / "evidence/findings.json"
        findings = json.loads(findings_path.read_text(encoding="utf-8"))
        for line in findings[0]["code"]["lines"]:
            line.pop("highlight", None)
        findings[0]["code"]["lines"][0]["highlight"] = True
        findings_path.write_text(json.dumps(findings) + "\n", encoding="utf-8")
        with self.assertRaisesRegex(
            DRIVER.WorkflowDataError,
            "highlights a line other than the finding line",
        ):
            self.call(DRIVER.render_report)

    def test_source_change_after_final_tally_blocks_rendering(self) -> None:
        self.prepare(effort="low")
        self.call(DRIVER.plan_matrix)
        self.call(DRIVER.dedup_rank)
        self.call(DRIVER.tally)
        self.call(DRIVER.final_tally)
        (self.root / "src/app.py").write_text("changed\n", encoding="utf-8")
        with self.assertRaisesRegex(DRIVER.WorkflowDataError, "source tree changed"):
            self.call(DRIVER.render_report)


class FabroWorkflowStaticContractTest(unittest.TestCase):
    def test_graph_pins_all_executable_support_files(self) -> None:
        graph = GRAPH_PATH.read_text(encoding="utf-8")
        for path in (
            DRIVER_PATH,
            GIT_WRAPPER_PATH,
            RENDERER_PATH,
            REPORT_SPEC_PATH,
            TEMPLATE_PATH,
        ):
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            self.assertEqual(graph.count(digest), 1, path.name)
        self.assertNotIn("__SUPPORT_HASH_ARGUMENTS__", graph)

    def test_model_stylesheet_and_agent_limits_match_decisions(self) -> None:
        graph = GRAPH_PATH.read_text(encoding="utf-8")

        def node_body(node: str) -> str:
            match = re.search(
                rf"^    {re.escape(node)} \[(.*?)^    \]",
                graph,
                flags=re.MULTILINE | re.DOTALL,
            )
            self.assertIsNotNone(match, node)
            return match.group(1)

        for rule in (
            ".inventory { model: sonnet; reasoning_effort: medium; }",
            ".threat-model { model: opus; reasoning_effort: medium; }",
            ".research { model: opus; reasoning_effort: xhigh; }",
            ".verification { model: opus; reasoning_effort: xhigh; }",
        ):
            self.assertIn(rule, graph)
        self.assertNotIn(".report-author", graph)
        self.assertIn('stall_timeout="14400s"', graph)
        for node, jobs, cap in (
            ("threat_models", "threat_jobs", 12),
            ("research", "research_jobs", 24),
            ("sweep", "sweep_jobs", 12),
            ("panel", "verification_jobs", 24),
            ("repanel", "repanel_jobs", 24),
            ("redteam", "redteam_jobs", 24),
        ):
            body = node_body(node)
            self.assertIn(f'for_each="context.{jobs}"', body)
            self.assertIn(f"max_parallel={cap}", body)

        for node, timeout in (
            ("inventory", 3600),
            ("threat_model", 7200),
            ("researcher", 10800),
            ("sweeper", 10800),
            ("panel_verifier", 7200),
            ("repanel_verifier", 7200),
            ("redteam_verifier", 10800),
        ):
            self.assertIn(f'timeout="{timeout}s"', node_body(node), node)

    def test_finding_schema_requires_patch_ready_details(self) -> None:
        schema = json.loads(
            (WORKFLOW_ROOT / "schemas/findings.schema.json").read_text(
                encoding="utf-8"
            )
        )
        required = set(
            schema["properties"]["findings"]["items"]["required"]
        )
        self.assertTrue(
            {
                "file",
                "line",
                "ruleId",
                "identity",
                "rationale",
                "evidence",
                "snippet",
                "symbol",
                "impact",
                "exploitScenarios",
                "preconditions",
                "recommendations",
                "difficulty",
            }.issubset(required)
        )
        properties = schema["properties"]["findings"]["items"]["properties"]
        self.assertEqual(
            properties["difficulty"]["enum"],
            ["LOW", "MEDIUM", "HIGH"],
        )
        for field in ("exploitScenarios", "recommendations"):
            self.assertEqual(properties[field]["type"], "array")
            self.assertEqual(properties[field]["minItems"], 1)
        for name in ("research.md", "sweep.md"):
            prompt = (
                WORKFLOW_ROOT / "prompts" / name
            ).read_text(encoding="utf-8")
            for field in (
                "evidence",
                "snippet",
                "symbol",
                "impact",
                "exploitScenarios",
                "preconditions",
                "recommendations",
                "ruleId",
            ):
                self.assertIn(f"`{field}`", prompt)
            self.assertIn("`identity.anchor`", prompt)
            # Difficulty must be defined where it is asked for, or researchers
            # rate exploitability on their own private scale.
            self.assertIn("difficulty", prompt)
            self.assertIn("access, knowledge, and effort", prompt)

    def test_stable_identity_contract_is_wired_through_the_graph_and_report(self) -> None:
        graph = GRAPH_PATH.read_text(encoding="utf-8")
        self.assertIn('stdin_source="context.internal.run_id"', graph)
        self.assertIn("prepare --scan-id-stdin", graph)

        schema = json.loads(
            (WORKFLOW_ROOT / "schemas/findings.schema.json").read_text(
                encoding="utf-8"
            )
        )
        item = schema["properties"]["findings"]["items"]
        self.assertIn("ruleId", item["required"])
        self.assertIn("identity", item["required"])
        self.assertFalse(
            item["properties"]["identity"]["additionalProperties"]
        )

        report_spec = REPORT_SPEC_PATH.read_text(encoding="utf-8")
        renderer = RENDERER_PATH.read_text(encoding="utf-8")
        for field in ("findingId", "occurrenceId"):
            self.assertIn(field, report_spec)
            self.assertIn(field, renderer)
        self.assertFalse((WORKFLOW_ROOT / "prompts/report.md").exists())

    def test_merges_pipe_context_directly_to_deterministic_scripts(self) -> None:
        graph = GRAPH_PATH.read_text(encoding="utf-8")
        self.assertEqual(
            graph.count('stdin_source="context.parallel.results"'),
            6,
        )
        self.assertEqual(
            graph.count('stdin_source="context.output.inventory"'),
            1,
        )
        for phase in (
            "inventory",
            "threat",
            "research",
            "sweep",
            "panel",
            "repanel",
            "redteam",
        ):
            self.assertIn(
                f"security_review.py merge {phase}",
                graph,
            )
            self.assertIn(f"merge_{phase} [", graph)
        self.assertIn(
            'target_gate -> inventory [condition="context.use_inventory=true"]',
            graph,
        )
        self.assertIn(
            'inventory -> merge_inventory [condition="outcome=succeeded"]',
            graph,
        )
        for prompt in (WORKFLOW_ROOT / "prompts").glob("*.md"):
            text = prompt.read_text(encoding="utf-8")
            self.assertNotIn("result_path", text)
            self.assertNotIn("write the exact JSON", text.lower())

    def test_routing_fails_fast_and_uses_decision_defaults(self) -> None:
        graph = GRAPH_PATH.read_text(encoding="utf-8")
        self.assertNotIn("goal_gate=true", graph)
        self.assertNotIn("abort ->", graph)
        for gate, conditional_target, default_target in (
            ("target_gate", "inventory", "plan_matrix"),
            ("inventory_gate", "inventory", "plan_matrix"),
            ("threat_gate", "threat_models", "research_gate"),
            ("research_gate", "research", "sweep_gate"),
            ("sweep_gate", "sweep", "dedup_rank"),
            ("panel_gate", "panel", "tally"),
            ("effort_gate", "repanel_gate", "final_tally"),
            ("repanel_gate", "repanel", "adversarial_plan"),
            ("redteam_gate", "redteam", "final_tally"),
        ):
            self.assertRegex(
                graph,
                rf"{gate} -> {conditional_target} \[condition=",
            )
            self.assertIn(f"    {gate} -> {default_target}\n", graph)

    def test_graph_has_one_execution_path_per_role(self) -> None:
        graph = GRAPH_PATH.read_text(encoding="utf-8")
        for edge in (
            'research_gate -> research [condition="context.run_research=true"]',
            'panel_gate -> panel [condition="context.run_panel=true"]',
            'repanel_gate -> repanel [condition="context.run_repanel=true"]',
            'final_tally -> render_report [condition="outcome=succeeded"]',
        ):
            self.assertIn(edge, graph)
        for node in (
            "researcher",
            "panel_verifier",
            "repanel_verifier",
            "render_report",
        ):
            self.assertEqual(graph.count(f"    {node} ["), 1)
        self.assertNotIn("report_author", graph)

    def test_both_run_configs_declare_the_same_model_fallback_chain(
        self,
    ) -> None:
        # The chain is keyed by the model a node requests, which the graph's
        # stylesheet decides. A key no stylesheet asks for never fires, so the
        # key and the routing have to be read together.
        # Ordered: the fastest endpoint first, then the model's own provider,
        # then another host for it, then a different model as the last resort.
        chain = (
            '[run.model.fallbacks]\n'
            '"kimi-k3" = ["kimi:kimi-k3", "openrouter:kimi-k3", '
            '"' + "clau" + 'de-opus-5"]\n'
        )
        for config_name in ("workflow.toml", "verify.toml"):
            config = (WORKFLOW_ROOT / config_name).read_text(encoding="utf-8")
            self.assertIn(chain, config, config_name)
        graph = GRAPH_PATH.read_text(encoding="utf-8")
        stylesheet = graph.split('model_stylesheet="', 1)[1].split('\n        "', 1)[0]
        requested = set(re.findall(r"model:\s*([^;\s]+)", stylesheet))
        self.assertTrue(requested, "the stylesheet requests no model")
        # This repository routes to Anthropic, so the kimi chain is declared
        # for a downstream copy that routes to Kimi and does not fire here.
        self.assertNotIn("kimi-k3", requested)

    def test_checkpoint_excludes_the_ignored_runtime_directory(self) -> None:
        workflow_config = (WORKFLOW_ROOT / "workflow.toml").read_text(
            encoding="utf-8"
        )
        checkpoint_section = workflow_config.split(
            "[run.checkpoint]\n",
            1,
        )[1].split("\n[", 1)[0]
        self.assertIn(
            '".fabro/workflows/security-review/runtime",',
            checkpoint_section,
        )
        self.assertNotIn(
            '".fabro/workflows/security-review/runtime/**",',
            checkpoint_section,
        )
        verify_config = (WORKFLOW_ROOT / "verify.toml").read_text(
            encoding="utf-8"
        )
        self.assertNotIn("[run.checkpoint]", verify_config)
        workflow_ignore = (WORKFLOW_ROOT / ".gitignore").read_text(
            encoding="utf-8"
        )
        self.assertIn("runtime/*", workflow_ignore)
        self.assertIn("!runtime/.gitkeep", workflow_ignore)
        self.assertTrue((WORKFLOW_ROOT / "runtime/.gitkeep").is_file())

    def test_phase_barriers_use_fabro_native_agent_retries(self) -> None:
        graph = GRAPH_PATH.read_text(encoding="utf-8")
        # The sandbox clones the repository itself, so prepare starts with the
        # support-file pin check rather than waiting to be staged by hand.
        self.assertNotIn(".sandbox-ready", graph)
        self.assertNotIn("bootstrap_wait", graph)
        for phase, next_node in (
            ("threat", "zip_cells"),
            ("research", "sweep_gate"),
            ("sweep", "dedup_rank"),
            ("panel", "tally"),
            ("repanel", "adversarial_plan"),
            ("redteam", "final_tally"),
        ):
            self.assertIn(
                f'merge_{phase} -> {next_node} '
                '[condition="outcome=succeeded"]',
                graph,
            )
            self.assertNotIn(f"wait_{phase}_", graph)
            self.assertNotIn(f"{phase}_retry_gate", graph)
        self.assertEqual(graph.count("max_retries=2"), 7)

    def test_agent_failures_degrade_before_aborting(self) -> None:
        graph = GRAPH_PATH.read_text(encoding="utf-8")
        self.assertIn("    inventory -> inventory_failed\n", graph)
        self.assertIn(
            'inventory_failed -> plan_matrix [condition="outcome=succeeded"]',
            graph,
        )
        self.assertIn("security_review.py inventory-failed", graph)
        self.assertNotIn("    inventory -> abort\n", graph)
        self.assertNotIn("\n        max_retries=0", graph)
        self.assertIn(
            'render_report -> abort',
            graph,
        )
        self.assertNotIn("report_author", graph)

    def test_nothing_enforces_the_read_only_rule(self) -> None:
        for config_name in ("workflow.toml", "verify.toml"):
            config = (WORKFLOW_ROOT / config_name).read_text(encoding="utf-8")
            self.assertNotIn("run.hooks", config, config_name)
            self.assertNotIn("pre_tool_use", config, config_name)
        self.assertFalse((WORKFLOW_ROOT / "scripts/tool_guard.py").exists())
        graph = GRAPH_PATH.read_text(encoding="utf-8")
        self.assertNotIn("tool_guard", graph)

    def test_report_never_claims_nothing_was_executed(self) -> None:
        # The read-only rule is instructed, not enforced, so the report may
        # not vouch for it. See test_nothing_enforces_the_read_only_rule.
        spec = REPORT_SPEC_PATH.read_text(encoding="utf-8")
        renderer = RENDERER_PATH.read_text(encoding="utf-8")
        self.assertIn("does not attest whether agents executed commands", spec)
        self.assertNotIn("no tests were run", spec)
        self.assertIn(
            "workflow does not attest whether agents executed commands",
            renderer,
        )
        self.assertFalse((WORKFLOW_ROOT / "prompts/report.md").exists())

    def test_explore_capable_prompts_offer_spawn_agent(self) -> None:
        for name in (
            "threat-model.md",
            "research.md",
            "sweep.md",
            "verify.md",
            "redteam.md",
        ):
            text = (WORKFLOW_ROOT / "prompts" / name).read_text(
                encoding="utf-8"
            )
            self.assertIn("dispatch one read-only explorer", text, name)
            self.assertNotIn("spawn subagents", text, name)
            # One provider profile exposes Agent/TaskOutput, while Fabro uses
            # the spawn_agent/wait vocabulary. Naming either misleads the other.
            for vocabulary_name in ("spawn_agent", "`wait`", "TaskOutput"):
                self.assertNotIn(vocabulary_name, text, name)
        inventory = (WORKFLOW_ROOT / "prompts/inventory.md").read_text(
            encoding="utf-8"
        )
        self.assertNotIn("read-only explorer", inventory)

    def test_artifacts_capture_all_workflow_output_paths(self) -> None:
        artifact_sections = {}
        for config_name in ("workflow.toml", "verify.toml"):
            config = (WORKFLOW_ROOT / config_name).read_text(encoding="utf-8")
            artifact_sections[config_name] = config.split(
                "[run.artifacts]\n",
                1,
            )[1].split("\n[", 1)[0]
            expected_artifacts = {
                "SECURITY-REVIEW-*/.gitignore",
                "SECURITY-REVIEW-*/SECURITY-REVIEW-RESULTS.md",
                "SECURITY-REVIEW-*/SECURITY-REVIEW-RESULTS.html",
                "SECURITY-REVIEW-*/SECURITY-REVIEW-RESULTS.jsonl",
                "SECURITY-REVIEW-*/evidence/scan-manifest.json",
                "SECURITY-REVIEW-*/evidence/candidate-ledger.jsonl",
                "SECURITY-REVIEW-*/evidence/findings.json",
                "SECURITY-REVIEW-*/evidence/coverage.json",
                "SECURITY-REVIEW-*/evidence/panel-votes.jsonl",
                "SECURITY-REVIEW-*/metadata/revision.json",
                "SECURITY-REVIEW-*/metadata/state.json",
                "SECURITY-REVIEW-*/metadata/scan-meta.json",
            }
            for artifact in expected_artifacts:
                self.assertIn(artifact, artifact_sections[config_name])
            self.assertNotIn(
                ".fabro/workflows/security-review/runtime",
                artifact_sections[config_name],
            )
            include_lines = [
                line.strip().strip('",')
                for line in artifact_sections[config_name].splitlines()
                if line.strip().startswith('"')
            ]
            self.assertTrue(include_lines)
            self.assertEqual(set(include_lines), expected_artifacts)
            self.assertTrue(
                all(
                    artifact.startswith("SECURITY-REVIEW-*/")
                    for artifact in include_lines
                )
            )
            self.assertNotIn("reports/**", artifact_sections[config_name])
            self.assertNotIn(
                ".security-review-run",
                artifact_sections[config_name],
            )
            self.assertNotIn(
                "SECURITY-REVIEW-REVISION-",
                artifact_sections[config_name],
            )
            self.assertNotIn("SARIF", artifact_sections[config_name].upper())
        self.assertEqual(
            artifact_sections["workflow.toml"],
            artifact_sections["verify.toml"],
        )

    def test_workflow_uses_only_generic_security_review_naming(self) -> None:
        legacy_name = "clau" + "de"
        paths = [
            REPOSITORY_ROOT / "README.md",
            # The guide and the example report went stale on the rename once
            # because nothing checked them.
            REPOSITORY_ROOT / "index.html",
            REPOSITORY_ROOT / "sample.html",
            Path(__file__).resolve(),
            *(
                path
                for path in WORKFLOW_ROOT.rglob("*")
                if path.is_file()
                and "__pycache__" not in path.parts
                and "runtime" not in path.parts
            ),
        ]
        # A model ID legitimately names its vendor. Nothing else may, so the
        # ids are removed before the check rather than the check being dropped.
        vendor_model_ids = (legacy_name + "-opus-5", legacy_name + "-sonnet-5")
        for path in paths:
            self.assertNotIn(legacy_name, path.as_posix().lower(), path)
            content = path.read_text(encoding="utf-8").lower()
            for model_id in vendor_model_ids:
                content = content.replace(model_id, "")
            self.assertNotIn(legacy_name, content, path)

    def test_template_builds_its_page_from_data_not_from_markup(self) -> None:
        template = TEMPLATE_PATH.read_text(encoding="utf-8")
        self.assertEqual(template.count("__REPORT_DATA__"), 1)
        # Model-authored text must never become markup.
        self.assertNotIn("innerHTML", template)
        self.assertNotIn("insertAdjacentHTML", template)
        self.assertNotIn("document.write", template)
        # The page is self-contained: a report is read from a file, offline.
        self.assertNotIn("src=\"http", template)
        self.assertNotIn("href=\"http", template)
        self.assertNotIn("fetch(", template)
        for element_id in (
            "report-title",
            "report-repository",
            "report-summary",
            "report-date",
            "scan-revision",
            "scan-mode",
            "scan-effort",
            "footer-title",
            "footer-date",
        ):
            self.assertIn(f'id="{element_id}"', template)
            self.assertIn(f'"{element_id}"', template)

    def test_guide_describes_the_artifacts_the_workflow_writes(self) -> None:
        guide = (REPOSITORY_ROOT / "index.html").read_text(encoding="utf-8")
        for artifact in (
            "SECURITY-REVIEW-RESULTS.md",
            "SECURITY-REVIEW-RESULTS.html",
            "SECURITY-REVIEW-RESULTS.jsonl",
            "scan-manifest.json",
            "candidate-ledger.jsonl",
            "findings.json",
            "coverage.json",
            "panel-votes.jsonl",
            "revision.json",
            "state.json",
            "scan-meta.json",
        ):
            self.assertIn(artifact, guide, artifact)
        self.assertIn("evidence/", guide)
        self.assertIn("metadata/", guide)
        # The guide quotes the researcher prompts verbatim. Any field name it
        # shows must still be one the schema asks for -- these went stale once.
        schema = json.loads(
            (WORKFLOW_ROOT / "schemas/findings.schema.json").read_text(
                encoding="utf-8"
            )
        )
        required = set(schema["properties"]["findings"]["items"]["required"])
        for field in ("exploitScenarios", "recommendations", "difficulty"):
            self.assertIn(field, required, field)
            self.assertIn(field, guide, field)
        for retired in ("`exploitScenario`", "`recommendation`"):
            self.assertNotIn(retired, guide, retired)

    def test_report_spec_records_the_html_view_and_its_rules(self) -> None:
        spec = REPORT_SPEC_PATH.read_text(encoding="utf-8")
        self.assertIn("SECURITY-REVIEW-RESULTS.html", spec)
        self.assertIn("templates/report.html", spec)
        for rule in (
            "`LOW` difficulty is the worse case",
            "part of `ruleId`",
            "no agent transcribes them",
        ):
            self.assertIn(rule, spec)

    def test_sample_report_is_rendered_from_the_template(self) -> None:
        builder = load_module(
            "sample_report_builder",
            Path(__file__).resolve().parent / "build_sample_report.py",
        )
        expected = builder.render_sample()
        actual = (REPOSITORY_ROOT / "sample.html").read_text(encoding="utf-8")
        self.assertEqual(
            actual,
            expected,
            "sample.html is stale; run tests/build_sample_report.py --write",
        )
        payload = html_payload(actual)
        # The example must exercise every rating the report can show.
        self.assertEqual(
            {finding["severity"] for finding in payload["findings"]},
            {"High", "Medium", "Low"},
        )
        self.assertEqual(
            {finding["difficulty"] for finding in payload["findings"]},
            {"Low", "Medium", "High"},
        )
        self.assertTrue(
            all(finding["code"]["lines"] for finding in payload["findings"])
        )
        self.assertNotIn("project", payload["report"])
        self.assertNotIn("classification", payload["report"])

    def test_canonical_bundle_schemas_are_versioned_contracts(self) -> None:
        expected = {
            "scan-manifest.schema.json",
            "candidate-ledger.schema.json",
            "canonical-findings.schema.json",
            "coverage.schema.json",
            "panel-vote.schema.json",
        }
        for name in expected:
            schema = json.loads(
                (WORKFLOW_ROOT / "schemas" / name).read_text(encoding="utf-8")
            )
            self.assertEqual(
                schema["$schema"],
                "https://json-schema.org/draft/2020-12/schema",
                name,
            )
        manifest = json.loads(
            (
                WORKFLOW_ROOT / "schemas/scan-manifest.schema.json"
            ).read_text(encoding="utf-8")
        )
        self.assertEqual(
            manifest["properties"]["canonicalFiles"]["const"],
            list(DRIVER.CANONICAL_FILES),
        )


if __name__ == "__main__":
    unittest.main()
