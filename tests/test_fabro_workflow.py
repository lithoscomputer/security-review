#!/usr/bin/env python3
"""Parity and transition tests for the Fabro security-review workflow."""

from __future__ import annotations

import contextlib
import hashlib
import importlib.util
import io
import json
import os
import shutil
import subprocess
import tempfile
import unittest
from argparse import Namespace
from pathlib import Path


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
WORKFLOW_ROOT = REPOSITORY_ROOT / ".fabro/workflows/security-review"
DRIVER_PATH = WORKFLOW_ROOT / "scripts/security_review.py"
GIT_WRAPPER_PATH = WORKFLOW_ROOT / "scripts/git_readonly.py"
RENDERER_PATH = WORKFLOW_ROOT / "scripts/render_report.py"
REPORT_SPEC_PATH = WORKFLOW_ROOT / "specs/report-spec.md"
GRAPH_PATH = WORKFLOW_ROOT / "security-review.fabro"


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


DRIVER = load_module("fabro_security_review_driver", DRIVER_PATH)


def run(*args: str, cwd: Path) -> subprocess.CompletedProcess:
    return subprocess.run(
        args,
        cwd=cwd,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )


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
        ensemble: object = True,
        scope: str = "",
        base: str = "",
        commit: str = "",
        revision_range: str = "",
        focus: str = "",
    ) -> dict:
        self.call(
            DRIVER.prepare,
            Namespace(
                mode=mode,
                effort=effort,
                ensemble=ensemble,
                scope=scope,
                base=base,
                commit=commit,
                range=revision_range,
                focus=focus,
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

    def merge_ensemble_success(
        self,
        batch: str,
        values: list[object],
    ) -> dict:
        phase, jobs_key, output_key = DRIVER.ENSEMBLE_BATCHES[batch]
        state = DRIVER.load_state()
        jobs = state[jobs_key]
        before = len(state["phase_results"][phase])
        results = [
            {
                "id": output_key.split(".", 1)[1],
                "index": index,
                "item_label": job["name"],
                "status": "succeeded",
                "context_updates": {output_key: value},
            }
            for index, (job, value) in enumerate(zip(jobs, values))
        ]
        updates = DRIVER.merge_phase(
            state,
            phase,
            results,
            jobs=jobs,
            output_key=output_key,
        )
        self.save(state)
        self.assertEqual(
            updates[f"{phase}_results_merged"],
            before + len(jobs),
        )
        return DRIVER.load_state()

    @staticmethod
    def finding() -> dict:
        return {
            "file": "src/app.py",
            "line": 5,
            "category": "command-injection",
            "severity": "HIGH",
            "confidence": "HIGH",
            "title": "Untrusted command reaches the shell",
            "rationale": "The caller supplies value and os.system executes it.",
            "evidence": "src/app.py:4-5",
            "snippet": "os.system(value)",
            "symbol": "run",
            "impact": "Arbitrary command execution.",
            "exploitScenario": "An attacker supplies a shell command.",
            "preconditions": [],
            "recommendation": "Replace the shell call with a fixed argv.",
            "cweId": "CWE-78",
        }

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
        self.assertEqual(len(state["research_jobs_a"]), 3)
        self.assertEqual(len(state["research_jobs_b"]), 3)
        self.assertTrue(
            all(
                job["job_id"].endswith(":1")
                for job in state["research_jobs_a"]
            )
        )
        self.assertTrue(
            all(
                job["job_id"].endswith(":2")
                for job in state["research_jobs_b"]
            )
        )
        self.assertEqual(len(sweep_jobs), 2)
        finding = self.finding()
        self.merge_ensemble_success(
            "research-a",
            [
                {"findings": [finding]} if index == 0 else {"findings": []}
                for index in range(len(state["research_jobs_a"]))
            ],
        )
        self.merge_ensemble_success(
            "research-b",
            [
                {"findings": [finding]} if index == 0 else {"findings": []}
                for index in range(len(state["research_jobs_b"]))
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
        for slot, lens in (
            ("a", "REACHABILITY"),
            ("b", "IMPACT"),
            ("c", "DEFENSES"),
        ):
            self.assertEqual(
                {job["lens"] for job in state[f"verification_jobs_{slot}"]},
                {lens},
            )
        for batch, verdict in (
            ("panel-a", "TRUE_POSITIVE"),
            ("panel-b", "TRUE_POSITIVE"),
            ("panel-c", "FALSE_POSITIVE"),
        ):
            self.merge_ensemble_success(
                batch,
                [
                    {
                        "verdict": verdict,
                        "reasoning": "src/app.py:4-5 confirms the path.",
                    }
                ],
            )
        self.call(DRIVER.tally)

        state = DRIVER.load_state()
        self.assertTrue(state["max_effort"])
        self.assertEqual(len(state["repanel_jobs"]), 3)
        self.assertNotIn("confidence", state["repanel_jobs"][0]["finding"])
        for slot, lens in (
            ("a", "REACHABILITY"),
            ("b", "IMPACT"),
            ("c", "DEFENSES"),
        ):
            self.assertEqual(
                {job["lens"] for job in state[f"repanel_jobs_{slot}"]},
                {lens},
            )
        for batch in ("repanel-a", "repanel-b", "repanel-c"):
            self.merge_ensemble_success(
                batch,
                [
                    {
                        "verdict": "TRUE_POSITIVE",
                        "reasoning": "src/app.py:4-5 confirms the path.",
                    }
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

        state = DRIVER.load_state()
        run_dir = Path(state["run_dir"])
        (run_dir / "CLAUDE-SECURITY-RESULTS.md").write_text(
            "# Claude Security results\n\nOne verified finding.\n",
            encoding="utf-8",
        )
        self.call(DRIVER.render_report)
        state = DRIVER.load_state()
        products = Path(state["products_dir"])
        self.assertTrue((products / "CLAUDE-SECURITY-RESULTS.md").is_file())
        self.assertTrue((products / "CLAUDE-SECURITY-RESULTS.jsonl").is_file())
        self.assertTrue(run_dir.is_dir(), "cloud scratch must be retained")
        stamp = json.loads(Path(state["stamp_path"]).read_text(encoding="utf-8"))
        self.assertEqual(stamp["verification"]["status"], "verified")
        self.assertEqual(stamp["findings"]["total"], 1)

    def test_ensemble_input_controls_routing_independently_of_effort(
        self,
    ) -> None:
        for effort in DRIVER.EFFORT_TIERS:
            with self.subTest(effort=effort):
                state = self.prepare(effort=effort, ensemble="true")
                self.assertTrue(state["ensemble_enabled"])
                state = self.prepare(effort=effort, ensemble="false")
                self.assertFalse(state["ensemble_enabled"])

    def test_invalid_ensemble_input_is_rejected(self) -> None:
        with self.assertRaisesRegex(
            DRIVER.WorkflowDataError,
            "ensemble must be true or false",
        ):
            self.prepare(ensemble="sometimes")

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
                    ensemble="true",
                    scope="",
                    base="",
                    commit="",
                    range="",
                    focus="",
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
        self.prepare(effort="low", ensemble=False)
        self.call(DRIVER.plan_matrix)
        state = DRIVER.load_state()
        self.assertTrue(state["run_standard_research"])
        self.assertFalse(state["run_ensemble_research"])
        self.merge_success("research", [{"findings": [self.finding()]}])
        self.call(DRIVER.dedup_rank)

        state = DRIVER.load_state()
        self.assertTrue(state["run_standard_panel"])
        self.assertFalse(state["run_ensemble_panel"])
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
        self.assertEqual(list(self.root.glob("CLAUDE-SECURITY-*")), [])

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
        self.assertEqual(
            state["file_manifest"]["files"][0]["readWith"],
            "git-show",
        )

    def test_change_manifest_classifies_every_changed_path(self) -> None:
        (self.root / "delete.py").write_text("delete_me = True\n", encoding="utf-8")
        (self.root / "rename.py").write_text(
            "".join(f"line_{index} = {index}\n" for index in range(30)),
            encoding="utf-8",
        )
        run("git", "add", "delete.py", "rename.py", cwd=self.root)
        run("git", "commit", "-qm", "manifest base", cwd=self.root)

        (self.root / "src/app.py").write_text(
            "import os\n\n\ndef run(value):\n    os.system(value + ' changed')\n",
            encoding="utf-8",
        )
        (self.root / "delete.py").unlink()
        run("git", "mv", "rename.py", "renamed.py", cwd=self.root)
        (self.root / "binary.dat").write_bytes(b"binary\x00data")
        (self.root / "generated.min.js").write_text(
            "window.generated=true;\n",
            encoding="utf-8",
        )
        (self.root / "oversized.txt").write_text(
            "x" * (DRIVER.FILE_REVIEW_MAX_BYTES + 1),
            encoding="utf-8",
        )
        (self.root / "link.py").symlink_to("src/app.py")
        run(
            "git",
            "add",
            "-A",
            "src/app.py",
            "delete.py",
            "renamed.py",
            "binary.dat",
            "generated.min.js",
            "oversized.txt",
            "link.py",
            cwd=self.root,
        )
        head = run("git", "rev-parse", "HEAD", cwd=self.root).stdout.decode().strip()
        run(
            "git",
            "update-index",
            "--add",
            "--cacheinfo",
            "160000",
            head,
            "vendored",
            cwd=self.root,
        )
        run("git", "commit", "-qm", "manifest changes", cwd=self.root)

        state = self.prepare(
            mode="changes",
            effort="low",
            ensemble=False,
            base="HEAD^",
        )
        rows = {
            row["path"]: row for row in state["file_manifest"]["files"]
        }
        self.assertEqual(set(rows), {
            "binary.dat",
            "delete.py",
            "generated.min.js",
            "link.py",
            "oversized.txt",
            "renamed.py",
            "src/app.py",
            "vendored",
        })
        self.assertEqual(rows["src/app.py"]["disposition"], "pending")
        self.assertEqual(rows["renamed.py"]["disposition"], "pending")
        self.assertEqual(rows["generated.min.js"]["disposition"], "pending")
        self.assertTrue(rows["generated.min.js"]["reviewRequired"])
        self.assertEqual(rows["renamed.py"]["oldPath"], "rename.py")
        self.assertEqual(rows["delete.py"]["disposition"], "excluded")
        self.assertIn("deleted", rows["delete.py"]["reason"])
        self.assertEqual(rows["binary.dat"]["disposition"], "excluded")
        self.assertIn("binary", rows["binary.dat"]["reason"])
        self.assertEqual(rows["link.py"]["disposition"], "excluded")
        self.assertIn("symbolic link", rows["link.py"]["reason"])
        self.assertEqual(rows["vendored"]["disposition"], "excluded")
        self.assertIn("submodule", rows["vendored"]["reason"])
        self.assertEqual(rows["oversized.txt"]["disposition"], "deferred")
        self.assertIn("full-file review limit", rows["oversized.txt"]["reason"])
        self.assertIn("higher file-size limit", rows["oversized.txt"]["workNeeded"])
        for path in ("generated.min.js", "renamed.py", "src/app.py"):
            self.assertEqual(rows[path]["readWith"], "git-show")

        assigned = [
            row["path"]
            for job in state["file_review_jobs"]
            for row in job["files"]
        ]
        self.assertEqual(
            sorted(assigned),
            ["generated.min.js", "renamed.py", "src/app.py"],
        )
        self.assertEqual(len(assigned), len(set(assigned)))
        self.assertTrue(state["run_standard_file_review"])
        self.assertFalse(state["run_ensemble_file_review"])

    def test_change_manifest_preserves_exact_literal_git_paths(self) -> None:
        paths = [" leading.py", ":(glob)*.py"]
        for path in paths:
            (self.root / path).write_text("changed = True\n", encoding="utf-8")
        run("git", "add", "--", *paths, cwd=self.root)
        run("git", "commit", "-qm", "literal path changes", cwd=self.root)

        state = self.prepare(
            mode="changes",
            effort="low",
            ensemble=False,
            base="HEAD^",
        )
        self.assertEqual(
            [row["path"] for row in state["file_manifest"]["files"]],
            paths,
        )
        self.assertEqual(
            [
                row["path"]
                for job in state["file_review_jobs"]
                for row in job["files"]
            ],
            paths,
        )

    def test_file_receipt_completes_change_coverage_and_is_exported(self) -> None:
        (self.root / "src/app.py").write_text(
            "import os\n\n\ndef run(value):\n    os.system(value + ' changed')\n",
            encoding="utf-8",
        )
        run("git", "add", "src/app.py", cwd=self.root)
        run("git", "commit", "-qm", "change", cwd=self.root)

        state = self.prepare(
            mode="changes",
            effort="low",
            ensemble=False,
            base="HEAD^",
        )
        self.assertEqual(len(state["phase_jobs"]["file_review"]), 1)
        self.merge_success(
            "file_review",
            [{
                "receipts": [{
                    "path": "src/app.py",
                    "status": "reviewed",
                    "reason": "",
                    "workNeeded": "",
                }],
                "supportingFilesReviewed": [],
                "findings": [],
            }],
        )
        coverage = DRIVER.file_coverage_from_state(DRIVER.load_state())
        self.assertEqual(coverage["completeness"], "complete")
        self.assertEqual(coverage["counts"], {
            "changedPaths": 1,
            "reviewRequired": 1,
            "reviewed": 1,
            "excluded": 0,
            "deferred": 0,
        })
        self.assertEqual(coverage["files"][0]["receipt"], {
            "jobId": "file-review:1",
            "status": "reviewed",
            "reason": None,
            "workNeeded": None,
        })

        self.call(DRIVER.plan_matrix)
        self.merge_success("research", [{"findings": []}])
        self.call(DRIVER.dedup_rank)
        self.call(DRIVER.tally)
        self.call(DRIVER.final_tally)
        state = DRIVER.load_state()
        self.assertEqual(
            state["final"]["coverage"]["fileCoverage"]["completeness"],
            "complete",
        )
        run_dir = Path(state["run_dir"])
        report_path = run_dir / "CLAUDE-SECURITY-RESULTS.md"
        report_path.write_text("# Claude Security results\n", encoding="utf-8")
        self.call(DRIVER.render_report)
        exported = (
            Path(DRIVER.load_state()["products_dir"])
            / "CLAUDE-SECURITY-FILE-COVERAGE.json"
        )
        self.assertEqual(
            json.loads(exported.read_text(encoding="utf-8"))["completeness"],
            "complete",
        )

    def test_missing_or_unassigned_receipt_makes_coverage_partial(self) -> None:
        (self.root / "src/app.py").write_text("changed\n", encoding="utf-8")
        run("git", "add", "src/app.py", cwd=self.root)
        run("git", "commit", "-qm", "change", cwd=self.root)
        self.prepare(
            mode="changes",
            effort="low",
            ensemble=False,
            base="HEAD^",
        )
        self.merge_success(
            "file_review",
            [{
                "receipts": [{
                    "path": "src/support.py",
                    "status": "reviewed",
                    "reason": "",
                    "workNeeded": "",
                }],
                "supportingFilesReviewed": ["src/app.py"],
                "findings": [],
            }],
        )
        coverage = DRIVER.file_coverage_from_state(DRIVER.load_state())
        self.assertEqual(coverage["completeness"], "partial")
        self.assertEqual(coverage["counts"]["deferred"], 1)
        self.assertIn(
            "0 receipts for this path",
            coverage["files"][0]["reason"],
        )
        self.assertEqual(len(coverage["invalidReceiptClaims"]), 1)
        self.assertEqual(
            coverage["supportingFilesReviewed"],
            [{"path": "src/app.py", "jobId": "file-review:1"}],
        )

    def test_commit_manifest_reads_non_checkout_target_with_git_show(self) -> None:
        target = run("git", "rev-parse", "HEAD", cwd=self.root).stdout.decode().strip()
        (self.root / "src/app.py").write_text("later checkout\n", encoding="utf-8")
        run("git", "add", "src/app.py", cwd=self.root)
        run("git", "commit", "-qm", "later", cwd=self.root)

        state = self.prepare(
            mode="commit",
            commit=target,
            effort="low",
            ensemble=False,
        )
        self.assertEqual(
            state["file_manifest"]["files"][0]["readWith"],
            "git-show",
        )

    def test_source_change_fails_closed_at_publication(self) -> None:
        self.prepare(effort="low")
        self.call(DRIVER.plan_matrix)
        (self.root / "src/app.py").write_text("changed\n", encoding="utf-8")
        # Intermediate steps proceed; the digest gates publication only.
        self.call(DRIVER.dedup_rank)
        self.call(DRIVER.tally)
        with self.assertRaisesRegex(DRIVER.WorkflowDataError, "source tree changed"):
            self.call(DRIVER.final_tally)

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
        ):
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            self.assertEqual(graph.count(digest), 1, path.name)
        self.assertNotIn("__SUPPORT_HASH_ARGUMENTS__", graph)

    def test_model_stylesheet_and_concurrency_caps_match_decisions(self) -> None:
        graph = GRAPH_PATH.read_text(encoding="utf-8")
        for rule in (
            ".inventory { model: sonnet; reasoning_effort: medium; }",
            ".threat-model { model: opus; reasoning_effort: medium; }",
            ".research { model: opus; reasoning_effort: xhigh; }",
            ".verification { model: opus; reasoning_effort: xhigh; }",
            ".report-author { model: opus; reasoning_effort: xhigh; }",
            (
                ".ensemble-a { model: gpt-5.6-sol; provider: openrouter; "
                "reasoning_effort: xhigh; }"
            ),
            (
                ".ensemble-b { model: claude-opus-4-8; "
                "provider: openrouter; reasoning_effort: xhigh; }"
            ),
            (
                ".ensemble-c { model: kimi-k3; provider: openrouter; "
                "reasoning_effort: high; }"
            ),
            (
                ".ensemble-d { model: glm-5.2; provider: openrouter; "
                "reasoning_effort: high; }"
            ),
        ):
            self.assertIn(rule, graph)
        for node, cap in (
            ("file_review_jobs", 8),
            ("file_review_jobs_a", 8),
            ("threat_jobs", 4),
            ("research_jobs", 8),
            ("research_jobs_a", 8),
            ("research_jobs_b", 8),
            ("sweep_jobs", 3),
            ("verification_jobs", 12),
            ("verification_jobs_a", 12),
            ("verification_jobs_b", 12),
            ("verification_jobs_c", 12),
            ("repanel_jobs", 12),
            ("repanel_jobs_a", 12),
            ("repanel_jobs_b", 12),
            ("repanel_jobs_c", 12),
            ("redteam_jobs", 4),
        ):
            self.assertIn(f'for_each="context.{node}"', graph)
            self.assertIn(f"max_parallel={cap}", graph)

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
                "rationale",
                "evidence",
                "snippet",
                "symbol",
                "impact",
                "exploitScenario",
                "preconditions",
                "recommendation",
            }.issubset(required)
        )
        for name in ("research.md", "sweep.md"):
            prompt = (
                WORKFLOW_ROOT / "prompts" / name
            ).read_text(encoding="utf-8")
            for field in (
                "evidence",
                "snippet",
                "symbol",
                "impact",
                "exploitScenario",
                "preconditions",
                "recommendation",
            ):
                self.assertIn(f"`{field}`", prompt)

    def test_file_review_contract_requires_exact_completion_receipts(self) -> None:
        schema = json.loads(
            (WORKFLOW_ROOT / "schemas/file-review.schema.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertEqual(
            set(schema["required"]),
            {"receipts", "supportingFilesReviewed", "findings"},
        )
        receipts = schema["properties"]["receipts"]
        self.assertEqual(receipts["maxItems"], DRIVER.FILE_REVIEW_BATCH_SIZE)
        self.assertEqual(
            set(receipts["items"]["properties"]["status"]["enum"]),
            {"reviewed", "deferred"},
        )
        self.assertEqual(
            set(receipts["items"]["required"]),
            {"path", "status", "reason", "workNeeded"},
        )
        prompt = (WORKFLOW_ROOT / "prompts/file-review.md").read_text(
            encoding="utf-8"
        )
        for statement in (
            "Read from the first byte through end of file",
            "Return exactly one receipt",
            "never replaces a required changed-file receipt",
            "the exact `workNeeded`",
            "The receipts array is never optional",
        ):
            self.assertIn(statement, prompt)
        self.assertIsNone(DRIVER.normalize_file_review_result({
            "receipts": [{
                "path": "src/app.py",
                "status": "deferred",
                "reason": "the file was truncated",
            }],
            "supportingFilesReviewed": [],
            "findings": [],
        }))

    def test_merges_pipe_context_directly_to_deterministic_scripts(self) -> None:
        graph = GRAPH_PATH.read_text(encoding="utf-8")
        self.assertEqual(
            graph.count('stdin_source="context.parallel.results"'),
            16,
        )
        self.assertEqual(
            graph.count('stdin_source="context.output.inventory"'),
            1,
        )
        for phase in (
            "file_review",
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
        for batch in DRIVER.ENSEMBLE_BATCHES:
            node = batch.replace("-", "_")
            self.assertIn(
                f"security_review.py merge-ensemble {batch}",
                graph,
            )
            self.assertIn(f"merge_{node} [", graph)
        self.assertIn(
            'target_gate -> inventory [condition="context.use_inventory=true"]',
            graph,
        )
        self.assertIn(
            "target_gate -> file_review_a "
            '[condition="context.run_ensemble_file_review=true"]',
            graph,
        )
        self.assertIn(
            "target_gate -> file_review "
            '[condition="context.run_standard_file_review=true"]',
            graph,
        )
        self.assertIn(
            'inventory -> merge_inventory [condition="outcome=succeeded"]',
            graph,
        )
        for prompt in (WORKFLOW_ROOT / "prompts").glob("*.md"):
            if prompt.name == "report.md":
                continue
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

    def test_ensemble_routes_through_neutral_model_slots(self) -> None:
        graph = GRAPH_PATH.read_text(encoding="utf-8")
        for edge in (
            (
                'target_gate -> file_review_a '
                '[condition="context.run_ensemble_file_review=true"]'
            ),
            (
                'research_gate -> research_a '
                '[condition="context.run_ensemble_research=true"]'
            ),
            (
                'panel_gate -> panel_a '
                '[condition="context.run_ensemble_panel=true"]'
            ),
            (
                'repanel_gate -> repanel_a '
                '[condition="context.run_ensemble_repanel=true"]'
            ),
            (
                'final_tally -> report_author_d '
                '[condition="context.run_ensemble_report=true"]'
            ),
        ):
            self.assertIn(edge, graph)
        for node, slot in (
            ("file_reviewer_a", "a"),
            ("researcher_a", "a"),
            ("researcher_b", "b"),
            ("panel_verifier_a", "a"),
            ("panel_verifier_b", "b"),
            ("panel_verifier_c", "c"),
            ("repanel_verifier_a", "a"),
            ("repanel_verifier_b", "b"),
            ("repanel_verifier_c", "c"),
            ("report_author_d", "d"),
        ):
            self.assertRegex(
                graph,
                rf'(?s){node} \[.*?class="ensemble-{slot}".*?\]',
            )

    def test_ensemble_input_defaults_to_true(self) -> None:
        graph = GRAPH_PATH.read_text(encoding="utf-8")
        self.assertIn("--ensemble {{ inputs.ensemble }}", graph)
        for config_name in ("workflow.toml", "verify.toml"):
            config = (WORKFLOW_ROOT / config_name).read_text(encoding="utf-8")
            self.assertRegex(config, r"(?m)^ensemble = true$")

    def test_checkpoint_excludes_the_ignored_runtime_directory(self) -> None:
        for config_name in ("workflow.toml", "verify.toml"):
            config = (WORKFLOW_ROOT / config_name).read_text(encoding="utf-8")
            self.assertIn(
                '".fabro/workflows/security-review/runtime",',
                config,
            )
            self.assertIn(
                '".fabro/workflows/security-review/runtime/**",',
                config,
            )
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
        self.assertIn(
            'merge_file_review -> post_file_review_gate '
            '[condition="outcome=succeeded"]',
            graph,
        )
        for merge_node, next_node in (
            ("merge_file_review_a", "post_file_review_gate"),
            ("merge_research_a", "research_b"),
            ("merge_research_b", "sweep_gate"),
            ("merge_panel_a", "panel_b"),
            ("merge_panel_b", "panel_c"),
            ("merge_panel_c", "tally"),
            ("merge_repanel_a", "repanel_b"),
            ("merge_repanel_b", "repanel_c"),
            ("merge_repanel_c", "adversarial_plan"),
        ):
            self.assertIn(
                f'{merge_node} -> {next_node} '
                '[condition="outcome=succeeded"]',
                graph,
            )
        self.assertEqual(graph.count("max_retries=2"), 19)

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
        self.assertRegex(graph, r"(?s)report_author \[[^\]]*max_retries=2")

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
        report_prompt = (WORKFLOW_ROOT / "prompts/report.md").read_text(
            encoding="utf-8"
        )
        self.assertIn("nothing enforces that instruction", spec)
        self.assertNotIn("no tests were run", spec)
        self.assertIn("do not assert that nothing was run", report_prompt)
        self.assertNotIn("read source and history only", report_prompt)

    def test_explore_capable_prompts_offer_spawn_agent(self) -> None:
        for name in (
            "file-review.md",
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
            # The Claude 5 profile exposes Agent/TaskOutput, the Fabro
            # vocabulary spawn_agent/wait. Naming either misleads the other.
            for vocabulary_name in ("spawn_agent", "`wait`", "TaskOutput"):
                self.assertNotIn(vocabulary_name, text, name)
        inventory = (WORKFLOW_ROOT / "prompts/inventory.md").read_text(
            encoding="utf-8"
        )
        self.assertNotIn("read-only explorer", inventory)

    def test_artifacts_export_only_final_bundle(self) -> None:
        config = (WORKFLOW_ROOT / "workflow.toml").read_text(encoding="utf-8")
        for artifact in (
            "CLAUDE-SECURITY-*/.gitignore",
            "CLAUDE-SECURITY-*/CLAUDE-SECURITY-RESULTS.md",
            "CLAUDE-SECURITY-*/CLAUDE-SECURITY-RESULTS.jsonl",
            "CLAUDE-SECURITY-*/CLAUDE-SECURITY-FILE-COVERAGE.json",
            "CLAUDE-SECURITY-*/CLAUDE-SECURITY-REVISION-*.json",
        ):
            self.assertIn(artifact, config)
        self.assertNotIn(".claude-security-run/**", config)
        self.assertNotIn("reports/**", config)


if __name__ == "__main__":
    unittest.main()
