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
GUARD_PATH = WORKFLOW_ROOT / "scripts/tool_guard.py"
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
GUARD = load_module("fabro_security_review_guard", GUARD_PATH)


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
        self.merge_success(
            "panel",
            [
                {
                    "verdict": (
                        "TRUE_POSITIVE" if index < 2 else "FALSE_POSITIVE"
                    ),
                    "reasoning": "src/app.py:4-5 confirms the path.",
                }
                for index in range(len(panel_jobs))
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
                for _ in state["phase_jobs"]["repanel"]
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
        self.merge_success("research", [{"findings": [self.finding()]}])
        self.call(DRIVER.dedup_rank)

        state = DRIVER.load_state()
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
            GUARD_PATH,
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
            ".inventory { model: sonnet; provider: openrouter; reasoning_effort: medium; }",
            ".threat-model { model: opus; provider: openrouter; reasoning_effort: medium; }",
            ".research { model: opus; provider: openrouter; reasoning_effort: xhigh; }",
            ".verification { model: opus; provider: openrouter; reasoning_effort: xhigh; }",
            ".report-author { model: opus; provider: openrouter; reasoning_effort: xhigh; }",
        ):
            self.assertIn(rule, graph)
        for node, cap in (
            ("threat_jobs", 4),
            ("research_jobs", 8),
            ("sweep_jobs", 3),
            ("verification_jobs", 12),
            ("repanel_jobs", 12),
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

    def test_phase_barriers_use_fabro_native_agent_retries(self) -> None:
        graph = GRAPH_PATH.read_text(encoding="utf-8")
        self.assertIn(
            ".fabro/workflows/security-review/.sandbox-ready",
            graph,
        )
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
        self.assertEqual(graph.count("max_retries=2"), 8)

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

    def test_artifacts_export_only_final_bundle(self) -> None:
        config = (WORKFLOW_ROOT / "workflow.toml").read_text(encoding="utf-8")
        for artifact in (
            "CLAUDE-SECURITY-*/.gitignore",
            "CLAUDE-SECURITY-*/CLAUDE-SECURITY-RESULTS.md",
            "CLAUDE-SECURITY-*/CLAUDE-SECURITY-RESULTS.jsonl",
            "CLAUDE-SECURITY-*/CLAUDE-SECURITY-REVISION-*.json",
        ):
            self.assertIn(artifact, config)
        self.assertNotIn(".claude-security-run/**", config)
        self.assertNotIn("reports/**", config)


class ToolGuardTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        (self.root / "src").mkdir()
        (self.root / "src/app.py").write_text("safe\n", encoding="utf-8")
        run_dir = self.root / "CLAUDE-SECURITY-20260729-120000/.claude-security-run"
        run_dir.mkdir(parents=True)
        state_path = self.root / GUARD.STATE_PATH
        state_path.parent.mkdir(parents=True)
        state_path.write_text(
            json.dumps({"run_dir": run_dir.as_posix()}),
            encoding="utf-8",
        )
        report_spec = self.root / GUARD.REPORT_SPEC
        report_spec.parent.mkdir(parents=True)
        report_spec.write_text("spec\n", encoding="utf-8")
        self.run_dir = run_dir
        self.previous_cwd = Path.cwd()
        os.chdir(self.root)

    def tearDown(self) -> None:
        os.chdir(self.previous_cwd)
        self.temporary.cleanup()

    def test_scan_agent_is_read_only_with_restricted_git(self) -> None:
        GUARD.handle(
            {
                "node_id": "researcher",
                "tool_name": "Bash",
                "tool_input": {
                    "command": "rg -n run_report --glob '!*.pyc'"
                },
            }
        )
        GUARD.handle(
            {
                "node_id": "researcher",
                "tool_name": "read_file",
                "tool_input": {
                    "file_path": (self.root / "src/app.py").as_posix()
                },
            }
        )
        GUARD.handle(
            {
                "node_id": "researcher",
                "tool_name": "shell",
                "tool_input": {
                    "command": (
                        "python3 .fabro/workflows/security-review/scripts/"
                        "git_readonly.py diff HEAD^..HEAD"
                    )
                },
            }
        )
        with self.assertRaises(GUARD.GuardError):
            GUARD.handle(
                {
                    "node_id": "researcher",
                    "tool_name": "shell",
                    "tool_input": {"command": "git diff HEAD^..HEAD"},
                }
            )
        with self.assertRaises(GUARD.GuardError):
            GUARD.handle(
                {
                    "node_id": "researcher",
                    "tool_name": "Bash",
                    "tool_input": {
                        "command": "rg --pre 'sh -c id' run_report"
                    },
                }
            )
        with self.assertRaises(GUARD.GuardError):
            GUARD.handle(
                {
                    "node_id": "researcher",
                    "tool_name": "Bash",
                    "tool_input": {"command": "rg run_report ../outside"},
                }
            )
        with self.assertRaises(GUARD.GuardError):
            GUARD.handle(
                {
                    "node_id": "researcher",
                    "tool_name": "write_file",
                    "tool_input": {
                        "file_path": (self.root / "src/app.py").as_posix(),
                        "content": "changed",
                    },
                }
            )

    def test_report_author_has_one_write_path(self) -> None:
        expected = self.run_dir / "CLAUDE-SECURITY-RESULTS.md"
        GUARD.handle(
            {
                "node_id": "report_author",
                "tool_name": "write_file",
                "tool_input": {
                    "file_path": expected.as_posix(),
                    "content": "# report\n",
                },
            }
        )
        with self.assertRaises(GUARD.GuardError):
            GUARD.handle(
                {
                    "node_id": "report_author",
                    "tool_name": "write_file",
                    "tool_input": {
                        "file_path": (self.root / "src/app.py").as_posix(),
                        "content": "changed",
                    },
                }
            )

if __name__ == "__main__":
    unittest.main()
