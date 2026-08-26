#!/usr/bin/env python3
"""Contract and transition tests for the suggest-security-patches workflow."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import re
import subprocess
import sys
import tempfile
import tomllib
import unittest
from pathlib import Path


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
WORKFLOW_ROOT = REPOSITORY_ROOT / ".fabro/workflows/suggest-security-patches"
ENGINE_PATH = WORKFLOW_ROOT / "scripts/suggest_patches.py"
GOAL_HELPER_PATH = WORKFLOW_ROOT / "scripts/make_goal.py"
GIT_WRAPPER_PATH = WORKFLOW_ROOT / "scripts/git_readonly.py"
PATCH_SPEC_PATH = WORKFLOW_ROOT / "specs/patch-spec.md"
GRAPH_PATH = WORKFLOW_ROOT / "suggest-security-patches.fabro"
FIXTURE_FINDING = WORKFLOW_ROOT / "fixtures/finding-command-injection.json"

CONFIGS = ("workflow.toml", "workflow-embargo.toml", "verify.toml")

# The files every deterministic node must hash-check before it runs. The
# implementer can write to the checkout, so a single check in prepare would not
# survive its node.
PINNED_SUPPORT_FILES = (
    "scripts/suggest_patches.py",
    "scripts/git_readonly.py",
    "specs/patch-spec.md",
)


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


sys.dont_write_bytecode = True
ENGINE = load_module("fabro_suggest_patches_engine", ENGINE_PATH)
GOAL_HELPER = load_module("fabro_suggest_patches_goal", GOAL_HELPER_PATH)

VULNERABLE_SOURCE = '''"""Fixture."""

import os


def run_report() -> None:
    command = input("Report command: ")
    os.system(command)
'''

FIXED_SOURCE = '''"""Fixture."""

import subprocess

ALLOWED = {"daily": ["./report", "--daily"]}


def run_report() -> None:
    name = input("Report command: ")
    argv = ALLOWED.get(name)
    if argv is None:
        raise ValueError("unknown report")
    subprocess.run(argv, shell=False, check=True)
'''

APPROVED_PLAN = {
    "rootCause": "Caller-controlled text reaches os.system.",
    "exploitPath": "run_report reads input and passes it to a shell.",
    "trustBoundary": "Interactive input crosses into command execution.",
    "implementationSteps": ["Replace the shell call with a fixed argv map."],
    "expectedFiles": ["app.py"],
    "compatibilityRisks": "Unknown report names will be rejected.",
    "validationPlan": "Review the changed path and its callers.",
    "ownerQuestion": None,
    "declineReason": None,
}

CLEAN_CONSOLIDATION = {
    "outcome": "clean",
    "summary": "All six review lanes found the patch acceptable.",
    "findings": [],
}

BLOCKING_FINDING = {
    "lane": "exploit-closure",
    "issue": "The original exploit remains reachable.",
    "evidence": "app.py still passes input to a shell.",
    "requiredChange": "Remove the remaining shell execution path.",
}


def git(*args: str, cwd: Path) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["git", *args],
        cwd=cwd,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )


class Workspace:
    """A throwaway repository shaped like the sandbox the workflow runs in."""

    def __init__(self, directory: Path) -> None:
        self.path = directory
        self.context_updates: dict = {}
        git("init", "-q", ".", cwd=directory)
        git("config", "user.email", "test@example.invalid", cwd=directory)
        git("config", "user.name", "Test", cwd=directory)
        git("config", "commit.gpgsign", "false", cwd=directory)
        engine_directory = directory / ".fabro/workflows/suggest-security-patches"
        (engine_directory / "scripts").mkdir(parents=True)
        (engine_directory / "specs").mkdir(parents=True)
        for relative in PINNED_SUPPORT_FILES:
            (engine_directory / relative).write_bytes(
                (WORKFLOW_ROOT / relative).read_bytes()
            )
        # The fence the workflow ships with: its runtime state is the engine's
        # own bookkeeping and never part of a patch.
        (engine_directory / ".gitignore").write_bytes(
            (WORKFLOW_ROOT / ".gitignore").read_bytes()
        )
        (directory / "app.py").write_text(VULNERABLE_SOURCE, encoding="utf-8")
        git("add", "-A", cwd=directory)
        git("commit", "-qm", "initial", cwd=directory)
        self.base = git(
            "rev-parse", "HEAD", cwd=directory
        ).stdout.decode().strip()

    def checkpoint(self, label: str) -> None:
        """What Fabro does after every node: stage everything and commit.

        Fabro honours `[run.checkpoint] exclude_globs`, so the products
        directory never enters a commit and never reaches the pull request's
        diff. The exclusion is modelled here because the decline invariant
        depends on it.
        """
        git("add", "-A", "--", ".", ":(exclude)SECURITY-PATCH-*", cwd=self.path)
        git(
            "commit",
            "-q",
            "--allow-empty",
            "-m",
            f"fabro(run): {label} (succeeded)",
            cwd=self.path,
        )

    def pin(self) -> dict:
        """Run pin_review the way the graph does: trusted base on stdin."""
        return self.context(self.engine("pin-review", self.base))

    def review_pin(self) -> str:
        """What Fabro's context would hand back to finalize via stdin_source."""
        pin = self.context_updates.get("review_pin")
        assert pin, "assess-change never emitted a review pin"
        return pin

    def engine(self, command: str, stdin: str = "") -> subprocess.CompletedProcess:
        return subprocess.run(
            [
                sys.executable,
                ".fabro/workflows/suggest-security-patches/scripts/suggest_patches.py",
                command,
            ],
            cwd=self.path,
            input=stdin.encode("utf-8"),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

    def context(self, result: subprocess.CompletedProcess) -> dict:
        payload = result.stdout.decode("utf-8").strip().splitlines()
        for line in reversed(payload):
            if line.startswith("{"):
                updates = json.loads(line)["context_updates"]
                # Fabro merges each node's updates into one run context.
                self.context_updates.update(updates)
                return updates
        raise AssertionError(f"no routing output: {result.stdout!r} {result.stderr!r}")

    def state(self) -> dict:
        return json.loads(
            (
                self.path
                / ".fabro/workflows/suggest-security-patches/runtime/state.json"
            ).read_text(encoding="utf-8")
        )

    def products(self) -> Path:
        matches = sorted(self.path.glob("SECURITY-PATCH-*"))
        assert matches, "no products directory"
        return matches[0]

    def goal(self, **overrides) -> str:
        finding = {
            "id": "F1",
            "title": "Command injection in run_report",
            "file": "app.py",
            "line": 8,
            "snippet": "os.system(command)",
            "symbol": "run_report",
            "recommendation": "Use subprocess with an argument list.",
        }
        finding.update(overrides)
        return json.dumps(finding)

    def start(self, **overrides) -> dict:
        return self.context(self.engine("prepare", self.goal(**overrides)))

    def generate(self, source: str = FIXED_SOURCE, **result) -> dict:
        """Write a change the way the generator would, then checkpoint it.

        Follows the graph: when assess_change reports a change, the run passes
        through pin_review, which re-derives it from the trusted base before
        any reviewer sees it. Returns assess_change's routing.
        """
        if source is not None:
            (self.path / "app.py").write_text(source, encoding="utf-8")
        self.checkpoint("generate")
        payload = {"summary": "fixed", "changedFiles": ["app.py"]}
        payload.update(result)
        assessed = self.context(self.engine("assess-change", json.dumps(payload)))
        if assessed.get("declined"):
            return assessed
        # The graph always continues into pin_review, which measures the tree
        # against the trusted base and decides where the run goes.
        return self.pin()

    def review_results(self, reviewed_paths: list[str] | None = None) -> list[dict]:
        results = []
        for branch_id, output_key, lane in ENGINE.REVIEW_LANES:
            output = {"summary": f"{lane} checked", "findings": []}
            if lane == "patch-completeness-evidence":
                output["reviewedPaths"] = (
                    ["app.py"] if reviewed_paths is None else reviewed_paths
                )
            results.append(
                {
                    "id": branch_id,
                    "status": "succeeded",
                    "context_updates": {output_key: output},
                }
            )
        return results

    def record_reviews(self, results: list[dict] | None = None) -> dict:
        return self.context(
            self.engine("record-reviews", json.dumps(results or self.review_results()))
        )

    def consolidate(self, result: dict | None = None) -> dict:
        return self.context(
            self.engine(
                "merge-consolidation",
                json.dumps(result or CLEAN_CONSOLIDATION),
            )
        )

    def clean_review(self) -> dict:
        self.record_reviews()
        return self.consolidate()


class WorkspaceTest(unittest.TestCase):
    def setUp(self) -> None:
        self._temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self._temporary.cleanup)
        self.workspace = Workspace(Path(self._temporary.name))


class PrepareTests(WorkspaceTest):
    def test_locates_the_finding_and_records_the_base(self) -> None:
        context = self.workspace.start()
        self.assertTrue(context["finding_located"])
        self.assertEqual(context["patch_base"], self.workspace.base)
        self.assertEqual(self.workspace.state()["base"], self.workspace.base)

    def test_stale_finding_declines_instead_of_patching_blind(self) -> None:
        context = self.workspace.start(snippet="os.execv(rewritten_since_the_scan)")
        self.assertFalse(context["finding_located"])
        self.assertEqual(self.workspace.state()["status"], "skipped_stale")

    def test_missing_file_is_stale(self) -> None:
        context = self.workspace.start(file="gone.py", snippet="anything")
        self.assertFalse(context["finding_located"])

    def test_template_delimiter_is_refused_with_a_named_reason(self) -> None:
        result = self.workspace.engine(
            "prepare", self.workspace.goal(title="uses {{ user }} in the title")
        )
        self.assertEqual(result.returncode, 2)
        self.assertIn("template delimiter", result.stderr.decode("utf-8"))

    def test_free_text_goal_is_refused(self) -> None:
        result = self.workspace.engine("prepare", "please fix the command injection")
        self.assertEqual(result.returncode, 2)
        self.assertIn("finding object", result.stderr.decode("utf-8"))

    def test_path_escaping_the_repository_is_refused(self) -> None:
        result = self.workspace.engine(
            "prepare", self.workspace.goal(file="../../etc/passwd")
        )
        self.assertEqual(result.returncode, 2)
        self.assertIn("escape the repository", result.stderr.decode("utf-8"))

    def test_malformed_id_is_refused(self) -> None:
        result = self.workspace.engine("prepare", self.workspace.goal(id="../../F1"))
        self.assertEqual(result.returncode, 2)
        self.assertIn("`id`", result.stderr.decode("utf-8"))


class ChangedSetTests(WorkspaceTest):
    """The changed set comes from Git, never from the generator's account."""

    def setUp(self) -> None:
        super().setUp()
        self.workspace.start()

    def test_change_survives_the_checkpoint_that_commits_it(self) -> None:
        # The regression this guards: a staged (--cached) diff is empty by the
        # time the engine looks, because Fabro already committed the tree.
        context = self.workspace.generate()
        self.assertEqual(context["pin_next"], "review")
        self.assertEqual(self.workspace.state()["changed_paths"], ["M app.py"])

    def test_added_deleted_and_renamed_paths_are_all_seen(self) -> None:
        workspace = self.workspace
        (workspace.path / "added.py").write_text("x = 1\n", encoding="utf-8")
        (workspace.path / "app.py").write_text(FIXED_SOURCE, encoding="utf-8")
        git("mv", "app.py", "renamed.py", cwd=workspace.path)
        context = workspace.generate(source=None)
        self.assertEqual(context["pin_next"], "review")
        entries = " ".join(workspace.state()["changed_paths"])
        self.assertIn("added.py", entries)
        self.assertIn("renamed.py", entries)

    def test_mode_change_alone_is_a_change(self) -> None:
        workspace = self.workspace
        os.chmod(workspace.path / "app.py", 0o755)
        context = workspace.generate(source=None)
        self.assertEqual(context["pin_next"], "review")

    def test_symlink_is_reported_as_a_changed_path(self) -> None:
        workspace = self.workspace
        (workspace.path / "link.py").symlink_to("app.py")
        context = workspace.generate(source=None)
        self.assertEqual(context["pin_next"], "review")
        self.assertIn("link.py", " ".join(workspace.state()["changed_paths"]))

    def test_generator_claim_of_changes_cannot_invent_one(self) -> None:
        context = self.workspace.generate(
            source=None, changedFiles=["app.py", "invented.py"]
        )
        self.assertNotEqual(context["pin_next"], "review")
        self.assertEqual(self.workspace.state()["status"], "declined")

    def test_no_change_and_no_question_declines(self) -> None:
        context = self.workspace.generate(source=None, summary="I changed nothing")
        self.assertEqual(context["pin_next"], "decline")
        self.assertIn("changed nothing", self.workspace.state()["decline_reason"])

    def test_refusal_declines(self) -> None:
        context = self.workspace.generate(source=None, refusal="dispatch was malformed")
        self.assertTrue(context["declined"])  # assess_change stops at a refusal
        self.assertIn("refused", self.workspace.state()["decline_reason"])


class TamperingTests(WorkspaceTest):
    def setUp(self) -> None:
        super().setUp()
        self.workspace.start()

    def test_patch_touching_the_engine_is_declined(self) -> None:
        workspace = self.workspace
        engine = (
            workspace.path
            / ".fabro/workflows/suggest-security-patches/scripts/suggest_patches.py"
        )
        engine.write_text(
            engine.read_text(encoding="utf-8") + "\n# tampered\n", encoding="utf-8"
        )
        context = workspace.generate(source=None)
        self.assertEqual(context["pin_next"], "decline")
        state = workspace.state()
        self.assertIn("support files", state["decline_reason"])
        self.assertTrue(state["tampering_signals"])

    def test_fixtures_are_patchable(self) -> None:
        # The smoke run's whole job is to patch a fixture, and a fixture
        # decides nothing, so it is the one exception to the rule above.
        workspace = self.workspace
        fixtures = (
            workspace.path / ".fabro/workflows/suggest-security-patches/fixtures"
        )
        fixtures.mkdir(parents=True, exist_ok=True)
        (fixtures / "command_injection.py").write_text("x = 1\n", encoding="utf-8")
        context = workspace.generate(source=None)
        self.assertEqual(context["pin_next"], "review")

    def test_engine_edited_after_prepare_aborts_the_next_node(self) -> None:
        """The per-node hash check, as the graph runs it."""
        workspace = self.workspace
        engine_relative = (
            ".fabro/workflows/suggest-security-patches/scripts/suggest_patches.py"
        )
        expected = hashlib.sha256(
            (workspace.path / engine_relative).read_bytes()
        ).hexdigest()
        (workspace.path / engine_relative).write_text(
            "# replaced\n", encoding="utf-8"
        )
        result = subprocess.run(
            [
                sys.executable,
                "-c",
                "import hashlib,sys; pairs=list(zip(sys.argv[1::2],sys.argv[2::2])); "
                "sys.exit(0 if pairs and all("
                "hashlib.sha256(open(path,'rb').read()).hexdigest()==expected "
                "for path,expected in pairs) else 91)",
                engine_relative,
                expected,
            ],
            cwd=workspace.path,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        self.assertEqual(result.returncode, 91)

    def test_hook_installed_at_an_active_path_is_reported(self) -> None:
        """Defense in depth only — see fabro-sh/fabro#809 for the real control.

        The engine cannot stop a hook from firing at the generator's own
        checkpoint, so what it owes the operator is noticing and saying so.
        """
        workspace = self.workspace
        hooks = workspace.path / "planted-hooks"
        hooks.mkdir()
        hook = hooks / "post-commit"
        hook.write_text("#!/bin/sh\ntouch /tmp/fabro-hook-ran\n", encoding="utf-8")
        hook.chmod(0o755)
        git("config", "core.hooksPath", str(hooks), cwd=workspace.path)

        workspace.generate(source=None)
        signals = " ".join(workspace.state()["tampering_signals"])
        self.assertIn("core.hooksPath", signals)
        # And the engine has repointed it away from the planted directory.
        configured = git(
            "config", "--local", "--get", "core.hooksPath", cwd=workspace.path
        ).stdout.decode().strip()
        self.assertNotEqual(configured, str(hooks))


class PlanReviewTests(WorkspaceTest):
    def setUp(self) -> None:
        super().setUp()
        self.workspace.start()

    def route(self, **overrides) -> dict:
        payload = json.loads(json.dumps(APPROVED_PLAN))
        payload.update(overrides)
        return self.workspace.context(
            self.workspace.engine("route-plan", json.dumps(payload))
        )

    def test_approved_plan_routes_to_implementation(self) -> None:
        self.assertEqual(self.route()["plan_next"], "implement")
        self.assertEqual(self.workspace.state()["approved_plan"], APPROVED_PLAN)

    def test_plan_can_ask_one_owner_question(self) -> None:
        first = self.route(ownerQuestion="Must legacy report names keep working?")
        self.assertEqual(first["plan_next"], "ask")
        self.assertTrue(self.workspace.state()["owner_question_used"])

        second = self.route(ownerQuestion="A second question?")
        self.assertEqual(second["plan_next"], "decline")
        self.assertIn("one question", self.workspace.state()["decline_reason"])

    def test_plan_review_can_decline_before_implementation(self) -> None:
        context = self.route(declineReason="The finding needs a product decision.")
        self.assertEqual(context["plan_next"], "decline")
        self.assertIn("Plan review declined", self.workspace.state()["decline_reason"])

    def test_planning_write_declines_before_implementation(self) -> None:
        (self.workspace.path / "plan-write.txt").write_text("unexpected\n")
        self.workspace.checkpoint("review_plan")
        context = self.workspace.context(
            self.workspace.engine("check-plan-clean", self.workspace.base)
        )
        self.assertFalse(context["plan_tree_clean"])
        self.assertIn("Planning changed", self.workspace.state()["decline_reason"])


class ReviewConsolidationTests(WorkspaceTest):
    def setUp(self) -> None:
        super().setUp()
        self.workspace.start()
        self.workspace.generate()

    def test_all_six_review_lanes_are_required(self) -> None:
        results = self.workspace.review_results()
        results.pop()
        result = self.workspace.engine("record-reviews", json.dumps(results))
        self.assertEqual(result.returncode, 2)
        self.assertIn("required review", result.stderr.decode("utf-8"))

    def test_completeness_paths_must_match_the_derived_set(self) -> None:
        results = self.workspace.review_results(["some_other_file.py"])
        result = self.workspace.engine("record-reviews", json.dumps(results))
        self.assertEqual(result.returncode, 2)
        self.assertIn("different path set", result.stderr.decode("utf-8"))

    def test_clean_consolidation_finalizes(self) -> None:
        self.workspace.record_reviews()
        context = self.workspace.consolidate()
        self.assertEqual(context["review_next"], "clean")
        self.assertEqual(self.workspace.state()["status"], "finalizing")

    def test_verified_findings_route_one_fixup(self) -> None:
        self.workspace.record_reviews()
        context = self.workspace.consolidate(
            {
                "outcome": "fix",
                "summary": "The exploit remains open.",
                "findings": [BLOCKING_FINDING],
            }
        )
        self.assertEqual(context["review_next"], "fix")
        marked = self.workspace.context(self.workspace.engine("mark-fixup"))
        self.assertTrue(marked["fixup_used"])
        self.assertTrue(self.workspace.state()["revision_used"])

    def test_decline_consolidation_stops_without_fixup(self) -> None:
        self.workspace.record_reviews()
        context = self.workspace.consolidate(
            {
                "outcome": "decline",
                "summary": "No safe automated fix exists.",
                "findings": [BLOCKING_FINDING],
            }
        )
        self.assertEqual(context["review_next"], "decline")
        self.assertFalse(self.workspace.state()["revision_used"])

    def test_unchanged_fixup_declines_before_second_review(self) -> None:
        self.workspace.record_reviews()
        self.workspace.consolidate(
            {
                "outcome": "fix",
                "summary": "Repair the remaining path.",
                "findings": [BLOCKING_FINDING],
            }
        )
        self.workspace.context(self.workspace.engine("mark-fixup"))
        self.workspace.checkpoint("fix_review_findings")
        assessed = self.workspace.context(
            self.workspace.engine(
                "assess-change", json.dumps({"summary": "unchanged"})
            )
        )
        self.assertFalse(assessed["declined"])
        pinned = self.workspace.pin()
        self.assertEqual(pinned["pin_next"], "decline")
        self.assertIn("unchanged", self.workspace.state()["decline_reason"])

    def test_changed_fixup_runs_all_six_lanes_again(self) -> None:
        self.workspace.record_reviews()
        self.workspace.consolidate(
            {
                "outcome": "fix",
                "summary": "Repair the remaining path.",
                "findings": [BLOCKING_FINDING],
            }
        )
        self.workspace.context(self.workspace.engine("mark-fixup"))
        (self.workspace.path / "app.py").write_text(
            FIXED_SOURCE.replace("unknown report", "unsupported report"),
            encoding="utf-8",
        )
        self.workspace.checkpoint("fix_review_findings")
        self.workspace.context(
            self.workspace.engine(
                "assess-change", json.dumps({"summary": "fixed review findings"})
            )
        )
        self.assertEqual(self.workspace.pin()["pin_next"], "review")
        recorded = self.workspace.record_reviews()
        self.assertEqual(recorded["review_round"], 2)

    def test_second_fix_request_declines(self) -> None:
        state = self.workspace.state()
        state["consolidation"] = {
            "outcome": "fix",
            "summary": "The second review still found a blocker.",
            "findings": [BLOCKING_FINDING],
        }
        state_path = (
            self.workspace.path
            / ".fabro/workflows/suggest-security-patches/runtime/state.json"
        )
        state_path.write_text(json.dumps(state), encoding="utf-8")
        context = self.workspace.context(self.workspace.engine("decline-repeat-fix"))
        self.assertTrue(context["repeat_fix_declined"])
        self.assertEqual(self.workspace.state()["status"], "declined")


class ReviewedBytesTests(WorkspaceTest):
    """The delivered bytes must be the bytes that were reviewed.

    Every node is followed by a checkpoint that commits whatever the tree
    holds. A reviewer is told not to modify anything, but an instruction is not
    a control: without the fingerprint, a reviewer's own checkpoint would fold
    its writes into the patch after review had already passed.
    """

    def setUp(self) -> None:
        super().setUp()
        self.workspace.start()
        self.workspace.generate()

    def test_fingerprint_is_taken_before_any_reviewer_runs(self) -> None:
        self.assertRegex(
            self.workspace.state()["reviewed_diff_sha256"], r"^[0-9a-f]{64}$"
        )

    def test_a_write_during_review_fanout_stops_the_run(self) -> None:
        (self.workspace.path / "smuggled.py").write_text(
            "BACKDOOR = True\n", encoding="utf-8"
        )
        self.workspace.checkpoint("review")
        result = self.workspace.engine(
            "record-reviews", json.dumps(self.workspace.review_results())
        )
        self.assertEqual(result.returncode, 2)
        self.assertIn("not what was reviewed", result.stderr.decode("utf-8"))

    def test_a_write_during_consolidation_stops_the_run(self) -> None:
        self.workspace.record_reviews()
        (self.workspace.path / "app.py").write_text(
            FIXED_SOURCE + "\nBACKDOOR = True\n", encoding="utf-8"
        )
        self.workspace.checkpoint("consolidate_reviews")
        result = self.workspace.engine(
            "merge-consolidation", json.dumps(CLEAN_CONSOLIDATION)
        )
        self.assertEqual(result.returncode, 2)
        self.assertIn("not what was reviewed", result.stderr.decode("utf-8"))

    def test_a_write_after_consolidation_stops_delivery(self) -> None:
        self.workspace.clean_review()
        (self.workspace.path / "app.py").write_text(
            FIXED_SOURCE + "\nBACKDOOR = True\n", encoding="utf-8"
        )
        self.workspace.checkpoint("late")
        result = self.workspace.engine("finalize", self.workspace.review_pin())
        self.assertEqual(result.returncode, 2)
        self.assertIn("not what was reviewed", result.stderr.decode("utf-8"))
        self.assertFalse(sorted(self.workspace.path.glob("SECURITY-PATCH-*")))

    def test_delivered_patch_hash_equals_the_reviewed_hash(self) -> None:
        self.workspace.clean_review()
        self.workspace.engine("finalize", self.workspace.review_pin())
        record = json.loads(
            (self.workspace.products() / "verdict.json").read_text(encoding="utf-8")
        )
        self.assertEqual(record["patchSha256"], record["reviewedDiffSha256"])


class TrustedPinTests(WorkspaceTest):
    """The expected value must live where agents cannot edit it.

    The state file sits in the checkout the implementer can write, so a
    fingerprint kept only there could be rewritten to match a change made
    afterwards. The pin travels through Fabro's run context instead, which is
    server-side, and finalize trusts it over anything on disk.
    """

    def setUp(self) -> None:
        super().setUp()
        self.workspace.start()
        self.workspace.generate()
        self.workspace.clean_review()

    def rewrite_state(self, **fields) -> None:
        path = (
            self.workspace.path
            / ".fabro/workflows/suggest-security-patches/runtime/state.json"
        )
        state = json.loads(path.read_text(encoding="utf-8"))
        state.update(fields)
        path.write_text(json.dumps(state), encoding="utf-8")

    def smuggle(self) -> None:
        (self.workspace.path / "app.py").write_text(
            FIXED_SOURCE + "\nBACKDOOR = True\n", encoding="utf-8"
        )
        self.workspace.checkpoint("smuggle")

    def test_the_pin_is_emitted_into_context(self) -> None:
        pin = json.loads(self.workspace.review_pin())
        self.assertEqual(pin["base"], self.workspace.base)
        self.assertRegex(pin["diff_sha256"], r"^[0-9a-f]{64}$")

    def test_rewriting_the_state_fingerprint_does_not_help(self) -> None:
        """The attack the review described, end to end."""
        pin = self.workspace.review_pin()
        self.smuggle()
        # The agent updates the state file so its own check would pass.
        forged = ENGINE.sha256_bytes(
            subprocess.run(
                [
                    "git",
                    "diff",
                    "--binary",
                    "--full-index",
                    "--no-ext-diff",
                    "--no-textconv",
                    "--src-prefix=a/",
                    "--dst-prefix=b/",
                    self.workspace.base,
                    "HEAD",
                ],
                cwd=self.workspace.path,
                check=True,
                stdout=subprocess.PIPE,
            ).stdout
        )
        self.rewrite_state(reviewed_diff_sha256=forged)

        result = self.workspace.engine("finalize", pin)
        self.assertEqual(result.returncode, 2)
        self.assertIn("state file was changed", result.stderr.decode("utf-8"))
        self.assertFalse(sorted(self.workspace.path.glob("SECURITY-PATCH-*")))

    def test_rewriting_the_state_base_does_not_help(self) -> None:
        pin = self.workspace.review_pin()
        self.rewrite_state(base="0" * 40)
        result = self.workspace.engine("finalize", pin)
        self.assertEqual(result.returncode, 2)
        self.assertIn("state file was changed", result.stderr.decode("utf-8"))

    def test_a_smuggled_change_is_caught_against_the_pin(self) -> None:
        pin = self.workspace.review_pin()
        self.smuggle()
        result = self.workspace.engine("finalize", pin)
        self.assertEqual(result.returncode, 2)
        self.assertIn("not what was reviewed", result.stderr.decode("utf-8"))

    def test_a_missing_pin_refuses_rather_than_publishing(self) -> None:
        result = self.workspace.engine("finalize", "")
        self.assertEqual(result.returncode, 2)
        self.assertIn("did not reach this step", result.stderr.decode("utf-8"))

    def test_a_forged_pin_must_still_match_the_tree(self) -> None:
        # A pin an agent invented cannot describe the tree it did not review.
        forged = json.dumps(
            {
                "base": self.workspace.base,
                "review_commit": self.workspace.base,
                "diff_sha256": "0" * 64,
            }
        )
        result = self.workspace.engine("finalize", forged)
        self.assertEqual(result.returncode, 2)
        self.assertIn("state file was changed", result.stderr.decode("utf-8"))

    def test_the_graph_feeds_finalize_from_context(self) -> None:
        graph = GRAPH_PATH.read_text(encoding="utf-8")
        node = re.search(r"    finalize \[(.*?)\n    \]", graph, flags=re.S)
        assert node
        self.assertIn('stdin_source="context.review_pin"', node.group(1))


class ForgedBaseTests(WorkspaceTest):
    """A forged base must not turn a rejected change into a published one.

    The state file is in the checkout the implementer can write. Setting its
    base to HEAD makes the change measure as empty, which routes to a decline
    — and a decline that restored to that same forged base would leave the
    change sitting in the run branch for Fabro to open a pull request from.
    Every step whose outcome can reach publication therefore takes the base
    from the run context instead.
    """

    def setUp(self) -> None:
        super().setUp()
        self.workspace.start()

    def forge_base_to_head(self) -> None:
        path = (
            self.workspace.path
            / ".fabro/workflows/suggest-security-patches/runtime/state.json"
        )
        state = json.loads(path.read_text(encoding="utf-8"))
        state["base"] = git(
            "rev-parse", "HEAD", cwd=self.workspace.path
        ).stdout.decode().strip()
        path.write_text(json.dumps(state), encoding="utf-8")

    def final_diff(self) -> str:
        return git(
            "diff", "--stat", f"{self.workspace.base}..HEAD", cwd=self.workspace.path
        ).stdout.decode().strip()

    def test_the_reported_attack_publishes_nothing(self) -> None:
        # 1-3: the generator writes a change and its checkpoint commits it.
        (self.workspace.path / "app.py").write_text(
            FIXED_SOURCE + "\nBACKDOOR = True\n", encoding="utf-8"
        )
        self.workspace.checkpoint("generate")
        # 2: the base is rewritten to HEAD, so the change measures as empty.
        self.forge_base_to_head()
        # 4: the change can no longer be hidden. assess_change measures
        # nothing at all, and pin_review measures against the trusted base, so
        # the forged value has nothing left to lie to.
        self.workspace.context(
            self.workspace.engine(
                "assess-change", json.dumps({"summary": "nothing to do"})
            )
        )
        measured = self.workspace.pin()
        self.assertEqual(
            measured["pin_next"],
            "review",
            "a forged base hid a real change from the run",
        )

        # 5: and a decline, however it is reached, restores against the
        # trusted base rather than the forged one.
        result = self.workspace.engine("no-patch", self.workspace.base)
        self.assertEqual(result.returncode, 0, result.stderr.decode("utf-8"))
        self.workspace.checkpoint("no_patch")

        self.assertEqual(
            self.final_diff(),
            "",
            "a declined run left a change for publication to open a PR from",
        )
        self.assertNotIn(
            "BACKDOOR",
            (self.workspace.path / "app.py").read_text(encoding="utf-8"),
        )

    def test_the_decline_records_that_the_base_disagreed(self) -> None:
        self.workspace.generate()
        self.forge_base_to_head()
        self.workspace.engine("no-patch", self.workspace.base)
        signals = " ".join(self.workspace.state()["tampering_signals"])
        self.assertIn("disagreed with the trusted base", signals)

    def test_pin_review_re_derives_the_change_from_the_trusted_base(self) -> None:
        self.workspace.generate()
        self.forge_base_to_head()
        context = self.workspace.pin()
        self.assertEqual(context["pin_next"], "review")
        pin = json.loads(context["review_pin"])
        self.assertEqual(pin["base"], self.workspace.base)
        self.assertEqual(self.workspace.state()["base"], self.workspace.base)

    def test_pin_review_catches_protected_paths_a_forged_base_hid(self) -> None:
        engine = (
            self.workspace.path
            / ".fabro/workflows/suggest-security-patches/scripts/suggest_patches.py"
        )
        engine.write_text(
            engine.read_text(encoding="utf-8") + "\n# tampered\n", encoding="utf-8"
        )
        self.workspace.checkpoint("generate")
        self.forge_base_to_head()
        context = self.workspace.pin()
        self.assertEqual(context["pin_next"], "decline")
        self.assertIn("support files", self.workspace.state()["decline_reason"])

    def test_a_missing_trusted_base_refuses_rather_than_guessing(self) -> None:
        for command in ("check-plan-clean", "pin-review", "no-patch"):
            with self.subTest(command=command):
                result = self.workspace.engine(command, "")
                self.assertEqual(result.returncode, 2)
                self.assertIn(
                    "did not reach this step", result.stderr.decode("utf-8")
                )

    def test_no_step_that_can_reach_publication_reads_the_state_base(self) -> None:
        """The rule, asserted against the code rather than trusted to review.

        `assess_change` reports what the generator said and measures nothing,
        so it has no base to forge. Every step that restores the tree, decides
        routing, or publishes takes the base from the run context.
        """
        source = ENGINE_PATH.read_text(encoding="utf-8")
        for name in ("assess_change", "no_patch", "pin_review"):
            body = re.search(
                r"\ndef " + name + r"\(\) -> None:\n(.*?)(?=\ndef )",
                source,
                flags=re.S,
            )
            assert body, f"{name} not found"
            with self.subTest(step=name):
                # Reading a base out of state is the hazard. Writing the
                # trusted value back into state is the correction.
                self.assertIsNone(
                    re.search(r'=\s*state(?:\["base"\]|\.get\("base"\))', body.group(1)),
                    f"{name} reads its base from the writable checkout",
                )
        for name in ("no_patch", "pin_review"):
            body = re.search(
                r"\ndef " + name + r"\(\) -> None:\n(.*?)(?=\ndef )",
                source,
                flags=re.S,
            )
            with self.subTest(step=name, expects="trusted base"):
                self.assertIn("read_trusted_base()", body.group(1))

    def test_assess_change_runs_no_git_at_all(self) -> None:
        source = ENGINE_PATH.read_text(encoding="utf-8")
        body = re.search(
            r"\ndef assess_change\(\) -> None:\n(.*?)(?=\ndef )", source, flags=re.S
        )
        assert body
        for forbidden in ("changed_entries(", "diff_bytes(", "diffstat("):
            with self.subTest(call=forbidden):
                self.assertNotIn(forbidden, body.group(1))

    def test_the_graph_feeds_the_trusted_base_to_every_such_step(self) -> None:
        graph = GRAPH_PATH.read_text(encoding="utf-8")
        for node in ("check_plan_clean", "pin_review", "no_patch"):
            with self.subTest(node=node):
                body = re.search(
                    r"    " + node + r" \[(.*?)\n    \]", graph, flags=re.S
                )
                assert body, f"{node} not found"
                self.assertIn(
                    'stdin_source="context.patch_base"',
                    body.group(1),
                    f"{node} reads its base from the writable checkout",
                )


class ReviewedPathsTests(WorkspaceTest):
    """The path cross-check must not pass by saying nothing."""

    def setUp(self) -> None:
        super().setUp()
        self.workspace.start()
        self.workspace.generate()

    def test_empty_reviewed_paths_is_refused(self) -> None:
        result = self.workspace.engine(
            "record-reviews", json.dumps(self.workspace.review_results([]))
        )
        self.assertEqual(result.returncode, 2)
        self.assertIn("no paths", result.stderr.decode("utf-8"))

    def test_a_summary_phrase_is_not_a_path_list(self) -> None:
        result = self.workspace.engine(
            "record-reviews",
            json.dumps(self.workspace.review_results(["reviewed everything"])),
        )
        self.assertEqual(result.returncode, 2)
        self.assertIn("different path set", result.stderr.decode("utf-8"))

    def test_bare_paths_match_the_derived_set(self) -> None:
        context = self.workspace.record_reviews(self.workspace.review_results(["app.py"]))
        self.assertTrue(context["reviews_recorded"])

    def test_the_schema_refuses_an_empty_list(self) -> None:
        schema = json.loads(
            (WORKFLOW_ROOT / "schemas/review-lane.schema.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertEqual(schema["properties"]["reviewedPaths"]["minItems"], 1)


class AwkwardFilenameTests(WorkspaceTest):
    """Paths a reviewer would quote and a naive parser would corrupt."""

    def setUp(self) -> None:
        super().setUp()
        self.workspace.start()

    def test_a_filename_with_spaces_survives_the_changed_set(self) -> None:
        awkward = "src/report generator.py"
        (self.workspace.path / "src").mkdir()
        (self.workspace.path / awkward).write_text("x = 1\n", encoding="utf-8")
        context = self.workspace.generate(source=None)
        self.assertEqual(context["pin_next"], "review")
        self.assertIn(awkward, self.workspace.state()["changed_path_set"])

    def test_a_backslash_is_not_a_directory_separator(self) -> None:
        r"""On Linux `a\b.py` and `a/b.py` are two different files.

        Rewriting separators before comparing would let a path the reviewer
        never looked at satisfy the check for one it did.
        """
        awkward = "weird\\name.py"
        (self.workspace.path / awkward).write_text("x = 1\n", encoding="utf-8")
        self.workspace.generate(source=None)
        result = self.workspace.engine(
            "record-reviews",
            json.dumps(self.workspace.review_results(["weird/name.py"])),
        )
        self.assertEqual(result.returncode, 2)
        self.assertIn("different path set", result.stderr.decode("utf-8"))

    def test_surrounding_whitespace_is_part_of_the_name(self) -> None:
        awkward = " leading.py"
        (self.workspace.path / awkward).write_text("x = 1\n", encoding="utf-8")
        self.workspace.generate(source=None)
        result = self.workspace.engine(
            "record-reviews",
            json.dumps(self.workspace.review_results(["leading.py"])),
        )
        self.assertEqual(result.returncode, 2)

    def test_a_reviewer_can_match_a_spaced_filename_exactly(self) -> None:
        awkward = "src/report generator.py"
        (self.workspace.path / "src").mkdir()
        (self.workspace.path / awkward).write_text("x = 1\n", encoding="utf-8")
        self.workspace.generate(source=FIXED_SOURCE)
        context = self.workspace.record_reviews(
            self.workspace.review_results(["app.py", awkward])
        )
        self.assertTrue(context["reviews_recorded"])


class DeliveryTests(WorkspaceTest):
    def setUp(self) -> None:
        super().setUp()
        self.workspace.start()
        self.workspace.generate()
        self.workspace.clean_review()

    def test_products_carry_the_record_and_the_bytes(self) -> None:
        self.workspace.engine("finalize", self.workspace.review_pin())
        products = self.workspace.products()
        record = json.loads((products / "verdict.json").read_text(encoding="utf-8"))
        payload = (products / "patch.diff").read_bytes()

        self.assertEqual(record["status"], "patch_written")
        self.assertEqual(record["base"], self.workspace.base)
        self.assertEqual(
            record["patchSha256"], hashlib.sha256(payload).hexdigest()
        )
        self.assertTrue(record["untested"])
        self.assertEqual(record["testsRun"], ENGINE.TESTS_RUN_TEXT)
        self.assertEqual(record["reviewRound"], 1)
        self.assertEqual(len(record["reviewLanes"]), 6)
        self.assertEqual(record["consolidation"]["outcome"], "clean")

    def test_patch_applies_to_the_recorded_base(self) -> None:
        self.workspace.engine("finalize", self.workspace.review_pin())
        products = self.workspace.products()
        git("checkout", "-q", self.workspace.base, "--", "app.py", cwd=self.workspace.path)
        subprocess.run(
            ["git", "apply", "--check", str(products / "patch.diff")],
            cwd=self.workspace.path,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

    def test_the_note_leads_with_the_absence_of_tests(self) -> None:
        self.workspace.engine("finalize", self.workspace.review_pin())
        note = (self.workspace.products() / "PATCH.md").read_text(encoding="utf-8")
        heading, remainder = note.split("\n", 1)
        self.assertIn("Reviewed patch", heading)
        self.assertIn("No tests were run", remainder[:400])
        self.assertNotIn("verified patch", note.lower())


class DeclineTests(WorkspaceTest):
    """The invariant that keeps a rejected attempt from becoming a PR."""

    def setUp(self) -> None:
        super().setUp()
        self.workspace.start()
        self.workspace.generate()

    def decline(self) -> subprocess.CompletedProcess:
        state = self.workspace.state()
        state["status"] = "declined"
        state["decline_reason"] = "The verifier could not establish behaviour."
        (
            self.workspace.path
            / ".fabro/workflows/suggest-security-patches/runtime/state.json"
        ).write_text(json.dumps(state), encoding="utf-8")
        return self.workspace.engine("no-patch", self.workspace.base)

    def test_decline_leaves_the_tree_at_base_so_the_final_diff_is_empty(self) -> None:
        self.decline()
        self.workspace.checkpoint("no_patch")
        diff = git(
            "diff",
            "--stat",
            f"{self.workspace.base}..HEAD",
            cwd=self.workspace.path,
        ).stdout.decode()
        self.assertEqual(diff.strip(), "", "a declined run would still open a PR")

    def test_decline_removes_untracked_leftovers(self) -> None:
        # `git reset --hard` would not: this is why the decline path restores
        # and then cleans, and asserts the result.
        (self.workspace.path / "stray.txt").write_text("left behind", encoding="utf-8")
        self.decline()
        self.assertFalse((self.workspace.path / "stray.txt").exists())

    def test_decline_removes_ignored_leftovers_too(self) -> None:
        # An ignored leftover is the one a `git status` check would miss and a
        # "fresh" attempt would silently inherit.
        (self.workspace.path / ".gitignore").write_text(
            "build/\n", encoding="utf-8"
        )
        self.workspace.checkpoint("ignore-rule")
        build = self.workspace.path / "build"
        build.mkdir()
        (build / "cached.bin").write_text("from the rejected attempt", encoding="utf-8")
        self.decline()
        self.assertFalse(build.exists(), "an ignored leftover survived the decline")

    def test_the_engines_own_state_survives_the_sweep(self) -> None:
        self.decline()
        state_path = (
            self.workspace.path
            / ".fabro/workflows/suggest-security-patches/runtime/state.json"
        )
        self.assertTrue(state_path.is_file(), "the engine swept away its own state")

    def test_decline_never_rewinds_the_pushed_branch(self) -> None:
        before = git(
            "rev-parse", "HEAD", cwd=self.workspace.path
        ).stdout.decode().strip()
        self.decline()
        after = git(
            "rev-parse", "HEAD", cwd=self.workspace.path
        ).stdout.decode().strip()
        self.assertEqual(before, after, "HEAD moved, so the next push would fail")

    def test_decline_writes_its_reason_and_the_recommendation(self) -> None:
        self.decline()
        note = (self.workspace.products() / "DECLINED.md").read_text(encoding="utf-8")
        self.assertIn("No patch for F1", note)
        self.assertIn("subprocess with an argument list", note)

class GoalHelperTests(unittest.TestCase):
    def setUp(self) -> None:
        self._temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self._temporary.cleanup)
        self.report = Path(self._temporary.name) / "SECURITY-REVIEW-20260826-000000"
        self.report.mkdir()

    def write(self, *findings: dict) -> Path:
        path = self.report / "SECURITY-REVIEW-RESULTS.jsonl"
        path.write_text(
            "\n".join(json.dumps(finding) for finding in findings) + "\n",
            encoding="utf-8",
        )
        return path

    def finding(self, **overrides) -> dict:
        value = {
            "id": "F1",
            "title": "Command injection",
            "file": "app.py",
            "snippet": "os.system(command)",
            "internalOnly": "dropped",
        }
        value.update(overrides)
        return value

    def test_selects_by_id_and_carries_only_what_the_run_reads(self) -> None:
        self.write(self.finding(), self.finding(id="F2", title="Other"))
        goal = GOAL_HELPER.build(
            GOAL_HELPER.select(
                GOAL_HELPER.load_findings(
                    self.report / "SECURITY-REVIEW-RESULTS.jsonl"
                ),
                "F1",
            )
        )
        self.assertEqual(goal["id"], "F1")
        self.assertNotIn("internalOnly", goal)

    def test_template_delimiter_is_refused_before_any_run(self) -> None:
        with self.assertRaises(GOAL_HELPER.GoalError) as caught:
            GOAL_HELPER.build(self.finding(title="uses {{ user }}"))
        message = str(caught.exception)
        self.assertIn("template delimiter", message)
        self.assertIn("Do not edit the finding", message)

    def test_unknown_id_names_what_is_available(self) -> None:
        self.write(self.finding())
        with self.assertRaises(GOAL_HELPER.GoalError) as caught:
            GOAL_HELPER.select(
                GOAL_HELPER.load_findings(
                    self.report / "SECURITY-REVIEW-RESULTS.jsonl"
                ),
                "F9",
            )
        self.assertIn("F1", str(caught.exception))

    def test_non_id_selection_is_refused(self) -> None:
        self.write(self.finding())
        with self.assertRaises(GOAL_HELPER.GoalError):
            GOAL_HELPER.select([self.finding()], "all")


class GitWrapperTests(unittest.TestCase):
    """The wrapper's hardening is positional, so re-enabling flags must fail.

    Git lets a later flag override an earlier one, so
    `--no-textconv ... --textconv` restores a driver the repository chose and
    runs it. The review wrapper requires isolated Python before import and has
    its own subprocess tests in test_fabro_workflow.py.
    """

    WRAPPERS = (WORKFLOW_ROOT / "scripts/git_readonly.py",)

    def wrapper_modules(self):
        for index, path in enumerate(self.WRAPPERS):
            yield path, load_module(f"fabro_git_wrapper_{index}", path)

    def test_flags_that_re_enable_driver_commands_are_refused(self) -> None:
        for path, module in self.wrapper_modules():
            for argument in ("--textconv", "--ext-diff"):
                with self.subTest(wrapper=path.parent.parent.name, argument=argument):
                    with self.assertRaises(module.GitWrapperError):
                        module.validate_arguments(["diff", argument])

    def test_reading_outside_the_repository_is_refused(self) -> None:
        for path, module in self.wrapper_modules():
            with self.subTest(wrapper=path.parent.parent.name):
                with self.assertRaises(module.GitWrapperError):
                    module.validate_arguments(
                        ["diff", "--no-index", "/etc/passwd", "/etc/hosts"]
                    )

    def test_bare_filesystem_operands_are_refused(self) -> None:
        """Git enters no-index mode on its own, with no flag to blocklist.

        `git diff /etc/passwd /etc/hosts` printed both files before this check
        existed, so refusing the explicit --no-index flag was not enough.
        """
        for path, module in self.wrapper_modules():
            with self.subTest(wrapper=path.parent.parent.name):
                with self.assertRaises(module.GitWrapperError):
                    module.validate_arguments(["diff", "/etc/passwd", "/etc/hosts"])

    def test_relative_escapes_are_refused(self) -> None:
        for path, module in self.wrapper_modules():
            with self.subTest(wrapper=path.parent.parent.name):
                with self.assertRaises(module.GitWrapperError):
                    module.validate_arguments(["show", "../../../../etc/passwd"])

    def test_revision_ranges_are_not_mistaken_for_traversal(self) -> None:
        # `A..B` is one path segment, not a parent reference.
        for path, module in self.wrapper_modules():
            with self.subTest(wrapper=path.parent.parent.name):
                module.validate_arguments(["diff", "HEAD~2..HEAD"])
                module.validate_arguments(["log", "origin/main..HEAD"])

    def test_an_equals_form_is_refused_the_same_way(self) -> None:
        for path, module in self.wrapper_modules():
            with self.subTest(wrapper=path.parent.parent.name):
                with self.assertRaises(module.GitWrapperError):
                    module.validate_arguments(["diff", "--textconv=anything"])

    def test_ordinary_history_reading_still_works(self) -> None:
        for path, module in self.wrapper_modules():
            with self.subTest(wrapper=path.parent.parent.name):
                command = module.build_command(["log", "-n", "1"])
                self.assertIn("--no-ext-diff", command)
                self.assertIn("--no-textconv", command)

    def test_an_inherited_external_diff_driver_is_cleared(self) -> None:
        for path, _ in self.wrapper_modules():
            with self.subTest(wrapper=path.parent.parent.name):
                self.assertIn(
                    '"GIT_EXTERNAL_DIFF": ""',
                    path.read_text(encoding="utf-8"),
                )


class GraphAndConfigurationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.graph = GRAPH_PATH.read_text(encoding="utf-8")

    def test_every_deterministic_node_rechecks_its_support_files(self) -> None:
        scripts = re.findall(r'script="(.*?)"\n', self.graph, flags=re.S)
        engine_scripts = [s for s in scripts if "suggest_patches.py" in s]
        self.assertGreaterEqual(len(engine_scripts), 7)
        for script in engine_scripts:
            self.assertIn("hashlib.sha256", script)
            for relative in PINNED_SUPPORT_FILES:
                self.assertIn(relative, script)

    def test_the_owner_gate_is_a_freeform_hexagon_with_a_decline_default(self) -> None:
        gate = re.search(r"owner_gate \[(.*?)\]", self.graph, flags=re.S)
        assert gate
        body = gate.group(1)
        self.assertIn("shape=hexagon", body)
        self.assertIn('timeout="86400s"', body)
        self.assertIn('human.default_choice="no_patch"', body)
        self.assertIn('on_failure="route"', body)
        self.assertIn("owner_gate -> plan [freeform=true]", self.graph)

    def test_gate_timeout_and_failure_are_routed_by_condition(self) -> None:
        """Neither may fall through to the freeform edge.

        Fabro evaluates conditions first, so routing both here keeps an
        unattended run from looping back into the generator: on timeout the
        handler sets preferred_label to the human.default_choice value, and a
        gate that fails closed arrives as outcome=failed.
        """
        edge = re.search(
            r"owner_gate -> no_patch \[condition=\"(.*?)\"\]", self.graph
        )
        assert edge, "the gate has no conditional route to no_patch"
        condition = edge.group(1)
        self.assertIn("preferred_label=no_patch", condition)
        self.assertIn("outcome=failed", condition)

    def test_revisited_agent_nodes_allow_two_runs(self) -> None:
        for name in (
            "plan",
            "review_plan",
            "review_exploit_closure",
            "review_new_attack_paths",
            "review_compatibility",
            "review_completeness",
            "review_design_economy",
            "review_performance_lifetime",
            "consolidate_reviews",
        ):
            node = re.search(
                r"    " + name + r" \[(.*?)\n    \]", self.graph, flags=re.S
            )
            assert node, name
            self.assertIn("max_visits=3", node.group(1), name)

    def test_native_failure_policies_exit_except_for_the_human_gate(self) -> None:
        self.assertIn('on_failure="exit"', self.graph)
        self.assertNotIn("    abort [", self.graph)
        self.assertNotIn(" -> abort", self.graph)
        self.assertIn('owner_gate [', self.graph)
        self.assertIn('on_failure="route"', self.graph)
        self.assertIn("    prepare -> exit\n", self.graph)
        self.assertIn("    check_plan_clean -> exit\n", self.graph)
        self.assertIn("    assess_change -> exit\n", self.graph)
        self.assertIn("    pin_review -> exit\n", self.graph)
        self.assertIn("    merge_consolidation -> exit\n", self.graph)

    def test_every_terminal_path_reaches_exit(self) -> None:
        for node in ("finalize", "no_patch"):
            self.assertIn(f"    {node} -> exit\n", self.graph)

    def test_configurations_disable_repository_hooks_at_checkpoint(self) -> None:
        for name in CONFIGS:
            settings = tomllib.loads(
                (WORKFLOW_ROOT / name).read_text(encoding="utf-8")
            )
            self.assertTrue(
                settings["run"]["checkpoint"]["skip_git_hooks"],
                f"{name} must not let repository hooks run at checkpoint",
            )

    def test_products_never_ride_in_the_pull_request_diff(self) -> None:
        for name in CONFIGS:
            settings = tomllib.loads(
                (WORKFLOW_ROOT / name).read_text(encoding="utf-8")
            )
            excluded = settings["run"]["checkpoint"]["exclude_globs"]
            self.assertIn("SECURITY-PATCH-*/**", excluded, name)

    def test_default_configuration_opens_a_draft_pull_request(self) -> None:
        settings = tomllib.loads(
            (WORKFLOW_ROOT / "workflow.toml").read_text(encoding="utf-8")
        )
        self.assertTrue(settings["run"]["pull_request"]["enabled"])
        self.assertTrue(settings["run"]["pull_request"]["draft"])

    def test_smoke_configuration_commits_without_pushing(self) -> None:
        settings = tomllib.loads(
            (WORKFLOW_ROOT / "verify.toml").read_text(encoding="utf-8")
        )
        self.assertFalse(settings["run"]["pull_request"]["enabled"])
        self.assertTrue(settings["run"]["run_branch"]["enabled"])
        self.assertFalse(settings["run"]["run_branch"]["push"])
        self.assertTrue(settings["run"]["meta_branch"]["enabled"])
        self.assertFalse(settings["run"]["meta_branch"]["push"])

    def test_embargo_configuration_publishes_nothing(self) -> None:
        settings = tomllib.loads(
            (WORKFLOW_ROOT / "workflow-embargo.toml").read_text(encoding="utf-8")
        )
        self.assertFalse(settings["run"]["pull_request"]["enabled"])
        self.assertFalse(settings["run"]["run_branch"]["push"])
        self.assertFalse(settings["run"]["meta_branch"]["push"])

    def test_no_configuration_requests_a_github_token(self) -> None:
        for name in CONFIGS:
            settings = tomllib.loads(
                (WORKFLOW_ROOT / name).read_text(encoding="utf-8")
            )
            integrations = settings["run"].get("integrations", {})
            self.assertNotIn("github", integrations, name)
            self.assertEqual(settings["run"]["environment"]["env"]["GITHUB_TOKEN"], "")

    def test_schemas_declare_their_dialect(self) -> None:
        for path in sorted((WORKFLOW_ROOT / "schemas").glob("*.json")):
            schema = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(
                schema["$schema"],
                "https://json-schema.org/draft/2020-12/schema",
                path.name,
            )

    def test_the_shipped_fixture_finding_is_valid_input(self) -> None:
        finding = json.loads(FIXTURE_FINDING.read_text(encoding="utf-8"))
        normalized = ENGINE.validate_finding(finding)
        self.assertEqual(normalized["id"], "F1")
        self.assertTrue(
            (REPOSITORY_ROOT / normalized["file"]).is_file(),
            "the fixture finding must point at a file that exists",
        )

    def test_smoke_fixture_exception_is_consistent_in_editing_prompts(self) -> None:
        for name in ("generate.md.j2", "fix-review-findings.md.j2"):
            prompt = (WORKFLOW_ROOT / "prompts" / name).read_text(encoding="utf-8")
            self.assertIn("except its `fixtures/` directory", prompt, name)

    def test_uses_gpt_sol_with_opus_then_kimi_fallbacks(self) -> None:
        stylesheet = re.search(
            r'model_stylesheet="(.*?)"', self.graph, flags=re.S
        )
        assert stylesheet
        self.assertIn("* { model: gpt-sol;", stylesheet.group(1))
        self.assertIn(
            ".planning { reasoning_effort: xhigh; }", stylesheet.group(1)
        )
        self.assertIn(
            ".consolidation { reasoning_effort: xhigh; }", stylesheet.group(1)
        )
        self.assertNotIn("model: kimi-k3", stylesheet.group(1))
        fixup = re.search(
            r"    fix_review_findings \[(.*?)\n    \]", self.graph, flags=re.S
        )
        assert fixup
        self.assertIn('reasoning_effort="xhigh"', fixup.group(1))

        expected = [
            "anthropic:claude-opus-5",
            "openrouter:claude-opus-5",
            "moonshot:kimi-k3",
            "openrouter:kimi-k3",
        ]
        for name in CONFIGS:
            settings = tomllib.loads(
                (WORKFLOW_ROOT / name).read_text(encoding="utf-8")
            )
            self.assertEqual(settings["run"]["model"]["fallbacks"]["gpt-sol"], expected)

    def test_a_surviving_original_exploit_is_always_blocking(self) -> None:
        prompt = (
            WORKFLOW_ROOT / "prompts/review-exploit-closure.md.j2"
        ).read_text(encoding="utf-8")
        self.assertIn(
            "A surviving original exploit is always a\nblocking finding",
            prompt,
        )

    def test_products_never_call_the_result_verified(self) -> None:
        engine_source = ENGINE_PATH.read_text(encoding="utf-8")
        self.assertIn("Reviewed patch", engine_source)
        self.assertTrue(ENGINE.TESTS_RUN_TEXT.startswith("none"))


if __name__ == "__main__":
    unittest.main()
