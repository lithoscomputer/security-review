"""Focused tests for suggest_patches.py review routing."""

import importlib.util
import json
import unittest
from pathlib import Path
from unittest import mock


SCRIPT = Path(__file__).with_name("suggest_patches.py")
SPEC = importlib.util.spec_from_file_location("suggest_patches", SCRIPT)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def review_results():
    results = []
    for branch_id, output_key, lane in MODULE.REVIEW_LANES:
        output = {
            "summary": f"{lane} checked",
            "findings": [],
            "residualRisks": [],
        }
        if lane == "patch-completeness-evidence":
            output["reviewedPaths"] = ["src/example.py"]
        results.append(
            {
                "id": branch_id,
                "status": "succeeded",
                "context_updates": {output_key: output},
            }
        )
    return results


class ReviewResultTests(unittest.TestCase):
    def test_requires_all_seven_review_lanes(self):
        results = review_results()
        results.pop()
        with self.assertRaisesRegex(MODULE.WorkflowDataError, "required review"):
            MODULE.parse_review_results(json.dumps(results))

    def test_keeps_completeness_paths(self):
        lanes = MODULE.parse_review_results(json.dumps(review_results()))
        self.assertEqual(
            lanes["patch-completeness-evidence"]["reviewedPaths"],
            ["src/example.py"],
        )

    def test_keeps_residual_risks_separate_from_findings(self):
        results = review_results()
        residual_risk = {
            "issue": "older state remains",
            "evidence": "src/example.py:10",
            "recommendedAction": "retire it separately",
        }
        results[0]["context_updates"]["output.review_exploit_closure"][
            "residualRisks"
        ] = [residual_risk]
        lanes = MODULE.parse_review_results(json.dumps(results))
        self.assertEqual(lanes["exploit-closure"]["findings"], [])
        self.assertEqual(
            lanes["exploit-closure"]["residualRisks"],
            [residual_risk],
        )


class ConsolidationTests(unittest.TestCase):
    def run_merge(self, state, result):
        emitted = mock.Mock()
        with mock.patch.object(MODULE, "guard", return_value=state), \
                mock.patch.object(MODULE, "advisory_diff_check"), \
                mock.patch.object(
                    MODULE, "read_stdin_text", return_value=json.dumps(result)
                ), \
                mock.patch.object(MODULE, "save_state"), \
                mock.patch.object(MODULE, "emit", emitted):
            MODULE.merge_consolidation()
        return emitted

    def test_clean_review_finalizes(self):
        state = {"review_round": 1, "revision_used": False}
        residual_risk = {
            "lane": "exploit-closure",
            "issue": "older state remains",
            "evidence": "src/example.py:10",
            "recommendedAction": "retire it separately",
        }
        emitted = self.run_merge(
            state,
            {
                "outcome": "clean",
                "summary": "no blocking findings remain",
                "findings": [],
                "residualRisks": [residual_risk],
            },
        )
        self.assertEqual(state["status"], "finalizing")
        self.assertEqual(state["consolidation"]["residualRisks"], [residual_risk])
        emitted.assert_called_once_with(review_next="clean")

    def test_review_with_findings_routes_a_fixup_below_the_limit(self):
        state = {"review_round": 4, "fixup_count": 3, "revision_used": True}
        finding = {
            "lane": "exploit-closure",
            "issue": "exploit remains",
            "evidence": "src/example.py:10",
            "requiredChange": "close the remaining path",
        }
        emitted = self.run_merge(
            state,
            {
                "outcome": "fix",
                "summary": "repair",
                "findings": [finding],
                "residualRisks": [],
            },
        )
        self.assertEqual(state["status"], "awaiting_review_fixup")
        emitted.assert_called_once_with(review_next="fix")

    def test_user_facing_finding_changes_behavior_confidence(self):
        state = {"review_round": 1, "revision_used": False}
        finding = {
            "lane": "user-facing-behavior",
            "issue": "The changed state misstates the outcome.",
            "evidence": "src/example.py:10",
            "requiredChange": "Describe the actual outcome.",
        }
        self.run_merge(
            state,
            {
                "outcome": "fix",
                "summary": "repair the user-facing state",
                "findings": [finding],
                "residualRisks": [],
            },
        )
        self.assertEqual(state["claims"]["behaviourUnchanged"]["state"], "NOT_CONFIDENT")

    def test_residual_risks_cannot_route_a_fix(self):
        state = {"review_round": 1, "revision_used": False}
        with self.assertRaisesRegex(
            MODULE.WorkflowDataError,
            "fix consolidation must retain findings",
        ):
            self.run_merge(
                state,
                {
                    "outcome": "fix",
                    "summary": "repair older state",
                    "findings": [],
                    "residualRisks": [
                        {
                            "lane": "exploit-closure",
                            "issue": "older state remains",
                            "evidence": "src/example.py:10",
                            "recommendedAction": "retire it separately",
                        }
                    ],
                },
            )

    def test_mark_fixup_records_the_server_routing_state(self):
        state = {"fixup_count": 0, "revision_used": False}
        emitted = mock.Mock()
        with mock.patch.object(MODULE, "guard", return_value=state), \
                mock.patch.object(MODULE, "save_state"), \
                mock.patch.object(MODULE, "emit", emitted):
            MODULE.mark_fixup()
        self.assertTrue(state["revision_used"])
        self.assertEqual(state["fixup_count"], 1)
        emitted.assert_called_once_with(fixup_count=1, fixup_used=True)

    def test_findings_after_four_fixups_finalize_the_patch(self):
        state = {"review_round": 5, "fixup_count": 4, "revision_used": True}
        finding = {
            "lane": "exploit-closure",
            "issue": "exploit remains",
            "evidence": "src/example.py:10",
            "requiredChange": "close the remaining path",
        }
        emitted = self.run_merge(
            state,
            {
                "outcome": "fix",
                "summary": "pending repair",
                "findings": [finding],
                "residualRisks": [],
            },
        )
        self.assertEqual(state["status"], "finalizing")
        self.assertEqual(state["objections"], [finding])
        emitted.assert_called_once_with(review_next="finalize")


if __name__ == "__main__":
    unittest.main()
