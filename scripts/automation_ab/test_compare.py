#!/usr/bin/env python3

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from scripts.automation_ab.compare import compare


def _write_result(path: Path, **details: object) -> None:
    path.write_text(
        json.dumps(
            {
                "results": [
                    {
                        "success": details.pop("runner_success", True),
                        "details": {
                            "case": "automation_ab_happy_path",
                            **details,
                        },
                    }
                ]
            }
        ),
        encoding="utf-8",
    )


class AutomationAbCompareTest(unittest.TestCase):
    def _paths(self, tmp: str) -> tuple[Path, Path]:
        return Path(tmp) / "baseline.json", Path(tmp) / "candidate.json"

    def test_passes_when_candidate_adds_contract_and_preserves_outcome(self):
        with tempfile.TemporaryDirectory() as tmp:
            baseline_path, candidate_path = self._paths(tmp)
            common = {
                "scheduled_run_completed": True,
                "final_reply_persisted": True,
                "semantic_result_correct": True,
                "exact_result_match": True,
            }
            _write_result(
                baseline_path, execution_contract_present=False, **common
            )
            _write_result(
                candidate_path, execution_contract_present=True, **common
            )
            report = compare(baseline_path, candidate_path)
            self.assertEqual(report["status"], "pass")
            self.assertTrue(report["contract_evidence_improved"])
            self.assertFalse(report["semantic_quality_improved"])

    def test_fails_when_candidate_answer_is_semantically_wrong(self):
        with tempfile.TemporaryDirectory() as tmp:
            baseline_path, candidate_path = self._paths(tmp)
            _write_result(
                baseline_path,
                execution_contract_present=False,
                scheduled_run_completed=True,
                final_reply_persisted=True,
                semantic_result_correct=True,
                exact_result_match=False,
            )
            _write_result(
                candidate_path,
                execution_contract_present=True,
                scheduled_run_completed=True,
                final_reply_persisted=True,
                semantic_result_correct=False,
                exact_result_match=False,
            )
            report = compare(baseline_path, candidate_path)
            self.assertEqual(report["status"], "fail")

    def test_blocks_when_baseline_cannot_produce_observable_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            baseline_path, candidate_path = self._paths(tmp)
            _write_result(
                baseline_path,
                execution_contract_present=False,
                scheduled_run_completed=False,
                final_reply_persisted=False,
                semantic_result_correct=False,
                exact_result_match=False,
            )
            _write_result(
                candidate_path,
                execution_contract_present=True,
                scheduled_run_completed=True,
                final_reply_persisted=True,
                semantic_result_correct=True,
                exact_result_match=True,
            )
            report = compare(baseline_path, candidate_path)
            self.assertEqual(report["status"], "blocked")


if __name__ == "__main__":
    unittest.main()
