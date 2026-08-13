#!/usr/bin/env python3

import unittest

from scripts.automation_ab.benchmark import aggregate, wilson_interval


def _record(arm: str, repetition: int, case_id: str, *, passed: bool = True):
    return {
        "arm": arm,
        "repetition": repetition,
        "benchmark_id": case_id,
        "deterministic": {"passed": passed},
        "semantic_passed": passed,
        "execution_contract_present": arm == "candidate",
        "created": True,
        "scheduled_run_completed": True,
        "final_reply_persisted": True,
        "answer": f"{arm} answer",
        "natural_prompt": "Please prepare the report.",
        "criteria": ["Be correct"],
    }


class SemanticBenchmarkTest(unittest.TestCase):
    def test_wilson_interval_is_bounded(self):
        low, high = wilson_interval(8, 10)
        self.assertGreater(low, 0)
        self.assertLess(high, 1)
        self.assertLess(low, 0.8)
        self.assertGreater(high, 0.8)

    def test_reports_improvement_only_with_confident_blind_wins(self):
        records = []
        for repetition in range(1, 6):
            for index in range(8):
                case_id = f"case-{index}"
                records.extend(
                    [
                        _record("baseline", repetition, case_id),
                        _record("candidate", repetition, case_id),
                    ]
                )
        report = aggregate(
            records,
            lambda _baseline, _candidate, _repetition: {"winner": "candidate"},
        )
        self.assertEqual(report["status"], "improved")
        self.assertEqual(report["pair_count"], 40)
        self.assertGreater(report["candidate_win_rate_95ci"][0], 0.5)

    def test_candidate_hard_regression_overrides_pairwise_wins(self):
        records = [
            _record("baseline", 1, "case"),
            _record("candidate", 1, "case", passed=False),
        ]
        report = aggregate(
            records,
            lambda _baseline, _candidate, _repetition: {"winner": "candidate"},
        )
        self.assertEqual(report["status"], "regressed")
        self.assertEqual(report["regression_count"], 1)

    def test_neutral_result_is_not_mislabeled_improvement(self):
        records = [
            _record("baseline", 1, "one"),
            _record("candidate", 1, "one"),
            _record("baseline", 1, "two"),
            _record("candidate", 1, "two"),
        ]
        winners = iter(("candidate", "baseline"))
        report = aggregate(
            records,
            lambda _baseline, _candidate, _repetition: {"winner": next(winners)},
        )
        self.assertEqual(report["status"], "no_regression")


if __name__ == "__main__":
    unittest.main()
