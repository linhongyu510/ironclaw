#!/usr/bin/env python3

import unittest

from scripts.automation_ab.corpus import CASES, deterministic_checks


class SemanticCorpusTest(unittest.TestCase):
    def test_has_eight_unique_natural_language_cases(self):
        self.assertEqual(len(CASES), 8)
        self.assertEqual(len({case.case_id for case in CASES}), 8)
        serialized = " ".join(
            f"{case.task} {case.reference_data}" for case in CASES
        ).lower()
        for internal in ("trigger_create", "execution_contract", "capability_id"):
            self.assertNotIn(internal, serialized)

    def test_deterministic_checks_enforce_required_and_forbidden_facts(self):
        case = CASES[0]
        passing = (
            "Checkout has been degraded for 12 minutes. Payments are healthy. "
            "The root cause remains unknown."
        )
        self.assertTrue(deterministic_checks(case, passing)["passed"])
        failing = "Checkout is degraded. Root cause confirmed: payments."
        result = deterministic_checks(case, failing)
        self.assertFalse(result["passed"])
        self.assertTrue(result["missing_required_groups"])
        self.assertEqual(result["forbidden_found"], ["root cause confirmed"])


if __name__ == "__main__":
    unittest.main()
