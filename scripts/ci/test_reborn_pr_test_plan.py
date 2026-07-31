#!/usr/bin/env python3
"""Contract tests for affected-area Reborn PR test planning."""

from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = ROOT / "scripts/ci/reborn_pr_test_plan.py"
SPEC = importlib.util.spec_from_file_location("reborn_pr_test_plan", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
planner = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = planner
SPEC.loader.exec_module(planner)


def metadata() -> dict:
    root = str(ROOT / "Cargo.toml")
    alpha = str(ROOT / "crates/alpha/Cargo.toml")
    beta = str(ROOT / "crates/beta/Cargo.toml")
    gamma = str(ROOT / "crates/gamma/Cargo.toml")
    return {
        "workspace_members": ["root", "alpha", "beta", "gamma"],
        "packages": [
            {"id": "root", "name": "ironclaw_reborn_integration_tests", "manifest_path": root},
            {"id": "alpha", "name": "alpha", "manifest_path": alpha},
            {"id": "beta", "name": "beta", "manifest_path": beta},
            {"id": "gamma", "name": "gamma", "manifest_path": gamma},
        ],
        "resolve": {
            "nodes": [
                {"id": "root", "deps": [{"pkg": "gamma"}]},
                {"id": "alpha", "deps": []},
                {"id": "beta", "deps": [{"pkg": "alpha"}]},
                {"id": "gamma", "deps": [{"pkg": "beta"}]},
            ]
        },
    }


class RebornPrTestPlanTests(unittest.TestCase):
    def setUp(self) -> None:
        self.original_bucket_packages = planner._bucket_packages
        planner._bucket_packages = lambda packages: (
            [{"name": "selected", "packages": packages}] if packages else []
        )
        self.canonical = ["alpha", "beta", "gamma"]

    def tearDown(self) -> None:
        planner._bucket_packages = self.original_bucket_packages

    def plan(self, event: str, paths: list[str]) -> dict:
        return planner.build_plan(
            event=event,
            changed_paths=paths,
            metadata=metadata(),
            canonical_packages=self.canonical,
        )

    def test_merge_queue_is_always_exhaustive(self) -> None:
        plan = self.plan("merge_group", ["crates/alpha/src/lib.rs"])
        self.assertEqual(plan["mode"], "full")
        self.assertEqual(plan["coverage_mode"], "full")
        self.assertEqual(plan["root_partitions"], [0, 1, 2, 3])
        self.assertEqual(plan["integration_lanes"], [0, 1, 2, 3, "groups"])

    def test_changed_package_includes_reverse_dependents(self) -> None:
        plan = self.plan("pull_request", ["crates/alpha/src/lib.rs"])
        self.assertEqual(plan["mode"], "selected")
        self.assertEqual(plan["changed_packages"], ["alpha"])
        self.assertEqual(plan["affected_packages"], ["alpha", "beta"])
        self.assertEqual(
            plan["crate_buckets"],
            [{"name": "selected", "packages": ["alpha", "beta"]}],
        )
        self.assertNotIn("gamma", plan["affected_packages"])
        self.assertEqual(plan["coverage_mode"], "none")

    def test_high_fanout_package_defers_consumers_to_merge_queue(self) -> None:
        wide = metadata()
        for index in range(5):
            package_id = f"consumer-{index}"
            package_name = f"consumer_{index}"
            wide["workspace_members"].append(package_id)
            wide["packages"].append(
                {
                    "id": package_id,
                    "name": package_name,
                    "manifest_path": str(
                        ROOT / f"crates/{package_name}/Cargo.toml"
                    ),
                }
            )
            wide["resolve"]["nodes"].append(
                {"id": package_id, "deps": [{"pkg": "alpha"}]}
            )
        canonical = ["alpha"] + [f"consumer_{index}" for index in range(5)]
        planner._bucket_packages = lambda packages: [
            {"name": package, "packages": [package]} for package in packages
        ]

        plan = planner.build_plan(
            event="pull_request",
            changed_paths=["crates/alpha/src/lib.rs"],
            metadata=wide,
            canonical_packages=canonical,
        )

        self.assertEqual(plan["affected_packages"], ["alpha"])
        self.assertIn("three-bucket PR budget", plan["reasons"][-1])

    def test_frontend_only_change_runs_only_frontend(self) -> None:
        plan = self.plan(
            "pull_request", ["crates/ironclaw_webui/frontend/src/app.tsx"]
        )
        self.assertEqual(plan["mode"], "selected")
        self.assertTrue(plan["run_frontend"])
        self.assertEqual(plan["crate_buckets"], [])
        self.assertEqual(plan["integration_lanes"], [])

    def test_nested_crate_markdown_remains_package_owned(self) -> None:
        plan = self.plan("pull_request", ["crates/alpha/README.md"])
        self.assertEqual(plan["changed_packages"], ["alpha"])
        self.assertNotEqual(plan["mode"], "none")

    def test_recorded_fixture_change_runs_only_qa_replay(self) -> None:
        plan = self.plan(
            "pull_request",
            ["tests/fixtures/llm_traces/reborn_qa/example.json"],
        )
        self.assertEqual(plan["mode"], "selected")
        self.assertTrue(plan["run_qa_replay"])
        self.assertEqual(plan["crate_buckets"], [])

    def test_unrelated_workflow_change_runs_no_reborn_lane(self) -> None:
        plan = self.plan("pull_request", [".github/workflows/code_style.yml"])
        self.assertEqual(plan["mode"], "none")

    def test_reborn_workflow_change_is_deferred_to_required_queue(self) -> None:
        plan = self.plan("pull_request", [".github/workflows/reborn-tests.yml"])
        self.assertEqual(plan["mode"], "deferred")
        self.assertEqual(plan["crate_buckets"], [])

    def test_generated_integration_suites_are_assigned_to_flat_lanes(self) -> None:
        lanes = planner._integration_test_lanes()
        self.assertIn("tests/integration/generated_gate_sequences.rs", lanes)
        self.assertIn("tests/integration/generated_restart_sequences.rs", lanes)
        self.assertIsInstance(
            lanes["tests/integration/generated_gate_sequences.rs"], int
        )
        lane_runner = (
            ROOT / "scripts/ci/reborn-coverage-lane-run.sh"
        ).read_text(encoding="utf-8")
        self.assertIn("reborn_(integration_|generated_)", lane_runner)

    def test_unmapped_crate_path_defers_to_merge_queue(self) -> None:
        plan = self.plan("pull_request", ["crates/deleted/src/lib.rs"])
        self.assertEqual(plan["mode"], "deferred")

    def test_unclassified_build_input_defers_to_merge_queue(self) -> None:
        plan = self.plan("pull_request", ["Dockerfile"])
        self.assertEqual(plan["mode"], "deferred")

    def test_changed_integration_binary_selects_its_exact_lane(self) -> None:
        path, lane = next(iter(planner._integration_test_lanes().items()))
        plan = self.plan("pull_request", [path])
        self.assertEqual(plan["mode"], "selected")
        self.assertEqual(plan["integration_lanes"], [lane])

    def test_workflow_consumes_plan_and_bounds_each_rust_matrix(self) -> None:
        workflow = (ROOT / ".github/workflows/reborn-tests.yml").read_text(
            encoding="utf-8"
        )
        self.assertIn("python3 scripts/ci/reborn_pr_test_plan.py", workflow)
        self.assertIn("scripts/ci/discover-reborn-package-crates.sh", workflow)
        self.assertIn("--canonical-packages", workflow)
        self.assertIn("needs.changes.outputs.crate_buckets", workflow)
        self.assertIn("needs.changes.outputs.root_partitions", workflow)
        self.assertIn("needs.changes.outputs.integration_lanes", workflow)
        self.assertIn(
            "max-parallel: ${{ github.event_name == 'pull_request' && 3 || 14 }}",
            workflow,
        )
        self.assertIn(
            "max-parallel: ${{ github.event_name == 'pull_request' && 1 || 4 }}",
            workflow,
        )
        self.assertIn(
            "max-parallel: ${{ github.event_name == 'pull_request' && 1 || 5 }}",
            workflow,
        )
        self.assertIn("github.event.merge_group.base_sha", workflow)
        self.assertIn(
            "ran with result '${result}' despite planned=false",
            workflow,
        )


if __name__ == "__main__":
    unittest.main()
