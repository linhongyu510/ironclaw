#!/usr/bin/env python3
"""Select focused Reborn test lanes for pull requests.

Pull requests run direct evidence for changed packages and test surfaces.
Merge-queue, main, and manual runs remain exhaustive.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import tomllib
from collections import defaultdict
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
MAX_PR_CRATE_BUCKETS = 3
FULL_EVENTS = {"merge_group", "push", "workflow_call", "workflow_dispatch", "schedule"}
IGNORED_PREFIXES = ("docs/", ".github/ISSUE_TEMPLATE/")
FULL_PATHS = {
    "Cargo.toml",
    "Cargo.lock",
    "rust-toolchain",
    "rust-toolchain.toml",
    ".cargo/config",
    ".cargo/config.toml",
    ".github/workflows/reborn-tests.yml",
    "scripts/ci/reborn_pr_test_plan.py",
    "scripts/ci/test_reborn_pr_test_plan.py",
    "scripts/ci/discover-reborn-package-crates.sh",
    "scripts/ci/reborn-crate-test-buckets.sh",
    "scripts/ci/package-feature-flags.sh",
    "scripts/ci/run-hermetic-deterministic-suite.sh",
    "scripts/ci/run-reborn-root-partition.sh",
    "scripts/ci/run-reborn-group-tests.sh",
    "scripts/ci/reborn-coverage-int-tier-tests.sh",
    "scripts/ci/reborn-coverage-lane-run.sh",
}


def _run(*argv: str) -> str:
    return subprocess.run(
        argv,
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def _metadata() -> dict[str, Any]:
    return json.loads(_run("cargo", "metadata", "--format-version", "1"))


def _canonical_packages() -> list[str]:
    return json.loads(_run("scripts/ci/discover-reborn-package-crates.sh"))


def _bucket_packages(packages: list[str]) -> list[dict[str, Any]]:
    return json.loads(
        _run("scripts/ci/reborn-crate-test-buckets.sh", json.dumps(packages))
    )


def _root_test_partitions() -> dict[str, int]:
    support_tests = (
        ["support_unit_tests"]
        if (ROOT / "tests/support_unit_tests.rs").is_file()
        else []
    )
    names = sorted(
        [
            path.stem
            for path in (ROOT / "tests").glob("reborn_*.rs")
            if path.is_file()
        ]
        + support_tests
    )
    return {f"tests/{name}.rs": index % 4 for index, name in enumerate(names)}


def _integration_test_lanes() -> dict[str, str | int]:
    with (ROOT / "Cargo.toml").open("rb") as manifest:
        data = tomllib.load(manifest)
    tests = {
        entry["path"]: entry["name"]
        for entry in data.get("test", [])
        if isinstance(entry, dict)
        and isinstance(entry.get("name"), str)
        and isinstance(entry.get("path"), str)
        and entry["path"].startswith("tests/integration/")
    }
    flat_names = sorted(
        name
        for name in tests.values()
        if name.startswith(("reborn_integration_", "reborn_generated_"))
    )
    flat_lanes = {name: index % 4 for index, name in enumerate(flat_names)}
    return {
        path: "groups" if name.startswith("reborn_group_") else flat_lanes[name]
        for path, name in tests.items()
    }


def _workspace_packages(metadata: dict[str, Any]) -> tuple[dict[str, str], dict[str, set[str]]]:
    members = set(metadata["workspace_members"])
    packages_by_id = {
        package["id"]: package
        for package in metadata["packages"]
        if package["id"] in members
    }
    directories = {
        str(Path(package["manifest_path"]).resolve().parent.relative_to(ROOT)): package[
            "name"
        ]
        for package in packages_by_id.values()
        if Path(package["manifest_path"]).resolve().parent != ROOT
    }
    reverse: dict[str, set[str]] = defaultdict(set)
    for node in metadata["resolve"]["nodes"]:
        if node["id"] not in packages_by_id:
            continue
        dependent = packages_by_id[node["id"]]["name"]
        for dependency in node["deps"]:
            if dependency["pkg"] in packages_by_id:
                reverse[packages_by_id[dependency["pkg"]]["name"]].add(dependent)
    return directories, reverse


def _affected_packages(changed: set[str], reverse: dict[str, set[str]]) -> set[str]:
    # PR feedback covers the changed package and its immediate contract
    # consumers. Transitive consumers and whole-path suites run exhaustively
    # in the required merge queue, avoiding a near-workspace-wide PR fanout
    # for low-level crates.
    return set(changed).union(
        *(reverse.get(package, set()) for package in changed)
    )


def _full_plan(
    reason: str,
    canonical_packages: list[str],
) -> dict[str, Any]:
    return {
        "mode": "full",
        "reasons": [reason],
        "changed_packages": [],
        "affected_packages": canonical_packages,
        "crate_buckets": _bucket_packages(canonical_packages),
        "root_partitions": [0, 1, 2, 3],
        "integration_lanes": [0, 1, 2, 3, "groups"],
        "run_group_tests": True,
        "run_frontend": True,
        "run_qa_replay": True,
        "coverage_mode": "full",
    }


def build_plan(
    *,
    event: str,
    changed_paths: list[str],
    metadata: dict[str, Any],
    canonical_packages: list[str],
) -> dict[str, Any]:
    """Build a deterministic test plan, failing open on unknown Reborn inputs."""
    if event in FULL_EVENTS:
        return _full_plan(f"{event} requires exhaustive coverage", canonical_packages)
    if event != "pull_request":
        return _full_plan(f"unknown event {event!r}", canonical_packages)

    paths = {path.strip().replace("\\", "/") for path in changed_paths if path.strip()}
    if not paths:
        return _full_plan("empty pull-request diff", canonical_packages)
    if any(path in FULL_PATHS for path in paths):
        return _full_plan(
            "Reborn test infrastructure or workspace topology changed",
            canonical_packages,
        )

    package_directories, reverse = _workspace_packages(metadata)
    changed_packages: set[str] = set()
    root_partitions: set[int] = set()
    integration_lanes: set[str | int] = set()
    run_frontend = False
    run_qa_replay = False
    reasons: list[str] = []
    root_inventory = _root_test_partitions()
    integration_inventory = _integration_test_lanes()

    for path in sorted(paths):
        if path.startswith(IGNORED_PREFIXES) or (
            path.endswith(".md") and "/" not in path
        ):
            continue
        if path.startswith(".github/workflows/"):
            continue
        if path.startswith("crates/ironclaw_webui/frontend/"):
            run_frontend = True
            reasons.append("WebUI frontend changed")
            continue
        if path in root_inventory:
            root_partitions.add(root_inventory[path])
            reasons.append(f"root test changed: {path}")
            continue
        if (
            path.startswith("tests/support/reborn_parity_qa/")
            or path == "tests/support_unit_tests.rs"
        ):
            root_partitions.update(range(4))
            reasons.append("shared root-test support changed")
            continue
        if path in integration_inventory:
            integration_lanes.add(integration_inventory[path])
            reasons.append(f"integration test changed: {path}")
            continue
        if path.startswith("tests/integration/"):
            integration_lanes.update([0, 1, 2, 3, "groups"])
            reasons.append("shared integration support changed")
            continue
        if path.startswith("tests/fixtures/llm_traces/reborn_qa/") or path in {
            "scripts/ci/check-reborn-qa-fixtures.sh",
            "scripts/ci/test-check-reborn-qa-fixtures.sh",
            "scripts/ci/test-check-regression-promotions.py",
        }:
            run_qa_replay = True
            reasons.append("recorded QA evidence changed")
            continue
        if path.startswith("crates/"):
            package = next(
                (
                    name
                    for directory, name in package_directories.items()
                    if path == directory or path.startswith(f"{directory}/")
                ),
                None,
            )
            if package is None:
                return _full_plan(f"unmapped crate path: {path}", canonical_packages)
            changed_packages.add(package)
            reasons.append(f"production package changed: {package}")
            continue
        if path.startswith(("tests/reborn_", "tests/e2e/reborn_", "scripts/ci/reborn-")):
            return _full_plan(f"unmapped Reborn test path: {path}", canonical_packages)
        if path.startswith(("scripts/", "tests/", ".github/actions/")):
            return _full_plan(f"unmapped test or CI path: {path}", canonical_packages)
        return _full_plan(f"unclassified pull-request path: {path}", canonical_packages)

    canonical_set = set(canonical_packages)
    affected = _affected_packages(changed_packages, reverse) & canonical_set
    if changed_packages and not affected:
        return _full_plan(
            "changed packages are outside the canonical Reborn set",
            canonical_packages,
        )

    buckets = _bucket_packages(sorted(affected)) if affected else []
    if len(buckets) > MAX_PR_CRATE_BUCKETS:
        # A foundational crate can have direct consumers in nearly every
        # bucket. Keep the PR on one fast wave by testing changed packages
        # themselves; all consumer buckets still run in the required queue.
        affected = changed_packages & canonical_set
        buckets = _bucket_packages(sorted(affected))
        reasons.append(
            "direct-dependent fanout exceeded the three-bucket PR budget; "
            "consumer tests deferred to merge queue"
        )
    active = bool(
        buckets
        or root_partitions
        or integration_lanes
        or run_frontend
        or run_qa_replay
    )
    return {
        "mode": "selected" if active else "none",
        "reasons": reasons or ["no Reborn test surface changed"],
        "changed_packages": sorted(changed_packages),
        "affected_packages": sorted(affected),
        "crate_buckets": buckets,
        "root_partitions": sorted(root_partitions),
        "integration_lanes": sorted(
            integration_lanes, key=lambda value: (isinstance(value, str), str(value))
        ),
        "run_group_tests": False,
        "run_frontend": run_frontend,
        "run_qa_replay": run_qa_replay,
        "coverage_mode": "none",
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--event", required=True)
    parser.add_argument(
        "--changed-files",
        type=Path,
        help="newline-delimited changed paths; required for pull_request",
    )
    args = parser.parse_args()
    try:
        changed_paths = (
            args.changed_files.read_text(encoding="utf-8").splitlines()
            if args.changed_files
            else []
        )
        plan = build_plan(
            event=args.event,
            changed_paths=changed_paths,
            metadata=_metadata(),
            canonical_packages=_canonical_packages(),
        )
    except (OSError, KeyError, ValueError, subprocess.CalledProcessError) as error:
        print(f"Reborn PR test planner failed: {error}", file=sys.stderr)
        return 1
    print(json.dumps(plan, separators=(",", ":"), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
