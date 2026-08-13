#!/usr/bin/env python3
"""Compare the same natural-language automation journey across two builds."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

CASE_NAME = "automation_ab_happy_path"
OUTCOME_FIELDS = (
    "scheduled_run_completed",
    "final_reply_persisted",
    "semantic_result_correct",
    "exact_result_match",
)


def _case_result(path: Path) -> dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    for result in payload.get("results", []):
        details = result.get("details", {})
        if details.get("case") == CASE_NAME:
            return result
    raise ValueError(f"{path} has no {CASE_NAME!r} result")


def _arm(result: dict[str, Any]) -> dict[str, Any]:
    details = result.get("details", {})
    return {
        "runner_success": result.get("success") is True,
        "execution_contract_present": details.get("execution_contract_present")
        is True,
        **{field: details.get(field) is True for field in OUTCOME_FIELDS},
        "semantic_judgment": details.get("semantic_judgment"),
        "error": details.get("error"),
    }


def compare(baseline_path: Path, candidate_path: Path) -> dict[str, Any]:
    baseline = _arm(_case_result(baseline_path))
    candidate = _arm(_case_result(candidate_path))
    baseline_outcome_score = sum(bool(baseline[field]) for field in OUTCOME_FIELDS)
    candidate_outcome_score = sum(bool(candidate[field]) for field in OUTCOME_FIELDS)
    candidate_requirements = {
        "runner_success": candidate["runner_success"],
        "execution_contract_present": candidate["execution_contract_present"],
        "scheduled_run_completed": candidate["scheduled_run_completed"],
        "final_reply_persisted": candidate["final_reply_persisted"],
        "semantic_result_correct": candidate["semantic_result_correct"],
    }
    baseline_observable = (
        baseline["scheduled_run_completed"] and baseline["final_reply_persisted"]
    )
    if not baseline_observable:
        status = "blocked"
    elif all(candidate_requirements.values()):
        status = "pass"
    else:
        status = "fail"
    return {
        "status": status,
        "case": CASE_NAME,
        "baseline": baseline,
        "candidate": candidate,
        "candidate_requirements": candidate_requirements,
        "outcome_score": {
            "baseline": baseline_outcome_score,
            "candidate": candidate_outcome_score,
            "delta": candidate_outcome_score - baseline_outcome_score,
            "maximum": len(OUTCOME_FIELDS),
        },
        "semantic_quality_improved": (
            candidate["semantic_result_correct"]
            and not baseline["semantic_result_correct"]
        ),
        "contract_evidence_improved": (
            candidate["execution_contract_present"]
            and not baseline["execution_contract_present"]
        ),
    }


def _markdown(report: dict[str, Any]) -> str:
    baseline = report["baseline"]
    candidate = report["candidate"]
    score = report["outcome_score"]
    rows = [
        ("Structured execution contract", "execution_contract_present"),
        ("Scheduled run completed", "scheduled_run_completed"),
        ("Final reply persisted", "final_reply_persisted"),
        ("Semantic result correct", "semantic_result_correct"),
        ("Exact requested output", "exact_result_match"),
    ]
    lines = [
        "## Automation A/B evidence",
        "",
        f"Result: **{str(report['status']).upper()}**",
        "",
        "| Evidence | Baseline | Candidate |",
        "| --- | ---: | ---: |",
    ]
    for label, key in rows:
        lines.append(
            f"| {label} | {'yes' if baseline[key] else 'no'} | "
            f"{'yes' if candidate[key] else 'no'} |"
        )
    lines.extend(
        [
            "",
            f"Outcome score: **{score['baseline']}/{score['maximum']} → "
            f"{score['candidate']}/{score['maximum']}** "
            f"(delta {score['delta']:+d}).",
            "",
            "Semantic improvement is claimed only when the baseline answer fails "
            "the pinned judge and the candidate answer passes it. Contract evidence "
            "is reported separately and is not treated as semantic improvement.",
        ]
    )
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--baseline", type=Path, required=True)
    parser.add_argument("--candidate", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    try:
        report = compare(args.baseline, args.candidate)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        report = {"status": "blocked", "case": CASE_NAME, "error": str(exc)}
    args.output_dir.mkdir(parents=True, exist_ok=True)
    (args.output_dir / "comparison.json").write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    if "baseline" in report:
        markdown = _markdown(report)
    else:
        markdown = (
            "## Automation A/B evidence\n\n"
            f"Result: **BLOCKED**\n\n{report.get('error', 'unknown error')}\n"
        )
    (args.output_dir / "comparison.md").write_text(markdown, encoding="utf-8")
    print(markdown, end="")
    return 0 if report["status"] == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
