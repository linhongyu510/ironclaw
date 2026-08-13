#!/usr/bin/env python3
"""Aggregate repeated semantic benchmark arms with blind pairwise judging."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import urllib.request
from pathlib import Path
from typing import Any, Callable

from scripts.live_canary.common import env_secret

CASE_NAME = "automation_semantic_benchmark"
PairwiseJudge = Callable[[dict[str, Any], dict[str, Any], int], dict[str, Any]]


def wilson_interval(successes: int, total: int, z: float = 1.96) -> tuple[float, float]:
    if total <= 0:
        return (0.0, 1.0)
    proportion = successes / total
    denominator = 1 + z * z / total
    center = (proportion + z * z / (2 * total)) / denominator
    margin = (
        z
        * math.sqrt(
            proportion * (1 - proportion) / total + z * z / (4 * total * total)
        )
        / denominator
    )
    return (max(0.0, center - margin), min(1.0, center + margin))


def load_records(root: Path) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for metadata_path in root.rglob("metadata.json"):
        metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
        results_path = metadata_path.with_name("results.json")
        payload = json.loads(results_path.read_text(encoding="utf-8"))
        benchmark_result = next(
            (
                result
                for result in payload.get("results", [])
                if result.get("details", {}).get("case") == CASE_NAME
            ),
            None,
        )
        if benchmark_result is None:
            raise ValueError(f"{results_path} has no {CASE_NAME!r} result")
        for case in benchmark_result.get("details", {}).get("benchmark_cases", []):
            records.append(
                {
                    **case,
                    "arm": metadata["arm"],
                    "repetition": int(metadata["repetition"]),
                    "runner_success": benchmark_result.get("success") is True,
                }
            )
    return records


def _judge_request(
    baseline: dict[str, Any], candidate: dict[str, Any], repetition: int
) -> dict[str, Any]:
    api_key_env = os.environ.get(
        "REBORN_WEBUI_V2_LIVE_QA_LLM_JUDGE_API_KEY_ENV",
        os.environ.get("REBORN_WEBUI_V2_LIVE_QA_LLM_API_KEY_ENV", "NEARAI_API_KEY"),
    )
    api_key = env_secret(api_key_env)
    if not api_key:
        return {"error": f"{api_key_env} unset"}
    case_id = str(candidate["benchmark_id"])
    candidate_first = (
        int(hashlib.sha256(f"{case_id}:{repetition}".encode()).hexdigest(), 16) % 2
        == 0
    )
    answer_a = candidate["answer"] if candidate_first else baseline["answer"]
    answer_b = baseline["answer"] if candidate_first else candidate["answer"]
    prompt = {
        "original_request": candidate["natural_prompt"],
        "rubric": candidate["criteria"],
        "answer_a": answer_a,
        "answer_b": answer_b,
        "required_schema": {
            "winner": "A, B, or tie",
            "confidence": "number from 0 to 1",
            "reason": "short rubric-grounded explanation",
            "unsupported_claims_a": "array of unsupported claims",
            "unsupported_claims_b": "array of unsupported claims",
        },
    }
    body = json.dumps(
        {
            "model": os.environ.get(
                "REBORN_WEBUI_V2_LIVE_QA_LLM_JUDGE_MODEL",
                os.environ.get(
                    "REBORN_WEBUI_V2_LIVE_QA_LLM_MODEL",
                    "deepseek-ai/DeepSeek-V4-Flash",
                ),
            ),
            "temperature": 0,
            "max_tokens": 600,
            "messages": [
                {
                    "role": "system",
                    "content": (
                        "You are a blind evaluator. Compare only how well answers A and B "
                        "satisfy the request and rubric. Do not infer which system produced "
                        "either answer. Penalize unsupported claims and false certainty. "
                        "Return JSON only."
                    ),
                },
                {"role": "user", "content": json.dumps(prompt, sort_keys=True)},
            ],
        }
    ).encode()
    base_url = os.environ.get(
        "REBORN_WEBUI_V2_LIVE_QA_LLM_JUDGE_BASE_URL",
        os.environ.get(
            "REBORN_WEBUI_V2_LIVE_QA_LLM_BASE_URL",
            os.environ.get(
                "LIVE_OPENAI_COMPATIBLE_BASE_URL", "https://cloud-api.near.ai/v1"
            ),
        ),
    ).rstrip("/")
    request = urllib.request.Request(
        f"{base_url}/chat/completions",
        data=body,
        headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=45) as response:
            payload = json.load(response)
        content = payload["choices"][0]["message"]["content"]
        parsed = json.loads(content)
    except Exception as exc:
        return {"error": f"pairwise judge failed: {exc}"}
    winner = str(parsed.get("winner", "")).upper()
    if winner not in {"A", "B", "TIE"}:
        return {"error": f"invalid judge winner: {winner!r}"}
    normalized_winner = (
        "tie"
        if winner == "TIE"
        else "candidate"
        if (winner == "A") == candidate_first
        else "baseline"
    )
    return {
        **parsed,
        "winner": normalized_winner,
        "candidate_was_answer": "A" if candidate_first else "B",
    }


def aggregate(
    records: list[dict[str, Any]], pairwise_judge: PairwiseJudge = _judge_request
) -> dict[str, Any]:
    indexed = {
        (str(record["arm"]), int(record["repetition"]), str(record["benchmark_id"])): record
        for record in records
    }
    keys = sorted(
        (repetition, case_id)
        for arm, repetition, case_id in indexed
        if arm == "candidate"
    )
    comparisons: list[dict[str, Any]] = []
    for repetition, case_id in keys:
        baseline = indexed.get(("baseline", repetition, case_id))
        candidate = indexed.get(("candidate", repetition, case_id))
        if baseline is None or candidate is None:
            comparisons.append(
                {
                    "benchmark_id": case_id,
                    "repetition": repetition,
                    "error": "missing paired arm",
                }
            )
            continue
        judgment = pairwise_judge(baseline, candidate, repetition)
        comparisons.append(
            {
                "benchmark_id": case_id,
                "repetition": repetition,
                "baseline_deterministic": baseline.get("deterministic", {}).get("passed")
                is True,
                "candidate_deterministic": candidate.get("deterministic", {}).get("passed")
                is True,
                "baseline_semantic": baseline.get("semantic_passed") is True,
                "candidate_semantic": candidate.get("semantic_passed") is True,
                "baseline_contract": baseline.get("execution_contract_present") is True,
                "candidate_contract": candidate.get("execution_contract_present") is True,
                "baseline_complete": all(
                    baseline.get(field) is True
                    for field in (
                        "created",
                        "scheduled_run_completed",
                        "final_reply_persisted",
                    )
                ),
                "candidate_complete": all(
                    candidate.get(field) is True
                    for field in (
                        "created",
                        "scheduled_run_completed",
                        "final_reply_persisted",
                    )
                ),
                "pairwise": judgment,
            }
        )
    complete = [comparison for comparison in comparisons if "error" not in comparison]
    judge_failures = [
        comparison
        for comparison in complete
        if comparison.get("pairwise", {}).get("error")
    ]
    regressions = [
        comparison
        for comparison in complete
        if not comparison["candidate_complete"]
        or not comparison["candidate_contract"]
        or (
            comparison["baseline_deterministic"]
            and not comparison["candidate_deterministic"]
        )
        or (comparison["baseline_semantic"] and not comparison["candidate_semantic"])
    ]
    wins = sum(
        comparison.get("pairwise", {}).get("winner") == "candidate"
        for comparison in complete
    )
    losses = sum(
        comparison.get("pairwise", {}).get("winner") == "baseline"
        for comparison in complete
    )
    decisive = wins + losses
    low, high = wilson_interval(wins, decisive)
    expected_pairs = len({key[1:] for key in indexed if key[0] == "candidate"})
    baseline_incomplete = any(
        not comparison["baseline_complete"] for comparison in complete
    )
    if len(complete) != expected_pairs or judge_failures or baseline_incomplete:
        status = "blocked"
    elif regressions:
        status = "regressed"
    elif decisive and low > 0.5:
        status = "improved"
    else:
        status = "no_regression"
    return {
        "status": status,
        "pair_count": len(complete),
        "candidate_wins": wins,
        "baseline_wins": losses,
        "ties": len(complete) - decisive,
        "candidate_win_rate_decisive": wins / decisive if decisive else None,
        "candidate_win_rate_95ci": [low, high],
        "regression_count": len(regressions),
        "judge_failure_count": len(judge_failures),
        "comparisons": comparisons,
    }


def _markdown(report: dict[str, Any]) -> str:
    rate = report.get("candidate_win_rate_decisive")
    interval = report["candidate_win_rate_95ci"]
    rate_text = "n/a" if rate is None else f"{rate:.1%}"
    return "\n".join(
        [
            "## Automation semantic benchmark",
            "",
            f"Result: **{str(report['status']).upper()}**",
            "",
            f"Paired answers: **{report['pair_count']}**",
            f"Candidate / baseline / ties: **{report['candidate_wins']} / "
            f"{report['baseline_wins']} / {report['ties']}**",
            f"Candidate decisive win rate: **{rate_text}** "
            f"(95% Wilson CI {interval[0]:.1%}–{interval[1]:.1%})",
            f"Hard regressions: **{report['regression_count']}**",
            f"Judge failures: **{report['judge_failure_count']}**",
            "",
            "`IMPROVED` requires no hard regressions and a decisive candidate "
            "win-rate confidence interval entirely above 50%. `NO_REGRESSION` "
            "means the evidence is neutral, not that semantic quality improved.",
            "",
        ]
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input-root", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    try:
        report = aggregate(load_records(args.input_root))
    except (OSError, ValueError, KeyError, json.JSONDecodeError) as exc:
        report = {"status": "blocked", "error": str(exc)}
    args.output_dir.mkdir(parents=True, exist_ok=True)
    (args.output_dir / "benchmark.json").write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    markdown = (
        _markdown(report)
        if "pair_count" in report
        else f"## Automation semantic benchmark\n\nResult: **BLOCKED**\n\n{report['error']}\n"
    )
    (args.output_dir / "benchmark.md").write_text(markdown, encoding="utf-8")
    print(markdown, end="")
    return 1 if report["status"] in {"blocked", "regressed"} else 0


if __name__ == "__main__":
    raise SystemExit(main())
