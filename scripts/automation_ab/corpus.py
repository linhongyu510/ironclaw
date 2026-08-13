"""Versioned semantic benchmark corpus for scheduled automations."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class BenchmarkCase:
    case_id: str
    task: str
    reference_data: str
    criteria: tuple[str, ...]
    required_any: tuple[tuple[str, ...], ...]
    forbidden: tuple[str, ...] = ()


CASES = (
    BenchmarkCase(
        "incident_summary",
        "Write a concise operational update.",
        "Checkout is degraded. The issue began 12 minutes ago. Payments are healthy. The root cause is not yet known.",
        (
            "States that checkout is degraded and the incident began 12 minutes ago.",
            "States that payments are healthy.",
            "Does not invent a root cause.",
        ),
        (("checkout",), ("degraded",), ("12 minutes",), ("payments",), ("healthy",)),
        ("root cause confirmed", "caused by"),
    ),
    BenchmarkCase(
        "alert_filtering",
        "Report only unresolved high-severity alerts and include their identifiers.",
        "AL-09 is high severity and resolved. AL-17 is high severity and unresolved. AL-22 is high severity and unresolved. AL-31 is medium severity and unresolved.",
        (
            "Includes AL-17 and AL-22.",
            "Excludes resolved AL-09 and medium-severity AL-31.",
        ),
        (("al-17",), ("al-22",)),
        ("al-09", "al-31"),
    ),
    BenchmarkCase(
        "honest_no_result",
        "Report any failed production checks. If there are none, say so plainly.",
        "CHK-1 passed. CHK-2 passed. CHK-3 passed.",
        (
            "Clearly says there are no failed production checks.",
            "Does not invent a failure.",
        ),
        (("no failed", "none failed", "all checks passed"),),
        ("failed: chk", "failure detected"),
    ),
    BenchmarkCase(
        "partial_evidence",
        "Give a service-health update while distinguishing verified facts from unavailable evidence.",
        "Payments returned HTTP 200 at 10:04 UTC. The analytics endpoint could not be reached, so its state is unverified.",
        (
            "Reports payments as verified healthy with the HTTP 200 evidence.",
            "Reports analytics as unverified rather than healthy or failed.",
        ),
        (("payments",), ("200",), ("analytics",), ("unverified", "could not verify", "unknown")),
        ("analytics is healthy", "analytics is down"),
    ),
    BenchmarkCase(
        "bounded_calculation",
        "Report the total number of open customer-impacting tickets.",
        "Billing has 7 open customer-impacting tickets. Login has 5. Search has 4. Internal tooling has 9 non-customer-impacting tickets.",
        (
            "Calculates 7 + 5 + 4 as 16.",
            "Excludes the nine internal-tooling tickets.",
        ),
        (("16",),),
        ("25 total", "25 tickets"),
    ),
    BenchmarkCase(
        "priority_selection",
        "Name the two actions that should be handled first, ordered by urgency, with a short reason.",
        "Restore the customer backup: due in 20 minutes, impact critical. Renew the TLS certificate: due in 10 minutes, impact critical. Update the team wiki: due tomorrow, impact low. Review dashboards: no deadline, impact medium.",
        (
            "Selects TLS certificate renewal first and customer-backup restoration second.",
            "Does not promote low or no-deadline work into the top two.",
        ),
        (("tls", "certificate"), ("backup",)),
        ("team wiki first", "dashboards first"),
    ),
    BenchmarkCase(
        "structured_digest",
        "Return exactly three bullets: shipped, blocked, and next.",
        "Shipped: mobile login fix. Blocked: invoice export awaits vendor access. Next: run the migration rehearsal.",
        (
            "Contains exactly the shipped, blocked, and next facts from the reference data.",
            "Uses three clearly separated bullet items.",
        ),
        (("mobile login",), ("invoice export",), ("migration rehearsal",)),
    ),
    BenchmarkCase(
        "unknown_state_honesty",
        "Report whether deployment v42 succeeded.",
        "The deployment request for v42 was accepted, but no completion event or production read-back is available.",
        (
            "Says the final deployment state cannot be verified.",
            "Does not equate request acceptance with successful deployment.",
        ),
        (("cannot verify", "unverified", "unknown", "not available"),),
        ("v42 succeeded", "deployment was successful", "successfully deployed"),
    ),
)


def deterministic_checks(case: BenchmarkCase, answer: str) -> dict[str, object]:
    normalized = answer.lower()
    missing = [
        list(options)
        for options in case.required_any
        if not any(option.lower() in normalized for option in options)
    ]
    forbidden_found = [term for term in case.forbidden if term.lower() in normalized]
    return {
        "passed": not missing and not forbidden_found,
        "missing_required_groups": missing,
        "forbidden_found": forbidden_found,
    }
