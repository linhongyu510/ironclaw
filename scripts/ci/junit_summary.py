#!/usr/bin/env python3
"""Summarize nextest JUnit reports into a Markdown per-test failure table.

Consumes one or more JUnit XML files (nextest's `[profile.ci.junit]`
output, one per nextest invocation) and prints a Markdown table of every
failed or errored <testcase>: binary (classname), test name, and the first
line of the failure/error message. Passing tests are not listed --
GitHub's own Checks UI already shows per-job pass/fail; this table exists
so a red run's *test* names are visible without opening every job log.

Usage: python3 scripts/ci/junit_summary.py <junit.xml> [<junit.xml> ...]
Exit status is always 0 -- this is a reporting step, never a gate; the
job's own test command already failed the step if there were failures.
"""
from __future__ import annotations

import sys
import xml.etree.ElementTree as ET
from dataclasses import dataclass


MAX_REPORT_BYTES = 64 * 1024 * 1024


@dataclass(frozen=True)
class FailedTest:
    classname: str
    name: str
    kind: str  # "failure" or "error"
    message: str


def _first_line(text: str | None) -> str:
    if not text:
        return "(no message)"
    stripped = text.strip()
    if not stripped:
        return "(no message)"
    return stripped.splitlines()[0][:200]


def parse_junit(path: str) -> list[FailedTest]:
    # Read once so validation and parsing operate on the same bounded input.
    # JUnit reports have no legitimate use for DTDs, and expat expands
    # internal entities. Test-controlled names and messages make these
    # CI-produced files untrusted input. Keep this dependency-free: defusedxml
    # is not a repository dependency.
    with open(path, "rb") as handle:
        report = handle.read(MAX_REPORT_BYTES + 1)
    if len(report) > MAX_REPORT_BYTES:
        raise ET.ParseError(
            f"JUnit report exceeds the {MAX_REPORT_BYTES}-byte limit"
        )
    if b"<!DOCTYPE" in report or b"<!ENTITY" in report:
        raise ET.ParseError("refusing JUnit XML containing a DTD or entity")

    root = ET.fromstring(report)
    testsuites = [root] if root.tag == "testsuite" else list(root.iter("testsuite"))
    failed: list[FailedTest] = []
    for suite in testsuites:
        for case in suite.iter("testcase"):
            for kind in ("failure", "error"):
                node = case.find(kind)
                if node is not None:
                    failed.append(
                        FailedTest(
                            classname=case.get("classname", suite.get("name", "?")),
                            name=case.get("name", "?"),
                            kind=kind,
                            message=_first_line(node.get("message") or node.text),
                        )
                    )
                    break
    return failed


def render_markdown(failures: list[FailedTest]) -> str:
    if not failures:
        return ""
    lines = ["### Failed tests", "", "| Binary | Test | Message |", "|---|---|---|"]
    for failure in sorted(failures, key=lambda f: (f.classname, f.name)):
        message = failure.message.replace("|", "\\|")
        lines.append(f"| `{failure.classname}` | `{failure.name}` | {message} |")
    return "\n".join(lines) + "\n"


def main(argv: list[str]) -> int:
    if not argv:
        print("usage: junit_summary.py <junit.xml> [<junit.xml> ...]", file=sys.stderr)
        return 2
    failures: list[FailedTest] = []
    for path in argv:
        try:
            failures.extend(parse_junit(path))
        except (ET.ParseError, FileNotFoundError) as exc:
            print(f"::warning::could not parse JUnit report {path}: {exc}", file=sys.stderr)
    print(render_markdown(failures))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
