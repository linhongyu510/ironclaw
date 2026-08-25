#!/usr/bin/env python3
"""Regression tests for scripts/ci/junit_summary.py."""
from __future__ import annotations

import contextlib
import io
import pathlib
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(pathlib.Path(__file__).parent))
import junit_summary  # noqa: E402

PASSING_XML = """<?xml version="1.0"?>
<testsuites>
  <testsuite name="reborn_scope_isolation_suite" tests="1" failures="0">
    <testcase classname="reborn_scope_isolation_suite" name="agent_scope_denies_cross_tenant_read" time="0.4"/>
  </testsuite>
</testsuites>
"""

FAILING_XML = """<?xml version="1.0"?>
<testsuites>
  <testsuite name="reborn_scope_isolation_suite" tests="2" failures="1" errors="0">
    <testcase classname="reborn_scope_isolation_suite" name="agent_scope_denies_cross_tenant_read" time="0.4"/>
    <testcase classname="reborn_scope_isolation_suite" name="project_scope_leaks_across_tenant" time="1.1">
      <failure message="assertion failed: leaked == false">panic at tests/reborn_scope_isolation_suite/reborn_project_scope_isolation_parity.rs:88</failure>
    </testcase>
  </testsuite>
  <testsuite name="reborn_group_approvals" tests="1" errors="1">
    <testcase classname="reborn_group_approvals" name="concurrent_dual_gate_resume" time="9.9">
      <error message="process aborted">SIGABRT</error>
    </testcase>
  </testsuite>
</testsuites>
"""


class JunitSummaryTest(unittest.TestCase):
    def _write(self, content: str) -> str:
        handle = tempfile.NamedTemporaryFile(mode="w", suffix=".xml", delete=False)
        handle.write(content)
        handle.close()
        return handle.name

    def test_all_passing_yields_empty_report(self) -> None:
        path = self._write(PASSING_XML)
        failures = junit_summary.parse_junit(path)
        self.assertEqual(failures, [])
        self.assertEqual(junit_summary.render_markdown(failures), "")

    def test_failures_and_errors_both_render(self) -> None:
        path = self._write(FAILING_XML)
        failures = junit_summary.parse_junit(path)
        self.assertEqual(len(failures), 2)
        self.assertEqual({f.kind for f in failures}, {"failure", "error"})
        markdown = junit_summary.render_markdown(failures)
        self.assertIn("reborn_scope_isolation_suite", markdown)
        self.assertIn("project_scope_leaks_across_tenant", markdown)
        self.assertIn("reborn_group_approvals", markdown)
        self.assertIn("concurrent_dual_gate_resume", markdown)

    def test_unparseable_file_warns_and_continues(self) -> None:
        bad = self._write("not xml")
        good = self._write(FAILING_XML)
        buf = io.StringIO()
        with contextlib.redirect_stderr(buf):
            status = junit_summary.main([bad, good])
        self.assertEqual(status, 0)
        self.assertIn("::warning::", buf.getvalue())

    def test_dtd_after_initial_4096_bytes_warns_and_continues(self) -> None:
        unsafe = self._write(
            '<?xml version="1.0"?>\n'
            + (" " * 4096)
            + '<!DOCTYPE testsuites [<!ENTITY injected "expanded">]>\n'
            + '<testsuites><testsuite name="unsafe"><testcase name="case">'
            + '<failure message="&injected;"/></testcase></testsuite></testsuites>'
        )
        good = self._write(FAILING_XML)
        stdout = io.StringIO()
        stderr = io.StringIO()

        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            status = junit_summary.main([unsafe, good])

        self.assertEqual(status, 0)
        self.assertIn("refusing JUnit XML containing a DTD or entity", stderr.getvalue())
        self.assertNotIn("expanded", stdout.getvalue())
        self.assertIn("project_scope_leaks_across_tenant", stdout.getvalue())

    def test_oversized_report_warns_and_continues(self) -> None:
        oversized = self._write(
            '<testsuites><testsuite name="oversized"><testcase name="case">'
            + ('<failure message="should not be parsed"/>' * 40)
            + "</testcase></testsuite></testsuites>"
        )
        good = self._write(FAILING_XML)
        stdout = io.StringIO()
        stderr = io.StringIO()

        with mock.patch.object(junit_summary, "MAX_REPORT_BYTES", 1024, create=True):
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                status = junit_summary.main([oversized, good])

        self.assertEqual(status, 0)
        self.assertIn("exceeds the 1024-byte limit", stderr.getvalue())
        self.assertNotIn("should not be parsed", stdout.getvalue())
        self.assertIn("project_scope_leaks_across_tenant", stdout.getvalue())


if __name__ == "__main__":
    unittest.main()
