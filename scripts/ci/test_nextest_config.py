#!/usr/bin/env python3
"""Pin the nextest serialisation that keeps port-racing tests deterministic.

`crates/app/ironclaw_cli/tests/smoke.rs` boots a real `serve` listener. Its
`unused_local_port` helper binds :0, reads the port, then releases it before
the spawned child re-binds — a TOCTOU window the helper's own comment
declines to grow past. Under `cargo test` those tests shared one process and
the window stayed narrow; nextest runs each test in its own process, and the
window widened until two raced for the same port and one reported
"connect to serve listener failed: Connection refused".

The fix is serialisation in .config/nextest.toml, not a test edit. These
tests fail if that group is removed, loses its single-thread bound, stops
applying to a profile, or stops covering the test that actually failed.
"""

from __future__ import annotations

import tomllib
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CONFIG = ROOT / ".config" / "nextest.toml"
GROUP = "cli-serve-listener"
LISTENER_FILTER = (
    "package(ironclaw) & binary(smoke) & "
    "(test(~serve) | test(~onboard_) | test(~stored_key_reaches) | "
    "test(a_real_env_var_beats_the_config_default_end_to_end))"
)


def _config() -> dict:
    return tomllib.loads(CONFIG.read_text(encoding="utf-8"))


def _listener_override(config: dict, profile: str) -> dict | None:
    overrides = config.get("profile", {}).get(profile, {}).get("overrides", [])
    if not overrides or overrides[0].get("filter") != LISTENER_FILTER:
        return None
    return overrides[0]


class NextestSerialisationTests(unittest.TestCase):
    def test_the_listener_group_exists(self) -> None:
        groups = _config().get("test-groups", {})
        self.assertIn(
            GROUP,
            groups,
            "the CLI smoke listener tests race for a port without this group",
        )

    def test_the_group_stays_single_threaded(self) -> None:
        group = _config().get("test-groups", {}).get(GROUP, {})
        self.assertEqual(
            1,
            group.get("max-threads"),
            "more than one thread reopens the port race this group closed",
        )

    def test_both_profiles_make_listener_tests_globally_exclusive(self) -> None:
        config = _config()
        for profile in ("default", "ci"):
            with self.subTest(profile=profile):
                override = _listener_override(config, profile)
                self.assertIsNotNone(
                    override,
                    f"profile {profile!r} must keep the canonical listener "
                    "override first so its semantics cannot be shadowed",
                )
                self.assertEqual(GROUP, override.get("test-group"))
                self.assertEqual(
                    "num-test-threads",
                    override.get("threads-required"),
                    "a one-thread group serialises only its own members; the "
                    "bind-close-rebind window must exclude every other test",
                )

    def test_filter_guard_rejects_heuristic_false_positives_and_shadowing(self) -> None:
        for expression in (
            "!test(~serve)",
            "package(other) & test(~serve)",
            "binary(other) & test(~serve)",
        ):
            with self.subTest(expression=expression):
                config = {"profile": {"ci": {"overrides": [{"filter": expression}]}}}
                self.assertIsNone(_listener_override(config, "ci"))

        shadowed = {
            "profile": {
                "ci": {
                    "overrides": [
                        {"filter": "test(~serve)", "test-group": "other"},
                        {"filter": LISTENER_FILTER, "test-group": GROUP},
                    ]
                }
            }
        }
        self.assertIsNone(_listener_override(shadowed, "ci"))


if __name__ == "__main__":
    unittest.main()
