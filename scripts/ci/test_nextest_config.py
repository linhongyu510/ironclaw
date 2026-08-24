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
# The test that failed in CI, plus one representative of each other shape the
# filter must keep covering.
MUST_COVER = (
    "onboard_login_link_then_bearer_authorizes_a_protected_request",
    "serve_boots_without_user_id_env_var",
    "stored_key_reaches_real_turn_via_product_surface",
)
GLOB_FRAGMENTS = ("serve", "onboard_", "stored_key_reaches")


def _config() -> dict:
    return tomllib.loads(CONFIG.read_text(encoding="utf-8"))


def _bound_filters(config: dict, profile: str) -> str:
    overrides = config.get("profile", {}).get(profile, {}).get("overrides", [])
    return " ".join(
        override.get("filter", "")
        for override in overrides
        if override.get("test-group") == GROUP
    )


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

    def test_both_profiles_bind_the_group(self) -> None:
        config = _config()
        for profile in ("default", "ci"):
            with self.subTest(profile=profile):
                self.assertNotEqual(
                    "",
                    _bound_filters(config, profile).strip(),
                    f"profile {profile!r} would run the listener tests in parallel",
                )

    def test_the_filter_still_covers_the_test_that_failed(self) -> None:
        config = _config()
        for profile in ("default", "ci"):
            expression = _bound_filters(config, profile)
            for name in MUST_COVER:
                with self.subTest(profile=profile, test=name):
                    covered = name in expression or any(
                        fragment in name
                        for fragment in GLOB_FRAGMENTS
                        if f"test(~{fragment})" in expression
                    )
                    self.assertTrue(
                        covered, f"{name} is no longer serialised in {profile!r}"
                    )


if __name__ == "__main__":
    unittest.main()
