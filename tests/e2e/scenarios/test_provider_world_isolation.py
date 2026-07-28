"""Compatibility marker for the retired provider-world isolation scenario.

The isolation checks were folded into the Reborn provider contract and QA
full-path coverage. This file remains for stale workflow references.
"""

from pathlib import Path


def test_provider_world_isolation_coverage_moved_to_reborn_provider_contracts():
    scenarios_dir = Path(__file__).parent
    assert (scenarios_dir / "test_emulate_reborn_provider_contracts.py").is_file()
    assert (scenarios_dir / "test_reborn_qa_trace_full_path.py").is_file()

