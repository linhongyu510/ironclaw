"""Compatibility marker for the retired Emulate build-parity scenario.

The Reborn E2E workflow used to reference this file directly. Current coverage
lives in the provider contract and harvested QA trace scenarios; keep this
marker until all workflow callers have moved to the new scenario list.
"""

from pathlib import Path


def test_emulate_build_parity_coverage_moved_to_reborn_provider_contracts():
    scenarios_dir = Path(__file__).parent
    assert (scenarios_dir / "test_emulate_reborn_provider_contracts.py").is_file()
    assert (scenarios_dir / "test_reborn_qa_trace_full_path.py").is_file()

