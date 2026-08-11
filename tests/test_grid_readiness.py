"""A readiness report that reports a rate over nothing is worse than none.

Note 31: a run over an empty attack class printed nan tables and exited 0. The
report must say "unavailable" where it has no evidence, and must name the basis
of every projection on the line that prints it.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from scripts import grid_readiness  # noqa: E402


def test_a_partition_with_no_native_valid_attacks_reports_unavailable():
    line = grid_readiness.format_native_line(
        partition="workspace", benign_valid=4, benign_total=5,
        attack_valid=0, attack_total=6)
    assert "unavailable" in line
    assert "0.0%" not in line, "a rate over zero valid attacks is not a measurement"


def test_a_partition_with_evidence_reports_both_rates():
    line = grid_readiness.format_native_line(
        partition="banking", benign_valid=4, benign_total=5,
        attack_valid=8, attack_total=15)
    assert "8/15" in line and "4/5" in line


def test_projection_names_its_basis_and_states_the_maximum_separately():
    line = grid_readiness.format_cost_projection(
        remaining=412, mean_usd=0.000675, max_usd=0.001416)
    assert "0.000675" in line, "the basis must be on the line that prints the projection"
    assert "0.001416" in line, "the observed maximum is stated, not folded into the mean"
    assert "$0.28" in line or "$0.278" in line


def test_the_emitted_command_is_resumable_and_carries_a_measured_cap():
    command = grid_readiness.format_resume_command(
        script="scripts/capture_agentdojo_openai.py", corpus_revision="v2", cap_usd=0.42)
    assert "--resume" in command
    assert "--corpus-revision v2" in command
    assert "--max-cost-usd 0.42" in command
    assert "3.0" not in command, "never emit the default cap"


def test_depth_flags_a_partition_under_the_quality_signal():
    shallow = grid_readiness.format_depth_line(
        partition="injecagent-dev", sessions=3, mean_calls=1.0, attack_mean_calls=1.0)
    deep = grid_readiness.format_depth_line(
        partition="banking", sessions=9, mean_calls=4.4, attack_mean_calls=5.1)
    assert "below the >=4 attack-depth signal" in shallow
    assert "below" not in deep


def test_a_report_over_an_empty_corpus_says_so_and_still_exits_zero(tmp_path):
    """After the archive is applied there is no corpus at all. That is a state to
    report, not a crash and not a silent zero."""
    text, code = grid_readiness.report(tmp_path)
    assert code == 0
    assert "0 of 452" in text and "0 of 558" in text
