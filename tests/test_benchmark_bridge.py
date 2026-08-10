"""Regression tests for the benchmark bridge package boundary."""

from benchmark_bridge import agentlab_replay


def test_agentlab_replay_uses_the_renamed_benign_generator():
    """The legacy replay must import its renamed generator at runtime."""
    assert agentlab_replay.build_benign_chains([]) == []
