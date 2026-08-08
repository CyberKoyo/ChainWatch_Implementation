"""Every capture driver must name its MCP server explicitly.

chainwatch/proxy/__main__.py falls back to the last argv token, which is a score-file
path on one half of a route and `--benign` on the other. ml/dataset.py reads that field
as the leave-one-environment-out environment, so the fallback puts the two classes in
disjoint environments. A grep-shaped test is the right shape here: these drivers build
their argv inside an embedded heredoc that cannot be imported.
"""

from __future__ import annotations

from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent

DRIVERS = [
    "scripts/capture_agentdojo.sh",
    "scripts/capture_injecagent.sh",
]


@pytest.mark.parametrize("driver", DRIVERS)
def test_every_driver_names_its_server(driver):
    text = (ROOT / driver).read_text(encoding="utf-8")
    assert '"--server"' in text, f"{driver} does not pass --server to chainwatch"
    assert '"--source"' in text
    assert text.index('"--server"') < text.index('"--source"')
