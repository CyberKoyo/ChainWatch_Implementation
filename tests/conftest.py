"""Shared pytest configuration.

Currently one job: keep the held-out payload family out of the default run.
"""

import pytest


def pytest_configure(config):
    config.addinivalue_line(
        "markers",
        "holdout: validation against a payload family reserved for a single final run; "
        "deselected by default so rules cannot be iterated against it",
    )


def pytest_collection_modifyitems(config, items):
    """Deselect holdout tests unless ``-m holdout`` is given explicitly.

    The held-out family is the only evidence that a rule generalises rather than
    fitting the family it was written against. Running it on every iteration
    would destroy that, which is how PS came to encode the generator rather than
    the attack -- see docs/development-notes.md, "Phase 8".
    """
    if config.getoption("-m") == "holdout":
        return
    skip = pytest.mark.skip(reason="holdout family; run with -m holdout")
    for item in items:
        if "holdout" in item.keywords:
            item.add_marker(skip)
