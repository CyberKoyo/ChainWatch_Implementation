"""Supervised layer over the rule engine -- optional, lazily imported.

Everything in :mod:`chainwatch.engine` is numpy-only and stays that way: it is the
part that has to be portable and readable (CLAUDE.md section 2). This package is the
one place ``xgboost`` may be imported, and nothing in ``engine/`` imports it, so a
plain ``pip install numpy`` install runs the proxy and the rules exactly as before.

Install with ``pip install -e '.[ml]'`` to use it.
"""
