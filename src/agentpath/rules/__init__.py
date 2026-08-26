"""Auto discovery for rule modules."""

from __future__ import annotations

import importlib
import pkgutil
from pathlib import Path

from .base import REGISTRY, Rule, all_rules, register  # noqa: F401

_loaded = False


def load_all() -> None:
    """Import every rule module in this package exactly once."""
    global _loaded
    if _loaded:
        return
    package_dir = Path(__file__).parent
    for info in pkgutil.iter_modules([str(package_dir)]):
        if info.name in {"base"}:
            continue
        importlib.import_module(f"{__name__}.{info.name}")
    _loaded = True
