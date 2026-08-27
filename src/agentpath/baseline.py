"""Accept the findings you already have, fail on the ones you add.

A scanner that reports forty existing findings on its first run in a real
repository gets switched off that same day. The baseline is what makes adoption
possible: record today's findings, and from then on CI only fails on something
new.

This is deliberately different from the accept list in .agentpath.yml. An
acceptance is a decision, made by a person, with a reason, about one specific
path. A baseline is a snapshot with no judgement attached, and it says nothing
about whether those findings are acceptable. Keeping them separate matters,
because collapsing them would let a bulk snapshot look like a set of reviewed
decisions.

Baselined findings still appear in the report, under their own heading. They are
just not what fails the build.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

SCHEMA = "agentpath-baseline/v1"
BASELINED = "baselined"


class BaselineError(ValueError):
    """Raised when a baseline file cannot be read."""


@dataclass
class Baseline:
    entries: dict[str, dict[str, Any]] = field(default_factory=dict)
    source_path: str = ""

    def has(self, fp: str) -> bool:
        return fp in self.entries

    def to_dict(self) -> dict[str, Any]:
        return {"schema": SCHEMA, "findings": self.entries}


def load_baseline(path: str | Path) -> Baseline:
    path = Path(path)
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise BaselineError(f"{path}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise BaselineError(f"{path}: not valid JSON: {exc}") from exc
    if raw.get("schema") != SCHEMA:
        raise BaselineError(f"{path}: expected schema {SCHEMA!r}, found {raw.get('schema')!r}")
    return Baseline(entries=raw.get("findings", {}) or {}, source_path=str(path))


def build_baseline(findings) -> Baseline:
    """Snapshot the current findings, keeping enough detail to read later."""
    from .fingerprint import fingerprint_of

    entries: dict[str, dict[str, Any]] = {}
    for finding in findings:
        if finding.suppressed:
            continue
        entries[fingerprint_of(finding)] = {
            "rule": finding.rule,
            "severity": finding.severity,
            "source": f"{finding.source.server}/{finding.source.tool}",
            "sink": f"{finding.sink.server}/{finding.sink.tool}",
        }
    return Baseline(entries=entries)


def apply_baseline(findings, baseline: Baseline | None) -> int:
    """Mark findings that were already known. Returns how many were marked."""
    if not baseline:
        return 0
    from .fingerprint import fingerprint_of

    marked = 0
    for finding in findings:
        if finding.suppressed:
            continue
        if baseline.has(fingerprint_of(finding)):
            finding.status = BASELINED
            finding.baseline = {"source": baseline.source_path}
            marked += 1
    return marked
