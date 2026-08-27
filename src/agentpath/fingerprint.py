"""Stable identity for a finding.

The APA-0001 style ids are positional: they are assigned after sorting, so
adding one critical finding renumbers everything below it. That is fine for
reading a report and useless for anything that has to recognise the same finding
across two runs.

A fingerprint is derived from what the finding actually is: the rule that fired
and the two tools it connects. It survives renumbering, reordering, and new
findings appearing, which is what a baseline file and a code scanning
integration both need.
"""

from __future__ import annotations

import hashlib


def fingerprint(rule: str, source: str, sink: str) -> str:
    material = f"{rule}\x00{source}\x00{sink}"
    return hashlib.sha256(material.encode("utf-8")).hexdigest()[:16]


def fingerprint_of(finding) -> str:
    return fingerprint(
        finding.rule,
        f"{finding.source.server}/{finding.source.tool}",
        f"{finding.sink.server}/{finding.sink.tool}",
    )
