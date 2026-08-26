"""A single file HTML report.

Everything inline, no external assets, so the file can be opened straight from
disk or attached to a ticket. The point of the HTML view over the Markdown one
is that a confirmed path and a merely candidate path should be visible at a
glance, so the confirmation status drives the colour rather than sitting in the
prose.
"""

from __future__ import annotations

import html
import json
from typing import Any

from .findings import Finding, active
from .model import Agent

SEVERITY_ORDER = ("critical", "high", "medium", "low")

VERDICT_LABEL = {
    "confirmed": "Confirmed",
    "not_confirmed": "Not confirmed",
    "not_delivered": "Not tested",
    "candidate": "Candidate",
}


def _esc(text: Any) -> str:
    return html.escape(str(text))


def _verdict_of(finding: Finding) -> str:
    data = finding.confirmation
    if data:
        return data.get("verdict", "candidate")
    return "candidate"


def _finding_card(finding: Finding) -> str:
    verdict = _verdict_of(finding)
    data = finding.confirmation
    parts: list[str] = []
    parts.append(f'<article class="finding sev-{_esc(finding.severity)} v-{_esc(verdict)}">')
    parts.append(f'<header><span class="id">{_esc(finding.id)}</span>'
                 f'<span class="sev">{_esc(finding.severity)}</span>'
                 f'<span class="verdict">{_esc(VERDICT_LABEL.get(verdict, "Candidate"))}</span>'
                 f'</header>')
    parts.append(f'<h3>{_esc(finding.name)}</h3>')
    parts.append(
        f'<p class="path"><code>{_esc(finding.source.server)}/{_esc(finding.source.tool)}</code>'
        f'<span class="arrow">to agent to</span>'
        f'<code>{_esc(finding.sink.server)}/{_esc(finding.sink.tool)}</code></p>'
    )
    if finding.crosses_trust_boundary:
        parts.append(f'<p class="boundary">Crosses a trust boundary: '
                     f'{_esc(finding.source.trust)} to {_esc(finding.sink.trust)}.</p>')

    if data:
        agent = ("a scripted stand in" if not data.get("trustworthy")
                 else _esc(data.get("agent_name", "the agent")))
        if verdict == "confirmed":
            parts.append(f'<p class="obs"><strong>Observed.</strong> {agent} called the sink '
                         f'with the planted marker in {data.get("succeeded", 0)} of '
                         f'{data.get("attempts", 0)} attempts.</p>')
            if data.get("observed_call"):
                parts.append(f'<pre class="call">{_esc(data["observed_call"])}</pre>')
        elif verdict == "not_confirmed":
            parts.append(f'<p class="obs"><strong>Not confirmed.</strong> The payload reached '
                         f'{agent} in {data.get("delivered", 0)} of {data.get("attempts", 0)} '
                         f'attempts and it did not call the sink with the marker.</p>')
        elif verdict == "not_delivered":
            parts.append(f'<p class="obs"><strong>Not tested.</strong> {agent} never read the '
                         f'planted content, so this path was never exercised.</p>')
        if data.get("agent_said"):
            parts.append(f'<blockquote class="said">{_esc(data["agent_said"])}</blockquote>')
        if data.get("caveat"):
            parts.append(f'<p class="caveat">{_esc(data["caveat"])}</p>')

    parts.append(f'<p class="scenario"><strong>Scenario.</strong> {_esc(finding.scenario)}</p>')
    parts.append(f'<p class="fix"><strong>Fix.</strong> {_esc(finding.fix)}</p>')
    ev = finding.evidence
    parts.append(f'<p class="why">Source: {_esc(ev.get("source_reason", ""))}. '
                 f'Sink: {_esc(ev.get("sink_reason", ""))}. '
                 f'Confidence {_esc(ev.get("confidence", ""))}.</p>')
    parts.append('</article>')
    return "\n".join(parts)


def to_html(agent: Agent, findings: list[Finding]) -> str:
    shown = active(findings)
    tool_count = sum(1 for _ in agent.tools())
    tested = [f for f in shown if f.confirmation]
    confirmed = [f for f in tested if _verdict_of(f) == "confirmed"]
    scripted_only = bool(tested) and all(
        not f.confirmation.get("trustworthy") for f in tested)

    cards = []
    for level in SEVERITY_ORDER:
        for finding in shown:
            if finding.severity == level:
                cards.append(_finding_card(finding))

    incomplete_note = ""
    if not agent.complete:
        missing = ", ".join(_esc(s.name) for s in agent.unenumerated())
        incomplete_note = (f'<p class="incomplete">Scan incomplete. '
                           f'{len(agent.unenumerated())} of {len(agent.servers)} servers were '
                           f'not enumerated ({missing}). Paths through them are missing.</p>')

    confirm_note = ""
    if tested:
        confirm_note = (f'<p class="confirmnote">{len(confirmed)} of {len(tested)} tested paths '
                        f'were observed being walked'
                        + (' against a scripted stand in, which shows the harness works rather '
                           'than that a real agent behaves this way.' if scripted_only
                           else '.') + '</p>')

    return TEMPLATE.format(
        name=_esc(agent.name),
        harness=_esc(agent.harness or "unknown"),
        servers=len(agent.servers),
        tools=tool_count,
        findings=len(shown),
        incomplete=incomplete_note,
        confirm=confirm_note,
        cards="\n".join(cards) if cards else "<p>No attack paths found.</p>",
    )


TEMPLATE = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>agentpath report: {name}</title>
<style>
  :root {{
    --ink: #1f2430; --muted: #6b7280; --line: #e5e7eb; --bg: #f8fafc;
    --crit: #b91c1c; --high: #c2410c; --med: #a16207; --low: #4b5563;
    --confirmed: #b91c1c; --notconf: #15803d; --nottested: #6b7280;
  }}
  * {{ box-sizing: border-box; }}
  body {{ font: 15px/1.6 -apple-system, Segoe UI, Roboto, sans-serif;
    color: var(--ink); background: var(--bg); margin: 0; padding: 32px; }}
  main {{ max-width: 860px; margin: 0 auto; }}
  h1 {{ font-size: 22px; margin: 0 0 4px; }}
  .meta {{ color: var(--muted); margin: 0 0 20px; }}
  .confirmnote, .incomplete {{ padding: 12px 14px; border-radius: 8px; margin: 0 0 14px; }}
  .confirmnote {{ background: #eef2ff; }}
  .incomplete {{ background: #fef3c7; }}
  .finding {{ background: #fff; border: 1px solid var(--line); border-left: 4px solid var(--low);
    border-radius: 10px; padding: 16px 18px; margin: 0 0 16px; }}
  .finding.sev-critical {{ border-left-color: var(--crit); }}
  .finding.sev-high {{ border-left-color: var(--high); }}
  .finding.sev-medium {{ border-left-color: var(--med); }}
  .finding header {{ display: flex; gap: 8px; align-items: center; margin: 0 0 6px; }}
  .id {{ font-weight: 700; letter-spacing: .02em; }}
  .sev {{ font-size: 12px; text-transform: uppercase; color: var(--muted); }}
  .verdict {{ margin-left: auto; font-size: 12px; font-weight: 600; padding: 2px 8px;
    border-radius: 999px; background: #f1f5f9; color: var(--nottested); }}
  .v-confirmed .verdict {{ background: #fee2e2; color: var(--confirmed); }}
  .v-not_confirmed .verdict {{ background: #dcfce7; color: var(--notconf); }}
  h3 {{ font-size: 16px; margin: 4px 0 8px; }}
  .path code {{ background: #f1f5f9; padding: 2px 6px; border-radius: 4px; font-size: 13px; }}
  .arrow {{ color: var(--muted); margin: 0 8px; font-size: 13px; }}
  .boundary {{ color: var(--high); font-size: 13px; }}
  .obs {{ background: #fafafa; border: 1px solid var(--line); border-radius: 8px;
    padding: 10px 12px; }}
  .call {{ background: #0f172a; color: #e2e8f0; padding: 10px 12px; border-radius: 8px;
    overflow-x: auto; font-size: 12px; }}
  .said {{ border-left: 3px solid var(--line); margin: 8px 0; padding: 4px 0 4px 12px;
    color: var(--muted); font-style: italic; }}
  .caveat {{ font-size: 13px; color: var(--muted); }}
  .why {{ font-size: 12px; color: var(--muted); border-top: 1px solid var(--line);
    padding-top: 8px; margin-top: 10px; }}
  footer {{ color: var(--muted); font-size: 12px; text-align: center; margin-top: 28px; }}
</style>
</head>
<body>
<main>
  <h1>Attack paths in {name}</h1>
  <p class="meta">Harness {harness}. {servers} servers, {tools} tools, {findings} findings.</p>
  {incomplete}
  {confirm}
  {cards}
  <footer>Generated by agentpath. Findings marked candidate were not tested against an agent.
  A result is only as current as the model and payloads it was produced with.</footer>
</main>
</body>
</html>"""
