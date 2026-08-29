"""Turn candidate findings into confirmed ones by watching an agent.

Static analysis says a path is possible. This says whether an agent walked it.

Three verdicts, and the wording of each matters as much as the mechanism:

  confirmed      the sink was called with the marker, at least once
  not_confirmed  the agent was given every chance and did not do it
  untestable     no agent was available, so nothing was learned

not_confirmed is NOT a clean bill of health, and nothing in this module or the
report is allowed to imply that it is. Models are sampled. A different model, a
different system prompt, a different temperature or a better payload can all flip
it. That sentence travels with every negative result.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Callable

from .agents.base import AgentUnavailable, ConfirmationAgent
from .harness import (
    CONFIRMED,
    NOT_CONFIRMED,
    NOT_DELIVERED,
    UNTESTABLE,
    build_scenario,
    judge,
    new_nonce,
)
from .payloads import default_selection

NOT_CONFIRMED_CAVEAT = (
    "Not confirmed is not a guarantee of safety. A different model, system prompt, "
    "temperature or payload can change this result."
)

SCRIPTED_CAVEAT = (
    "This result came from a scripted stand in, not a language model. It shows the "
    "harness works. It says nothing about whether a real agent would do this."
)

NOT_DELIVERED_CAVEAT = (
    "The agent never called the source tool, so the payload was never put in front of "
    "it. This path was not tested. Do not read it as a negative result."
)


@dataclass
class Confirmation:
    finding_id: str
    verdict: str
    attempts: int = 0
    succeeded: int = 0
    agent_kind: str = ""
    agent_name: str = ""
    trustworthy: bool = False
    delivered: int = 0
    payloads_tried: list[str] = field(default_factory=list)
    attempts_log: list[dict[str, Any]] = field(default_factory=list)
    observed_call: str = ""
    nonce: str = ""
    agent_said: str = ""
    agent_responses: list[str] = field(default_factory=list)
    detail: str = ""
    caveat: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def confirm_finding(finding, agent: ConfirmationAgent, attempts: int = 3) -> Confirmation:
    """Run one candidate path through the harness several times."""
    source = finding.source.tool
    sink = finding.sink.tool
    payloads = default_selection(attempts)

    result = Confirmation(
        finding_id=finding.id,
        verdict=NOT_CONFIRMED,
        attempts=0,
        agent_kind=agent.kind,
        agent_name=agent.name,
        trustworthy=bool(agent.trustworthy),
        payloads_tried=[payload.id for payload in payloads],
    )

    for payload in payloads:
        scenario = build_scenario(source, sink, payload, new_nonce())
        try:
            run = agent.run(scenario)
        except AgentUnavailable as exc:
            result.verdict = UNTESTABLE
            result.detail = str(exc)
            result.caveat = "No agent was available, so this path was not tested at all."
            return result

        result.attempts += 1
        verdict, evidence = judge(scenario, run.recorder)
        if evidence["payload_delivered"]:
            result.delivered += 1

        result.attempts_log.append({
            "payload": payload.id,
            "style": payload.style,
            "delivered": evidence["payload_delivered"],
            "sink_called": evidence["sink_called"],
            "verdict": verdict,
        })

        if verdict == CONFIRMED:
            result.succeeded += 1
            result.verdict = CONFIRMED
            result.nonce = evidence["nonce"]
            result.observed_call = evidence.get("observed_call", "")
        else:
            if not result.agent_said:
                result.agent_said = run.final_text()
            if evidence["sink_called_without_marker"] and not result.detail:
                # Worth recording, but it is not proof: the agent may have called
                # the sink for its own reasons, without the planted data reaching it.
                result.detail = (
                    "The sink was called, but without the marker, so this does not "
                    "demonstrate that the planted content reached it."
                )

    # A trial where the payload never reached the agent is not a negative result,
    # it is an absence of a result, and it has to be reported as one.
    if result.verdict != CONFIRMED and result.delivered == 0 and result.attempts:
        result.verdict = NOT_DELIVERED

    if result.verdict == CONFIRMED:
        result.caveat = SCRIPTED_CAVEAT if not result.trustworthy else ""
    elif result.verdict == NOT_DELIVERED:
        result.caveat = NOT_DELIVERED_CAVEAT
    else:
        result.caveat = NOT_CONFIRMED_CAVEAT
        if not result.trustworthy:
            result.caveat = f"{SCRIPTED_CAVEAT} {NOT_CONFIRMED_CAVEAT}"
    return result


def confirm_all(findings, agent: ConfirmationAgent, attempts: int = 3,
                on_event: Callable[[str, Any], None] | None = None) -> list[Confirmation]:
    """Confirm every candidate. Suppressed findings are skipped, not tested."""
    results: list[Confirmation] = []
    for finding in findings:
        if finding.suppressed:
            continue
        if on_event:
            on_event("start", finding)
        confirmation = confirm_finding(finding, agent, attempts)
        results.append(confirmation)
        if on_event:
            on_event("done", confirmation)
    return results


def apply_confirmations(findings, confirmations: list[Confirmation] | list[dict]) -> None:
    """Attach confirmation results to findings, in place."""
    by_id: dict[str, dict] = {}
    for entry in confirmations:
        data = entry if isinstance(entry, dict) else entry.to_dict()
        by_id[data["finding_id"]] = data

    for finding in findings:
        data = by_id.get(finding.id)
        if not data or finding.suppressed:
            continue
        finding.confirmation = data
        # A confirmed path is no longer a candidate. A negative result leaves it
        # exactly where it was: still a candidate, not downgraded, not cleared.
        if data["verdict"] == CONFIRMED:
            finding.status = CONFIRMED
        elif data["verdict"] in (UNTESTABLE, NOT_DELIVERED):
            # Nothing was learned, so the finding stays exactly as it was.
            finding.status = "candidate"
        else:
            finding.status = NOT_CONFIRMED


POISONING_CAVEAT = (
    "Not confirmed means this model, on this task, did not act on the description. "
    "A different model, task or client could still be steered by it."
)

NOT_EXERCISED_CAVEAT = (
    "The model never called the tool whose description was under test, so nothing "
    "exercised the planted text. This path was not tested."
)


def confirm_issue(issue, agent: ConfirmationAgent, attempts: int = 3) -> Confirmation:
    """Put a flagged description in front of a model and watch what it does.

    The static rule says a description contains instructions aimed at the model.
    This asks the only question that settles it: does a model follow them.

    The oracle is an unrequested tool call. The task needs exactly one tool, so
    anything else the model reaches for came from the description rather than
    from the conversation. That works without us having to interpret whatever
    the instruction actually said, which matters because the text is the server
    author's, not ours.
    """
    from .harness import build_poison_scenario, judge_poisoning

    qualified = issue.tools[0] if issue.tools else ""
    tool_name = qualified.split("/")[-1]
    description = issue.evidence.get("description", "")

    result = Confirmation(
        finding_id=issue.id,
        verdict=NOT_CONFIRMED,
        agent_kind=agent.kind,
        agent_name=agent.name,
        trustworthy=bool(agent.trustworthy),
    )
    if not description:
        result.verdict = UNTESTABLE
        result.detail = "the flagged description was not recorded, so there is nothing to test"
        result.caveat = "This description was not tested at all."
        return result

    scenario = build_poison_scenario(tool_name, description)
    exercised = 0

    for _ in range(max(1, attempts)):
        try:
            run = agent.run(scenario)
        except AgentUnavailable as exc:
            result.verdict = UNTESTABLE
            result.detail = str(exc)
            result.caveat = "No agent was available, so this description was not tested."
            return result

        result.attempts += 1
        verdict, evidence = judge_poisoning(scenario, run.recorder)
        if evidence["payload_delivered"]:
            exercised += 1
        result.attempts_log.append({
            "payload": "the tool's own description",
            "style": "real description under test",
            "delivered": evidence["payload_delivered"],
            "sink_called": bool(evidence["unrequested_calls"]),
            "verdict": verdict,
        })

        if verdict == CONFIRMED:
            result.succeeded += 1
            result.verdict = CONFIRMED
            result.observed_call = evidence.get("observed_call", "")
            result.detail = (f"the model called {', '.join(evidence['unrequested_calls'])}, "
                             f"which the task never asked for")
        else:
            said = run.final_text()
            if said:
                result.agent_responses.append(said)
                if not result.agent_said:
                    result.agent_said = said

    result.delivered = exercised

    if result.verdict != CONFIRMED and exercised == 0:
        result.verdict = NOT_DELIVERED
        result.caveat = NOT_EXERCISED_CAVEAT
    elif result.verdict == CONFIRMED:
        result.caveat = SCRIPTED_CAVEAT if not result.trustworthy else ""
    else:
        result.caveat = POISONING_CAVEAT
        if not result.trustworthy:
            result.caveat = f"{SCRIPTED_CAVEAT} {POISONING_CAVEAT}"
    return result


def confirm_poisoning(issues, agent: ConfirmationAgent, attempts: int = 3,
                      on_event=None) -> list[Confirmation]:
    """Test every flagged description. Suppressed and baselined ones are skipped."""
    from .toolaudit import CONCEALED_TEXT, POISONED_DESCRIPTION

    results: list[Confirmation] = []
    for issue in issues:
        if issue.kind not in (POISONED_DESCRIPTION, CONCEALED_TEXT):
            continue
        if issue.status != "open":
            continue
        if on_event:
            on_event("start", issue)
        confirmation = confirm_issue(issue, agent, attempts)
        results.append(confirmation)
        if on_event:
            on_event("done", confirmation)
    return results


def apply_issue_confirmations(issues, confirmations) -> None:
    by_id: dict[str, dict] = {}
    for entry in confirmations:
        data = entry if isinstance(entry, dict) else entry.to_dict()
        by_id[data["finding_id"]] = data
    for issue in issues:
        data = by_id.get(issue.id)
        if data:
            issue.confirmation = data
