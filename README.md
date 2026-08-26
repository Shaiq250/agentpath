# agentpath

An offline attack path analyser for AI agents and the tools they can call.

Point it at an agent's tool configuration and it reports the paths an attacker
could use: which untrusted input tool can reach which dangerous tool, the
scenario that gets it there, and how to break the chain.

Everything runs locally. No account, no API key, no network call, nothing about
your tools leaves the machine.

## Status

Early. This is M0, the walking skeleton: it reads a manifest file, labels the
tools, finds the paths, and writes a report. Live enumeration of MCP servers and
the confirmation mode described below are the next two milestones.

## The problem

An AI agent cannot tell the difference between content it reads and instructions
it is given. If one of its tools reads something an attacker controls, a support
ticket, a pull request comment, a web page, and another of its tools does
something dangerous, run a command, send an email, issue a refund, then the
attacker can write an instruction into the content and the agent may carry it
out. That is indirect prompt injection, and it is a property of the tool
combination rather than of any one tool.

So the unit of analysis is not the tool, it is the path.

## Example

```
$ agentpath analyze examples/support-agent.json

### APA-0001: Full exfiltration chain: untrusted input, sensitive data, outbound channel

`zendesk/read_ticket` -> agent -> `zendesk/send_email`

Scenario. An attacker plants an instruction in content read by
zendesk/read_ticket. The agent can reach sensitive data through
billing-db/get_customer_record, and can send data out through
zendesk/send_email...

Fix. Break the chain at one point: keep zendesk/read_ticket out of any session
that can also reach sensitive data, or pin zendesk/send_email to approved
destinations, or require approval before sensitive data leaves.
```

## Install and run

```
pip install -e ".[dev]"
agentpath analyze examples/support-agent.json
agentpath analyze examples/support-agent.json --format json -o report.json
agentpath analyze examples/support-agent.json --fail-on high
```

`analyze` exits 1 when a finding at or above the threshold exists, so it works
in CI.

## How it decides

Each tool gets zero or more capability labels: `untrusted-read`, `secret-read`,
`egress`, `state-change`, `code-exec`. A rule fires when a dangerous combination
of labels exists in the same agent. Labels come from MCP annotations, input
schema parameters, tool name patterns and description keywords, and every label
in the report carries the reason it was assigned.

Annotations are supplied by the server author, so they raise confidence when
they signal danger but are never trusted to clear a tool as safe. A tool
annotated read only whose name says delete is reported, with the conflict noted.

## How this compares to what else exists

This is not the first tool in this space and does not claim to be. Snyk Agent
Scan, AgentAuditKit and others already scan agents and MCP servers, and the
source to sink flow model itself is published prior art, including Invariant
Labs' work on toxic flow analysis.

Three things here are different:

- It runs entirely offline. The leading free alternative requires an API token
  and sends your tool inventory to a hosted endpoint for analysis.
- It reports paths rather than per tool risk scores: a named source, a named
  sink, the scenario, and the fix.
- It will confirm paths rather than only predicting them. A later milestone adds
  a mode that plants a marked payload through a source tool and observes whether
  the agent really calls the sink, with the real sink replaced by an
  instrumented stand in so nothing dangerous actually runs.

## Known limitations

- Findings are candidates. A candidate means the tool combination makes the path
  possible, not that this agent has been observed walking it.
- An empty report is not a guarantee of safety.
- File reading tools are not treated as untrusted entry points yet, even though
  an attacker who can write a file could use one as an entry point. Entry point
  labels multiply across every sink, so this one is kept strict on purpose. The
  override file in the next milestone is how you add the label for your own
  environment.
- Single agent only. Several agents on one machine sharing a server, tool
  shadowing across servers, and multi hop chains are later milestones.

## Ethics

Analyse only agents you own or are authorised to test.

## Licence

Apache 2.0.
