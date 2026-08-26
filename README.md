# agentpath

An offline attack path analyser for AI agents and the tools they can call.

Point it at an agent's tool configuration and it reports the paths an attacker
could use: which untrusted input tool can reach which dangerous tool, the
scenario that gets it there, and how to break the chain.

Everything runs locally. No account, no API key, no network call, nothing about
your tools leaves the machine.

## Status

Early, but complete end to end. It discovers the MCP servers configured on a
machine, asks each one which tools it offers, analyses the result, and can test
whether an agent actually walks the paths it finds.

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

# scan this machine
agentpath collect -o manifest.json
agentpath analyze manifest.json

# or analyse a manifest you wrote by hand
agentpath analyze examples/support-agent.json --fail-on high
agentpath analyze examples/support-agent.json --format json -o report.json
```

The two commands are deliberately separate. `collect` touches your system,
`analyze` never does. That means a report can always be reproduced from a file,
and the only command that runs anything is one you choose to run.

`analyze` exits 1 when a finding at or above the threshold exists, or when the
scan was incomplete, so it works in CI.

## collect runs the commands in your config files

An MCP config file lists servers and how to start them. It does not list their
tools. The only way to learn a server's tools is to start it and ask, so
`collect` runs the command each config entry specifies.

Before it starts anything, it prints every server and the exact command it is
about to run. If you are scanning a config you did not write, use `--no-launch`,
which reads the config files and executes nothing, or run the scan inside a
container.

```
agentpath collect --no-launch -o manifest.json   # nothing is executed
agentpath collect --no-cache -o manifest.json    # re-ask every server
agentpath collect --timeout 30 -o manifest.json
```

## An incomplete scan never reads as a clean one

A server that fails to start, times out, or is skipped contributes zero tools.
Zero tools looks exactly like a harmless server, so the manifest records what
happened to every server, and the report refuses to give a clean verdict when
any of them is unknown:

```
> Scan incomplete. 2 of 3 servers were not enumerated.
>
> - `broken` (failed): server exited before replying: ImportError: no module named nope
> - `remote` (skipped): http transport is not enumerated yet, so its tools are unknown
```

A scan that saw nothing is not a scan that found nothing. That distinction is
worth more than any individual rule in this tool.

## How it decides

Each tool gets zero or more capability labels: `untrusted-read`, `secret-read`,
`egress`, `state-change`, `code-exec`. A rule fires when a dangerous combination
of labels exists in the same agent. Labels come from MCP annotations, input
schema parameters, tool name patterns and description keywords, and every label
in the report carries the reason it was assigned.

Annotations are supplied by the server author, so they raise confidence when
they signal danger but are never trusted to clear a tool as safe. A tool
annotated read only whose name says delete is reported, with the conflict noted.

## Confirming a path instead of predicting it

Static analysis produces candidates. `agentpath confirm` turns a candidate into
something you have watched happen.

```
agentpath confirm manifest.json -o confirmations.json
agentpath analyze manifest.json --confirmations confirmations.json
```

For each candidate path it builds a stand in source tool that returns realistic
content with a planted instruction inside it, and a stand in sink tool that
records calls and does nothing else. Then it gives an agent a normal task and
watches what happens.

**The real tools are never called.** No refund is issued, no email is sent, no
command runs. The agent believes it has these tools and its decision to use them
is real. Only the consequence is fake, and the consequence is the part nobody
needs.

The planted content carries a marker that exists nowhere else. A path is
confirmed only when the sink is called with that marker in its arguments, which
proves the data flowed rather than the agent happening to use a tool. The check
is a string comparison, not a second model grading the first, which is why this
stays deterministic and free.

Each path is tried several times with different payload phrasings, because one
refusal proves nothing: an agent that ignores a blunt instruction may still
follow one dressed as a system notice.

### Two agents, and the difference matters

`--agent model` uses a real language model and needs `ANTHROPIC_API_KEY`. Only
these results say anything about how an agent behaves.

`--agent scripted` uses a small program that always follows what it reads. It
needs no key and runs offline, and it exists so the harness itself can be tested
in CI. **A confirmation from the scripted agent proves the plumbing works, not
that anything is vulnerable**, and every place those results appear says so.

Without an API key the tool reports paths as untestable rather than quietly
falling back to the scripted agent, because that would be manufacturing
evidence.

### Three outcomes, not two

A path can be confirmed, not confirmed, or not tested. That third one matters:
if the agent never calls the source tool, the payload was never put in front of
it, and reporting that as a negative result would let a broken test look like a
resistant agent. Not tested is called out separately and leaves the finding a
candidate.

Not confirmed is not safe either. Models are sampled, and a different model,
prompt, temperature or payload can change the answer. A tested-and-not-walked
path stays a candidate with that sentence attached, and the report keeps the
agent's own response so a refusal can be read rather than assumed.

The payloads ship at two difficulty levels, obvious and plausible, and a
confirmed result reports which one walked it. This is deliberate: a confirmation
that only ever works with a blunt all-caps instruction is a weaker result than
one that works with an instruction disguised as a routine field, and the report
should not let the two look the same.

## Correcting it: .agentpath.yml

The classifier guesses from names, descriptions and annotations, so it will be
wrong about tools specific to your environment. Put a file next to your manifest
to fix that, and to record paths you have reviewed and decided to live with:

```yaml
labels:
  docs/search_handbook: []                     # not an entry point, curated content
  workspace/read_file:
    add: [untrusted-read]                      # it is one here, attackers can write there
    remove: [secret-read]

trust:
  github: third-party
  workspace: privileged

accept:
  - rule: untrusted_read_to_egress
    source: slack/get_channel_history
    sink: slack/post_message
    reason: "Reviewed 2026-09-01, channel is internal only"
    date: 2026-09-01
```

Accepted paths are suppressed, not deleted. They stay in the report under their
own heading with the reason attached, because a suppression nobody can see is
indistinguishable from a bug. An acceptance without a reason is rejected.

The file is read from the current directory only. Silently inheriting
suppressions from a parent directory would be a nasty way to lose a finding.
Use `--policy PATH` to point somewhere else, or `--no-policy` to ignore it.

## How accurate is it

There is a hand labelled corpus in `examples/corpus/`: 30 tools across six
servers modelled on common ones, with the correct labels written out in
`ground-truth.json`, including the reasoning for the debatable calls.

```
python scripts/measure_labels.py
```

It currently scores 1.00 precision and 1.00 recall on that corpus.

**Do not read that as an accuracy claim.** The rules were tuned until they
matched this corpus, so the score measures agreement with our own labels on
tools we already looked at. A corpus collected after tuning would score lower,
and the honest way to improve this number is to add servers first and fix the
rules afterwards.

What it is genuinely good for is regressions. Change a rule and every tool whose
labels move is printed by name, so a fix in one place cannot quietly break
another. The ground truth is also our judgement rather than an external
standard, which is why the debatable calls are written down: disagree with a
specific line rather than with the number.

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
- It confirms paths rather than only predicting them. `agentpath confirm` plants
  a marked payload through a stand in source tool and observes whether the agent
  really calls the sink, with the real sink replaced by an instrumented stand in
  so nothing dangerous runs.

## Known limitations

- Findings are candidates. A candidate means the tool combination makes the path
  possible, not that this agent has been observed walking it.
- The accuracy number above is measured on a corpus the rules were tuned
  against, so treat it as a regression guard rather than an estimate of
  performance on servers nobody has looked at.
- An empty report is not a guarantee of safety.
- File reading tools are not treated as untrusted entry points yet, even though
  an attacker who can write a file could use one as an entry point. Entry point
  labels multiply across every sink, so this one is kept strict on purpose. The
  override file in the next milestone is how you add the label for your own
  environment.
- Single agent only. Several agents on one machine sharing a server, tool
  shadowing across servers, and multi hop chains are later milestones.
- Only stdio servers are enumerated. HTTP and SSE servers are recorded as
  skipped, which makes the scan incomplete rather than silently empty.

## Ethics

Analyse only agents you own or are authorised to test.

## Licence

Apache 2.0.
