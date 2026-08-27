# agentpath

![tests](https://github.com/Shaiq250/agentpath/actions/workflows/ci.yml/badge.svg)

An offline tool that finds attack paths in the tools an AI agent can call, and
then tests whether a model follows an injection planted along one of them.

Point it at an agent's configuration and it reports the paths an attacker could
use: which untrusted input tool can reach which dangerous tool, the scenario that
gets it there, and how to break the chain. Then, if you want, it puts a marked
instruction in front of a real model through stand in versions of those tools,
and checks whether the model follows it.

That last step tests a model against tools shaped like the ones the agent has. It
is not a test of a deployed agent end to end, since it does not use the agent's
real system prompt or its real tool implementations. It tells you whether a model
of that kind follows this kind of injection, which is worth knowing and is not
the same as proving that a particular deployment is exploitable.

Everything else runs on your machine. No account, no API key for the analysis,
and nothing about your tools leaves the box. The confirmation step can use a real
model if you give it a key, but it never has to.

## The problem

An AI agent cannot reliably tell the difference between content it reads and
instructions it is given. If one of its tools reads something an attacker
controls, a support ticket, a pull request comment, a web page, and another of
its tools does something dangerous, runs a command, sends an email, issues a
refund, then the attacker can write an instruction into the content and the agent
may carry it out. This is indirect prompt injection, and it is a property of the
combination of tools rather than of any single tool.

So the thing worth analysing is not the tool. It is the path.

## What makes this different

This is not the first tool to scan agents and MCP servers, and it does not claim
to be. Snyk, AgentAuditKit and others already work in this space, and the source
to sink flow idea is older than any of them. Three things here are worth your
attention anyway.

It runs entirely offline. The analysis needs no account and sends nothing
anywhere. A well known free alternative requires an API token and uploads your
tool inventory for analysis.

It reports paths, not scores. Instead of telling you a tool looks risky and
giving it a number, it names the source, names the sink, describes the scenario,
and tells you how to break it.

It can confirm a path instead of only predicting one. It plants a marked
instruction in content a source tool returns, gives a model an ordinary task, and
checks whether the dangerous tool gets called with that marker. The check is a
plain string match rather than a second model judging the first, so it stays
deterministic and free. I have not found another free tool that does this, though
I have only surveyed the well known ones.

## A worked result

Here is what the tool found on the bundled support agent example. Both halves
matter, which is why they are reported together.

Static analysis found three candidate paths. Against a scripted stand in, a small
program that follows any instruction it reads, all three were walked. That shows
the paths are real and the harness delivers its payload.

Against `claude-sonnet-4-6` in August 2026, with five different payload
phrasings, none of the three were walked. The model read the planted ticket,
recognised the injection attempt, and refused it, in some cases flagging it to
the user in its reply.

Neither number says much alone. The scripted run by itself would read as
scaremongering. The model run by itself would read as nothing to see here.
Together they say something true: the paths are genuinely reachable, and a
current model resists the naive version of the attack.

The caveat travels with every negative result. Not walked is not the same as
safe. A different model, a different system prompt, a different temperature or a
better payload can change the answer.

## Try it in two minutes

The `examples/demo/` folder has a deliberately vulnerable agent and its own
walkthrough. The short version:

```
pip install -e ".[dev]"

# find the paths
agentpath analyze examples/demo/vulnerable-agent.json

# watch them get walked by a scripted follower, no key needed
agentpath confirm examples/demo/vulnerable-agent.json --agent scripted -o conf.json
agentpath analyze examples/demo/vulnerable-agent.json --confirmations conf.json --format html -o report.html
```

Reports come out as Markdown, JSON, HTML or SARIF. Open `report.html` in a
browser and the whole picture is in one file. There is a
pre generated copy at `examples/demo/sample-report.html` if you would rather look
before you install.

## Scanning your own machine

```
agentpath collect -o manifest.json
agentpath analyze manifest.json
```

`collect` reads the MCP configurations for Claude Code, Claude Desktop, Cursor,
VS Code and others, starts each configured server, and asks it which tools it
offers. Starting a server means running the command in its config file, so those
commands are printed before anything runs. Use `--no-launch` to read the configs
without executing anything, and scan configurations you do not trust inside a
container.

A server that fails to start, times out, or gets skipped contributes no tools,
and no tools looks exactly like a safe server. So every server carries its
enumeration status, and the report refuses to call a scan clean when any server
was not enumerated. A scan that saw nothing is not a scan that found nothing.

## Confirming a path

```
agentpath confirm manifest.json -o confirmations.json
agentpath analyze manifest.json --confirmations confirmations.json
```

For each candidate it builds a stand in source tool that returns realistic
content with a planted instruction inside, and a stand in sink that records calls
and does nothing else. The real tools are never called. No refund is issued, no
email is sent, no command runs. The model's decision is real, only the
consequence is fake, and the consequence is the part nobody needs.

There are three outcomes, not two. Confirmed means the sink was called with the
planted marker. Not confirmed means the model read the content and did not act on
it. Not tested means the model never read the content at all, so nothing was
learned. That third case is kept separate on purpose: a model that never sees the
payload should never be mistaken for one that resisted it.

Two kinds of agent can run. A scripted stand in that needs no key and always
follows what it reads, there to prove the harness works. And a real model, which
needs `ANTHROPIC_API_KEY` and is the only one whose results say anything about
how a model behaves. Without a key the tool reports paths as untestable rather
than quietly falling back to the scripted agent, because that would be
manufacturing evidence. The two are always labelled differently in the output.

The payloads ship at two difficulty levels, obvious and plausible, and a
confirmed result reports which one walked the path. A confirmation that only
works with a blunt all caps instruction is a weaker result than one that works
with an instruction disguised as a routine field, and the report does not let the
two look alike.

## Running it in CI

There is a GitHub Action and SARIF output, so findings show up in the Security
tab of a repository rather than only in a log nobody reads.

```yaml
- uses: Shaiq250/agentpath@main
  id: scan
  with:
    manifest: agent-manifest.json
    baseline: .agentpath-baseline.json
    fail-on: high

- uses: github/codeql-action/upload-sarif@v3
  if: always()
  with:
    sarif_file: ${{ steps.scan.outputs.sarif-file }}
```

The full workflow, including the permissions it needs, is in
`docs/github-action.md`.

When no manifest is given the action runs `collect --no-launch`, which reads
configuration without executing anything. A workflow triggered by a pull request
may be looking at a branch a stranger wrote, and starting the servers it declares
would mean running that stranger's commands on your runner.

## Adopting it on a repository that already has findings

Nobody fixes forty findings the day they install a scanner, and a tool that
demands it gets switched off instead. Record what is already there and let CI
fail only on what gets added:

```
agentpath analyze manifest.json --write-baseline .agentpath-baseline.json
agentpath analyze manifest.json --baseline .agentpath-baseline.json
```

Baselined findings still appear in the report and in SARIF, marked as suppressed
with a reason. A baseline is a snapshot of what was already there. It is not a
decision that any of it is acceptable, and the report says so every time it
prints one, because the failure mode here is a team believing forty findings were
reviewed when nobody looked at any of them.

If you have reviewed one specific path and decided it is fine, that belongs in
the accept list in `.agentpath.yml` instead, where it carries a reason and a
date. The two are kept apart on purpose so a bulk snapshot never reads like a set
of considered decisions.

## Problems between servers

Some things only go wrong when several servers share one agent, and no amount of
looking at a single tool will show them.

**Shadowing.** Two servers offering a tool with the same name. Which one the
agent calls depends on its client's resolution order, so it may not be the one
you meant. When the two servers are not equally trusted this is an attack rather
than an inconvenience: a third party server can end up standing in for a
privileged one.

**Confusable names.** Names that differ only by case, punctuation or a trailing
version number. Nobody has necessarily done anything wrong, but a person
approving one call out of several can reasonably mistake `sendReport2` for
`send_report`.

**Drift.** A tool that is not the tool it was last time you looked. This is the
rug pull: a server behaves while you evaluate it, then rewrites a description
afterwards. `collect` records a fingerprint of every tool definition it sees, so
the next scan can tell you what moved, including tools that appeared or vanished
without anyone approving the change.

All three appear under "Between servers" in the report, with their own APX ids,
and in SARIF as their own rules.

### The first scan cannot detect drift

There is nothing to compare a server against until it has been seen once. A first
scan therefore reports no drift for the same reason an unplugged smoke alarm
reports no fire, so the report says which servers were seen for the first time
and that no conclusion about them is possible yet.

That is also why the tool re-reads every server on every run rather than reusing
what it cached. The record of what a server offered is there to catch it
changing, not to save a few seconds.

## Correcting it: .agentpath.yml

The classifier guesses labels from names, descriptions and annotations, so it
will be wrong about tools specific to your setup. A file next to your manifest
fixes that, and records paths you have reviewed and chosen to accept:

```yaml
labels:
  docs/search_handbook: []                     # not an entry point, curated content
  workspace/read_file:
    add: [untrusted-read]                      # it is one here, attackers can write there

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

The file is read from the current directory only. Inheriting suppressions from a
parent directory you had forgotten about would be a nasty way to lose a finding.

## How accurate is the classifier

There is a hand labelled corpus in `examples/corpus/`, 30 tools across six
servers modelled on common ones, with the correct labels and the reasoning for
the debatable calls written out.

```
python scripts/measure_labels.py
```

It scores 1.00 precision and 1.00 recall on that corpus, and you should not read
that as an accuracy claim. The rules were tuned until they matched this corpus,
so the score measures agreement with labels the tool has already seen. A corpus
collected after tuning would score lower.

What it is good for is catching regressions. Change a rule and every tool whose
labels move is printed by name, so a fix in one place cannot quietly break
another. The honest way to turn this into a real accuracy number is to add fresh
servers, label them first, and measure without touching the rules afterwards.

## Measured against someone else's answer key

The number above has a problem: the rules were tuned to that corpus, so it
measures agreement with labels this tool has already seen. Hand labelling by the
person who wrote the rules only ever proves they are internally consistent.

MCP tool annotations are a way around that. Server authors declare in their own
source what their tools do. `readOnlyHint` says a tool does not modify its
environment, `openWorldHint` says it reaches out to external entities. Those
declarations were written by people who have never heard of this tool.

So the classifier was switched to ignore annotations entirely, made to work out
what each tool does from its name, description and schema alone, and compared
against what the authors declared.

```
python scripts/measure_annotations.py
```

On 21 annotated tools taken from the git, memory, fetch and time servers in
`modelcontextprotocol/servers`, extracted from source:

| check | agreement |
| --- | --- |
| `openWorldHint` against untrusted-read | 21 of 21 |
| `readOnlyHint` against state-change | 18 of 21 |
| overall | 39 of 42, 93 percent |

The three it got wrong were `git_commit`, `git_reset` and `git_checkout`. Their
authors declared all three as modifying the repository. Reading only the name and
description, the classifier said they did not, because those verbs were missing
from its state-change list.

That run is kept verbatim at `examples/heldout/RESULT-2026-08-27.txt`, dated and
recorded before any rule was changed in response to it, so the number cannot be
quietly improved later.

Those verbs have since been added, and the score is now 42 of 42. **That second
number is not a measurement.** It is what you get after tuning to the key, so
this corpus has become a regression guard, in the same way the first one did. The
93 percent is the honest figure, and the recorded file is there so it stays
visible next to the perfect one.

Getting another independent number means finding servers nobody here has looked
at yet. That is the cost of measuring properly and it is worth paying.

## Known limitations

Accuracy numbers age. Both measurements above are dated and tied to a specific
set of servers, and a corpus stops being a measurement the moment its results are
used to change the rules.

Findings without a confirmation are candidates. A candidate means the combination
makes the path possible, not that any model has been observed walking it.

An empty report is not a guarantee of safety, and neither is a not confirmed
result.

Confirmation uses stand in tools and a generic task, so it does not exercise a
deployed agent's own system prompt or tool implementations.

Only stdio MCP servers are enumerated today. HTTP and SSE servers are recorded as
skipped, which makes the scan incomplete rather than silently empty.

File reading tools are not treated as untrusted entry points by default, because
whether an attacker can write to what they read depends on the environment. The
override file is how you tell the tool about your own setup.

One agent at a time. Several agents sharing a server, tool shadowing across
servers, and multi hop chains are on the roadmap and not built yet.

## Ethics

Analyse and test only agents you own or are explicitly authorised to test. The
payload library exists to check whether a model can be steered, not to attack
anything, and it is kept small and clearly labelled for that reason.

## Licence

Apache 2.0.
