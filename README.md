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

## Write-up

[What it costs to measure a security tool honestly](docs/measuring-a-detector.md)
covers how this tool was measured and what each attempt got wrong: a corpus that
scored 1.00 and meant nothing, an external answer key that turned out to be
answering a different question, and a recall corpus where the labelling took four
attempts and the detector was right every time I disagreed with it.

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

## Tools that did not come from MCP

The analysis never cared where a tool came from. It works on a manifest, and a
manifest is a list of tools with names, descriptions and schemas.

```
agentpath import tools.json -o manifest.json          # tool definitions
agentpath import openapi.json -o manifest.json        # an API description
agentpath analyze manifest.json
```

The first reads the array of tool definitions an agent built against a model API
already has, in either the snake_case or camelCase spelling, and unwraps the
OpenAI function wrapper if it finds one.

The second turns each operation in an OpenAPI document into a tool, which is
worth more than it sounds: the HTTP method says something the tool name often
does not. A GET is a read whatever it is called, and a DELETE changes something
even when its summary is a cheerful sentence about tidying up. Those become the
same annotations an MCP server would declare, so the classifier does not need to
know where the tool came from.

If your tools live somewhere neither importer covers, `docs/manifest.md`
documents the format. An importer is a function that reads something and returns
that structure, and the two that ship are about a hundred lines each. There is no
plugin system because there does not need to be one.

## Scanning your own machine

```
agentpath scan
```

That reads the agent configuration on this machine, asks each server what it
offers, and prints a report. It keeps the manifest, so the same report can be
reproduced, re-analysed under a different policy, or confirmed against a model
later without touching anything again. The two steps are also available
separately:

```
agentpath collect -o manifest.json
agentpath analyze manifest.json
```

`collect` reads the MCP configurations for Claude Code, Claude Desktop, Cursor,
VS Code and others, then asks each configured server which tools it offers. For a
local server that means running the command in its config file. For a remote one
it means a request to the URL that file names, which is a smaller risk but still
somewhere a config chose, so both happen under the same rule and both are printed
before anything runs. Use `--no-launch` to read the configs
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

Both attack paths and the issues between servers can be baselined, so a
repository with three unpinned servers can record that once instead of being
pushed into the accept list, which is for decisions rather than snapshots.
Baselined findings still appear in the report and in SARIF, marked as suppressed
with a reason. A baseline is a snapshot of what was already there. It is not a
decision that any of it is acceptable, and the report says so every time it
prints one, because the failure mode here is a team believing forty findings were
reviewed when nobody looked at any of them.

If you have reviewed one specific path and decided it is fine, that belongs in
the accept list in `.agentpath.yml` instead, where it carries a reason and a
date. The two are kept apart on purpose so a bulk snapshot never reads like a set
of considered decisions.

## Which attack classes it covers

`docs/coverage.md` has a table of the publicly documented MCP attack classes and
what agentpath does about each one, including the ones it cannot see and why.
Tool poisoning, concealed payloads, rug pulls, shadowing, unpinned servers and
credentials in configs are detected. Poisoning is checked in prompts and
resources as well as tools, because all three are loaded into the same context
and text that steers a model does not care which one it arrived in. Confused deputy, typosquatting and server
side implementation bugs are not, because nothing in a tool manifest reveals
them.

The rules that read tool descriptions are checked in both directions.

For false positives, against 123 tool definitions from nine real servers. A test
fails if any of them produces a single finding on that set, because a rule that
fires on ordinary tools covers a class and helps nobody.

For recall, against deliberately vulnerable servers published by other people:
Invariant Labs' original tool poisoning and shadowing demonstrations, and the
Damn Vulnerable MCP challenge servers. **80 percent caught, with no false
positives on the 26 benign tools alongside them**, recorded before the rules were
changed in response. The one miss was a `<HIDDEN>` instruction block, which the
pattern did not know about because it listed three tag words rather than
describing what a pseudo tag is. That is now generalised, so the corpus has
become a regression guard and the 80 percent is the standing figure.

```
python scripts/measure_recall.py
```

Worth reading `examples/recall/ground-truth.json` for how the labelling went. It
took four attempts, the number moved between 40 and 80 percent purely on
labelling choices, and every one of the four disagreements between the detector
and a label turned out to be the label's fault. On a corpus this small the
labelling decision matters more than the detector does, and all four wrong
attempts are written down rather than tidied away.

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

Shadowing also has a quieter effect on the path findings themselves. If two
servers both offer `read_file` and both offer `send_report`, the naive result is
four findings describing one situation. Paths that differ only in which server
provides an identically named tool are folded into one, the version that crosses
a trust boundary is the one kept, and the others are listed on it. Which server
actually answers the call is the shadowing issue's business and is reported
there.

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

## Trust domains and mitigations

A tool that reports every path at full severity is describing a theoretical
system rather than the one in front of you. The policy file can describe what is
already true, and findings move accordingly:

```yaml
domains:
  privileged: [workspace, vault]
  internal: [wiki]
  third-party: [community-plugin, web]

gated:
  - "workspace/deploy"          # a human approves each call

approved_flows:
  - from: internal
    to: privileged
    reason: "Same estate, reviewed 2026-09-01"
```

A path that reaches a more trusted domain than it started in is raised. One that
stays inside a single domain is lowered. A sink you have gated behind human
approval is lowered, and so is a flow you have reviewed.

Two rules keep this from becoming a way to make findings disappear.

**Severity moves, findings do not.** Nothing here can push a finding below low
and nothing here removes one. Hiding a finding is what the accept list is for,
and that is a decision someone makes explicitly, with a reason and a date.

**Anything you assert is labelled as asserted.** agentpath cannot see whether a
sink really is gated behind a human. It only knows you said so. So every
adjustment is printed with its reason and with where it came from, either from
the configuration itself or declared in your policy file and not verified. The
original severity stays visible. If the gate does not actually exist, the report
should let someone notice that rather than quietly build it in.

For CI there is a third control. `--ignore-declared` makes the exit code use the
severity a finding would have had without any claim from the policy file, while
still applying the adjustments that come from the configuration itself. Without
it, adding a `gated:` line for a tool nobody actually gates is enough to turn a
build green. The finding stays in the report either way, so nothing is hidden,
but a build passing on an unverified assertion is close enough to the failure
this tool spends its time avoiding.

```
agentpath analyze manifest.json --policy .agentpath.yml --fail-on high --ignore-declared
```

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
source what their tools do, and those declarations were written by people who
have never heard of this tool. So the classifier is switched to ignore
annotations entirely, made to work out what each tool does from its name,
description and schema alone, and compared against what the authors declared.

```
python scripts/measure_annotations.py     # git, memory, fetch, time
python scripts/measure_annotations_2.py   # sentry, cloudflare
```

The comparison is `readOnlyHint` against the state-change label. An author
setting it to false is stating that the tool modifies something.

| batch | servers | tools | agreement |
| --- | --- | --- | --- |
| first, after fixing what it found | git, memory, fetch, time | 21 | 21 of 21 |
| second, untouched since | sentry, cloudflare | 69 | 67 of 69, 97 percent |

The second batch is the one to trust. Nothing was tuned to it, and the two it
missed are still missed: `d1_database_query`, a SQL tool that can write, and
`analyze_issue_with_seer`, which reads like analysis and starts a job. Neither is
decidable from a name and a description, so the rules were left alone rather than
bent to fit two hard cases.

Both runs are kept verbatim and dated at `examples/heldout/RESULT-2026-08-27.txt`
and `examples/heldout-2/RESULT-2026-08-27.txt`, recorded before anything was
changed in response to them.

### A mapping that was retired, and why

This used to compare `openWorldHint` against untrusted-read as well, and scored
21 of 21 on the first batch. The second batch showed that was luck.

Sentry marks nearly every one of its tools `openWorldHint: true`, correctly,
because they all call the Sentry API. But `whoami`, `create_team` and
`find_projects` are not entry points for attacker authored content. The label was
right and the annotation was answering a different question. `openWorldHint`
means "talks to something outside this process". Untrusted-read means "brings in
content someone hostile could have written". One cannot stand in for the other,
and the earlier perfect score came from a batch of local tools where almost
nothing set the annotation, so the mapping was never really tested.

It was retired rather than kept, and the earlier claim is corrected here rather
than quietly deleted. A check that only agrees when it happens not to be tested
is worse than no check.

That also means untrusted-read, secret-read and egress have never been measured
against an external answer key. Only state-change has. Worth knowing when reading
any of these numbers.

## Messy input

Config files are written by hand and by other tools, so fields turn up in the
wrong shape. A command written as a list, args written as one string, a
description that is a number, a schema that is a list of names, a server entry
that is null. All of it is read as generously as possible rather than rejected,
because a scanner that throws on one malformed entry has stopped scanning the
whole machine, which is a worse outcome than reading that entry loosely.

The one place this does not apply is annotations. An annotation with the wrong
type is not read as true, because a value that is not `true` should never be
what clears a tool.

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

Remote servers are reached over streamable HTTP. The older HTTP and SSE
transport is not implemented, and a server using it is recorded as failed with
the reason rather than quietly contributing nothing.

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
