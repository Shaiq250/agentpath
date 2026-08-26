# agentpath

<!-- After you create the GitHub repo, replace OWNER/REPO below and delete this comment. -->
![tests](https://github.com/OWNER/REPO/actions/workflows/ci.yml/badge.svg)

An offline tool that finds attack paths in the tools an AI agent can call, and
then tests whether an agent actually walks them.

Point it at an agent's configuration and it reports the paths an attacker could
use: which untrusted input tool can reach which dangerous tool, the scenario
that gets it there, and how to break the chain. Then, if you want, it plants a
marked instruction and watches whether the agent really follows it.

Everything runs on your machine. No account, no API key for the analysis, and
nothing about your tools leaves the box. The confirmation step can use a real
model if you give it a key, but it never has to.

## The problem

An AI agent cannot reliably tell the difference between content it reads and
instructions it is given. If one of its tools reads something an attacker
controls, a support ticket, a pull request comment, a web page, and another of
its tools does something dangerous, runs a command, sends an email, issues a
refund, then the attacker can write an instruction into the content and the
agent may carry it out. This is indirect prompt injection, and it is a property
of the combination of tools, not of any single tool.

So the thing worth analysing is not the tool. It is the path.

## What makes this different

This is not the first tool to scan agents and MCP servers, and it does not claim
to be. Snyk, AgentAuditKit and others already work in this space, and the source
to sink flow idea itself is older than any of them. Three things here are worth
your attention anyway.

It runs entirely offline. The analysis needs no account and sends nothing
anywhere. The leading free alternative requires an API token and uploads your
tool inventory for analysis.

It reports paths, not scores. Instead of telling you a tool looks risky and
giving it a number, it names the source, names the sink, describes the scenario,
and tells you how to break it.

It can confirm a path instead of only predicting one. This is the part nothing
else in the free tooling does. It plants a marked instruction in content a
source tool returns, gives an agent an ordinary task, and checks whether the
dangerous tool gets called with that marker. The check is a plain string match,
not a second model judging the first, so it stays deterministic and free.

## A worked result

Here is what the tool actually found on the bundled support agent example, which
is worth reading in full because the two halves together are the point.

Static analysis found three candidate paths. Run against a scripted stand in,
one that follows any instruction it reads, all three were walked, which shows the
paths are real and the harness delivers the payload. Run against a current
language model, none of the three were walked. The model read the planted
ticket, recognised the injection attempt, and refused it, in some cases flagging
it to the user.

Neither number means much alone. The scripted run on its own would read as
scaremongering. The model run on its own would read as "nothing to see here."
Together they say something true and useful: the paths are genuinely reachable,
and a current model currently resists the naive version of the attack. That is
the honest state of things, and it is exactly what a tool like this should be
able to show rather than assert.

And the caveat that travels with every negative result: not walked is not the
same as safe. A different model, a different prompt, or a better payload can
change the answer.

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

Open `report.html` in a browser and you have the whole picture in one file.

## Scanning your own machine

```
agentpath collect -o manifest.json
agentpath analyze manifest.json
```

`collect` reads the MCP configurations for Claude Code, Claude Desktop, Cursor,
VS Code and others, starts each configured server, and asks it which tools it
offers. Starting a server means running the command in its config file, so the
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
email is sent, no command runs. The agent's decision is real, only the
consequence is fake, and the consequence is the part nobody needs.

There are three outcomes, not two. Confirmed means the sink was called with the
planted marker. Not confirmed means the agent read the content and did not act on
it. Not tested means the agent never read the content at all, so nothing was
learned, and that case is kept separate on purpose: an agent that never sees the
payload should never be mistaken for one that resisted it.

Two kinds of agent can run. A scripted stand in that needs no key and always
follows what it reads, there to prove the harness works. And a real model, which
needs `ANTHROPIC_API_KEY` and is the only one whose results say anything about
how an agent behaves. Without a key the tool reports paths as untestable rather
than quietly falling back to the scripted agent, because that would be
manufacturing evidence. The two are always labelled differently in the output.

The payloads ship at two difficulty levels, obvious and plausible, and a
confirmed result reports which one walked the path. A confirmation that only
works with a blunt all caps instruction is a weaker result than one that works
with an instruction disguised as a routine field, and the report does not let
the two look alike.

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

## How accurate is the classifier

There is a hand labelled corpus in `examples/corpus/`, 30 tools across six
servers modelled on common ones, with the correct labels and the reasoning for
the debatable calls written out.

```
python scripts/measure_labels.py
```

It scores 1.00 precision and 1.00 recall on that corpus, and you should not read
that as an accuracy claim. The rules were tuned until they matched this corpus,
so the score measures agreement with labels the tool has already seen. What it is
good for is catching regressions: change a rule and any tool whose labels move is
printed by name. The honest way to get a real accuracy number is to add fresh
servers, label them first, and measure without touching the rules afterwards.

## Known limitations

Findings without a confirmation are candidates. A candidate means the combination
makes the path possible, not that any agent has been observed walking it.

An empty report is not a guarantee of safety, and neither is a not confirmed
result.

Only stdio MCP servers are enumerated today. HTTP and SSE servers are recorded as
skipped, which makes the scan incomplete rather than silently empty.

File reading tools are not treated as untrusted entry points by default, because
whether an attacker can write to what they read depends on the environment. The
override file is how you tell the tool about your own setup.

Single agent at a time. Several agents sharing a server, tool shadowing across
servers, and multi hop chains are on the roadmap, not built yet.

## Ethics

Analyse and test only agents you own or are explicitly authorised to test. The
payload library exists to check whether an agent can be steered, not to attack
anything, and it is kept small and clearly labelled for that reason.

## Licence

Apache 2.0.
