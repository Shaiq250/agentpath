# Demo: a deliberately vulnerable agent

This folder holds a fake agent, `vulnerable-agent.json`, built to have obvious
attack paths so you can see agentpath work end to end in about two minutes,
without an API key and without touching anything real.

The agent is a pretend helpdesk bot. It can read customer tickets, run shell
commands, send email, and read secrets from a vault. That combination is exactly
what agentpath looks for: attacker controlled input reaching a dangerous action.

## See the paths

```
agentpath analyze examples/demo/vulnerable-agent.json
```

You should get several findings, including a critical one where a support ticket
can reach `run_command`.

## Watch a path get walked

```
agentpath confirm examples/demo/vulnerable-agent.json --agent scripted -o /tmp/demo-conf.json
agentpath analyze examples/demo/vulnerable-agent.json --confirmations /tmp/demo-conf.json
```

The scripted agent is not a language model. It is a small program that follows
whatever instruction it reads, so it walks every path. That is the point of it:
it proves the harness delivers the payload and the marker travels, so the
mechanism is visible with no key and no cost. It says nothing about whether a
real model would do the same.

## See what a real model does

If you have an API key, point it at a real model instead:

```
export ANTHROPIC_API_KEY=sk-ant-...
agentpath confirm examples/demo/vulnerable-agent.json --agent model -o /tmp/demo-conf.json
agentpath analyze examples/demo/vulnerable-agent.json --confirmations /tmp/demo-conf.json
```

The result you get there is the honest current picture for that model. When this
was last run against a current model on the support example, the model read the
planted ticket, recognised the injection, and refused it. Your run may differ,
which is the whole reason the tool tests rather than assumes.

## A note on the payloads

The planted instructions live in the payload library and are deliberately kept
small and clearly labelled. They are test fixtures for checking whether an agent
can be steered, not a toolkit for attacking anything. Only ever run this against
agents you own or are allowed to test.
