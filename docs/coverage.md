# Which attack classes agentpath covers

The MCP attack classes below are the ones named consistently across the public
sources: the OWASP MCP Security Cheat Sheet, the Cloud Security Alliance research
notes on tool poisoning, Microsoft's 2026 state of MCP security review, Simon
Willison's writing on the lethal trifecta, Invariant Labs on toxic agent flows,
and the academic threat taxonomies.

This table is the honest version, which means it says what is not covered as
plainly as what is. Almost no scanner publishes the second column, and that is
the part worth reading.

| Attack class | agentpath | How, or why not |
| --- | --- | --- |
| Indirect prompt injection reaching a dangerous tool | Detected, and confirmable | Source to sink path analysis, plus `confirm` to test whether a model actually walks it |
| Lethal trifecta: untrusted input, private data, egress | Detected | The `exfiltration_chain` rule, reported as one finding rather than three |
| Tool poisoning by description | Detected | Instructions aimed at the model inside a description: concealment, instruction override, forced chaining |
| Concealed payloads in descriptions | Detected | Unicode tag blocks, zero width and bidi characters. Tag block content is decoded and shown |
| Rug pull, post approval mutation | Detected | Every tool definition is fingerprinted at collection, and a later scan reports what changed |
| Tool shadowing | Detected | Two servers claiming one tool name, with severity driven by the trust gap between them |
| Confusable tool names | Detected | Names that differ only by case, punctuation or a version suffix, across servers |
| Supply chain: unpinned server package | Detected | A server started with `npx`, `uvx` or similar without a pinned version |
| Credential written into an agent config | Detected | Variable names only. The value is never read into the manifest or the report |
| Transport exposure | Partly | Plain http to a remote server is reported. Certificate and identity checks are not attempted |
| Excessive scopes | Partly | Broad capability inside one agent shows up as paths. The scopes on a token are not visible to a scanner that only sees tool definitions |
| Confused deputy, OAuth weaknesses | Not detected | Lives in how a server authenticates and whose identity it acts under. Nothing in a tool list reveals it |
| Typosquatted or impersonating packages | Not detected | Needs registry data and package reputation, which an offline tool does not have |
| Server side vulnerabilities, for example command injection in a server | Not detected | This analyses what a server declares, not how it is implemented. Use ordinary application security tooling for the server itself |
| Runtime enforcement | Out of scope | agentpath analyses and tests. Blocking a call as it happens is what a gateway does, and this is not one |

## On the not detected rows

They are not a roadmap. Confused deputy and typosquatting need information a tool
that reads a manifest does not have, and pretending otherwise would produce
findings that look authoritative and mean nothing. If that changes, for example
by taking a registry feed as optional input, the row changes with it.

## Detection quality

Coverage is only half the question and the easier half. A rule that fires on
everything covers a class and helps nobody. The rules above are checked against
123 tool definitions taken from nine real servers, and a test fails if any of
them produces a single finding on that set. The state-change label is separately
measured against server author annotations at 97 percent on tools it was never
tuned against.

Recall is measured separately, against poisoning samples published by other
people: 80 percent caught with no false positives, recorded before the rules were
adjusted. See the README for what all of these numbers do and do not mean.
