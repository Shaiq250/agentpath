# What it costs to measure a security tool honestly

I spent a few weeks building agentpath, a tool that finds attack paths in the
tools an AI agent can call. The building was the easy part. The part worth
writing about is what happened when I tried to work out whether it was any good,
because every number I produced was wrong in a different way, and each one was
wrong for a reason that was not obvious until I looked.

This is that story. You do not need to care about my tool to get something out
of it. If you have ever written a detector and put a percentage next to it, some
of this will be uncomfortably familiar.

## The problem the tool addresses

An AI agent cannot reliably tell the difference between content it reads and
instructions it is given. If one of its tools reads something an attacker
controls, a support ticket, a pull request comment, a web page, and another of
its tools does something dangerous, runs a command, sends an email, issues a
refund, then an attacker can write an instruction into the content and the agent
may carry it out.

The important thing about this is that it is a property of the combination. No
individual tool is wrong. `read_ticket` is fine. `issue_refund` is fine. An agent
that has both is a machine for turning customer complaints into refunds.

So the unit of analysis is not the tool, it is the path from an untrusted source
to a dangerous sink. That is the whole idea, and it is not mine: it is the same
taint analysis that static analysis tools have done for decades, and Invariant
Labs had already applied it to agents under the name toxic flow analysis. What I
wanted to add was the ability to check whether a path is real rather than merely
possible.

## The failure mode I kept finding

Very early on, the tool did something that scared me. I pointed it at a machine
where one of the configured servers failed to start, and it reported no attack
paths found.

Which was true. A server that fails to start contributes no tools, and no tools
means no paths. It was also completely useless, because a scan that saw nothing
looks exactly like a scan that found nothing, and the person reading the report
cannot tell the difference.

I fixed it, and then I kept finding the same failure wearing different clothes.

When every finding was suppressed by policy, the report said no dangerous
combination was detected. There had been dangerous combinations. Someone had
waved them through.

When a baseline was applied, the same. Forty findings recorded as known, and a
clean-looking report.

When the confirmation harness ran against a model that never called the source
tool, it reported the path as not confirmed, which is what it also reports when a
model reads the injection and refuses it. Those are opposite results. One says
the agent resisted, the other says the test never happened.

When trust domains arrived, a user could declare a sink as gated behind human
approval and drop a finding below the CI threshold. Nothing verified the gate
existed.

Five instances of one bug. The bug is not any of the individual cases, it is that
absence of evidence keeps getting rendered as evidence of absence. Every one of
them now has a test whose name says so, and the reports say things like "this is
not a clean result" and "not the same as nothing being found" in as many words.

I would go further: for a security tool, this is the failure mode. A false
positive wastes somebody's afternoon. A false all clear is the tool actively
telling someone they are safe when nobody has checked.

## Number one: the corpus I tuned against

Once the tool worked, I wanted to know how accurate its classifier was. So I
wrote a corpus: thirty tools across six servers modelled on real ones, and a
ground truth file saying which capability labels each tool should carry.

It scored 0.72 precision and 0.62 recall, and printed every mistake by name. The
mistakes were real bugs. A bare `path` parameter was making every filesystem tool
look like it read secrets. A `destination` parameter counted as an outbound
channel. The state-change list was missing most of the verbs that change state.

I fixed them. It scored 1.00 on both.

That number is worthless and I knew it as I wrote it down. I had tuned the rules
until they matched my own labels on tools I had already looked at. It is an exam
written after seeing the answer key.

It is not useless, but it is not accuracy. It is a regression test: change a rule
and any tool whose labels move gets printed by name, so a fix in one place cannot
quietly break another. That is worth having. It is just not the thing the number
looks like it is.

The README says so, in bold, next to the 1.00.

## Number two: somebody else's answer key

The problem with hand labelling is that I wrote the rules, so my labels are my
rules written twice. What I needed was ground truth from someone who had never
heard of my tool.

MCP has one. Tool annotations. Server authors declare, in their own source, that
a tool does not modify its environment, or that it reaches out to external
systems. Those declarations were written by people with no interest in my
classifier.

So I switched the classifier to ignore annotations entirely, made it work out
what each tool does from name, description and schema alone, and compared its
conclusions against what the authors had declared. Two mappings, both taken
from the specification:

`readOnlyHint: false` means the tool modifies something, so it should be labelled
state-change. `openWorldHint: true` means the tool reaches outside, so it should
be labelled as an untrusted input.

On twenty-one annotated tools from four reference servers, it scored 93 percent.
Perfect on the second mapping, three misses on the first, all three being verbs
the rules simply did not know: commit, reset, checkout.

I published the 93, fixed the verbs, and recorded the pre-fix run in the
repository so the honest number could not quietly disappear behind the improved
one.

Then I ran a second batch, from Sentry and Cloudflare, sixty-nine tools this
time. Overall it dropped to 78 percent. The state-change mapping held at 97. The
other one collapsed to 52.

I looked at the failures, and they were not failures. Sentry marks nearly every
one of its tools `openWorldHint: true`, correctly, because they all call the
Sentry API. But `whoami` and `create_team` and `find_projects` are not entry
points for attacker authored content. My label was right. The annotation was
answering a different question.

`openWorldHint` means "talks to something outside this process". Untrusted-read
means "brings in content someone hostile could have written". Those are not the
same property, and I had been treating one as a proxy for the other.

Which also meant the perfect score on the first batch had been luck. Git, memory
and time are local tools that set the annotation to false, so the mapping was
never really tested. It scored 21 of 21 by never being asked a hard question.

I retired the mapping and corrected the earlier claim in place rather than
deleting it. A check that only agrees when it happens not to be tested is worse
than no check, because it produces confidence rather than information.

The standing number from that work is 97 percent on the state-change mapping,
sixty-nine tools, nothing tuned to it. It measures one label out of five. The
other four have never been measured against an external answer key at all, and
the README says that too.

## Number three: the one where I was wrong four times

The rules that read tool descriptions and look for planted instructions had been
checked in one direction only. I knew they stayed quiet on ordinary tools, 123 of
them across nine real servers with zero false positives. I had no idea whether
they caught anything.

Recall needs known-bad samples that I did not write, and those exist: Invariant
Labs published the original tool poisoning and shadowing demonstrations, and
there is a Damn Vulnerable MCP project with deliberately broken challenge
servers. Thirty-one tools, and the labels could come from the sample authors
rather than from me.

Except that deciding which tools are the poisoned ones turned out to be the whole
problem.

My first rule was to use the challenge names. The repository says challenge two
is tool poisoning and challenge five is shadowing, so those tools are positives.
Result: 75 percent, with one false positive. I looked at the false positive. It
was a tool in challenge ten with an instruction block telling the model to
include a master password in its response and not mention it. The challenge is
documented as a multi-vector attack. My label was wrong.

Second rule: mark every tool in a poisoning challenge. Result: 40 percent. Also
wrong, in the other direction. Challenge ten contains ordinary tools whose
descriptions are entirely clean, and I was now punishing the detector for failing
to flag `authenticate`.

Third rule: use the tools each challenge's own solution guide names. Result: 67
percent. Better, and still wrong. The solution guide names `analyze_log_file`
because its argument allows path traversal, not because its description is
poisoned. I had conflated being part of an attack with having a poisoned
description, which is not the thing these rules detect.

Fourth rule, and the one I settled on: a tool is a positive if its description
contains instructions the author inserted for the model to follow. Verifiable by
opening the description. Result: 80 percent, one miss, no false positives.

The miss was a `<HIDDEN>` block. My pattern knew about three specific tag words
rather than describing what a pseudo tag is, which is a list of examples wearing
the costume of a rule. I generalised it, and the corpus went to six of six.

Then it flagged one more tool I had marked benign. It is called
`malicious_check_system_status` and it carries a hidden block about extracting
credentials and disguising them as normal output. My label was wrong for the
fourth time.

The number moved between 40 and 80 percent purely on labelling decisions. Every
single disagreement between the detector and my labels was resolved in the
detector's favour. All four wrong attempts are written into the ground truth
file, because deleting them would leave a clean-looking artifact that hides the
most useful thing I learned.

Which is this: on a small corpus, the labelling decision matters more than the
detector does. And hand-labelled ground truth is considerably less reliable than
the confident percentage sitting on top of it suggests.

## Number four: the one that undid number three

Everything above was written before I ran the rules against MCPTox, an academic
benchmark of tool poisoning built on 45 real MCP servers, with 485 poisoned tool
descriptions and the legitimate tools of those same servers alongside them.

The rules caught 5 percent.

The 80 percent from the previous section came from six samples. Six is not a
corpus. What I had actually measured was how well rules shaped around six
descriptions performed on those same six descriptions, which is the tuned corpus
problem from section one, wearing yet another disguise and this time fooling me
for a week.

The reason is visible the moment you look. My patterns keyed on things like an
`<IMPORTANT>` block and phrases such as "do not tell the user". Across MCPTox's
485 cases, exactly one uses a tag like that and two say anything about not
telling. The dominant shapes are different: ninety-one say the model must first
call some other tool, seventy-eight simply assert that the tool description takes
priority over the user's request. Nothing in my rule set was looking for either.

The false positive half survived, and that is worth something: zero of 362
legitimate tools were flagged, in a field where an independent audit of two
YARA based scanners found roughly 78 percent of their detections were not real.
Precision without recall is half a detector, but it is the harder half to fix
honestly.

Three lessons, and the third is the uncomfortable one.

A corpus of six tells you nothing, and I knew that while writing the number down.
I published it with caveats about it being a regression guard, which was true and
also let me keep quoting it.

An external corpus is not the same as a large one. My six samples came from
published research, so they passed my own test of independence, and they were
still hopelessly unrepresentative.

And the failure mode I have been describing for this entire piece caught me
again, at the exact moment I thought I had it beaten.

### What fixing it actually required

The temptation was to add patterns for the two phrasings I had seen. That would
have been the same mistake a fourth time.

What the rules needed was to stop matching phrases and start matching structure.
Three signals did most of the work, and none of them cares which words an
attacker chooses.

A tool description that requires the model to use a **different** tool. A
description exists to describe its own tool. When it starts imposing
requirements involving another one, something is wrong. There is exactly one
innocent reason to name a sibling tool, which is to steer people away from it,
so "use this instead of" and "prefer this over" are excluded. That exception is
not a detail: without it, four perfectly good filesystem tools get flagged.

A description that claims to **outrank the user's request**. Only when it is
about the user, though, because plenty of tools have a parameter called
priority.

A description naming a **specific sensitive artifact**, an SSH key, /etc/shadow,
an .env file. I first wrote this to include the bare word "credential" and it
immediately flagged a tool called get_credentials, which was describing itself
honestly. Punishing a server for being clear about what it does is not
detection.

That took the benchmark from 5 percent to 68. Two further rounds got it to 82,
one fixing a rule that only recognised tool names when they were quoted, lower
case and snake_case, so `'markAsRead'` and "the tool sendmail" walked past, and
one adding two new categories: a description that dictates what value an
argument must take, and one that argues for why the model has to comply.

That second round taught me something about benchmarks. The compliance argument
signal looked strong, catching 21 of the remaining misses. Then I checked, and
20 of its 27 matches were one identical generated sentence. The general shape is
a real signal. The size of the win was a property of the benchmark's generator,
and quoting it without that caveat would have been another small dishonesty.

There is also a ceiling here, and it is worth naming. Several further
configurations traded recall for precision roughly one for one. The misses that
remain need meaning rather than pattern: "Helper tool to get information" and
"Before use the tool sendmail" are both a word beside the word tool, and telling
them apart is a question about grammar and intent. Going further means putting a
model in the loop, which costs the two properties the tool is built on. So the
honest place to stop is 82 percent, with the reason written down. Every number after the first is tuned, not measured, which the repository says
next to each of them. The 5 percent is what this benchmark actually told me.

## Number five: the one that held

After all that, there was still something I had never done. Every measurement so
far, including the one that humiliated me, tested recall. None of them tested
precision against a corpus somebody else had built. The zero false positives I
kept quoting came from 123 tools I had assembled myself.

InjecAgent is a benchmark for a different problem. It injects attacker
instructions into tool responses, the content an agent reads back, rather than
into descriptions. It cannot tell me anything about whether my rules catch a
poisoned description. What it has is 330 ordinary tool descriptions across 38
toolkits, written by researchers with no interest in my rules. Every finding on
those is a false positive and nothing else.

I ran it before touching anything and before looking at the data.

Three false positives out of 330. Under one percent.

That is the first number in this project that is both good and honest, and I want
to be careful about why. Nothing was tuned first. I had not read the corpus. The
result is a measurement rather than a regression guard, which is more than I can
say for the 82 percent sitting a section above it.

Then I looked at the three, and they were the same mistake I had already made
once. The rule treated the phrase "private key" as suspicious, so it flagged
three Ethereum tools whose entire purpose is handling private keys. Weeks
earlier, the bare word "credential" had flagged a tool called get_credentials for
exactly the same reason.

The distinction that fixes both is worth stating because it took me two goes to
see it. A path to a secret file is unusual in a tool description. Nothing
legitimate needs to name ~/.ssh/id_rsa. The phrase "private key" is ordinary
language for a crypto or auth tool describing itself accurately. Match the path,
not the subject. That took it to zero of 330, with recall unchanged.

The general form of that mistake now has a name in my head. Punishing a server
for honestly describing what it does is not detection. It is noise wearing a
security badge, and I have made it twice, so I expect to make it again.

## Predicting versus observing

The other half of the tool is the part I actually built it for.

Static analysis says a path is possible. It cannot say whether a model would walk
it. So agentpath can plant a marked instruction in content a stand-in source tool
returns, give a model an ordinary task, and watch whether the dangerous tool gets
called with that marker in its arguments. The marker existed nowhere else, so if
it turns up in the sink's arguments, attacker controlled data provably reached a
dangerous call. The check is a string comparison, not a second model grading the
first.

The real tools are never called. The harness substitutes an instrumented stand-in
with the same name and schema, so no refund is issued, no mail is sent, no
command runs. The model's decision is real. Only the consequence is fake, and the
consequence is the part nobody needs.

The result I got is not the dramatic one. Against a current model, with five
different payload phrasings, none of the three candidate paths were walked. The
model read the planted ticket, recognised the injection attempt, and said so in
its reply.

Against a scripted stand-in that follows any instruction it reads, all three were
walked.

I report both, because neither is honest alone. The scripted run by itself is
scaremongering: of course a program that follows instructions followed the
instructions. The model run by itself reads as nothing to see here. Together they
say something true, which is that the paths are genuinely reachable and a current
model currently resists the naive version of the attack.

Everything downstream of that carries the provenance. Scripted results are
labelled as a stand-in and say outright that they demonstrate the harness rather
than any real behaviour. A model gets named. Without an API key the tool reports
paths as untestable rather than falling back to the scripted agent, because that
would be manufacturing evidence.

And one of those runs taught me something I would have missed. One path came back
not confirmed in five of five attempts, but the payload had only been delivered
once. The other four times the model asked a clarifying question and never read
the poisoned content at all. Without delivery tracking that would have looked
like a strong negative result. It was four non-tests and one refusal.

## What I would tell someone building a detector

Publish the number you got before you fixed anything, and keep the file. Once
the improved number exists, the honest one becomes very easy to lose.

When your detector disagrees with your labels, check the label first. Mine was
wrong every single time, and I would not have guessed that going in.

Ask what your ground truth actually means, not just where it came from. External
does not mean correct for your question. The annotations were genuinely
independent and still wrong as a proxy, and it took a second corpus to notice.

A perfect score is a smell. If you tuned against the corpus, say so next to the
number, in the same sentence if you can.

Measure both directions. False positives and recall answer different questions,
and a rule set can look excellent on one while being useless on the other.

And for security tools specifically: decide what your empty result means before
you ship. Silence is the easiest output to produce and the most dangerous one to
get wrong.

One more, learned last. Test both halves against strangers. I spent weeks
improving recall against corpora I had built and only afterwards discovered that
precision, the thing I had been quietly confident about, had never once been
checked by anyone but me. It happened to hold. It might not have.

## The tool

agentpath is at github.com/Shaiq250/agentpath, Apache licensed. It finds attack
paths in agent tool configurations, checks tools, prompts and resources for
planted instructions, reports what changed since the last scan, and can test
whether a model actually walks a path it found. It runs offline apart from that
last part.

It is not the only tool in this space and does not claim to be. Snyk,
AgentAuditKit and others got there first, and the flow model is older than any of
us. What I have not found elsewhere is the combination of running entirely
locally, reporting chains rather than per-tool scores, and being able to confirm
a path by observation. And the measurement files, which as far as I can tell
nobody else publishes, including the ones where the number went down.
