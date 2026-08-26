"""Build the tool graph and enumerate candidate source to sink pairs.

An honest note about this graph, worth keeping in mind while reading the code.
Inside one agent, everything the agent reads lands in the same context window,
so any source can reach any sink. The base graph is therefore complete, and
simply printing every pair would be multiplication rather than analysis.

The graph still earns its place for two reasons. It gives the later milestones
somewhere to live: several agents on one machine, trust domain nodes, tool
shadowing and multi hop chains are all graph level questions. And it keeps the
pipeline shape identical to iam-escalate, where the graph does carry the real
work.

What makes the output meaningful today is what happens after this module:
severity ranking, and, from M3, confirmation.
"""

from __future__ import annotations

from typing import Iterator

import networkx as nx

from .labels import SINK_LABELS, SOURCE_LABELS
from .model import Agent, Tool

AGENT_NODE = "*agent*"


def build_graph(agent: Agent) -> nx.DiGraph:
    graph = nx.DiGraph()
    graph.add_node(AGENT_NODE, kind="agent", name=agent.name)

    for tool in agent.tools():
        graph.add_node(
            tool.qualified,
            kind="tool",
            server=tool.server,
            labels=sorted(tool.label_set()),
            trust=agent.trust_of(tool),
        )
        if any(tool.has(label) for label in SOURCE_LABELS):
            graph.add_edge(tool.qualified, AGENT_NODE, why="untrusted content enters context")
        if any(tool.has(label) for label in SINK_LABELS):
            graph.add_edge(AGENT_NODE, tool.qualified, why="agent can call this tool")

    return graph


def candidate_pairs(agent: Agent, source_label: str, sink_label: str) -> Iterator[tuple[Tool, Tool]]:
    """Yield every (source, sink) pair carrying the requested labels.

    A tool never pairs with itself: a single tool that both reads and sends is a
    different finding, and belongs to a later milestone.
    """
    sources = [tool for tool in agent.tools() if tool.has(source_label)]
    sinks = [tool for tool in agent.tools() if tool.has(sink_label)]
    for source in sources:
        for sink in sinks:
            if source.qualified == sink.qualified:
                continue
            yield source, sink
