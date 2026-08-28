# The manifest format

Everything agentpath does works on a manifest. `collect` produces one from MCP
configuration, `import` produces one from tool definitions or an OpenAPI
document, and you can write one by hand in a text editor.

The format is documented here so you do not have to ask anyone's permission to
analyse a source that is not supported yet. If your agent gets its tools from
somewhere neither importer covers, write thirty lines that produce this shape and
everything else works unchanged.

```json
{
  "schema": "agent-manifest/v2",
  "agent": {
    "name": "support-assistant",
    "harness": "claude-desktop",
    "source_path": "~/.config/Claude/claude_desktop_config.json"
  },
  "collection": {
    "mode": "launch",
    "complete": true,
    "unenumerated": []
  },
  "servers": [
    {
      "name": "zendesk",
      "transport": "stdio",
      "command": "npx zendesk-mcp@1.4.0",
      "trust": "third-party",
      "status": {"state": "enumerated"},
      "seen_before": true,
      "drift": [],
      "literal_secrets": [],
      "tools": [
        {
          "name": "read_ticket",
          "description": "Read the full text and comments of a support ticket.",
          "input_schema": {"ticket_id": "string"},
          "annotations": {"readOnlyHint": true, "openWorldHint": true}
        }
      ]
    }
  ]
}
```

## The fields that carry meaning

`trust` places a server in a domain. Anything is allowed, and `third-party`,
`internal` and `privileged` are ordered from least to most trusted, which is what
lets the tool say a path reaches somewhere more trusted than it started. Leave it
out and it is `unknown`, which sits in the middle.

`status.state` is `enumerated`, `skipped` or `failed`. This is the important one.
A server with no tools looks exactly like a harmless server, so anything other
than `enumerated` makes the scan incomplete and the report refuses to call it
clean. If you are writing a manifest by hand and you listed all the tools, the
default of `enumerated` is correct.

`annotations` follows the MCP tool annotation names. `readOnlyHint: false` says
the tool changes something, `destructiveHint: true` says it changes something
irreversibly, and `openWorldHint: true` says it reaches outside. They are treated
as the author's declaration, which raises confidence when they indicate danger,
and are never trusted on their own to clear a tool as safe.

`prompts` and `resources` are the other two things a server exposes. Both carry
descriptions that reach the model, so both are checked for poisoning alongside
tools. They do not take part in path analysis, which is about what an agent can
be made to do rather than what it reads.

`drift`, `seen_before` and `literal_secrets` are written by `collect` and can be
omitted. They exist so a later scan can say what changed since an earlier one.

## v1 and v2

An `agent-manifest/v1` document is still accepted. It has no `status` or
`collection` block, and a manifest without a status is treated as complete,
because a hand written file lists what it lists. v2 exists so a collection that
partly failed can say so.

## Writing an importer

There is no plugin system and there does not need to be. An importer is a
function that reads something and returns this structure, and the two that ship
live in `src/agentpath/importers.py` in about a hundred lines each. Copy one.

If you write one worth sharing, the honest thing to preserve is the status field.
An importer that cannot see every tool should say so rather than quietly produce
a short list.
