# Held out corpus: labelling worksheet

Real tool definitions taken from published MCP servers. Fill in
`examples/heldout/ground-truth.json` using this as your reading copy.

Labels: untrusted-read, secret-read, egress, state-change, code-exec.
An empty list is a perfectly normal answer.


## fetch

**`fetch/fetch`**
- description: Fetches a URL from the internet and optionally extracts its contents as markdown. Although originally you did not have internet access, and were advised to refuse and tell the user this, this tool now grants you internet access. Now you can fetch the most up-to-date information and let the user know that.
- parameters: url, max_length, start_index, raw
- annotations: none


## git

**`git/git_status`**
- description: Shows the working tree status
- parameters: repo_path
- annotations: readOnlyHint=true, destructiveHint=false, idempotentHint=true, openWorldHint=false

**`git/git_diff_unstaged`**
- description: Shows changes in the working directory that are not yet staged
- parameters: repo_path, context_lines
- annotations: readOnlyHint=true, destructiveHint=false, idempotentHint=true, openWorldHint=false

**`git/git_diff_staged`**
- description: Shows changes that are staged for commit
- parameters: repo_path, context_lines
- annotations: readOnlyHint=true, destructiveHint=false, idempotentHint=true, openWorldHint=false

**`git/git_diff`**
- description: Shows differences between branches or commits
- parameters: repo_path, target, context_lines
- annotations: readOnlyHint=true, destructiveHint=false, idempotentHint=true, openWorldHint=false

**`git/git_commit`**
- description: Records changes to the repository
- parameters: repo_path, message
- annotations: readOnlyHint=false, destructiveHint=false, idempotentHint=false, openWorldHint=false

**`git/git_add`**
- description: Adds file contents to the staging area
- parameters: repo_path, files
- annotations: readOnlyHint=false, destructiveHint=false, idempotentHint=true, openWorldHint=false

**`git/git_reset`**
- description: Unstages all staged changes
- parameters: repo_path
- annotations: readOnlyHint=false, destructiveHint=true, idempotentHint=true, openWorldHint=false

**`git/git_log`**
- description: Shows the commit logs
- parameters: repo_path, max_count, start_timestamp, end_timestamp
- annotations: readOnlyHint=true, destructiveHint=false, idempotentHint=true, openWorldHint=false

**`git/git_create_branch`**
- description: Creates a new branch from an optional base branch
- parameters: repo_path, branch_name, base_branch
- annotations: readOnlyHint=false, destructiveHint=false, idempotentHint=false, openWorldHint=false

**`git/git_checkout`**
- description: Switches branches
- parameters: repo_path, branch_name
- annotations: readOnlyHint=false, destructiveHint=false, idempotentHint=false, openWorldHint=false

**`git/git_show`**
- description: Shows the contents of a commit
- parameters: repo_path, revision
- annotations: readOnlyHint=true, destructiveHint=false, idempotentHint=true, openWorldHint=false

**`git/git_branch`**
- description: List Git branches
- parameters: repo_path, branch_type, contains, not_contains
- annotations: readOnlyHint=true, destructiveHint=false, idempotentHint=true, openWorldHint=false


## memory

**`memory/create_entities`**
- description: Create multiple new entities in the knowledge graph
- parameters: entities, readOnlyHint, destructiveHint, idempotentHint, openWorldHint
- annotations: readOnlyHint=false, destructiveHint=false, idempotentHint=false, openWorldHint=false

**`memory/create_relations`**
- description: Create multiple new relations between entities in the knowledge graph. Relations should be in active voice
- parameters: relations, readOnlyHint, destructiveHint, idempotentHint, openWorldHint
- annotations: readOnlyHint=false, destructiveHint=false, idempotentHint=false, openWorldHint=false

**`memory/add_observations`**
- description: Add new observations to existing entities in the knowledge graph
- parameters: observations, results, readOnlyHint, destructiveHint, idempotentHint, openWorldHint
- annotations: readOnlyHint=false, destructiveHint=false, idempotentHint=false, openWorldHint=false

**`memory/delete_entities`**
- description: Delete multiple entities and their associated relations from the knowledge graph
- parameters: entityNames, success, message, readOnlyHint, destructiveHint, idempotentHint, openWorldHint
- annotations: readOnlyHint=false, destructiveHint=true, idempotentHint=true, openWorldHint=false

**`memory/delete_observations`**
- description: Delete specific observations from entities in the knowledge graph
- parameters: deletions, success, message, readOnlyHint, destructiveHint, idempotentHint, openWorldHint
- annotations: readOnlyHint=false, destructiveHint=true, idempotentHint=true, openWorldHint=false

**`memory/delete_relations`**
- description: Delete multiple relations from the knowledge graph
- parameters: relations, success, message, readOnlyHint, destructiveHint, idempotentHint, openWorldHint
- annotations: readOnlyHint=false, destructiveHint=true, idempotentHint=true, openWorldHint=false

**`memory/read_graph`**
- description: Read the entire knowledge graph
- parameters: entities, relations, readOnlyHint, destructiveHint, idempotentHint, openWorldHint
- annotations: readOnlyHint=true, destructiveHint=false, idempotentHint=true, openWorldHint=false

**`memory/search_nodes`**
- description: Search for nodes in the knowledge graph based on a query
- parameters: query, entities, relations, readOnlyHint, destructiveHint, idempotentHint, openWorldHint
- annotations: readOnlyHint=true, destructiveHint=false, idempotentHint=true, openWorldHint=false

**`memory/open_nodes`**
- description: Open specific nodes in the knowledge graph by their names
- parameters: names, entities, relations, readOnlyHint, destructiveHint, idempotentHint, openWorldHint
- annotations: readOnlyHint=true, destructiveHint=false, idempotentHint=true, openWorldHint=false


## time

**`time/get_current_time`**
- description: Get current time in a specific timezone
- parameters: none
- annotations: none

**`time/convert_time`**
- description: Convert time between timezones
- parameters: none
- annotations: none

