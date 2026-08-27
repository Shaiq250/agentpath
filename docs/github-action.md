# Running agentpath in GitHub Actions

The action analyses an agent manifest and writes SARIF, which GitHub renders in
the Security tab of the repository.

```yaml
name: agent security

on:
  push:
    branches: [main]
  pull_request:

permissions:
  contents: read
  security-events: write   # needed to upload SARIF

jobs:
  agentpath:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

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

`if: always()` on the upload step matters. Without it, a run that fails because
it found something never uploads the findings that caused the failure, which is
the wrong way round.

## Adopting it on a repository that already has findings

Nobody fixes forty findings on the day they install a scanner. Record what is
already there, then let CI fail only on what gets added:

```
agentpath analyze agent-manifest.json --write-baseline .agentpath-baseline.json
git add .agentpath-baseline.json
git commit -m "Baseline current agentpath findings"
```

Baselined findings still appear in the report and in code scanning, marked as
suppressed with a reason. A baseline is a snapshot of what was already there. It
is not a decision that any of it is acceptable, and it is worth working through
it rather than leaving it forever.

If you have reviewed a specific path and decided it is fine, that belongs in the
accept list in `.agentpath.yml` instead, where it carries a reason and a date.
The two are kept separate on purpose so a bulk snapshot never looks like a set of
considered decisions.

## Note on pull requests

When no manifest is given, the action runs `agentpath collect --no-launch`, which
reads configuration files without executing anything. That is deliberate. A
workflow triggered by a pull request can be looking at a branch a stranger wrote,
and starting the MCP servers it declares would mean running that stranger's
commands on your runner.
