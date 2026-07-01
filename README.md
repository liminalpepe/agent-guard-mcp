# agent-guard-mcp

**Verify-before-act safety tools for AI coding agents.** Call these *before* installing a dependency, merging a CI change, or installing a third-party skill/plugin — so an agent refuses hallucinated packages, typosquats, poisoned manifests, and compromised CI actions.

Exposes four MCP tools (also available as a plain HTTP service):

| Tool | Use before… | Returns |
|------|-------------|---------|
| `check_package` | adding a single npm/PyPI dependency | OK / SUSPICIOUS / DANGER + typosquat/slop flags |
| `verify_lockfile` | running `npm/pip/yarn install` | scans every direct + transitive dep in a lockfile |
| `score_manifest` | installing a Cursor/Claude skill or MCP/Smithery plugin | poison-signature + scope-overreach + drift score 0–100 |
| `check_workflow` | merging a PR that touches CI | flags mutable action pins, compromised actions, curl\|bash, pwn-requests, secret exposure |

## Why

AI agents routinely hallucinate package names (slopsquatting), trust LLM-generated lockfiles, install unvetted skill packs, and pin CI actions to mutable tags. Each is a live supply-chain vector. This server gives an agent a cheap "is this safe?" call before it acts.

## Install (MCP client)

```json
{
  "mcpServers": {
    "agent-guard": { "command": "npx", "args": ["-y", "@liminallablibs/agent-guard-mcp"] }
  }
}
```

Or run directly:

```bash
npm install
node src/mcp-server.mjs        # stdio MCP server
npm run http                   # optional HTTP mirror on :8402
```

## HTTP endpoints (mirror of the MCP tools)

- `GET  /check?name=<pkg>&ecosystem=<npm|pypi>`
- `POST /check-lockfile   {lockfile_content, format}`   — format ∈ package-lock.json | yarn.lock | pnpm-lock.yaml | poetry.lock | requirements.txt
- `POST /score-manifest   {manifest_type, manifest_content}`
- `POST /check-workflow   {workflow_content}`

## License

MIT.
