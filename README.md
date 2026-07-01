# agent-guard-mcp

[![npm](https://img.shields.io/npm/v/@liminallablibs/agent-guard-mcp)](https://www.npmjs.com/package/@liminallablibs/agent-guard-mcp)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

> **One line:** Verify-before-act safety for AI agents — check packages, lockfiles, skill manifests, and CI workflows *before* install or merge. **Zero API keys. Zero config.**

**Scores Cursor/Claude skill manifests + GitHub Actions workflows** — not just npm dependencies.

| When you… | Call |
|-----------|------|
| `npm install foo` / agent suggests a new dep | `check_package` |
| Review an LLM-generated lockfile | `verify_lockfile` |
| Install a Cursor skill or MCP plugin | `score_manifest` |
| Merge a PR touching `.github/workflows/*` | `check_workflow` |

Call these *before* installing a dependency, merging a CI change, or installing a third-party skill/plugin — so an agent refuses hallucinated packages, typosquats, poisoned manifests, and compromised CI actions.

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
    "agent-guard": { "command": "npx", "args": ["-y", "@liminallablibs/agent-guard-mcp@0.2.1"] }
  }
}
```

## Agent rule (paste into Cursor Rules / CLAUDE.md)

> Before installing any npm/PyPI package, running install from a lockfile, installing a third-party skill/MCP plugin, or merging CI workflow changes, call the agent-guard MCP tools (`check_package`, `verify_lockfile`, `score_manifest`, `check_workflow`). If verdict is SUSPICIOUS, REVIEW, or BLOCK/DANGER, stop and show findings to the user — do not proceed.

## Quick demo

```bash
npx -y @liminallablibs/agent-guard-mcp@0.2.1   # MCP clients spawn this via npx
# HTTP mirror:
npm run http && curl "http://localhost:8402/check?name=reactt&ecosystem=npm"
# → DANGER — typosquat of "react"
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
