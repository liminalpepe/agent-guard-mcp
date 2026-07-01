#!/usr/bin/env node
/**
 * Agent-native package/plugin safety — MCP server (stdio).
 *
 * Exposes THREE verify-before-act tools an AI agent should call before it acts:
 *   - check_package    : is this npm/PyPI package real + is it a slopsquat/typosquat?
 *   - verify_lockfile  : scan a whole lockfile (direct + transitive) before install
 *   - score_manifest   : score a skill/plugin/MCP manifest for poison/backdoor/scope-overreach
 *
 * stdout is reserved for the MCP protocol — all logging goes to stderr.
 * Run: node src/mcp-server.mjs
 */

import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { ListToolsRequestSchema, CallToolRequestSchema } from '@modelcontextprotocol/sdk/types.js';
import { checkPackage } from './check.mjs';
import { scanLockfile } from './lockfile.mjs';
import { scoreManifest } from './manifest.mjs';
import { scanWorkflow } from './workflow.mjs';

export const SERVER_NAME = 'agent-guard';
export const SERVER_VERSION = '0.2.0';

const LOCK_FORMATS = ['package-lock.json', 'yarn.lock', 'pnpm-lock.yaml', 'poetry.lock', 'requirements.txt'];
const MANIFEST_TYPES = ['cursor-skill', 'claude-skill', 'mcp-server', 'smithery-package'];

const TOOLS = [
  {
    name: 'check_package',
    description: 'Check whether a single package exists and assess slopsquat/typosquat risk BEFORE installing it. Returns OK/SUSPICIOUS/DANGER + risk + flags. Nonexistent names are likely hallucinated; names 1-2 chars from a popular package are likely typosquats.',
    inputSchema: { type: 'object', properties: {
      name: { type: 'string', description: 'Package name, e.g. "huggingface-cli".' },
      ecosystem: { type: 'string', enum: ['npm', 'pypi'], default: 'npm' },
    }, required: ['name'], additionalProperties: false },
  },
  {
    name: 'verify_lockfile',
    description: 'Scan an entire lockfile (direct + transitive deps) for hallucinated / typosquatted / suspicious packages BEFORE running install. Call this instead of trusting an LLM-generated lockfile.',
    inputSchema: { type: 'object', properties: {
      lockfile_content: { type: 'string', description: 'Raw lockfile text (not a path).' },
      format: { type: 'string', enum: LOCK_FORMATS },
      ecosystem: { type: 'string', enum: ['npm', 'pypi'], description: 'Optional; inferred from format.' },
    }, required: ['lockfile_content', 'format'], additionalProperties: false },
  },
  {
    name: 'score_manifest',
    description: 'Score a Cursor/Claude skill or MCP/Smithery plugin manifest for poison/backdoor signatures, credential scope over-reach, and drift BEFORE installing a third-party agent extension. Returns risk 0-100 + install recommendation (PROCEED/REVIEW/BLOCK).',
    inputSchema: { type: 'object', properties: {
      manifest_type: { type: 'string', enum: MANIFEST_TYPES },
      manifest_content: { type: 'string', description: 'Primary manifest text (SKILL.md, plugin.json, smithery.yaml, package.json).' },
      declared_purpose: { type: 'string', description: 'One-line stated purpose (for scope-overreach heuristics).' },
      baseline_manifest: { type: 'string', description: 'Optional previously-approved manifest for drift scoring.' },
    }, required: ['manifest_type', 'manifest_content'], additionalProperties: false },
  },
  {
    name: 'check_workflow',
    description: 'Validate a CI workflow (GitHub Actions / GitLab CI YAML) BEFORE merging a PR that touches it. Flags mutable action pins, known-compromised actions, untrusted owners, curl|bash fetch-exec, pull_request_target pwn-requests, and secret exposure. Returns risk 0-100 + merge recommendation (PROCEED/REVIEW/BLOCK).',
    inputSchema: { type: 'object', properties: {
      workflow_content: { type: 'string', description: 'Raw CI workflow YAML text.' },
      platform: { type: 'string', enum: ['github-actions', 'gitlab-ci'], default: 'github-actions' },
    }, required: ['workflow_content'], additionalProperties: false },
  },
];

const err = (text) => ({ isError: true, content: [{ type: 'text', text }] });
const ok = (text, structured) => ({ content: [{ type: 'text', text }], structuredContent: structured });

export function createServer() {
  const server = new Server({ name: SERVER_NAME, version: SERVER_VERSION }, { capabilities: { tools: {} } });
  server.setRequestHandler(ListToolsRequestSchema, async () => ({ tools: TOOLS }));

  server.setRequestHandler(CallToolRequestSchema, async (request) => {
    const { name: tool, arguments: a = {} } = request.params;
    try {
      if (tool === 'check_package') {
        if (typeof a.name !== 'string' || !a.name) return err('Missing required parameter: name.');
        const eco = a.ecosystem ?? 'npm';
        if (eco !== 'npm' && eco !== 'pypi') return err('ecosystem must be "npm" or "pypi".');
        const r = await checkPackage(a.name, eco);
        return ok(`${r.verdict} (risk ${r.risk ?? 'n/a'}/100) — ${r.name} [${r.ecosystem}] exists=${r.exists}` + (r.flags?.length ? `\n- ${r.flags.join('\n- ')}` : ''), r);
      }
      if (tool === 'verify_lockfile') {
        if (typeof a.lockfile_content !== 'string' || !LOCK_FORMATS.includes(a.format)) return err(`Require lockfile_content + format in ${LOCK_FORMATS.join('|')}.`);
        const r = await scanLockfile(a.lockfile_content, a.format, a.ecosystem);
        return ok(`${r.overall_verdict} — scanned ${r.scanned} deps: ${r.counts.danger} danger, ${r.counts.suspicious} suspicious` + (r.flagged.length ? `\nflagged: ${r.flagged.map(f => `${f.name}(${f.verdict})`).join(', ')}` : ''), r);
      }
      if (tool === 'score_manifest') {
        if (typeof a.manifest_content !== 'string' || !MANIFEST_TYPES.includes(a.manifest_type)) return err(`Require manifest_content + manifest_type in ${MANIFEST_TYPES.join('|')}.`);
        const r = scoreManifest(a);
        const { _findings, ...pub } = r;
        return ok(`${r.overall_verdict} — risk ${r.risk_score}/100, ${r.install_recommendation}. ${r.summary}`, pub);
      }
      if (tool === 'check_workflow') {
        if (typeof a.workflow_content !== 'string' || !a.workflow_content) return err('Require workflow_content (raw CI YAML).');
        const r = scanWorkflow(a.workflow_content, a.platform);
        const { _findings, ...pub } = r;
        return ok(`${r.overall_verdict} — risk ${r.risk_score}/100, ${r.merge_recommendation}. ${r.summary}`, pub);
      }
      return err(`Unknown tool: ${tool}`);
    } catch (e) {
      return err(`${tool} failed: ${e?.message ?? String(e)}`);
    }
  });

  return server;
}

async function main() {
  const server = createServer();
  await server.connect(new StdioServerTransport());
  console.error(`${SERVER_NAME} v${SERVER_VERSION} running via stdio (3 tools)`);
}

if (import.meta.url === `file://${process.argv[1]}`) {
  main().catch((error) => { console.error('Fatal error starting MCP server:', error); process.exit(1); });
}
