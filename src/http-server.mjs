#!/usr/bin/env node
/**
 * Slopsquat Guard — HTTP server (plain Node http, no framework).
 *
 * Endpoints:
 *   GET /                              -> 200 service descriptor (discoverability)
 *   GET /health                       -> 200 { ok: true }
 *   GET /check?name=&ecosystem=       -> 200 verdict JSON
 *   GET /stats                        -> 200 { total_calls, since }  (demand signal)
 *
 * MVP demand-test mode (FREE_MODE, default ON): /check is served FREE and every
 * call is logged to CALL_LOG. The whole point of the MVP is to measure organic,
 * uncontacted usage before charging. Set FREE_MODE=false to enable the x402
 * payment gate (402 challenge) once demand is proven + a wallet is wired.
 *
 * Env:
 *   PORT             port to listen on (default 8402)
 *   FREE_MODE        'true' (default) = free+logged; 'false' = x402-gated
 *   WALLET_ADDRESS   payTo advertised in the 402 challenge (only when FREE_MODE=false)
 *   CALL_LOG         path to JSONL call log (default /app/data/calls.jsonl)
 */

import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import { checkPackage } from './check.mjs';
import { parseLockfile, ecosystemFor } from './lockfile.mjs';
import { scoreManifest } from './manifest.mjs';
import { scanWorkflow } from './workflow.mjs';
import { gateDetail, paywallActive } from './x402.mjs';

const PORT = Number(process.env.PORT) || 8402;
const FREE_MODE = (process.env.FREE_MODE ?? 'true') !== 'false';
const WALLET_ADDRESS = process.env.WALLET_ADDRESS || '0x0000000000000000000000000000000000000000';
const CALL_LOG = process.env.CALL_LOG || '/app/data/calls.jsonl';

try { fs.mkdirSync(path.dirname(CALL_LOG), { recursive: true }); } catch {}
let TOTAL = 0;
try { TOTAL = fs.readFileSync(CALL_LOG, 'utf8').split('\n').filter(Boolean).length; } catch {}
const STARTED = new Date().toISOString();

function logCall(entry) {
  TOTAL++;
  try { fs.appendFileSync(CALL_LOG, JSON.stringify(entry) + '\n'); } catch {}
}

// --- H1 lockfile-guard helpers ---
const MAX_DEPS = 400;
function readBody(req, maxBytes = 600000) {
  return new Promise((resolve, reject) => {
    let data = ''; let size = 0;
    req.on('data', c => { size += c.length; if (size > maxBytes) { req.destroy(); reject(new Error('body too large')); } else data += c; });
    req.on('end', () => resolve(data));
    req.on('error', reject);
  });
}
async function mapLimit(items, limit, fn) {
  const out = new Array(items.length); let i = 0;
  const workers = Array.from({ length: Math.min(limit, items.length || 1) }, async () => {
    while (i < items.length) { const idx = i++; out[idx] = await fn(items[idx]); }
  });
  await Promise.all(workers); return out;
}
async function handleLockfile(req, res) {
  let payload;
  try { payload = JSON.parse((await readBody(req)) || '{}'); }
  catch (e) { return sendJson(res, e.message === 'body too large' ? 413 : 400, { error: e.message === 'body too large' ? 'body too large' : 'invalid JSON body' }); }
  const FORMATS = ['package-lock.json', 'yarn.lock', 'pnpm-lock.yaml', 'poetry.lock', 'requirements.txt'];
  const { lockfile_content, format, ecosystem } = payload;
  if (!lockfile_content || !FORMATS.includes(format)) return sendJson(res, 400, { error: `require lockfile_content + format in ${FORMATS.join('|')}` });
  const eco = ecosystemFor(format, ecosystem);
  let names = parseLockfile(String(lockfile_content), format);
  const total_deps = names.length;
  const truncated = names.length > MAX_DEPS;
  if (truncated) names = names.slice(0, MAX_DEPS);
  const results = await mapLimit(names, 6, n => checkPackage(n, eco).catch(e => ({ name: n, verdict: 'UNKNOWN', risk: null, error: String(e?.message || e) })));
  const flagged = results.filter(r => r.verdict === 'DANGER' || r.verdict === 'SUSPICIOUS');
  const counts = {
    total_scanned: results.length,
    danger: results.filter(r => r.verdict === 'DANGER').length,
    suspicious: results.filter(r => r.verdict === 'SUSPICIOUS').length,
    ok: results.filter(r => r.verdict === 'OK').length,
  };
  const overall = counts.danger ? 'DANGER' : counts.suspicious ? 'SUSPICIOUS' : 'OK';
  logCall({ ts: new Date().toISOString(), kind: 'lockfile', format, ecosystem: eco, total_deps, overall, danger: counts.danger, suspicious: counts.suspicious,
    ip: (req.headers['x-forwarded-for'] || req.socket.remoteAddress || '').toString().split(',')[0].trim(), ua: (req.headers['user-agent'] || '').slice(0, 200) });
  return sendJson(res, 200, { overall_verdict: overall, ecosystem: eco, format, total_deps, scanned: results.length, truncated, counts,
    flagged: flagged.map(f => ({ name: f.name, verdict: f.verdict, risk: f.risk, flags: f.flags })) });
}

// --- H2 skillpack-guard: score a skill/plugin manifest ---
async function handleManifest(req, res) {
  let payload;
  try { payload = JSON.parse((await readBody(req)) || '{}'); }
  catch (e) { return sendJson(res, e.message === 'body too large' ? 413 : 400, { error: e.message === 'body too large' ? 'body too large' : 'invalid JSON body' }); }
  const TYPES = ['cursor-skill', 'claude-skill', 'mcp-server', 'smithery-package'];
  const { manifest_type, manifest_content } = payload;
  if (!manifest_content || !TYPES.includes(manifest_type)) return sendJson(res, 400, { error: `require manifest_content + manifest_type in ${TYPES.join('|')}` });
  const r = scoreManifest(payload);
  logCall({ ts: new Date().toISOString(), kind: 'manifest', manifest_type, risk: r.risk_score, verdict: r.overall_verdict, flags: r.flag_count,
    ip: (req.headers['x-forwarded-for'] || req.socket.remoteAddress || '').toString().split(',')[0].trim(), ua: (req.headers['user-agent'] || '').slice(0, 200) });
  const { _findings, ...pub } = r;
  const wantsDetail = /[?&]detail=full/.test(req.url || '');
  const gate = await gateDetail(req, '/score-manifest?detail=full', wantsDetail);
  if (gate.challenge) return sendJson(res, 402, { error: 'payment required for full report', ...gate.challenge });
  const body = { ...pub, paywall: paywallActive(), scanned_at: new Date().toISOString() };
  if (gate.allow) { body.findings = _findings; if (gate.paid) body.payment_receipt = gate.receipt; }
  return sendJson(res, 200, body);
}

// --- CI workflow action-integrity validator ---
async function handleWorkflow(req, res) {
  let payload;
  try { payload = JSON.parse((await readBody(req)) || '{}'); }
  catch (e) { return sendJson(res, e.message === 'body too large' ? 413 : 400, { error: e.message === 'body too large' ? 'body too large' : 'invalid JSON body' }); }
  const { workflow_content, platform = 'github-actions' } = payload;
  if (!workflow_content) return sendJson(res, 400, { error: 'require workflow_content (raw CI YAML)' });
  const r = scanWorkflow(workflow_content, platform);
  logCall({ ts: new Date().toISOString(), kind: 'workflow', platform, risk: r.risk_score, verdict: r.overall_verdict, flags: r.flag_count,
    ip: (req.headers['x-forwarded-for'] || req.socket.remoteAddress || '').toString().split(',')[0].trim(), ua: (req.headers['user-agent'] || '').slice(0, 200) });
  const { _findings, ...pub } = r;
  const wantsDetail = /[?&]detail=full/.test(req.url || '');
  const gate = await gateDetail(req, '/check-workflow?detail=full', wantsDetail);
  if (gate.challenge) return sendJson(res, 402, { error: 'payment required for full report', ...gate.challenge });
  const body = { ...pub, paywall: paywallActive(), scanned_at: new Date().toISOString() };
  if (gate.allow) { body.findings = _findings; if (gate.paid) body.payment_receipt = gate.receipt; }
  return sendJson(res, 200, body);
}

const PAYMENT_REQUIREMENT = {
  amount: '$0.01', asset: 'USDC', network: 'base', payTo: WALLET_ADDRESS,
  resource: '/check', description: 'Slopsquat Guard package-safety check (one query).',
};

function sendJson(res, status, body) {
  const payload = JSON.stringify(body, null, 2);
  res.writeHead(status, { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(payload) });
  res.end(payload);
}

const server = http.createServer(async (req, res) => {
  let url;
  try { url = new URL(req.url, `http://${req.headers.host || 'localhost'}`); }
  catch { return sendJson(res, 400, { error: 'bad request URL' }); }

  // --- H1 Lockfile scan (POST /check-lockfile or /v1/verify-lockfile) ---
  if (req.method === 'POST' && (url.pathname === '/check-lockfile' || url.pathname === '/v1/verify-lockfile')) {
    return handleLockfile(req, res);
  }
  // --- H2 Manifest scan (POST /score-manifest or /v1/score-manifest) ---
  if (req.method === 'POST' && (url.pathname === '/score-manifest' || url.pathname === '/v1/score-manifest')) {
    return handleManifest(req, res);
  }
  // --- CI workflow scan (POST /check-workflow or /v1/check-workflow) ---
  if (req.method === 'POST' && (url.pathname === '/check-workflow' || url.pathname === '/v1/check-workflow')) {
    return handleWorkflow(req, res);
  }

  if (req.method !== 'GET') return sendJson(res, 405, { error: 'method not allowed' });

  if (url.pathname === '/' ) {
    return sendJson(res, 200, {
      service: 'agent-guard',
      description: 'Verify-before-act safety suite for AI coding agents: check packages, lockfiles, and skill/plugin manifests before installing.',
      tools: {
        check_package: 'GET /check?name=<pkg>&ecosystem=<npm|pypi> — does a package exist + slopsquat/typosquat risk',
        verify_lockfile: 'POST /check-lockfile {lockfile_content, format} — scan a whole lockfile (direct+transitive)',
        score_manifest: 'POST /score-manifest {manifest_type, manifest_content} — poison/backdoor/scope-overreach score 0-100',
      },
      mcp: 'stdio MCP server exposes the same three tools (check_package, verify_lockfile, score_manifest)',
      free: FREE_MODE, version: '0.2.0',
    });
  }
  if (url.pathname === '/health') return sendJson(res, 200, { ok: true, service: 'slopsquat-guard', version: '0.1.0' });
  if (url.pathname === '/stats') return sendJson(res, 200, { total_calls: TOTAL, since: STARTED, free: FREE_MODE });

  if (url.pathname === '/check') {
    if (!FREE_MODE) {
      const paymentHeader = req.headers['x-payment'];
      if (!paymentHeader) return sendJson(res, 402, { error: 'payment required', x402Version: 1, accepts: [PAYMENT_REQUIREMENT] });
    }
    const name = url.searchParams.get('name');
    const ecosystem = url.searchParams.get('ecosystem') || 'npm';
    if (!name) return sendJson(res, 400, { error: 'missing query param: name' });
    if (ecosystem !== 'npm' && ecosystem !== 'pypi') return sendJson(res, 400, { error: 'ecosystem must be "npm" or "pypi"' });

    try {
      const result = await checkPackage(name, ecosystem);
      logCall({
        ts: new Date().toISOString(), name, ecosystem,
        verdict: result.verdict, risk: result.risk,
        ip: (req.headers['x-forwarded-for'] || req.socket.remoteAddress || '').toString().split(',')[0].trim(),
        ua: (req.headers['user-agent'] || '').slice(0, 200),
      });
      return sendJson(res, 200, result);
    } catch (error) {
      return sendJson(res, 500, { error: error?.message ?? String(error) });
    }
  }

  return sendJson(res, 404, { error: 'not found' });
});

server.listen(PORT, () => {
  console.error(`slopsquat-guard on :${PORT} · FREE_MODE=${FREE_MODE} · log=${CALL_LOG}`);
});
