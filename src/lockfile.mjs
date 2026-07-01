// Lockfile Guard (H1) — parse a lockfile to its flat dependency list (direct + transitive),
// so each package can be fanned out to slopsquat's checkPackage(). Best-effort parsers per format.
// Formats: package-lock.json · yarn.lock · pnpm-lock.yaml · poetry.lock · requirements.txt

import { checkPackage } from './check.mjs';

const NPM_FORMATS = new Set(['package-lock.json', 'yarn.lock', 'pnpm-lock.yaml']);

// Shared aggregation used by both the HTTP route and the MCP tool.
export async function scanLockfile(content, format, ecosystem, maxDeps = 400) {
  const eco = ecosystemFor(format, ecosystem);
  let names = parseLockfile(String(content), format);
  const total_deps = names.length;
  const truncated = names.length > maxDeps;
  if (truncated) names = names.slice(0, maxDeps);
  const results = []; const q = [...names];
  const worker = async () => { while (q.length) { const n = q.shift(); try { results.push(await checkPackage(n, eco)); } catch { results.push({ name: n, verdict: 'UNKNOWN', risk: null }); } } };
  await Promise.all(Array.from({ length: Math.min(6, names.length || 1) }, worker));
  const danger = results.filter(r => r.verdict === 'DANGER');
  const suspicious = results.filter(r => r.verdict === 'SUSPICIOUS');
  const overall = danger.length ? 'DANGER' : suspicious.length ? 'SUSPICIOUS' : 'OK';
  return { overall_verdict: overall, ecosystem: eco, format, total_deps, scanned: results.length, truncated,
    counts: { total_scanned: results.length, danger: danger.length, suspicious: suspicious.length, ok: results.filter(r => r.verdict === 'OK').length },
    flagged: [...danger, ...suspicious].map(f => ({ name: f.name, verdict: f.verdict, risk: f.risk, flags: f.flags })) };
}

export function ecosystemFor(format, override) {
  if (override === 'npm' || override === 'pypi') return override;
  return NPM_FORMATS.has(format) ? 'npm' : 'pypi';
}

// strip an npm scope's version noise; keep the package name (incl. @scope/name)
function cleanNpmName(raw) {
  let s = String(raw).trim().replace(/^"|"$/g, '');
  // "@scope/name@^1.2.3" or "name@1.2.3" -> drop the version after the LAST @ (but keep leading @scope)
  const at = s.lastIndexOf('@');
  if (at > 0) s = s.slice(0, at);
  return s.trim();
}

function parsePackageLockJson(text) {
  const names = new Set();
  let j;
  try { j = JSON.parse(text); } catch { return []; }
  // v2/v3: "packages": { "node_modules/foo": {...}, "node_modules/@scope/bar": {...} }
  if (j.packages && typeof j.packages === 'object') {
    for (const key of Object.keys(j.packages)) {
      if (!key) continue; // root ""
      const idx = key.lastIndexOf('node_modules/');
      if (idx >= 0) { const n = key.slice(idx + 'node_modules/'.length); if (n) names.add(n); }
    }
  }
  // v1: "dependencies": { name: { requires, dependencies } } (recursive)
  const walk = (deps) => {
    if (!deps || typeof deps !== 'object') return;
    for (const [name, meta] of Object.entries(deps)) { names.add(name); if (meta && meta.dependencies) walk(meta.dependencies); }
  };
  if (j.dependencies) walk(j.dependencies);
  return [...names];
}

function parseYarnLock(text) {
  const names = new Set();
  for (const line of text.split('\n')) {
    // entry headers start at col 0 and end with ':' ; may list several specifiers comma-separated
    if (!line || line[0] === ' ' || line[0] === '#') continue;
    if (!line.trimEnd().endsWith(':')) continue;
    const header = line.trimEnd().replace(/:$/, '');
    for (const spec of header.split(',')) names.add(cleanNpmName(spec));
  }
  return [...names].filter(Boolean);
}

function parsePnpmLock(text) {
  const names = new Set();
  // pnpm keys like: /@scope/name@1.2.3:  or  /name@1.2.3:  (v6)  ·  '@scope/name@1.2.3': (v9)
  const re = /^\s*['"]?\/?((?:@[^/@\s]+\/)?[^@/\s'"]+)@[^\s:'"]+['"]?:/gm;
  let m; while ((m = re.exec(text)) !== null) { if (m[1]) names.add(m[1]); }
  return [...names];
}

function parsePoetryLock(text) {
  const names = new Set();
  // TOML [[package]] blocks with name = "x"
  const re = /^\s*name\s*=\s*"([^"]+)"/gm;
  let m; while ((m = re.exec(text)) !== null) names.add(m[1]);
  return [...names];
}

function parseRequirementsTxt(text) {
  const names = new Set();
  for (let line of text.split('\n')) {
    line = line.trim();
    if (!line || line.startsWith('#') || line.startsWith('-')) continue; // skip flags/-r/-e
    // drop env markers / extras / version specifiers
    line = line.split(';')[0].trim();
    const m = line.match(/^([A-Za-z0-9._-]+)\s*(\[[^\]]*\])?\s*(==|>=|<=|~=|!=|>|<|@|=)?/);
    if (m && m[1]) names.add(m[1]);
  }
  return [...names];
}

export function parseLockfile(content, format) {
  switch (format) {
    case 'package-lock.json': return parsePackageLockJson(content);
    case 'yarn.lock':         return parseYarnLock(content);
    case 'pnpm-lock.yaml':    return parsePnpmLock(content);
    case 'poetry.lock':       return parsePoetryLock(content);
    case 'requirements.txt':  return parseRequirementsTxt(content);
    default: return [];
  }
}
