// H2 — Skill-Pack / Agent-Plugin Manifest Scorer.
// Scores a Cursor/Claude skill or MCP plugin manifest (+ optional bundle files) for
// poison/backdoor signatures, credential scope over-reach, and drift vs a baseline.
// Findings-based: each finding carries a risk_delta; risk_score = clamp(sum). Maintained
// signature corpus is the compounding moat (grows per real incident).

// --- signature corpus (seed; grows over time) -------------------------------
const SIG = {
  exfil: [
    [/discord(app)?\.com\/api\/webhooks/i, 'CRITICAL', 45, 'Discord webhook exfil endpoint'],
    [/https?:\/\/[^\s"'`]*\b(exfil|collect|telemetry-ingest|stealer)\b/i, 'CRITICAL', 45, 'exfil-style endpoint'],
    [/(t\.me\/|pastebin\.com|transfer\.sh|ngrok\.io|burpcollaborator)/i, 'HIGH', 30, 'known drop/tunnel host'],
  ],
  obfuscation: [
    [/eval\s*\(/, 'HIGH', 28, 'dynamic eval()'],
    [/new\s+Function\s*\(/, 'HIGH', 28, 'Function() constructor (dynamic code)'],
    [/atob\s*\(|Buffer\.from\([^)]*,\s*['"]base64['"]\)|base64\s*(-d|--decode)/i, 'MEDIUM', 20, 'base64 decode of payload'],
    [/(\\x[0-9a-f]{2}){8,}/i, 'MEDIUM', 18, 'long hex-escaped blob'],
  ],
  shell: [
    [/curl\s+[^\n|]*\|\s*(ba)?sh/i, 'CRITICAL', 40, 'curl | sh remote execution'],
    [/wget\s+[^\n|]*\|\s*(ba)?sh/i, 'CRITICAL', 40, 'wget | sh remote execution'],
    [/child_process|\bexecSync?\s*\(|\bspawnSync?\s*\(|subprocess\.|os\.system\s*\(/, 'MEDIUM', 15, 'shell/process execution'],
  ],
  credpath: [
    [/(~\/|\/)\.ssh\/(id_|authorized|known_hosts)/i, 'CRITICAL', 40, 'reads SSH private keys'],
    [/(~\/|\/)\.aws\/credentials/i, 'CRITICAL', 40, 'reads AWS credentials'],
    [/login\.keychain|security\s+find-generic-password/i, 'HIGH', 30, 'macOS keychain access'],
    [/(~\/|\/)\.(netrc|git-credentials|npmrc)\b/i, 'HIGH', 28, 'reads stored credentials'],
    [/(~\/|\/)\.cursor\/|(~\/|\/)\.config\/(claude|cursor)/i, 'MEDIUM', 18, 'reads agent config/creds dir'],
  ],
  credtoken: [
    [/AKIA[0-9A-Z]{16}/, 'CRITICAL', 40, 'hardcoded AWS access key'],
    [/\b(sk-[a-zA-Z0-9]{20,}|ghp_[a-zA-Z0-9]{20,}|xox[baprs]-[a-zA-Z0-9-]{10,})\b/, 'CRITICAL', 40, 'hardcoded API/token secret'],
    [/-----BEGIN (RSA |OPENSSH |EC )?PRIVATE KEY-----/, 'CRITICAL', 45, 'embedded private key'],
    [/postmark|smtp[_-]?pass|mailgun/i, 'LOW', 8, 'mail-credential reference'],
  ],
  // threat-corpus seed-2026-07-01: tool-poisoning / prompt-injection / drift
  toolpoison: [
    [/ignore\s+(all\s+)?(previous|prior)\s+instructions|disregard\s+(the\s+)?system\s+prompt/i, 'CRITICAL', 40, 'prompt-injection: instruction override in manifest/description'],
    [/do\s+not\s+(tell|inform|reveal|mention)\s+(the\s+)?user/i, 'CRITICAL', 40, 'concealment: hides actions from the user'],
    [/[​-‍﻿­]/, 'HIGH', 25, 'zero-width / soft-hyphen homoglyph smuggling in text'],
    [/(post|pre)install["'\s:]+[^\n]{0,40}(curl|wget|https?:\/\/)/i, 'CRITICAL', 40, 'lifecycle script phone-home (postinstall curl/http)'],
  ],
};
const URL_RE = /https?:\/\/([a-z0-9.-]+)/gi;
const ENV_RE = /process\.env\.([A-Z0-9_]+)|(?:^|\n)\s*([A-Z][A-Z0-9_]{2,})\s*[:=]/g;

const SEV_RANK = { LOW: 1, MEDIUM: 2, HIGH: 3, CRITICAL: 4 };
const clamp = (n) => Math.max(0, Math.min(100, Math.round(n)));

function scanText(text, file, findings) {
  for (const [dim, rules] of Object.entries(SIG)) {
    const dimension = dim === 'credpath' || dim === 'credtoken' ? 'scope_overreach' : 'poison_signatures';
    for (const [re, severity, delta, evidence] of rules) {
      const m = re.exec(text);
      if (m) {
        const line = text.slice(0, m.index).split('\n').length;
        findings.push({ id: `${dim}:${findings.length}`, dimension, severity, risk_delta: delta, evidence, file: file || null, line, corpus_ref: dim });
      }
    }
  }
}

function hosts(text) { const s = new Set(); let m; while ((m = URL_RE.exec(text))) s.add(m[1].toLowerCase()); return [...s]; }

export function scoreManifest(input) {
  const { manifest_type, manifest_content, bundle_files = [], baseline_manifest, declared_purpose } = input;
  const findings = [];
  const blob = String(manifest_content || '');
  scanText(blob, 'manifest', findings);
  for (const f of bundle_files.slice(0, 20)) scanText(String(f.content || ''), f.path, findings);

  // scope-overreach: breadth of network hosts vs a simple declared purpose
  const allHosts = hosts(blob + '\n' + bundle_files.map(f => f.content || '').join('\n'));
  if (allHosts.length >= 3) {
    findings.push({ id: `scope:hosts`, dimension: 'scope_overreach', severity: allHosts.length >= 6 ? 'HIGH' : 'MEDIUM',
      risk_delta: Math.min(30, allHosts.length * 4), evidence: `${allHosts.length} distinct network hosts referenced`, file: null, line: null, corpus_ref: 'scope-breadth' });
  }
  if (declared_purpose && declared_purpose.length < 120 && allHosts.length >= 4) {
    findings.push({ id: `scope:mismatch`, dimension: 'scope_overreach', severity: 'MEDIUM', risk_delta: 15,
      evidence: `broad network access for a narrowly stated purpose ("${declared_purpose.slice(0, 60)}")`, file: null, line: null, corpus_ref: 'scope-mismatch' });
  }

  // drift vs baseline
  if (baseline_manifest) {
    const baseHosts = new Set(hosts(String(baseline_manifest)));
    const newHosts = allHosts.filter(h => !baseHosts.has(h));
    if (newHosts.length) findings.push({ id: 'drift:hosts', dimension: 'manifest_drift', severity: 'HIGH', risk_delta: Math.min(45, newHosts.length * 15),
      evidence: `new network host(s) not in approved baseline: ${newHosts.slice(0, 5).join(', ')}`, file: null, line: null, corpus_ref: 'drift-host' });
  }

  const dim = { manifest_drift: 0, scope_overreach: 0, poison_signatures: 0 };
  for (const f of findings) dim[f.dimension] = clamp(dim[f.dimension] + f.risk_delta);
  const risk_score = clamp(findings.reduce((s, f) => s + f.risk_delta, 0));
  const maxSev = findings.reduce((m, f) => Math.max(m, SEV_RANK[f.severity] || 0), 0);
  const hasCritical = maxSev === 4, hasHigh = maxSev >= 3;

  const overall_verdict = risk_score >= 70 || hasCritical ? 'DANGER' : risk_score >= 35 || hasHigh ? 'SUSPICIOUS' : 'OK';
  const install_recommendation = risk_score >= 70 || hasCritical ? 'BLOCK' : risk_score >= 35 || hasHigh ? 'REVIEW' : 'PROCEED';
  const summary = overall_verdict === 'OK'
    ? `No poison signatures or scope over-reach detected across ${1 + bundle_files.length} file(s).`
    : `${findings.length} finding(s); top severity ${['none','LOW','MEDIUM','HIGH','CRITICAL'][maxSev]}. ${install_recommendation}.`;

  return { manifest_type, risk_score, overall_verdict, install_recommendation, summary,
    dimension_scores: dim, flag_count: findings.length, _findings: findings };
}
