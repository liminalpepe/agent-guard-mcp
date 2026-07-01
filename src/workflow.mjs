// CI Workflow Action-Integrity Validator.
// An agent calls this before merging a PR that touches CI workflows. Parses `uses:` actions,
// flags mutable pins, known-compromised actions, untrusted owners, and fetch-and-exec / secret-exposure
// patterns. Maintained compromised-action corpus is the compounding moat.

// Reputable owners — we only info-flag "unknown owner" for those NOT in this allowlist.
const GOOD_OWNERS = new Set([
  'actions', 'github', 'docker', 'aws-actions', 'azure', 'google-github-actions', 'hashicorp',
  'gradle', 'pnpm', 'denoland', 'ruby', 'oven-sh', 'softprops', 'peter-evans', 'codecov', 'dorny',
  'actions-rs', 'JamesIves', 'ncipollo', 'goreleaser', 'sigstore', 'slsa-framework',
]);

// Seed compromised/risky corpus (name-prefix → note, severity). Compounds per real incident.
const COMPROMISED = [
  [/^tj-actions\/changed-files/i, 'CRITICAL', 'tj-actions/changed-files supply-chain compromise (Mar 2025) — leaked CI secrets via mutated tags'],
  [/^reviewdog\/action-setup/i, 'HIGH', 'reviewdog/action-setup implicated in the 2025 tag-mutation incident chain'],
];

const SEV = { LOW: 1, MEDIUM: 2, HIGH: 3, CRITICAL: 4 };
const clamp = (n) => Math.max(0, Math.min(100, Math.round(n)));
const isSha = (ref) => /^[0-9a-f]{40}$/i.test(ref);

export function scanWorkflow(content, platform = 'github-actions') {
  const text = String(content || '');
  const findings = [];
  const push = (dimension, severity, delta, evidence, line, ref) =>
    findings.push({ id: `${dimension}:${findings.length}`, dimension, severity, risk_delta: delta, evidence, line: line ?? null, corpus_ref: ref ?? null });

  // 1) parse `uses:` third-party actions + pins
  const usesRe = /^\s*-?\s*uses:\s*['"]?([^'"@\s]+)@([^'"\s#]+)/gim;
  const actions = [];
  let m;
  while ((m = usesRe.exec(text)) !== null) {
    const [full, name, ref] = m;
    const line = text.slice(0, m.index).split('\n').length;
    if (name.startsWith('./') || name.startsWith('.\\')) continue; // local action
    actions.push({ name, ref, line });
    const owner = name.split('/')[0];

    // known-compromised
    for (const [re, sev, note] of COMPROMISED) if (re.test(name)) push('compromised_action', sev, sev === 'CRITICAL' ? 45 : 30, `${name}@${ref}: ${note}`, line, 'compromised-corpus');

    // mutable pin (tag/branch, not a 40-char SHA)
    if (!isSha(ref)) push('mutable_pin', 'MEDIUM', 15, `${name} pinned to mutable ref "@${ref}" — pin to a full commit SHA`, line, 'mutable-pin');

    // untrusted owner
    if (!GOOD_OWNERS.has(owner)) push('untrusted_owner', 'LOW', 6, `${name}: owner "${owner}" not in known-good allowlist — review reputation`, line, 'owner-allowlist');
  }

  // 2) fetch-and-exec in run: steps
  if (/(curl|wget)\s+[^\n|]*\|\s*(ba)?sh/i.test(text)) push('fetch_exec', 'CRITICAL', 40, 'workflow pipes a remote script into a shell (curl|bash)', null, 'fetch-exec');

  // 3) pull_request_target + checkout of untrusted head
  if (/pull_request_target/.test(text) && /actions\/checkout/i.test(text) && /head\.(sha|ref)|pull_request\.head/i.test(text))
    push('pr_target_checkout', 'HIGH', 30, 'pull_request_target checks out untrusted PR head — arbitrary code with secrets in scope', null, 'pwn-request');

  // 4) secret exposure
  if (/echo\s+[^\n]*\$\{\{\s*secrets\./i.test(text) || /print[^\n]*secrets\./i.test(text))
    push('secret_exposure', 'HIGH', 28, 'workflow echoes/prints a secret — risk of log exfiltration', null, 'secret-echo');

  // 5) self-hosted runner (informational risk on public repos)
  if (/runs-on:\s*\[?\s*self-hosted/i.test(text)) push('self_hosted_runner', 'LOW', 6, 'self-hosted runner — fork PRs can compromise the host if not gated', null, 'self-hosted');

  const dim = {};
  for (const f of findings) dim[f.dimension] = clamp((dim[f.dimension] || 0) + f.risk_delta);
  const risk_score = clamp(findings.reduce((s, f) => s + f.risk_delta, 0));
  const maxSev = findings.reduce((mx, f) => Math.max(mx, SEV[f.severity] || 0), 0);
  const overall_verdict = risk_score >= 70 || maxSev === 4 ? 'DANGER' : risk_score >= 35 || maxSev >= 3 ? 'SUSPICIOUS' : 'OK';
  const merge_recommendation = overall_verdict === 'DANGER' ? 'BLOCK' : overall_verdict === 'SUSPICIOUS' ? 'REVIEW' : 'PROCEED';
  const summary = overall_verdict === 'OK'
    ? `${actions.length} third-party action(s); all pinned/known-good.`
    : `${findings.length} finding(s) across ${actions.length} action(s); top severity ${['none', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'][maxSev]}. ${merge_recommendation}.`;

  return { platform, risk_score, overall_verdict, merge_recommendation, summary,
    actions_scanned: actions.length, dimension_scores: dim, flag_count: findings.length, _findings: findings };
}
