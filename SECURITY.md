# Security Policy

## Scope

`agent-guard-mcp` is a **read-only** analysis tool. It queries public package
registries (npm, PyPI) and inspects text you pass in (lockfiles, manifests, CI
YAML). It never installs packages, executes fetched code, writes to your
filesystem, or requires API keys or credentials.

## Reporting a vulnerability

If you find a security issue in agent-guard itself (e.g. a way to make it return
a false OK for a known-malicious package, or a crash on crafted input), please
open a **private security advisory** on the GitHub repository rather than a
public issue. We aim to acknowledge reports within 72 hours.

## Supported versions

The latest published `0.2.x` release on npm is supported. Older versions are not
patched — pin a specific version (e.g. `@0.2.1`) and update deliberately.

## Detection caveats

agent-guard uses heuristics (existence checks, typo-distance, a maintained
slop/threat corpus, and known-compromised-artifact signatures such as the
tj-actions / reviewdog CI incidents). It is not a CVE database and does not
replace `npm audit` / OSV. It reduces risk; it is not a guarantee. A verdict of `OK` means no known signal fired, not that a package is
proven safe. Always keep a human in the loop for `SUSPICIOUS` / `REVIEW` /
`DANGER` / `BLOCK` verdicts.
