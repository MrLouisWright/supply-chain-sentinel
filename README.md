# supply-chain-sentinel

[![npm version](https://img.shields.io/npm/v/supply-chain-sentinel.svg)](https://www.npmjs.com/package/supply-chain-sentinel) [![CI](https://github.com/MrLouisWright/supply-chain-sentinel/actions/workflows/ci.yml/badge.svg)](https://github.com/MrLouisWright/supply-chain-sentinel/actions/workflows/ci.yml) [![Node](https://img.shields.io/node/v/supply-chain-sentinel.svg)](https://nodejs.org) [![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

> One supply-chain gate for npm projects: risky dependency changes, license policy, new vulnerabilities and SBOM drift, and GitHub Actions hardening, with one config, one report and one exit code.

`supply-chain-sentinel` is an orchestrator: it has no checks of its own. It runs four focused tools, merges their results, scores them and applies one shared baseline:

| Check | Tool | What it catches |
|---|---|---|
| `tripwire` | [package-tripwire](https://github.com/MrLouisWright/package-tripwire) | Lockfile changes since `--base`: new install scripts, typosquats, publisher/maintainer changes, integrity changes, very fresh releases, git/tarball sources, deprecated packages |
| `license` | [license-sentinel](https://github.com/MrLouisWright/license-sentinel) | Dependency licenses against your policy (presets, allow/deny lists, exceptions with expiry) |
| `sbom` | [sbom-diff-sentinel](https://github.com/MrLouisWright/sbom-diff-sentinel) | CycloneDX SBOM of `--base` vs now: new OSV vulnerabilities (with VEX), licence changes, hash changes, downgrades, too many changes. Licence *policy* stays with license-sentinel |
| `workflows` | [workflow-sentinel](https://github.com/MrLouisWright/workflow-sentinel) | GitHub Actions: unpinned actions, script injection, `pull_request_target` checkouts, broad permissions, persisted credentials… |

Every finding gets a prefixed rule id (`tripwire/install-script`, `license/denied-license`, `sbom/new-vulnerability`, `workflows/unpinned-action`), so one allowlist and one severity map cover everything, and one `--fail-on` decides the exit code. Node.js 18+.

All four tools are regular dependencies (`^1.1.0`), so `npm i -D supply-chain-sentinel` is all you need.

### Combined score

Each check that ran scores 100 minus 40 per critical, 15 per high, 5 per medium and 1 per low finding (floored at 0). The overall score is the mean of those (set `"scoreWeights": { "sbom": 2 }` to weight a check), capped at 49 while any critical finding is open and at 59 when a check crashed. Grades: A ≥ 90, B ≥ 80, C ≥ 70, D ≥ 60, else F. The score is in the JSON report (`score.overall`, `score.byCheck`), the text output and the Markdown table; `--min-score <n>` (or `"minScore"`) also fails the run below `n`.

### Shared baseline

Adopting a gate on an existing project usually means a wall of old findings. Record them once for all four checks and only new findings count from then on:

```bash
npx supply-chain-sentinel --update-baseline --base origin/main   # writes .supply-chain-baseline.json
npx supply-chain-sentinel --baseline .supply-chain-baseline.json
```

The baseline stores a fingerprint per finding (check-prefixed rule, location and evidence, not the message wording, so tool upgrades that reword messages do not resurface them). Its optional `base` ref becomes the default `--base` for both `tripwire` and `sbom`, so both diffs start from the same point. Baselined findings are listed under `baselined` in JSON and do not affect the exit code or the score.

Checks that do not apply are skipped with a reason: no lockfile, no workflows, or not a git repository (for `tripwire` you can point `"tripwire": { "baseline": "deps-baseline.json" }` at a baseline saved with package-tripwire instead). A check that crashes is reported as `check-error` and the exit code is 2, while the other checks still run.

## Install and run

```bash
npm i -D supply-chain-sentinel
npx supply-chain-sentinel                        # all checks, compared with HEAD
npx supply-chain-sentinel --base origin/main --fail-on medium
npx supply-chain-sentinel --only workflows,license --offline
npx supply-chain-sentinel --format sarif > supply-chain.sarif
```

In a pull request on GitHub Actions the default base is `origin/$GITHUB_BASE_REF`; check out with `fetch-depth: 0` so the base exists.

## Configuration

`.supply-chain-sentinel.json` (or `--config <file>`). Shared keys apply to the combined report; per-tool keys are passed to that tool unchanged.

```json
{
  "failOn": "high",
  "only": ["tripwire", "license", "sbom", "workflows"],
  "severity": { "tripwire/recent-publish": "low", "license/*": "high" },
  "allow": [
    { "rule": "workflows/unpinned-action", "match": "*actions/checkout*", "reason": "Pinned by Dependabot, SEC-42", "expires": "2027-01-31" },
    { "rule": "sbom/new-vulnerability", "match": "GHSA-xxxx-*", "reason": "Not reachable, see SEC-50", "expires": "2026-12-31" }
  ],
  "tripwire": { "minAge": "3d" },
  "license": { "preset": "permissive", "deny": ["AGPL-3.0-only"] },
  "sbom": { "vex": ["vex.openvex.json"], "maxChanges": 50 },
  "baseline": ".supply-chain-baseline.json",
  "minScore": 80,
  "scoreWeights": { "sbom": 2 },
  "workflows": { "trustedOwners": ["my-org"] }
}
```

- **`severity`** changes the severity of any rule (globs such as `license/*` work), or turns it `off`.
- **`allow`** suppresses findings. Each entry needs a `rule` and a `reason`, and can be narrowed with `target` (the check name) and `match` (a glob tested against the location, file and evidence). When `expires` (YYYY-MM-DD) has passed, the finding comes back together with an `allow-expired` finding. Entries that match nothing are reported as `allow-unused` (info). Each tool's own allowlist (inside its section) still works too.

## Output and exit codes

- `--format text|json|sarif|markdown` for stdout, plus `--json`, `--sarif` and `--markdown <file>` to write extra copies in one run. SARIF 2.1.0 works with GitHub code scanning.
- `--fail-on critical|high|medium|low|info|none` (default `high`).
- Exit code **0**: passed. **1**: at least one finding at or above `--fail-on`. **2**: usage or config error, or a check could not run.
- `--list-rules` prints every rule of every check with its default severity.

## GitHub Action

```yaml
on: pull_request
permissions:
  contents: read
  security-events: write   # only for the SARIF upload
jobs:
  supply-chain:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262 # v4
        with: { persist-credentials: false, fetch-depth: 0 }
      - uses: MrLouisWright/supply-chain-sentinel@v1
        with:
          fail-on: high
          sarif: supply-chain.sarif
      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        with: { sarif_file: supply-chain.sarif }
```

Inputs: `targets` (project directory, default `.`), `base`, `only`, `offline`, `fail-on`, `config`, `sarif`, `json`, `baseline`, `min-score`, `job-summary` (Markdown report in the job summary, default `true`), `args` (extra CLI flags). Outputs: `markdown-file`, `exit-code`.

## Library

```js
import { check, exitCode } from 'supply-chain-sentinel';
const report = await check('.', { base: 'origin/main', checks: ['tripwire', 'workflows'], baseline: '.supply-chain-baseline.json' });
console.log(report.score.overall, report.score.grade);
process.exitCode = exitCode(report, 'high');
```

### Module formats and types

Ships **ESM and CommonJS** (`import` and `require` both work, via `exports`), with TypeScript declarations generated from the source at build time. Tests run on Node 18/20/22 in GitHub Actions (`test/`), including require/import checks against the packed tarball; releases are published with npm provenance.

## Requirements

Node.js 18 or newer, and `git` for the `tripwire` and `sbom` comparisons. Runtime dependencies: package-tripwire, license-sentinel, sbom-diff-sentinel and workflow-sentinel (and their own, e.g. `yaml`).

## Support

If this project is useful to you, you can support its development with a donation: [Buy me a coffee](https://donate.stripe.com/aFa00lek3cvX4Ds2Fk9EI0b). It helps keep these tools maintained, documented and free for everyone.

## Credit (optional)

Free to use under MIT, no attribution required. If supply-chain-sentinel helps you, a link back is appreciated:

```html
<a href="https://louiswright.co.uk">Built with supply-chain-sentinel by Louis Wright</a>
```

```markdown
[![Built with supply-chain-sentinel by Louis Wright](https://img.shields.io/badge/built%20with-supply--chain--sentinel-blue)](https://louiswright.co.uk)
```

## License

MIT © Louis Wright ([Louis Wright](https://github.com/MrLouisWright))
