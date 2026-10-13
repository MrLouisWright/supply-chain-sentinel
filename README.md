# supply-chain-sentinel

> One supply-chain gate for npm projects: risky dependency changes, license policy, new vulnerabilities and SBOM drift, and GitHub Actions hardening, with one config, one report and one exit code.

`supply-chain-sentinel` runs four focused tools and merges their results:

| Check | Tool | What it catches |
|---|---|---|
| `tripwire` | [package-tripwire](https://github.com/MrLouisWright/package-tripwire) | Lockfile changes since `--base`: new install scripts, typosquats, publisher/maintainer changes, integrity changes, very fresh releases, git/tarball sources, deprecated packages |
| `license` | [license-sentinel](https://github.com/MrLouisWright/license-sentinel) | Dependency licenses against your policy (presets, allow/deny lists, exceptions with expiry) |
| `sbom` | [sbom-diff-sentinel](https://github.com/MrLouisWright/sbom-diff-sentinel) | CycloneDX SBOM of `--base` vs now: new OSV vulnerabilities, copyleft additions, hash changes, downgrades, too many changes |
| `workflows` | [workflow-sentinel](https://github.com/MrLouisWright/workflow-sentinel) | GitHub Actions: unpinned actions, script injection, `pull_request_target` checkouts, broad permissions, persisted credentials… |

Every finding gets a prefixed rule id (`tripwire/install-script`, `license/denied-license`, `sbom/new-vulnerability`, `workflows/unpinned-action`), so one allowlist and one severity map cover everything, and one `--fail-on` decides the exit code. Node.js 18+.

**sbom-diff-sentinel is an optional peer dependency**: install it next to this package (`npm i -D supply-chain-sentinel sbom-diff-sentinel`) to enable the `sbom` check. Without it the check is reported as unavailable (info) and the others still run. The GitHub Action installs this package's own dependencies.

Checks that do not apply are skipped with a reason: no lockfile, no workflows, or not a git repository (for `tripwire` you can point `"tripwire": { "baseline": "deps-baseline.json" }` at a baseline saved with package-tripwire instead). A check that crashes is reported as `check-error` and the exit code is 2, while the other checks still run.

## Install and run

```bash
npm i -D supply-chain-sentinel sbom-diff-sentinel
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
  "sbom": { "copyleft": "strong", "maxChanges": 50 },
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

Inputs: `targets` (project directory, default `.`), `base`, `only`, `offline`, `fail-on`, `config`, `sarif`, `json`, `job-summary` (Markdown report in the job summary, default `true`), `args` (extra CLI flags). Outputs: `markdown-file`, `exit-code`.

## Library

```js
import { check, exitCode } from 'supply-chain-sentinel';
const report = await check('.', { base: 'origin/main', checks: ['tripwire', 'workflows'] });
process.exitCode = exitCode(report, 'high');
```

## Requirements

Node.js 18 or newer, and `git` for the `tripwire` and `sbom` comparisons. Runtime dependencies: package-tripwire, license-sentinel, workflow-sentinel (and their own, e.g. `yaml`), plus the optional peer sbom-diff-sentinel.

## License

MIT © Louis Wright
