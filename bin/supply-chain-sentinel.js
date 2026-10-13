#!/usr/bin/env node
import { runCli, list, UsageError } from '../src/cli-core.js';
import { check, CHECKS, TOOL } from '../src/index.js';

const HELP = `supply-chain-sentinel {VERSION} — one supply-chain gate: dependencies, licenses, SBOM drift, CI workflows

Usage: supply-chain-sentinel [project-dir] [options]

Runs, with one config, one report and one exit code:
  tripwire    package-tripwire: risky dependency changes since --base (install scripts, typosquats,
              new publishers, integrity changes, fresh releases, non-registry sources…)
  license     license-sentinel: dependency licenses against your policy
  sbom        sbom-diff-sentinel: SBOM diff against --base, new OSV vulnerabilities (optional peer)
  workflows   workflow-sentinel: GitHub Actions hardening

      --only <list>          Run only these checks (comma-separated)
      --skip <list>          Skip these checks
      --base <ref>           Git ref to compare against (default: origin/$GITHUB_BASE_REF in PRs, else HEAD)
      --offline              No registry or OSV lookups
Rule ids are prefixed with the check: tripwire/install-script, license/denied-license, sbom/new-vulnerability,
workflows/unpinned-action. "allow" and "severity" in .supply-chain-sentinel.json use these ids (globs work:
"workflows/*"). Per-tool settings go under "tripwire", "license", "sbom" and "workflows".
{COMMON}`;

process.exitCode = await runCli(TOOL, {
  help: HELP,
  options: { only: { type: 'string' }, skip: { type: 'string' }, base: { type: 'string' }, offline: { type: 'boolean' } },
  async run(o, pos, cfg) {
    if (pos.length > 1) throw new UsageError('Give one project directory');
    const only = o.only ? list(o.only) : cfg.only; const skip = o.skip ? list(o.skip) : cfg.skip || [];
    for (const c of [...(only || []), ...skip]) if (!CHECKS.includes(c)) throw new UsageError(`Unknown check "${c}" (use ${CHECKS.join(', ')})`);
    const checks = (only || CHECKS).filter((c) => !skip.includes(c));
    if (!checks.length) throw new UsageError('No checks left to run');
    return check(pos[0] || cfg.dir || '.', { checks, base: o.base || cfg.base, offline: o.offline ?? cfg.offline, config: { tripwire: cfg.tripwire, license: cfg.license, sbom: cfg.sbom, workflows: cfg.workflows }, allow: cfg.allow, severity: cfg.severity });
  },
});
