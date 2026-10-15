#!/usr/bin/env node
import { runCli, list, UsageError } from '../src/cli-core.js';
import { check, CHECKS, TOOL, writeBaseline, exitCode } from '../src/index.js';

const HELP = `supply-chain-sentinel {VERSION} — one supply-chain gate: dependencies, licenses, SBOM drift, CI workflows

Usage: supply-chain-sentinel [project-dir] [options]

Runs, with one config, one report and one exit code:
  tripwire    package-tripwire: risky dependency changes since --base (install scripts, typosquats,
              new publishers, integrity changes, fresh releases, non-registry sources…)
  license     license-sentinel: dependency licenses against your policy
  sbom        sbom-diff-sentinel: SBOM diff against --base, new OSV vulnerabilities, licence changes
  workflows   workflow-sentinel: GitHub Actions hardening

      --only <list>          Run only these checks (comma-separated)
      --skip <list>          Skip these checks
      --base <ref>           Git ref to compare against (default: origin/$GITHUB_BASE_REF in PRs, else HEAD)
      --offline              No registry or OSV lookups
      --baseline <file>      Shared baseline for all checks: known findings are hidden, only new ones count;
                             its "base" ref (if set) is the default --base for tripwire and sbom
      --update-baseline      Write the current findings to --baseline (default .supply-chain-baseline.json)
      --min-score <n>        Also fail (exit 1) when the combined score (0-100) is below n
Rule ids are prefixed with the check: tripwire/install-script, license/denied-license, sbom/new-vulnerability,
workflows/unpinned-action. "allow" and "severity" in .supply-chain-sentinel.json use these ids (globs work:
"workflows/*"). Per-tool settings go under "tripwire", "license", "sbom" and "workflows".
{COMMON}`;

process.exitCode = await runCli(TOOL, {
  help: HELP,
  options: { only: { type: 'string' }, skip: { type: 'string' }, base: { type: 'string' }, offline: { type: 'boolean' }, baseline: { type: 'string' }, 'update-baseline': { type: 'boolean' }, 'min-score': { type: 'string' } },
  async run(o, pos, cfg, ctx) {
    if (pos.length > 1) throw new UsageError('Give one project directory');
    const only = o.only ? list(o.only) : cfg.only; const skip = o.skip ? list(o.skip) : cfg.skip || [];
    for (const c of [...(only || []), ...skip]) if (!CHECKS.includes(c)) throw new UsageError(`Unknown check "${c}" (use ${CHECKS.join(', ')})`);
    const checks = (only || CHECKS).filter((c) => !skip.includes(c));
    if (!checks.length) throw new UsageError('No checks left to run');
    const minScore = o['min-score'] ?? cfg.minScore;
    if (minScore !== undefined && !(Number(minScore) >= 0 && Number(minScore) <= 100)) throw new UsageError(`Invalid --min-score: ${minScore}`);
    const baselineFile = o.baseline || cfg.baseline || (o['update-baseline'] ? '.supply-chain-baseline.json' : undefined);
    const report = await check(pos[0] || cfg.dir || '.', { checks, base: o.base || cfg.base, offline: o.offline ?? cfg.offline, config: { tripwire: cfg.tripwire, license: cfg.license, sbom: cfg.sbom, workflows: cfg.workflows }, allow: cfg.allow, severity: cfg.severity, scoreWeights: cfg.scoreWeights, baseline: o['update-baseline'] ? undefined : baselineFile });
    if (o['update-baseline']) {
      const b = writeBaseline(report, baselineFile, { base: o.base || cfg.base });
      ctx.io.stderr.write(`Wrote ${b.findings.length} finding(s) to ${baselineFile}.\n`);
      return { report, exit: report.targets.some((t) => t.fatal) ? 2 : 0 };
    }
    let exit = exitCode(report, ctx.failOn);
    if (exit === 0 && minScore !== undefined && report.score.overall != null && report.score.overall < Number(minScore)) { exit = 1; ctx.io.stderr.write(`Score ${report.score.overall} is below --min-score ${minScore}.\n`); }
    return { report, exit };
  },
});
