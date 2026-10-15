import { readFileSync, writeFileSync, existsSync, statSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { join, resolve, relative } from 'node:path';
import { execFileSync } from 'node:child_process';
import { buildReport, exceeds, exitCode, formatText, formatJson, formatSarif, formatMarkdown, SEVERITIES, ConfigError, validateConfig } from './core.js';
import * as tripwire from 'package-tripwire';
import * as license from 'license-sentinel';
import * as workflows from 'workflow-sentinel';
import * as sbom from 'sbom-diff-sentinel';

export { exceeds, exitCode, formatText, formatJson, formatSarif, formatMarkdown, SEVERITIES, ConfigError };
export const VERSION = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8')).version;
export const CHECKS = ['tripwire', 'license', 'sbom', 'workflows'];
const LEVEL = { error: 'high', warn: 'medium', note: 'low' };

function buildRules() {
  const r = {
    'check-error': { severity: 'high', title: 'A check could not run (see message)', group: 'gate' },
    'check-unavailable': { severity: 'info', title: 'A check was skipped because its package or inputs are missing', group: 'gate' },
  };
  for (const [k, v] of Object.entries(tripwire.RULES)) r[`tripwire/${k}`] = { severity: LEVEL[v.level] || 'medium', title: v.title, group: 'tripwire' };
  for (const [k, v] of Object.entries(license.RULES)) r[`license/${k}`] = { severity: v.severity, title: v.title, group: 'license' };
  for (const [k, v] of Object.entries(sbom.RULES)) r[`sbom/${k}`] = { severity: v.severity === 'vuln' ? 'high' : v.severity, title: v.title, group: 'sbom' };
  for (const [k, v] of Object.entries(workflows.RULES)) r[`workflows/${k}`] = { severity: v.severity, title: v.title, group: 'workflows' };
  return r;
}
export const RULES = buildRules();
export const TOOL = { name: 'supply-chain-sentinel', version: VERSION, rules: RULES, title: 'supply-chain-sentinel', emoji: '🔗', defaultFailOn: 'high' };

const git = (cwd, args) => { try { return execFileSync('git', args, { cwd, encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] }).trim(); } catch { return null; } };
/** Default comparison base: the PR base branch on GitHub Actions, else HEAD (uncommitted changes). */
export function defaultBase(dir, env = process.env) {
  if (env.GITHUB_BASE_REF && git(dir, ['rev-parse', '--verify', '--quiet', `origin/${env.GITHUB_BASE_REF}^{commit}`])) return `origin/${env.GITHUB_BASE_REF}`;
  return 'HEAD';
}

async function runTripwire(dir, o) {
  const lf = tripwire.detectLockfile(dir);
  if (!lf) return { skipped: 'no lockfile (package-lock.json, npm-shrinkwrap.json, pnpm-lock.yaml or yarn.lock)' };
  const { baseline, ...tcfg } = o.config.tripwire || {};
  if (!baseline && !git(dir, ['rev-parse', '--is-inside-work-tree'])) return { skipped: 'not a git repository; set "tripwire": { "baseline": "<file>" } to compare against a saved baseline' };
  const r = await tripwire.run({ cwd: dir, base: o.base, ...(baseline ? { baseline } : {}), config: tcfg, offline: o.offline, now: o.now ? +new Date(o.now) : undefined, ...(o.modules?.tripwireRegistry ? { registry: o.modules.tripwireRegistry } : {}) });
  return {
    summary: { lockfile: r.lockfile, base: r.base, ...r.stats },
    raw: r.findings.map((f) => ({ rule: `tripwire/${f.rule}`, severity: LEVEL[f.level] || 'medium', location: `${r.lockfile}: ${f.package}@${f.version}`, file: r.lockfile, message: `${f.package}@${f.version}${f.previousVersion ? ` (was ${f.previousVersion})` : ''}: ${f.message}`, evidence: `${f.package}@${f.version}` })),
    suppressed: r.suppressed.length,
  };
}
async function runLicense(dir, o) {
  if (!existsSync(join(dir, 'package.json'))) return { skipped: 'no package.json' };
  const cfg = { ...(o.config.license || {}) };
  const r = o.offline ? license.audit(dir, cfg) : await license.auditAsync(dir, cfg, o.modules?.fetchImpl ? { fetchImpl: o.modules.fetchImpl } : {});
  return {
    summary: { packages: r.summary.packages, license: r.project.license || undefined, preset: r.policy.preset || undefined },
    raw: r.findings.map((f) => ({ rule: `license/${f.rule}`, severity: f.severity, location: `${f.package}@${f.version}`, message: `${f.package}@${f.version}${f.dev ? ' (dev)' : ''}: ${f.message}`, fix: f.fix, evidence: f.license || undefined })),
    suppressed: r.suppressed.length,
  };
}
async function runSbom(dir, o) {
  const mod = o.modules?.sbom || sbom;
  if (!git(dir, ['rev-parse', '--is-inside-work-tree'])) return { skipped: 'not a git repository (needed to build the base SBOM)' };
  if (!tripwire.detectLockfile(dir)) return { skipped: 'no lockfile' };
  let base;
  try { base = mod.generateSbomAtRef(dir, o.base); } catch (e) { return { skipped: `no base SBOM at ${o.base}: ${e.message}` }; }
  const head = mod.generateSbom(dir);
  const sc = { ...(o.config.sbom || {}) };
  if (sc.vex) sc.vex = [].concat(sc.vex).map((v) => resolve(dir, v));
  const opts = { ...sc, offline: o.offline, ...(o.modules?.fetchImpl ? { fetchImpl: o.modules.fetchImpl } : {}), ...(o.now ? { now: o.now } : {}) };
  const r = await mod.analyze(base, head, opts);
  return {
    summary: { base: o.base, added: r.diff.added.length, removed: r.diff.removed.length, upgraded: r.diff.upgraded.length, newVulnerabilities: r.vulnerabilities.new.length, osv: r.vulnerabilities.status },
    raw: r.findings.map((f) => ({ rule: `sbom/${f.rule}`, severity: f.severity, location: f.package ? `${f.package}${f.version ? `@${f.version}` : ''}` : 'sbom', message: f.message, fix: f.fix, evidence: f.id || f.package || undefined, ...(f.url ? { url: f.url } : {}) })),
    suppressed: r.suppressed.length,
  };
}
function runWorkflows(dir, o) {
  const files = workflows.findFiles(dir);
  if (!files.length) return { skipped: 'no GitHub Actions workflows or action.yml' };
  const r = workflows.scan({ cwd: dir, config: { ...(o.config.workflows || {}) }, now: o.now ? +new Date(o.now) : undefined });
  return {
    summary: { files: r.files.length },
    raw: r.findings.map((f) => ({ rule: `workflows/${f.rule}`, severity: f.severity, file: f.file, line: f.line, location: `${f.file}:${f.line}`, message: f.message, fix: f.fix, evidence: f.target || f.ref || undefined })),
    suppressed: r.suppressed.length,
  };
}
const RUNNERS = { tripwire: runTripwire, license: runLicense, sbom: runSbom, workflows: runWorkflows };

/** Points deducted per finding when scoring a check (100 = clean). */
export const SCORE_WEIGHTS = { critical: 40, high: 15, medium: 5, low: 1, info: 0 };
export const gradeOf = (n) => (n == null ? null : n >= 90 ? 'A' : n >= 80 ? 'B' : n >= 70 ? 'C' : n >= 60 ? 'D' : 'F');

/**
 * Combined score: each check that ran gets 100 minus the points of its (unsuppressed, non-baselined) findings,
 * floored at 0; the overall score is the weighted mean of those (weights default to 1 per check), and is capped
 * at 49 (grade F) when any critical finding is open, so one critical issue cannot hide behind clean checks.
 */
export function scoreReport(report, { weights = {}, points = SCORE_WEIGHTS } = {}) {
  const byCheck = {}; let sum = 0; let wsum = 0;
  for (const t of report.targets) {
    if (!CHECKS.includes(t.target)) continue;
    if (t.fatal) { byCheck[t.target] = { score: null, grade: null, status: 'error' }; continue; }
    if (t.summary?.status !== 'ran') { byCheck[t.target] = { score: null, grade: null, status: 'skipped' }; continue; }
    const penalty = t.findings.reduce((n, f) => n + (points[f.severity] ?? 0), 0);
    const score = Math.max(0, 100 - penalty);
    byCheck[t.target] = { score, grade: gradeOf(score), status: 'ran' };
    const w = weights[t.target] ?? 1; sum += score * w; wsum += w;
  }
  let overall = wsum ? Math.round(sum / wsum) : null;
  if (overall != null && report.findings.some((f) => f.severity === 'critical')) overall = Math.min(overall, 49);
  if (report.targets.some((t) => t.fatal) && overall != null) overall = Math.min(overall, 59);
  return { overall, grade: gradeOf(overall), byCheck };
}

/** Stable identity of a finding across runs: check-prefixed rule + location + evidence (not the message wording). */
export function fingerprint(f) {
  return createHash('sha256').update([f.rule, f.location || '', f.file || '', f.evidence || ''].join('\u0000')).digest('hex').slice(0, 20);
}

/** Read a shared baseline file ({ version: 1, base?, findings: [{ fingerprint, rule, location }] }). */
export function readBaseline(file) {
  let b; try { b = JSON.parse(readFileSync(file, 'utf8')); } catch (e) { throw new ConfigError(`Cannot read baseline ${file}: ${e.message}`); }
  if (!b || !Array.isArray(b.findings)) throw new ConfigError(`Baseline ${file} has no "findings" array`);
  return b;
}

/** Write the open findings of a report (plus any already baselined) as the new shared baseline. */
export function writeBaseline(report, file, { base } = {}) {
  const items = [...report.findings.filter((f) => CHECKS.some((c) => f.rule.startsWith(`${c}/`))), ...(report.baselined || [])];
  const seen = new Set(); const findings = [];
  for (const f of items) { const fp = f.fingerprint || fingerprint(f); if (seen.has(fp)) continue; seen.add(fp); findings.push({ fingerprint: fp, rule: f.rule, location: f.location || f.file || '' }); }
  findings.sort((a, b) => a.rule.localeCompare(b.rule) || a.location.localeCompare(b.location));
  const out = { tool: TOOL.name, version: 1, createdAt: report.generatedAt, ...(base ? { base } : {}), findings };
  writeFileSync(file, JSON.stringify(out, null, 2) + '\n');
  return out;
}

/**
 * Run the selected checks on a project directory and merge them into one report.
 * Options: checks (default all), base (git ref), offline, config: { tripwire, license, sbom, workflows }, allow, severity, now.
 */
export async function check(dir = '.', opts = {}) {
  validateConfig({ allow: opts.allow, severity: opts.severity });
  const abs = resolve(dir);
  if (!existsSync(abs) || !statSync(abs).isDirectory()) return buildReport(TOOL, [{ target: dir, fatal: true, raw: [], errors: [`${dir} is not a directory`] }], opts);
  const checks = opts.checks?.length ? opts.checks : CHECKS;
  for (const c of checks) if (!CHECKS.includes(c)) throw new ConfigError(`Unknown check "${c}" (use ${CHECKS.join(', ')})`);
  const baseline = opts.baseline ? (typeof opts.baseline === 'string' ? readBaseline(resolve(opts.baseline)) : opts.baseline) : null;
  const known = new Set((baseline?.findings || []).map((f) => f.fingerprint));
  const o = { ...opts, config: opts.config || {}, base: opts.base || baseline?.base || defaultBase(abs) };
  const results = []; const baselined = [];
  for (const c of checks) {
    let r;
    try { r = await RUNNERS[c](abs, o); }
    catch (e) { results.push({ target: c, fatal: true, raw: [{ rule: 'check-error', location: c, message: `${c}: ${e.message}` }], errors: [`${c}: ${e.message}`] }); continue; }
    if (r.skipped || r.unavailable) { results.push({ target: c, summary: { status: 'skipped', reason: r.skipped || r.unavailable }, raw: r.unavailable ? [{ rule: 'check-unavailable', location: c, message: r.unavailable }] : [] }); continue; }
    for (const f of r.raw) { f.fingerprint = fingerprint(f); if (f.file) f.file = relative(process.cwd(), join(abs, f.file)) || f.file; }
    const open = baseline ? r.raw.filter((f) => !known.has(f.fingerprint)) : r.raw;
    if (baseline) baselined.push(...r.raw.filter((f) => known.has(f.fingerprint)).map((f) => ({ ...f, target: c })));
    results.push({ target: c, summary: { status: 'ran', ...r.summary, ...(r.suppressed ? { suppressedByTool: r.suppressed } : {}), ...(baseline ? { baselined: r.raw.length - open.length } : {}) }, raw: open });
  }
  const report = buildReport(TOOL, results, { ...opts, meta: { base: o.base, ...(baseline ? { baseline: { file: typeof opts.baseline === 'string' ? opts.baseline : undefined, entries: known.size, matched: baselined.length } } : {}), ...(opts.meta || {}) } });
  report.baselined = baselined;
  report.score = scoreReport(report, { weights: opts.scoreWeights });
  return report;
}
