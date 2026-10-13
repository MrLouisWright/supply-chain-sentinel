import { readFileSync, existsSync, statSync } from 'node:fs';
import { join, resolve, relative } from 'node:path';
import { execFileSync } from 'node:child_process';
import { buildReport, exceeds, exitCode, formatText, formatJson, formatSarif, formatMarkdown, SEVERITIES, ConfigError, validateConfig } from './core.js';
import * as tripwire from 'package-tripwire';
import * as license from 'license-sentinel';
import * as workflows from 'workflow-sentinel';

let sbom = null; let sbomError = null;
try { sbom = await import('sbom-diff-sentinel'); } catch (e) { sbomError = e.code || e.message; }

export { exceeds, exitCode, formatText, formatJson, formatSarif, formatMarkdown, SEVERITIES, ConfigError };
export const VERSION = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8')).version;
export const CHECKS = ['tripwire', 'license', 'sbom', 'workflows'];
const LEVEL = { error: 'high', warn: 'medium', note: 'low' };
const SBOM_RULES = { 'new-vulnerability': 'high', 'copyleft-license': 'high', 'hash-changed': 'high', 'too-many-changes': 'high', 'osv-error': 'high', downgrade: 'medium', 'supplier-changed': 'medium', 'license-changed': 'low', 'allowlist-expired': 'low', 'unscanned-component': 'info', 'sbom-warning': 'info' };

function buildRules() {
  const r = {
    'check-error': { severity: 'high', title: 'A check could not run (see message)', group: 'gate' },
    'check-unavailable': { severity: 'info', title: 'A check was skipped because its package or inputs are missing', group: 'gate' },
  };
  for (const [k, v] of Object.entries(tripwire.RULES)) r[`tripwire/${k}`] = { severity: LEVEL[v.level] || 'medium', title: v.title, group: 'tripwire' };
  for (const [k, v] of Object.entries(license.RULES)) r[`license/${k}`] = { severity: v.severity, title: v.title, group: 'license' };
  for (const [k, v] of Object.entries(sbom?.RULES || Object.fromEntries(Object.entries(SBOM_RULES).map(([k2, s]) => [k2, { severity: s, title: k2 }])))) r[`sbom/${k}`] = { severity: v.severity === 'vuln' ? 'high' : v.severity, title: v.title, group: 'sbom' };
  for (const [k, v] of Object.entries(workflows.RULES)) r[`workflows/${k}`] = { severity: v.severity, title: v.title, group: 'workflows' };
  return r;
}
export const RULES = buildRules();
export const TOOL = { name: 'supply-chain-sentinel', version: VERSION, rules: RULES, title: 'supply-chain-sentinel', emoji: '🔗', defaultFailOn: 'high' };
export const sbomAvailable = () => !!sbom;

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
  if (!mod) return { unavailable: `sbom-diff-sentinel is not installed (${sbomError}); run "npm i -D sbom-diff-sentinel" to enable it` };
  if (!git(dir, ['rev-parse', '--is-inside-work-tree'])) return { skipped: 'not a git repository (needed to build the base SBOM)' };
  if (!tripwire.detectLockfile(dir)) return { skipped: 'no lockfile' };
  let base;
  try { base = mod.generateSbomAtRef(dir, o.base); } catch (e) { return { skipped: `no base SBOM at ${o.base}: ${e.message}` }; }
  const head = mod.generateSbom(dir);
  const opts = { ...(o.config.sbom || {}), offline: o.offline, ...(o.modules?.fetchImpl ? { fetchImpl: o.modules.fetchImpl } : {}), ...(o.now ? { now: o.now } : {}) };
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
  const o = { ...opts, config: opts.config || {}, base: opts.base || defaultBase(abs) };
  const results = [];
  for (const c of checks) {
    let r;
    try { r = await RUNNERS[c](abs, o); }
    catch (e) { results.push({ target: c, fatal: true, raw: [{ rule: 'check-error', location: c, message: `${c}: ${e.message}` }], errors: [`${c}: ${e.message}`] }); continue; }
    if (r.skipped || r.unavailable) { results.push({ target: c, summary: { status: 'skipped', reason: r.skipped || r.unavailable }, raw: r.unavailable ? [{ rule: 'check-unavailable', location: c, message: r.unavailable }] : [] }); continue; }
    for (const f of r.raw) if (f.file) f.file = relative(process.cwd(), join(abs, f.file)) || f.file;
    results.push({ target: c, summary: { status: 'ran', ...r.summary, ...(r.suppressed ? { suppressedByTool: r.suppressed } : {}) }, raw: r.raw });
  }
  return buildReport(TOOL, results, opts);
}
