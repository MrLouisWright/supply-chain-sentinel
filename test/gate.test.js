import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, mkdirSync, rmSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { execFileSync, spawnSync } from 'node:child_process';
import { check, exitCode, RULES, CHECKS, defaultBase, scoreReport, fingerprint, writeBaseline, readBaseline } from '../src/index.js';
import { readFileSync } from 'node:fs';

const lock = (pkgs) => JSON.stringify({ name: 'demo', version: '1.0.0', lockfileVersion: 3, requires: true, packages: { '': { name: 'demo', version: '1.0.0', license: 'MIT', dependencies: Object.fromEntries(Object.keys(pkgs).map((k) => [k, pkgs[k].version])) }, ...Object.fromEntries(Object.entries(pkgs).map(([k, v]) => [`node_modules/${k}`, { version: v.version, resolved: v.resolved || `https://registry.npmjs.org/${k}/-/${k}-${v.version}.tgz`, integrity: v.integrity || 'sha512-' + Buffer.from(k + v.version).toString('base64'), license: v.license || 'MIT', ...(v.hasInstallScript ? { hasInstallScript: true } : {}) }])) } }, null, 2);
let dir;
before(() => {
  dir = mkdtempSync(join(tmpdir(), 'scs-'));
  const g = (...a) => execFileSync('git', a, { cwd: dir, stdio: 'ignore' });
  g('init', '-q', '-b', 'main'); g('config', 'user.email', 't@e.st'); g('config', 'user.name', 't'); g('config', 'commit.gpgsign', 'false');
  writeFileSync(join(dir, 'package.json'), JSON.stringify({ name: 'demo', version: '1.0.0', license: 'MIT', dependencies: { 'left-pad': '1.3.0' } }));
  writeFileSync(join(dir, 'package-lock.json'), lock({ 'left-pad': { version: '1.3.0' } }));
  g('add', '.'); g('commit', '-qm', 'base');
  writeFileSync(join(dir, 'package.json'), JSON.stringify({ name: 'demo', version: '1.0.0', license: 'MIT', dependencies: { 'left-pad': '1.3.0', sketchy: 'github:someone/sketchy', gpl: '1.0.0' } }));
  writeFileSync(join(dir, 'package-lock.json'), lock({ 'left-pad': { version: '1.3.0' }, sketchy: { version: '0.0.1', resolved: 'git+ssh://git@github.com/someone/sketchy.git#abc', hasInstallScript: true }, gpl: { version: '1.0.0', license: 'AGPL-3.0-only' } }));
  mkdirSync(join(dir, '.github/workflows'), { recursive: true });
  writeFileSync(join(dir, '.github/workflows/ci.yml'), 'on: pull_request_target\njobs:\n  b:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n        with:\n          ref: ${{ github.event.pull_request.head.sha }}\n      - run: echo "${{ github.event.pull_request.title }}"\n');
});
after(() => rmSync(dir, { recursive: true, force: true }));
const rules = (r) => new Set(r.findings.map((f) => f.rule));
const fakeSbom = { generateSbomAtRef: () => ({}), generateSbom: () => ({}), analyze: async () => ({ diff: { added: [1], removed: [], upgraded: [] }, vulnerabilities: { new: [{}], status: 'ok' }, findings: [{ rule: 'new-vulnerability', severity: 'critical', package: 'gpl', version: '1.0.0', message: 'gpl@1.0.0: GHSA-xxxx-yyyy-zzzz (critical)', id: 'GHSA-xxxx-yyyy-zzzz' }], suppressed: [] }) };

test('rule catalogue is prefixed per check', () => {
  assert.ok(RULES['tripwire/install-script'] && RULES['license/denied-license'] !== undefined || Object.keys(RULES).some((k) => k.startsWith('license/')));
  assert.ok(Object.keys(RULES).some((k) => k.startsWith('workflows/')) && Object.keys(RULES).some((k) => k.startsWith('sbom/')));
  assert.deepEqual(CHECKS, ['tripwire', 'license', 'sbom', 'workflows']);
});
test('combined report: tripwire, license, workflows and (injected) sbom', async () => {
  const r = await check(dir, { offline: true, base: 'HEAD', modules: { sbom: fakeSbom }, config: { license: { preset: 'permissive' } } });
  const s = rules(r);
  assert.ok(s.has('tripwire/install-script'), [...s].join());
  assert.ok(s.has('tripwire/non-registry-source'));
  assert.ok([...s].some((k) => k.startsWith('license/')), 'license finding for AGPL');
  assert.ok(s.has('sbom/new-vulnerability'));
  assert.ok([...s].some((k) => k.startsWith('workflows/')));
  assert.deepEqual(r.targets.map((t) => t.target), CHECKS);
  assert.equal(exitCode(r, 'high'), 1);
});
test('shared allowlist and severity use prefixed ids and globs', async () => {
  const r = await check(dir, { offline: true, base: 'HEAD', checks: ['workflows', 'tripwire'], allow: [{ rule: 'workflows/*', reason: 'tracked in SEC-1', expires: '2099-01-01' }], severity: { 'tripwire/install-script': 'off' } });
  const s = rules(r);
  assert.ok(![...s].some((k) => k.startsWith('workflows/'))); assert.ok(!s.has('tripwire/install-script'));
  assert.ok(r.suppressed.length > 0);
});
test('checks can be selected; sbom-diff-sentinel is a declared dependency', async () => {
  const pkg = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8'));
  assert.match(pkg.dependencies['sbom-diff-sentinel'], /^\^1\./); assert.equal(pkg.peerDependencies, undefined);
  const r = await check(dir, { offline: true, checks: ['sbom'], base: 'HEAD' });
  assert.equal(r.targets[0].summary.status, 'ran');
  assert.notEqual(exitCode(r, 'high'), 2);
  await assert.rejects(() => check(dir, { checks: ['nope'] }), /Unknown check/);
});
test('real sbom-diff-sentinel runs with the shared base', async () => {
  const r = await check(dir, { offline: true, checks: ['sbom'], base: 'HEAD' });
  assert.equal(r.targets[0].summary.status, 'ran');
});
test('non-git directory: tripwire and sbom are skipped', async () => {
  const d = mkdtempSync(join(tmpdir(), 'scs-nogit-'));
  writeFileSync(join(d, 'package.json'), JSON.stringify({ name: 'x', version: '1.0.0', license: 'MIT' }));
  writeFileSync(join(d, 'package-lock.json'), lock({}));
  const r = await check(d, { offline: true, modules: { sbom: fakeSbom } });
  assert.equal(r.targets.find((t) => t.target === 'tripwire').summary.status, 'skipped');
  assert.equal(r.targets.find((t) => t.target === 'sbom').summary.status, 'skipped');
  assert.equal(exitCode(r, 'high'), 0);
  rmSync(d, { recursive: true, force: true });
});
test('a failing check is a fatal error (exit 2) without stopping the others', async () => {
  const r = await check(dir, { offline: true, base: 'HEAD', checks: ['sbom', 'workflows'], modules: { sbom: { ...fakeSbom, analyze: async () => { throw new Error('boom'); } } } });
  assert.ok(rules(r).has('check-error')); assert.equal(exitCode(r, 'high'), 2);
  assert.equal(r.targets.find((t) => t.target === 'workflows').summary.status, 'ran');
});
test('defaultBase uses the PR base branch when available', () => { assert.equal(defaultBase(dir, {}), 'HEAD'); assert.equal(defaultBase(dir, { GITHUB_BASE_REF: 'nope' }), 'HEAD'); });
test('CLI', () => {
  const bin = new URL('../bin/supply-chain-sentinel.js', import.meta.url).pathname;
  for (const f of ['json', 'sarif', 'markdown', 'text']) { const p = spawnSync('node', [bin, dir, '--offline', '--base', 'HEAD', '--skip', 'sbom', '-f', f]); assert.equal(p.status, 1, f + p.stderr); assert.ok(p.stdout.length); }
  assert.equal(spawnSync('node', [bin, dir, '--offline', '--only', 'license', '--fail-on', 'none']).status, 0);
  assert.equal(spawnSync('node', [bin, dir, '--only', 'bogus']).status, 2);
  assert.equal(spawnSync('node', [bin, '/nonexistent']).status, 2);
  assert.match(spawnSync('node', [bin, '--list-rules']).stdout.toString(), /workflows\/unpinned-action/);
});

test('combined score: per check, weighted, capped by criticals', async () => {
  const r = await check(dir, { offline: true, base: 'HEAD', modules: { sbom: fakeSbom } });
  assert.deepEqual(Object.keys(r.score.byCheck), CHECKS);
  for (const v of Object.values(r.score.byCheck)) { assert.equal(v.status, 'ran'); assert.ok(v.score >= 0 && v.score <= 100); }
  assert.ok(r.score.overall <= 49 && r.score.grade === 'F', 'critical sbom finding caps the score');
  const fake = (t) => ({ findings: t.flatMap((x) => x.findings), targets: t });
  const t = (target, sevs, status = 'ran') => ({ target, summary: { status }, findings: sevs.map((severity) => ({ severity })) });
  const s = scoreReport(fake([t('tripwire', ['high']), t('license', []), t('sbom', [], 'skipped'), t('workflows', ['medium', 'low'])]));
  assert.deepEqual(s, { overall: 93, grade: 'A', byCheck: { tripwire: { score: 85, grade: 'B', status: 'ran' }, license: { score: 100, grade: 'A', status: 'ran' }, sbom: { score: null, grade: null, status: 'skipped' }, workflows: { score: 94, grade: 'A', status: 'ran' } } });
  assert.equal(scoreReport(fake([t('tripwire', ['high']), t('license', [])]), { weights: { tripwire: 3 } }).overall, 89);
  assert.equal(scoreReport(fake([t('license', [])])).overall, 100);
  assert.match((await import('../src/core.js')).formatText(r), /Score: \d+\/100 \(F\)/);
  assert.match((await import('../src/core.js')).formatMarkdown(r), /\*\*Score: \d+\/100/);
});
test('shared baseline: one file for every check, only new findings count', async () => {
  const opts = { offline: true, base: 'HEAD', modules: { sbom: fakeSbom } };
  const first = await check(dir, opts);
  const file = join(mkdtempSync(join(tmpdir(), 'scs-bl-')), 'baseline.json');
  const b = writeBaseline(first, file, { base: 'HEAD' });
  assert.ok(b.findings.length > 3); assert.equal(b.base, 'HEAD');
  assert.ok(new Set(b.findings.map((f) => f.rule.split('/')[0])).size >= 3, 'covers several checks');
  assert.deepEqual(readBaseline(file).findings, b.findings);
  const again = await check(dir, { ...opts, base: undefined, baseline: file });
  assert.equal(again.base, 'HEAD', 'base taken from baseline');
  assert.equal(again.findings.filter((f) => f.rule.includes('/')).length, 0);
  assert.equal(again.baselined.length, first.findings.filter((f) => f.rule.includes('/')).length);
  assert.equal(again.score.overall, 100); assert.equal(exitCode(again, 'high'), 0);
  const trimmed = { ...b, findings: b.findings.filter((f) => !f.rule.startsWith('workflows/')) };
  const partial = await check(dir, { ...opts, baseline: trimmed });
  assert.ok(partial.findings.length > 0 && partial.findings.every((f) => f.rule.startsWith('workflows/')));
  assert.equal(fingerprint({ rule: 'a', location: 'x', message: 'one' }), fingerprint({ rule: 'a', location: 'x', message: 'two' }));
  await assert.rejects(() => check(dir, { ...opts, baseline: join(tmpdir(), 'nope-baseline.json') }), /Cannot read baseline/);
});
test('CLI: --update-baseline, --baseline and --min-score', () => {
  const bin = new URL('../bin/supply-chain-sentinel.js', import.meta.url).pathname;
  const f = join(mkdtempSync(join(tmpdir(), 'scs-cli-')), 'b.json');
  const args = [bin, dir, '--offline', '--base', 'HEAD', '--skip', 'sbom'];
  const u = spawnSync('node', [...args, '--update-baseline', '--baseline', f]); assert.equal(u.status, 0, u.stderr.toString()); assert.match(u.stderr.toString(), /Wrote \d+ finding/);
  const p = spawnSync('node', [...args, '--baseline', f]); assert.equal(p.status, 0, p.stdout.toString()); assert.match(p.stdout.toString(), /hidden by the baseline/);
  const m = spawnSync('node', [bin, dir, '--offline', '--only', 'workflows', '--fail-on', 'none', '--min-score', '99']); assert.equal(m.status, 1); assert.match(m.stderr.toString(), /below --min-score/);
  assert.equal(spawnSync('node', [bin, dir, '--min-score', 'abc']).status, 2);
});
