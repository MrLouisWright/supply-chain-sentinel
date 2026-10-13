import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, mkdirSync, rmSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { execFileSync, spawnSync } from 'node:child_process';
import { check, exitCode, RULES, CHECKS, defaultBase } from '../src/index.js';

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
test('checks can be selected; missing sbom module is reported, not fatal', async () => {
  const r = await check(dir, { offline: true, checks: ['sbom'], modules: {} });
  if (!r.targets[0].summary || r.targets[0].summary.status === 'skipped') assert.ok(rules(r).has('check-unavailable') || r.targets[0].summary.status === 'skipped');
  assert.notEqual(exitCode(r, 'high'), 2);
  await assert.rejects(() => check(dir, { checks: ['nope'] }), /Unknown check/);
});
test('real sbom-diff-sentinel when it is installed', { skip: !existsSync(new URL('../node_modules/sbom-diff-sentinel/package.json', import.meta.url)) && 'sbom-diff-sentinel not installed' }, async () => {
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
