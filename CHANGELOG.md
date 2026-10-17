# Changelog

## 1.1.0 - 2026-10-17

Re-release: these changes were committed after 1.0.0 was published but never reached npm. 1.0.0 on npm is the original first release.

- Orchestrator only: supply-chain-sentinel has no checks of its own; every finding comes from package-tripwire, license-sentinel, sbom-diff-sentinel or workflow-sentinel.
- sbom-diff-sentinel is now a declared dependency (`^1.1.0`, was an optional peer), so the `sbom` check always runs; all tool dependencies use `^1.1.0` ranges. Licence policy stays with license-sentinel; sbom-diff-sentinel only reports licence changes. `sbom.vex` paths are resolved against the project directory.
- Combined score: per-check 0–100 scores and grades, weighted overall score (`scoreWeights`), capped while criticals are open; shown in text, Markdown and JSON; `--min-score` / `minScore` fails below a threshold.
- Shared baseline: `--update-baseline` records the current findings of every check in one file (`.supply-chain-baseline.json`); `--baseline` hides them so only new findings count. Its `base` ref is the shared default base for tripwire and sbom. Action inputs `baseline` and `min-score`.
- Dual ESM + CommonJS build with generated TypeScript declarations; CI checks require and import from the packed tarball.

## 1.0.0 - 2026-10-15

- First release: one gate that runs package-tripwire, license-sentinel, sbom-diff-sentinel (optional peer) and workflow-sentinel with a shared config, prefixed rule ids, one combined text/JSON/SARIF/Markdown report and one exit code (0/1/2). Checks can be selected with `--only`/`--skip`; non-applicable checks are skipped with a reason; a crashing check is reported without stopping the others. Composite GitHub Action that installs its own dependencies.
