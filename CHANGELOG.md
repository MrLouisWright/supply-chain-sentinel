# Changelog

## 1.0.0 - 2026-10-14

- First release: one gate that runs package-tripwire, license-sentinel, sbom-diff-sentinel (optional peer) and workflow-sentinel with a shared config, prefixed rule ids, one combined text/JSON/SARIF/Markdown report and one exit code (0/1/2). Checks can be selected with `--only`/`--skip`; non-applicable checks are skipped with a reason; a crashing check is reported without stopping the others. Composite GitHub Action that installs its own dependencies.
