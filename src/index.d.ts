import type { Report, PolicyOptions, RuleInfo, Severity } from './core.js';
export * from './core.js';
export type CheckName = 'tripwire' | 'license' | 'sbom' | 'workflows';
export interface GateConfig {
  /** package-tripwire config, plus optional "baseline" file for non-git use */
  tripwire?: Record<string, unknown> & { baseline?: string };
  /** license-sentinel config (preset, allow, deny, exceptions, includeDev…) */
  license?: Record<string, unknown>;
  /** sbom-diff-sentinel options (copyleft, maxChanges, rules, allow…) */
  sbom?: Record<string, unknown>;
  /** workflow-sentinel config (trustedOwners, rules, allow, ignore…) */
  workflows?: Record<string, unknown>;
}
export interface CheckOptions extends PolicyOptions { checks?: CheckName[]; base?: string; offline?: boolean; config?: GateConfig; modules?: { sbom?: unknown; fetchImpl?: typeof fetch; tripwireRegistry?: unknown }; }
export declare const VERSION: string;
export declare const CHECKS: CheckName[];
export declare const RULES: Record<string, RuleInfo>;
export declare const TOOL: { name: string; version: string; rules: Record<string, RuleInfo>; title: string; emoji: string; defaultFailOn: Severity };
export declare function sbomAvailable(): boolean;
export declare function defaultBase(dir: string, env?: Record<string, string | undefined>): string;
/** Run the selected checks on a project directory and merge them into one report. */
export declare function check(dir?: string, opts?: CheckOptions): Promise<Report>;
