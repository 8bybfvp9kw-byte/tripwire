export type Severity = 'info' | 'low' | 'medium' | 'high' | 'critical';

export const SEVERITIES: Severity[] = ['info', 'low', 'medium', 'high', 'critical'];

export function severityRank(severity: Severity): number {
  return SEVERITIES.indexOf(severity);
}

export function parseSeverity(value: string): Severity {
  const normalized = value.trim().toLowerCase();
  if ((SEVERITIES as string[]).includes(normalized)) return normalized as Severity;
  throw new Error(`Unknown severity "${value}". Use one of: ${SEVERITIES.join(', ')}.`);
}

export type CanaryKind = 'secret' | 'marker' | 'url';

export type CanaryFormat =
  | 'github_pat'
  | 'aws_access_key_id'
  | 'aws_secret_access_key'
  | 'stripe_test_secret_key'
  | 'signal'
  | 'callback_url'
  | 'guard_nonce';

export interface Canary {
  id: string;
  kind: CanaryKind;
  format: CanaryFormat;
  sha256: string;
  plantedPaths: string[];
  /** When set, the value is expected only inside this delimited block. */
  blockId?: string;
  severity: Severity;
  description: string;
}

export interface PlantedFile {
  path: string;
  type: 'file' | 'block';
  blockId?: string;
  sha256: string;
  createdFile: boolean;
}

export interface Manifest {
  version: 1;
  namespace: string;
  generatedAt: string;
  canaries: Canary[];
  retired: Canary[];
  files: PlantedFile[];
}

export type PlacementType = 'secrets' | 'guard' | 'instruction';

export interface Placement {
  path: string;
  type: PlacementType;
  id?: string;
}

export interface Config {
  version: 1;
  failOn: Severity;
  allowManifestEdits: boolean;
  ignore: string[];
  ignoreSecretsInIgnoredPaths: boolean;
  placements: Placement[];
}

export interface Finding {
  id: string;
  severity: Severity;
  kind: CanaryKind | 'tamper' | 'manifest';
  path: string;
  line: number;
  message: string;
  /** Display line with secret material redacted. */
  detail?: string;
}

export interface ScanReport {
  result: 'pass' | 'fail';
  failOn: Severity;
  findings: Finding[];
  /** Findings at or above failOn. */
  blocking: Finding[];
  agentSignals: string[];
  filesScanned: number;
}

export class TripwireError extends Error {
  readonly exitCode = 2;

  constructor(message: string) {
    super(message);
    this.name = 'TripwireError';
  }
}
