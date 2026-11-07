import fs from 'fs';
import path from 'path';
import { assertSafeRelPath } from './paths';
import { Config, Placement, PlacementType, Severity, TripwireError, parseSeverity } from './types';

export const CONFIG_FILENAME = 'tripwire.config.json';

const PLACEMENT_TYPES: PlacementType[] = ['secrets', 'guard', 'instruction'];

export function defaultConfig(): Config {
  return {
    version: 1,
    failOn: 'low',
    allowManifestEdits: false,
    ignore: ['node_modules/**', 'dist/**', 'build/**', 'vendor/**', '**/*.lock', 'package-lock.json'],
    ignoreSecretsInIgnoredPaths: false,
    placements: [
      { path: '.tripwire/decoys/credentials.example', type: 'secrets', id: 'secrets' },
      { path: '.tripwire/GUARD.txt', type: 'guard', id: 'guard' },
      { path: 'AGENTS.md', type: 'instruction', id: 'agents' },
      { path: 'docs/onboarding.md', type: 'instruction', id: 'onboarding' },
      { path: '.github/ISSUE_TEMPLATE/bug_report.md', type: 'instruction', id: 'issue' },
    ],
  };
}

function asBoolean(value: unknown, fallback: boolean, label: string): boolean {
  if (value === undefined) return fallback;
  if (typeof value !== 'boolean') throw new TripwireError(`${label} must be true or false.`);
  return value;
}

function parsePlacement(value: unknown, index: number): Placement {
  if (value === null || typeof value !== 'object') {
    throw new TripwireError(`placements[${index}] must be an object.`);
  }
  const raw = value as Record<string, unknown>;
  if (typeof raw.path !== 'string' || raw.path.trim() === '') {
    throw new TripwireError(`placements[${index}].path is required.`);
  }
  if (typeof raw.type !== 'string' || !PLACEMENT_TYPES.includes(raw.type as PlacementType)) {
    throw new TripwireError(
      `placements[${index}].type must be one of: ${PLACEMENT_TYPES.join(', ')}.`,
    );
  }
  const placement: Placement = {
    path: assertSafeRelPath(raw.path),
    type: raw.type as PlacementType,
  };
  if (raw.id !== undefined) {
    if (typeof raw.id !== 'string' || !/^[a-z][a-z0-9]{0,31}$/.test(raw.id)) {
      throw new TripwireError(
        `placements[${index}].id must match /^[a-z][a-z0-9]{0,31}$/ so it can be embedded safely.`,
      );
    }
    placement.id = raw.id;
  }
  return placement;
}

export function parseConfig(value: unknown): Config {
  if (value === null || typeof value !== 'object') throw new TripwireError('Config must be a JSON object.');
  const raw = value as Record<string, unknown>;
  if (raw.version !== 1) throw new TripwireError('tripwire.config.json version must be 1.');
  const defaults = defaultConfig();
  const failOn: Severity =
    raw.failOn === undefined ? defaults.failOn : parseSeverity(String(raw.failOn));
  let ignore = defaults.ignore;
  if (raw.ignore !== undefined) {
    if (!Array.isArray(raw.ignore) || raw.ignore.some((item) => typeof item !== 'string')) {
      throw new TripwireError('ignore must be an array of glob strings.');
    }
    ignore = raw.ignore as string[];
  }
  let placements = defaults.placements;
  if (raw.placements !== undefined) {
    if (!Array.isArray(raw.placements) || raw.placements.length === 0) {
      throw new TripwireError('placements must be a non-empty array.');
    }
    placements = raw.placements.map((item, index) => parsePlacement(item, index));
  }
  const secrets = placements.filter((item) => item.type === 'secrets');
  const guards = placements.filter((item) => item.type === 'guard');
  if (secrets.length !== 1) throw new TripwireError('Config needs exactly one placements entry of type "secrets".');
  if (guards.length !== 1) throw new TripwireError('Config needs exactly one placements entry of type "guard".');
  if (!placements.some((item) => item.type === 'instruction')) {
    throw new TripwireError('Config needs at least one placements entry of type "instruction".');
  }
  const ids = new Set<string>();
  for (const placement of placements) {
    const id = placementId(placement);
    if (ids.has(id)) throw new TripwireError(`Duplicate placement id "${id}".`);
    ids.add(id);
  }
  return {
    version: 1,
    failOn,
    allowManifestEdits: asBoolean(raw.allowManifestEdits, defaults.allowManifestEdits, 'allowManifestEdits'),
    ignore,
    ignoreSecretsInIgnoredPaths: asBoolean(
      raw.ignoreSecretsInIgnoredPaths,
      defaults.ignoreSecretsInIgnoredPaths,
      'ignoreSecretsInIgnoredPaths',
    ),
    placements,
  };
}

export function placementId(placement: Placement): string {
  if (placement.id) return placement.id;
  if (placement.type === 'secrets') return 'secrets';
  if (placement.type === 'guard') return 'guard';
  const slug = placement.path
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '')
    .slice(0, 32);
  if (!/^[a-z][a-z0-9]{0,31}$/.test(slug)) {
    throw new TripwireError(`Cannot derive a safe id from path "${placement.path}". Set an explicit id.`);
  }
  return slug;
}

export function configPath(root: string): string {
  return path.join(root, CONFIG_FILENAME);
}

export function readConfig(root: string): Config {
  const file = configPath(root);
  if (!fs.existsSync(file)) return defaultConfig();
  let parsed: unknown;
  try {
    parsed = JSON.parse(fs.readFileSync(file, 'utf8'));
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    throw new TripwireError(`Could not parse ${CONFIG_FILENAME}: ${message}`);
  }
  return parseConfig(parsed);
}

export function writeConfig(root: string, config: Config): void {
  const file = configPath(root);
  fs.writeFileSync(file, `${JSON.stringify(config, null, 2)}\n`, 'utf8');
}

export function loadOrCreateConfig(root: string): { config: Config; created: boolean } {
  const file = configPath(root);
  if (!fs.existsSync(file)) {
    const config = defaultConfig();
    writeConfig(root, config);
    return { config, created: true };
  }
  return { config: readConfig(root), created: false };
}
