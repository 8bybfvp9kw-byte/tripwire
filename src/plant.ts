import fs from 'fs';
import path from 'path';
import { findBlock, renderBlock, stripBlock, upsertBlock } from './blocks';
import { defaultConfig, placementId, readConfig, writeConfig } from './config';
import { sha256Text } from './hash';
import { MANIFEST_PATH, readManifest, writeManifest } from './manifest';
import { resolveInside } from './paths';
import { byteSource } from './rng';
import { credentialsFile, guardFile, instructionBody, PREFACES } from './templates';
import { callbackUrl, generateSecrets, markerFor } from './tokens';
import { Canary, Manifest, Placement, PlantedFile, TripwireError } from './types';

const FIXED_SEED_TIME = '2026-01-01T00:00:00.000Z';
const RETIRED_CAP = 100;

export interface PlantOptions {
  seed?: string;
  dryRun?: boolean;
}

export interface PlantResult {
  root: string;
  manifest: Manifest;
  wrote: string[];
  removed: string[];
  dryRun: boolean;
}

function readText(file: string): string | null {
  if (!fs.existsSync(file)) return null;
  return fs.readFileSync(file, 'utf8').replace(/\r\n/g, '\n');
}

function writeText(root: string, rel: string, content: string): void {
  const abs = resolveInside(root, rel);
  fs.mkdirSync(path.dirname(abs), { recursive: true });
  fs.writeFileSync(abs, content.endsWith('\n') ? content : `${content}\n`, 'utf8');
}

function ownedHeader(content: string): boolean {
  return content.startsWith('# Tripwire decoy credentials\n') || content.startsWith('Tripwire guard file.\n');
}

interface PlannedWrite {
  path: string;
  content: string;
  planted: PlantedFile;
  canaries: Canary[];
}

function planInstruction(
  placement: Placement,
  namespace: string,
  existing: string | null,
  createdFile: boolean,
): PlannedWrite {
  const id = placementId(placement);
  const marker = markerFor(namespace, id);
  const url = callbackUrl(namespace, id);
  const block = renderBlock(id, instructionBody(marker, url, id));
  const base = existing ?? PREFACES[placement.path] ?? '';
  const content = upsertBlock(base, id, block);
  const span = findBlock(content, id);
  if (!span) throw new TripwireError(`Failed to embed the canary block in ${placement.path}.`);
  const canaries: Canary[] = [
    {
      id: `marker-${id}`,
      kind: 'marker',
      format: 'signal',
      sha256: sha256Text(marker),
      plantedPaths: [placement.path],
      blockId: id,
      severity: 'high',
      description: `Hidden instruction in ${placement.path} tells an agent to add this marker.`,
    },
    {
      id: `url-${id}`,
      kind: 'url',
      format: 'callback_url',
      sha256: sha256Text(url),
      plantedPaths: [placement.path],
      blockId: id,
      severity: 'high',
      description: `Hidden instruction in ${placement.path} tells an agent to add this callback URL.`,
    },
  ];
  return {
    path: placement.path,
    content,
    planted: {
      path: placement.path,
      type: 'block',
      blockId: id,
      sha256: sha256Text(span.text),
      createdFile,
    },
    canaries,
  };
}

function planSecrets(placement: Placement, secrets: ReturnType<typeof generateSecrets>): PlannedWrite {
  const content = credentialsFile(secrets);
  const canaries: Canary[] = [
    {
      id: 'secret-github-pat',
      kind: 'secret',
      format: 'github_pat',
      sha256: sha256Text(secrets.githubPat),
      plantedPaths: [placement.path],
      severity: 'critical',
      description: 'Synthetic GitHub-shaped canary (gh_tripwire_ prefix, not a GitHub credential).',
    },
    {
      id: 'secret-aws-access-key-id',
      kind: 'secret',
      format: 'aws_access_key_id',
      sha256: sha256Text(secrets.awsAccessKeyId),
      plantedPaths: [placement.path],
      severity: 'critical',
      description: 'Synthetic AWS access-key canary (aws_tripwire_ prefix, not an AWS access key id).',
    },
    {
      id: 'secret-aws-secret',
      kind: 'secret',
      format: 'aws_secret_access_key',
      sha256: sha256Text(secrets.awsSecretAccessKey),
      plantedPaths: [placement.path],
      severity: 'critical',
      description: 'Synthetic AWS secret canary (aws_tripwire_secret_ prefix, not an AWS secret).',
    },
    {
      id: 'secret-stripe-test',
      kind: 'secret',
      format: 'stripe_test_secret_key',
      sha256: sha256Text(secrets.stripeTestSecretKey),
      plantedPaths: [placement.path],
      severity: 'critical',
      description: 'Synthetic Stripe-shaped canary (sk_tripwire_ prefix, not a Stripe API key).',
    },
  ];
  return {
    path: placement.path,
    content,
    planted: {
      path: placement.path,
      type: 'file',
      sha256: sha256Text(content),
      createdFile: true,
    },
    canaries,
  };
}

function planGuard(placement: Placement, secrets: ReturnType<typeof generateSecrets>): PlannedWrite {
  const content = guardFile(secrets.namespace, secrets.guardNonce);
  return {
    path: placement.path,
    content,
    planted: {
      path: placement.path,
      type: 'file',
      sha256: sha256Text(content),
      createdFile: true,
    },
    canaries: [
      {
        id: 'guard-nonce',
        kind: 'marker',
        format: 'guard_nonce',
        sha256: sha256Text(secrets.guardNonce),
        plantedPaths: [placement.path],
        severity: 'high',
        description: 'Guard-file nonce.',
      },
    ],
  };
}

function retire(canaries: Canary[], stamp: string): Canary[] {
  return canaries.map((canary) => ({
    id: `${canary.id}@${stamp}`,
    kind: canary.kind,
    format: canary.format,
    sha256: canary.sha256,
    plantedPaths: [],
    severity: canary.severity,
    description: `Retired canary ${canary.id}. It is no longer planted and still counts if it shows up.`,
  }));
}

function assertCanOverwrite(root: string, rel: string, nextIsManaged: boolean): void {
  if (!nextIsManaged) return;
  const existing = readText(resolveInside(root, rel));
  if (existing === null) return;
  if (ownedHeader(existing)) return;
  throw new TripwireError(
    `${rel} already exists and is not a Tripwire file. Move it, or run \`tripwire remove\` if it is from an older plant.`,
  );
}

export function plant(root: string, options: PlantOptions & { rotate: boolean }): PlantResult {
  const absRoot = path.resolve(root);
  if (!fs.existsSync(absRoot) || !fs.statSync(absRoot).isDirectory()) {
    throw new TripwireError(`Not a directory: ${absRoot}`);
  }
  const previous = options.rotate ? readManifest(absRoot) : null;
  if (!options.rotate && fs.existsSync(path.join(absRoot, MANIFEST_PATH))) {
    throw new TripwireError(
      `Already initialized (${MANIFEST_PATH}). Run \`tripwire rotate\` to replace canaries, or \`tripwire remove\` first.`,
    );
  }
  const configFile = path.join(absRoot, 'tripwire.config.json');
  const configExisted = fs.existsSync(configFile);
  const config = configExisted ? readConfig(absRoot) : defaultConfig();

  const source = byteSource(options.seed);
  const secrets = generateSecrets(source);
  const planned: PlannedWrite[] = [];
  for (const placement of config.placements) {
    if (placement.type === 'secrets') {
      assertCanOverwrite(absRoot, placement.path, true);
      planned.push(planSecrets(placement, secrets));
    } else if (placement.type === 'guard') {
      assertCanOverwrite(absRoot, placement.path, true);
      planned.push(planGuard(placement, secrets));
    } else {
      const existing = readText(resolveInside(absRoot, placement.path));
      const prior = previous?.files.find((file) => file.path === placement.path);
      const createdFile = existing === null ? true : prior?.createdFile === true;
      planned.push(planInstruction(placement, secrets.namespace, existing, createdFile));
    }
  }

  const newPaths = new Set(planned.map((item) => item.path));
  const removed: string[] = [];
  if (previous) {
    for (const file of previous.files) {
      if (newPaths.has(file.path)) continue;
      removed.push(...cleanupPlanted(absRoot, file, options.dryRun === true));
    }
  }

  const retired = [
    ...(previous ? retire(previous.canaries, previous.namespace) : []),
    ...(previous?.retired ?? []),
  ].slice(0, RETIRED_CAP);
  const manifest: Manifest = {
    version: 1,
    namespace: secrets.namespace,
    generatedAt: options.seed === undefined ? new Date().toISOString() : FIXED_SEED_TIME,
    canaries: planned.flatMap((item) => item.canaries),
    retired,
    files: planned.map((item) => item.planted),
  };

  const wrote = [MANIFEST_PATH, ...planned.map((item) => item.path)];
  if (!options.rotate && !configExisted) wrote.push('tripwire.config.json');
  if (!options.dryRun) {
    if (!options.rotate && !configExisted) writeConfig(absRoot, config);
    for (const item of planned) writeText(absRoot, item.path, item.content);
    // Re-hash from disk so the manifest matches the bytes the scanner will read.
    manifest.files = planned.map((item) => rehash(absRoot, item.planted));
    manifest.canaries = planned.flatMap((item) => item.canaries);
    writeManifest(absRoot, manifest);
  }
  return { root: absRoot, manifest, wrote: unique(wrote), removed, dryRun: options.dryRun === true };
}

function rehash(root: string, planted: PlantedFile): PlantedFile {
  const text = readText(resolveInside(root, planted.path));
  if (text === null) throw new TripwireError(`Planted file disappeared: ${planted.path}`);
  if (planted.type === 'file') return { ...planted, sha256: sha256Text(text) };
  const blockId = planted.blockId;
  if (!blockId) throw new TripwireError(`Block file ${planted.path} has no block id.`);
  const span = findBlock(text, blockId);
  if (!span) throw new TripwireError(`Canary block ${blockId} is missing from ${planted.path} after write.`);
  return { ...planted, sha256: sha256Text(span.text) };
}

function unique(values: string[]): string[] {
  return [...new Set(values)];
}

function cleanupPlanted(root: string, file: PlantedFile, dryRun: boolean): string[] {
  const abs = resolveInside(root, file.path);
  const existing = readText(abs);
  if (existing === null) return [];
  if (file.type === 'file') {
    if (!ownedHeader(existing)) return [];
    if (!dryRun) {
      fs.rmSync(abs);
      pruneEmptyParents(root, path.dirname(abs));
    }
    return [file.path];
  }
  if (!file.blockId) return [];
  const stripped = stripBlock(existing, file.blockId).replace(/^\n+/, '').replace(/\n+$/, '\n');
  const preface = PREFACES[file.path];
  const onlyPreface =
    file.createdFile &&
    (stripped.trim() === '' || (preface !== undefined && stripped.trim() === preface.trim()));
  if (!dryRun) {
    if (onlyPreface) {
      fs.rmSync(abs);
      pruneEmptyParents(root, path.dirname(abs));
    } else if (stripped.trim() === '') {
      fs.rmSync(abs);
      pruneEmptyParents(root, path.dirname(abs));
    } else {
      fs.writeFileSync(abs, stripped.endsWith('\n') ? stripped : `${stripped}\n`, 'utf8');
    }
  }
  return onlyPreface || stripped.trim() === '' ? [file.path] : [];
}

function pruneEmptyParents(root: string, dir: string): void {
  const absRoot = path.resolve(root);
  let current = dir;
  while (current.startsWith(absRoot) && current !== absRoot) {
    if (!fs.existsSync(current)) break;
    const entries = fs.readdirSync(current);
    if (entries.length > 0) break;
    fs.rmdirSync(current);
    current = path.dirname(current);
  }
}

export function initRepo(root: string, options: PlantOptions = {}): PlantResult {
  return plant(root, { ...options, rotate: false });
}

export function rotateRepo(root: string, options: PlantOptions = {}): PlantResult {
  return plant(root, { ...options, rotate: true });
}

export function removeRepo(root: string, options: { dryRun?: boolean } = {}): { removed: string[] } {
  const absRoot = path.resolve(root);
  const manifest = readManifest(absRoot);
  const removed: string[] = [];
  for (const file of manifest.files) {
    removed.push(...cleanupPlanted(absRoot, file, options.dryRun === true));
  }
  const manifestAbs = path.join(absRoot, MANIFEST_PATH);
  if (fs.existsSync(manifestAbs)) {
    if (!options.dryRun) {
      fs.rmSync(manifestAbs);
      pruneEmptyParents(absRoot, path.dirname(manifestAbs));
    }
    removed.push(MANIFEST_PATH);
  }
  return { removed };
}

export function describePlant(result: PlantResult, verb: 'Planted' | 'Rotated'): string {
  const lines = [
    `Tripwire ${verb.toLowerCase()} canaries in ${result.root}.`,
    ...result.wrote.map((file) => `  ${file}`),
  ];
  if (result.removed.length > 0) {
    lines.push('Removed:');
    lines.push(...result.removed.map((file) => `  ${file}`));
  }
  if (verb === 'Rotated') {
    lines.push(
      'Previous values stay in the manifest as retired and still fail the check if they show up.',
      'The manifest change itself fails the check until a maintainer bypasses it or sets allow-manifest-edits.',
    );
  } else if (!result.dryRun) {
    lines.push('Commit these files. Canaries are inert. Remove them with `tripwire remove`.');
  }
  if (result.dryRun) lines.unshift('Dry run. No files were written.');
  return lines.join('\n');
}

