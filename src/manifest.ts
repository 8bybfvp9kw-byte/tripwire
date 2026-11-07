import fs from 'fs';
import path from 'path';
import { Manifest, TripwireError } from './types';

export const MANIFEST_PATH = '.tripwire/manifest.json';

export function manifestFile(root: string): string {
  return path.join(root, MANIFEST_PATH);
}

export function parseManifest(parsed: unknown): Manifest {
  if (parsed === null || typeof parsed !== 'object') throw new TripwireError('Manifest is not an object.');
  const raw = parsed as Partial<Manifest>;
  if (raw.version !== 1) throw new TripwireError('Manifest version must be 1.');
  if (typeof raw.namespace !== 'string' || !/^tw[a-f0-9]{8}$/.test(raw.namespace)) {
    throw new TripwireError('Manifest namespace is missing or malformed.');
  }
  if (!Array.isArray(raw.canaries) || !Array.isArray(raw.files) || !Array.isArray(raw.retired)) {
    throw new TripwireError('Manifest is missing canaries, files, or retired.');
  }
  return raw as Manifest;
}

export function parseManifestText(text: string): Manifest {
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    throw new TripwireError(`Could not parse ${MANIFEST_PATH}: ${message}`);
  }
  return parseManifest(parsed);
}

export function readManifest(root: string): Manifest {
  const file = manifestFile(root);
  if (!fs.existsSync(file)) {
    throw new TripwireError(`No canary manifest at ${MANIFEST_PATH}. Run \`tripwire init\` first.`);
  }
  return parseManifestText(fs.readFileSync(file, 'utf8'));
}

export function writeManifest(root: string, manifest: Manifest): void {
  const file = manifestFile(root);
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, `${JSON.stringify(manifest, null, 2)}\n`, 'utf8');
}
