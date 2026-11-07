import path from 'path';
import { TripwireError } from './types';

export function toPosix(value: string): string {
  return value.replace(/\\/g, '/');
}

/** Relative path, no traversal, no absolute form. */
export function assertSafeRelPath(value: string): string {
  const posix = toPosix(value).trim();
  if (posix === '' || posix.startsWith('/')) {
    throw new TripwireError(`Refusing path "${value}". Use a relative path.`);
  }
  const norm = path.posix.normalize(posix);
  if (norm === '..' || norm.startsWith('../') || norm.includes('/../') || path.posix.isAbsolute(norm)) {
    throw new TripwireError(`Refusing path "${value}".`);
  }
  return norm;
}

export function resolveInside(root: string, rel: string): string {
  const safe = assertSafeRelPath(rel);
  const absRoot = path.resolve(root);
  const abs = path.resolve(absRoot, safe);
  const prefix = absRoot.endsWith(path.sep) ? absRoot : absRoot + path.sep;
  if (abs !== absRoot && !abs.startsWith(prefix)) {
    throw new TripwireError(`Refusing path "${rel}".`);
  }
  return abs;
}
