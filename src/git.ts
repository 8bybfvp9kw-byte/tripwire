import { execFileSync } from 'child_process';
import fs from 'fs';
import path from 'path';
import { TripwireError } from './types';

const MAX_BUFFER = 50 * 1024 * 1024;

export function git(cwd: string, args: string[]): string {
  try {
    return execFileSync('git', args, {
      cwd,
      encoding: 'utf8',
      maxBuffer: MAX_BUFFER,
      stdio: ['ignore', 'pipe', 'pipe'],
    });
  } catch (err) {
    const error = err as { stderr?: string | Buffer; message?: string };
    const stderr = error.stderr ? error.stderr.toString().trim() : '';
    throw new TripwireError(stderr || error.message || `git ${args.join(' ')} failed`);
  }
}

export function gitRefExists(cwd: string, ref: string): boolean {
  try {
    execFileSync('git', ['rev-parse', '--verify', '--quiet', ref], {
      cwd,
      stdio: 'ignore',
    });
    return true;
  } catch {
    return false;
  }
}

export function gitShow(cwd: string, ref: string, rel: string): string | null {
  const spec = `${ref}:${rel.replace(/\\/g, '/')}`;
  try {
    return execFileSync('git', ['show', spec], {
      cwd,
      encoding: 'utf8',
      maxBuffer: MAX_BUFFER,
      stdio: ['ignore', 'pipe', 'pipe'],
    });
  } catch {
    return null;
  }
}

export function readWorktree(cwd: string, rel: string): string | null {
  const abs = path.resolve(cwd, rel);
  const root = path.resolve(cwd);
  if (abs !== root && !abs.startsWith(root + path.sep)) return null;
  if (!fs.existsSync(abs) || !fs.statSync(abs).isFile()) return null;
  return fs.readFileSync(abs, 'utf8');
}

export const DIFF_FLAGS = ['diff', '--unified=3', '--find-renames', '--no-color', '--no-ext-diff'];

export function diffRange(cwd: string, range: string): string {
  return git(cwd, [...DIFF_FLAGS, range]);
}

export function diffWorktree(cwd: string): string {
  return git(cwd, [...DIFF_FLAGS, 'HEAD']);
}
