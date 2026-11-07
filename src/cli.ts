#!/usr/bin/env node
import fs from 'fs';
import path from 'path';
import { readConfig } from './config';
import { runDemo } from './demo';
import { diffRange, diffWorktree, git, gitShow, readWorktree } from './git';
import { readManifest } from './manifest';
import { describePlant, initRepo, removeRepo, rotateRepo } from './plant';
import { renderJson, renderText } from './report';
import { scan } from './scan';
import { TripwireError } from './types';

interface Flags {
  positionals: string[];
  values: Map<string, string | boolean>;
}

const VALUE_FLAGS = new Set([
  'diff',
  'range',
  'format',
  'fail-on',
  'seed',
  'config',
  'branch',
  'actor',
  'output',
  'emit',
]);

export function parseArgs(argv: string[]): Flags {
  const positionals: string[] = [];
  const values = new Map<string, string | boolean>();
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i] ?? '';
    if (arg === '--') {
      positionals.push(...argv.slice(i + 1));
      break;
    }
    if (!arg.startsWith('--')) {
      positionals.push(arg);
      continue;
    }
    const body = arg.slice(2);
    const eq = body.indexOf('=');
    if (eq !== -1) {
      values.set(body.slice(0, eq), body.slice(eq + 1));
      continue;
    }
    if (VALUE_FLAGS.has(body)) {
      const next = argv[i + 1];
      if (next === undefined || next.startsWith('--')) {
        throw new TripwireError(`Missing value for --${body}.`);
      }
      values.set(body, next);
      i += 1;
      continue;
    }
    values.set(body, true);
  }
  return { positionals, values };
}

function flagString(flags: Flags, name: string): string | undefined {
  const value = flags.values.get(name);
  return typeof value === 'string' ? value : undefined;
}

function version(): string {
  const pkgPath = path.join(__dirname, '..', '..', 'package.json');
  const pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf8')) as { version?: string };
  return pkg.version ?? '0.0.0';
}

function help(): string {
  return [
    `tripwire ${version()}`,
    'Smoke alarm for AI coding agents.',
    '',
    'Usage:',
    '  tripwire init [dir] [--seed <string>] [--dry-run]',
    '  tripwire scan [dir] [--diff <file>] [--range <git-range>] [--format text|json]',
    '                  [--fail-on <severity>] [--allow-manifest-edits]',
    '                  [--branch <name>] [--actor <login>]',
    '  tripwire rotate [dir] [--seed <string>] [--dry-run]',
    '  tripwire remove [dir] [--dry-run]',
    '  tripwire demo [--seed public] [--emit <dir>]',
    '',
    'init     Plant decoy secrets, instruction canaries, and a guard file.',
    'scan     Read a diff and fail if a canary was copied, followed, or edited.',
    'rotate   Replace canaries. Previous values stay armed as retired.',
    'remove   Delete managed canary files and strip canary blocks.',
    'demo     Build a throwaway repo, simulate a hijacked agent, and print the check.',
    '',
    'scan without --diff or --range compares the worktree to HEAD.',
    'Severities: info, low, medium, high, critical. Default fail threshold is low.',
    '',
  ].join('\n');
}

function rootFrom(flags: Flags): string {
  return path.resolve(flags.positionals[0] ?? '.');
}

function printPlant(text: string): number {
  process.stdout.write(`${text}\n`);
  return 0;
}

export function main(argv: string[]): number {
  const [command, ...rest] = argv;
  if (!command || command === 'help' || command === '--help' || command === '-h') {
    process.stdout.write(help());
    return 0;
  }
  if (command === '--version' || command === '-v') {
    process.stdout.write(`${version()}\n`);
    return 0;
  }
  const flags = parseArgs(rest);
  if (command === 'init') {
    const result = initRepo(rootFrom(flags), {
      seed: flagString(flags, 'seed'),
      dryRun: flags.values.get('dry-run') === true,
    });
    return printPlant(describePlant(result, 'Planted'));
  }
  if (command === 'rotate') {
    const result = rotateRepo(rootFrom(flags), {
      seed: flagString(flags, 'seed'),
      dryRun: flags.values.get('dry-run') === true,
    });
    return printPlant(describePlant(result, 'Rotated'));
  }
  if (command === 'remove') {
    const root = rootFrom(flags);
    const dryRun = flags.values.get('dry-run') === true;
    const { removed } = removeRepo(root, { dryRun });
    const lines = [
      dryRun ? 'Dry run. No files were written.' : `Tripwire removed canaries from ${path.resolve(root)}.`,
      ...removed.map((file) => `  ${file}`),
      'Left tripwire.config.json in place.',
    ];
    process.stdout.write(`${lines.join('\n')}\n`);
    return 0;
  }
  if (command === 'demo') {
    const result = runDemo({
      seed: flagString(flags, 'seed') ?? 'public',
      emitDir: flagString(flags, 'emit'),
    });
    process.stdout.write(result.text);
    return result.passed ? 0 : 1;
  }
  if (command === 'scan') return cmdScan(flags);
  throw new TripwireError(`Unknown command "${command}". Run \`tripwire help\`.`);
}

function cmdScan(flags: Flags): number {
  const root = rootFrom(flags);
  const manifest = readManifest(root);
  const config = readConfig(root);
  const diffFile = flagString(flags, 'diff');
  const range = flagString(flags, 'range');
  let diffText: string;
  let readFile: (rel: string) => string | null;
  let commitText = '';
  let authors: string[] = [];
  if (diffFile && range) throw new TripwireError('Pass either --diff or --range, not both.');
  if (diffFile) {
    diffText = fs.readFileSync(diffFile, 'utf8');
    readFile = (rel) => readWorktree(root, rel);
  } else if (range) {
    diffText = diffRange(root, range);
    const head = rangeHead(range);
    readFile = (rel) => gitShow(root, head, rel);
    commitText = git(root, ['log', '--format=%B%x00', range]).replace(/\0/g, '\n');
    authors = git(root, ['log', '--format=%an', range])
      .split('\n')
      .map((line) => line.trim())
      .filter((line) => line.length > 0);
  } else {
    diffText = diffWorktree(root);
    readFile = (rel) => readWorktree(root, rel);
  }
  let branch = flagString(flags, 'branch');
  if (!branch) {
    try {
      branch = git(root, ['rev-parse', '--abbrev-ref', 'HEAD']).trim();
    } catch {
      branch = undefined;
    }
  }
  const report = scan({
    manifest,
    config,
    diffText,
    readFile,
    allowManifestEdits: flags.values.get('allow-manifest-edits') === true ? true : undefined,
    failOn: flagString(flags, 'fail-on'),
    agent: {
      branch,
      actor: flagString(flags, 'actor'),
      authors,
      commitText,
    },
  });
  const format = flagString(flags, 'format') ?? 'text';
  if (format !== 'text' && format !== 'json') {
    throw new TripwireError('--format must be text or json.');
  }
  process.stdout.write(format === 'json' ? renderJson(report) : renderText(report));
  return report.result === 'fail' ? 1 : 0;
}

function rangeHead(range: string): string {
  if (range.includes('...')) return range.split('...')[1] || 'HEAD';
  if (range.includes('..')) return range.split('..')[1] || 'HEAD';
  return range;
}

if (require.main === module) {
  try {
    process.exit(main(process.argv.slice(2)));
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    process.stderr.write(`tripwire: ${message}\n`);
    process.exit(err instanceof TripwireError ? err.exitCode : 2);
  }
}
