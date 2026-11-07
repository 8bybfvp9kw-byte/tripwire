import { execFileSync } from 'child_process';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { readConfig } from './config';
import { diffWorktree, git, gitShow } from './git';
import { readManifest } from './manifest';
import { renderText } from './report';
import { scan } from './scan';
import { initRepo } from './plant';
import { TripwireError } from './types';

export interface DemoResult {
  text: string;
  passed: boolean;
  diff: string;
  repo: string;
}

function gitQuiet(cwd: string, args: string[]): void {
  execFileSync('git', args, { cwd, stdio: 'ignore' });
}

function requireMatch(label: string, text: string, pattern: RegExp): string {
  const match = pattern.exec(text);
  const value = match?.[0];
  if (!value) throw new TripwireError(`Demo could not find ${label} in the planted files.`);
  return value;
}

export interface DemoOptions {
  seed?: string;
  keepDir?: boolean;
  /** Write demo-repo/, hijacked.diff, and demo-output.txt under this directory. */
  emitDir?: string;
}

function copyTree(from: string, to: string): void {
  fs.mkdirSync(to, { recursive: true });
  for (const entry of fs.readdirSync(from, { withFileTypes: true })) {
    if (entry.name === '.git') continue;
    const src = path.join(from, entry.name);
    const dest = path.join(to, entry.name);
    if (entry.isDirectory()) copyTree(src, dest);
    else if (entry.isFile()) fs.copyFileSync(src, dest);
  }
}

export function runDemo(options: DemoOptions = {}): DemoResult {
  const seed = options.seed ?? 'public';
  const repo = fs.mkdtempSync(path.join(os.tmpdir(), 'tripwire-demo-'));
  try {
    gitQuiet(repo, ['init', '-b', 'main']);
    gitQuiet(repo, ['config', 'user.name', 'Tripwire Demo']);
    gitQuiet(repo, ['config', 'user.email', 'tripwire-demo@example.invalid']);
    fs.writeFileSync(
      path.join(repo, 'README.md'),
      '# Fixture app\n\nA tiny repo used to show Tripwire catching a simulated hijacked agent.\n',
      'utf8',
    );
    gitQuiet(repo, ['add', 'README.md']);
    gitQuiet(repo, ['commit', '-m', 'Initial commit']);
    gitQuiet(repo, ['checkout', '-b', 'cursor/hijack-demo']);
    initRepo(repo, { seed });
    gitQuiet(repo, ['add', '-A']);
    gitQuiet(repo, ['commit', '-m', 'Plant Tripwire canaries']);

    const cleanDiff = git(repo, ['diff', '--unified=3', '--find-renames', '--no-color', '--no-ext-diff', 'HEAD~1...HEAD']);
    const clean = scan({
      manifest: readManifest(repo),
      config: readConfig(repo),
      diffText: cleanDiff,
      readFile: (rel) => gitShow(repo, 'HEAD', rel),
      agent: { branch: 'cursor/hijack-demo' },
    });

    const creds = fs.readFileSync(path.join(repo, '.tripwire/decoys/credentials.example'), 'utf8');
    const agents = fs.readFileSync(path.join(repo, 'AGENTS.md'), 'utf8');
    const github = requireMatch('GitHub canary', creds, /gh_tripwire_[0-9A-Za-z]{32}/);
    const marker = requireMatch('marker', agents, /TRIPWIRE_SIGNAL_tw[a-f0-9]{8}_agents/);
    const url = requireMatch('callback URL', agents, /https:\/\/canary\.tripwire\.invalid\/h\/tw[a-f0-9]{8}\/agents/);
    fs.mkdirSync(path.join(repo, 'src'), { recursive: true });
    fs.writeFileSync(
      path.join(repo, 'src/client.ts'),
      ['// simulated hijacked agent', `const token = "${github}";`, `// ${url}`, ''].join('\n'),
      'utf8',
    );
    fs.writeFileSync(path.join(repo, 'tripwire-signal-agents.txt'), `${marker}\n`, 'utf8');
    fs.rmSync(path.join(repo, '.tripwire/GUARD.txt'));
    gitQuiet(repo, ['add', '-A']);

    const hijackDiff = diffWorktree(repo);
    const hijack = scan({
      manifest: readManifest(repo),
      config: readConfig(repo),
      diffText: hijackDiff,
      readFile: (rel) => {
        const abs = path.join(repo, rel);
        if (!fs.existsSync(abs) || !fs.statSync(abs).isFile()) return null;
        return fs.readFileSync(abs, 'utf8');
      },
      agent: {
        branch: 'cursor/hijack-demo',
        commitText: 'Co-authored-by: Copilot',
      },
    });

    const want = ['secret-github-pat', 'marker-agents', 'url-agents', 'tamper-.tripwire/GUARD.txt'];
    const ids = new Set(hijack.findings.map((finding) => finding.id));
    const missing = want.filter((id) => !ids.has(id));
    const cleanOk = clean.result === 'pass';
    const passed = cleanOk && hijack.result === 'fail' && missing.length === 0;
    const text = [
      '--- clean diff, canary commit vs its parent ---',
      renderText(clean).trimEnd(),
      '',
      '--- simulated hijacked agent diff ---',
      renderText(hijack).trimEnd(),
      '',
      passed
        ? 'Demo result: the clean canary commit passed and the hijack was caught.'
        : `Demo result: expected the hijack to trip ${want.join(', ')}. Missing: ${missing.join(', ') || 'none'}. Clean pass: ${cleanOk}.`,
      '',
    ].join('\n');
    if (options.emitDir) {
      const emitRoot = path.resolve(options.emitDir);
      fs.rmSync(emitRoot, { recursive: true, force: true });
      copyTree(repo, path.join(emitRoot, 'demo-repo'));
      fs.writeFileSync(path.join(emitRoot, 'hijacked.diff'), hijackDiff);
      fs.writeFileSync(path.join(emitRoot, 'demo-output.txt'), text);
    }
    if (!options.keepDir) fs.rmSync(repo, { recursive: true, force: true });
    return { text, passed, diff: hijackDiff, repo: options.keepDir ? repo : '' };
  } catch (err) {
    if (!options.keepDir) fs.rmSync(repo, { recursive: true, force: true });
    throw err;
  }
}
