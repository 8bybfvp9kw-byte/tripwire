import assert from 'node:assert/strict';
import { execFileSync } from 'child_process';
import fs from 'fs';
import path from 'path';
import { after, describe, it } from 'node:test';
import { CLI, initGit, tempDir } from './helpers';

const dirs: string[] = [];
after(() => {
  for (const dir of dirs) fs.rmSync(dir, { recursive: true, force: true });
});

function run(args: string[], cwd?: string): { status: number; stdout: string; stderr: string } {
  try {
    const stdout = execFileSync(process.execPath, [CLI, ...args], { cwd, encoding: 'utf8' });
    return { status: 0, stdout, stderr: '' };
  } catch (err) {
    const error = err as { status?: number; stdout?: string | Buffer; stderr?: string | Buffer };
    return {
      status: error.status ?? 1,
      stdout: (error.stdout ?? '').toString(),
      stderr: (error.stderr ?? '').toString(),
    };
  }
}

describe('cli', () => {
  it('prints help and rejects an unknown command', () => {
    const help = run(['help']);
    assert.equal(help.status, 0);
    assert.match(help.stdout, /tripwire scan/);
    const unknown = run(['nope']);
    assert.equal(unknown.status, 2);
    assert.match(unknown.stderr, /Unknown command/);
  });

  it('scans a clean worktree as pass and a copied canary as fail', () => {
    const root = tempDir();
    dirs.push(root);
    initGit(root);
    fs.writeFileSync(path.join(root, 'README.md'), '# App\n');
    execFileSync('git', ['add', 'README.md'], { cwd: root });
    execFileSync('git', ['commit', '-m', 'init'], { cwd: root });
    const planted = run(['init', root, '--seed', 'cli']);
    assert.equal(planted.status, 0, planted.stderr);
    execFileSync('git', ['add', '-A'], { cwd: root });
    execFileSync('git', ['commit', '-m', 'canaries'], { cwd: root });
    const clean = run(['scan', root]);
    assert.equal(clean.status, 0, clean.stdout + clean.stderr);
    assert.match(clean.stdout, /Tripwire scan: PASS/);
    const creds = fs.readFileSync(path.join(root, '.tripwire/decoys/credentials.example'), 'utf8');
    const secret = creds.match(/gh_tripwire_[0-9A-Za-z]{32}/)?.[0] ?? '';
    fs.mkdirSync(path.join(root, 'src'));
    fs.writeFileSync(path.join(root, 'src/leak.ts'), `export const token = "${secret}";\n`);
    execFileSync('git', ['add', '-A'], { cwd: root });
    const leaked = run(['scan', root, '--format', 'json']);
    assert.equal(leaked.status, 1);
    const body = JSON.parse(leaked.stdout) as { result: string; findings: { id: string }[] };
    assert.equal(body.result, 'fail');
    assert.ok(body.findings.some((finding) => finding.id === 'secret-github-pat'));
    assert.equal(leaked.stdout.includes(secret), false);
  });
});
