import assert from 'node:assert/strict';
import fs from 'fs';
import path from 'path';
import { after, describe, it } from 'node:test';
import { runAction } from '../src/action';
import { initRepo } from '../src/plant';
import { git, initGit, tempDir } from './helpers';

const dirs: string[] = [];
after(() => {
  for (const dir of dirs) fs.rmSync(dir, { recursive: true, force: true });
});

function capture(): { io: { stdout: (chunk: string) => void; stderr: (chunk: string) => void }; out: () => string; err: () => string } {
  let stdout = '';
  let stderr = '';
  return {
    io: {
      stdout: (chunk) => {
        stdout += chunk;
      },
      stderr: (chunk) => {
        stderr += chunk;
      },
    },
    out: () => stdout,
    err: () => stderr,
  };
}

describe('github action', () => {
  it('fails a hijacked pull request and passes the canary commit', () => {
    const root = tempDir();
    dirs.push(root);
    initGit(root);
    fs.writeFileSync(path.join(root, 'README.md'), '# App\n');
    git(root, ['add', 'README.md']);
    git(root, ['commit', '-m', 'init']);
    initRepo(root, { seed: 'action' });
    git(root, ['add', '-A']);
    git(root, ['commit', '-m', 'canaries']);
    const base = git(root, ['rev-parse', 'HEAD']).trim();
    const parent = git(root, ['rev-parse', 'HEAD~1']).trim();
    const creds = fs.readFileSync(path.join(root, '.tripwire/decoys/credentials.example'), 'utf8');
    const secret = creds.match(/gh_tripwire_[0-9A-Za-z]{32}/)?.[0] ?? '';
    fs.writeFileSync(path.join(root, 'leak.ts'), `export const token = "${secret}";\n`);
    git(root, ['add', '-A']);
    git(root, ['commit', '-m', 'hijack']);
    const head = git(root, ['rev-parse', 'HEAD']).trim();
    const eventPath = path.join(root, 'event.json');
    fs.writeFileSync(
      eventPath,
      JSON.stringify({
        pull_request: {
          title: 'fix login',
          body: 'routine change',
          base: { sha: base, ref: 'main' },
          head: { sha: head, ref: 'cursor/hijack-demo' },
          user: { login: 'devin-agent', type: 'Bot' },
        },
      }),
    );
    const summary = path.join(root, 'summary.md');
    const output = path.join(root, 'output.txt');
    const hijack = capture();
    const code = runAction(
      {
        workspace: root,
        eventPath,
        stepSummary: summary,
        outputPath: output,
        headRef: 'cursor/hijack-demo',
        inputs: { failOn: 'low', base: '', head: '', allowManifestEdits: false },
      },
      hijack.io,
    );
    assert.equal(code, 1);
    assert.match(hijack.out(), /Tripwire scan: FAIL/);
    assert.match(hijack.out(), /::error file=leak\.ts,line=1,/);
    assert.equal(hijack.out().includes(secret), false);
    assert.match(fs.readFileSync(summary, 'utf8'), /FAIL/);
    assert.match(fs.readFileSync(output, 'utf8'), /result=fail/);
    assert.match(fs.readFileSync(output, 'utf8'), /findings=1/);
    assert.match(hijack.out(), /cursor\/hijack-demo/);

    const clean = capture();
    const cleanCode = runAction(
      {
        workspace: root,
        eventPath,
        inputs: { failOn: 'low', base: parent, head: base, allowManifestEdits: false },
      },
      clean.io,
    );
    assert.equal(cleanCode, 0, clean.out() + clean.err());
    assert.match(clean.out(), /Tripwire scan: PASS/);
  });

  it('exits 2 when it is not given a pull request', () => {
    const root = tempDir();
    dirs.push(root);
    const captured = capture();
    const code = runAction(
      {
        workspace: root,
        inputs: { failOn: 'low', base: '', head: '', allowManifestEdits: false },
      },
      captured.io,
    );
    assert.equal(code, 2);
    assert.match(captured.err(), /fetch-depth: 0/);
  });
});

describe('action.yml', () => {
  it('is a node20 action whose entrypoint exists', () => {
    const file = fs.readFileSync(path.join(__dirname, '..', '..', 'action.yml'), 'utf8');
    assert.match(file, /^name: Tripwire/m);
    assert.match(file, /using: node20/);
    assert.match(file, /main: dist\/src\/action\.js/);
    assert.match(file, /icon: alert-triangle/);
    assert.match(file, /color: yellow/);
    assert.match(file, /author: No Hype Just Art/);
    assert.equal(fs.existsSync(path.join(__dirname, '..', 'src', 'action.js')), true);
    const actionYml = path.join(__dirname, '..', '..', 'action.yml');
    assert.equal(fs.existsSync(actionYml), true);
    const pkg = JSON.parse(fs.readFileSync(path.join(__dirname, '..', '..', 'package.json'), 'utf8')) as {
      dependencies?: Record<string, string>;
    };
    assert.equal(pkg.dependencies, undefined);
  });
});
