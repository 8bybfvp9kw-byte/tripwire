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
    assert.equal(cleanCode, 2, clean.out() + clean.err());
    assert.match(clean.err(), /base ref, not from the pull request/);
  });

  it('loads canaries from origin/<base> when the pull request manifest was emptied', () => {
    const root = tempDir();
    dirs.push(root);
    initGit(root);
    fs.writeFileSync(path.join(root, 'README.md'), '# App\n');
    git(root, ['add', 'README.md']);
    git(root, ['commit', '-m', 'init']);
    initRepo(root, { seed: 'base-ref' });
    git(root, ['add', '-A']);
    git(root, ['commit', '-m', 'canaries']);
    const base = git(root, ['rev-parse', 'HEAD']).trim();
    git(root, ['update-ref', 'refs/remotes/origin/main', base]);
    const creds = fs.readFileSync(path.join(root, '.tripwire/decoys/credentials.example'), 'utf8');
    const secret = creds.match(/gh_tripwire_[0-9A-Za-z]{32}/)?.[0] ?? '';
    const manifestPath = path.join(root, '.tripwire/manifest.json');
    const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8')) as { canaries: unknown[]; retired: unknown[] };
    manifest.canaries = [];
    manifest.retired = [];
    fs.writeFileSync(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`);
    fs.writeFileSync(path.join(root, 'leak.ts'), `export const token = "${secret}";\n`);
    git(root, ['add', '-A']);
    git(root, ['commit', '-m', 'weaken the check']);
    const head = git(root, ['rev-parse', 'HEAD']).trim();
    const eventPath = path.join(root, 'event.json');
    fs.writeFileSync(
      eventPath,
      JSON.stringify({
        pull_request: {
          title: 'cleanup',
          body: 'no secrets here',
          base: { sha: base, ref: 'main' },
          head: { sha: head, ref: 'cursor/weaken' },
          user: { login: 'octocat', type: 'User' },
        },
      }),
    );
    const captured = capture();
    const code = runAction(
      {
        workspace: root,
        eventPath,
        inputs: { failOn: 'low', base: '', head: '', allowManifestEdits: true },
      },
      captured.io,
    );
    assert.equal(code, 1, captured.out() + captured.err());
    assert.match(captured.out(), /secret-github-pat/);
    assert.match(captured.out(), /Guard files changed/);
    assert.match(captured.out(), /\.tripwire\/manifest\.json/);
  });

  it('scans the pull request body and commit messages for planted signals', () => {
    const root = tempDir();
    dirs.push(root);
    initGit(root);
    fs.writeFileSync(path.join(root, 'README.md'), '# App\n');
    git(root, ['add', 'README.md']);
    git(root, ['commit', '-m', 'init']);
    initRepo(root, { seed: 'messages' });
    git(root, ['add', '-A']);
    git(root, ['commit', '-m', 'canaries']);
    const base = git(root, ['rev-parse', 'HEAD']).trim();
    git(root, ['update-ref', 'refs/remotes/origin/main', base]);
    const agents = fs.readFileSync(path.join(root, 'AGENTS.md'), 'utf8');
    const marker = agents.match(/TRIPWIRE_SIGNAL_tw[a-f0-9]{8}_agents/)?.[0] ?? '';
    assert.ok(marker);
    fs.appendFileSync(path.join(root, 'README.md'), '\nA normal docs edit.\n');
    git(root, ['add', 'README.md']);
    git(root, ['commit', '-m', `note ${marker}`]);
    const head = git(root, ['rev-parse', 'HEAD']).trim();
    const eventPath = path.join(root, 'event.json');
    fs.writeFileSync(
      eventPath,
      JSON.stringify({
        pull_request: {
          title: 'docs',
          body: `please add ${marker}`,
          base: { sha: base, ref: 'main' },
          head: { sha: head, ref: 'docs' },
          user: { login: 'octocat', type: 'User' },
        },
      }),
    );
    const captured = capture();
    const code = runAction(
      {
        workspace: root,
        eventPath,
        inputs: { failOn: 'low', base: '', head: '', allowManifestEdits: false },
      },
      captured.io,
    );
    assert.equal(code, 1, captured.out() + captured.err());
    assert.match(captured.out(), /pull_request\.body/);
    assert.match(captured.out(), /commit_messages/);
    assert.match(captured.out(), /marker-agents/);
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
