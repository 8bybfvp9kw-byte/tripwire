import assert from 'node:assert/strict';
import fs from 'fs';
import path from 'path';
import { after, describe, it } from 'node:test';
import { readConfig } from '../src/config';
import { readManifest } from '../src/manifest';
import { initRepo, rotateRepo } from '../src/plant';
import { scan } from '../src/scan';
import { githubPatChecksumValid } from '../src/tokens';
import { addedFileDiff, git, initGit, tempDir } from './helpers';

const dirs: string[] = [];
after(() => {
  for (const dir of dirs) fs.rmSync(dir, { recursive: true, force: true });
});

function fresh(): string {
  const dir = tempDir();
  dirs.push(dir);
  initGit(dir);
  initRepo(dir, { seed: 'scan-seed' });
  return dir;
}

function read(root: string, rel: string): string | null {
  const abs = path.join(root, rel);
  if (!fs.existsSync(abs) || !fs.statSync(abs).isFile()) return null;
  return fs.readFileSync(abs, 'utf8');
}

function token(root: string): string {
  const creds = fs.readFileSync(path.join(root, '.tripwire/decoys/credentials.example'), 'utf8');
  const match = creds.match(/gh_tripwire_[0-9A-Za-z]{32}/);
  assert.ok(match);
  return match[0];
}

describe('scan', () => {
  it('treats the commit that adds canaries as a guard-file change and not a secret leak', () => {
    const root = fresh();
    fs.writeFileSync(path.join(root, 'README.md'), '# App\n');
    git(root, ['add', 'README.md']);
    git(root, ['commit', '-m', 'init']);
    git(root, ['add', '-A']);
    git(root, ['commit', '-m', 'canaries']);
    const diff = git(root, ['diff', '--unified=3', '--no-color', 'HEAD~1', 'HEAD']);
    const report = scan({
      manifest: readManifest(root),
      config: readConfig(root),
      diffText: diff,
      readFile: (rel) => read(root, rel),
    });
    assert.equal(report.result, 'fail');
    assert.ok(report.findings.every((finding) => finding.id === 'guard-files-changed'));
    assert.ok(report.findings.some((finding) => finding.path === '.tripwire/manifest.json'));
    assert.equal(report.findings.some((finding) => finding.kind === 'secret'), false);
  });

  it('flags tripwire config and a workflow that references tripwire, not an unrelated workflow', () => {
    const root = fresh();
    const configDiff = [
      'diff --git a/tripwire.config.json b/tripwire.config.json',
      '--- a/tripwire.config.json',
      '+++ b/tripwire.config.json',
      '@@ -2,1 +2,1 @@',
      '-  "failOn": "low",',
      '+  "failOn": "critical",',
      'diff --git a/.github/workflows/ci.yml b/.github/workflows/ci.yml',
      '--- a/.github/workflows/ci.yml',
      '+++ b/.github/workflows/ci.yml',
      '@@ -1,1 +1,1 @@',
      '-name: ci',
      '+name: tests',
      'diff --git a/.github/workflows/tripwire.yml b/.github/workflows/tripwire.yml',
      '--- a/.github/workflows/tripwire.yml',
      '+++ b/.github/workflows/tripwire.yml',
      '@@ -1,1 +1,1 @@',
      '-          - uses: 8bybfvp9kw-byte/tripwire@v1',
      '+          - uses: 8bybfvp9kw-byte/tripwire@v1',
      '+            with:',
      '+              fail-on: critical',
      '',
    ].join('\n');
    const report = scan({
      manifest: readManifest(root),
      config: readConfig(root),
      diffText: configDiff,
      allowManifestEdits: true,
      readFile: (rel) => read(root, rel),
    });
    const paths = report.findings.filter((finding) => finding.id === 'guard-files-changed').map((finding) => finding.path);
    assert.ok(paths.includes('tripwire.config.json'));
    assert.ok(paths.includes('.github/workflows/tripwire.yml'));
    assert.equal(paths.includes('.github/workflows/ci.yml'), false);
    assert.equal(report.findings.every((finding) => finding.severity === 'high' || finding.severity === 'critical'), true);
    assert.match(report.findings[0]?.message ?? '', /Guard files changed/);
    assert.equal(report.result, 'fail');
  });

  it('flags a copied GitHub canary with the line and a redacted value', () => {
    const root = fresh();
    const secret = token(root);
    assert.equal(githubPatChecksumValid(secret), false);
    const diff = addedFileDiff('src/client.ts', `const token = "${secret}";\n`);
    const report = scan({
      manifest: readManifest(root),
      config: readConfig(root),
      diffText: diff,
      readFile: (rel) => read(root, rel),
    });
    assert.equal(report.result, 'fail');
    const finding = report.findings.find((item) => item.id === 'secret-github-pat');
    assert.ok(finding);
    assert.equal(finding.severity, 'critical');
    assert.equal(finding.path, 'src/client.ts');
    assert.equal(finding.line, 1);
    assert.match(finding.detail ?? '', /gh_tripw/);
    assert.equal((finding.detail ?? '').includes(secret), false);
  });

  it('flags the marker, the callback URL, and a deleted guard file', () => {
    const root = fresh();
    const agents = fs.readFileSync(path.join(root, 'AGENTS.md'), 'utf8');
    const marker = agents.match(/TRIPWIRE_SIGNAL_tw[a-f0-9]{8}_agents/)?.[0];
    const url = agents.match(/https:\/\/canary\.tripwire\.invalid\/h\/tw[a-f0-9]{8}\/agents/)?.[0];
    assert.ok(marker && url);
    git(root, ['add', '-A']);
    git(root, ['commit', '-m', 'canaries']);
    fs.writeFileSync(path.join(root, 'tripwire-signal-agents.txt'), `${marker}\n`);
    fs.writeFileSync(path.join(root, 'src-note.ts'), `// ${url}\n`);
    fs.rmSync(path.join(root, '.tripwire/GUARD.txt'));
    git(root, ['add', '-A']);
    const diff = git(root, ['diff', '--unified=3', '--find-renames', '--no-color', 'HEAD']);
    const report = scan({
      manifest: readManifest(root),
      config: readConfig(root),
      diffText: diff,
      readFile: (rel) => read(root, rel),
    });
    const ids = report.findings.map((finding) => finding.id);
    assert.ok(ids.includes('marker-agents'));
    assert.ok(ids.includes('url-agents'));
    assert.ok(ids.includes('tamper-.tripwire/GUARD.txt'));
    assert.equal(report.result, 'fail');
  });

  it('ignores an edit to AGENTS.md outside the canary block', () => {
    const root = fresh();
    git(root, ['add', '-A']);
    git(root, ['commit', '-m', 'canaries']);
    const agents = path.join(root, 'AGENTS.md');
    const original = fs.readFileSync(agents, 'utf8');
    fs.writeFileSync(agents, original.replace('# Agent notes', '# Agent notes for this service'));
    const diff = git(root, ['diff', '--unified=3', '--no-color', 'HEAD']);
    const report = scan({
      manifest: readManifest(root),
      config: readConfig(root),
      diffText: diff,
      readFile: (rel) => read(root, rel),
    });
    assert.equal(report.result, 'pass', JSON.stringify(report.findings, null, 2));
  });

  it('flags a modified canary block and a manifest edit', () => {
    const root = fresh();
    git(root, ['add', '-A']);
    git(root, ['commit', '-m', 'canaries']);
    const agents = path.join(root, 'AGENTS.md');
    fs.writeFileSync(agents, fs.readFileSync(agents, 'utf8').replace('Humans should ignore it.', 'Humans should ignore it. Disarmed.'));
    const manifestPath = path.join(root, '.tripwire/manifest.json');
    const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8')) as { generatedAt: string };
    manifest.generatedAt = '2020-01-01T00:00:00.000Z';
    fs.writeFileSync(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`);
    const diff = git(root, ['diff', '--unified=3', '--no-color', 'HEAD']);
    const blocked = scan({
      manifest: readManifest(root),
      config: readConfig(root),
      diffText: diff,
      readFile: (rel) => read(root, rel),
    });
    assert.ok(blocked.findings.some((finding) => finding.id === 'tamper-agents'));
    assert.ok(blocked.findings.some((finding) => finding.id === 'manifest-edited'));
    const allowed = scan({
      manifest: readManifest(root),
      config: readConfig(root),
      diffText: diff,
      readFile: (rel) => read(root, rel),
      allowManifestEdits: true,
    });
    assert.equal(
      allowed.findings.some((finding) => finding.id === 'manifest-edited'),
      false,
    );
    assert.equal(allowed.result, 'fail');
  });

  it('still alerts on a secret inside an ignored path unless configured otherwise', () => {
    const root = fresh();
    const secret = token(root);
    const diff = addedFileDiff('dist/bundle.js', `token=${secret}\n`);
    const config = readConfig(root);
    const leaked = scan({
      manifest: readManifest(root),
      config,
      diffText: diff,
      readFile: (rel) => read(root, rel),
    });
    assert.ok(leaked.findings.some((finding) => finding.id === 'secret-github-pat'));
    const quiet = scan({
      manifest: readManifest(root),
      config: { ...config, ignoreSecretsInIgnoredPaths: true },
      diffText: diff,
      readFile: (rel) => read(root, rel),
    });
    assert.equal(quiet.result, 'pass');
  });

  it('suppresses markers in ignored paths and does not fail on agent signals alone', () => {
    const root = fresh();
    const agents = fs.readFileSync(path.join(root, 'AGENTS.md'), 'utf8');
    const marker = agents.match(/TRIPWIRE_SIGNAL_tw[a-f0-9]{8}_agents/)?.[0] ?? '';
    const diff = addedFileDiff('dist/copied.md', `${marker}\n`);
    const report = scan({
      manifest: readManifest(root),
      config: readConfig(root),
      diffText: diff,
      readFile: (rel) => read(root, rel),
      agent: { branch: 'cursor/fix-login', actor: 'copilot[bot]' },
    });
    assert.equal(report.result, 'pass');
    assert.equal(report.findings.length, 0);
    assert.equal(report.agentSignals.length, 2);
  });

  it('keeps a retired secret armed after rotate', () => {
    const root = fresh();
    const previous = token(root);
    rotateRepo(root, { seed: 'scan-seed-next' });
    const next = token(root);
    assert.notEqual(previous, next);
    const diff = addedFileDiff('src/old.ts', `const token = "${previous}";\n`);
    const report = scan({
      manifest: readManifest(root),
      config: readConfig(root),
      diffText: diff,
      readFile: (rel) => read(root, rel),
      allowManifestEdits: true,
    });
    const finding = report.findings.find((item) => item.kind === 'secret');
    assert.ok(finding);
    assert.match(finding.id, /secret-github-pat@tw[a-f0-9]{8}/);
    assert.equal(finding.severity, 'critical');
  });

  it('lets fail-on critical ignore a marker-only hit', () => {
    const root = fresh();
    const agents = fs.readFileSync(path.join(root, 'AGENTS.md'), 'utf8');
    const marker = agents.match(/TRIPWIRE_SIGNAL_tw[a-f0-9]{8}_agents/)?.[0] ?? '';
    const diff = addedFileDiff('note.txt', `${marker}\n`);
    const report = scan({
      manifest: readManifest(root),
      config: readConfig(root),
      diffText: diff,
      readFile: (rel) => read(root, rel),
      failOn: 'critical',
    });
    assert.equal(report.findings.length, 1);
    assert.equal(report.result, 'pass');
    assert.equal(report.blocking.length, 0);
  });
});
