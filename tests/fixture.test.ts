import assert from 'node:assert/strict';
import fs from 'fs';
import path from 'path';
import { describe, it } from 'node:test';
import { readConfig } from '../src/config';
import { readManifest } from '../src/manifest';
import { scan } from '../src/scan';

const ROOT = path.join(__dirname, '..', '..');
const FIXTURE = path.join(ROOT, 'fixtures', 'demo-repo');

describe('committed demo fixture', () => {
  it('fails the hijacked diff and keeps decoys off provider key shapes', () => {
    const creds = fs.readFileSync(path.join(FIXTURE, '.tripwire/decoys/credentials.example'), 'utf8');
    const token = creds.match(/gh_tripwire_[0-9A-Za-z]{32}/)?.[0] ?? '';
    assert.match(token, /^gh_tripwire_/);
    assert.equal(new RegExp(`${'sk' + '_test_'}[A-Za-z0-9]`).test(creds), false);
    assert.equal(new RegExp(`${'sk' + '_live_'}[A-Za-z0-9]`).test(creds), false);
    assert.equal(new RegExp(`${'AK' + 'IA'}[A-Z0-9]{16}`).test(creds), false);
    assert.equal(new RegExp(`${'gh' + 'p_'}[A-Za-z0-9]{36}`).test(creds), false);
    const diffText = fs.readFileSync(path.join(ROOT, 'fixtures', 'hijacked.diff'), 'utf8');
    const report = scan({
      manifest: readManifest(FIXTURE),
      config: readConfig(FIXTURE),
      diffText,
      readFile: (rel) => {
        const abs = path.join(FIXTURE, rel);
        if (!fs.existsSync(abs) || !fs.statSync(abs).isFile()) return null;
        return fs.readFileSync(abs, 'utf8');
      },
      agent: { branch: 'cursor/hijack-demo' },
    });
    assert.equal(report.result, 'fail');
    const ids = report.findings.map((finding) => finding.id).sort();
    assert.deepEqual(ids, [
      'marker-agents',
      'secret-github-pat',
      'tamper-.tripwire/GUARD.txt',
      'url-agents',
    ]);
  });

  it('includes the demo failure verbatim in the README', () => {
    const demo = fs.readFileSync(path.join(ROOT, 'fixtures', 'demo-output.txt'), 'utf8');
    const start = demo.indexOf('Tripwire scan: FAIL');
    const end = demo.indexOf('\nDemo result:');
    assert.ok(start > 0 && end > start);
    const sample = demo.slice(start, end).trimEnd();
    const readme = fs.readFileSync(path.join(ROOT, 'README.md'), 'utf8');
    assert.equal(readme.includes(sample), true);
    assert.match(readme, /^# Tripwire\n\nSmoke alarm for AI coding agents/);
    assert.match(readme, /### Is this safe\?/);
    assert.match(readme, /### Limits and false negatives/);
  });
});
