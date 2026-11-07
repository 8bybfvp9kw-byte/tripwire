import assert from 'node:assert/strict';
import fs from 'fs';
import path from 'path';
import { after, describe, it } from 'node:test';
import { parseConfig } from '../src/config';
import { initRepo, removeRepo, rotateRepo } from '../src/plant';
import { TripwireError } from '../src/types';
import { tempDir } from './helpers';

const dirs: string[] = [];
after(() => {
  for (const dir of dirs) fs.rmSync(dir, { recursive: true, force: true });
});

function fresh(): string {
  const dir = tempDir();
  dirs.push(dir);
  return dir;
}

describe('plant', () => {
  it('writes inert canaries and refuses to run init twice', () => {
    const root = fresh();
    const planted = initRepo(root, { seed: 'plant' });
    assert.ok(planted.wrote.includes('AGENTS.md'));
    assert.ok(planted.wrote.includes('.github/ISSUE_TEMPLATE/bug_report.md'));
    const creds = fs.readFileSync(path.join(root, '.tripwire/decoys/credentials.example'), 'utf8');
    assert.match(creds, /Synthetic values, unique to this repository/);
    const token = creds.match(/gh_tripwire_[0-9A-Za-z]{32}/)?.[0] ?? '';
    assert.match(token, /^gh_tripwire_/);
    assert.equal(new RegExp(`${'sk' + '_test_'}[A-Za-z0-9]`).test(creds), false);
    const agents = fs.readFileSync(path.join(root, 'AGENTS.md'), 'utf8');
    assert.match(agents, /canary\.tripwire\.invalid/);
    assert.match(agents, /Do not send a request/);
    assert.throws(() => initRepo(root), TripwireError);
  });

  it('does not write files on a dry run', () => {
    const root = fresh();
    const result = initRepo(root, { seed: 'dry', dryRun: true });
    assert.equal(result.dryRun, true);
    assert.equal(fs.readdirSync(root).length, 0);
  });

  it('removes managed files and keeps human edits', () => {
    const root = fresh();
    initRepo(root, { seed: 'remove' });
    fs.appendFileSync(path.join(root, 'AGENTS.md'), '\nHuman note that should stay.\n');
    const removed = removeRepo(root);
    assert.ok(removed.removed.includes('.tripwire/manifest.json'));
    assert.equal(fs.existsSync(path.join(root, '.tripwire/decoys/credentials.example')), false);
    assert.equal(fs.existsSync(path.join(root, '.tripwire/GUARD.txt')), false);
    const agents = fs.readFileSync(path.join(root, 'AGENTS.md'), 'utf8');
    assert.match(agents, /Human note that should stay/);
    assert.equal(agents.includes('tripwire:start'), false);
    assert.equal(fs.existsSync(path.join(root, 'tripwire.config.json')), true);
    assert.equal(fs.existsSync(path.join(root, 'docs/onboarding.md')), false);
  });

  it('rotates values and preserves that Tripwire created AGENTS.md', () => {
    const root = fresh();
    initRepo(root, { seed: 'rotate-a' });
    const before = fs.readFileSync(path.join(root, '.tripwire/decoys/credentials.example'), 'utf8');
    rotateRepo(root, { seed: 'rotate-b' });
    const after = fs.readFileSync(path.join(root, '.tripwire/decoys/credentials.example'), 'utf8');
    assert.notEqual(before, after);
    removeRepo(root);
    assert.equal(fs.existsSync(path.join(root, 'AGENTS.md')), false);
  });

  it('rejects a placement path that escapes the repository', () => {
    assert.throws(
      () =>
        parseConfig({
          version: 1,
          placements: [
            { path: '../secrets.txt', type: 'secrets' },
            { path: '.tripwire/GUARD.txt', type: 'guard' },
            { path: 'AGENTS.md', type: 'instruction', id: 'agents' },
          ],
        }),
      /Refusing path/,
    );
  });
});
