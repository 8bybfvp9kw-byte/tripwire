import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { matchAnyGlob } from '../src/glob';

describe('globs', () => {
  const patterns = ['node_modules/**', 'dist/**', '**/*.lock', 'package-lock.json'];

  it('matches generated paths and lockfiles at any depth', () => {
    assert.equal(matchAnyGlob('dist/index.js', patterns), true);
    assert.equal(matchAnyGlob('dist/a/b.js', patterns), true);
    assert.equal(matchAnyGlob('node_modules/leftpad/index.js', patterns), true);
    assert.equal(matchAnyGlob('yarn.lock', patterns), true);
    assert.equal(matchAnyGlob('packages/app/foo.lock', patterns), true);
    assert.equal(matchAnyGlob('package-lock.json', patterns), true);
    assert.equal(matchAnyGlob('apps/web/package-lock.json', patterns), true);
  });

  it('does not match source files', () => {
    assert.equal(matchAnyGlob('src/index.ts', patterns), false);
    assert.equal(matchAnyGlob('AGENTS.md', patterns), false);
    assert.equal(matchAnyGlob('.tripwire/decoys/credentials.example', patterns), false);
  });
});
