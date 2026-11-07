import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { runDemo } from '../src/demo';

describe('demo', () => {
  it('flags the planting commit and catches the simulated hijack', () => {
    const result = runDemo({ seed: 'public' });
    assert.equal(result.passed, true, result.text);
    assert.match(result.text, /Guard files changed/);
    assert.match(result.text, /Tripwire scan: FAIL/);
    assert.match(result.text, /secret-github-pat/);
    assert.match(result.text, /marker-agents/);
    assert.match(result.text, /url-agents/);
    assert.match(result.text, /tamper-\.tripwire\/GUARD\.txt/);
    assert.match(result.text, /cursor\/hijack-demo/);
    assert.match(result.text, /Co-authored-by: Copilot/);
  });
});
