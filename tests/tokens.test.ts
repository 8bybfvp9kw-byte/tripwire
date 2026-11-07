import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { seededByteSource } from '../src/rng';
import {
  crc32,
  generateSecrets,
  githubEntropyChecksum,
  githubPatChecksumValid,
} from '../src/tokens';

describe('token canaries', () => {
  it('uses the IEEE CRC32 test vector', () => {
    assert.equal(crc32('123456789'), 0xcbf43926);
  });

  it('matches the public checksum vector and rejects a one-character flip', () => {
    const entropy = 'A'.repeat(30);
    assert.equal(githubEntropyChecksum(entropy), '0uCPlr');
    const prefix = 'gh' + 'p_';
    const valid = `${prefix}${entropy}${githubEntropyChecksum(entropy)}`;
    assert.equal(githubPatChecksumValid(valid), true);
    assert.equal(githubPatChecksumValid(`${valid.slice(0, -1)}s`), false);
  });

  it('plants unique decoys that are not provider key shapes', () => {
    const first = generateSecrets(seededByteSource('public'));
    const second = generateSecrets(seededByteSource('public'));
    const other = generateSecrets(seededByteSource('other-seed'));
    assert.deepEqual(first, second);
    assert.notEqual(first.githubPat, other.githubPat);
    assert.match(first.githubPat, /^gh_tripwire_[0-9A-Za-z]{32}$/);
    assert.match(first.awsAccessKeyId, /^aws_tripwire_[A-Z0-9]{16}$/);
    assert.match(first.awsSecretAccessKey, /^aws_tripwire_secret_[0-9A-Za-z]{24}$/);
    assert.match(first.stripeTestSecretKey, /^sk_tripwire_[0-9A-Za-z]{24}$/);
    const planted = [first.githubPat, first.awsAccessKeyId, first.awsSecretAccessKey, first.stripeTestSecretKey].join('\n');
    assert.equal(new RegExp(`${'sk' + '_test_'}[A-Za-z0-9]`).test(planted), false);
    assert.equal(new RegExp(`${'sk' + '_live_'}[A-Za-z0-9]`).test(planted), false);
    assert.equal(new RegExp(`${'AK' + 'IA'}[A-Z0-9]{16}`).test(planted), false);
    assert.equal(new RegExp(`${'gh' + 'p_'}[A-Za-z0-9]{36}`).test(planted), false);
    assert.match(first.namespace, /^tw[a-f0-9]{8}$/);
    assert.match(first.guardNonce, /^TWGUARD_[a-f0-9]{32}$/);
  });
});
