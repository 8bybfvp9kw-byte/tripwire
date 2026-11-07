"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const strict_1 = __importDefault(require("node:assert/strict"));
const node_test_1 = require("node:test");
const rng_1 = require("../src/rng");
const tokens_1 = require("../src/tokens");
(0, node_test_1.describe)('token canaries', () => {
    (0, node_test_1.it)('uses the IEEE CRC32 test vector', () => {
        strict_1.default.equal((0, tokens_1.crc32)('123456789'), 0xcbf43926);
    });
    (0, node_test_1.it)('matches the public checksum vector and rejects a one-character flip', () => {
        const entropy = 'A'.repeat(30);
        strict_1.default.equal((0, tokens_1.githubEntropyChecksum)(entropy), '0uCPlr');
        const prefix = 'gh' + 'p_';
        const valid = `${prefix}${entropy}${(0, tokens_1.githubEntropyChecksum)(entropy)}`;
        strict_1.default.equal((0, tokens_1.githubPatChecksumValid)(valid), true);
        strict_1.default.equal((0, tokens_1.githubPatChecksumValid)(`${valid.slice(0, -1)}s`), false);
    });
    (0, node_test_1.it)('plants unique decoys that are not provider key shapes', () => {
        const first = (0, tokens_1.generateSecrets)((0, rng_1.seededByteSource)('public'));
        const second = (0, tokens_1.generateSecrets)((0, rng_1.seededByteSource)('public'));
        const other = (0, tokens_1.generateSecrets)((0, rng_1.seededByteSource)('other-seed'));
        strict_1.default.deepEqual(first, second);
        strict_1.default.notEqual(first.githubPat, other.githubPat);
        strict_1.default.match(first.githubPat, /^gh_tripwire_[0-9A-Za-z]{32}$/);
        strict_1.default.match(first.awsAccessKeyId, /^aws_tripwire_[A-Z0-9]{16}$/);
        strict_1.default.match(first.awsSecretAccessKey, /^aws_tripwire_secret_[0-9A-Za-z]{24}$/);
        strict_1.default.match(first.stripeTestSecretKey, /^sk_tripwire_[0-9A-Za-z]{24}$/);
        const planted = [first.githubPat, first.awsAccessKeyId, first.awsSecretAccessKey, first.stripeTestSecretKey].join('\n');
        strict_1.default.equal(new RegExp(`${'sk' + '_test_'}[A-Za-z0-9]`).test(planted), false);
        strict_1.default.equal(new RegExp(`${'sk' + '_live_'}[A-Za-z0-9]`).test(planted), false);
        strict_1.default.equal(new RegExp(`${'AK' + 'IA'}[A-Z0-9]{16}`).test(planted), false);
        strict_1.default.equal(new RegExp(`${'gh' + 'p_'}[A-Za-z0-9]{36}`).test(planted), false);
        strict_1.default.match(first.namespace, /^tw[a-f0-9]{8}$/);
        strict_1.default.match(first.guardNonce, /^TWGUARD_[a-f0-9]{32}$/);
    });
});
