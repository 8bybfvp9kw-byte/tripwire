"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.randomByteSource = randomByteSource;
exports.seededByteSource = seededByteSource;
exports.byteSource = byteSource;
exports.takeChars = takeChars;
const crypto_1 = require("crypto");
function randomByteSource() {
    return (n) => (0, crypto_1.randomBytes)(n);
}
function seededByteSource(seed) {
    let counter = 0;
    return (n) => {
        const out = Buffer.alloc(n);
        let offset = 0;
        while (offset < n) {
            const digest = (0, crypto_1.createHash)('sha256')
                .update('tripwire-seed-v1')
                .update(seed)
                .update(Buffer.from(String(counter)))
                .digest();
            counter += 1;
            const take = Math.min(digest.length, n - offset);
            digest.copy(out, offset, 0, take);
            offset += take;
        }
        return out;
    };
}
function byteSource(seed) {
    return seed === undefined ? randomByteSource() : seededByteSource(seed);
}
/** Unbiased sample from an alphabet. */
function takeChars(source, alphabet, length) {
    if (alphabet.length < 2 || alphabet.length > 256) {
        throw new Error('Alphabet length is out of range.');
    }
    const limit = Math.floor(256 / alphabet.length) * alphabet.length;
    let out = '';
    while (out.length < length) {
        const buf = source(Math.max(length, 16));
        for (const byte of buf) {
            if (out.length >= length)
                break;
            if (byte >= limit)
                continue;
            out += alphabet[byte % alphabet.length];
        }
    }
    return out;
}
