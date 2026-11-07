import { createHash, randomBytes } from 'crypto';

/** Returns the next n bytes. Seeded sources are deterministic. */
export type ByteSource = (n: number) => Buffer;

export function randomByteSource(): ByteSource {
  return (n) => randomBytes(n);
}

export function seededByteSource(seed: string): ByteSource {
  let counter = 0;
  return (n) => {
    const out = Buffer.alloc(n);
    let offset = 0;
    while (offset < n) {
      const digest = createHash('sha256')
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

export function byteSource(seed?: string): ByteSource {
  return seed === undefined ? randomByteSource() : seededByteSource(seed);
}

/** Unbiased sample from an alphabet. */
export function takeChars(source: ByteSource, alphabet: string, length: number): string {
  if (alphabet.length < 2 || alphabet.length > 256) {
    throw new Error('Alphabet length is out of range.');
  }
  const limit = Math.floor(256 / alphabet.length) * alphabet.length;
  let out = '';
  while (out.length < length) {
    const buf = source(Math.max(length, 16));
    for (const byte of buf) {
      if (out.length >= length) break;
      if (byte >= limit) continue;
      out += alphabet[byte % alphabet.length];
    }
  }
  return out;
}
