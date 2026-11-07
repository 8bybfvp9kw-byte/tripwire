import { ByteSource, takeChars } from './rng';

/**
 * GitHub's published token checksum: CRC32 (IEEE) of the 30-character entropy,
 * base62-encoded to 6 characters. Kept so tests can show Tripwire understands
 * that shape. Planted canaries do not use it. They use tripwire prefixes so a
 * committed decoy is not a provider key.
 */
export const BASE62 = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';

const AWS_KEY_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
const AWS_SECRET_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
const STRIPE_ALPHABET = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';

export function crc32(value: string): number {
  let crc = 0xffffffff;
  for (let i = 0; i < value.length; i++) {
    crc ^= value.charCodeAt(i);
    for (let bit = 0; bit < 8; bit++) {
      const mask = -(crc & 1);
      crc = (crc >>> 1) ^ (0xedb88320 & mask);
    }
  }
  return (crc ^ 0xffffffff) >>> 0;
}

export function encodeBase62(n: number, pad = 6): string {
  if (!Number.isInteger(n) || n < 0 || n > 0xffffffff) {
    throw new Error('Checksum is out of range.');
  }
  if (n === 0) return BASE62[0].repeat(pad);
  let x = n;
  const chars: string[] = [];
  while (x > 0) {
    chars.push(BASE62[x % 62] ?? '');
    x = Math.floor(x / 62);
  }
  return chars.reverse().join('').padStart(pad, BASE62[0]);
}

export function githubEntropyChecksum(entropy: string): string {
  return encodeBase62(crc32(entropy), 6);
}

export function githubPatChecksumValid(token: string): boolean {
  const shape = new RegExp(`^${'gh' + 'p_'}[0-9A-Za-z]{36}$`);
  if (!shape.test(token)) return false;
  const entropy = token.slice(4, 34);
  const checksum = token.slice(34);
  return checksum === githubEntropyChecksum(entropy);
}

export interface GeneratedSecrets {
  namespace: string;
  githubPat: string;
  awsAccessKeyId: string;
  awsSecretAccessKey: string;
  stripeTestSecretKey: string;
  guardNonce: string;
}

export function generateNamespace(source: ByteSource): string {
  return `tw${source(4).toString('hex')}`;
}

/** Provider prefixes, split so this source file never contains them whole. */
function providerPrefix(parts: string[]): string {
  return parts.join('');
}

function assertNotProviderSecret(value: string): void {
  const banned = [
    providerPrefix(['sk', '_test_']),
    providerPrefix(['sk', '_live_']),
    providerPrefix(['rk', '_test_']),
    providerPrefix(['rk', '_live_']),
    providerPrefix(['pk', '_test_']),
    providerPrefix(['pk', '_live_']),
  ];
  for (const prefix of banned) {
    if (value.includes(prefix)) throw new Error('Refusing to plant a provider Stripe key shape.');
  }
  const github = new RegExp(`${providerPrefix(['gh', 'p_'])}[0-9A-Za-z]{36}`);
  const aws = new RegExp(`${providerPrefix(['AK', 'IA'])}[A-Z0-9]{16}`);
  const awsTemp = new RegExp(`${providerPrefix(['AS', 'IA'])}[A-Z0-9]{16}`);
  if (github.test(value) || aws.test(value) || awsTemp.test(value)) {
    throw new Error('Refusing to plant a provider AWS or GitHub key shape.');
  }
}

export function generateSecrets(source: ByteSource, namespace?: string): GeneratedSecrets {
  const ns = namespace ?? generateNamespace(source);
  const githubPat = `gh_tripwire_${takeChars(source, BASE62, 32)}`;
  if (!/^gh_tripwire_[0-9A-Za-z]{32}$/.test(githubPat)) {
    throw new Error('GitHub canary does not match the tripwire token shape.');
  }

  const awsAccessKeyId = `aws_tripwire_${takeChars(source, AWS_KEY_ALPHABET, 16)}`;
  if (!/^aws_tripwire_[A-Z0-9]{16}$/.test(awsAccessKeyId)) {
    throw new Error('AWS access key canary does not match the tripwire shape.');
  }

  const awsSecretAccessKey = `aws_tripwire_secret_${takeChars(source, AWS_SECRET_ALPHABET, 24)}`;
  if (!/^aws_tripwire_secret_[0-9A-Za-z]{24}$/.test(awsSecretAccessKey)) {
    throw new Error('AWS secret canary does not match the tripwire shape.');
  }

  const stripeTestSecretKey = `sk_tripwire_${takeChars(source, STRIPE_ALPHABET, 24)}`;
  if (!/^sk_tripwire_[0-9A-Za-z]{24}$/.test(stripeTestSecretKey)) {
    throw new Error('Stripe canary does not match the tripwire shape.');
  }

  for (const value of [githubPat, awsAccessKeyId, awsSecretAccessKey, stripeTestSecretKey]) {
    assertNotProviderSecret(value);
  }

  const guardNonce = `TWGUARD_${source(16).toString('hex')}`;
  return {
    namespace: ns,
    githubPat,
    awsAccessKeyId,
    awsSecretAccessKey,
    stripeTestSecretKey,
    guardNonce,
  };
}

export function markerFor(namespace: string, id: string): string {
  return `TRIPWIRE_SIGNAL_${namespace}_${id}`;
}

export function callbackUrl(namespace: string, id: string): string {
  return `https://canary.tripwire.invalid/h/${namespace}/${id}`;
}
