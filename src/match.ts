import { sha256Text } from './hash';
import { Canary, CanaryFormat } from './types';

const EXTRACTORS: Record<CanaryFormat, (line: string) => string[]> = {
  github_pat: (line) => line.match(/gh_tripwire_[0-9A-Za-z]{32}/g) ?? [],
  aws_access_key_id: (line) => line.match(/aws_tripwire_[A-Z0-9]{16}/g) ?? [],
  aws_secret_access_key: (line) => line.match(/aws_tripwire_secret_[0-9A-Za-z]{24}/g) ?? [],
  stripe_test_secret_key: (line) => line.match(/sk_tripwire_[0-9A-Za-z]{24}/g) ?? [],
  signal: (line) => line.match(/TRIPWIRE_SIGNAL_tw[a-f0-9]{8}_[a-z0-9]+/g) ?? [],
  callback_url: (line) => line.match(/https:\/\/canary\.tripwire\.invalid\/h\/tw[a-f0-9]{8}\/[a-z0-9]+/g) ?? [],
  guard_nonce: (line) => line.match(/TWGUARD_[a-f0-9]{32}/g) ?? [],
};

export interface LineHit {
  canary: Canary;
  value: string;
}

export function matchLine(line: string, canaries: Canary[]): LineHit[] {
  const hits: LineHit[] = [];
  for (const canary of canaries) {
    const extractor = EXTRACTORS[canary.format];
    for (const value of extractor(line)) {
      if (sha256Text(value) === canary.sha256) {
        hits.push({ canary, value });
        break;
      }
    }
  }
  return hits;
}

export function redactSecret(value: string): string {
  if (value.length <= 12) return `${value.slice(0, 4)}…`;
  return `${value.slice(0, 8)}…${value.slice(-4)}`;
}
