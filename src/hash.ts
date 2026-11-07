import { createHash } from 'crypto';

export function normalizeNewlines(text: string): string {
  return text.replace(/\r\n/g, '\n');
}

export function sha256Text(text: string): string {
  return createHash('sha256').update(normalizeNewlines(text), 'utf8').digest('hex');
}

export function escapeRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}
