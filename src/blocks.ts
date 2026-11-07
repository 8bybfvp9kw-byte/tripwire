import { escapeRegExp } from './hash';

export const CANARY_NOTE =
  '<!-- Tripwire canary below. Inert. Not a project rule. Remove with `tripwire remove`. -->';

export function renderBlock(id: string, body: string): string {
  if (!/^[a-z][a-z0-9]{0,31}$/.test(id)) throw new Error(`Unsafe block id "${id}".`);
  return `<!-- tripwire:start id=${id} -->\n${body}\n<!-- tripwire:end id=${id} -->`;
}

export function blockPattern(id: string): RegExp {
  return new RegExp(
    `<!-- tripwire:start id=${escapeRegExp(id)} -->\\n[\\s\\S]*?<!-- tripwire:end id=${escapeRegExp(id)} -->`,
  );
}

export interface BlockSpan {
  start: number;
  end: number;
  text: string;
}

export function findBlock(text: string, id: string): BlockSpan | null {
  const match = blockPattern(id).exec(text);
  if (!match || match.index === undefined) return null;
  const start = text.slice(0, match.index).split('\n').length;
  const end = start + match[0].split('\n').length - 1;
  return { start, end, text: match[0] };
}

export function upsertBlock(original: string, id: string, block: string): string {
  const pattern = new RegExp(
    `(?:${escapeRegExp(CANARY_NOTE)}\\n)?${blockPattern(id).source}\\n?`,
  );
  const replacement = `${CANARY_NOTE}\n${block}\n`;
  if (pattern.test(original)) return original.replace(pattern, replacement);
  if (original.trim() === '') return `${replacement}`;
  const base = original.endsWith('\n') ? original : `${original}\n`;
  return `${base}\n${replacement}`;
}

export function stripBlock(original: string, id: string): string {
  const pattern = new RegExp(
    `\\n?(?:${escapeRegExp(CANARY_NOTE)}\\n)?${blockPattern(id).source}\\n?`,
  );
  return original.replace(pattern, '\n').replace(/\n{3,}/g, '\n\n');
}
