import { escapeRegExp } from './hash';

export function compileGlob(pattern: string): RegExp {
  const raw = pattern.replace(/\\/g, '/');
  const anchored = raw.startsWith('/');
  const g = raw.replace(/^\//, '');
  let body = '';
  for (let i = 0; i < g.length; i++) {
    if (g.startsWith('**/', i)) {
      body += '(?:.*/)?';
      i += 2;
      continue;
    }
    if (g.startsWith('**', i)) {
      body += '.*';
      i += 1;
      continue;
    }
    const c = g[i] ?? '';
    if (c === '*') body += '[^/]*';
    else if (c === '?') body += '[^/]';
    else body += escapeRegExp(c);
  }
  const hasSlash = g.includes('/');
  if (!anchored && !hasSlash) return new RegExp(`^(?:.*/)?${body}$`);
  return new RegExp(`^${body}$`);
}

export function matchAnyGlob(filePath: string, patterns: string[]): boolean {
  const posix = filePath.replace(/\\/g, '/').replace(/^\.\//, '');
  return patterns.some((pattern) => compileGlob(pattern).test(posix));
}
