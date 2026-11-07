import { execFileSync } from 'child_process';
import fs from 'fs';
import os from 'os';
import path from 'path';

export function tempDir(): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'tripwire-test-'));
}

export function git(cwd: string, args: string[]): string {
  return execFileSync('git', args, { cwd, encoding: 'utf8', maxBuffer: 20 * 1024 * 1024 });
}

export function initGit(cwd: string): void {
  git(cwd, ['init', '-b', 'main']);
  git(cwd, ['config', 'user.name', 'Tripwire Demo']);
  git(cwd, ['config', 'user.email', 'tripwire-demo@example.invalid']);
}

export function addedFileDiff(filePath: string, content: string): string {
  const body = content.endsWith('\n') ? content.slice(0, -1) : content;
  const lines = body.split('\n');
  return [
    `diff --git a/${filePath} b/${filePath}`,
    'new file mode 100644',
    'index 0000000..1111111',
    '--- /dev/null',
    `+++ b/${filePath}`,
    `@@ -0,0 +1,${lines.length} @@`,
    ...lines.map((line) => `+${line}`),
    '',
  ].join('\n');
}

export const CLI = path.join(__dirname, '..', 'src', 'cli.js');
