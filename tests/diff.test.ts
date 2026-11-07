import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { parseUnifiedDiff } from '../src/diff';

describe('unified diff parser', () => {
  it('reads added, removed, and context line numbers', () => {
    const diff = [
      'diff --git a/src/pay.ts b/src/pay.ts',
      'index 1111111..2222222 100644',
      '--- a/src/pay.ts',
      '+++ b/src/pay.ts',
      '@@ -1,4 +1,5 @@',
      ' const a = 1;',
      '-const old = 2;',
      '+const token = "gh_tripwire_example";',
      '+const extra = 3;',
      ' const tail = 4;',
      '',
    ].join('\n');
    const [file] = parseUnifiedDiff(diff);
    assert.ok(file);
    assert.equal(file.status, 'modified');
    assert.equal(file.path, 'src/pay.ts');
    assert.deepEqual(
      file.addedLines.map((line) => [line.line, line.text]),
      [
        [2, 'const token = "gh_tripwire_example";'],
        [3, 'const extra = 3;'],
      ],
    );
    assert.deepEqual(file.deletedLines, [{ line: 2, text: 'const old = 2;' }]);
  });

  it('treats a new file and a deletion as such', () => {
    const diff = [
      'diff --git a/new.txt b/new.txt',
      'new file mode 100644',
      '--- /dev/null',
      '+++ b/new.txt',
      '@@ -0,0 +1 @@',
      '+hello',
      'diff --git a/.tripwire/GUARD.txt b/.tripwire/GUARD.txt',
      'deleted file mode 100644',
      '--- a/.tripwire/GUARD.txt',
      '+++ /dev/null',
      '@@ -1 +0,0 @@',
      '-Tripwire guard file.',
      '',
    ].join('\n');
    const files = parseUnifiedDiff(diff);
    assert.equal(files[0]?.status, 'added');
    assert.equal(files[0]?.addedLines[0]?.text, 'hello');
    assert.equal(files[0]?.addedLines[0]?.line, 1);
    assert.equal(files[1]?.status, 'deleted');
    assert.equal(files[1]?.path, '.tripwire/GUARD.txt');
    assert.equal(files[1]?.deletedLines[0]?.line, 1);
  });

  it('keeps quoted paths and renames', () => {
    const diff = [
      'diff --git "a/my file.txt" "b/my file.txt"',
      '--- "a/my file.txt"',
      '+++ "b/my file.txt"',
      '@@ -1 +1 @@',
      '-old',
      '+new',
      'diff --git a/old.md b/new.md',
      'similarity index 90%',
      'rename from old.md',
      'rename to new.md',
      '--- a/old.md',
      '+++ b/new.md',
      '@@ -1 +1 @@',
      '-a',
      '+b',
      '',
    ].join('\n');
    const files = parseUnifiedDiff(diff);
    assert.equal(files[0]?.path, 'my file.txt');
    assert.equal(files[0]?.addedLines[0]?.text, 'new');
    assert.equal(files[1]?.status, 'renamed');
    assert.equal(files[1]?.oldPath, 'old.md');
    assert.equal(files[1]?.path, 'new.md');
  });

  it('marks binary diffs and ignores an empty patch', () => {
    const diff = ['diff --git a/a.bin b/a.bin', 'Binary files a/a.bin and b/a.bin differ', ''].join('\n');
    const [file] = parseUnifiedDiff(diff);
    assert.equal(file?.binary, true);
    assert.equal(file?.path, 'a.bin');
    assert.deepEqual(parseUnifiedDiff(''), []);
    assert.deepEqual(parseUnifiedDiff('\n'), []);
  });
});
