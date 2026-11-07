"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const strict_1 = __importDefault(require("node:assert/strict"));
const node_test_1 = require("node:test");
const diff_1 = require("../src/diff");
(0, node_test_1.describe)('unified diff parser', () => {
    (0, node_test_1.it)('reads added, removed, and context line numbers', () => {
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
        const [file] = (0, diff_1.parseUnifiedDiff)(diff);
        strict_1.default.ok(file);
        strict_1.default.equal(file.status, 'modified');
        strict_1.default.equal(file.path, 'src/pay.ts');
        strict_1.default.deepEqual(file.addedLines.map((line) => [line.line, line.text]), [
            [2, 'const token = "gh_tripwire_example";'],
            [3, 'const extra = 3;'],
        ]);
        strict_1.default.deepEqual(file.deletedLines, [{ line: 2, text: 'const old = 2;' }]);
    });
    (0, node_test_1.it)('treats a new file and a deletion as such', () => {
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
        const files = (0, diff_1.parseUnifiedDiff)(diff);
        strict_1.default.equal(files[0]?.status, 'added');
        strict_1.default.equal(files[0]?.addedLines[0]?.text, 'hello');
        strict_1.default.equal(files[0]?.addedLines[0]?.line, 1);
        strict_1.default.equal(files[1]?.status, 'deleted');
        strict_1.default.equal(files[1]?.path, '.tripwire/GUARD.txt');
        strict_1.default.equal(files[1]?.deletedLines[0]?.line, 1);
    });
    (0, node_test_1.it)('keeps quoted paths and renames', () => {
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
        const files = (0, diff_1.parseUnifiedDiff)(diff);
        strict_1.default.equal(files[0]?.path, 'my file.txt');
        strict_1.default.equal(files[0]?.addedLines[0]?.text, 'new');
        strict_1.default.equal(files[1]?.status, 'renamed');
        strict_1.default.equal(files[1]?.oldPath, 'old.md');
        strict_1.default.equal(files[1]?.path, 'new.md');
    });
    (0, node_test_1.it)('marks binary diffs and ignores an empty patch', () => {
        const diff = ['diff --git a/a.bin b/a.bin', 'Binary files a/a.bin and b/a.bin differ', ''].join('\n');
        const [file] = (0, diff_1.parseUnifiedDiff)(diff);
        strict_1.default.equal(file?.binary, true);
        strict_1.default.equal(file?.path, 'a.bin');
        strict_1.default.deepEqual((0, diff_1.parseUnifiedDiff)(''), []);
        strict_1.default.deepEqual((0, diff_1.parseUnifiedDiff)('\n'), []);
    });
});
