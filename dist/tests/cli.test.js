"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const strict_1 = __importDefault(require("node:assert/strict"));
const child_process_1 = require("child_process");
const fs_1 = __importDefault(require("fs"));
const path_1 = __importDefault(require("path"));
const node_test_1 = require("node:test");
const helpers_1 = require("./helpers");
const dirs = [];
(0, node_test_1.after)(() => {
    for (const dir of dirs)
        fs_1.default.rmSync(dir, { recursive: true, force: true });
});
function run(args, cwd) {
    try {
        const stdout = (0, child_process_1.execFileSync)(process.execPath, [helpers_1.CLI, ...args], { cwd, encoding: 'utf8' });
        return { status: 0, stdout, stderr: '' };
    }
    catch (err) {
        const error = err;
        return {
            status: error.status ?? 1,
            stdout: (error.stdout ?? '').toString(),
            stderr: (error.stderr ?? '').toString(),
        };
    }
}
(0, node_test_1.describe)('cli', () => {
    (0, node_test_1.it)('prints help and rejects an unknown command', () => {
        const help = run(['help']);
        strict_1.default.equal(help.status, 0);
        strict_1.default.match(help.stdout, /tripwire scan/);
        const unknown = run(['nope']);
        strict_1.default.equal(unknown.status, 2);
        strict_1.default.match(unknown.stderr, /Unknown command/);
    });
    (0, node_test_1.it)('scans a clean worktree as pass and a copied canary as fail', () => {
        const root = (0, helpers_1.tempDir)();
        dirs.push(root);
        (0, helpers_1.initGit)(root);
        fs_1.default.writeFileSync(path_1.default.join(root, 'README.md'), '# App\n');
        (0, child_process_1.execFileSync)('git', ['add', 'README.md'], { cwd: root });
        (0, child_process_1.execFileSync)('git', ['commit', '-m', 'init'], { cwd: root });
        const planted = run(['init', root, '--seed', 'cli']);
        strict_1.default.equal(planted.status, 0, planted.stderr);
        (0, child_process_1.execFileSync)('git', ['add', '-A'], { cwd: root });
        (0, child_process_1.execFileSync)('git', ['commit', '-m', 'canaries'], { cwd: root });
        const clean = run(['scan', root]);
        strict_1.default.equal(clean.status, 0, clean.stdout + clean.stderr);
        strict_1.default.match(clean.stdout, /Tripwire scan: PASS/);
        const creds = fs_1.default.readFileSync(path_1.default.join(root, '.tripwire/decoys/credentials.example'), 'utf8');
        const secret = creds.match(/gh_tripwire_[0-9A-Za-z]{32}/)?.[0] ?? '';
        fs_1.default.mkdirSync(path_1.default.join(root, 'src'));
        fs_1.default.writeFileSync(path_1.default.join(root, 'src/leak.ts'), `export const token = "${secret}";\n`);
        (0, child_process_1.execFileSync)('git', ['add', '-A'], { cwd: root });
        const leaked = run(['scan', root, '--format', 'json']);
        strict_1.default.equal(leaked.status, 1);
        const body = JSON.parse(leaked.stdout);
        strict_1.default.equal(body.result, 'fail');
        strict_1.default.ok(body.findings.some((finding) => finding.id === 'secret-github-pat'));
        strict_1.default.equal(leaked.stdout.includes(secret), false);
    });
});
