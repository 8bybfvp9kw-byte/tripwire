"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const strict_1 = __importDefault(require("node:assert/strict"));
const fs_1 = __importDefault(require("fs"));
const path_1 = __importDefault(require("path"));
const node_test_1 = require("node:test");
const action_1 = require("../src/action");
const plant_1 = require("../src/plant");
const helpers_1 = require("./helpers");
const dirs = [];
(0, node_test_1.after)(() => {
    for (const dir of dirs)
        fs_1.default.rmSync(dir, { recursive: true, force: true });
});
function capture() {
    let stdout = '';
    let stderr = '';
    return {
        io: {
            stdout: (chunk) => {
                stdout += chunk;
            },
            stderr: (chunk) => {
                stderr += chunk;
            },
        },
        out: () => stdout,
        err: () => stderr,
    };
}
(0, node_test_1.describe)('github action', () => {
    (0, node_test_1.it)('fails a hijacked pull request and passes the canary commit', () => {
        const root = (0, helpers_1.tempDir)();
        dirs.push(root);
        (0, helpers_1.initGit)(root);
        fs_1.default.writeFileSync(path_1.default.join(root, 'README.md'), '# App\n');
        (0, helpers_1.git)(root, ['add', 'README.md']);
        (0, helpers_1.git)(root, ['commit', '-m', 'init']);
        (0, plant_1.initRepo)(root, { seed: 'action' });
        (0, helpers_1.git)(root, ['add', '-A']);
        (0, helpers_1.git)(root, ['commit', '-m', 'canaries']);
        const base = (0, helpers_1.git)(root, ['rev-parse', 'HEAD']).trim();
        const parent = (0, helpers_1.git)(root, ['rev-parse', 'HEAD~1']).trim();
        const creds = fs_1.default.readFileSync(path_1.default.join(root, '.tripwire/decoys/credentials.example'), 'utf8');
        const secret = creds.match(/gh_tripwire_[0-9A-Za-z]{32}/)?.[0] ?? '';
        fs_1.default.writeFileSync(path_1.default.join(root, 'leak.ts'), `export const token = "${secret}";\n`);
        (0, helpers_1.git)(root, ['add', '-A']);
        (0, helpers_1.git)(root, ['commit', '-m', 'hijack']);
        const head = (0, helpers_1.git)(root, ['rev-parse', 'HEAD']).trim();
        const eventPath = path_1.default.join(root, 'event.json');
        fs_1.default.writeFileSync(eventPath, JSON.stringify({
            pull_request: {
                title: 'fix login',
                body: 'routine change',
                base: { sha: base, ref: 'main' },
                head: { sha: head, ref: 'cursor/hijack-demo' },
                user: { login: 'devin-agent', type: 'Bot' },
            },
        }));
        const summary = path_1.default.join(root, 'summary.md');
        const output = path_1.default.join(root, 'output.txt');
        const hijack = capture();
        const code = (0, action_1.runAction)({
            workspace: root,
            eventPath,
            stepSummary: summary,
            outputPath: output,
            headRef: 'cursor/hijack-demo',
            inputs: { failOn: 'low', base: '', head: '', allowManifestEdits: false },
        }, hijack.io);
        strict_1.default.equal(code, 1);
        strict_1.default.match(hijack.out(), /Tripwire scan: FAIL/);
        strict_1.default.match(hijack.out(), /::error file=leak\.ts,line=1,/);
        strict_1.default.equal(hijack.out().includes(secret), false);
        strict_1.default.match(fs_1.default.readFileSync(summary, 'utf8'), /FAIL/);
        strict_1.default.match(fs_1.default.readFileSync(output, 'utf8'), /result=fail/);
        strict_1.default.match(fs_1.default.readFileSync(output, 'utf8'), /findings=1/);
        strict_1.default.match(hijack.out(), /cursor\/hijack-demo/);
        const clean = capture();
        const cleanCode = (0, action_1.runAction)({
            workspace: root,
            eventPath,
            inputs: { failOn: 'low', base: parent, head: base, allowManifestEdits: false },
        }, clean.io);
        strict_1.default.equal(cleanCode, 0, clean.out() + clean.err());
        strict_1.default.match(clean.out(), /Tripwire scan: PASS/);
    });
    (0, node_test_1.it)('exits 2 when it is not given a pull request', () => {
        const root = (0, helpers_1.tempDir)();
        dirs.push(root);
        const captured = capture();
        const code = (0, action_1.runAction)({
            workspace: root,
            inputs: { failOn: 'low', base: '', head: '', allowManifestEdits: false },
        }, captured.io);
        strict_1.default.equal(code, 2);
        strict_1.default.match(captured.err(), /fetch-depth: 0/);
    });
});
(0, node_test_1.describe)('action.yml', () => {
    (0, node_test_1.it)('is a node20 action whose entrypoint exists', () => {
        const file = fs_1.default.readFileSync(path_1.default.join(__dirname, '..', '..', 'action.yml'), 'utf8');
        strict_1.default.match(file, /^name: Tripwire/m);
        strict_1.default.match(file, /using: node20/);
        strict_1.default.match(file, /main: dist\/src\/action\.js/);
        strict_1.default.match(file, /icon: alert-triangle/);
        strict_1.default.match(file, /color: yellow/);
        strict_1.default.match(file, /author: No Hype Just Art/);
        strict_1.default.equal(fs_1.default.existsSync(path_1.default.join(__dirname, '..', 'src', 'action.js')), true);
        const actionYml = path_1.default.join(__dirname, '..', '..', 'action.yml');
        strict_1.default.equal(fs_1.default.existsSync(actionYml), true);
        const pkg = JSON.parse(fs_1.default.readFileSync(path_1.default.join(__dirname, '..', '..', 'package.json'), 'utf8'));
        strict_1.default.equal(pkg.dependencies, undefined);
    });
});
