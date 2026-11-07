"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const strict_1 = __importDefault(require("node:assert/strict"));
const fs_1 = __importDefault(require("fs"));
const path_1 = __importDefault(require("path"));
const node_test_1 = require("node:test");
const config_1 = require("../src/config");
const manifest_1 = require("../src/manifest");
const scan_1 = require("../src/scan");
const ROOT = path_1.default.join(__dirname, '..', '..');
const FIXTURE = path_1.default.join(ROOT, 'fixtures', 'demo-repo');
(0, node_test_1.describe)('committed demo fixture', () => {
    (0, node_test_1.it)('fails the hijacked diff and keeps decoys off provider key shapes', () => {
        const creds = fs_1.default.readFileSync(path_1.default.join(FIXTURE, '.tripwire/decoys/credentials.example'), 'utf8');
        const token = creds.match(/gh_tripwire_[0-9A-Za-z]{32}/)?.[0] ?? '';
        strict_1.default.match(token, /^gh_tripwire_/);
        strict_1.default.equal(new RegExp(`${'sk' + '_test_'}[A-Za-z0-9]`).test(creds), false);
        strict_1.default.equal(new RegExp(`${'sk' + '_live_'}[A-Za-z0-9]`).test(creds), false);
        strict_1.default.equal(new RegExp(`${'AK' + 'IA'}[A-Z0-9]{16}`).test(creds), false);
        strict_1.default.equal(new RegExp(`${'gh' + 'p_'}[A-Za-z0-9]{36}`).test(creds), false);
        const diffText = fs_1.default.readFileSync(path_1.default.join(ROOT, 'fixtures', 'hijacked.diff'), 'utf8');
        const report = (0, scan_1.scan)({
            manifest: (0, manifest_1.readManifest)(FIXTURE),
            config: (0, config_1.readConfig)(FIXTURE),
            diffText,
            readFile: (rel) => {
                const abs = path_1.default.join(FIXTURE, rel);
                if (!fs_1.default.existsSync(abs) || !fs_1.default.statSync(abs).isFile())
                    return null;
                return fs_1.default.readFileSync(abs, 'utf8');
            },
            agent: { branch: 'cursor/hijack-demo' },
        });
        strict_1.default.equal(report.result, 'fail');
        const ids = report.findings.map((finding) => finding.id).sort();
        strict_1.default.deepEqual(ids, [
            'guard-files-changed',
            'marker-agents',
            'secret-github-pat',
            'tamper-.tripwire/GUARD.txt',
            'url-agents',
        ]);
    });
    (0, node_test_1.it)('includes the demo failure verbatim in the README', () => {
        const demo = fs_1.default.readFileSync(path_1.default.join(ROOT, 'fixtures', 'demo-output.txt'), 'utf8');
        const start = demo.indexOf('Tripwire scan: FAIL');
        const end = demo.indexOf('\nDemo result:');
        strict_1.default.ok(start > 0 && end > start);
        const sample = demo.slice(start, end).trimEnd();
        const readme = fs_1.default.readFileSync(path_1.default.join(ROOT, 'README.md'), 'utf8');
        strict_1.default.equal(readme.includes(sample), true);
        strict_1.default.match(readme, /^# Tripwire\n\nSmoke alarm for AI coding agents/);
        strict_1.default.match(readme, /### Is this safe\?/);
        strict_1.default.match(readme, /### Limits and false negatives/);
    });
});
