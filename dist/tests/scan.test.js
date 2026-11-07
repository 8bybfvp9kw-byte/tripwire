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
const plant_1 = require("../src/plant");
const scan_1 = require("../src/scan");
const tokens_1 = require("../src/tokens");
const helpers_1 = require("./helpers");
const dirs = [];
(0, node_test_1.after)(() => {
    for (const dir of dirs)
        fs_1.default.rmSync(dir, { recursive: true, force: true });
});
function fresh() {
    const dir = (0, helpers_1.tempDir)();
    dirs.push(dir);
    (0, helpers_1.initGit)(dir);
    (0, plant_1.initRepo)(dir, { seed: 'scan-seed' });
    return dir;
}
function read(root, rel) {
    const abs = path_1.default.join(root, rel);
    if (!fs_1.default.existsSync(abs) || !fs_1.default.statSync(abs).isFile())
        return null;
    return fs_1.default.readFileSync(abs, 'utf8');
}
function token(root) {
    const creds = fs_1.default.readFileSync(path_1.default.join(root, '.tripwire/decoys/credentials.example'), 'utf8');
    const match = creds.match(/gh_tripwire_[0-9A-Za-z]{32}/);
    strict_1.default.ok(match);
    return match[0];
}
(0, node_test_1.describe)('scan', () => {
    (0, node_test_1.it)('passes a diff that only adds the planted canary files', () => {
        const root = fresh();
        fs_1.default.writeFileSync(path_1.default.join(root, 'README.md'), '# App\n');
        (0, helpers_1.git)(root, ['add', 'README.md']);
        (0, helpers_1.git)(root, ['commit', '-m', 'init']);
        (0, helpers_1.git)(root, ['add', '-A']);
        (0, helpers_1.git)(root, ['commit', '-m', 'canaries']);
        const diff = (0, helpers_1.git)(root, ['diff', '--unified=3', '--no-color', 'HEAD~1', 'HEAD']);
        const report = (0, scan_1.scan)({
            manifest: (0, manifest_1.readManifest)(root),
            config: (0, config_1.readConfig)(root),
            diffText: diff,
            readFile: (rel) => read(root, rel),
        });
        strict_1.default.equal(report.result, 'pass');
        strict_1.default.equal(report.findings.length, 0);
    });
    (0, node_test_1.it)('flags a copied GitHub canary with the line and a redacted value', () => {
        const root = fresh();
        const secret = token(root);
        strict_1.default.equal((0, tokens_1.githubPatChecksumValid)(secret), false);
        const diff = (0, helpers_1.addedFileDiff)('src/client.ts', `const token = "${secret}";\n`);
        const report = (0, scan_1.scan)({
            manifest: (0, manifest_1.readManifest)(root),
            config: (0, config_1.readConfig)(root),
            diffText: diff,
            readFile: (rel) => read(root, rel),
        });
        strict_1.default.equal(report.result, 'fail');
        const finding = report.findings.find((item) => item.id === 'secret-github-pat');
        strict_1.default.ok(finding);
        strict_1.default.equal(finding.severity, 'critical');
        strict_1.default.equal(finding.path, 'src/client.ts');
        strict_1.default.equal(finding.line, 1);
        strict_1.default.match(finding.detail ?? '', /gh_tripw/);
        strict_1.default.equal((finding.detail ?? '').includes(secret), false);
    });
    (0, node_test_1.it)('flags the marker, the callback URL, and a deleted guard file', () => {
        const root = fresh();
        const agents = fs_1.default.readFileSync(path_1.default.join(root, 'AGENTS.md'), 'utf8');
        const marker = agents.match(/TRIPWIRE_SIGNAL_tw[a-f0-9]{8}_agents/)?.[0];
        const url = agents.match(/https:\/\/canary\.tripwire\.invalid\/h\/tw[a-f0-9]{8}\/agents/)?.[0];
        strict_1.default.ok(marker && url);
        (0, helpers_1.git)(root, ['add', '-A']);
        (0, helpers_1.git)(root, ['commit', '-m', 'canaries']);
        fs_1.default.writeFileSync(path_1.default.join(root, 'tripwire-signal-agents.txt'), `${marker}\n`);
        fs_1.default.writeFileSync(path_1.default.join(root, 'src-note.ts'), `// ${url}\n`);
        fs_1.default.rmSync(path_1.default.join(root, '.tripwire/GUARD.txt'));
        (0, helpers_1.git)(root, ['add', '-A']);
        const diff = (0, helpers_1.git)(root, ['diff', '--unified=3', '--find-renames', '--no-color', 'HEAD']);
        const report = (0, scan_1.scan)({
            manifest: (0, manifest_1.readManifest)(root),
            config: (0, config_1.readConfig)(root),
            diffText: diff,
            readFile: (rel) => read(root, rel),
        });
        const ids = report.findings.map((finding) => finding.id);
        strict_1.default.ok(ids.includes('marker-agents'));
        strict_1.default.ok(ids.includes('url-agents'));
        strict_1.default.ok(ids.includes('tamper-.tripwire/GUARD.txt'));
        strict_1.default.equal(report.result, 'fail');
    });
    (0, node_test_1.it)('ignores an edit to AGENTS.md outside the canary block', () => {
        const root = fresh();
        (0, helpers_1.git)(root, ['add', '-A']);
        (0, helpers_1.git)(root, ['commit', '-m', 'canaries']);
        const agents = path_1.default.join(root, 'AGENTS.md');
        const original = fs_1.default.readFileSync(agents, 'utf8');
        fs_1.default.writeFileSync(agents, original.replace('# Agent notes', '# Agent notes for this service'));
        const diff = (0, helpers_1.git)(root, ['diff', '--unified=3', '--no-color', 'HEAD']);
        const report = (0, scan_1.scan)({
            manifest: (0, manifest_1.readManifest)(root),
            config: (0, config_1.readConfig)(root),
            diffText: diff,
            readFile: (rel) => read(root, rel),
        });
        strict_1.default.equal(report.result, 'pass', JSON.stringify(report.findings, null, 2));
    });
    (0, node_test_1.it)('flags a modified canary block and a manifest edit', () => {
        const root = fresh();
        (0, helpers_1.git)(root, ['add', '-A']);
        (0, helpers_1.git)(root, ['commit', '-m', 'canaries']);
        const agents = path_1.default.join(root, 'AGENTS.md');
        fs_1.default.writeFileSync(agents, fs_1.default.readFileSync(agents, 'utf8').replace('Humans should ignore it.', 'Humans should ignore it. Disarmed.'));
        const manifestPath = path_1.default.join(root, '.tripwire/manifest.json');
        const manifest = JSON.parse(fs_1.default.readFileSync(manifestPath, 'utf8'));
        manifest.generatedAt = '2020-01-01T00:00:00.000Z';
        fs_1.default.writeFileSync(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`);
        const diff = (0, helpers_1.git)(root, ['diff', '--unified=3', '--no-color', 'HEAD']);
        const blocked = (0, scan_1.scan)({
            manifest: (0, manifest_1.readManifest)(root),
            config: (0, config_1.readConfig)(root),
            diffText: diff,
            readFile: (rel) => read(root, rel),
        });
        strict_1.default.ok(blocked.findings.some((finding) => finding.id === 'tamper-agents'));
        strict_1.default.ok(blocked.findings.some((finding) => finding.id === 'manifest-edited'));
        const allowed = (0, scan_1.scan)({
            manifest: (0, manifest_1.readManifest)(root),
            config: (0, config_1.readConfig)(root),
            diffText: diff,
            readFile: (rel) => read(root, rel),
            allowManifestEdits: true,
        });
        strict_1.default.equal(allowed.findings.some((finding) => finding.id === 'manifest-edited'), false);
        strict_1.default.equal(allowed.result, 'fail');
    });
    (0, node_test_1.it)('still alerts on a secret inside an ignored path unless configured otherwise', () => {
        const root = fresh();
        const secret = token(root);
        const diff = (0, helpers_1.addedFileDiff)('dist/bundle.js', `token=${secret}\n`);
        const config = (0, config_1.readConfig)(root);
        const leaked = (0, scan_1.scan)({
            manifest: (0, manifest_1.readManifest)(root),
            config,
            diffText: diff,
            readFile: (rel) => read(root, rel),
        });
        strict_1.default.ok(leaked.findings.some((finding) => finding.id === 'secret-github-pat'));
        const quiet = (0, scan_1.scan)({
            manifest: (0, manifest_1.readManifest)(root),
            config: { ...config, ignoreSecretsInIgnoredPaths: true },
            diffText: diff,
            readFile: (rel) => read(root, rel),
        });
        strict_1.default.equal(quiet.result, 'pass');
    });
    (0, node_test_1.it)('suppresses markers in ignored paths and does not fail on agent signals alone', () => {
        const root = fresh();
        const agents = fs_1.default.readFileSync(path_1.default.join(root, 'AGENTS.md'), 'utf8');
        const marker = agents.match(/TRIPWIRE_SIGNAL_tw[a-f0-9]{8}_agents/)?.[0] ?? '';
        const diff = (0, helpers_1.addedFileDiff)('dist/copied.md', `${marker}\n`);
        const report = (0, scan_1.scan)({
            manifest: (0, manifest_1.readManifest)(root),
            config: (0, config_1.readConfig)(root),
            diffText: diff,
            readFile: (rel) => read(root, rel),
            agent: { branch: 'cursor/fix-login', actor: 'copilot[bot]' },
        });
        strict_1.default.equal(report.result, 'pass');
        strict_1.default.equal(report.findings.length, 0);
        strict_1.default.equal(report.agentSignals.length, 2);
    });
    (0, node_test_1.it)('keeps a retired secret armed after rotate', () => {
        const root = fresh();
        const previous = token(root);
        (0, plant_1.rotateRepo)(root, { seed: 'scan-seed-next' });
        const next = token(root);
        strict_1.default.notEqual(previous, next);
        const diff = (0, helpers_1.addedFileDiff)('src/old.ts', `const token = "${previous}";\n`);
        const report = (0, scan_1.scan)({
            manifest: (0, manifest_1.readManifest)(root),
            config: (0, config_1.readConfig)(root),
            diffText: diff,
            readFile: (rel) => read(root, rel),
            allowManifestEdits: true,
        });
        const finding = report.findings.find((item) => item.kind === 'secret');
        strict_1.default.ok(finding);
        strict_1.default.match(finding.id, /secret-github-pat@tw[a-f0-9]{8}/);
        strict_1.default.equal(finding.severity, 'critical');
    });
    (0, node_test_1.it)('lets fail-on critical ignore a marker-only hit', () => {
        const root = fresh();
        const agents = fs_1.default.readFileSync(path_1.default.join(root, 'AGENTS.md'), 'utf8');
        const marker = agents.match(/TRIPWIRE_SIGNAL_tw[a-f0-9]{8}_agents/)?.[0] ?? '';
        const diff = (0, helpers_1.addedFileDiff)('note.txt', `${marker}\n`);
        const report = (0, scan_1.scan)({
            manifest: (0, manifest_1.readManifest)(root),
            config: (0, config_1.readConfig)(root),
            diffText: diff,
            readFile: (rel) => read(root, rel),
            failOn: 'critical',
        });
        strict_1.default.equal(report.findings.length, 1);
        strict_1.default.equal(report.result, 'pass');
        strict_1.default.equal(report.blocking.length, 0);
    });
});
