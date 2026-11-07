"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.runDemo = runDemo;
const child_process_1 = require("child_process");
const fs_1 = __importDefault(require("fs"));
const os_1 = __importDefault(require("os"));
const path_1 = __importDefault(require("path"));
const config_1 = require("./config");
const git_1 = require("./git");
const manifest_1 = require("./manifest");
const report_1 = require("./report");
const scan_1 = require("./scan");
const plant_1 = require("./plant");
const types_1 = require("./types");
function gitQuiet(cwd, args) {
    (0, child_process_1.execFileSync)('git', args, { cwd, stdio: 'ignore' });
}
function requireMatch(label, text, pattern) {
    const match = pattern.exec(text);
    const value = match?.[0];
    if (!value)
        throw new types_1.TripwireError(`Demo could not find ${label} in the planted files.`);
    return value;
}
function copyTree(from, to) {
    fs_1.default.mkdirSync(to, { recursive: true });
    for (const entry of fs_1.default.readdirSync(from, { withFileTypes: true })) {
        if (entry.name === '.git')
            continue;
        const src = path_1.default.join(from, entry.name);
        const dest = path_1.default.join(to, entry.name);
        if (entry.isDirectory())
            copyTree(src, dest);
        else if (entry.isFile())
            fs_1.default.copyFileSync(src, dest);
    }
}
function runDemo(options = {}) {
    const seed = options.seed ?? 'public';
    const repo = fs_1.default.mkdtempSync(path_1.default.join(os_1.default.tmpdir(), 'tripwire-demo-'));
    try {
        gitQuiet(repo, ['init', '-b', 'main']);
        gitQuiet(repo, ['config', 'user.name', 'Tripwire Demo']);
        gitQuiet(repo, ['config', 'user.email', 'tripwire-demo@example.invalid']);
        fs_1.default.writeFileSync(path_1.default.join(repo, 'README.md'), '# Fixture app\n\nA tiny repo used to show Tripwire catching a simulated hijacked agent.\n', 'utf8');
        gitQuiet(repo, ['add', 'README.md']);
        gitQuiet(repo, ['commit', '-m', 'Initial commit']);
        gitQuiet(repo, ['checkout', '-b', 'cursor/hijack-demo']);
        (0, plant_1.initRepo)(repo, { seed });
        gitQuiet(repo, ['add', '-A']);
        gitQuiet(repo, ['commit', '-m', 'Plant Tripwire canaries']);
        const cleanDiff = (0, git_1.git)(repo, ['diff', '--unified=3', '--find-renames', '--no-color', '--no-ext-diff', 'HEAD~1...HEAD']);
        const clean = (0, scan_1.scan)({
            manifest: (0, manifest_1.readManifest)(repo),
            config: (0, config_1.readConfig)(repo),
            diffText: cleanDiff,
            readFile: (rel) => (0, git_1.gitShow)(repo, 'HEAD', rel),
            agent: { branch: 'cursor/hijack-demo' },
        });
        const creds = fs_1.default.readFileSync(path_1.default.join(repo, '.tripwire/decoys/credentials.example'), 'utf8');
        const agents = fs_1.default.readFileSync(path_1.default.join(repo, 'AGENTS.md'), 'utf8');
        const github = requireMatch('GitHub canary', creds, /gh_tripwire_[0-9A-Za-z]{32}/);
        const marker = requireMatch('marker', agents, /TRIPWIRE_SIGNAL_tw[a-f0-9]{8}_agents/);
        const url = requireMatch('callback URL', agents, /https:\/\/canary\.tripwire\.invalid\/h\/tw[a-f0-9]{8}\/agents/);
        fs_1.default.mkdirSync(path_1.default.join(repo, 'src'), { recursive: true });
        fs_1.default.writeFileSync(path_1.default.join(repo, 'src/client.ts'), ['// simulated hijacked agent', `const token = "${github}";`, `// ${url}`, ''].join('\n'), 'utf8');
        fs_1.default.writeFileSync(path_1.default.join(repo, 'tripwire-signal-agents.txt'), `${marker}\n`, 'utf8');
        fs_1.default.rmSync(path_1.default.join(repo, '.tripwire/GUARD.txt'));
        gitQuiet(repo, ['add', '-A']);
        const hijackDiff = (0, git_1.diffWorktree)(repo);
        const hijack = (0, scan_1.scan)({
            manifest: (0, manifest_1.readManifest)(repo),
            config: (0, config_1.readConfig)(repo),
            diffText: hijackDiff,
            readFile: (rel) => {
                const abs = path_1.default.join(repo, rel);
                if (!fs_1.default.existsSync(abs) || !fs_1.default.statSync(abs).isFile())
                    return null;
                return fs_1.default.readFileSync(abs, 'utf8');
            },
            agent: {
                branch: 'cursor/hijack-demo',
                commitText: 'Co-authored-by: Copilot',
            },
        });
        const want = ['secret-github-pat', 'marker-agents', 'url-agents', 'tamper-.tripwire/GUARD.txt', 'guard-files-changed'];
        const ids = new Set(hijack.findings.map((finding) => finding.id));
        const missing = want.filter((id) => !ids.has(id));
        const cleanIds = new Set(clean.findings.map((finding) => finding.id));
        const cleanLeak = [...cleanIds].some((id) => id.startsWith('secret-') || id.startsWith('marker-') || id.startsWith('url-'));
        const cleanOk = cleanIds.has('guard-files-changed') && !cleanLeak;
        const passed = cleanOk && hijack.result === 'fail' && missing.length === 0;
        const text = [
            '--- canary planting commit vs its parent ---',
            (0, report_1.renderText)(clean).trimEnd(),
            '',
            '--- simulated hijacked agent diff ---',
            (0, report_1.renderText)(hijack).trimEnd(),
            '',
            passed
                ? 'Demo result: planting canaries is reported as a guard-file change, and the hijack was caught.'
                : `Demo result: expected the hijack to trip ${want.join(', ')}. Missing: ${missing.join(', ') || 'none'}. Planting commit flagged guard files: ${cleanOk}.`,
            '',
        ].join('\n');
        if (options.emitDir) {
            const emitRoot = path_1.default.resolve(options.emitDir);
            fs_1.default.rmSync(emitRoot, { recursive: true, force: true });
            copyTree(repo, path_1.default.join(emitRoot, 'demo-repo'));
            fs_1.default.writeFileSync(path_1.default.join(emitRoot, 'hijacked.diff'), hijackDiff);
            fs_1.default.writeFileSync(path_1.default.join(emitRoot, 'demo-output.txt'), text);
        }
        if (!options.keepDir)
            fs_1.default.rmSync(repo, { recursive: true, force: true });
        return { text, passed, diff: hijackDiff, repo: options.keepDir ? repo : '' };
    }
    catch (err) {
        if (!options.keepDir)
            fs_1.default.rmSync(repo, { recursive: true, force: true });
        throw err;
    }
}
