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
const plant_1 = require("../src/plant");
const types_1 = require("../src/types");
const helpers_1 = require("./helpers");
const dirs = [];
(0, node_test_1.after)(() => {
    for (const dir of dirs)
        fs_1.default.rmSync(dir, { recursive: true, force: true });
});
function fresh() {
    const dir = (0, helpers_1.tempDir)();
    dirs.push(dir);
    return dir;
}
(0, node_test_1.describe)('plant', () => {
    (0, node_test_1.it)('writes inert canaries and refuses to run init twice', () => {
        const root = fresh();
        const planted = (0, plant_1.initRepo)(root, { seed: 'plant' });
        strict_1.default.ok(planted.wrote.includes('AGENTS.md'));
        strict_1.default.ok(planted.wrote.includes('.github/ISSUE_TEMPLATE/bug_report.md'));
        const creds = fs_1.default.readFileSync(path_1.default.join(root, '.tripwire/decoys/credentials.example'), 'utf8');
        strict_1.default.match(creds, /Synthetic values, unique to this repository/);
        const token = creds.match(/gh_tripwire_[0-9A-Za-z]{32}/)?.[0] ?? '';
        strict_1.default.match(token, /^gh_tripwire_/);
        strict_1.default.equal(new RegExp(`${'sk' + '_test_'}[A-Za-z0-9]`).test(creds), false);
        const agents = fs_1.default.readFileSync(path_1.default.join(root, 'AGENTS.md'), 'utf8');
        strict_1.default.match(agents, /canary\.tripwire\.invalid/);
        strict_1.default.match(agents, /Do not send a request/);
        strict_1.default.throws(() => (0, plant_1.initRepo)(root), types_1.TripwireError);
    });
    (0, node_test_1.it)('does not write files on a dry run', () => {
        const root = fresh();
        const result = (0, plant_1.initRepo)(root, { seed: 'dry', dryRun: true });
        strict_1.default.equal(result.dryRun, true);
        strict_1.default.equal(fs_1.default.readdirSync(root).length, 0);
    });
    (0, node_test_1.it)('removes managed files and keeps human edits', () => {
        const root = fresh();
        (0, plant_1.initRepo)(root, { seed: 'remove' });
        fs_1.default.appendFileSync(path_1.default.join(root, 'AGENTS.md'), '\nHuman note that should stay.\n');
        const removed = (0, plant_1.removeRepo)(root);
        strict_1.default.ok(removed.removed.includes('.tripwire/manifest.json'));
        strict_1.default.equal(fs_1.default.existsSync(path_1.default.join(root, '.tripwire/decoys/credentials.example')), false);
        strict_1.default.equal(fs_1.default.existsSync(path_1.default.join(root, '.tripwire/GUARD.txt')), false);
        const agents = fs_1.default.readFileSync(path_1.default.join(root, 'AGENTS.md'), 'utf8');
        strict_1.default.match(agents, /Human note that should stay/);
        strict_1.default.equal(agents.includes('tripwire:start'), false);
        strict_1.default.equal(fs_1.default.existsSync(path_1.default.join(root, 'tripwire.config.json')), true);
        strict_1.default.equal(fs_1.default.existsSync(path_1.default.join(root, 'docs/onboarding.md')), false);
    });
    (0, node_test_1.it)('rotates values and preserves that Tripwire created AGENTS.md', () => {
        const root = fresh();
        (0, plant_1.initRepo)(root, { seed: 'rotate-a' });
        const before = fs_1.default.readFileSync(path_1.default.join(root, '.tripwire/decoys/credentials.example'), 'utf8');
        (0, plant_1.rotateRepo)(root, { seed: 'rotate-b' });
        const after = fs_1.default.readFileSync(path_1.default.join(root, '.tripwire/decoys/credentials.example'), 'utf8');
        strict_1.default.notEqual(before, after);
        (0, plant_1.removeRepo)(root);
        strict_1.default.equal(fs_1.default.existsSync(path_1.default.join(root, 'AGENTS.md')), false);
    });
    (0, node_test_1.it)('rejects a placement path that escapes the repository', () => {
        strict_1.default.throws(() => (0, config_1.parseConfig)({
            version: 1,
            placements: [
                { path: '../secrets.txt', type: 'secrets' },
                { path: '.tripwire/GUARD.txt', type: 'guard' },
                { path: 'AGENTS.md', type: 'instruction', id: 'agents' },
            ],
        }), /Refusing path/);
    });
});
