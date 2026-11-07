#!/usr/bin/env node
"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.parseArgs = parseArgs;
exports.main = main;
const fs_1 = __importDefault(require("fs"));
const path_1 = __importDefault(require("path"));
const config_1 = require("./config");
const demo_1 = require("./demo");
const git_1 = require("./git");
const manifest_1 = require("./manifest");
const plant_1 = require("./plant");
const report_1 = require("./report");
const scan_1 = require("./scan");
const types_1 = require("./types");
const VALUE_FLAGS = new Set([
    'diff',
    'range',
    'format',
    'fail-on',
    'seed',
    'config',
    'branch',
    'actor',
    'output',
    'emit',
]);
function parseArgs(argv) {
    const positionals = [];
    const values = new Map();
    for (let i = 0; i < argv.length; i++) {
        const arg = argv[i] ?? '';
        if (arg === '--') {
            positionals.push(...argv.slice(i + 1));
            break;
        }
        if (!arg.startsWith('--')) {
            positionals.push(arg);
            continue;
        }
        const body = arg.slice(2);
        const eq = body.indexOf('=');
        if (eq !== -1) {
            values.set(body.slice(0, eq), body.slice(eq + 1));
            continue;
        }
        if (VALUE_FLAGS.has(body)) {
            const next = argv[i + 1];
            if (next === undefined || next.startsWith('--')) {
                throw new types_1.TripwireError(`Missing value for --${body}.`);
            }
            values.set(body, next);
            i += 1;
            continue;
        }
        values.set(body, true);
    }
    return { positionals, values };
}
function flagString(flags, name) {
    const value = flags.values.get(name);
    return typeof value === 'string' ? value : undefined;
}
function version() {
    const pkgPath = path_1.default.join(__dirname, '..', '..', 'package.json');
    const pkg = JSON.parse(fs_1.default.readFileSync(pkgPath, 'utf8'));
    return pkg.version ?? '0.0.0';
}
function help() {
    return [
        `tripwire ${version()}`,
        'Smoke alarm for AI coding agents.',
        '',
        'Usage:',
        '  tripwire init [dir] [--seed <string>] [--dry-run]',
        '  tripwire scan [dir] [--diff <file>] [--range <git-range>] [--format text|json]',
        '                  [--fail-on <severity>] [--allow-manifest-edits]',
        '                  [--branch <name>] [--actor <login>]',
        '  tripwire rotate [dir] [--seed <string>] [--dry-run]',
        '  tripwire remove [dir] [--dry-run]',
        '  tripwire demo [--seed public] [--emit <dir>]',
        '',
        'init     Plant decoy secrets, instruction canaries, and a guard file.',
        'scan     Read a diff and fail if a canary was copied, followed, or edited.',
        'rotate   Replace canaries. Previous values stay armed as retired.',
        'remove   Delete managed canary files and strip canary blocks.',
        'demo     Build a throwaway repo, simulate a hijacked agent, and print the check.',
        '',
        'scan without --diff or --range compares the worktree to HEAD.',
        'Severities: info, low, medium, high, critical. Default fail threshold is low.',
        '',
    ].join('\n');
}
function rootFrom(flags) {
    return path_1.default.resolve(flags.positionals[0] ?? '.');
}
function printPlant(text) {
    process.stdout.write(`${text}\n`);
    return 0;
}
function main(argv) {
    const [command, ...rest] = argv;
    if (!command || command === 'help' || command === '--help' || command === '-h') {
        process.stdout.write(help());
        return 0;
    }
    if (command === '--version' || command === '-v') {
        process.stdout.write(`${version()}\n`);
        return 0;
    }
    const flags = parseArgs(rest);
    if (command === 'init') {
        const result = (0, plant_1.initRepo)(rootFrom(flags), {
            seed: flagString(flags, 'seed'),
            dryRun: flags.values.get('dry-run') === true,
        });
        return printPlant((0, plant_1.describePlant)(result, 'Planted'));
    }
    if (command === 'rotate') {
        const result = (0, plant_1.rotateRepo)(rootFrom(flags), {
            seed: flagString(flags, 'seed'),
            dryRun: flags.values.get('dry-run') === true,
        });
        return printPlant((0, plant_1.describePlant)(result, 'Rotated'));
    }
    if (command === 'remove') {
        const root = rootFrom(flags);
        const dryRun = flags.values.get('dry-run') === true;
        const { removed } = (0, plant_1.removeRepo)(root, { dryRun });
        const lines = [
            dryRun ? 'Dry run. No files were written.' : `Tripwire removed canaries from ${path_1.default.resolve(root)}.`,
            ...removed.map((file) => `  ${file}`),
            'Left tripwire.config.json in place.',
        ];
        process.stdout.write(`${lines.join('\n')}\n`);
        return 0;
    }
    if (command === 'demo') {
        const result = (0, demo_1.runDemo)({
            seed: flagString(flags, 'seed') ?? 'public',
            emitDir: flagString(flags, 'emit'),
        });
        process.stdout.write(result.text);
        return result.passed ? 0 : 1;
    }
    if (command === 'scan')
        return cmdScan(flags);
    throw new types_1.TripwireError(`Unknown command "${command}". Run \`tripwire help\`.`);
}
function cmdScan(flags) {
    const root = rootFrom(flags);
    const manifest = (0, manifest_1.readManifest)(root);
    const config = (0, config_1.readConfig)(root);
    const diffFile = flagString(flags, 'diff');
    const range = flagString(flags, 'range');
    let diffText;
    let readFile;
    let commitText = '';
    let authors = [];
    if (diffFile && range)
        throw new types_1.TripwireError('Pass either --diff or --range, not both.');
    if (diffFile) {
        diffText = fs_1.default.readFileSync(diffFile, 'utf8');
        readFile = (rel) => (0, git_1.readWorktree)(root, rel);
    }
    else if (range) {
        diffText = (0, git_1.diffRange)(root, range);
        const head = rangeHead(range);
        readFile = (rel) => (0, git_1.gitShow)(root, head, rel);
        commitText = (0, git_1.git)(root, ['log', '--format=%B%x00', range]).replace(/\0/g, '\n');
        authors = (0, git_1.git)(root, ['log', '--format=%an', range])
            .split('\n')
            .map((line) => line.trim())
            .filter((line) => line.length > 0);
    }
    else {
        diffText = (0, git_1.diffWorktree)(root);
        readFile = (rel) => (0, git_1.readWorktree)(root, rel);
    }
    let branch = flagString(flags, 'branch');
    if (!branch) {
        try {
            branch = (0, git_1.git)(root, ['rev-parse', '--abbrev-ref', 'HEAD']).trim();
        }
        catch {
            branch = undefined;
        }
    }
    const report = (0, scan_1.scan)({
        manifest,
        config,
        diffText,
        readFile,
        allowManifestEdits: flags.values.get('allow-manifest-edits') === true ? true : undefined,
        failOn: flagString(flags, 'fail-on'),
        agent: {
            branch,
            actor: flagString(flags, 'actor'),
            authors,
            commitText,
        },
    });
    const format = flagString(flags, 'format') ?? 'text';
    if (format !== 'text' && format !== 'json') {
        throw new types_1.TripwireError('--format must be text or json.');
    }
    process.stdout.write(format === 'json' ? (0, report_1.renderJson)(report) : (0, report_1.renderText)(report));
    return report.result === 'fail' ? 1 : 0;
}
function rangeHead(range) {
    if (range.includes('...'))
        return range.split('...')[1] || 'HEAD';
    if (range.includes('..'))
        return range.split('..')[1] || 'HEAD';
    return range;
}
if (require.main === module) {
    try {
        process.exit(main(process.argv.slice(2)));
    }
    catch (err) {
        const message = err instanceof Error ? err.message : String(err);
        process.stderr.write(`tripwire: ${message}\n`);
        process.exit(err instanceof types_1.TripwireError ? err.exitCode : 2);
    }
}
