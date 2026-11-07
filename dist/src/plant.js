"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.plant = plant;
exports.initRepo = initRepo;
exports.rotateRepo = rotateRepo;
exports.removeRepo = removeRepo;
exports.describePlant = describePlant;
const fs_1 = __importDefault(require("fs"));
const path_1 = __importDefault(require("path"));
const blocks_1 = require("./blocks");
const config_1 = require("./config");
const hash_1 = require("./hash");
const manifest_1 = require("./manifest");
const paths_1 = require("./paths");
const rng_1 = require("./rng");
const templates_1 = require("./templates");
const tokens_1 = require("./tokens");
const types_1 = require("./types");
const FIXED_SEED_TIME = '2026-01-01T00:00:00.000Z';
const RETIRED_CAP = 100;
function readText(file) {
    if (!fs_1.default.existsSync(file))
        return null;
    return fs_1.default.readFileSync(file, 'utf8').replace(/\r\n/g, '\n');
}
function writeText(root, rel, content) {
    const abs = (0, paths_1.resolveInside)(root, rel);
    fs_1.default.mkdirSync(path_1.default.dirname(abs), { recursive: true });
    fs_1.default.writeFileSync(abs, content.endsWith('\n') ? content : `${content}\n`, 'utf8');
}
function ownedHeader(content) {
    return content.startsWith('# Tripwire decoy credentials\n') || content.startsWith('Tripwire guard file.\n');
}
function planInstruction(placement, namespace, existing, createdFile) {
    const id = (0, config_1.placementId)(placement);
    const marker = (0, tokens_1.markerFor)(namespace, id);
    const url = (0, tokens_1.callbackUrl)(namespace, id);
    const block = (0, blocks_1.renderBlock)(id, (0, templates_1.instructionBody)(marker, url, id));
    const base = existing ?? templates_1.PREFACES[placement.path] ?? '';
    const content = (0, blocks_1.upsertBlock)(base, id, block);
    const span = (0, blocks_1.findBlock)(content, id);
    if (!span)
        throw new types_1.TripwireError(`Failed to embed the canary block in ${placement.path}.`);
    const canaries = [
        {
            id: `marker-${id}`,
            kind: 'marker',
            format: 'signal',
            sha256: (0, hash_1.sha256Text)(marker),
            plantedPaths: [placement.path],
            blockId: id,
            severity: 'high',
            description: `Hidden instruction in ${placement.path} tells an agent to add this marker.`,
        },
        {
            id: `url-${id}`,
            kind: 'url',
            format: 'callback_url',
            sha256: (0, hash_1.sha256Text)(url),
            plantedPaths: [placement.path],
            blockId: id,
            severity: 'high',
            description: `Hidden instruction in ${placement.path} tells an agent to add this callback URL.`,
        },
    ];
    return {
        path: placement.path,
        content,
        planted: {
            path: placement.path,
            type: 'block',
            blockId: id,
            sha256: (0, hash_1.sha256Text)(span.text),
            createdFile,
        },
        canaries,
    };
}
function planSecrets(placement, secrets) {
    const content = (0, templates_1.credentialsFile)(secrets);
    const canaries = [
        {
            id: 'secret-github-pat',
            kind: 'secret',
            format: 'github_pat',
            sha256: (0, hash_1.sha256Text)(secrets.githubPat),
            plantedPaths: [placement.path],
            severity: 'critical',
            description: 'Synthetic GitHub-shaped canary (gh_tripwire_ prefix, not a GitHub credential).',
        },
        {
            id: 'secret-aws-access-key-id',
            kind: 'secret',
            format: 'aws_access_key_id',
            sha256: (0, hash_1.sha256Text)(secrets.awsAccessKeyId),
            plantedPaths: [placement.path],
            severity: 'critical',
            description: 'Synthetic AWS access-key canary (aws_tripwire_ prefix, not an AWS access key id).',
        },
        {
            id: 'secret-aws-secret',
            kind: 'secret',
            format: 'aws_secret_access_key',
            sha256: (0, hash_1.sha256Text)(secrets.awsSecretAccessKey),
            plantedPaths: [placement.path],
            severity: 'critical',
            description: 'Synthetic AWS secret canary (aws_tripwire_secret_ prefix, not an AWS secret).',
        },
        {
            id: 'secret-stripe-test',
            kind: 'secret',
            format: 'stripe_test_secret_key',
            sha256: (0, hash_1.sha256Text)(secrets.stripeTestSecretKey),
            plantedPaths: [placement.path],
            severity: 'critical',
            description: 'Synthetic Stripe-shaped canary (sk_tripwire_ prefix, not a Stripe API key).',
        },
    ];
    return {
        path: placement.path,
        content,
        planted: {
            path: placement.path,
            type: 'file',
            sha256: (0, hash_1.sha256Text)(content),
            createdFile: true,
        },
        canaries,
    };
}
function planGuard(placement, secrets) {
    const content = (0, templates_1.guardFile)(secrets.namespace, secrets.guardNonce);
    return {
        path: placement.path,
        content,
        planted: {
            path: placement.path,
            type: 'file',
            sha256: (0, hash_1.sha256Text)(content),
            createdFile: true,
        },
        canaries: [
            {
                id: 'guard-nonce',
                kind: 'marker',
                format: 'guard_nonce',
                sha256: (0, hash_1.sha256Text)(secrets.guardNonce),
                plantedPaths: [placement.path],
                severity: 'high',
                description: 'Guard-file nonce.',
            },
        ],
    };
}
function retire(canaries, stamp) {
    return canaries.map((canary) => ({
        id: `${canary.id}@${stamp}`,
        kind: canary.kind,
        format: canary.format,
        sha256: canary.sha256,
        plantedPaths: [],
        severity: canary.severity,
        description: `Retired canary ${canary.id}. It is no longer planted and still counts if it shows up.`,
    }));
}
function assertCanOverwrite(root, rel, nextIsManaged) {
    if (!nextIsManaged)
        return;
    const existing = readText((0, paths_1.resolveInside)(root, rel));
    if (existing === null)
        return;
    if (ownedHeader(existing))
        return;
    throw new types_1.TripwireError(`${rel} already exists and is not a Tripwire file. Move it, or run \`tripwire remove\` if it is from an older plant.`);
}
function plant(root, options) {
    const absRoot = path_1.default.resolve(root);
    if (!fs_1.default.existsSync(absRoot) || !fs_1.default.statSync(absRoot).isDirectory()) {
        throw new types_1.TripwireError(`Not a directory: ${absRoot}`);
    }
    const previous = options.rotate ? (0, manifest_1.readManifest)(absRoot) : null;
    if (!options.rotate && fs_1.default.existsSync(path_1.default.join(absRoot, manifest_1.MANIFEST_PATH))) {
        throw new types_1.TripwireError(`Already initialized (${manifest_1.MANIFEST_PATH}). Run \`tripwire rotate\` to replace canaries, or \`tripwire remove\` first.`);
    }
    const configFile = path_1.default.join(absRoot, 'tripwire.config.json');
    const configExisted = fs_1.default.existsSync(configFile);
    const config = configExisted ? (0, config_1.readConfig)(absRoot) : (0, config_1.defaultConfig)();
    const source = (0, rng_1.byteSource)(options.seed);
    const secrets = (0, tokens_1.generateSecrets)(source);
    const planned = [];
    for (const placement of config.placements) {
        if (placement.type === 'secrets') {
            assertCanOverwrite(absRoot, placement.path, true);
            planned.push(planSecrets(placement, secrets));
        }
        else if (placement.type === 'guard') {
            assertCanOverwrite(absRoot, placement.path, true);
            planned.push(planGuard(placement, secrets));
        }
        else {
            const existing = readText((0, paths_1.resolveInside)(absRoot, placement.path));
            const prior = previous?.files.find((file) => file.path === placement.path);
            const createdFile = existing === null ? true : prior?.createdFile === true;
            planned.push(planInstruction(placement, secrets.namespace, existing, createdFile));
        }
    }
    const newPaths = new Set(planned.map((item) => item.path));
    const removed = [];
    if (previous) {
        for (const file of previous.files) {
            if (newPaths.has(file.path))
                continue;
            removed.push(...cleanupPlanted(absRoot, file, options.dryRun === true));
        }
    }
    const retired = [
        ...(previous ? retire(previous.canaries, previous.namespace) : []),
        ...(previous?.retired ?? []),
    ].slice(0, RETIRED_CAP);
    const manifest = {
        version: 1,
        namespace: secrets.namespace,
        generatedAt: options.seed === undefined ? new Date().toISOString() : FIXED_SEED_TIME,
        canaries: planned.flatMap((item) => item.canaries),
        retired,
        files: planned.map((item) => item.planted),
    };
    const wrote = [manifest_1.MANIFEST_PATH, ...planned.map((item) => item.path)];
    if (!options.rotate && !configExisted)
        wrote.push('tripwire.config.json');
    if (!options.dryRun) {
        if (!options.rotate && !configExisted)
            (0, config_1.writeConfig)(absRoot, config);
        for (const item of planned)
            writeText(absRoot, item.path, item.content);
        // Re-hash from disk so the manifest matches the bytes the scanner will read.
        manifest.files = planned.map((item) => rehash(absRoot, item.planted));
        manifest.canaries = planned.flatMap((item) => item.canaries);
        (0, manifest_1.writeManifest)(absRoot, manifest);
    }
    return { root: absRoot, manifest, wrote: unique(wrote), removed, dryRun: options.dryRun === true };
}
function rehash(root, planted) {
    const text = readText((0, paths_1.resolveInside)(root, planted.path));
    if (text === null)
        throw new types_1.TripwireError(`Planted file disappeared: ${planted.path}`);
    if (planted.type === 'file')
        return { ...planted, sha256: (0, hash_1.sha256Text)(text) };
    const blockId = planted.blockId;
    if (!blockId)
        throw new types_1.TripwireError(`Block file ${planted.path} has no block id.`);
    const span = (0, blocks_1.findBlock)(text, blockId);
    if (!span)
        throw new types_1.TripwireError(`Canary block ${blockId} is missing from ${planted.path} after write.`);
    return { ...planted, sha256: (0, hash_1.sha256Text)(span.text) };
}
function unique(values) {
    return [...new Set(values)];
}
function cleanupPlanted(root, file, dryRun) {
    const abs = (0, paths_1.resolveInside)(root, file.path);
    const existing = readText(abs);
    if (existing === null)
        return [];
    if (file.type === 'file') {
        if (!ownedHeader(existing))
            return [];
        if (!dryRun) {
            fs_1.default.rmSync(abs);
            pruneEmptyParents(root, path_1.default.dirname(abs));
        }
        return [file.path];
    }
    if (!file.blockId)
        return [];
    const stripped = (0, blocks_1.stripBlock)(existing, file.blockId).replace(/^\n+/, '').replace(/\n+$/, '\n');
    const preface = templates_1.PREFACES[file.path];
    const onlyPreface = file.createdFile &&
        (stripped.trim() === '' || (preface !== undefined && stripped.trim() === preface.trim()));
    if (!dryRun) {
        if (onlyPreface) {
            fs_1.default.rmSync(abs);
            pruneEmptyParents(root, path_1.default.dirname(abs));
        }
        else if (stripped.trim() === '') {
            fs_1.default.rmSync(abs);
            pruneEmptyParents(root, path_1.default.dirname(abs));
        }
        else {
            fs_1.default.writeFileSync(abs, stripped.endsWith('\n') ? stripped : `${stripped}\n`, 'utf8');
        }
    }
    return onlyPreface || stripped.trim() === '' ? [file.path] : [];
}
function pruneEmptyParents(root, dir) {
    const absRoot = path_1.default.resolve(root);
    let current = dir;
    while (current.startsWith(absRoot) && current !== absRoot) {
        if (!fs_1.default.existsSync(current))
            break;
        const entries = fs_1.default.readdirSync(current);
        if (entries.length > 0)
            break;
        fs_1.default.rmdirSync(current);
        current = path_1.default.dirname(current);
    }
}
function initRepo(root, options = {}) {
    return plant(root, { ...options, rotate: false });
}
function rotateRepo(root, options = {}) {
    return plant(root, { ...options, rotate: true });
}
function removeRepo(root, options = {}) {
    const absRoot = path_1.default.resolve(root);
    const manifest = (0, manifest_1.readManifest)(absRoot);
    const removed = [];
    for (const file of manifest.files) {
        removed.push(...cleanupPlanted(absRoot, file, options.dryRun === true));
    }
    const manifestAbs = path_1.default.join(absRoot, manifest_1.MANIFEST_PATH);
    if (fs_1.default.existsSync(manifestAbs)) {
        if (!options.dryRun) {
            fs_1.default.rmSync(manifestAbs);
            pruneEmptyParents(absRoot, path_1.default.dirname(manifestAbs));
        }
        removed.push(manifest_1.MANIFEST_PATH);
    }
    return { removed };
}
function describePlant(result, verb) {
    const lines = [
        `Tripwire ${verb.toLowerCase()} canaries in ${result.root}.`,
        ...result.wrote.map((file) => `  ${file}`),
    ];
    if (result.removed.length > 0) {
        lines.push('Removed:');
        lines.push(...result.removed.map((file) => `  ${file}`));
    }
    if (verb === 'Rotated') {
        lines.push('Previous values stay in the manifest as retired and still fail the check if they show up.', 'The manifest change itself fails the check until a maintainer bypasses it or sets allow-manifest-edits.');
    }
    else if (!result.dryRun) {
        lines.push('Commit these files. Canaries are inert. Remove them with `tripwire remove`.');
    }
    if (result.dryRun)
        lines.unshift('Dry run. No files were written.');
    return lines.join('\n');
}
