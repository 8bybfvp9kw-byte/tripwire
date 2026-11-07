"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.CONFIG_FILENAME = void 0;
exports.defaultConfig = defaultConfig;
exports.parseConfig = parseConfig;
exports.placementId = placementId;
exports.configPath = configPath;
exports.readConfig = readConfig;
exports.writeConfig = writeConfig;
exports.loadOrCreateConfig = loadOrCreateConfig;
const fs_1 = __importDefault(require("fs"));
const path_1 = __importDefault(require("path"));
const paths_1 = require("./paths");
const types_1 = require("./types");
exports.CONFIG_FILENAME = 'tripwire.config.json';
const PLACEMENT_TYPES = ['secrets', 'guard', 'instruction'];
function defaultConfig() {
    return {
        version: 1,
        failOn: 'low',
        allowManifestEdits: false,
        ignore: ['node_modules/**', 'dist/**', 'build/**', 'vendor/**', '**/*.lock', 'package-lock.json'],
        ignoreSecretsInIgnoredPaths: false,
        placements: [
            { path: '.tripwire/decoys/credentials.example', type: 'secrets', id: 'secrets' },
            { path: '.tripwire/GUARD.txt', type: 'guard', id: 'guard' },
            { path: 'AGENTS.md', type: 'instruction', id: 'agents' },
            { path: 'docs/onboarding.md', type: 'instruction', id: 'onboarding' },
            { path: '.github/ISSUE_TEMPLATE/bug_report.md', type: 'instruction', id: 'issue' },
        ],
    };
}
function asBoolean(value, fallback, label) {
    if (value === undefined)
        return fallback;
    if (typeof value !== 'boolean')
        throw new types_1.TripwireError(`${label} must be true or false.`);
    return value;
}
function parsePlacement(value, index) {
    if (value === null || typeof value !== 'object') {
        throw new types_1.TripwireError(`placements[${index}] must be an object.`);
    }
    const raw = value;
    if (typeof raw.path !== 'string' || raw.path.trim() === '') {
        throw new types_1.TripwireError(`placements[${index}].path is required.`);
    }
    if (typeof raw.type !== 'string' || !PLACEMENT_TYPES.includes(raw.type)) {
        throw new types_1.TripwireError(`placements[${index}].type must be one of: ${PLACEMENT_TYPES.join(', ')}.`);
    }
    const placement = {
        path: (0, paths_1.assertSafeRelPath)(raw.path),
        type: raw.type,
    };
    if (raw.id !== undefined) {
        if (typeof raw.id !== 'string' || !/^[a-z][a-z0-9]{0,31}$/.test(raw.id)) {
            throw new types_1.TripwireError(`placements[${index}].id must match /^[a-z][a-z0-9]{0,31}$/ so it can be embedded safely.`);
        }
        placement.id = raw.id;
    }
    return placement;
}
function parseConfig(value) {
    if (value === null || typeof value !== 'object')
        throw new types_1.TripwireError('Config must be a JSON object.');
    const raw = value;
    if (raw.version !== 1)
        throw new types_1.TripwireError('tripwire.config.json version must be 1.');
    const defaults = defaultConfig();
    const failOn = raw.failOn === undefined ? defaults.failOn : (0, types_1.parseSeverity)(String(raw.failOn));
    let ignore = defaults.ignore;
    if (raw.ignore !== undefined) {
        if (!Array.isArray(raw.ignore) || raw.ignore.some((item) => typeof item !== 'string')) {
            throw new types_1.TripwireError('ignore must be an array of glob strings.');
        }
        ignore = raw.ignore;
    }
    let placements = defaults.placements;
    if (raw.placements !== undefined) {
        if (!Array.isArray(raw.placements) || raw.placements.length === 0) {
            throw new types_1.TripwireError('placements must be a non-empty array.');
        }
        placements = raw.placements.map((item, index) => parsePlacement(item, index));
    }
    const secrets = placements.filter((item) => item.type === 'secrets');
    const guards = placements.filter((item) => item.type === 'guard');
    if (secrets.length !== 1)
        throw new types_1.TripwireError('Config needs exactly one placements entry of type "secrets".');
    if (guards.length !== 1)
        throw new types_1.TripwireError('Config needs exactly one placements entry of type "guard".');
    if (!placements.some((item) => item.type === 'instruction')) {
        throw new types_1.TripwireError('Config needs at least one placements entry of type "instruction".');
    }
    const ids = new Set();
    for (const placement of placements) {
        const id = placementId(placement);
        if (ids.has(id))
            throw new types_1.TripwireError(`Duplicate placement id "${id}".`);
        ids.add(id);
    }
    return {
        version: 1,
        failOn,
        allowManifestEdits: asBoolean(raw.allowManifestEdits, defaults.allowManifestEdits, 'allowManifestEdits'),
        ignore,
        ignoreSecretsInIgnoredPaths: asBoolean(raw.ignoreSecretsInIgnoredPaths, defaults.ignoreSecretsInIgnoredPaths, 'ignoreSecretsInIgnoredPaths'),
        placements,
    };
}
function placementId(placement) {
    if (placement.id)
        return placement.id;
    if (placement.type === 'secrets')
        return 'secrets';
    if (placement.type === 'guard')
        return 'guard';
    const slug = placement.path
        .toLowerCase()
        .replace(/[^a-z0-9]+/g, '')
        .slice(0, 32);
    if (!/^[a-z][a-z0-9]{0,31}$/.test(slug)) {
        throw new types_1.TripwireError(`Cannot derive a safe id from path "${placement.path}". Set an explicit id.`);
    }
    return slug;
}
function configPath(root) {
    return path_1.default.join(root, exports.CONFIG_FILENAME);
}
function readConfig(root) {
    const file = configPath(root);
    if (!fs_1.default.existsSync(file))
        return defaultConfig();
    let parsed;
    try {
        parsed = JSON.parse(fs_1.default.readFileSync(file, 'utf8'));
    }
    catch (err) {
        const message = err instanceof Error ? err.message : String(err);
        throw new types_1.TripwireError(`Could not parse ${exports.CONFIG_FILENAME}: ${message}`);
    }
    return parseConfig(parsed);
}
function writeConfig(root, config) {
    const file = configPath(root);
    fs_1.default.writeFileSync(file, `${JSON.stringify(config, null, 2)}\n`, 'utf8');
}
function loadOrCreateConfig(root) {
    const file = configPath(root);
    if (!fs_1.default.existsSync(file)) {
        const config = defaultConfig();
        writeConfig(root, config);
        return { config, created: true };
    }
    return { config: readConfig(root), created: false };
}
