"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.MANIFEST_PATH = void 0;
exports.manifestFile = manifestFile;
exports.parseManifest = parseManifest;
exports.parseManifestText = parseManifestText;
exports.readManifest = readManifest;
exports.writeManifest = writeManifest;
const fs_1 = __importDefault(require("fs"));
const path_1 = __importDefault(require("path"));
const types_1 = require("./types");
exports.MANIFEST_PATH = '.tripwire/manifest.json';
function manifestFile(root) {
    return path_1.default.join(root, exports.MANIFEST_PATH);
}
function parseManifest(parsed) {
    if (parsed === null || typeof parsed !== 'object')
        throw new types_1.TripwireError('Manifest is not an object.');
    const raw = parsed;
    if (raw.version !== 1)
        throw new types_1.TripwireError('Manifest version must be 1.');
    if (typeof raw.namespace !== 'string' || !/^tw[a-f0-9]{8}$/.test(raw.namespace)) {
        throw new types_1.TripwireError('Manifest namespace is missing or malformed.');
    }
    if (!Array.isArray(raw.canaries) || !Array.isArray(raw.files) || !Array.isArray(raw.retired)) {
        throw new types_1.TripwireError('Manifest is missing canaries, files, or retired.');
    }
    return raw;
}
function parseManifestText(text) {
    let parsed;
    try {
        parsed = JSON.parse(text);
    }
    catch (err) {
        const message = err instanceof Error ? err.message : String(err);
        throw new types_1.TripwireError(`Could not parse ${exports.MANIFEST_PATH}: ${message}`);
    }
    return parseManifest(parsed);
}
function readManifest(root) {
    const file = manifestFile(root);
    if (!fs_1.default.existsSync(file)) {
        throw new types_1.TripwireError(`No canary manifest at ${exports.MANIFEST_PATH}. Run \`tripwire init\` first.`);
    }
    return parseManifestText(fs_1.default.readFileSync(file, 'utf8'));
}
function writeManifest(root, manifest) {
    const file = manifestFile(root);
    fs_1.default.mkdirSync(path_1.default.dirname(file), { recursive: true });
    fs_1.default.writeFileSync(file, `${JSON.stringify(manifest, null, 2)}\n`, 'utf8');
}
