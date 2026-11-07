"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.toPosix = toPosix;
exports.assertSafeRelPath = assertSafeRelPath;
exports.resolveInside = resolveInside;
const path_1 = __importDefault(require("path"));
const types_1 = require("./types");
function toPosix(value) {
    return value.replace(/\\/g, '/');
}
/** Relative path, no traversal, no absolute form. */
function assertSafeRelPath(value) {
    const posix = toPosix(value).trim();
    if (posix === '' || posix.startsWith('/')) {
        throw new types_1.TripwireError(`Refusing path "${value}". Use a relative path.`);
    }
    const norm = path_1.default.posix.normalize(posix);
    if (norm === '..' || norm.startsWith('../') || norm.includes('/../') || path_1.default.posix.isAbsolute(norm)) {
        throw new types_1.TripwireError(`Refusing path "${value}".`);
    }
    return norm;
}
function resolveInside(root, rel) {
    const safe = assertSafeRelPath(rel);
    const absRoot = path_1.default.resolve(root);
    const abs = path_1.default.resolve(absRoot, safe);
    const prefix = absRoot.endsWith(path_1.default.sep) ? absRoot : absRoot + path_1.default.sep;
    if (abs !== absRoot && !abs.startsWith(prefix)) {
        throw new types_1.TripwireError(`Refusing path "${rel}".`);
    }
    return abs;
}
