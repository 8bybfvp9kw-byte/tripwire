"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.DIFF_FLAGS = void 0;
exports.git = git;
exports.gitShow = gitShow;
exports.readWorktree = readWorktree;
exports.diffRange = diffRange;
exports.diffWorktree = diffWorktree;
const child_process_1 = require("child_process");
const fs_1 = __importDefault(require("fs"));
const path_1 = __importDefault(require("path"));
const types_1 = require("./types");
const MAX_BUFFER = 50 * 1024 * 1024;
function git(cwd, args) {
    try {
        return (0, child_process_1.execFileSync)('git', args, {
            cwd,
            encoding: 'utf8',
            maxBuffer: MAX_BUFFER,
            stdio: ['ignore', 'pipe', 'pipe'],
        });
    }
    catch (err) {
        const error = err;
        const stderr = error.stderr ? error.stderr.toString().trim() : '';
        throw new types_1.TripwireError(stderr || error.message || `git ${args.join(' ')} failed`);
    }
}
function gitShow(cwd, ref, rel) {
    const spec = `${ref}:${rel.replace(/\\/g, '/')}`;
    try {
        return (0, child_process_1.execFileSync)('git', ['show', spec], {
            cwd,
            encoding: 'utf8',
            maxBuffer: MAX_BUFFER,
            stdio: ['ignore', 'pipe', 'pipe'],
        });
    }
    catch {
        return null;
    }
}
function readWorktree(cwd, rel) {
    const abs = path_1.default.resolve(cwd, rel);
    const root = path_1.default.resolve(cwd);
    if (abs !== root && !abs.startsWith(root + path_1.default.sep))
        return null;
    if (!fs_1.default.existsSync(abs) || !fs_1.default.statSync(abs).isFile())
        return null;
    return fs_1.default.readFileSync(abs, 'utf8');
}
exports.DIFF_FLAGS = ['diff', '--unified=3', '--find-renames', '--no-color', '--no-ext-diff'];
function diffRange(cwd, range) {
    return git(cwd, [...exports.DIFF_FLAGS, range]);
}
function diffWorktree(cwd) {
    return git(cwd, [...exports.DIFF_FLAGS, 'HEAD']);
}
