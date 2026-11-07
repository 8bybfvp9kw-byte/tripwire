"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const strict_1 = __importDefault(require("node:assert/strict"));
const node_test_1 = require("node:test");
const glob_1 = require("../src/glob");
(0, node_test_1.describe)('globs', () => {
    const patterns = ['node_modules/**', 'dist/**', '**/*.lock', 'package-lock.json'];
    (0, node_test_1.it)('matches generated paths and lockfiles at any depth', () => {
        strict_1.default.equal((0, glob_1.matchAnyGlob)('dist/index.js', patterns), true);
        strict_1.default.equal((0, glob_1.matchAnyGlob)('dist/a/b.js', patterns), true);
        strict_1.default.equal((0, glob_1.matchAnyGlob)('node_modules/leftpad/index.js', patterns), true);
        strict_1.default.equal((0, glob_1.matchAnyGlob)('yarn.lock', patterns), true);
        strict_1.default.equal((0, glob_1.matchAnyGlob)('packages/app/foo.lock', patterns), true);
        strict_1.default.equal((0, glob_1.matchAnyGlob)('package-lock.json', patterns), true);
        strict_1.default.equal((0, glob_1.matchAnyGlob)('apps/web/package-lock.json', patterns), true);
    });
    (0, node_test_1.it)('does not match source files', () => {
        strict_1.default.equal((0, glob_1.matchAnyGlob)('src/index.ts', patterns), false);
        strict_1.default.equal((0, glob_1.matchAnyGlob)('AGENTS.md', patterns), false);
        strict_1.default.equal((0, glob_1.matchAnyGlob)('.tripwire/decoys/credentials.example', patterns), false);
    });
});
