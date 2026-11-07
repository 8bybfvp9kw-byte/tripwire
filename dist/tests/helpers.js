"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.CLI = void 0;
exports.tempDir = tempDir;
exports.git = git;
exports.initGit = initGit;
exports.addedFileDiff = addedFileDiff;
const child_process_1 = require("child_process");
const fs_1 = __importDefault(require("fs"));
const os_1 = __importDefault(require("os"));
const path_1 = __importDefault(require("path"));
function tempDir() {
    return fs_1.default.mkdtempSync(path_1.default.join(os_1.default.tmpdir(), 'tripwire-test-'));
}
function git(cwd, args) {
    return (0, child_process_1.execFileSync)('git', args, { cwd, encoding: 'utf8', maxBuffer: 20 * 1024 * 1024 });
}
function initGit(cwd) {
    git(cwd, ['init', '-b', 'main']);
    git(cwd, ['config', 'user.name', 'Tripwire Demo']);
    git(cwd, ['config', 'user.email', 'tripwire-demo@example.invalid']);
}
function addedFileDiff(filePath, content) {
    const body = content.endsWith('\n') ? content.slice(0, -1) : content;
    const lines = body.split('\n');
    return [
        `diff --git a/${filePath} b/${filePath}`,
        'new file mode 100644',
        'index 0000000..1111111',
        '--- /dev/null',
        `+++ b/${filePath}`,
        `@@ -0,0 +1,${lines.length} @@`,
        ...lines.map((line) => `+${line}`),
        '',
    ].join('\n');
}
exports.CLI = path_1.default.join(__dirname, '..', 'src', 'cli.js');
