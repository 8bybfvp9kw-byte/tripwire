"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.compileGlob = compileGlob;
exports.matchAnyGlob = matchAnyGlob;
const hash_1 = require("./hash");
function compileGlob(pattern) {
    const raw = pattern.replace(/\\/g, '/');
    const anchored = raw.startsWith('/');
    const g = raw.replace(/^\//, '');
    let body = '';
    for (let i = 0; i < g.length; i++) {
        if (g.startsWith('**/', i)) {
            body += '(?:.*/)?';
            i += 2;
            continue;
        }
        if (g.startsWith('**', i)) {
            body += '.*';
            i += 1;
            continue;
        }
        const c = g[i] ?? '';
        if (c === '*')
            body += '[^/]*';
        else if (c === '?')
            body += '[^/]';
        else
            body += (0, hash_1.escapeRegExp)(c);
    }
    const hasSlash = g.includes('/');
    if (!anchored && !hasSlash)
        return new RegExp(`^(?:.*/)?${body}$`);
    return new RegExp(`^${body}$`);
}
function matchAnyGlob(filePath, patterns) {
    const posix = filePath.replace(/\\/g, '/').replace(/^\.\//, '');
    return patterns.some((pattern) => compileGlob(pattern).test(posix));
}
