"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.CANARY_NOTE = void 0;
exports.renderBlock = renderBlock;
exports.blockPattern = blockPattern;
exports.findBlock = findBlock;
exports.upsertBlock = upsertBlock;
exports.stripBlock = stripBlock;
const hash_1 = require("./hash");
exports.CANARY_NOTE = '<!-- Tripwire canary below. Inert. Not a project rule. Remove with `tripwire remove`. -->';
function renderBlock(id, body) {
    if (!/^[a-z][a-z0-9]{0,31}$/.test(id))
        throw new Error(`Unsafe block id "${id}".`);
    return `<!-- tripwire:start id=${id} -->\n${body}\n<!-- tripwire:end id=${id} -->`;
}
function blockPattern(id) {
    return new RegExp(`<!-- tripwire:start id=${(0, hash_1.escapeRegExp)(id)} -->\\n[\\s\\S]*?<!-- tripwire:end id=${(0, hash_1.escapeRegExp)(id)} -->`);
}
function findBlock(text, id) {
    const match = blockPattern(id).exec(text);
    if (!match || match.index === undefined)
        return null;
    const start = text.slice(0, match.index).split('\n').length;
    const end = start + match[0].split('\n').length - 1;
    return { start, end, text: match[0] };
}
function upsertBlock(original, id, block) {
    const pattern = new RegExp(`(?:${(0, hash_1.escapeRegExp)(exports.CANARY_NOTE)}\\n)?${blockPattern(id).source}\\n?`);
    const replacement = `${exports.CANARY_NOTE}\n${block}\n`;
    if (pattern.test(original))
        return original.replace(pattern, replacement);
    if (original.trim() === '')
        return `${replacement}`;
    const base = original.endsWith('\n') ? original : `${original}\n`;
    return `${base}\n${replacement}`;
}
function stripBlock(original, id) {
    const pattern = new RegExp(`\\n?(?:${(0, hash_1.escapeRegExp)(exports.CANARY_NOTE)}\\n)?${blockPattern(id).source}\\n?`);
    return original.replace(pattern, '\n').replace(/\n{3,}/g, '\n\n');
}
