"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.normalizeNewlines = normalizeNewlines;
exports.sha256Text = sha256Text;
exports.escapeRegExp = escapeRegExp;
const crypto_1 = require("crypto");
function normalizeNewlines(text) {
    return text.replace(/\r\n/g, '\n');
}
function sha256Text(text) {
    return (0, crypto_1.createHash)('sha256').update(normalizeNewlines(text), 'utf8').digest('hex');
}
function escapeRegExp(value) {
    return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}
