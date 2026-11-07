"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.matchLine = matchLine;
exports.redactSecret = redactSecret;
const hash_1 = require("./hash");
const EXTRACTORS = {
    github_pat: (line) => line.match(/gh_tripwire_[0-9A-Za-z]{32}/g) ?? [],
    aws_access_key_id: (line) => line.match(/aws_tripwire_[A-Z0-9]{16}/g) ?? [],
    aws_secret_access_key: (line) => line.match(/aws_tripwire_secret_[0-9A-Za-z]{24}/g) ?? [],
    stripe_test_secret_key: (line) => line.match(/sk_tripwire_[0-9A-Za-z]{24}/g) ?? [],
    signal: (line) => line.match(/TRIPWIRE_SIGNAL_tw[a-f0-9]{8}_[a-z0-9]+/g) ?? [],
    callback_url: (line) => line.match(/https:\/\/canary\.tripwire\.invalid\/h\/tw[a-f0-9]{8}\/[a-z0-9]+/g) ?? [],
    guard_nonce: (line) => line.match(/TWGUARD_[a-f0-9]{32}/g) ?? [],
};
function matchLine(line, canaries) {
    const hits = [];
    for (const canary of canaries) {
        const extractor = EXTRACTORS[canary.format];
        for (const value of extractor(line)) {
            if ((0, hash_1.sha256Text)(value) === canary.sha256) {
                hits.push({ canary, value });
                break;
            }
        }
    }
    return hits;
}
function redactSecret(value) {
    if (value.length <= 12)
        return `${value.slice(0, 4)}…`;
    return `${value.slice(0, 8)}…${value.slice(-4)}`;
}
