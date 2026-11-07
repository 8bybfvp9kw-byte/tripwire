"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.detectAgentSignals = detectAgentSignals;
const AGENT_BRANCH = /^(?:cursor|claude|copilot|codex|devin|aider|sweep|agent)\//i;
const AGENT_NAME = /cursor|claude|copilot|codex|devin|aider|sweep|codegen|openhands|gpt-engineer|cody/i;
function detectAgentSignals(input) {
    const reasons = [];
    const branch = (input.branch ?? '').trim();
    if (branch && AGENT_BRANCH.test(branch)) {
        reasons.push(`head branch "${branch}" matches an agent branch prefix`);
    }
    const actor = (input.actor ?? '').trim();
    if (actor && (AGENT_NAME.test(actor) || /\[bot\]$/i.test(actor) || input.authorType === 'Bot')) {
        reasons.push(`pull request author "${actor}" looks like a bot or coding agent`);
    }
    for (const author of input.authors ?? []) {
        const name = author.trim();
        if (!name)
            continue;
        if (AGENT_NAME.test(name) || /\[bot\]$/i.test(name)) {
            reasons.push(`commit author "${name}" looks like a bot or coding agent`);
        }
    }
    const trailers = (input.commitText ?? '').match(/^co-authored-by:\s*.+$/gim) ?? [];
    for (const trailer of trailers) {
        if (AGENT_NAME.test(trailer) || /\[bot\]/i.test(trailer)) {
            reasons.push(`commit trailer ${trailer.trim()} looks like a coding agent`);
        }
    }
    return [...new Set(reasons)];
}
