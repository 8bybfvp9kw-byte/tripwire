"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const strict_1 = __importDefault(require("node:assert/strict"));
const node_test_1 = require("node:test");
const demo_1 = require("../src/demo");
(0, node_test_1.describe)('demo', () => {
    (0, node_test_1.it)('flags the planting commit and catches the simulated hijack', () => {
        const result = (0, demo_1.runDemo)({ seed: 'public' });
        strict_1.default.equal(result.passed, true, result.text);
        strict_1.default.match(result.text, /Guard files changed/);
        strict_1.default.match(result.text, /Tripwire scan: FAIL/);
        strict_1.default.match(result.text, /secret-github-pat/);
        strict_1.default.match(result.text, /marker-agents/);
        strict_1.default.match(result.text, /url-agents/);
        strict_1.default.match(result.text, /tamper-\.tripwire\/GUARD\.txt/);
        strict_1.default.match(result.text, /cursor\/hijack-demo/);
        strict_1.default.match(result.text, /Co-authored-by: Copilot/);
    });
});
