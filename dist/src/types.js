"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.TripwireError = exports.SEVERITIES = void 0;
exports.severityRank = severityRank;
exports.parseSeverity = parseSeverity;
exports.SEVERITIES = ['info', 'low', 'medium', 'high', 'critical'];
function severityRank(severity) {
    return exports.SEVERITIES.indexOf(severity);
}
function parseSeverity(value) {
    const normalized = value.trim().toLowerCase();
    if (exports.SEVERITIES.includes(normalized))
        return normalized;
    throw new Error(`Unknown severity "${value}". Use one of: ${exports.SEVERITIES.join(', ')}.`);
}
class TripwireError extends Error {
    exitCode = 2;
    constructor(message) {
        super(message);
        this.name = 'TripwireError';
    }
}
exports.TripwireError = TripwireError;
