"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.parseUnifiedDiff = parseUnifiedDiff;
function emptyFile() {
    return {
        oldPath: null,
        path: '',
        status: 'modified',
        binary: false,
        addedLines: [],
        deletedLines: [],
        firstChangeLine: 1,
    };
}
function stripAB(value) {
    if (value === '/dev/null')
        return value;
    if (value.startsWith('a/') || value.startsWith('b/'))
        return value.slice(2);
    return value;
}
function unquote(value) {
    if (value.length >= 2 && value.startsWith('"') && value.endsWith('"')) {
        return value
            .slice(1, -1)
            .replace(/\\n/g, '\n')
            .replace(/\\t/g, '\t')
            .replace(/\\"/g, '"')
            .replace(/\\\\/g, '\\');
    }
    return value;
}
function splitQuoted(input) {
    const parts = [];
    let current = '';
    let quote = false;
    let escape = false;
    for (const ch of input) {
        if (escape) {
            current += ch;
            escape = false;
            continue;
        }
        if (ch === '\\') {
            current += ch;
            escape = true;
            continue;
        }
        if (ch === '"') {
            current += ch;
            quote = !quote;
            continue;
        }
        if (ch === ' ' && !quote) {
            if (current.length > 0)
                parts.push(current);
            current = '';
            continue;
        }
        current += ch;
    }
    if (current.length > 0)
        parts.push(current);
    return parts;
}
function parseDiffHeader(line) {
    const rest = line.slice('diff --git '.length);
    const parts = splitQuoted(rest).map(unquote);
    return {
        oldPath: stripAB(parts[0] ?? ''),
        newPath: stripAB(parts[1] ?? ''),
    };
}
function markerPath(value) {
    const trimmed = value.trim();
    const tab = trimmed.indexOf('\t');
    const raw = tab === -1 ? trimmed : trimmed.slice(0, tab);
    return stripAB(unquote(raw));
}
/**
 * Parse a unified diff. Line numbers on added lines are the new file's
 * numbers. Deleted files keep their old path in `path` so callers can match
 * planted locations.
 */
function parseUnifiedDiff(input) {
    if (input.trim() === '')
        return [];
    const lines = input.split(/\r?\n/);
    const files = [];
    let current = null;
    let newLine = 0;
    let oldLine = 0;
    let inHunk = false;
    let sawFirstChange = false;
    for (const line of lines) {
        if (line.startsWith('diff --git ')) {
            current = emptyFile();
            const header = parseDiffHeader(line);
            current.oldPath = header.oldPath || null;
            current.path = header.newPath;
            sawFirstChange = false;
            inHunk = false;
            files.push(current);
            continue;
        }
        if (!current)
            continue;
        if (line.startsWith('new file mode')) {
            current.status = 'added';
            continue;
        }
        if (line.startsWith('deleted file mode')) {
            current.status = 'deleted';
            continue;
        }
        if (line.startsWith('rename from ')) {
            current.status = 'renamed';
            current.oldPath = line.slice('rename from '.length).trim();
            continue;
        }
        if (line.startsWith('rename to ')) {
            current.status = 'renamed';
            current.path = line.slice('rename to '.length).trim();
            continue;
        }
        if (line.startsWith('Binary files ') || line.startsWith('GIT binary patch')) {
            current.binary = true;
            inHunk = false;
            continue;
        }
        if (line.startsWith('--- ')) {
            const marker = markerPath(line.slice(4));
            if (marker === '/dev/null') {
                if (current.status !== 'deleted')
                    current.status = 'added';
            }
            else {
                current.oldPath = marker;
            }
            continue;
        }
        if (line.startsWith('+++ ')) {
            const marker = markerPath(line.slice(4));
            if (marker === '/dev/null') {
                current.status = 'deleted';
                if (current.oldPath)
                    current.path = current.oldPath;
            }
            else {
                current.path = marker;
                if (current.status !== 'added' && current.status !== 'deleted' && current.status !== 'renamed') {
                    current.status = 'modified';
                }
            }
            continue;
        }
        const hunk = /^@@ -(\d+)(?:,\d+)? \+(\d+)(?:,\d+)? @@/.exec(line);
        if (hunk) {
            oldLine = Number(hunk[1]);
            newLine = Number(hunk[2]);
            inHunk = true;
            continue;
        }
        if (!inHunk)
            continue;
        if (line.startsWith('\\'))
            continue;
        if (line.startsWith('+')) {
            current.addedLines.push({ text: line.slice(1), line: newLine });
            if (!sawFirstChange) {
                current.firstChangeLine = newLine;
                sawFirstChange = true;
            }
            newLine += 1;
            continue;
        }
        if (line.startsWith('-')) {
            current.deletedLines.push({ text: line.slice(1), line: oldLine });
            if (!sawFirstChange) {
                current.firstChangeLine = oldLine;
                sawFirstChange = true;
            }
            oldLine += 1;
            continue;
        }
        if (line.startsWith(' ') || line === '') {
            oldLine += 1;
            newLine += 1;
        }
    }
    for (const file of files) {
        if (file.status === 'deleted' && file.oldPath)
            file.path = file.oldPath;
        if (!file.path && file.oldPath)
            file.path = file.oldPath;
        if (file.status === 'modified' &&
            file.oldPath &&
            file.path &&
            file.oldPath !== file.path &&
            file.oldPath !== '/dev/null') {
            file.status = 'renamed';
        }
    }
    return files.filter((file) => file.path.length > 0);
}
