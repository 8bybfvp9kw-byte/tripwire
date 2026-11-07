import { detectAgentSignals, AgentInput } from './agent';
import { findBlock } from './blocks';
import { parseUnifiedDiff, DiffFile } from './diff';
import { matchAnyGlob } from './glob';
import { sha256Text } from './hash';
import { MANIFEST_PATH } from './manifest';
import { matchLine, redactSecret } from './match';
import {
  Canary,
  Config,
  Finding,
  Manifest,
  ScanReport,
  Severity,
  TripwireError,
  parseSeverity,
  severityRank,
} from './types';

export interface ExtraText {
  path: string;
  text: string;
}

export interface ScanInput {
  manifest: Manifest;
  config: Config;
  diffText: string;
  /** Post-image of a path at the commit being scanned. Null when the file is absent. */
  readFile?: (relPath: string) => string | null;
  extraTexts?: ExtraText[];
  allowManifestEdits?: boolean;
  failOn?: Severity | string;
  agent?: AgentInput;
}

function allCanaries(manifest: Manifest): Canary[] {
  return [...manifest.canaries, ...manifest.retired];
}

function diffFor(files: DiffFile[], plantedPath: string): DiffFile | undefined {
  return files.find((file) => file.path === plantedPath || file.oldPath === plantedPath);
}

function posixPath(filePath: string): string {
  return filePath.replace(/\\/g, '/');
}

function isTripwireGuardPath(filePath: string): boolean {
  const path = posixPath(filePath);
  return path === '.tripwire' || path.startsWith('.tripwire/') || path === 'tripwire.config.json' || path.endsWith('/tripwire.config.json');
}

function isWorkflowPath(filePath: string): boolean {
  return posixPath(filePath).startsWith('.github/workflows/');
}

function workflowReferencesTripwire(file: DiffFile, readFile?: ScanInput['readFile']): boolean {
  const hunk = [...file.addedLines, ...file.deletedLines].some((line) => /tripwire/i.test(line.text));
  if (hunk) return true;
  if (!readFile) return false;
  for (const candidate of [file.path, file.oldPath]) {
    if (!candidate || !isWorkflowPath(candidate)) continue;
    const text = readFile(candidate);
    if (text && /tripwire/i.test(text)) return true;
  }
  return false;
}

function guardFileFindings(files: DiffFile[], readFile?: ScanInput['readFile']): Finding[] {
  const findings: Finding[] = [];
  for (const file of files) {
    const paths = [file.path, file.oldPath].filter((value): value is string => Boolean(value) && value !== '/dev/null');
    const guard = paths.some(isTripwireGuardPath);
    const workflow = paths.some(isWorkflowPath) && workflowReferencesTripwire(file, readFile);
    if (!guard && !workflow) continue;
    const path = file.status === 'deleted' && file.oldPath ? file.oldPath : file.path;
    findings.push({
      id: 'guard-files-changed',
      severity: 'high',
      kind: 'tamper',
      path,
      line: file.firstChangeLine || 1,
      message:
        'Guard files changed. A pull request cannot edit Tripwire canaries, tripwire.config.json, or a workflow that runs Tripwire.',
    });
  }
  return findings;
}

function isExpected(canary: Canary, filePath: string, line: number, readFile?: ScanInput['readFile']): boolean {
  if (canary.plantedPaths.length === 0) return false;
  if (!canary.plantedPaths.includes(filePath)) return false;
  if (!canary.blockId) return true;
  if (!readFile) return true;
  const text = readFile(filePath);
  if (text === null) return false;
  const span = findBlock(text.replace(/\r\n/g, '\n'), canary.blockId);
  if (!span) return false;
  return line >= span.start && line <= span.end;
}

function pushFinding(findings: Finding[], finding: Finding): void {
  const key = `${finding.id}\0${finding.path}\0${finding.line}\0${finding.kind}`;
  if (findings.some((item) => `${item.id}\0${item.path}\0${item.line}\0${item.kind}` === key)) return;
  findings.push(finding);
}

function detailFor(line: string, hits: { value: string; canary: Canary }[]): string {
  let shown = line;
  for (const hit of hits) {
    if (hit.canary.kind !== 'secret') continue;
    shown = shown.split(hit.value).join(redactSecret(hit.value));
  }
  return shown;
}

export function scan(input: ScanInput): ScanReport {
  const failOn =
    input.failOn === undefined
      ? input.config.failOn
      : typeof input.failOn === 'string'
        ? parseSeverity(input.failOn)
        : input.failOn;
  const allowManifestEdits = input.allowManifestEdits ?? input.config.allowManifestEdits;
  const diffFiles = parseUnifiedDiff(input.diffText);
  const findings: Finding[] = [];
  const canaries = allCanaries(input.manifest);
  const ignored = (filePath: string) => matchAnyGlob(filePath, input.config.ignore);

  const considerLine = (filePath: string, lineNumber: number, text: string): void => {
    const hits = matchLine(text, canaries);
    if (hits.length === 0) return;
    const unexpected = hits.filter((hit) => !isExpected(hit.canary, filePath, lineNumber, input.readFile));
    if (unexpected.length === 0) return;
    const pathIgnored = ignored(filePath);
    const reported = unexpected.filter((hit) => {
      if (!pathIgnored) return true;
      if (hit.canary.kind === 'secret') return !input.config.ignoreSecretsInIgnoredPaths;
      return false;
    });
    if (reported.length === 0) return;
    const detail = detailFor(text, reported);
    for (const hit of reported) {
      const planted = hit.canary.plantedPaths.join(', ');
      const message =
        hit.canary.kind === 'secret'
          ? `${hit.canary.description} It appeared in ${filePath}, outside ${planted || 'its planted file'}.`
          : `${hit.canary.description} It appeared in ${filePath}.`;
      pushFinding(findings, {
        id: hit.canary.id,
        severity: hit.canary.severity,
        kind: hit.canary.kind,
        path: filePath,
        line: lineNumber,
        message,
        detail: `${lineNumber} | ${detail}`,
      });
    }
  };

  for (const file of diffFiles) {
    if (file.binary) continue;
    for (const line of file.addedLines) considerLine(file.path, line.line, line.text);
  }
  for (const extra of input.extraTexts ?? []) {
    const lines = extra.text.replace(/\r\n/g, '\n').split('\n');
    lines.forEach((text, index) => considerLine(extra.path, index + 1, text));
  }

  for (const planted of input.manifest.files) {
    const diffFile = diffFor(diffFiles, planted.path);
    if (!diffFile) continue;
    const movedAway = diffFile.status === 'renamed' && diffFile.oldPath === planted.path && diffFile.path !== planted.path;
    if (diffFile.status === 'deleted' || movedAway) {
      pushFinding(findings, {
        id: `tamper-${planted.path}`,
        severity: 'high',
        kind: 'tamper',
        path: planted.path,
        line: diffFile.firstChangeLine || 1,
        message:
          diffFile.status === 'deleted'
            ? `Canary file ${planted.path} was deleted.`
            : `Canary file ${planted.path} was renamed to ${diffFile.path}.`,
      });
      continue;
    }
    if (diffFile.binary) {
      pushFinding(findings, {
        id: `tamper-${planted.path}`,
        severity: 'high',
        kind: 'tamper',
        path: planted.path,
        line: 1,
        message: `Canary file ${planted.path} was replaced with binary content.`,
      });
      continue;
    }
    if (!input.readFile) {
      pushFinding(findings, {
        id: `tamper-${planted.path}`,
        severity: 'high',
        kind: 'tamper',
        path: planted.path,
        line: diffFile.firstChangeLine || 1,
        message: `Canary file ${planted.path} changed. Re-run the scan with the head checkout to compare the canary block exactly.`,
      });
      continue;
    }
    const text = input.readFile(planted.path);
    if (text === null) {
      pushFinding(findings, {
        id: `tamper-${planted.path}`,
        severity: 'high',
        kind: 'tamper',
        path: planted.path,
        line: diffFile.firstChangeLine || 1,
        message: `Canary file ${planted.path} is missing at the revision being scanned.`,
      });
      continue;
    }
    const normalized = text.replace(/\r\n/g, '\n');
    if (planted.type === 'file') {
      if (sha256Text(normalized) !== planted.sha256) {
        pushFinding(findings, {
          id: `tamper-${planted.path}`,
          severity: 'high',
          kind: 'tamper',
          path: planted.path,
          line: diffFile.firstChangeLine || 1,
          message: `Canary file ${planted.path} was modified.`,
        });
      }
      continue;
    }
    if (!planted.blockId) throw new TripwireError(`Manifest block entry ${planted.path} has no block id.`);
    const span = findBlock(normalized, planted.blockId);
    if (!span) {
      pushFinding(findings, {
        id: `tamper-${planted.blockId}`,
        severity: 'high',
        kind: 'tamper',
        path: planted.path,
        line: diffFile.firstChangeLine || 1,
        message: `Canary block ${planted.blockId} was removed from ${planted.path}.`,
      });
      continue;
    }
    if (sha256Text(span.text) !== planted.sha256) {
      pushFinding(findings, {
        id: `tamper-${planted.blockId}`,
        severity: 'high',
        kind: 'tamper',
        path: planted.path,
        line: span.start,
        message: `Canary block ${planted.blockId} in ${planted.path} was modified.`,
      });
    }
  }

  for (const finding of guardFileFindings(diffFiles, input.readFile)) pushFinding(findings, finding);

  const manifestDiff = diffFor(diffFiles, MANIFEST_PATH);
  if (manifestDiff && manifestDiff.status === 'deleted') {
    pushFinding(findings, {
      id: 'manifest-deleted',
      severity: 'critical',
      kind: 'manifest',
      path: MANIFEST_PATH,
      line: manifestDiff.firstChangeLine || 1,
      message: 'The canary manifest was deleted. The scan can no longer recognize planted values.',
    });
  } else if (manifestDiff && manifestDiff.status !== 'added' && !allowManifestEdits) {
    pushFinding(findings, {
      id: 'manifest-edited',
      severity: 'high',
      kind: 'manifest',
      path: MANIFEST_PATH,
      line: manifestDiff.firstChangeLine || 1,
      message:
        'The canary manifest changed in this diff. That is expected for `tripwire rotate` and suspicious otherwise. A maintainer should review it, or set allow-manifest-edits for a rotation pull request.',
    });
  }

  findings.sort((a, b) => {
    const bySeverity = severityRank(b.severity) - severityRank(a.severity);
    if (bySeverity !== 0) return bySeverity;
    if (a.id !== b.id) return a.id < b.id ? -1 : 1;
    if (a.path !== b.path) return a.path < b.path ? -1 : 1;
    return a.line - b.line;
  });

  const blocking = findings.filter((finding) => severityRank(finding.severity) >= severityRank(failOn));
  const extraCount = (input.extraTexts ?? []).filter((item) => item.text.length > 0).length;
  return {
    result: blocking.length > 0 ? 'fail' : 'pass',
    failOn,
    findings,
    blocking,
    agentSignals: detectAgentSignals(input.agent ?? {}),
    filesScanned: diffFiles.length + extraCount,
  };
}
