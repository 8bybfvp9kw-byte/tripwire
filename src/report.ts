import { Finding, ScanReport } from './types';

function lineFor(finding: Finding): string {
  const severity = finding.severity.toUpperCase().padEnd(8, ' ');
  return `${severity} ${finding.id}  ${finding.path}:${finding.line}`;
}

export function renderText(report: ScanReport): string {
  const lines: string[] = [];
  lines.push(`Tripwire scan: ${report.result === 'fail' ? 'FAIL' : 'PASS'}`);
  if (report.findings.length === 0) {
    lines.push(`No canaries tripped. ${report.filesScanned} changed file${report.filesScanned === 1 ? '' : 's'}.`);
  } else {
    const noun = report.blocking.length === 1 ? 'finding' : 'findings';
    lines.push(
      `${report.blocking.length} ${noun} at or above ${report.failOn}. ${report.findings.length} total.`,
    );
    lines.push('');
    for (const finding of report.findings) {
      lines.push(lineFor(finding));
      lines.push(`  ${finding.message}`);
      if (finding.detail) lines.push(`  ${finding.detail}`);
      lines.push('');
    }
  }
  if (report.agentSignals.length > 0) {
    lines.push('Agent signals (informational; every pull request is scanned):');
    for (const signal of report.agentSignals) lines.push(`- ${signal}`);
  }
  return `${lines.join('\n').replace(/\n+$/, '')}\n`;
}

export function renderJson(report: ScanReport): string {
  return `${JSON.stringify(
    {
      result: report.result,
      failOn: report.failOn,
      filesScanned: report.filesScanned,
      findings: report.findings,
      agentSignals: report.agentSignals,
    },
    null,
    2,
  )}\n`;
}

function escapeData(value: string): string {
  return value.replace(/%/g, '%25').replace(/\r/g, '%0D').replace(/\n/g, '%0A');
}

function escapeProp(value: string): string {
  return value
    .replace(/%/g, '%25')
    .replace(/\r/g, '%0D')
    .replace(/\n/g, '%0A')
    .replace(/,/g, '%2C')
    .replace(/:/g, '%3A');
}

export function renderAnnotations(report: ScanReport): string[] {
  return report.blocking.map((finding) => {
    const level = finding.severity === 'critical' || finding.severity === 'high' ? 'error' : 'warning';
    const title = escapeProp(`Tripwire ${finding.severity.toUpperCase()} ${finding.id}`);
    const file = escapeProp(finding.path);
    const message = escapeData(`${finding.message}${finding.detail ? ` ${finding.detail}` : ''}`);
    return `::${level} file=${file},line=${finding.line},title=${title}::${message}`;
  });
}

export function renderSummary(report: ScanReport): string {
  const lines: string[] = ['# Tripwire', ''];
  if (report.result === 'pass') {
    lines.push(`**PASS.** No canaries tripped (${report.filesScanned} changed files).`);
  } else {
    lines.push(`**FAIL.** ${report.blocking.length} findings at or above \`${report.failOn}\`.`);
    lines.push('');
    lines.push('| Severity | Canary | Location |');
    lines.push('| --- | --- | --- |');
    for (const finding of report.blocking) {
      lines.push(
        `| ${finding.severity.toUpperCase()} | \`${finding.id}\` | \`${finding.path}:${finding.line}\` |`,
      );
    }
  }
  if (report.agentSignals.length > 0) {
    lines.push('');
    lines.push('Agent signals are informational. Every pull request is scanned.');
    for (const signal of report.agentSignals) lines.push(`- ${signal}`);
  }
  lines.push('');
  return lines.join('\n');
}
