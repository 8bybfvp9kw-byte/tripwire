import fs from 'fs';
import { readConfig } from './config';
import { diffRange, git, gitShow } from './git';
import { readManifest } from './manifest';
import { renderAnnotations, renderSummary, renderText } from './report';
import { scan } from './scan';
import { TripwireError, parseSeverity } from './types';

export interface ActionIo {
  stdout: (chunk: string) => void;
  stderr: (chunk: string) => void;
}

interface PullRequestEvent {
  pull_request?: {
    title?: string;
    body?: string | null;
    base?: { sha?: string; ref?: string };
    head?: { sha?: string; ref?: string };
    user?: { login?: string; type?: string };
  };
}

export interface ActionEnv {
  workspace: string;
  eventPath?: string;
  stepSummary?: string;
  outputPath?: string;
  headRef?: string;
  actor?: string;
  inputs: {
    failOn: string;
    base: string;
    head: string;
    allowManifestEdits: boolean;
  };
}

function readEvent(eventPath: string | undefined): PullRequestEvent | null {
  if (!eventPath || !fs.existsSync(eventPath)) return null;
  return JSON.parse(fs.readFileSync(eventPath, 'utf8')) as PullRequestEvent;
}

export function actionEnvFromProcess(env: NodeJS.ProcessEnv = process.env): ActionEnv {
  const allow = (env.INPUT_ALLOW_MANIFEST_EDITS ?? 'false').toLowerCase();
  return {
    workspace: env.GITHUB_WORKSPACE || process.cwd(),
    eventPath: env.GITHUB_EVENT_PATH,
    stepSummary: env.GITHUB_STEP_SUMMARY,
    outputPath: env.GITHUB_OUTPUT,
    headRef: env.GITHUB_HEAD_REF,
    actor: env.GITHUB_ACTOR,
    inputs: {
      failOn: env.INPUT_FAIL_ON || 'low',
      base: env.INPUT_BASE || '',
      head: env.INPUT_HEAD || '',
      allowManifestEdits: allow === 'true' || allow === '1',
    },
  };
}

function writeOutput(file: string | undefined, pairs: Record<string, string>): void {
  if (!file) return;
  const body = Object.entries(pairs)
    .map(([key, value]) => `${key}=${value}`)
    .join('\n');
  fs.appendFileSync(file, `${body}\n`);
}

export function runAction(env: ActionEnv, io: ActionIo = {
  stdout: (chunk) => process.stdout.write(chunk),
  stderr: (chunk) => process.stderr.write(chunk),
}): number {
  try {
    parseSeverity(env.inputs.failOn);
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    io.stderr(`tripwire: ${message}\n`);
    return 2;
  }
  const event = readEvent(env.eventPath);
  const pull = event?.pull_request;
  const base = env.inputs.base || pull?.base?.sha || '';
  const head = env.inputs.head || pull?.head?.sha || '';
  if (!base || !head) {
    io.stderr(
      'tripwire: set base and head, or run on a pull_request event. The checkout needs fetch-depth: 0 so both commits are present.\n',
    );
    return 2;
  }
  let code = 0;
  try {
    const manifest = readManifest(env.workspace);
    const config = readConfig(env.workspace);
    const diffText = diffRange(env.workspace, `${base}...${head}`);
    const commitText = git(env.workspace, ['log', '--format=%B%x00', `${base}...${head}`]).replace(/\0/g, '\n');
    const authors = git(env.workspace, ['log', '--format=%an', `${base}...${head}`])
      .split('\n')
      .map((line) => line.trim())
      .filter((line) => line.length > 0);
    const extraTexts = [
      { path: 'pull_request.title', text: pull?.title ?? '' },
      { path: 'pull_request.body', text: pull?.body ?? '' },
    ].filter((item) => item.text.trim().length > 0);
    const report = scan({
      manifest,
      config,
      diffText,
      readFile: (rel) => gitShow(env.workspace, head, rel),
      extraTexts,
      allowManifestEdits: env.inputs.allowManifestEdits,
      failOn: env.inputs.failOn,
      agent: {
        branch: env.headRef || pull?.head?.ref || '',
        actor: pull?.user?.login || env.actor || '',
        authorType: pull?.user?.type,
        authors,
        commitText,
      },
    });
    io.stdout(renderText(report));
    for (const annotation of renderAnnotations(report)) io.stdout(`${annotation}\n`);
    if (env.stepSummary) fs.appendFileSync(env.stepSummary, renderSummary(report));
    writeOutput(env.outputPath, {
      result: report.result,
      findings: String(report.blocking.length),
    });
    code = report.result === 'fail' ? 1 : 0;
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    const hint = /unknown revision|bad revision|ambiguous argument|no merge base/i.test(message)
      ? ' Fetch the base and head commits (actions/checkout fetch-depth: 0) and try again.'
      : '';
    io.stderr(`tripwire: ${message}.${hint}\n`);
    if (env.stepSummary) {
      fs.appendFileSync(env.stepSummary, `# Tripwire\n\nThe scan did not run.\n\n\`\`\`\n${message}${hint}\n\`\`\`\n`);
    }
    code = err instanceof TripwireError ? err.exitCode : 2;
  }
  return code;
}

if (require.main === module) {
  process.exit(runAction(actionEnvFromProcess()));
}
