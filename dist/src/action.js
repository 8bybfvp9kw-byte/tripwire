"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.actionEnvFromProcess = actionEnvFromProcess;
exports.runAction = runAction;
const fs_1 = __importDefault(require("fs"));
const config_1 = require("./config");
const git_1 = require("./git");
const manifest_1 = require("./manifest");
const report_1 = require("./report");
const scan_1 = require("./scan");
const types_1 = require("./types");
function readEvent(eventPath) {
    if (!eventPath || !fs_1.default.existsSync(eventPath))
        return null;
    return JSON.parse(fs_1.default.readFileSync(eventPath, 'utf8'));
}
function actionEnvFromProcess(env = process.env) {
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
function writeOutput(file, pairs) {
    if (!file)
        return;
    const body = Object.entries(pairs)
        .map(([key, value]) => `${key}=${value}`)
        .join('\n');
    fs_1.default.appendFileSync(file, `${body}\n`);
}
function runAction(env, io = {
    stdout: (chunk) => process.stdout.write(chunk),
    stderr: (chunk) => process.stderr.write(chunk),
}) {
    try {
        (0, types_1.parseSeverity)(env.inputs.failOn);
    }
    catch (err) {
        const message = err instanceof Error ? err.message : String(err);
        io.stderr(`tripwire: ${message}\n`);
        return 2;
    }
    const event = readEvent(env.eventPath);
    const pull = event?.pull_request;
    const base = env.inputs.base || pull?.base?.sha || '';
    const head = env.inputs.head || pull?.head?.sha || '';
    if (!base || !head) {
        io.stderr('tripwire: set base and head, or run on a pull_request event. The checkout needs fetch-depth: 0 so both commits are present.\n');
        return 2;
    }
    let code = 0;
    try {
        const manifest = (0, manifest_1.readManifest)(env.workspace);
        const config = (0, config_1.readConfig)(env.workspace);
        const diffText = (0, git_1.diffRange)(env.workspace, `${base}...${head}`);
        const commitText = (0, git_1.git)(env.workspace, ['log', '--format=%B%x00', `${base}...${head}`]).replace(/\0/g, '\n');
        const authors = (0, git_1.git)(env.workspace, ['log', '--format=%an', `${base}...${head}`])
            .split('\n')
            .map((line) => line.trim())
            .filter((line) => line.length > 0);
        const extraTexts = [
            { path: 'pull_request.title', text: pull?.title ?? '' },
            { path: 'pull_request.body', text: pull?.body ?? '' },
        ].filter((item) => item.text.trim().length > 0);
        const report = (0, scan_1.scan)({
            manifest,
            config,
            diffText,
            readFile: (rel) => (0, git_1.gitShow)(env.workspace, head, rel),
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
        io.stdout((0, report_1.renderText)(report));
        for (const annotation of (0, report_1.renderAnnotations)(report))
            io.stdout(`${annotation}\n`);
        if (env.stepSummary)
            fs_1.default.appendFileSync(env.stepSummary, (0, report_1.renderSummary)(report));
        writeOutput(env.outputPath, {
            result: report.result,
            findings: String(report.blocking.length),
        });
        code = report.result === 'fail' ? 1 : 0;
    }
    catch (err) {
        const message = err instanceof Error ? err.message : String(err);
        const hint = /unknown revision|bad revision|ambiguous argument|no merge base/i.test(message)
            ? ' Fetch the base and head commits (actions/checkout fetch-depth: 0) and try again.'
            : '';
        io.stderr(`tripwire: ${message}.${hint}\n`);
        if (env.stepSummary) {
            fs_1.default.appendFileSync(env.stepSummary, `# Tripwire\n\nThe scan did not run.\n\n\`\`\`\n${message}${hint}\n\`\`\`\n`);
        }
        code = err instanceof types_1.TripwireError ? err.exitCode : 2;
    }
    return code;
}
if (require.main === module) {
    process.exit(runAction(actionEnvFromProcess()));
}
