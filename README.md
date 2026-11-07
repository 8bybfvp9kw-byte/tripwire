# Tripwire

Smoke alarm for AI coding agents. Plant inert canaries, and fail the pull request if a diff trips one.

Coding agents read the repository, the issues, the docs, and the dependency tree, then they commit and open a pull request. A hidden instruction in any of those inputs can tell the agent to copy a secret, add a backdoor, or ignore the rules you wrote down. The diff looks normal. Tripwire is the check that fails before merge.

## Install

Add this workflow. It scans every pull request, not only ones that look like they came from an agent. `fetch-depth: 0` is required so both commits are on disk. The action does not take a token and does not phone home.

```yaml
name: tripwire
on:
  pull_request:
jobs:
  tripwire:
    runs-on: ubuntu-latest
    permissions:
      contents: read
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
      - uses: 8bybfvp9kw-byte/tripwire@v1
```

The action is [8bybfvp9kw-byte/tripwire](https://github.com/8bybfvp9kw-byte/tripwire). `action.yml` is at the repository root, and the `v1` tag includes `dist/`, so the check runs without a separate build.

Plant the canaries once, from a checkout of this repo, and commit what it writes:

```bash
npm install
npm run build
node dist/src/cli.js init
```

## A failing check

`tripwire demo` builds a throwaway repo, plants canaries, and applies a simulated hijacked-agent diff. The plant commit passes. The hijack below is real output from `tripwire demo --seed public`. The same text is in `fixtures/demo-output.txt`.

```
Tripwire scan: FAIL
4 findings at or above low. 4 total.

CRITICAL secret-github-pat  src/client.ts:2
  Synthetic GitHub-shaped canary (gh_tripwire_ prefix, not a GitHub credential). It appeared in src/client.ts, outside .tripwire/decoys/credentials.example.
  2 | const token = "gh_tripw…0CLK";

HIGH     marker-agents  tripwire-signal-agents.txt:1
  Hidden instruction in AGENTS.md tells an agent to add this marker. It appeared in tripwire-signal-agents.txt.
  1 | TRIPWIRE_SIGNAL_tw456e3477_agents

HIGH     tamper-.tripwire/GUARD.txt  .tripwire/GUARD.txt:1
  Canary file .tripwire/GUARD.txt was deleted.

HIGH     url-agents  src/client.ts:3
  Hidden instruction in AGENTS.md tells an agent to add this callback URL. It appeared in src/client.ts.
  3 | // https://canary.tripwire.invalid/h/tw456e3477/agents

Agent signals (informational; every pull request is scanned):
- head branch "cursor/hijack-demo" matches an agent branch prefix
- commit trailer Co-authored-by: Copilot looks like a coding agent
```

The branch name and the `Co-authored-by` trailer are tags. They do not decide pass or fail. A human branch with the same diff fails the same way. The commit that only plants the canaries prints `Tripwire scan: PASS`.

Re-run that diff locally:

```bash
node dist/src/cli.js scan fixtures/demo-repo --diff fixtures/hijacked.diff
```

The command exits 1.

## How it works

`tripwire init` writes three kinds of canary, plus `tripwire.config.json` and `.tripwire/manifest.json`. The manifest stores SHA-256 hashes of the canary values, not the values themselves.

- **Decoy secrets** in `.tripwire/decoys/credentials.example`. Unique `gh_tripwire_`, `sk_tripwire_`, `aws_tripwire_`, and `aws_tripwire_secret_` values. They are not GitHub, Stripe, or AWS credentials, and they do not use those providers' key prefixes. A diff that copies one into any other file is `critical`.
- **Instruction canaries** in `AGENTS.md`, `docs/onboarding.md`, and `.github/ISSUE_TEMPLATE/bug_report.md`. Each is an HTML comment between `tripwire:start` and `tripwire:end` markers. It tells an agent to add a marker line and a URL on `canary.tripwire.invalid`. It also says not to send a request. If that marker or URL shows up outside the block, the finding is `high`.
- **A guard file**, `.tripwire/GUARD.txt`. Deleting it, renaming it, or changing its bytes is `high`. Editing the rest of `AGENTS.md` is not. Editing the canary block is.

`tripwire scan` reads a unified diff. With no flags it compares the worktree to `HEAD`. `--range base...head` is what the action runs. Added lines are matched by the tripwire prefix and then by hash, so an unrelated string does not alert. Secret values are redacted in the report. The line number is not.

`tripwire rotate` replaces the values and keeps the previous hashes armed, so a leak of the old secret still fails. That commit also changes the manifest, which is itself a finding until a maintainer bypasses the check or sets `allow-manifest-edits`. `tripwire remove` deletes managed files and strips the blocks. It leaves `tripwire.config.json` in place.

Put `.tripwire/**` and `tripwire.config.json` in `CODEOWNERS`. An agent that understands the manifest can try to disarm the alarm by editing it. The manifest edit is the signal, and a person should be the one who merges it.

## CLI

```
tripwire init [dir] [--seed <string>] [--dry-run]
tripwire scan [dir] [--diff <file>] [--range <git-range>] [--format text|json]
              [--fail-on info|low|medium|high|critical] [--allow-manifest-edits]
              [--branch <name>] [--actor <login>]
tripwire rotate [dir] [--dry-run]
tripwire remove [dir] [--dry-run]
tripwire demo [--seed public] [--emit <dir>]
```

`--fail-on critical` fails only secret leaks and a deleted manifest. The default is `low`, so every current finding fails the check. Scan exits 0 for pass, 1 for findings, 2 for a broken invocation.

## Config

`tripwire.config.json` is written on the first `init` if you do not already have one. Paths are relative. `..` is rejected.

```json
{
  "version": 1,
  "failOn": "low",
  "allowManifestEdits": false,
  "ignore": ["node_modules/**", "dist/**", "build/**", "vendor/**", "**/*.lock", "package-lock.json"],
  "ignoreSecretsInIgnoredPaths": false,
  "placements": [
    { "path": ".tripwire/decoys/credentials.example", "type": "secrets", "id": "secrets" },
    { "path": ".tripwire/GUARD.txt", "type": "guard", "id": "guard" },
    { "path": "AGENTS.md", "type": "instruction", "id": "agents" },
    { "path": "docs/onboarding.md", "type": "instruction", "id": "onboarding" },
    { "path": ".github/ISSUE_TEMPLATE/bug_report.md", "type": "instruction", "id": "issue" }
  ]
}
```

`ignore` drops marker, URL, and guard-noise hits in generated files. A canary secret in an ignored path still fails the check, unless you set `ignoreSecretsInIgnoredPaths` to true. Write the config before `init` if you want different files. `init` will not clobber an existing file that it does not own.

## FAQ

### Is this safe?

Yes, if you use the values `tripwire init` generates and you do not edit them into something real.

The decoys use `gh_tripwire_`, `sk_tripwire_`, `aws_tripwire_`, and `aws_tripwire_secret_` prefixes. They were not issued by GitHub, Stripe, or AWS, so they cannot authenticate. Those prefixes are not the provider prefixes push protection looks for. The callback host is `canary.tripwire.invalid`. `.invalid` is reserved by RFC 2606 and does not resolve. Tripwire never sends a request to it. The planted instruction says not to send one either.

The credentials file says, in the first lines, that the values are synthetic. `tripwire remove` deletes that file, the guard file, and the canary blocks.

### Limits and false negatives

A pass means this diff did not trip the alarm. It does not mean the agent was safe.

Tripwire does not see a secret that leaves the machine without being written into the diff, the pull request body, or a commit message. It does not reassemble a value that was split across lines, base64-encoded, or lightly edited. It does not scan your network. An attacker who has read the canary file can tell the agent to avoid those exact strings. Unique values raise that bar, and they do not close it. A model that carefully ignores every hidden instruction will not trip the canary, and it will also ignore the attacker's instruction. That is the case this alarm is built for, and it is not a proof.

### False positives

Matching is exact, by hash, so a tutorial that pastes the AWS documentation example does not alert. Editing `AGENTS.md` outside the `tripwire:start` / `tripwire:end` block does not alert. Editing the block does. `tripwire rotate` changes the manifest on purpose and the check fails until a person lets it through. A build that commits a copy of the credentials file will alert, including under `dist/`, because secrets are not silenced by `ignore` unless you opt in.

### Does it only scan bot pull requests?

No. Every pull request is scanned. If the head branch starts with `cursor/`, `claude/`, `copilot/`, `codex/`, `devin/`, `aider/`, `sweep/`, or `agent/`, or the author, a commit author, or a `Co-authored-by` trailer matches a known agent name or a `[bot]` login, the report says so. That is a tag, not a filter.

### Will GitHub push protection block the canaries?

The planted strings are not provider key shapes, so GitHub push protection should not treat `.tripwire/decoys/credentials.example` as a leaked Stripe, AWS, or GitHub credential. Do not "fix" a finding by replacing a canary with a real key. If another scanner still flags the file, allowlist that path. The values are synthetic.

### Who is it from?

No Hype Just Art. MIT license. Source: https://github.com/8bybfvp9kw-byte/tripwire. See [CONTRIBUTING.md](CONTRIBUTING.md) for how to add a canary format without turning the bait into a real instruction.
