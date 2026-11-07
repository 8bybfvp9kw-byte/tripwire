# Contributing

Tripwire is a small scanner. Changes should stay small enough to read in one sitting.

## Develop

Node 20 or newer. There are no runtime dependencies.

```bash
npm install
npm test
npm run demo
```

`npm test` compiles TypeScript and runs the tests. The GitHub Action runs `dist/src/action.js`, so commit `dist/` after a build. CI rejects a `dist/` tree that does not match the source.

## Adding a canary format

1. Generate the value in `src/tokens.ts`. It must be unique per repository, recognizable as that provider's shape, and unable to authenticate. If the provider publishes a checksum, fail it on purpose.
2. Add a `CanaryFormat` and an extractor in `src/match.ts`. Extractors are hardcoded. Do not run regular expressions stored in the manifest.
3. Plant it from `src/plant.ts` and cover it with a scan test.
4. Keep the bait inert. Do not tell an agent to call a real host, exfiltrate a real secret, or change security settings. Callback URLs stay on `canary.tripwire.invalid` (RFC 2606).

## What not to send

Do not open an issue or pull request that contains a real token, a personal email address, a wallet address, or an account id. Canary values in fixtures are synthetic and must keep the `gh_tripwire_`, `sk_tripwire_`, and `aws_tripwire_` prefixes. If a demo prints a provider key prefix followed by a key body, stop and fix the generator.

## Reporting a problem

Open a GitHub issue at https://github.com/8bybfvp9kw-byte/tripwire/issues. Describe the diff you scanned and the finding you expected. Do not paste live credentials. A failing check on `tripwire rotate` is the manifest-edited finding, not a scanner bug.
