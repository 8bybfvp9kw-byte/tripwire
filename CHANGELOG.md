# Changelog

## 1.1.0

- The GitHub Action loads `tripwire.config.json` and `.tripwire/manifest.json` from `origin/<base>`, not from the pull request head.
- A pull request that edits `.tripwire/**`, `tripwire.config.json`, or a workflow that mentions Tripwire is a high finding: "Guard files changed." The pull request cannot suppress that finding.
- The Action scans the pull request title, the pull request body, and commit messages from `git log base..head`, in addition to the diff.

## 1.0.0

- Initial release. Plant inert canaries, scan a diff, and fail the check when one is tripped.
