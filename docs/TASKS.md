# TASKS.md

Every user-requested task is recorded here before work starts.
Each task is one `###` entry with these fields, in this order:

- **id**: short slug, `YYYY-MM-DD-kebab-name`. Unique in this file.
- **title**: what the task delivers, 3 to 8 words.
- **Status**: `todo`, `in progress`, `done`, or `blocked: <reason>`.

---

## Open

### 2026-11-22-judge-attempts-in-contract Save judge attempts to the contract

Status: in progress. Built and tested (29 of 29): commits 19c84e2, 73f5cfc, 43f490e on branch `feat/judge-attempts-in-contract`, unpushed. The governor now saves judge attempts and a JUDGE_UNAVAILABLE entry to the contract history, tells judges to use no tools (rule 6, because agentic judges tried to read files and timed out), caps each reason fairly, and reloads the contract before the failure save. Its own gate (contract `gov-judge-attempts`) is at cycle 1 of 3: REJECT from claude-cli (same family), three of four findings fixed; the fourth (save after every attempt, so a killed server still keeps the reasons) was left out on purpose. Cycle 2 not run. Open: run cycle 2; decide whether to push; reasonix still times out at 120 s on real payloads (raise its timeout); codex fails on the model set in the user's Codex config.

<!-- Add new entries above this line. Move finished entries to Done. -->

## Done

<!-- Keep the entry; change Status to done. -->

### 2026-10-25-zod4-audit-fix Upgrade zod and fix audit advisories for 2.3.0

Status: done. zod ^3.23.8 to ^4.6.7 and `npm audit fix` (body-parser 2.4.0) committed as a52d43d; `npm audit` reports 0 vulnerabilities. Version bumped to 2.3.0 (b45f170), CI green, annotated tag v2.3.0 and GitHub release v2.3.0 created on 2026-10-25. Tested on throwaway copies first: tsc clean, 21 of 21 tests pass. Client-visible changes: tool JSON Schemas no longer advertise `additionalProperties: false`, validation error wording changes, and the exported `ContractRecordSchema` types use zod 4 types.

### 2026-10-24-judge-chain-refactor Judge chain refactor for v2.2.4

Status: done. Committed as 5514dc3. The in-session `verify_adversarial_diff` could not run (the server resolved its git root to /home/paulk, and it diffs against a baseline locked at HEAD), so the diff was checked with the outside judges directly: zCode and reasonix both returned PASS on `git diff origin/main...HEAD`. 21 of 21 tests pass and a fresh build leaves `dist/` unchanged. Fast-forward merged into main (bfde9dd) on 2026-10-25.

### 2026-10-24-v224-version-decision Decide version bump and tag for v2.2.4

Status: done. Bumped to 2.2.4 in package.json, package-lock.json, src/server.ts and the rebuilt dist/server.js (be29557). Annotated tag v2.2.4 and GitHub release v2.2.4 created on 2026-10-25; CI passed on be29557.

### 2026-10-24-dist-orphan-fixture Verify dist orphan check on fixtures

Status: done. The extracted ci.yml check passed on an all-matched fixture (exit 0) and failed on nested orphans .js and .js.map (exit 1, with the expected message).
