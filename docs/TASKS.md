# TASKS.md

Every user-requested task is recorded here before work starts.
Each task is one `###` entry with these fields, in this order:

- **id**: short slug, `YYYY-MM-DD-kebab-name`. Unique in this file.
- **title**: what the task delivers, 3 to 8 words.
- **Status**: `todo`, `in progress`, `done`, or `blocked: <reason>`.

---

## Open

### 2026-10-25-zod4-audit-fix Upgrade zod and fix audit advisories for 2.3.0

Status: in progress. Apply `npm audit fix` (body-parser 2.3.0 to 2.4.0, lockfile only) and zod ^4.6.7 (GHSA-mrhx-c7xc-m3w5), run tsc and npm test, bump to 2.3.0, tag and release. Tested on throwaway copies first: tsc clean, 21 of 21 tests pass, `dist/` identical. Known client-visible changes: tool JSON Schemas no longer advertise `additionalProperties: false`, and validation error wording changes.

<!-- Add new entries above this line. Move finished entries to Done. -->

## Done

<!-- Keep the entry; change Status to done. -->

### 2026-10-24-judge-chain-refactor Judge chain refactor for v2.2.4

Status: done. Committed as 5514dc3. The in-session `verify_adversarial_diff` could not run (the server resolved its git root to /home/paulk, and it diffs against a baseline locked at HEAD), so the diff was checked with the outside judges directly: zCode and reasonix both returned PASS on `git diff origin/main...HEAD`. 21 of 21 tests pass and a fresh build leaves `dist/` unchanged. Fast-forward merged into main (bfde9dd) on 2026-10-25.

### 2026-10-24-v224-version-decision Decide version bump and tag for v2.2.4

Status: done. Bumped to 2.2.4 in package.json, package-lock.json, src/server.ts and the rebuilt dist/server.js (be29557). Annotated tag v2.2.4 and GitHub release v2.2.4 created on 2026-10-25; CI passed on be29557.

### 2026-10-24-dist-orphan-fixture Verify dist orphan check on fixtures

Status: done. The extracted ci.yml check passed on an all-matched fixture (exit 0) and failed on nested orphans .js and .js.map (exit 1, with the expected message).
