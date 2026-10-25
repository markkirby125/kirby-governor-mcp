# TASKS.md

Every user-requested task is recorded here before work starts.
Each task is one `###` entry with these fields, in this order:

- **id**: short slug, `YYYY-MM-DD-kebab-name`. Unique in this file.
- **title**: what the task delivers, 3 to 8 words.
- **Status**: `todo`, `in progress`, `done`, or `blocked: <reason>`.

---

## Open

<!-- Add new entries above this line. Move finished entries to Done. -->

### 2026-10-24-judge-chain-refactor Judge chain refactor for v2.2.4

Status: blocked: verify_adversarial_diff could not run from this session. The governor MCP server resolved its git root to /home/paulk, not this repo. Committed on refactor/judge-chain-split as 5514dc3; needs verify before merge.

### 2026-10-24-v224-version-decision Decide version bump and tag for v2.2.4

Status: todo. Package version is still 2.2.3. Needs the user: bump, tag and release are outward-facing.

## Done

<!-- Keep the entry; change Status to done. -->

### 2026-10-24-dist-orphan-fixture Verify dist orphan check on fixtures

Status: done. The extracted ci.yml check passed on an all-matched fixture (exit 0) and failed on nested orphans .js and .js.map (exit 1, with the expected message).
