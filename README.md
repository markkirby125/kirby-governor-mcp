# Kirby Autonomous Engineering Governor MCP (`kirby-governor-mcp`)

Zero-trust Model Context Protocol (MCP) governance server implementing Felix Rieseberg's 4-pillar engineering workflow (**Altitude, Depth, Range, Resources / Grounding Triad**) and decoupled **Cross-Model Adversarial Diff Verification**.

### 🪄 The Magic Prompt
Copy and paste this into any AI coding app (Cursor, Windsurf, Claude Code, Grok, Kimi, Reasonix):

```markdown
@agent Install the Kirby Autonomous Engineering Governor MCP skill from: https://github.com/markkirby125/kirby-governor-mcp
1. Read `SKILL.md` and `references/` from the repository.
2. Place into your environment's skills/rules directory preserving the dispatcher structure.
3. Build the MCP server (`npm install && npm run build`) and register `dist/server.js` under `mcpServers.kirby-governor-mcp`.
4. Confirm when installation is complete.
```

## Tools Exposed

1. **`compile_execution_contract`**: Locks an outcome-anchored contract (Altitude + 4-Part Depth + Empirical Proof Command + `base_sha`) to `.governor/contracts/<id>.json` with circuit-breaker immutability protection.
2. **`inspect_system_telemetry`**: Implements the Grounding Triad (`crash_and_logs` with stack deduplication & symlink-escape blocking, `version_commit_map`, and `reproduce_and_test`).
3. **`verify_adversarial_diff`**: Runs the deterministic `proof_command` pre-gate (blocking inline eval flags), extracts a lockfile-free & secret-redacted git diff (preserving git index state for untracked files), short-circuits on matching `verified_tree_hash`, and pipes unverified diffs over `stdin` to a cross-model outside judge CLI (`codex`, `reasonix`, `zcode`, `claude`) with a 3-strike `ESCALATE_TO_HUMAN` circuit breaker.
4. **`orchestrate_range_crew`**: Reframes nouns into human-outcome verbs and executes a sequential multi-disciplinary specialist review pipeline with bounded context windows.

## Feature Switches (Environment Variables)

- `KIRBY_GOVERNOR_REDACT_SECRETS` (default `"1"`): Excludes `.env*`/`*.pem`/`*.key` files and redacts inline API keys/tokens before dispatching diffs to external judge CLIs. Set to `"0"` to disable.
- `KIRBY_GOVERNOR_CACHE_VERIFIED_DIFF` (default `"1"`): Short-circuits `verify_adversarial_diff` with zero LLM token burn when `status === "PASSED"` and the SHA-256 `treeHash` matches `verified_tree_hash`, while invalidating `PASSED` back to `ACTIVE` if post-pass file drift occurs. Set to `"0"` to disable.
- `KIRBY_GOVERNOR_ENABLE_ZCODE_JUDGE` (default `"1"`): Includes `zcode` (`zcode -p -`) in the cross-model outside judge rotation. Set to `"0"` to disable.
