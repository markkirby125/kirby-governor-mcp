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
3. **`verify_adversarial_diff`**: Runs the deterministic `proof_command` pre-gate (blocking inline eval flags), extracts a lockfile-free & secret-redacted git diff (preserving git index state for untracked files), short-circuits on matching `verified_tree_hash`, and sends unverified diffs to a cross-model outside judge chain: `zcode` first (diff attached as a file, because `zcode -p` ignores stdin), then `reasonix` with `deepseek-flash` as failover (diff over `stdin`), then `codex` and `claude`. A judge that exits with empty output hands the diff to the next one. The chain ends in `JUDGE_UNAVAILABLE` only when every judge fails. A 3-strike `ESCALATE_TO_HUMAN` circuit breaker applies.
4. **`orchestrate_range_crew`**: Reframes nouns into human-outcome verbs and executes a sequential multi-disciplinary specialist review pipeline with bounded context windows.

## Outside Judge Chain

`verify_adversarial_diff` sends unverified diffs to an outside judge CLI from a different model family than the primary agent. Candidates run in this order:

1. **`zcode`** (`zcode-cli`): the diff is written to a temporary file and passed with `--attach`, because `zcode -p` ignores stdin. The file is deleted after the call.
2. **`reasonix`** (`reasonix-cli`): runs as `reasonix -p --model deepseek-flash --output-format text`, with the diff on stdin.
3. **`codex`** (`codex-cli`): runs as `codex exec -`, with the diff on stdin.
4. **`claude`** (`claude-cli`): runs as `claude -p -`, with the diff on stdin.

Only CLIs found on `PATH` are used. A candidate from the same model family as the primary agent is tried last.

The chain moves on to the next judge when a judge produces empty stdout. That covers a non-zero exit with no output, a spawn error, and a 120-second timeout. The first judge that writes stdout is used. If every judge fails, the tool returns `JUDGE_UNAVAILABLE` with each attempt's reason.

Setting `KIRBY_GOVERNOR_JUDGE_CMD` replaces the whole chain with the single command you give (a JSON array or a shell-style string).

## Feature Switches (Environment Variables)

- `KIRBY_GOVERNOR_REDACT_SECRETS` (default `"1"`): Excludes `.env*`/`*.pem`/`*.key` files and redacts known credential formats (PEM keys, OpenAI/Anthropic, GitHub, AWS, Google `AIza`, Slack, JWTs, and `SECRET`/`TOKEN`/`PASSWORD`/`API_KEY` assignments) before dispatching diffs to external judge CLIs. Note: redaction is pattern-based defense-in-depth; avoid committing custom unencrypted secret formats in tracked source files. Set to `"0"` to disable.
- `KIRBY_GOVERNOR_EXCLUDE_SECRET_FILES` (default `"1"`): Independently controls pathspec exclusion of `.env*`, `*.pem`, and `*.key` files during diff extraction.
- `KIRBY_GOVERNOR_CACHE_VERIFIED_DIFF` (default `"1"`): Short-circuits `verify_adversarial_diff` with zero LLM token burn when `status === "PASSED"` and the SHA-256 `treeHash` matches `verified_tree_hash`, while invalidating `PASSED` back to `ACTIVE` if post-pass file drift occurs. Set to `"0"` to disable.
- `KIRBY_GOVERNOR_ENABLE_ZCODE_JUDGE` (default `"1"`): Puts `zcode` first in the [outside judge chain](#outside-judge-chain). Set to `"0"` to remove it; `reasonix`, `codex` and `claude` then run in that order.
