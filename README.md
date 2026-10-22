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

1. **`compile_execution_contract`**: Locks an outcome-anchored contract (Altitude + 4-Part Depth + Empirical Proof Command + `base_sha`) to `.governor/contracts/<id>.json`.
2. **`inspect_system_telemetry`**: Implements the Grounding Triad (`crash_and_logs` with stack deduplication, `version_commit_map`, and `reproduce_and_test`).
3. **`verify_adversarial_diff`**: Runs the deterministic `proof_command` pre-gate, extracts a lockfile-free git diff (including untracked files via `git add -N`), and pipes it over `stdin` to a cross-model outside judge CLI (`codex`, `reasonix`, `claude`) with a 3-strike `ESCALATE_TO_HUMAN` circuit breaker.
4. **`orchestrate_range_crew`**: Reframes nouns into human-outcome verbs and executes a sequential multi-disciplinary specialist review pipeline.
