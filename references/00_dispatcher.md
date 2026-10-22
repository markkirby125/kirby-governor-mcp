# SOP: Kirby Autonomous Engineering Governor MCP (`kirby-governor-mcp`) — Dispatcher

> Ambient, zero-trust Model Context Protocol (MCP) governance layer implementing Felix Rieseberg's 4-pillar engineering framework (*Altitude, Depth, Range, Resources / Grounding Triad*) and William Fitzpatrick's 3D Architectural Grounding (*Z1 Memory Lifecycle, Z2 Concurrency Model, Z3 FMEA*).

**Related Skills:**
* Security & Zero-Trust MCP Auditing: [`../../kirby-agent-security/SKILL.md`](../../kirby-agent-security/SKILL.md)
* Adversarial Code Review Standards: [`../../kirby-open-code-review/SKILL.md`](../../kirby-open-code-review/SKILL.md)
* Deterministic Gate Workflows: [`../../kirby-helix-workflow/SKILL.md`](../../kirby-helix-workflow/SKILL.md)

---

## 1. Core Mandate & Failure Modes Prevented

Standard conversational coding sessions suffer from four failure modes:
1. **The Persona Fallacy:** Asking an agent to *"act like a principal engineer"* changes surface tone without changing data sources, tools, or verification rigor.
2. **Minimal Viable Completion (Altitude Deficit):** Agents complete the literal task (*"build a dashboard"*) with passive vanity numbers rather than solving the operational outcome (*"show why hiring is slow and which 3 decisions to make today"*).
3. **Single-Discipline Tunnel Vision (Range Deficit):** One model evaluates the app from one angle rather than reframing nouns into human-outcome verbs and running sequential specialist passes.
4. **Circular Self-Grading:** A model reviewing its own diff shares the exact assumptions and blind spots that created the bug.

`kirby-governor-mcp` eliminates these failure modes via **four stateful MCP tools** backed by zero-shell-interpolation subprocess execution (`spawn` with `shell: false` and `stdin` piping).

---

## 2. The 4-Tool Governance Lifecycle

### Tool 1: `compile_execution_contract` (Altitude + 4-Part Depth Gate)
Must be called **before** mutating application files. The agent inspects the repository and registers a verified contract persisted atomically to `.governor/contracts/<contract_id>.json`:
* **Altitude:** `ultimate_outcome` (the goal beyond the literal task) + `decisions_enabled` (actionable decisions or automated remediations; zero passive displays).
* **Depth (Felix's 4-Part Prompt):**
  1. `unasked_expert_actions`: What a top domain specialist would do here without being asked.
  2. `raw_data_sources`: The rawest files, schemas, or telemetry inspected before coding.
  3. `expert_methods_and_tools`: Specific profilers, AST checks, or statistical/invariant models used.
  4. `unreasonable_target`: Extreme performance/correctness target (e.g., `<50ms P99`, `0 unhandled boundary states`) that prevents superficial tweaking.
* **Empirical Gate:** `proof_command` — the exact deterministic test command that must exit `0` before any LLM judge is called.
* **Baseline & Immutability Lock:** Captures and locks `base_sha` (`git rev-parse HEAD`), initializes `review_cycle_count = 0`, and blocks overwriting any contract where `review_cycle_count > 0` or `status !== "ACTIVE"`.

### Tool 2: `inspect_system_telemetry` (The Grounding Triad)
Connects the agent to empirical ground truth across three modes:
* `crash_and_logs`: Reads repository logs (strictly contained within `REPO_ROOT` via `realpathSync` symlink validation) and deduplicates repetitive stack frames.
* `version_commit_map`: Maps recent commits, branches, and release tags (`git log --graph --oneline --decorate`) to correlate regressions with code changes.
* `reproduce_and_test`: Executes an allowlisted test runner (`npm_test`, `vitest`, `pytest`, `go_test`, `cargo_test`) to reproduce crashes and verify fixes empirically.

### Tool 3: `verify_adversarial_diff` (Deterministic Pre-Gate + Cross-Model Outside Judge)
Enforces decoupled verification before task completion:
1. **Stage A (Zero-Token Deterministic Pre-Gate):** Runs the contract's `proof_command` (blocking inline code execution flags such as `-e` or `-c`). If it exits non-zero, rejects immediately with test output—burning **zero** external LLM tokens.
2. **Stage B (Clean & Secret-Redacted Diff Extraction):** Captures untracked files via temporary `git add -N` (restoring index state in `finally`), strips lockfiles and `.env*`/`*.pem`/`*.key` files, and redacts inline credentials (`sk-...`, `ghp_...`, `AKIA...`, PEM blocks).
3. **Stage B.2 (Cryptographic Tree-Hash Short-Circuit):** If `status === "PASSED"` and the current SHA-256 `treeHash` matches `verified_tree_hash`, returns an instant cached `VERDICT: PASS` with zero external LLM calls. If the working tree mutated after passing, automatically invalidates `PASSED` back to `ACTIVE`.
4. **Stage C (Cross-Model Outside Judge):** Selects an installed CLI from a **different model family** than `primary_agent_family` (`codex`, `reasonix`, `zcode`, `claude`), pipes the contract + 3D audit rules (`[MEMORY]`, `[CONCURRENCY]`, `[FAILURE]`, `[SHALLOW-SPEC]`) + diff over `stdin`, and checks the final line for `VERDICT: PASS` vs `BLOCKING ISSUE: [file:line]`.
5. **3-Strike Circuit Breaker:** Increments `review_cycle_count` on each rejection. At 3 rejections, locks contract status to `ESCALATED` and returns `ESCALATE_TO_HUMAN`.

### Tool 4: `orchestrate_range_crew` (Noun-to-Verb Multi-Disciplinary Pipeline)
Implements Felix Rieseberg's **Range** workflow:
1. Requires `verb_reframing` — replacing nouns (*what the app is*) with human-outcome verbs (*what the app does for people*).
2. Executes 2–4 domain specialists **strictly sequentially**, feeding each specialist's bounded findings forward so every pass builds on the prior discipline's audit.

---

## 3. MCP Registration & CLI Usage

### Build & Test
```bash
cd /home/paulk/Desktop/SKILLS/kirby-skills/kirby-governor-mcp
npm install
npm test
```

### Register in `.claude.json` or MCP Config
```json
{
  "mcpServers": {
    "kirby-governor-mcp": {
      "command": "node",
      "args": ["/home/paulk/Desktop/SKILLS/kirby-skills/kirby-governor-mcp/dist/server.js"],
      "env": {
        "KIRBY_GOVERNOR_REDACT_SECRETS": "1",
        "KIRBY_GOVERNOR_CACHE_VERIFIED_DIFF": "1",
        "KIRBY_GOVERNOR_ENABLE_ZCODE_JUDGE": "1"
      }
    }
  }
}
```
