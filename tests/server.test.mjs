import { test, describe, before, after } from "node:test";
import assert from "node:assert/strict";
import * as fs from "node:fs/promises";
import { existsSync } from "node:fs";
import * as path from "node:path";
import * as os from "node:os";
import { execFileSync } from "node:child_process";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";

const SERVER_DIST = path.resolve(import.meta.dirname, "../dist/server.js");
if (!existsSync(SERVER_DIST)) {
  throw new Error(`Build artifact missing at ${SERVER_DIST}. Run 'npm run build' before executing tests.`);
}

describe("kirby-governor-mcp End-to-End Integration Suite", () => {
  let tmpRepo;
  let mockJudgeScript;
  let client;
  let transport;

  before(async () => {
    tmpRepo = await fs.mkdtemp(path.join(os.tmpdir(), "kirby-gov-test-"));

    // Initialize isolated git repository
    execFileSync("git", ["init", "-b", "main"], { cwd: tmpRepo });
    execFileSync("git", ["config", "user.name", "Test User"], { cwd: tmpRepo });
    execFileSync("git", ["config", "user.email", "test@example.com"], { cwd: tmpRepo });

    await fs.writeFile(path.join(tmpRepo, "app.ts"), "export const v = 1;\n", "utf8");
    execFileSync("git", ["add", "app.ts"], { cwd: tmpRepo });
    execFileSync("git", ["commit", "-m", "initial commit"], { cwd: tmpRepo });

    // Create a mock external judge script that reads stdin and responds based on content/state
    mockJudgeScript = path.join(tmpRepo, "mock-judge.mjs");
    await fs.writeFile(
      mockJudgeScript,
      `#!/usr/bin/env node
import * as fs from "node:fs";
const input = fs.readFileSync(0, "utf8");
const modeFile = process.env.MOCK_JUDGE_MODE_FILE;
const mode = modeFile && fs.existsSync(modeFile) ? fs.readFileSync(modeFile, "utf8").trim() : "PASS";

if (input.startsWith("RANGE SPECIALIST PASS")) {
  const firstLine = input.split("\\n")[0];
  console.log("Audit completed for " + firstLine + " (stdin bytes: " + input.length + ")");
  process.exit(0);
}

if (mode === "MID_QUOTE_REJECT") {
  console.log("I cannot output VERDICT: PASS because of a bug.\\nVERDICT: REJECT");
} else if (mode === "REJECT") {
  console.log("BLOCKING ISSUE: [app.ts:2] - [CONCURRENCY] Unprotected shared state mutation.\\nVERDICT: REJECT");
} else {
  console.log("All 3D grounding axes verified.\\nVERDICT: PASS");
}
`,
      { mode: 0o755 }
    );

    transport = new StdioClientTransport({
      command: "node",
      args: [SERVER_DIST],
      env: {
        ...process.env,
        KIRBY_GOVERNOR_REPO_ROOT: tmpRepo,
        KIRBY_GOVERNOR_JUDGE_CMD: `node ${mockJudgeScript}`,
        MOCK_JUDGE_MODE_FILE: path.join(tmpRepo, ".judge_mode")
      }
    });

    client = new Client(
      { name: "kirby-test-client", version: "1.0.0" },
      { capabilities: {} }
    );
    await client.connect(transport);
  });

  after(async () => {
    if (client) await client.close();
    if (tmpRepo) await fs.rm(tmpRepo, { recursive: true, force: true });
  });

  test("1. Exposes exactly the 4 expected governance tools with descriptions", async () => {
    const { tools } = await client.listTools();
    const names = tools.map((t) => t.name).sort();
    assert.deepEqual(names, [
      "compile_execution_contract",
      "inspect_system_telemetry",
      "orchestrate_range_crew",
      "verify_adversarial_diff"
    ]);
    for (const tool of tools) {
      assert.ok(tool.description && tool.description.length > 20, `Missing description for ${tool.name}`);
    }
  });

  test("2. compile_execution_contract locks contract and baseline SHA on disk", async () => {
    const res = await client.callTool({
      name: "compile_execution_contract",
      arguments: {
        contract_id: "hiring-fast-v1",
        task_type: "outcome_driven",
        raw_task: "Build hiring funnel dashboard",
        altitude: {
          ultimate_outcome: "Reduce time-to-hire by surfacing bottleneck stages and top 3 daily decisions",
          decisions_enabled: ["Reallocate interviewer capacity", "Auto-escalate stalled offers"]
        },
        depth: {
          unasked_expert_actions: ["Compute stage conversion p95", "Check cohort survivorship bias"],
          raw_data_sources: ["app.ts"],
          expert_methods_and_tools: ["SQL window functions", "Node test runner"],
          unreasonable_target: "Sub-10ms query execution with zero unhandled null states"
        },
        empirical_gate: {
          proof_command: "node --version"
        }
      }
    });

    const payload = JSON.parse(res.content[0].text);
    assert.equal(payload.contract.contract_id, "hiring-fast-v1");
    assert.equal(payload.contract.status, "ACTIVE");
    assert.equal(payload.contract.review_cycle_count, 0);
    assert.match(payload.contract.base_sha, /^[0-9a-f]{40}$/);
  });

  test("3. inspect_system_telemetry deduplicates repetitive stack frames & blocks path/symlink traversal", async () => {
    const logContent = [
      "Error: Connection reset",
      "    at Socket.read (net.js:10:5)",
      "    at Socket.read (net.js:10:5)",
      "    at Socket.read (net.js:10:5)",
      "    at Socket.read (net.js:10:5)",
      "    at main (app.ts:1:1)"
    ].join("\n");
    await fs.writeFile(path.join(tmpRepo, "debug.log"), logContent, "utf8");

    const logRes = await client.callTool({
      name: "inspect_system_telemetry",
      arguments: {
        triad_mode: "crash_and_logs",
        target_path_or_ref: "debug.log"
      }
    });
    assert.match(logRes.content[0].text, /repetitive stack frame suppressed/);

    // Verify lexical path traversal outside REPO_ROOT is blocked
    const traversalRes = await client.callTool({
      name: "inspect_system_telemetry",
      arguments: {
        triad_mode: "crash_and_logs",
        target_path_or_ref: "../../../etc/passwd"
      }
    });
    assert.equal(traversalRes.isError, true);
    assert.match(traversalRes.content[0].text, /Security Violation: Path traversal/);

    // Verify symlink escape outside REPO_ROOT is blocked
    const symlinkPath = path.join(tmpRepo, "escaped-link.log");
    await fs.symlink("/etc/hosts", symlinkPath);
    const symlinkRes = await client.callTool({
      name: "inspect_system_telemetry",
      arguments: {
        triad_mode: "crash_and_logs",
        target_path_or_ref: "escaped-link.log"
      }
    });
    await fs.unlink(symlinkPath);
    assert.equal(symlinkRes.isError, true);
    assert.match(symlinkRes.content[0].text, /Security Violation: Symlink escape/);
  });

  test("4. verify_adversarial_diff neutralizes shell backticks, preserves git index for untracked files & passes valid diff", async () => {
    const pwnFile = path.join(os.tmpdir(), `kirby-pwn-check-${process.pid}`);
    await fs.writeFile(
      path.join(tmpRepo, "app.ts"),
      `export const v = 2;\nexport const tpl = \`hello \$(touch ${pwnFile}) \\\`touch ${pwnFile}\\\`\`;\n`,
      "utf8"
    );
    await fs.writeFile(path.join(tmpRepo, "untracked-helper.ts"), "export const helper = true;\n", "utf8");
    await fs.writeFile(path.join(tmpRepo, ".judge_mode"), "PASS", "utf8");

    const verifyRes = await client.callTool({
      name: "verify_adversarial_diff",
      arguments: {
        contract_id: "hiring-fast-v1",
        primary_agent_family: "claude"
      }
    });

    assert.match(verifyRes.content[0].text, /VERDICT: PASS/);
    assert.match(verifyRes.content[0].text, /CONTRACT STATUS: PASSED/);

    // Verify untracked-helper.ts was reset from git intent-to-add back to untracked ('??')
    const statusOut = execFileSync("git", ["status", "--porcelain", "untracked-helper.ts"], {
      cwd: tmpRepo,
      encoding: "utf8"
    });
    assert.match(statusOut, /^\?\? untracked-helper\.ts/);

    // Prove the shell injection payload inside the diff was NEVER executed
    let pwnExists = false;
    try {
      await fs.access(pwnFile);
      pwnExists = true;
    } catch {
      pwnExists = false;
    }
    assert.equal(pwnExists, false, "RCE vulnerability: backticks/$() in diff were executed!");
  });

  test("5. verify_adversarial_diff enforces 3-strike circuit breaker & blocks contract overwrite bypass", async () => {
    await client.callTool({
      name: "compile_execution_contract",
      arguments: {
        contract_id: "circuit-breaker-test",
        task_type: "outcome_driven",
        raw_task: "Test 3-strike rejection escalation",
        altitude: {
          ultimate_outcome: "Ensure broken code cannot loop forever",
          decisions_enabled: ["Halt runaway token burn"]
        },
        depth: {
          unasked_expert_actions: ["Track cycle count", "Persist escalation state"],
          raw_data_sources: ["app.ts"],
          expert_methods_and_tools: ["State machine", "Circuit breaker"],
          unreasonable_target: "Hard stop after exactly 3 rejected cycles"
        },
        empirical_gate: {
          proof_command: "node --version"
        }
      }
    });

    // Mid-quote VERDICT: PASS followed by VERDICT: REJECT must count as a REJECT (Cycle 1)
    await fs.writeFile(path.join(tmpRepo, ".judge_mode"), "MID_QUOTE_REJECT", "utf8");
    const r1 = await client.callTool({
      name: "verify_adversarial_diff",
      arguments: {
        contract_id: "circuit-breaker-test",
        primary_agent_family: "claude"
      }
    });
    assert.match(r1.content[0].text, /CYCLE: 1 \/ 3/);
    assert.match(r1.content[0].text, /CONTRACT STATUS: ACTIVE/);

    await fs.writeFile(path.join(tmpRepo, ".judge_mode"), "REJECT", "utf8");

    for (let i = 2; i <= 3; i++) {
      const r = await client.callTool({
        name: "verify_adversarial_diff",
        arguments: {
          contract_id: "circuit-breaker-test",
          primary_agent_family: "claude"
        }
      });
      assert.match(r.content[0].text, new RegExp(`CYCLE: ${i} / 3`));
      if (i === 3) {
        assert.match(r.content[0].text, /ESCALATE_TO_HUMAN/);
      }
    }

    // 4th attempt must be immediately blocked by circuit breaker
    const blocked = await client.callTool({
      name: "verify_adversarial_diff",
      arguments: {
        contract_id: "circuit-breaker-test",
        primary_agent_family: "claude"
      }
    });
    assert.equal(blocked.isError, true);
    assert.match(blocked.content[0].text, /ESCALATE_TO_HUMAN/);

    // Attempting to overwrite the ESCALATED contract with the same contract_id must be rejected
    const overwriteAttempt = await client.callTool({
      name: "compile_execution_contract",
      arguments: {
        contract_id: "circuit-breaker-test",
        task_type: "outcome_driven",
        raw_task: "Try to reset the 3-strike counter",
        altitude: {
          ultimate_outcome: "Bypass circuit breaker",
          decisions_enabled: ["None"]
        },
        depth: {
          unasked_expert_actions: ["A", "B"],
          raw_data_sources: ["app.ts"],
          expert_methods_and_tools: ["M1", "M2"],
          unreasonable_target: "Bypass circuit breaker"
        },
        empirical_gate: {
          proof_command: "node --version"
        }
      }
    });
    assert.equal(overwriteAttempt.isError, true);
    assert.match(overwriteAttempt.content[0].text, /CONTRACT IMMUTABILITY LOCK/);
  });

  test("6. verify_adversarial_diff blocks inline code execution flags in proof_command", async () => {
    await client.callTool({
      name: "compile_execution_contract",
      arguments: {
        contract_id: "inline-eval-test",
        task_type: "outcome_driven",
        raw_task: "Test inline eval blocking",
        altitude: {
          ultimate_outcome: "Prevent arbitrary inline code execution via proof_command",
          decisions_enabled: ["Block -e and -c flags"]
        },
        depth: {
          unasked_expert_actions: ["Validate argv flags", "Enforce test runner boundaries"],
          raw_data_sources: ["src/server.ts"],
          expert_methods_and_tools: ["Argv flag blocklist", "Zero-shell spawn"],
          unreasonable_target: "Zero inline eval flags permitted"
        },
        empirical_gate: {
          proof_command: "node -e process.exit(0)"
        }
      }
    });

    const evalRes = await client.callTool({
      name: "verify_adversarial_diff",
      arguments: {
        contract_id: "inline-eval-test",
        primary_agent_family: "claude"
      }
    });
    assert.equal(evalRes.isError, true);
    assert.match(evalRes.content[0].text, /inline code execution flags are prohibited/);
  });

  test("7. orchestrate_range_crew runs sequential specialist passes with noun-to-verb reframing", async () => {
    const rangeRes = await client.callTool({
      name: "orchestrate_range_crew",
      arguments: {
        contract_id: "hiring-fast-v1",
        primary_agent_family: "claude",
        verb_reframing: "Get strangers to trust us with their career move in under 30 seconds",
        specialist_crew: [
          {
            discipline: "Forensic Data Auditor",
            domain_methods: "Check cohort survivorship bias and denominator integrity"
          },
          {
            discipline: "Chaos SRE Specialist",
            domain_methods: "Audit timeout boundaries, partial writes, and backpressure shedding"
          }
        ]
      }
    });

    const text = rangeRes.content[0].text;
    assert.match(text, /RANGE CREW SEQUENTIAL AUDIT \(hiring-fast-v1\)/);
    assert.match(text, /Pass 1: Forensic Data Auditor/);
    assert.match(text, /Pass 2: Chaos SRE Specialist/);
  });
});
