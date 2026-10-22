#!/usr/bin/env node
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { spawn } from "node:child_process";
import * as fs from "node:fs/promises";
import { realpathSync } from "node:fs";
import * as path from "node:path";
import * as crypto from "node:crypto";
import { fileURLToPath } from "node:url";
import { z } from "zod";

const REPO_ROOT = path.resolve(process.env.KIRBY_GOVERNOR_REPO_ROOT || process.cwd());
const GOVERNOR_DIR = path.join(REPO_ROOT, ".governor", "contracts");
const MAX_DIFF_BYTES = 200_000;
const MAX_REVIEW_CYCLES = 3;
const MAX_STORED_CONTRACTS = 50;

export interface ContractRecord {
  contract_id: string;
  created_at: string;
  base_sha: string;
  task_type: "outcome_driven" | "creative_exploratory";
  raw_task: string;
  altitude: {
    ultimate_outcome: string;
    decisions_enabled: string[];
  };
  depth: {
    unasked_expert_actions: string[];
    raw_data_sources: string[];
    expert_methods_and_tools: string[];
    unreasonable_target: string;
  };
  empirical_gate: {
    proof_command: string;
  };
  review_cycle_count: number;
  status: "ACTIVE" | "PASSED" | "ESCALATED";
  verified_tree_hash?: string;
  history: Array<{ cycle: number; timestamp: string; judge_cli: string; verdict: string }>;
}

export interface ExecResult {
  exitCode: number;
  stdout: string;
  stderr: string;
}

/**
 * Zero-Trust Subprocess Runner: NEVER invokes /bin/sh.
 * Passes arguments strictly as an argv array and pipes payloads via stdin.
 */
export function runCommandSafe(
  command: string,
  args: string[],
  options: { stdinData?: string; timeoutMs?: number; cwd?: string } = {}
): Promise<ExecResult> {
  const { stdinData, timeoutMs = 120_000, cwd = REPO_ROOT } = options;

  return new Promise((resolve) => {
    const child = spawn(command, args, {
      cwd,
      shell: false,
      stdio: ["pipe", "pipe", "pipe"],
      env: { ...process.env, CI: "true", NO_COLOR: "1" }
    });

    let stdout = "";
    let stderr = "";
    let killedByTimeout = false;

    const timer = setTimeout(() => {
      killedByTimeout = true;
      child.kill("SIGTERM");
      setTimeout(() => child.kill("SIGKILL"), 5_000).unref();
    }, timeoutMs);

    child.stdout.on("data", (chunk: Buffer) => {
      if (stdout.length < MAX_DIFF_BYTES * 2) stdout += chunk.toString("utf8");
    });

    child.stderr.on("data", (chunk: Buffer) => {
      if (stderr.length < MAX_DIFF_BYTES) stderr += chunk.toString("utf8");
    });

    child.on("error", (err) => {
      clearTimeout(timer);
      resolve({ exitCode: 127, stdout, stderr: `${stderr}\nSpawn error: ${err.message}` });
    });

    child.on("close", (code) => {
      clearTimeout(timer);
      if (killedByTimeout) {
        resolve({ exitCode: 124, stdout, stderr: `${stderr}\nProcess timed out after ${timeoutMs}ms` });
      } else {
        resolve({ exitCode: code ?? 1, stdout, stderr });
      }
    });

    if (stdinData !== undefined) {
      child.stdin.write(stdinData, "utf8");
    }
    child.stdin.end();
  });
}

/**
 * Ensures requested file paths stay strictly inside REPO_ROOT.
 */
export function resolveSafeRepoPath(relativePath: string): string {
  const resolved = path.resolve(REPO_ROOT, relativePath);
  if (!resolved.startsWith(REPO_ROOT + path.sep) && resolved !== REPO_ROOT) {
    throw new Error(`Security Violation: Path traversal outside repository root is forbidden: ${relativePath}`);
  }
  return resolved;
}

/**
 * Deduplicates repetitive stack trace frames to preserve agent context budget.
 */
export function deduplicateStackFrames(rawLog: string, maxLines = 120): string {
  const lines = rawLog.split(/\r?\n/);
  const seenFrames = new Map<string, number>();
  const compacted: string[] = [];

  for (const line of lines) {
    const trimmed = line.trim();
    if (trimmed.startsWith("at ")) {
      const count = (seenFrames.get(trimmed) ?? 0) + 1;
      seenFrames.set(trimmed, count);
      if (count <= 2) compacted.push(line);
      else if (count === 3) compacted.push(`    ... [repetitive stack frame suppressed: ${trimmed}]`);
    } else {
      compacted.push(line);
    }
  }
  return compacted.slice(-maxLines).join("\n");
}

export class KirbyGovernorServer {
  private server: McpServer;
  private activeLocks = new Set<string>();

  constructor() {
    this.server = new McpServer({
      name: "kirby-governor-mcp",
      version: "2.0.0"
    });
    this.registerTools();
  }

  private async pruneOldContracts(): Promise<void> {
    try {
      const entries = await fs.readdir(GOVERNOR_DIR);
      const jsonFiles = entries.filter((f) => f.endsWith(".json"));
      if (jsonFiles.length <= MAX_STORED_CONTRACTS) return;

      const stats = await Promise.all(
        jsonFiles.map(async (f) => {
          const full = path.join(GOVERNOR_DIR, f);
          const st = await fs.stat(full);
          return { full, mtimeMs: st.mtimeMs };
        })
      );
      stats.sort((a, b) => b.mtimeMs - a.mtimeMs);
      for (const old of stats.slice(MAX_STORED_CONTRACTS)) {
        await fs.unlink(old.full).catch(() => {});
      }
    } catch {
      // Directory may not exist yet
    }
  }

  private async saveContractAtomically(record: ContractRecord): Promise<void> {
    await fs.mkdir(GOVERNOR_DIR, { recursive: true });
    const filePath = path.join(GOVERNOR_DIR, `${record.contract_id}.json`);
    const tmpPath = `${filePath}.tmp.${process.pid}.${Date.now()}`;
    await fs.writeFile(tmpPath, JSON.stringify(record, null, 2), "utf8");
    await fs.rename(tmpPath, filePath);
    await this.pruneOldContracts();
  }

  private async loadContract(contractId: string): Promise<ContractRecord> {
    const filePath = path.join(GOVERNOR_DIR, `${contractId}.json`);
    const raw = await fs.readFile(filePath, "utf8");
    return JSON.parse(raw) as ContractRecord;
  }

  /**
   * Selects a judge CLI from a DIFFERENT model family than the primary agent [08:01].
   */
  private async selectOutsideJudgeCli(primaryFamily: string): Promise<{ name: string; cmd: string; args: string[] }> {
    if (process.env.KIRBY_GOVERNOR_JUDGE_CMD) {
      const parts = process.env.KIRBY_GOVERNOR_JUDGE_CMD.trim().split(/\s+/);
      return { name: "custom-judge", cmd: parts[0], args: parts.slice(1) };
    }

    const candidates: Array<{ family: string; name: string; cmd: string; args: string[] }> = [
      { family: "codex", name: "codex-cli", cmd: "codex", args: ["exec", "-"] },
      { family: "gemini", name: "reasonix-cli", cmd: "reasonix", args: ["-p", "-", "--model", "deepseek-flash"] },
      { family: "claude", name: "claude-cli", cmd: "claude", args: ["-p", "-"] }
    ];

    const ordered = [
      ...candidates.filter((c) => c.family !== primaryFamily),
      ...candidates.filter((c) => c.family === primaryFamily)
    ];

    for (const candidate of ordered) {
      const check = await runCommandSafe("which", [candidate.cmd], { timeoutMs: 3_000 });
      if (check.exitCode === 0) return candidate;
    }

    throw new Error("No supported external judge CLI (codex, reasonix, claude) found in PATH.");
  }

  /**
   * Captures tracked, staged, and untracked changes against base_sha while excluding lockfiles.
   */
  private async extractCleanDiff(baseSha: string): Promise<{ diff: string; treeHash: string }> {
    await runCommandSafe("git", ["add", "-N", "."], { timeoutMs: 10_000 });

    const diffArgs = [
      "diff",
      baseSha,
      "--",
      ".",
      ":(exclude)package-lock.json",
      ":(exclude)pnpm-lock.yaml",
      ":(exclude)yarn.lock",
      ":(exclude)bun.lockb",
      ":(exclude)dist/**",
      ":(exclude)build/**",
      ":(exclude).governor/**"
    ];

    const res = await runCommandSafe("git", diffArgs, { timeoutMs: 15_000 });
    const rawDiff = res.stdout.slice(0, MAX_DIFF_BYTES);
    const treeHash = crypto.createHash("sha256").update(rawDiff).digest("hex");

    return { diff: rawDiff, treeHash };
  }

  private registerTools() {
    // TOOL 1: Compile & Lock Execution Contract (Altitude + Depth)
    this.server.tool(
      "compile_execution_contract",
      "MANDATORY FIRST STEP before writing or modifying code. Registers an outcome-anchored Execution Contract (Altitude + 4-Part Depth + Empirical Proof Command) and locks the baseline Git SHA.",
      {
        contract_id: z.string().regex(/^[a-zA-Z0-9_-]{3,64}$/).describe("Unique slug for this task"),
        task_type: z.enum(["outcome_driven", "creative_exploratory"]).describe("Task classification [03:51]"),
        raw_task: z.string().min(5).describe("Original user prompt"),
        altitude: z.object({
          ultimate_outcome: z.string().min(15).describe("The high-level outcome beyond the literal task [02:36]"),
          decisions_enabled: z.array(z.string()).min(1).describe("Actionable decisions or remediations surfaced by this change [03:05]")
        }),
        depth: z.object({
          unasked_expert_actions: z.array(z.string()).min(2).describe("(1) What a domain expert would do here without being asked [06:18]"),
          raw_data_sources: z.array(z.string()).min(1).describe("(2) Rawest files/telemetry/schemas inspected before coding [06:21]"),
          expert_methods_and_tools: z.array(z.string()).min(2).describe("(3) Specific methods, profilers, or invariants applied [06:23]"),
          unreasonable_target: z.string().min(10).describe("Extreme target that forces architectural depth over surface tweaking [06:51]")
        }),
        empirical_gate: z.object({
          proof_command: z.string().min(2).describe("(4) Exact CLI test command (e.g. 'npm test') that proves completion [06:26]")
        })
      },
      async (input) => {
        const headRes = await runCommandSafe("git", ["rev-parse", "HEAD"], { timeoutMs: 5_000 });
        const baseSha = headRes.exitCode === 0 ? headRes.stdout.trim() : "HEAD";

        const record: ContractRecord = {
          contract_id: input.contract_id,
          created_at: new Date().toISOString(),
          base_sha: baseSha,
          task_type: input.task_type,
          raw_task: input.raw_task,
          altitude: input.altitude,
          depth: input.depth,
          empirical_gate: input.empirical_gate,
          review_cycle_count: 0,
          status: "ACTIVE",
          history: []
        };

        await this.saveContractAtomically(record);

        return {
          content: [
            {
              type: "text",
              text: JSON.stringify(
                {
                  message: "EXECUTION CONTRACT LOCKED. Proceed with implementation in a clean mental context, then call verify_adversarial_diff.",
                  contract: record
                },
                null,
                2
              )
            }
          ]
        };
      }
    );

    // TOOL 2: Inspect System Telemetry (The Grounding Triad [10:02-11:16])
    this.server.tool(
      "inspect_system_telemetry",
      "Implements the Grounding Triad: (1) deduplicated crash/log inspection, (2) version-to-commit regression mapping, and (3) isolated reproduction test execution.",
      {
        triad_mode: z.enum(["crash_and_logs", "version_commit_map", "reproduce_and_test"]),
        target_path_or_ref: z.string().optional().describe("Relative log file path, git ref/tag, or runner key (npm_test, vitest, pytest, go_test, cargo_test)"),
        filter_pattern: z.string().max(120).optional().describe("Optional filter substring")
      },
      async ({ triad_mode, target_path_or_ref, filter_pattern }) => {
        try {
          if (triad_mode === "crash_and_logs") {
            const safePath = resolveSafeRepoPath(target_path_or_ref || "debug.log");
            const raw = await fs.readFile(safePath, "utf8");
            const filtered = filter_pattern
              ? raw
                  .split(/\r?\n/)
                  .filter((l) => l.includes(filter_pattern))
                  .join("\n")
              : raw;
            return {
              content: [{ type: "text", text: deduplicateStackFrames(filtered) || "No matching log entries." }]
            };
          }

          if (triad_mode === "version_commit_map") {
            const ref = target_path_or_ref && /^[a-zA-Z0-9._/~^-]+$/.test(target_path_or_ref) ? target_path_or_ref : "-n 25";
            const args = ref.startsWith("-n")
              ? ["log", "-n", "25", "--oneline", "--decorate", "--graph"]
              : ["log", `${ref}..HEAD`, "--oneline", "--decorate", "--stat"];
            const res = await runCommandSafe("git", args, { timeoutMs: 10_000 });
            return {
              content: [{ type: "text", text: res.stdout || res.stderr || "No git revision history found." }]
            };
          }

          const allowedRunners: Record<string, string[]> = {
            npm_test: ["npm", "test"],
            vitest: ["npx", "vitest", "run"],
            pytest: ["pytest", "-q"],
            go_test: ["go", "test", "./..."],
            cargo_test: ["cargo", "test"]
          };
          const runnerKey = target_path_or_ref && allowedRunners[target_path_or_ref] ? target_path_or_ref : "npm_test";
          const [cmd, ...args] = allowedRunners[runnerKey];
          const res = await runCommandSafe(cmd, args, { timeoutMs: 90_000 });

          return {
            content: [
              {
                type: "text",
                text: `REPRODUCTION / TEST EXIT CODE: ${res.exitCode}\n\nSTDOUT:\n${res.stdout.slice(-8000)}\n\nSTDERR:\n${deduplicateStackFrames(res.stderr)}`
              }
            ]
          };
        } catch (error: any) {
          return {
            isError: true,
            content: [{ type: "text", text: `Telemetry error: ${error.message}` }]
          };
        }
      }
    );

    // TOOL 3: Decoupled Cross-Model Adversarial Judge [07:20-08:21]
    this.server.tool(
      "verify_adversarial_diff",
      "MANDATORY PRE-COMPLETION GATE. Runs the contract's empirical proof command, then dispatches the git diff via stdin to a clean, cross-model outside judge CLI. Enforces a 3-strike circuit breaker.",
      {
        contract_id: z.string().regex(/^[a-zA-Z0-9_-]{3,64}$/),
        primary_agent_family: z.enum(["claude", "codex", "gemini", "other"]).default("claude")
      },
      async ({ contract_id, primary_agent_family }) => {
        if (this.activeLocks.has(contract_id)) {
          return {
            isError: true,
            content: [{ type: "text", text: `CONCURRENCY LOCK: Verification already in progress for ${contract_id}.` }]
          };
        }

        this.activeLocks.add(contract_id);
        try {
          const contract = await this.loadContract(contract_id);

          if (contract.status === "ESCALATED" || contract.review_cycle_count >= MAX_REVIEW_CYCLES) {
            return {
              isError: true,
              content: [
                {
                  type: "text",
                  text: `ESCALATE_TO_HUMAN: Maximum automated remediation cycles (${MAX_REVIEW_CYCLES}) reached for '${contract_id}'. Stop modifying code and request human architectural review.`
                }
              ]
            };
          }

          // Stage A: Deterministic Pre-Gate (Zero LLM Tokens if tests fail)
          const proofParts = contract.empirical_gate.proof_command.trim().split(/\s+/);
          const [proofCmd, ...proofArgs] = proofParts;
          const allowedProofBinaries = new Set(["npm", "npx", "pnpm", "yarn", "bun", "node", "pytest", "python3", "go", "cargo"]);

          if (!allowedProofBinaries.has(proofCmd)) {
            return {
              isError: true,
              content: [{ type: "text", text: `Security Gate: proof_command binary '${proofCmd}' is not in the allowlist.` }]
            };
          }

          const proofRes = await runCommandSafe(proofCmd, proofArgs, { timeoutMs: 90_000 });
          if (proofRes.exitCode !== 0) {
            return {
              content: [
                {
                  type: "text",
                  text: `VERDICT: REJECT (DETERMINISTIC PRE-GATE FAILED).\nYour empirical proof command ('${contract.empirical_gate.proof_command}') exited with code ${proofRes.exitCode}.\nFix the failing tests before invoking the external LLM judge:\n\n${deduplicateStackFrames(proofRes.stderr || proofRes.stdout)}`
                }
              ]
            };
          }

          // Stage B: Extract Clean Diff against locked base_sha
          const { diff, treeHash } = await this.extractCleanDiff(contract.base_sha);
          if (!diff.trim()) {
            return {
              content: [{ type: "text", text: "VERDICT: REJECT. Git diff against base_sha is empty." }]
            };
          }

          // Stage C: Pipe to Outside Judge CLI via stdin (Zero shell escaping risk)
          const judge = await this.selectOutsideJudgeCli(primary_agent_family);
          const reviewPayload = [
            "CRITICAL ADVERSARIAL CODE AUDIT",
            "You are an independent, external principal engineer grading work written by another model.",
            "Your objective is to reject shallow implementations, race conditions, memory leaks, missing error handling, and mocked/fake tests.",
            "",
            "=== EXECUTION CONTRACT ===",
            JSON.stringify(
              {
                altitude: contract.altitude,
                depth: contract.depth,
                empirical_gate: contract.empirical_gate
              },
              null,
              2
            ),
            "",
            "=== AUDIT RULES ===",
            "1. Tag every blocking defect with its 3D axis: [MEMORY], [CONCURRENCY], [FAILURE], or [SHALLOW-SPEC].",
            "2. Prefix every blocking defect with: 'BLOCKING ISSUE: [file:line] - <axis> <description & repro>'.",
            "3. If tests are mocked to force a fake pass or ignore the unreasonable_target, REJECT immediately.",
            "4. If and only if zero blocking issues exist, end your output with the exact line: 'VERDICT: PASS'. Otherwise end with: 'VERDICT: REJECT'.",
            "",
            "=== GIT DIFF ===",
            diff
          ].join("\n");

          const judgeRes = await runCommandSafe(judge.cmd, judge.args, {
            stdinData: reviewPayload,
            timeoutMs: 120_000
          });

          if (judgeRes.exitCode !== 0 && !judgeRes.stdout.trim()) {
            return {
              isError: true,
              content: [
                {
                  type: "text",
                  text: `JUDGE_UNAVAILABLE (${judge.name} exited ${judgeRes.exitCode}): ${judgeRes.stderr}`
                }
              ]
            };
          }

          const output = judgeRes.stdout.trim();
          const passed = output.includes("VERDICT: PASS") && !output.includes("BLOCKING ISSUE:");

          if (passed) {
            contract.status = "PASSED";
            contract.verified_tree_hash = treeHash;
          } else {
            contract.review_cycle_count += 1;
            if (contract.review_cycle_count >= MAX_REVIEW_CYCLES) {
              contract.status = "ESCALATED";
            }
          }

          contract.history.push({
            cycle: contract.review_cycle_count,
            timestamp: new Date().toISOString(),
            judge_cli: judge.name,
            verdict: passed ? "PASS" : "REJECT"
          });

          await this.saveContractAtomically(contract);

          return {
            content: [
              {
                type: "text",
                text: [
                  `OUTSIDE JUDGE: ${judge.name} (Primary Family: ${primary_agent_family})`,
                  `CYCLE: ${contract.review_cycle_count} / ${MAX_REVIEW_CYCLES}`,
                  `CONTRACT STATUS: ${contract.status}`,
                  "",
                  output,
                  contract.status === "ESCALATED"
                    ? `\nESCALATE_TO_HUMAN: Maximum automated remediation cycles (${MAX_REVIEW_CYCLES}) reached.`
                    : ""
                ].join("\n")
              }
            ]
          };
        } finally {
          this.activeLocks.delete(contract_id);
        }
      }
    );

    // TOOL 4: Orchestrate Range Crew (Noun-to-Verb Multi-Disciplinary Pipeline [08:22-10:01])
    this.server.tool(
      "orchestrate_range_crew",
      "Executes Felix Rieseberg's Range workflow: reframes the app from nouns to human-outcome verbs and runs a sequential multi-disciplinary specialist crew over the diff.",
      {
        contract_id: z.string().regex(/^[a-zA-Z0-9_-]{3,64}$/),
        verb_reframing: z.string().min(15).describe("What the system DOES for humans (verbs, not nouns) [09:01]"),
        specialist_crew: z
          .array(
            z.object({
              discipline: z.string().min(3),
              domain_methods: z.string().min(10)
            })
          )
          .min(2)
          .max(4)
      },
      async ({ contract_id, verb_reframing, specialist_crew }) => {
        const contract = await this.loadContract(contract_id);
        const { diff } = await this.extractCleanDiff(contract.base_sha);
        const judge = await this.selectOutsideJudgeCli("claude");

        const findingsReport: string[] = [
          `# RANGE CREW SEQUENTIAL AUDIT (${contract_id})`,
          `**Verb Reframing:** ${verb_reframing}\n`
        ];

        let accumulatedContext = "";
        for (const [idx, specialist] of specialist_crew.entries()) {
          const prompt = [
            `RANGE SPECIALIST PASS ${idx + 1}/${specialist_crew.length}: ${specialist.discipline}`,
            `System Human-Outcome Verb Goal: "${verb_reframing}"`,
            `Mandatory Domain Methods to Apply (Do NOT roleplay tone; execute these methods): ${specialist.domain_methods}`,
            accumulatedContext ? `\nPrior Crew Findings:\n${accumulatedContext}` : "",
            "\nInspect the following diff through your discipline's methods and list concrete, non-overlapping defects and required fixes:",
            diff
          ].join("\n");

          const res = await runCommandSafe(judge.cmd, judge.args, {
            stdinData: prompt,
            timeoutMs: 90_000
          });

          const stepOutput = res.stdout.trim() || res.stderr.trim();
          accumulatedContext += `\n[${specialist.discipline}]:\n${stepOutput}\n`;
          findingsReport.push(`## Pass ${idx + 1}: ${specialist.discipline}\n${stepOutput}\n`);
        }

        return {
          content: [{ type: "text", text: findingsReport.join("\n") }]
        };
      }
    );
  }

  public async start() {
    const transport = new StdioServerTransport();
    await this.server.connect(transport);
  }
}

const isMainModule = (() => {
  try {
    return Boolean(process.argv[1]) && realpathSync(fileURLToPath(import.meta.url)) === realpathSync(process.argv[1]);
  } catch {
    return false;
  }
})();

if (isMainModule) {
  const governor = new KirbyGovernorServer();
  governor.start().catch((err) => {
    console.error("Fatal Kirby Governor Server Error:", err);
    process.exit(1);
  });
}
