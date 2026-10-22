#!/usr/bin/env node
import { z } from "zod";
export declare const MAX_DIFF_BYTES: number;
declare const AGENT_FAMILIES: readonly ["claude", "codex", "gemini", "zcode", "grok", "other"];
export type AgentFamily = (typeof AGENT_FAMILIES)[number];
/**
 * Checks whether any proof_command argument attempts inline code execution or module preloading,
 * including equals-attached forms (--eval=..., -e=..., --require=...) without over-blocking legitimate
 * flags like 'go test -race', 'go test -run', 'pytest -ra', or 'node --check'.
 */
export declare function findBlockedProofArg(proofArgs: string[]): string | undefined;
/**
 * Redacts high-entropy credentials, tokens, and private keys before diffs or contracts are persisted/dispatched.
 * Reversible switches:
 * - KIRBY_GOVERNOR_REDACT_SECRETS=0 disables inline regex redaction (and file exclusion unless KIRBY_GOVERNOR_EXCLUDE_SECRET_FILES=1).
 */
export declare function redactDiffSecrets(rawText: string): {
    sanitizedDiff: string;
    redactedCount: number;
};
/**
 * Minimal quote-aware tokenizer for proof_command strings.
 */
export declare function tokenizeCommand(commandStr: string): string[];
export declare const ContractRecordSchema: z.ZodObject<{
    contract_id: z.ZodString;
    created_at: z.ZodString;
    base_sha: z.ZodString;
    task_type: z.ZodEnum<["outcome_driven", "creative_exploratory"]>;
    raw_task: z.ZodString;
    altitude: z.ZodObject<{
        ultimate_outcome: z.ZodString;
        decisions_enabled: z.ZodArray<z.ZodString, "many">;
    }, "strip", z.ZodTypeAny, {
        ultimate_outcome: string;
        decisions_enabled: string[];
    }, {
        ultimate_outcome: string;
        decisions_enabled: string[];
    }>;
    depth: z.ZodObject<{
        unasked_expert_actions: z.ZodArray<z.ZodString, "many">;
        raw_data_sources: z.ZodArray<z.ZodString, "many">;
        expert_methods_and_tools: z.ZodArray<z.ZodString, "many">;
        unreasonable_target: z.ZodString;
    }, "strip", z.ZodTypeAny, {
        unasked_expert_actions: string[];
        raw_data_sources: string[];
        expert_methods_and_tools: string[];
        unreasonable_target: string;
    }, {
        unasked_expert_actions: string[];
        raw_data_sources: string[];
        expert_methods_and_tools: string[];
        unreasonable_target: string;
    }>;
    empirical_gate: z.ZodObject<{
        proof_command: z.ZodString;
    }, "strip", z.ZodTypeAny, {
        proof_command: string;
    }, {
        proof_command: string;
    }>;
    review_cycle_count: z.ZodNumber;
    pregate_failure_count: z.ZodDefault<z.ZodOptional<z.ZodNumber>>;
    status: z.ZodEnum<["ACTIVE", "PASSED", "ESCALATED"]>;
    verified_tree_hash: z.ZodOptional<z.ZodString>;
    history: z.ZodArray<z.ZodObject<{
        cycle: z.ZodNumber;
        timestamp: z.ZodString;
        judge_cli: z.ZodString;
        verdict: z.ZodString;
    }, "strip", z.ZodTypeAny, {
        cycle: number;
        timestamp: string;
        judge_cli: string;
        verdict: string;
    }, {
        cycle: number;
        timestamp: string;
        judge_cli: string;
        verdict: string;
    }>, "many">;
}, "strip", z.ZodTypeAny, {
    contract_id: string;
    created_at: string;
    base_sha: string;
    task_type: "outcome_driven" | "creative_exploratory";
    status: "ACTIVE" | "PASSED" | "ESCALATED";
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
    pregate_failure_count: number;
    history: {
        cycle: number;
        timestamp: string;
        judge_cli: string;
        verdict: string;
    }[];
    verified_tree_hash?: string | undefined;
}, {
    contract_id: string;
    created_at: string;
    base_sha: string;
    task_type: "outcome_driven" | "creative_exploratory";
    status: "ACTIVE" | "PASSED" | "ESCALATED";
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
    history: {
        cycle: number;
        timestamp: string;
        judge_cli: string;
        verdict: string;
    }[];
    pregate_failure_count?: number | undefined;
    verified_tree_hash?: string | undefined;
}>;
export type ContractRecord = z.infer<typeof ContractRecordSchema>;
export interface ExecResult {
    exitCode: number;
    stdout: string;
    stderr: string;
    stdoutTruncated: boolean;
    stdoutSha256: string;
}
/**
 * Zero-Trust Subprocess Runner: NEVER invokes /bin/sh.
 * Passes arguments strictly as an argv array, pipes payloads via stdin,
 * streams full stdout into SHA-256 before buffer caps, and enforces a hard I/O + process-group deadline.
 */
export declare function runCommandSafe(command: string, args: string[], options?: {
    stdinData?: string;
    timeoutMs?: number;
    cwd?: string;
    extraEnv?: Record<string, string>;
}): Promise<ExecResult>;
/**
 * Ensures requested file paths stay strictly inside REPO_ROOT (including null-byte and ancestor symlink resolution).
 */
export declare function resolveSafeRepoPath(relativePath: string): string;
/**
 * Deduplicates repetitive stack trace frames while preserving the leading exception header line.
 */
export declare function deduplicateStackFrames(rawLog: string, maxLines?: number): string;
export declare class KirbyGovernorServer {
    private server;
    private activeLocks;
    private indexMutex;
    constructor();
    private acquireContractLock;
    private releaseContractLock;
    private pruneOldContracts;
    private saveContractAtomically;
    private loadContract;
    /**
     * Checks whether an executable exists in PATH (fallback when which/where is unavailable).
     */
    private findBinaryInPath;
    /**
     * Selects a judge CLI from a DIFFERENT model family than the primary agent [08:01].
     * Reversible switch: set KIRBY_GOVERNOR_ENABLE_ZCODE_JUDGE=0 to exclude zcode-cli.
     */
    private selectOutsideJudgeCli;
    /**
     * Captures tracked, staged, and untracked changes against base_sha using a throwaway GIT_INDEX_FILE
     * inside an isolated 0o700 mkdtemp directory so the user's real .git/index is NEVER mutated or locked.
     */
    private extractCleanDiff;
    private registerTools;
    start(): Promise<void>;
}
export {};
