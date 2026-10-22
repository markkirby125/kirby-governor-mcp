#!/usr/bin/env node
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
    history: Array<{
        cycle: number;
        timestamp: string;
        judge_cli: string;
        verdict: string;
    }>;
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
export declare function runCommandSafe(command: string, args: string[], options?: {
    stdinData?: string;
    timeoutMs?: number;
    cwd?: string;
}): Promise<ExecResult>;
/**
 * Ensures requested file paths stay strictly inside REPO_ROOT.
 */
export declare function resolveSafeRepoPath(relativePath: string): string;
/**
 * Deduplicates repetitive stack trace frames to preserve agent context budget.
 */
export declare function deduplicateStackFrames(rawLog: string, maxLines?: number): string;
export declare class KirbyGovernorServer {
    private server;
    private activeLocks;
    constructor();
    private pruneOldContracts;
    private saveContractAtomically;
    private loadContract;
    /**
     * Selects a judge CLI from a DIFFERENT model family than the primary agent [08:01].
     */
    private selectOutsideJudgeCli;
    /**
     * Captures tracked, staged, and untracked changes against base_sha while excluding lockfiles.
     */
    private extractCleanDiff;
    private registerTools;
    start(): Promise<void>;
}
