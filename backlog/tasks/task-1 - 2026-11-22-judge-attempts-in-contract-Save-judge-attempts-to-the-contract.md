---
id: TASK-1
title: 2026-11-22-judge-attempts-in-contract Save judge attempts to the contract
status: Done
assignee: []
created_date: '2026-11-25T11:48:53Z'
updated_date: '2026-11-28T12:11:12Z'
labels: []
dependencies: []
ordinal: 1000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Status: in progress. Built and tested (32 of 32): commits 19c84e2, 73f5cfc, 43f490e, 0434cc9 on branch `feat/judge-attempts-in-contract`, unpushed. The governor now saves judge attempts and a JUDGE_UNAVAILABLE entry to the contract history, tells judges to use no tools (rule 6, because agentic judges tried to read files and timed out), caps each reason fairly, and reloads the contract before the failure save. Its own gate (contract `gov-judge-attempts`) is at cycle 1 of 3: REJECT from claude-cli (same family), three of four findings fixed; the fourth (save after every attempt, so a killed server still keeps the reasons) was left out on purpose. Reasonix (independent) then rejected the reload-before-save in 43f490e; 0434cc9 removes it, gives reasonix 300 s and raises the lock window to 20 minutes. Cycle 2 was running on 0434cc9 at handoff. Open: run cycle 2; decide whether to push; confirm reasonix answers inside a gate with its new 300 s timeout; codex fails on the model set in the user's Codex config. Update 2026-11-22: gate cycle 3 (reasonix) REJECTED and escalated; commit 2aa62ad saves the judge text in the history, and the lock is now refreshed every 20 s while a call runs (stale limit 2 minutes), which closes the stale-lock overwrite finding. The incremental save (a killed server keeps the reasons) is still left out on purpose, and the gate is ESCALATED, so there is no re-review.
<!-- SECTION:DESCRIPTION:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
2026-11-28: User confirmed no Codex subscription so Codex judge failures are expected/won't be fixed. Confirmed branch feat/judge-attempts-in-contract pushed.

2026-11-28: Verified reasonix-cli responds inside verify_adversarial_diff gate under 300s timeout (34s elapsed, 2026-11-28T12:10:17Z..12:10:51Z; judge returned REJECT on metadata-only diff).
<!-- SECTION:NOTES:END -->
