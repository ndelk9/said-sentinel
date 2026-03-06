# Broadcast Reduction Design
**Date:** 2026-03-06

## Goal
Reduce Telegram broadcast noise to daily digest only, plus requested re-audits.

## Current State
Five broadcast points in `plugin.ts`:
1. Daily Digest (line ~1486) — 9 AM UTC daily
2. Drift Alert (line ~1572) — re-auditor detects MODERATE+ drift worsening
3. Verdict Change Alert (line ~1596) — re-auditor sees verdict flip
4. New Agent Audit (line ~1771, source="watcher") — watcher finds new agent
5. Requested Re-Audit (line ~1771, source="requested") — API-triggered

## Changes
**Keep:** #1 (Daily Digest), #5 (Requested Re-Audit)
**Silence:** #2 (Drift Alert), #3 (Verdict Change), #4 (New Agent Watcher Audit)

## Implementation
1. `runMicroCycle()`: Remove both `broadcastToTelegram` calls (drift + verdict change)
2. `auditAndBroadcast()`: Gate broadcast on `source !== "watcher"`
3. Update CLAUDE.md broadcast documentation

No changes to audit logic, drift tracking, tier classification, or feedback submission.
