# Re-Auditor Scaling Design

**Date:** 2026-03-02
**Status:** Approved
**Problem:** Said Protocol registry grew to 684+ agents. Current re-auditor (fixed batch of 20, every 6 hours) takes 5+ days for full rotation. Watcher has no rate limiting — 400-agent burst floods RPC and Telegram.

## Constraints

- Public Solana RPC (`mainnet-beta.solana.com`): ~40 req/10s cap
- Package manager: bun
- All core logic stays in `src/plugin.ts`
- `SaidAuditResult` schema unchanged
- Must scale to 1,000+ agents

## Design

### 1. Tiered Priority Queue

Agents are classified into tiers based on audit results:

| Tier | Re-audit interval | Assignment criteria |
|---|---|---|
| HOT | 2 hours | Verdict FAIL/WARNING, drift severity HIGH/CRITICAL |
| WARM | 12 hours | Never audited, last audit >7 days, drift MODERATE |
| COOL | 48 hours | Stable PASS, drift NONE/LOW |

**Demotion is immediate** (PASS→WARNING = jump to HOT).
**Promotion is gradual** (2 consecutive PASSes with low drift to move up one tier).

Per-agent metadata:

```
{ wallet, tier, lastAuditedAt, nextDueAt, consecutivePasses }
```

### 2. Micro-Cycle Scheduling

Replace single large batch with frequent small cycles:

| Parameter | Default | Env var |
|---|---|---|
| Cycle interval | 10 min | `REAUDIT_CYCLE_INTERVAL_MS` |
| Agents per cycle | 8 | `REAUDIT_AGENTS_PER_CYCLE` |
| Delay between agents | 15s | `REAUDIT_AGENT_DELAY_MS` |

Selection uses **urgency scoring**: `urgencyScore = now - nextDueAt`. Highest score picked first, ties broken by tier rank (HOT > WARM > COOL).

Throughput: 8 agents × 6 cycles/hour × 24h = 1,152 audit slots/day.
RPC load: 32 calls per cycle spread over ~2 min = ~0.27 calls/sec (93% headroom).

### 3. Watcher Backpressure

Current watcher processes all new agents in a tight loop. Fix:

- Cap at `WATCHER_BATCH_CAP` (default 10) new agents per poll
- Add `WATCHER_AGENT_DELAY_MS` (default 15s) between each
- Overflow agents added to `knownAgentWallets` and classified WARM — picked up by priority queue via urgency scoring

400-agent wave: 10 per poll × 5 min intervals = ~3.3 hours clean processing. Remainder enters priority queue immediately.

### 4. Persistence Migration

Extend drift-history.json from flat array to structured format:

**Old:** `{ "wallet": [driftRecord, ...] }`
**New:** `{ "wallet": { driftRecords: [...], tier, lastAuditedAt, nextDueAt, consecutivePasses } }`

Migration on read: detect old array format → wrap into new shape → default tier WARM → nextDueAt = now.

### 5. Env Var Changes

New variables:

```bash
REAUDIT_CYCLE_INTERVAL_MS=600000
REAUDIT_AGENTS_PER_CYCLE=8
REAUDIT_AGENT_DELAY_MS=15000
REAUDIT_TIER_HOT_MS=7200000
REAUDIT_TIER_WARM_MS=43200000
REAUDIT_TIER_COOL_MS=172800000
WATCHER_BATCH_CAP=10
WATCHER_AGENT_DELAY_MS=15000
```

Deprecated (log warning if set, ignore):

```bash
REAUDIT_BATCH_SIZE
REAUDIT_DELAY_MS
REAUDIT_INTERVAL_MS
```

### 6. Removed / Replaced

- `reauditorOffset` — replaced by urgency scoring
- `runReauditCycle()` — rewritten entirely
- Old `REAUDIT_*` constants — replaced by new env vars

### 7. Unchanged

- `auditIdentityPDA()` — same 4 API calls per audit
- `SaidAuditResult` schema — canonical
- `broadcastToTelegram()` — unchanged
- Drift analysis / alert logic — unchanged
- Dashboard — reads from same `auditHistory` map
