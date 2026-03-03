# Re-Auditor Scaling Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Replace the fixed-batch re-auditor with a tiered priority queue system that scales to 1,000+ agents on public Solana RPC, and add backpressure to the watcher's new-agent loop.

**Architecture:** Agents are classified into HOT/WARM/COOL tiers based on audit results. A micro-cycle scheduler runs every 10 minutes, picks the 8 most overdue agents by urgency score, and audits them with 15s spacing. The watcher caps new-agent processing at 10 per poll with the same 15s delay, spilling overflow into the priority queue.

**Tech Stack:** TypeScript, bun:test, ElizaOS plugin system, @solana/web3.js, said-sdk

**Design doc:** `docs/plans/2026-03-02-reauditor-scaling-design.md`

---

### Task 1: Add New Constants and Types

**Files:**
- Modify: `src/plugin.ts:20-33` (constants section)
- Modify: `src/plugin.ts:68-92` (types section)

**Step 1: Replace old re-auditor constants with new ones**

In `src/plugin.ts`, replace lines 31-33:

```typescript
const REAUDIT_INTERVAL_MS = parseInt(process.env.REAUDIT_INTERVAL_MS ?? '21600000', 10); // 6 hours
const REAUDIT_BATCH_SIZE = parseInt(process.env.REAUDIT_BATCH_SIZE ?? '20', 10);
const REAUDIT_DELAY_MS = parseInt(process.env.REAUDIT_DELAY_MS ?? '1000', 10); // 1s between agents
```

With:

```typescript
// ── Re-Auditor (tiered micro-cycle) ──────────────────────────────────────────
const REAUDIT_CYCLE_INTERVAL_MS = parseInt(process.env.REAUDIT_CYCLE_INTERVAL_MS ?? '600000', 10); // 10 min
const REAUDIT_AGENTS_PER_CYCLE = parseInt(process.env.REAUDIT_AGENTS_PER_CYCLE ?? '8', 10);
const REAUDIT_AGENT_DELAY_MS = parseInt(process.env.REAUDIT_AGENT_DELAY_MS ?? '15000', 10); // 15s between agents
const REAUDIT_TIER_HOT_MS = parseInt(process.env.REAUDIT_TIER_HOT_MS ?? '7200000', 10);    // 2h
const REAUDIT_TIER_WARM_MS = parseInt(process.env.REAUDIT_TIER_WARM_MS ?? '43200000', 10);  // 12h
const REAUDIT_TIER_COOL_MS = parseInt(process.env.REAUDIT_TIER_COOL_MS ?? '172800000', 10); // 48h

// ── Watcher backpressure ─────────────────────────────────────────────────────
const WATCHER_BATCH_CAP = parseInt(process.env.WATCHER_BATCH_CAP ?? '10', 10);
const WATCHER_AGENT_DELAY_MS = parseInt(process.env.WATCHER_AGENT_DELAY_MS ?? '15000', 10); // 15s

// ── Deprecation warnings for old env vars ────────────────────────────────────
for (const v of ['REAUDIT_INTERVAL_MS', 'REAUDIT_BATCH_SIZE', 'REAUDIT_DELAY_MS']) {
  if (process.env[v]) logger.warn(`Env var ${v} is deprecated and ignored. See docs/plans/2026-03-02-reauditor-scaling-design.md for new config.`);
}
```

**Step 2: Add tier types and AgentMeta interface**

After the existing `DriftAnalysis` interface (~line 92), add:

```typescript
type AgentTier = 'HOT' | 'WARM' | 'COOL';

interface AgentMeta {
  tier: AgentTier;
  lastAuditedAt: string | null;
  nextDueAt: string;
  consecutivePasses: number;
}
```

**Step 3: Add tier helper functions**

After the `sleep()` helper (~line 97), add:

```typescript
const TIER_INTERVAL: Record<AgentTier, number> = {
  HOT: REAUDIT_TIER_HOT_MS,
  WARM: REAUDIT_TIER_WARM_MS,
  COOL: REAUDIT_TIER_COOL_MS,
};

const TIER_RANK: Record<AgentTier, number> = { HOT: 2, WARM: 1, COOL: 0 };

function classifyTier(
  verdict: AuditVerdict,
  driftSeverity: DriftSeverity,
  consecutivePasses: number
): AgentTier {
  if (verdict === 'FAIL' || verdict === 'WARNING') return 'HOT';
  if (driftSeverity === 'SEVERE' || driftSeverity === 'MODERATE') return 'HOT';
  if (consecutivePasses < 2) return 'WARM';
  return 'COOL';
}

function computeNextDueAt(tier: AgentTier): string {
  return new Date(Date.now() + TIER_INTERVAL[tier]).toISOString();
}
```

**Step 4: Run type-check**

Run: `bun run type-check`
Expected: PASS (new types/constants are additive, not yet used)

**Step 5: Commit**

```bash
git add src/plugin.ts
git commit -m "feat: add tiered re-auditor constants, types, and helpers"
```

---

### Task 2: Write Tests for Tier Classification

**Files:**
- Create: `src/__tests__/tier-classification.test.ts`

**Step 1: Write tests for classifyTier and computeNextDueAt**

```typescript
import { describe, expect, it } from 'bun:test';

// We test via the module — these functions are not exported, so we test them
// indirectly through the service behavior. For unit-level coverage, we
// replicate the logic here and validate the contract.

describe('Tier Classification Logic', () => {
  // Mirror the classifyTier logic for contract testing
  type AuditVerdict = 'PASS' | 'WARNING' | 'FAIL';
  type DriftSeverity = 'NONE' | 'MILD' | 'MODERATE' | 'SEVERE';
  type AgentTier = 'HOT' | 'WARM' | 'COOL';

  function classifyTier(
    verdict: AuditVerdict,
    driftSeverity: DriftSeverity,
    consecutivePasses: number
  ): AgentTier {
    if (verdict === 'FAIL' || verdict === 'WARNING') return 'HOT';
    if (driftSeverity === 'SEVERE' || driftSeverity === 'MODERATE') return 'HOT';
    if (consecutivePasses < 2) return 'WARM';
    return 'COOL';
  }

  describe('classifyTier', () => {
    it('assigns HOT for FAIL verdict', () => {
      expect(classifyTier('FAIL', 'NONE', 10)).toBe('HOT');
    });

    it('assigns HOT for WARNING verdict', () => {
      expect(classifyTier('WARNING', 'NONE', 5)).toBe('HOT');
    });

    it('assigns HOT for SEVERE drift even with PASS verdict', () => {
      expect(classifyTier('PASS', 'SEVERE', 5)).toBe('HOT');
    });

    it('assigns HOT for MODERATE drift even with PASS verdict', () => {
      expect(classifyTier('PASS', 'MODERATE', 5)).toBe('HOT');
    });

    it('assigns WARM for PASS with fewer than 2 consecutive passes', () => {
      expect(classifyTier('PASS', 'NONE', 0)).toBe('WARM');
      expect(classifyTier('PASS', 'NONE', 1)).toBe('WARM');
    });

    it('assigns COOL for PASS with 2+ consecutive passes and low drift', () => {
      expect(classifyTier('PASS', 'NONE', 2)).toBe('COOL');
      expect(classifyTier('PASS', 'MILD', 3)).toBe('COOL');
    });

    it('FAIL verdict overrides high consecutive passes', () => {
      expect(classifyTier('FAIL', 'NONE', 100)).toBe('HOT');
    });

    it('demotion is immediate — SEVERE drift overrides consecutive passes', () => {
      expect(classifyTier('PASS', 'SEVERE', 100)).toBe('HOT');
    });
  });
});
```

**Step 2: Run the test**

Run: `bun test src/__tests__/tier-classification.test.ts`
Expected: All 8 tests PASS

**Step 3: Commit**

```bash
git add src/__tests__/tier-classification.test.ts
git commit -m "test: add tier classification contract tests"
```

---

### Task 3: Update Service State — Replace Old Re-Auditor Fields

**Files:**
- Modify: `src/plugin.ts:614-640` (service class properties)

**Step 1: Replace re-auditor state fields**

In `SaidSentinelService`, replace lines 625-632:

```typescript
  // Re-Auditor state
  auditHistory: Map<string, AuditSnapshot> = new Map();
  reauditorTimer: ReturnType<typeof setInterval> | null = null;
  reauditorRunning = false;
  reauditorLastRun: Date | null = null;
  reauditorNextRun: Date | null = null;
  reauditorLastCycleStats: { audited: number; alerts: number } | null = null;
  reauditorOffset = 0; // rotating cursor — advances each cycle so all agents are covered
```

With:

```typescript
  // Re-Auditor state (tiered priority queue)
  auditHistory: Map<string, AuditSnapshot> = new Map();
  agentMeta: Map<string, AgentMeta> = new Map();
  reauditorTimer: ReturnType<typeof setInterval> | null = null;
  reauditorRunning = false;
  reauditorLastRun: Date | null = null;
  reauditorLastCycleStats: { audited: number; alerts: number } | null = null;
  reauditorTotalAuditsToday = 0;
  reauditorDayStart: Date = new Date();
```

Note: `reauditorOffset` removed (replaced by urgency scoring). `reauditorNextRun` removed (micro-cycles run on fixed interval). Added `agentMeta` map for tier tracking.

**Step 2: Run type-check**

Run: `bun run type-check`
Expected: FAIL — references to `reauditorOffset` and `reauditorNextRun` will break. This is expected; we fix them in Task 5.

**Step 3: Commit**

```bash
git add src/plugin.ts
git commit -m "refactor: replace re-auditor state fields with tiered priority queue fields"
```

---

### Task 4: Update Persistence — Migrate Drift History Format

**Files:**
- Modify: `src/plugin.ts:676-708` (loadDriftHistory / saveDriftHistory)

**Step 1: Update loadDriftHistory to handle both formats**

Replace `loadDriftHistory()` method:

```typescript
  async loadDriftHistory(): Promise<void> {
    try {
      const raw = await readFile(DRIFT_HISTORY_FILE, 'utf-8');
      const parsed = JSON.parse(raw) as Record<string, unknown>;

      for (const [wallet, value] of Object.entries(parsed)) {
        // Migrate old format: array of DriftRecords → new structured format
        if (Array.isArray(value)) {
          // Old format: { "wallet": [DriftRecord, ...] }
          const records = value as DriftRecord[];
          this.driftHistory.set(wallet, records);
          this.agentMeta.set(wallet, {
            tier: 'WARM',
            lastAuditedAt: records.length > 0 ? records[records.length - 1].timestamp : null,
            nextDueAt: new Date().toISOString(), // audit promptly
            consecutivePasses: 0,
          });
        } else if (value && typeof value === 'object' && 'driftRecords' in value) {
          // New format: { "wallet": { driftRecords, tier, ... } }
          const entry = value as { driftRecords: DriftRecord[]; tier: AgentTier; lastAuditedAt: string | null; nextDueAt: string; consecutivePasses: number };
          this.driftHistory.set(wallet, entry.driftRecords);
          this.agentMeta.set(wallet, {
            tier: entry.tier,
            lastAuditedAt: entry.lastAuditedAt,
            nextDueAt: entry.nextDueAt,
            consecutivePasses: entry.consecutivePasses,
          });
        }
      }

      // Restore auditHistory and driftSeverityCache from latest records
      for (const [wallet, records] of this.driftHistory) {
        if (records.length > 0) {
          const latest = records[records.length - 1];
          this.auditHistory.set(wallet, latest);
          const analysis = computeDriftAnalysis(wallet, records);
          this.driftSeverityCache.set(wallet, analysis.severity);
        }
      }

      logger.info(
        { wallets: this.driftHistory.size, migrated: [...this.agentMeta.values()].filter(m => m.tier === 'WARM' && m.consecutivePasses === 0).length },
        'Drift history loaded from disk'
      );
    } catch {
      logger.info('No existing drift history — starting fresh');
    }
  }
```

**Step 2: Update saveDriftHistory to write new format**

Replace `saveDriftHistory()` method:

```typescript
  async saveDriftHistory(): Promise<void> {
    try {
      await mkdir('/app/data', { recursive: true });
      const obj: Record<string, { driftRecords: DriftRecord[]; tier: AgentTier; lastAuditedAt: string | null; nextDueAt: string; consecutivePasses: number }> = {};
      for (const [wallet, records] of this.driftHistory) {
        const meta = this.agentMeta.get(wallet) ?? { tier: 'WARM' as AgentTier, lastAuditedAt: null, nextDueAt: new Date().toISOString(), consecutivePasses: 0 };
        obj[wallet] = { driftRecords: records, ...meta };
      }
      await writeFile(DRIFT_HISTORY_FILE, JSON.stringify(obj));
    } catch (err) {
      logger.warn({ err }, 'Failed to save drift history');
    }
  }
```

**Step 3: Run type-check**

Run: `bun run type-check`
Expected: Still failing from Task 3's removed fields — that's fine, fixed in Task 5.

**Step 4: Commit**

```bash
git add src/plugin.ts
git commit -m "feat: migrate drift history persistence to new structured format with tier metadata"
```

---

### Task 5: Rewrite Re-Auditor — Priority Queue Scheduler

**Files:**
- Modify: `src/plugin.ts:756-996` (startReauditor, stopReauditor, runReauditCycle)

**Step 1: Rewrite startReauditor**

Replace the `startReauditor()` method:

```typescript
  startReauditor(): void {
    this.reauditorTimer = setInterval(() => {
      void this.runMicroCycle();
    }, REAUDIT_CYCLE_INTERVAL_MS);

    logger.info(
      {
        cycleIntervalMin: (REAUDIT_CYCLE_INTERVAL_MS / 60000).toFixed(1),
        agentsPerCycle: REAUDIT_AGENTS_PER_CYCLE,
        delayMs: REAUDIT_AGENT_DELAY_MS,
        tierHotH: (REAUDIT_TIER_HOT_MS / 3600000).toFixed(1),
        tierWarmH: (REAUDIT_TIER_WARM_MS / 3600000).toFixed(1),
        tierCoolH: (REAUDIT_TIER_COOL_MS / 3600000).toFixed(1),
      },
      'Tiered Re-Auditor: started'
    );
  }
```

**Step 2: Add ensureAgentMeta helper**

Add this method to the service class (after `stopReauditor`):

```typescript
  ensureAgentMeta(wallet: string): AgentMeta {
    let meta = this.agentMeta.get(wallet);
    if (!meta) {
      meta = {
        tier: 'WARM',
        lastAuditedAt: null,
        nextDueAt: new Date().toISOString(), // due immediately
        consecutivePasses: 0,
      };
      this.agentMeta.set(wallet, meta);
    }
    return meta;
  }
```

**Step 3: Add selectNextBatch method**

```typescript
  selectNextBatch(limit: number): string[] {
    const now = Date.now();

    // Build urgency-scored list from all known agents
    const scored: { wallet: string; urgency: number; tierRank: number }[] = [];
    for (const wallet of this.knownAgentWallets) {
      const meta = this.ensureAgentMeta(wallet);
      const dueAt = new Date(meta.nextDueAt).getTime();
      const urgency = now - dueAt; // positive = overdue
      scored.push({ wallet, urgency, tierRank: TIER_RANK[meta.tier] });
    }

    // Sort: most overdue first, then by tier rank (HOT > WARM > COOL)
    scored.sort((a, b) => {
      if (b.urgency !== a.urgency) return b.urgency - a.urgency;
      return b.tierRank - a.tierRank;
    });

    // Only pick agents that are actually due (urgency > 0)
    return scored
      .filter((s) => s.urgency > 0)
      .slice(0, limit)
      .map((s) => s.wallet);
  }
```

**Step 4: Rewrite runReauditCycle as runMicroCycle**

Replace `runReauditCycle()` with:

```typescript
  async runMicroCycle(): Promise<{ audited: number; alerts: number }> {
    if (this.reauditorRunning) {
      logger.debug('Tiered Re-Auditor: previous micro-cycle still running, skipping');
      return { audited: 0, alerts: 0 };
    }

    // Reset daily counter at midnight
    const today = new Date();
    if (today.getUTCDate() !== this.reauditorDayStart.getUTCDate()) {
      this.reauditorTotalAuditsToday = 0;
      this.reauditorDayStart = today;
    }

    const batch = this.selectNextBatch(REAUDIT_AGENTS_PER_CYCLE);
    if (batch.length === 0) {
      logger.debug('Tiered Re-Auditor: no agents due, skipping cycle');
      return { audited: 0, alerts: 0 };
    }

    this.reauditorRunning = true;
    this.reauditorLastRun = new Date();

    let audited = 0;
    let alerts = 0;

    try {
      for (const wallet of batch) {
        try {
          const { findings, confidenceScore } = await auditIdentityPDA(wallet, this.saidClient, this.connection);
          const verdict = deriveVerdict(findings, confidenceScore);
          const prev = this.auditHistory.get(wallet) ?? null;

          const verdictChanged = prev !== null && prev.verdict !== verdict;
          const isFirstAuditAlert =
            prev === null && (verdict === 'FAIL' || verdict === 'WARNING');

          const snapshot: AuditSnapshot = {
            verdict,
            confidenceScore: Math.round(confidenceScore * 100) / 100,
            timestamp: new Date().toISOString(),
          };

          // Update in-memory audit history
          this.auditHistory.set(wallet, snapshot);

          // Append to persistent drift history and compute analysis
          const driftAnalysis = this.appendDriftRecord(wallet, snapshot);
          const prevSeverity = this.driftSeverityCache.get(wallet) ?? 'NONE';

          // Broadcast drift alert if severity worsened
          if (severityRank(driftAnalysis.severity) > severityRank(prevSeverity)) {
            this.driftSeverityCache.set(wallet, driftAnalysis.severity);
            await broadcastToTelegram(formatDriftAlert(driftAnalysis));
          } else {
            this.driftSeverityCache.set(wallet, driftAnalysis.severity);
          }

          // Broadcast only on verdict changes or first-time alerts
          if (verdictChanged || isFirstAuditAlert) {
            const payload: Omit<SaidAuditResult, 'attestation'> = {
              protocol: 'SAID_v1',
              auditId: crypto.randomUUID(),
              timestamp: new Date().toISOString(),
              target: wallet,
              verdict,
              confidenceScore: Math.round(confidenceScore * 100) / 100,
              findings,
            };
            const signature = signPayload(payload, this.keypair);
            const auditResult: SaidAuditResult = {
              ...payload,
              attestation: { auditor: this.keypair.publicKey.toString(), signature },
            };
            await broadcastToTelegram(formatReauditBroadcast(wallet, auditResult, prev));
            alerts++;
          }

          // Update tier metadata
          const meta = this.ensureAgentMeta(wallet);
          if (verdict === 'PASS') {
            meta.consecutivePasses++;
          } else {
            meta.consecutivePasses = 0;
          }
          meta.tier = classifyTier(verdict, driftAnalysis.severity, meta.consecutivePasses);
          meta.lastAuditedAt = snapshot.timestamp;
          meta.nextDueAt = computeNextDueAt(meta.tier);

          audited++;
        } catch (err) {
          logger.warn({ err, wallet }, 'Tiered Re-Auditor: audit failed for wallet, skipping');
        }

        // Rate limit: pause between each agent
        await sleep(REAUDIT_AGENT_DELAY_MS);
      }
    } finally {
      this.reauditorRunning = false;
      this.reauditorLastCycleStats = { audited, alerts };
      this.reauditorTotalAuditsToday += audited;
      await this.saveDriftHistory();
    }

    logger.info(
      { audited, alerts, totalToday: this.reauditorTotalAuditsToday },
      'Tiered Re-Auditor: micro-cycle complete'
    );

    return { audited, alerts };
  }
```

**Step 5: Run type-check**

Run: `bun run type-check`
Expected: May still fail due to references in REAUDIT_NOW action and status action. We fix those in Task 7.

**Step 6: Commit**

```bash
git add src/plugin.ts
git commit -m "feat: rewrite re-auditor with tiered priority queue and micro-cycle scheduling"
```

---

### Task 6: Add Watcher Backpressure

**Files:**
- Modify: `src/plugin.ts:998-1029` (checkForNewAgents method)

**Step 1: Add backpressure to checkForNewAgents**

Replace `checkForNewAgents()`:

```typescript
  async checkForNewAgents(): Promise<void> {
    logger.debug('New Agent Watcher: polling Said Protocol...');
    let current: AgentIdentity[];

    try {
      current = await this.saidClient.listAgents({ includeCards: true });
    } catch (err) {
      logger.warn({ err }, 'New Agent Watcher: listAgents() failed — will retry next poll');
      return;
    }

    const newAgents = current.filter((a) => !this.knownAgentWallets.has(a.owner));

    if (newAgents.length === 0) {
      logger.debug(
        { totalKnown: this.knownAgentWallets.size },
        'New Agent Watcher: no new agents detected'
      );
      return;
    }

    logger.info(
      { newCount: newAgents.length, totalKnown: this.knownAgentWallets.size },
      'New Agent Watcher: new agents detected!'
    );

    // Process up to WATCHER_BATCH_CAP agents this poll
    const batch = newAgents.slice(0, WATCHER_BATCH_CAP);
    const overflow = newAgents.slice(WATCHER_BATCH_CAP);

    // Register ALL new agents immediately (prevents re-detection next poll)
    for (const agent of newAgents) {
      this.knownAgentWallets.add(agent.owner);
    }

    // Overflow agents: register as WARM in priority queue (no immediate audit)
    if (overflow.length > 0) {
      for (const agent of overflow) {
        this.ensureAgentMeta(agent.owner); // defaults to WARM, nextDueAt = now
      }
      logger.info(
        { overflow: overflow.length },
        'New Agent Watcher: excess agents queued for priority re-auditor'
      );
    }

    // Audit the capped batch with delay between each
    for (const agent of batch) {
      await this.auditAndBroadcast(agent);
      if (batch.indexOf(agent) < batch.length - 1) {
        await sleep(WATCHER_AGENT_DELAY_MS);
      }
    }
  }
```

**Step 2: Run type-check**

Run: `bun run type-check`
Expected: May still have issues from Task 3/5 references. Addressed in Task 7.

**Step 3: Commit**

```bash
git add src/plugin.ts
git commit -m "feat: add backpressure to watcher with batch cap and delay"
```

---

### Task 7: Update Actions, Provider, and Dashboard References

**Files:**
- Modify: `src/plugin.ts:1380-1386` (WATCHER_STATUS action)
- Modify: `src/plugin.ts:1441-1466` (REAUDIT_NOW action)
- Modify: `src/plugin.ts:1707-1732` (dashboard API JSON)
- Modify: `src/plugin.ts:1860-1910` (dashboard HTML)

**Step 1: Update WATCHER_STATUS action text**

Replace the re-auditor status lines (~1380-1386):

```typescript
      `**Tiered Re-Auditor**`,
      `${reauditorRunning ? '🟢' : '🔴'} ${reauditorRunning ? 'Running' : 'Stopped'}${svc.reauditorRunning ? ' *(micro-cycle in progress)*' : ''}`,
      `Cycle: every ${(REAUDIT_CYCLE_INTERVAL_MS / 60000).toFixed(0)}min | ${REAUDIT_AGENTS_PER_CYCLE} agents/cycle | ${REAUDIT_AGENT_DELAY_MS / 1000}s delay`,
      `Tiers: HOT=${(REAUDIT_TIER_HOT_MS / 3600000).toFixed(0)}h / WARM=${(REAUDIT_TIER_WARM_MS / 3600000).toFixed(0)}h / COOL=${(REAUDIT_TIER_COOL_MS / 3600000).toFixed(0)}h`,
      `Last micro-cycle: ${svc.reauditorLastRun?.toUTCString() ?? 'Not yet run'}`,
      `Last cycle: ${svc.reauditorLastCycleStats ? `${svc.reauditorLastCycleStats.audited} audited, ${svc.reauditorLastCycleStats.alerts} alerts` : 'N/A'}`,
      `Tier distribution: HOT=${tierCounts.HOT} / WARM=${tierCounts.WARM} / COOL=${tierCounts.COOL}`,
      `Coverage: ${svc.auditHistory.size}/${svc.knownAgentWallets.size} agents audited | ${svc.reauditorTotalAuditsToday} audits today`,
```

Before this block, compute tier counts:

```typescript
    const tierCounts = { HOT: 0, WARM: 0, COOL: 0 };
    for (const meta of svc.agentMeta.values()) tierCounts[meta.tier]++;
```

**Step 2: Update REAUDIT_NOW action**

Replace line 1449:

```typescript
    const total = Math.min(svc.knownAgentWallets.size, REAUDIT_BATCH_SIZE);
```

With:

```typescript
    const total = Math.min(svc.knownAgentWallets.size, REAUDIT_AGENTS_PER_CYCLE);
```

Replace line 1451:

```typescript
      text: `Starting re-audit cycle for up to **${total}** agents (${REAUDIT_DELAY_MS}ms between each). I'll report when done.`,
```

With:

```typescript
      text: `Starting micro-cycle for up to **${total}** agents (${REAUDIT_AGENT_DELAY_MS / 1000}s between each). I'll report when done.`,
```

Replace line 1456:

```typescript
    void svc.runReauditCycle(true).then(({ audited, alerts }) => {
```

With:

```typescript
    void svc.runMicroCycle().then(({ audited, alerts }) => {
```

**Step 3: Update dashboard API JSON**

Replace the `reauditor` block in the dashboard API (~1719-1729):

```typescript
          reauditor: {
            running: svc.reauditorTimer !== null,
            cycleInProgress: svc.reauditorRunning,
            lastRun: svc.reauditorLastRun?.toISOString() ?? null,
            lastCycleStats: svc.reauditorLastCycleStats,
            auditsToday: svc.reauditorTotalAuditsToday,
            cycleIntervalMs: REAUDIT_CYCLE_INTERVAL_MS,
            agentsPerCycle: REAUDIT_AGENTS_PER_CYCLE,
            tierDistribution: (() => {
              const counts = { HOT: 0, WARM: 0, COOL: 0 };
              for (const meta of svc.agentMeta.values()) counts[meta.tier]++;
              return counts;
            })(),
            coverage: {
              audited: svc.auditHistory.size,
              total: svc.knownAgentWallets.size,
            },
          },
```

**Step 4: Update dashboard HTML**

In the dashboard HTML, replace the re-auditor display line (~1872) that reads:

```javascript
      'Poll every '+Math.round(d.watcher.pollIntervalMs/60000)+'min',
```

Keep that line, but also update any reference to `d.reauditor.nextRun` (remove it) and add tier distribution display. Replace the re-auditor info section with:

```javascript
      'Re-auditor: '+(d.reauditor.running?'running':'stopped')+
      ' | '+d.reauditor.agentsPerCycle+'/cycle every '+Math.round(d.reauditor.cycleIntervalMs/60000)+'min'+
      ' | '+d.reauditor.auditsToday+' audits today'+
      ' | HOT:'+d.reauditor.tierDistribution.HOT+' WARM:'+d.reauditor.tierDistribution.WARM+' COOL:'+d.reauditor.tierDistribution.COOL,
```

**Step 5: Run type-check**

Run: `bun run type-check`
Expected: PASS — all references to removed fields should now be fixed.

**Step 6: Commit**

```bash
git add src/plugin.ts
git commit -m "feat: update actions, dashboard, and provider for tiered re-auditor"
```

---

### Task 8: Update CLAUDE.md and .env.example

**Files:**
- Modify: `CLAUDE.md` (env var documentation)
- Modify: `.env.example` (if it exists and has old vars)

**Step 1: Update CLAUDE.md env var section**

Replace the old re-auditor env vars:

```bash
REAUDIT_INTERVAL_MS=21600000        # 6 hours
REAUDIT_BATCH_SIZE=20
REAUDIT_DELAY_MS=1000
```

With:

```bash
# Re-auditor (tiered micro-cycle scheduler)
REAUDIT_CYCLE_INTERVAL_MS=600000    # 10 min between micro-cycles
REAUDIT_AGENTS_PER_CYCLE=8          # Agents per micro-cycle
REAUDIT_AGENT_DELAY_MS=15000        # 15s between agents (RPC rate limit)
REAUDIT_TIER_HOT_MS=7200000         # 2h — FAIL/WARNING/high drift
REAUDIT_TIER_WARM_MS=43200000       # 12h — new/unknown/moderate drift
REAUDIT_TIER_COOL_MS=172800000      # 48h — stable PASS

# Watcher backpressure
WATCHER_BATCH_CAP=10                # Max new agents audited per poll
WATCHER_AGENT_DELAY_MS=15000        # 15s between new agent audits
```

**Step 2: Update .env.example similarly**

**Step 3: Commit**

```bash
git add CLAUDE.md .env.example
git commit -m "docs: update env var documentation for tiered re-auditor"
```

---

### Task 9: Run Full Test Suite and Verify

**Files:**
- All test files

**Step 1: Run type-check**

Run: `bun run type-check`
Expected: PASS

**Step 2: Run full test suite**

Run: `bun test`
Expected: All existing tests pass, new tier classification tests pass.

**Step 3: Run build**

Run: `bun run build`
Expected: Build succeeds.

**Step 4: Commit any fixes if needed**

```bash
git add -A
git commit -m "fix: resolve any test/build issues from re-auditor refactor"
```

---

### Task 10: Update Daily Digest for Tier Info

**Files:**
- Modify: `src/plugin.ts:811-874` (sendDailyDigest)

**Step 1: Add tier stats to daily digest**

In `sendDailyDigest()`, after the re-audit summary section, add tier distribution:

```typescript
    // Tier distribution
    const tierCounts = { HOT: 0, WARM: 0, COOL: 0 };
    for (const meta of this.agentMeta.values()) tierCounts[meta.tier]++;
    lines.push(`Tiers: 🔴 HOT ${tierCounts.HOT} · 🟡 WARM ${tierCounts.WARM} · 🟢 COOL ${tierCounts.COOL}`);
    lines.push(`Audits (24h): ${this.reauditorTotalAuditsToday}`);
```

**Step 2: Run type-check**

Run: `bun run type-check`
Expected: PASS

**Step 3: Commit**

```bash
git add src/plugin.ts
git commit -m "feat: add tier distribution stats to daily digest"
```
