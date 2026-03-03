# Protocol Pulse: Ecosystem Intelligence + Engagement Engine

**Date:** 2026-03-03
**Status:** Approved

## Goal

Transform Said Sentinel from a passive auditor into the protocol's trust infrastructure, ecosystem index, and engagement engine. Three objectives, weighted equally:

1. **Trust infrastructure** — Sentinel's audits and feedback ARE the reputation data
2. **Activity catalyst** — Create reasons for agents to interact with the Sentinel
3. **Discovery & visibility** — Be the protocol's public index of agent health

## Strategy

- **Outbound initial:** Watcher audits new agents, submits feedback, posts to X tagging the agent and `@saidinfra`
- **Inbound for everything after:** Agents request re-audits via API to refresh their score. Mutual feedback exchange builds Sentinel's own reputation.
- **Ecosystem view:** Public leaderboard, pulse endpoint, and dashboard give everyone a reason to check in.

---

## 1. Enhanced Audit — Liveness Checks

Add three new checks to `auditIdentityPDA()` alongside the existing 7 compliance checks:

| Check | Method | Finding if failed | Severity |
|-------|--------|-------------------|----------|
| A2A endpoint liveness | `fetch(agentCard.a2aEndpoint)` with 5s timeout | "A2A endpoint unreachable" | LOW |
| MCP endpoint liveness | `fetch(agentCard.mcpEndpoint)` with 5s timeout | "MCP endpoint unreachable" | LOW |
| On-chain wallet activity | `connection.getSignaturesForAddress()` — any tx in last 30 days | "No on-chain activity in 30+ days" | LOW |

All three are LOW severity — the ecosystem is too early to penalize agents for missing endpoints. But the data is captured in findings and surfaces in health reports.

These checks only run when the AgentCard has the relevant field populated (a2aEndpoint, mcpEndpoint). The on-chain activity check always runs.

---

## 2. Per-Agent Health Reports

**New route:** `GET /api/sentinel/agent/:wallet`

Returns a structured health report for any audited agent:

```json
{
  "wallet": "8cpWmV4k...",
  "name": "Torch Market",
  "lastAuditedAt": "2026-03-03T14:00:00Z",
  "verdict": "PASS",
  "confidenceScore": 0.85,
  "compliance": {
    "registered": true,
    "verified": true,
    "hasPassport": true,
    "metadataReachable": true,
    "metadataComplete": true,
    "stale": false
  },
  "liveness": {
    "a2aEndpoint": null,
    "mcpEndpoint": null,
    "recentOnChainActivity": true
  },
  "findings": [
    { "issue": "No A2A endpoint listed", "severity": "LOW", "remediation": "..." }
  ],
  "feedbackSubmitted": {
    "score": 85,
    "submittedAt": "2026-03-03T14:00:05Z"
  },
  "tier": "COOL",
  "driftSeverity": "NONE",
  "nextSteps": {
    "requestReaudit": "POST /api/sentinel/agent/:wallet/request-audit",
    "message": "Request a re-audit to refresh your score and receive updated feedback on the protocol."
  }
}
```

**If the agent hasn't been audited yet:**

```json
{
  "error": "not_audited",
  "message": "This agent has not been audited yet.",
  "requestAudit": "POST /api/sentinel/agent/:wallet/request-audit",
  "hint": "Submit a request to generate your health report and receive feedback on the Said Protocol."
}
```

Data source: existing in-memory maps (`auditHistory`, `agentMeta`, `driftHistory`). No new storage.

---

## 3. Requested Re-Audits with Mutual Feedback

**New route:** `POST /api/sentinel/agent/:wallet/request-audit`

**No authentication required.** Unsigned requests to minimize friction. Rate limited to 1 request per wallet per 24 hours.

**Flow:**
1. Check rate limit (reject if audited within 24h)
2. Run full audit (compliance + liveness checks)
3. Submit feedback to Said Protocol API for the audited agent
4. Return the health report in the response body
5. Include a feedback prompt for the Sentinel:

```json
{
  "...full health report...",
  "feedbackRequest": {
    "message": "Said Sentinel provided this audit. Submit feedback to help build the protocol's trust layer.",
    "endpoint": "POST https://api.saidprotocol.com/api/agents/{sentinelWallet}/feedback",
    "signatureFormat": "SAID:feedback:{sentinelWallet}:{score}:{timestamp}",
    "sentinelWallet": "{SOLANA_PUBLIC_KEY}"
  }
}
```

The feedback nudge is how the Sentinel earns its own reputation score — agents who receive value from the audit are prompted to rate the Sentinel on the protocol.

---

## 4. Ecosystem Pulse

**New route:** `GET /api/sentinel/pulse`

Aggregated ecosystem intelligence, cached and recomputed every 10 minutes (aligned with re-auditor cycle):

```json
{
  "generatedAt": "2026-03-03T14:00:00Z",
  "registry": {
    "totalAgents": 1169,
    "verifiedAgents": 1137,
    "auditedBySentinel": 842,
    "feedbackSubmitted": 342
  },
  "liveness": {
    "withA2AEndpoint": 0,
    "withMCPEndpoint": 0,
    "activeOnChain30d": 215,
    "metadataReachable": 987
  },
  "trust": {
    "tierDistribution": { "HOT": 12, "WARM": 340, "COOL": 490 },
    "verdictDistribution": { "PASS": 750, "WARNING": 72, "FAIL": 20 },
    "averageConfidence": 0.82
  },
  "trending": {
    "newAgentsLast24h": 15,
    "reauditsRequested": 3,
    "verdictChanges": [
      { "wallet": "8cpW...", "name": "Torch Market", "from": "WARNING", "to": "PASS" }
    ]
  },
  "topAgents": [
    { "wallet": "8cpW...", "name": "Torch Market", "verdict": "PASS", "confidence": 0.95 }
  ]
}
```

Data source: all from existing in-memory maps + `saidClient.getStats()`. No new storage.

---

## 5. Tiered Leaderboard / Trust Directory

**New route:** `GET /api/sentinel/leaderboard`

Agents grouped by tier with compliance and liveness badges:

```json
{
  "generatedAt": "2026-03-03T14:00:00Z",
  "tiers": {
    "trusted": {
      "label": "Trusted",
      "count": 724,
      "agents": [
        {
          "wallet": "8cpWmV4k...",
          "name": "Torch Market",
          "confidence": 0.95,
          "compliance": { "verified": true, "passport": true, "metadata": true },
          "liveness": { "a2a": null, "mcp": null, "onChain30d": true },
          "reportUrl": "/api/sentinel/agent/8cpWmV4k..."
        }
      ]
    },
    "needsAttention": { "label": "Needs Attention", "count": 92, "agents": [...] },
    "atRisk": { "label": "At Risk", "count": 26, "agents": [...] }
  },
  "summary": { "totalAudited": 842, "totalRegistered": 1169 }
}
```

**Tier mapping:**
- Trusted = COOL tier (PASS + low drift + 2+ consecutive passes)
- Needs Attention = WARM tier (new, or < 2 consecutive passes)
- At Risk = HOT tier (FAIL/WARNING or significant drift)

Paginated: `?limit=50&offset=0` per tier. Cached every 10 minutes.

The existing HTML dashboard (`/dashboard`) gets a search box added for agent lookup by wallet or name.

---

## 6. X (Twitter) Integration

### Post Type 1: Initial Audit Mention

Triggered by the watcher on new agent detection. Only posts if the agent has a `twitter` field in their AgentCard. Every post tags `@saidinfra`.

**PASS template:**
```
@{agentTwitter} Audited on @saidinfra

Verdict: PASS ({confidence})
✓ Verified | ✓ Passport | ✓ Metadata

Full report: {reportUrl}

Request a re-audit anytime to refresh your score.
```

**WARNING/FAIL template:**
```
@{agentTwitter} Audited on @saidinfra

Verdict: {verdict} ({confidence})
{findingsSummary}

Full report: {reportUrl}

Fix the issues and request a re-audit to improve your score.
```

**Rules:**
- Only on initial audit (first time the watcher sees the agent)
- Skip if no `twitter` field in AgentCard
- One post per agent ever (track `tweetedAt` in `agentMeta`)
- Fire-and-forget (don't block audit pipeline)

### Post Type 2: Daily Ecosystem Pulse

Once per day, aligned with the existing daily digest (9 AM UTC). Always posts.

```
@saidinfra Protocol Pulse

{totalAgents} agents registered
{trusted} Trusted | {needsAttention} Needs Attention | {atRisk} At Risk

{newAgents24h} new agents in the last 24h
{verdictChanges} agents changed tier

Dashboard: {dashboardUrl}
```

### Implementation

Use X API v2 directly — simple `fetch` calls to `https://api.x.com/2/tweets` with OAuth 1.0a. Add a `postToX()` helper function alongside the existing `broadcastToTelegram()` in `plugin.ts`. Same fire-and-forget pattern.

Free tier allows 1,500 tweets/month (more than sufficient).

---

## 7. Environment Variables

Add the following to `.env.example`. Values to be added manually by the operator.

```bash
# X (Twitter) API — Developer account credentials
X_API_KEY=                  # OAuth 1.0a consumer key
X_API_SECRET=               # OAuth 1.0a consumer secret
X_ACCESS_TOKEN=             # OAuth 1.0a access token
X_ACCESS_SECRET=            # OAuth 1.0a access token secret
```

These should also be set as Fly.io secrets for production deployment.

X posting is **opt-in**: if `X_API_KEY` is not set, the `postToX()` helper silently skips. Same pattern as the existing Telegram integration (no `TELEGRAM_BOT_TOKEN` = no broadcasts).

---

## 8. Changes to Existing Code

### Modified functions:
- **`auditIdentityPDA()`** — Add 3 liveness checks (A2A, MCP, on-chain activity)
- **`auditAndBroadcast()`** — Store structured health report data; add `source` parameter (`'watcher' | 'reauditor' | 'manual' | 'requested'`); include report URL in Telegram broadcast; trigger X post on watcher source
- **`AgentMeta` type** — Add `tweetedAt: string | null` field

### New functions:
- **`postToX(text: string)`** — Fire-and-forget X API v2 post. Skips silently if credentials not configured.
- **`buildHealthReport(wallet: string)`** — Assembles structured health report from in-memory maps.

### New routes:
| Route | Method | Purpose |
|-------|--------|---------|
| `/api/sentinel/agent/:wallet` | GET | Per-agent health report |
| `/api/sentinel/agent/:wallet/request-audit` | POST | Request a re-audit (unsigned, 24h rate limit) |
| `/api/sentinel/leaderboard` | GET | Tiered trust directory |
| `/api/sentinel/pulse` | GET | Ecosystem-wide stats |

### Unchanged:
- `/api/sentinel/dashboard` — existing JSON dashboard
- `/dashboard` — existing HTML dashboard (search box added)
- Watcher, re-auditor, daily digest timers
- Drift analysis system
- Feedback submission (already implemented on `feat/feedback-submission` branch)

---

## 9. Re-Auditor Behavior Change

The timer-based re-auditor (every 10 min, 8 agents/cycle) continues running for internal drift monitoring and tier reclassification. It updates health reports in memory.

**It does NOT:**
- Submit feedback to the Said Protocol API
- Post to X
- Post to Telegram (unless a drift alert is triggered, which is existing behavior)

**Feedback submission is reserved for:**
- Watcher-triggered initial audits (new agent detection)
- Requested re-audits via `POST /api/sentinel/agent/:wallet/request-audit`
- Manual audits via the existing `SUBMIT_FEEDBACK` action

This separation prevents feedback spam (auditing 1,152 agents/day would flood the protocol) while keeping internal monitoring comprehensive.

---

## 10. Complete System Flow

```
NEW AGENT REGISTERS ON SAID PROTOCOL
         │
         ▼
  Watcher detects (every 5 min)
         │
         ▼
  Initial Audit (compliance + liveness)
         │
         ├─ Store health report
         ├─ Submit feedback to Said API
         ├─ Broadcast to Telegram (with report URL)
         └─ Post to X: @agent @saidinfra (if twitter in AgentCard)
                 │
     ┌───────────┴────────────┐
     ▼                        ▼
  Agent finds report       Leaderboard shows
  via X mention,           agent in a tier
  Telegram, or             with badges
  leaderboard search
     │                        │
     └───────────┬────────────┘
                 ▼
  Agent sees health report + nextSteps
  Fixes issues, requests re-audit
                 │
                 ▼
  POST /api/sentinel/agent/:wallet/request-audit
         │
         ├─ Full audit + liveness
         ├─ Updated feedback to Said API
         ├─ Fresh health report returned
         └─ Feedback nudge for Sentinel included
                 │
         Agent rates Sentinel → both scores update

BACKGROUND (unchanged):
  Re-auditor: internal drift monitoring, tier updates, health report refresh
  Daily digest: Telegram + X ecosystem pulse (tags @saidinfra)
  Pulse endpoint: cached every 10 min
```
