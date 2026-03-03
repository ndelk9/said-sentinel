# Said Sentinel — Claude Code Context

## What This Project Is

Said Sentinel is an ElizaOS audit agent for the Said Protocol on Solana. It audits on-chain PDAs for identity verification, inspects Solana transaction payloads for protocol compliance, and validates A2A (Agent-to-Agent) JSON message envelopes. Every audit produces a cryptographically signed `SAID_v1` report using the Sentinel's on-chain keypair. The agent also tracks trust score drift over time and fires alerts via Telegram. A public React dashboard shows live audit history.

Package manager: **`bun`** (required — never use npm or yarn).

---

## Key Files

| File | Role |
|---|---|
| `src/plugin.ts` | All core agent logic: audit actions, drift detection, Telegram alerts, re-audit scheduler |
| `src/character.ts` | Agent personality, plugin composition (env-gated plugins) |
| `src/frontend/` | React/Vite public dashboard |
| `src/index.ts` | Entry point and exports |
| `build.ts` | Compiles TypeScript and builds the Vite frontend; invoked by `bun run build` |
| `fly.toml` | fly.io deployment config |

---

## Commands

```bash
bun dev              # Start with hot reload (recommended for development)
bun start            # Start without hot reload (requires bun run build first)
bun run build        # Build (runs build.ts)
bun test             # Install test deps, then run component + e2e tests (slow)
bun run type-check   # TypeScript check
bun run lint         # Reformat src/ with Prettier (modifies files; use format:check to only check)
fly deploy           # Deploy to fly.io
```

---

## Environment Variables

```bash
# Sentinel identity (required)
SOLANA_PRIVATE_KEY=          # JSON byte array, e.g. [12,34,...]
SOLANA_PUBLIC_KEY=           # Base58 public key

# Solana / Said Protocol
SOLANA_RPC_URL=              # Default: mainnet-beta public RPC
SAID_PROGRAM_ID=             # Default: 5dpw6KEQPn248pnkkaYyWfHwu2nfb3LUMbTucb6LaA8G
SAID_API_ROOT=               # Default: https://api.saidprotocol.com

# Telegram alerts (optional but recommended)
TELEGRAM_BOT_TOKEN=
TELEGRAM_AUDIT_CHANNEL_ID=

# LLM provider — at least one required
ANTHROPIC_API_KEY=
OPENAI_API_KEY=
OPENROUTER_API_KEY=
OLLAMA_API_ENDPOINT=

# Polling / batch tuning (optional, defaults shown)
WATCHER_POLL_INTERVAL_MS=300000     # 5 min

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

---

## Conventions

- All core agent logic lives in `src/plugin.ts` — don't spread it across new files
- The `SAID_v1` schema shape is canonical — never modify `SaidAuditResult`'s structure
- Every audit report must be signed via `signPayload()` using the Sentinel keypair — `attestation.signature` is not optional
- Solana address detection: 32–44 char base58; TX signature detection: 87–88 char base58
- Drift history is persisted to `/app/data/drift-history.json` (max 50 records per agent)
- Use `@solana/web3.js` and `said-sdk` directly — do **not** add `@elizaos/plugin-solana`
- All dependencies managed with `bun add` — never `npm install` or `yarn add`
