# Design: CLAUDE.md Improvements

**Date:** 2026-03-01
**Topic:** Replace generic ElizaOS template with project-specific lean context doc
**Approach:** B — Lean context doc (~80-100 lines)

## Problem

The current `CLAUDE.md` is a copy of the default ElizaOS project template documentation. It tells Claude how to use ElizaOS generically but says nothing about what Said Sentinel is, how it works, or what conventions to follow. This makes every Claude Code session start from zero context.

## Approved Design

### Section 1 — Project identity

Said Sentinel is an ElizaOS audit agent for the Said Protocol on Solana. It audits on-chain PDAs for identity verification, inspects Solana transaction payloads for protocol compliance, and validates A2A (Agent-to-Agent) JSON message envelopes. Every audit produces a cryptographically signed `SAID_v1` report using the Sentinel's on-chain keypair. The agent also tracks trust score drift over time and fires alerts via Telegram. A public React dashboard shows live audit history.

Package manager: `bun` (required — never use npm or yarn).

### Section 2 — Key files

| File | Role |
|---|---|
| `src/plugin.ts` | All core agent logic: audit actions, drift detection, Telegram alerts, re-audit scheduler |
| `src/character.ts` | Agent personality, plugin composition (env-gated plugins) |
| `src/frontend/` | React/Vite public dashboard |
| `src/index.ts` | Entry point and exports |
| `build.ts` | Custom build script (used by `bun run build`) |
| `fly.toml` | fly.io deployment config |

### Section 3 — Commands

```bash
bun dev              # Start with hot reload (recommended for development)
bun start            # Start without hot reload (requires bun run build first)
bun run build        # Build (runs build.ts)
bun test             # Run component tests
bun run type-check   # TypeScript check
bun run lint         # Format with Prettier
fly deploy           # Deploy to fly.io
```

### Section 4 — Required environment variables

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
REAUDIT_INTERVAL_MS=21600000        # 6 hours
REAUDIT_BATCH_SIZE=20
REAUDIT_DELAY_MS=1000
```

### Section 5 — Key conventions

- All core agent logic lives in `src/plugin.ts` — don't spread it across new files
- The `SAID_v1` schema shape is canonical — never modify `SaidAuditResult`'s structure
- Every audit report must be signed via `signPayload()` using the Sentinel keypair — `attestation.signature` is not optional
- Solana address detection: 32–44 char base58; TX signature detection: 87–88 char base58
- Drift history is persisted to `/app/data/drift-history.json` (max 50 records per agent)
- Use `@solana/web3.js` and `said-sdk` directly — do **not** add `@elizaos/plugin-solana`
- All dependencies managed with `bun add` — never `npm install` or `yarn add`

## Implementation

Replace the entire contents of `CLAUDE.md` with a new lean context doc using the 5 approved sections above. Target length: ~80-100 lines. Remove all generic ElizaOS template content.
