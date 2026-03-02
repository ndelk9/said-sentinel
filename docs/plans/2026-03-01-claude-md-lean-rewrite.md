# CLAUDE.md Lean Rewrite Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Replace the generic ElizaOS template in `CLAUDE.md` with a lean, project-specific context doc for Said Sentinel.

**Architecture:** Single file replacement — delete all existing content, write 5 approved sections (identity, key files, commands, env vars, conventions). Target ~80-100 lines. No new files needed.

**Tech Stack:** Markdown only. No code changes.

---

### Task 1: Verify current state

**Files:**
- Read: `CLAUDE.md`

**Step 1: Count current lines**

Run:
```bash
wc -l CLAUDE.md
```
Expected: 200+ lines (the generic ElizaOS template)

**Step 2: Confirm the file is the generic template**

Check that the file starts with `# ElizaOS Agent Project Development Guide for Claude` — this confirms we're replacing the right content.

---

### Task 2: Write the new CLAUDE.md

**Files:**
- Modify: `CLAUDE.md` (full replacement)

**Step 1: Replace the entire file with the approved lean context doc**

Write the following content exactly to `CLAUDE.md`:

```markdown
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
| `build.ts` | Custom build script (used by `bun run build`) |
| `fly.toml` | fly.io deployment config |

---

## Commands

```bash
bun dev              # Start with hot reload (recommended for development)
bun start            # Start without hot reload (requires bun run build first)
bun run build        # Build (runs build.ts)
bun test             # Run component tests
bun run type-check   # TypeScript check
bun run lint         # Format with Prettier
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
REAUDIT_INTERVAL_MS=21600000        # 6 hours
REAUDIT_BATCH_SIZE=20
REAUDIT_DELAY_MS=1000
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
```

**Step 2: Verify line count**

Run:
```bash
wc -l CLAUDE.md
```
Expected: 80-100 lines

**Step 3: Verify all 5 sections are present**

Run:
```bash
grep -n "^##" CLAUDE.md
```
Expected output should include:
```
## What This Project Is
## Key Files
## Commands
## Environment Variables
## Conventions
```

**Step 4: Commit**

```bash
git add CLAUDE.md
git commit -m "docs: replace generic ElizaOS template with said-sentinel lean context"
```

---

### Task 3: Verify the result

**Step 1: Read the final file**

Run:
```bash
cat CLAUDE.md
```
Confirm it reads cleanly, has no leftover template content, and all sections are complete.

**Step 2: Done**

No further action needed. The CLAUDE.md is now project-specific and will give Claude accurate context from the start of every session.
