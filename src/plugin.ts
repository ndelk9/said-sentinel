import type {
  Plugin,
  Action,
  ActionResult,
  Evaluator,
  Provider,
  IAgentRuntime,
  Memory,
  State,
  HandlerCallback,
  ProviderResult,
} from '@elizaos/core';
import { Service, logger } from '@elizaos/core';
import { readFile, writeFile, mkdir } from 'node:fs/promises';
import { Connection, Keypair, PublicKey } from '@solana/web3.js';
import { SAID, type AgentIdentity } from 'said-sdk';
import nacl from 'tweetnacl';
import { z } from 'zod';

// ─── Constants ────────────────────────────────────────────────────────────────
const SAID_PROGRAM_ID =
  process.env.SAID_PROGRAM_ID ?? '5dpw6KEQPn248pnkkaYyWfHwu2nfb3LUMbTucb6LaA8G';
const SAID_API_ROOT = process.env.SAID_API_ROOT ?? 'https://api.saidprotocol.com';
const RPC_URL = process.env.SOLANA_RPC_URL ?? 'https://api.mainnet-beta.solana.com';
const TELEGRAM_BOT_TOKEN = process.env.TELEGRAM_BOT_TOKEN ?? '';
const TELEGRAM_AUDIT_CHANNEL = process.env.TELEGRAM_AUDIT_CHANNEL_ID ?? '';
const WATCHER_POLL_MS = parseInt(process.env.WATCHER_POLL_INTERVAL_MS ?? '300000', 10); // 5 min
const PASSPORT_PROGRAM_ID = 'L2TExMFKdjpN9kozasaurPirfHy9P8sbXoAN1qA3S95';
const TOKEN_2022_PROGRAM_ID = new PublicKey('TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb');
const STALENESS_THRESHOLD_DAYS = 90;
const REAUDIT_INTERVAL_MS = parseInt(process.env.REAUDIT_INTERVAL_MS ?? '21600000', 10); // 6 hours
const REAUDIT_BATCH_SIZE = parseInt(process.env.REAUDIT_BATCH_SIZE ?? '20', 10);
const REAUDIT_DELAY_MS = parseInt(process.env.REAUDIT_DELAY_MS ?? '1000', 10); // 1s between agents

// ─── Config Schema ────────────────────────────────────────────────────────────
const configSchema = z.object({
  SOLANA_PRIVATE_KEY: z.string().min(1, 'SOLANA_PRIVATE_KEY is required'),
  SOLANA_PUBLIC_KEY: z.string().min(1, 'SOLANA_PUBLIC_KEY is required'),
  SOLANA_RPC_URL: z.string().optional(),
  SAID_PROGRAM_ID: z.string().optional(),
  SAID_API_ROOT: z.string().optional(),
});

// ─── Types ────────────────────────────────────────────────────────────────────
type AuditVerdict = 'PASS' | 'FAIL' | 'WARNING';
type FindingSeverity = 'LOW' | 'MEDIUM' | 'HIGH';

interface AuditFinding {
  issue: string;
  severity: FindingSeverity;
  remediation: string;
}

interface SaidAuditResult {
  protocol: 'SAID_v1';
  auditId: string;
  timestamp: string;
  target: string;
  verdict: AuditVerdict;
  confidenceScore: number;
  findings: AuditFinding[];
  attestation: {
    auditor: string;
    signature: string;
  };
}

interface AuditSnapshot {
  verdict: AuditVerdict;
  confidenceScore: number;
  timestamp: string;
}

type DriftSeverity = 'NONE' | 'MILD' | 'MODERATE' | 'SEVERE';

interface DriftRecord {
  timestamp: string;
  verdict: AuditVerdict;
  confidenceScore: number;
}

interface DriftAnalysis {
  wallet: string;
  recordCount: number;
  latestVerdict: AuditVerdict;
  baselineScore: number;
  latestScore: number;
  scoreDrop: number;       // baseline - latest (positive = getting worse)
  scoreTrend: number;      // slope over last 5 records (negative = declining)
  consecutiveAlerts: number;
  severity: DriftSeverity;
}

// ─── Helpers ──────────────────────────────────────────────────────────────────
function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
function isTxSignature(str: string): boolean {
  return /^[1-9A-HJ-NP-Za-km-z]{87,88}$/.test(str.trim());
}

function isSolanaAddress(str: string): boolean {
  return /^[1-9A-HJ-NP-Za-km-z]{32,44}$/.test(str.trim());
}

function isJsonEnvelope(str: string): boolean {
  try {
    const parsed = JSON.parse(str);
    return typeof parsed === 'object' && parsed !== null;
  } catch {
    return false;
  }
}

function loadKeypair(): Keypair {
  const raw = process.env.SOLANA_PRIVATE_KEY ?? '[]';
  const bytes = Uint8Array.from(JSON.parse(raw) as number[]);
  return Keypair.fromSecretKey(bytes);
}

function signPayload(payload: Omit<SaidAuditResult, 'attestation'>, keypair: Keypair): string {
  const message = Buffer.from(JSON.stringify(payload));
  const sig = nacl.sign.detached(message, keypair.secretKey);
  return Buffer.from(sig).toString('base64');
}

function extractAuditTarget(text: string): string | null {
  const txMatch = text.match(/\b([1-9A-HJ-NP-Za-km-z]{87,88})\b/);
  if (txMatch) return txMatch[1];
  const addrMatch = text.match(/\b([1-9A-HJ-NP-Za-km-z]{32,44})\b/);
  if (addrMatch) return addrMatch[1];
  return null;
}

function deriveVerdict(findings: AuditFinding[], score: number): AuditVerdict {
  if (findings.some((f) => f.severity === 'HIGH')) return 'FAIL';
  if (findings.some((f) => f.severity === 'MEDIUM') || score < 0.8) return 'WARNING';
  return 'PASS';
}

const DRIFT_HISTORY_FILE = '/app/data/drift-history.json';
const DRIFT_MAX_RECORDS = 50; // max records kept per agent

function computeDriftAnalysis(wallet: string, records: DriftRecord[]): DriftAnalysis {
  const latest = records[records.length - 1];
  const baseline = records[0];

  // Score trend: slope over last 5 records (negative = declining)
  const recent = records.slice(-5);
  const scoreTrend =
    recent.length > 1
      ? (recent[recent.length - 1].confidenceScore - recent[0].confidenceScore) /
        (recent.length - 1)
      : 0;

  // Consecutive non-PASS count from the end
  let consecutiveAlerts = 0;
  for (let i = records.length - 1; i >= 0; i--) {
    if (records[i].verdict !== 'PASS') consecutiveAlerts++;
    else break;
  }

  const scoreDrop = baseline.confidenceScore - latest.confidenceScore;

  // Severity ladder
  let severity: DriftSeverity = 'NONE';
  if (latest.verdict === 'FAIL' || consecutiveAlerts >= 4 || scoreDrop >= 0.3) {
    severity = 'SEVERE';
  } else if (consecutiveAlerts >= 3 || scoreDrop >= 0.2 || scoreTrend < -0.05) {
    severity = 'MODERATE';
  } else if (consecutiveAlerts >= 1 || scoreDrop >= 0.1 || scoreTrend < -0.02) {
    severity = 'MILD';
  }

  return {
    wallet,
    recordCount: records.length,
    latestVerdict: latest.verdict,
    baselineScore: baseline.confidenceScore,
    latestScore: latest.confidenceScore,
    scoreDrop,
    scoreTrend,
    consecutiveAlerts,
    severity,
  };
}

function severityRank(s: DriftSeverity): number {
  return { NONE: 0, MILD: 1, MODERATE: 2, SEVERE: 3 }[s];
}

function formatDriftAlert(analysis: DriftAnalysis): string {
  const icons: Record<DriftSeverity, string> = {
    NONE: '✅',
    MILD: '🟡',
    MODERATE: '🟠',
    SEVERE: '🔴',
  };
  const icon = icons[analysis.severity];

  const lines = [
    `${icon} *Reputation Drift Detected*`,
    ``,
    `Wallet: \`${analysis.wallet}\``,
    `Severity: *${analysis.severity}*`,
    `Latest Verdict: ${analysis.latestVerdict}`,
    `Consecutive Alerts: ${analysis.consecutiveAlerts}`,
    `Score: ${(analysis.baselineScore * 100).toFixed(0)}% → ${(analysis.latestScore * 100).toFixed(0)}% (${analysis.scoreDrop > 0 ? '-' : '+'}${(Math.abs(analysis.scoreDrop) * 100).toFixed(0)}%)`,
    `Trend (last 5): ${analysis.scoreTrend < 0 ? '📉' : '📈'} ${(analysis.scoreTrend * 100).toFixed(1)}%/audit`,
    `Records: ${analysis.recordCount} audits tracked`,
    ``,
    `_Said Sentinel Drift Monitor • ${new Date().toUTCString()}_`,
  ];

  return lines.join('\n');
}

// ─── Telegram Broadcast ───────────────────────────────────────────────────────
async function broadcastToTelegram(text: string): Promise<void> {
  if (!TELEGRAM_BOT_TOKEN || !TELEGRAM_AUDIT_CHANNEL) {
    logger.debug('Telegram broadcast skipped: TELEGRAM_BOT_TOKEN or TELEGRAM_AUDIT_CHANNEL_ID not configured');
    return;
  }
  try {
    const res = await fetch(`https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        chat_id: TELEGRAM_AUDIT_CHANNEL,
        text,
        parse_mode: 'Markdown',
        disable_web_page_preview: true,
      }),
      signal: AbortSignal.timeout(10000),
    });
    if (!res.ok) {
      const body = await res.text().catch(() => '');
      logger.warn({ status: res.status, body }, 'Telegram broadcast returned non-OK status');
    }
  } catch (err) {
    logger.warn({ err }, 'Telegram broadcast error');
  }
}

function formatAuditBroadcast(agent: AgentIdentity, audit: SaidAuditResult): string {
  const verdictEmoji = audit.verdict === 'PASS' ? '✅' : audit.verdict === 'FAIL' ? '❌' : '⚠️';
  const verifiedBadge = agent.isVerified ? '🔵 Verified' : '⬜ Unverified';
  const displayName = agent.card?.name ?? `${agent.owner.slice(0, 8)}...`;

  const lines: string[] = [
    `🔍 *New Agent Detected on Said Protocol*`,
    ``,
    `*${displayName}* — ${verifiedBadge}`,
    `Wallet: \`${agent.owner}\``,
  ];

  if (agent.card?.twitter) {
    lines.push(`Twitter: @${agent.card.twitter}`);
  }
  if (agent.card?.description) {
    lines.push(`_${agent.card.description}_`);
  }

  lines.push(``);
  lines.push(`${verdictEmoji} *Audit Result: ${audit.verdict}* (${(audit.confidenceScore * 100).toFixed(0)}% confidence)`);
  lines.push(`Audit ID: \`${audit.auditId.slice(0, 8)}\``);

  if (audit.findings.length > 0) {
    lines.push(``);
    lines.push(`*Findings:*`);
    for (const f of audit.findings) {
      const icon = f.severity === 'HIGH' ? '🔴' : f.severity === 'MEDIUM' ? '🟡' : '🟢';
      lines.push(`${icon} ${f.issue}`);
    }
  } else {
    lines.push(`No issues found.`);
  }

  lines.push(``);
  lines.push(`_Said Sentinel • ${new Date(audit.timestamp).toUTCString()}_`);

  return lines.join('\n');
}

function formatReauditBroadcast(
  wallet: string,
  audit: SaidAuditResult,
  prev: AuditSnapshot | null
): string {
  const verdictEmoji = audit.verdict === 'PASS' ? '✅' : audit.verdict === 'FAIL' ? '❌' : '⚠️';

  let headerEmoji = '🔄';
  if (prev) {
    if (audit.verdict === 'FAIL' && prev.verdict !== 'FAIL') headerEmoji = '🚨';
    else if (audit.verdict === 'PASS' && prev.verdict !== 'PASS') headerEmoji = '📈';
    else if (audit.verdict === 'WARNING' && prev.verdict === 'PASS') headerEmoji = '📉';
  }

  const lines: string[] = [
    `${headerEmoji} *Re-Audit Alert*`,
    ``,
    `Wallet: \`${wallet}\``,
    `${verdictEmoji} *${audit.verdict}* (${(audit.confidenceScore * 100).toFixed(0)}% confidence)`,
  ];

  if (prev) {
    lines.push(`Change: *${prev.verdict} → ${audit.verdict}*`);
    const scoreDelta = (audit.confidenceScore - prev.confidenceScore) * 100;
    if (Math.abs(scoreDelta) >= 5) {
      lines.push(`Score drift: ${scoreDelta > 0 ? '+' : ''}${scoreDelta.toFixed(0)}%`);
    }
  }

  if (audit.findings.length > 0) {
    lines.push(``);
    lines.push(`*Findings:*`);
    for (const f of audit.findings) {
      const icon = f.severity === 'HIGH' ? '🔴' : f.severity === 'MEDIUM' ? '🟡' : '🟢';
      lines.push(`${icon} ${f.issue}`);
    }
  }

  lines.push(``);
  lines.push(`_Said Sentinel Re-Auditor • ${new Date(audit.timestamp).toUTCString()}_`);

  return lines.join('\n');
}

// ─── Audit Logic ──────────────────────────────────────────────────────────────
async function auditTransaction(
  signature: string,
  connection: Connection
): Promise<{ findings: AuditFinding[]; confidenceScore: number }> {
  const findings: AuditFinding[] = [];
  let confidenceScore = 1.0;

  try {
    const tx = await connection.getParsedTransaction(signature, {
      commitment: 'confirmed',
      maxSupportedTransactionVersion: 0,
    });

    if (!tx) {
      findings.push({
        issue: 'Transaction not found on-chain',
        severity: 'HIGH',
        remediation: 'Verify the transaction signature is correct and the transaction is confirmed.',
      });
      return { findings, confidenceScore: 0.1 };
    }

    if (tx.meta?.err) {
      findings.push({
        issue: `Transaction failed on-chain: ${JSON.stringify(tx.meta.err)}`,
        severity: 'HIGH',
        remediation: 'Review the transaction error and resubmit with corrected parameters.',
      });
      confidenceScore -= 0.3;
    }

    const involvesSaidProgram = tx.transaction.message.accountKeys.some(
      (k) => k.pubkey.toString() === SAID_PROGRAM_ID
    );
    if (!involvesSaidProgram) {
      findings.push({
        issue: 'Transaction does not interact with the Said Protocol program',
        severity: 'MEDIUM',
        remediation: `Ensure the transaction includes program ID ${SAID_PROGRAM_ID} in its account keys.`,
      });
      confidenceScore -= 0.15;
    }

    const { preBalances, postBalances } = tx.meta ?? {};
    if (preBalances && postBalances) {
      const netChanges = preBalances.map((pre, i) => (postBalances[i] ?? 0) - pre);
      if ((netChanges[0] ?? 0) > 0) {
        findings.push({
          issue: 'Transaction signer gained balance — potential self-dealing detected',
          severity: 'HIGH',
          remediation:
            'Verify the transaction intent; the signer should not profit from protocol calls.',
        });
        confidenceScore -= 0.4;
      }
    }
  } catch (err) {
    findings.push({
      issue: `RPC error during transaction fetch: ${err instanceof Error ? err.message : String(err)}`,
      severity: 'MEDIUM',
      remediation: 'Retry the audit or switch to a more reliable RPC endpoint.',
    });
    confidenceScore -= 0.2;
  }

  return { findings, confidenceScore: Math.max(0, confidenceScore) };
}

async function auditIdentityPDA(
  address: string,
  saidClient: SAID,
  connection: Connection
): Promise<{ findings: AuditFinding[]; confidenceScore: number }> {
  const findings: AuditFinding[] = [];
  let confidenceScore = 1.0;

  try {
    // Use said-sdk to look up the agent PDA directly — handles derivation correctly
    const agent = await saidClient.lookup(address);

    if (!agent) {
      findings.push({
        issue: `No Said Protocol identity found for ${address}`,
        severity: 'HIGH',
        remediation:
          'Register with the Said Protocol: npx said register -k ./wallet.json -n "AgentName"',
      });
      return { findings, confidenceScore: 0.05 };
    }

    if (!agent.isVerified) {
      findings.push({
        issue: 'Agent is registered but not verified on Said Protocol',
        severity: 'MEDIUM',
        remediation: 'Complete verification: npx said verify -k ./wallet.json (costs 0.01 SOL)',
      });
      confidenceScore -= 0.2;
    }

    // Fetch full identity + reputation from Said API
    try {
      const resp = await fetch(`${SAID_API_ROOT}/api/verify/${address}`, {
        signal: AbortSignal.timeout(5000),
      });
      if (resp.ok) {
        const data = (await resp.json()) as {
          isVerified?: boolean;
          reputation?: { score?: number; totalInteractions?: number; positiveRatio?: number };
        };
        const score = data.reputation?.score ?? 0;
        const interactions = data.reputation?.totalInteractions ?? 0;
        if (interactions > 0 && score < 5000) {
          findings.push({
            issue: `Reputation score is low: ${score}/10000 across ${interactions} interactions`,
            severity: 'MEDIUM',
            remediation: 'Improve agent reliability to increase reputation score.',
          });
          confidenceScore -= 0.15;
        }
      } else {
        findings.push({
          issue: `Said API returned HTTP ${resp.status} for identity verification`,
          severity: 'LOW',
          remediation: 'Ensure the address is registered in the Said Protocol reputation system.',
        });
        confidenceScore -= 0.05;
      }
    } catch {
      findings.push({
        issue: 'Said Protocol API unreachable — reputation data unavailable',
        severity: 'LOW',
        remediation: 'Verify api.saidprotocol.com is reachable and retry.',
      });
      confidenceScore -= 0.05;
    }
    // ── Passport NFT check ────────────────────────────────────────────────────
    try {
      const tokenAccounts = await connection.getParsedTokenAccountsByOwner(
        new PublicKey(address),
        { programId: TOKEN_2022_PROGRAM_ID }
      );
      // A passport is a Token-2022 NFT: amount=1, decimals=0
      const hasPassport = tokenAccounts.value.some((acc) => {
        const info = acc.account.data.parsed?.info as
          | { tokenAmount?: { amount?: string; decimals?: number } }
          | undefined;
        return info?.tokenAmount?.amount === '1' && info?.tokenAmount?.decimals === 0;
      });
      if (!hasPassport) {
        findings.push({
          issue: 'No Said Protocol Passport NFT found for this agent wallet',
          severity: 'MEDIUM',
          remediation: 'Mint a Passport NFT at saidprotocol.com (costs ~0.056 SOL)',
        });
        confidenceScore -= 0.15;
      }
    } catch {
      // Non-fatal — RPC error, skip passport check
    }

    // ── Metadata URI validation ───────────────────────────────────────────────
    if (!agent.metadataUri) {
      findings.push({
        issue: 'Agent has no metadataUri set on-chain',
        severity: 'LOW',
        remediation: 'Set a metadataUri pointing to valid agent metadata JSON.',
      });
      confidenceScore -= 0.1;
    } else {
      try {
        const metaResp = await fetch(agent.metadataUri, { signal: AbortSignal.timeout(5000) });
        if (!metaResp.ok) {
          findings.push({
            issue: `metadataUri returned HTTP ${metaResp.status}: ${agent.metadataUri}`,
            severity: 'MEDIUM',
            remediation: 'Ensure the metadata URI is publicly accessible and returns valid JSON.',
          });
          confidenceScore -= 0.15;
        } else {
          const meta = (await metaResp.json()) as Record<string, unknown>;
          for (const field of ['name', 'description']) {
            if (!meta[field]) {
              findings.push({
                issue: `Agent metadata missing field: "${field}"`,
                severity: 'LOW',
                remediation: `Add "${field}" to the metadata JSON at ${agent.metadataUri}`,
              });
              confidenceScore -= 0.05;
            }
          }
        }
      } catch {
        findings.push({
          issue: `metadataUri is unreachable: ${agent.metadataUri}`,
          severity: 'MEDIUM',
          remediation: 'Ensure the metadata URI is publicly accessible.',
        });
        confidenceScore -= 0.15;
      }
    }

    // ── Staleness detection ───────────────────────────────────────────────────
    // registeredAt / verifiedAt come from Solana block time (Unix seconds)
    const toMs = (t: number) => (t > 1e12 ? t : t * 1000);
    const daysSince = (t: number) => (Date.now() - toMs(t)) / 86_400_000;

    if (agent.registeredAt) {
      const ageDays = daysSince(agent.registeredAt);
      if (!agent.isVerified && ageDays > STALENESS_THRESHOLD_DAYS) {
        findings.push({
          issue: `Agent registered ${Math.floor(ageDays)} days ago but has never been verified`,
          severity: 'MEDIUM',
          remediation: 'Complete verification or decommission the agent.',
        });
        confidenceScore -= 0.2;
      }
    }

    if (agent.isVerified && agent.verifiedAt) {
      const staleDays = daysSince(agent.verifiedAt);
      if (staleDays > STALENESS_THRESHOLD_DAYS) {
        findings.push({
          issue: `Verification is ${Math.floor(staleDays)} days old — identity may be stale`,
          severity: 'LOW',
          remediation: 'Re-verify the agent to confirm it is still active.',
        });
        confidenceScore -= 0.1;
      }
    }

  } catch (err) {
    findings.push({
      issue: `Invalid Solana address or RPC error: ${err instanceof Error ? err.message : String(err)}`,
      severity: 'HIGH',
      remediation: 'Provide a valid base58 Solana public key.',
    });
    confidenceScore = 0;
  }

  return { findings, confidenceScore: Math.max(0, confidenceScore) };
}

async function auditA2AEnvelope(
  json: object
): Promise<{ findings: AuditFinding[]; confidenceScore: number }> {
  const findings: AuditFinding[] = [];
  let confidenceScore = 1.0;
  const envelope = json as Record<string, unknown>;

  const REQUIRED_FIELDS = ['protocol', 'sender', 'recipient', 'intent', 'timestamp'];
  for (const field of REQUIRED_FIELDS) {
    if (!(field in envelope)) {
      findings.push({
        issue: `Missing required field: "${field}" in A2A message envelope`,
        severity: 'HIGH',
        remediation: `Add the "${field}" field per the Said Protocol A2A spec.`,
      });
      confidenceScore -= 0.15;
    }
  }

  if (envelope.protocol && envelope.protocol !== 'SAID_v1') {
    findings.push({
      issue: `Protocol field is "${envelope.protocol}" — expected "SAID_v1"`,
      severity: 'MEDIUM',
      remediation: 'Set the protocol field to "SAID_v1" for Said Protocol compatibility.',
    });
    confidenceScore -= 0.2;
  }

  if (envelope.sender && envelope.recipient && envelope.sender === envelope.recipient) {
    findings.push({
      issue: 'Sender and recipient are identical — possible hallucination or self-loop',
      severity: 'HIGH',
      remediation: 'Verify agent routing logic; sender and recipient must be distinct agents.',
    });
    confidenceScore -= 0.4;
  }

  return { findings, confidenceScore: Math.max(0, confidenceScore) };
}

// ─── Service ──────────────────────────────────────────────────────────────────
export class SaidSentinelService extends Service {
  static serviceType = 'said-sentinel';
  capabilityDescription =
    'Manages the Solana RPC connection, Sentinel keypair, and autonomous New Agent Watcher for Said Protocol audits.';
  connection!: Connection;
  keypair!: Keypair;
  saidClient!: SAID;
  knownAgentWallets: Set<string> = new Set();
  watcherTimer: ReturnType<typeof setInterval> | null = null;
  watcherStartedAt: Date | null = null;

  // Re-Auditor state
  auditHistory: Map<string, AuditSnapshot> = new Map();
  reauditorTimer: ReturnType<typeof setInterval> | null = null;
  reauditorRunning = false;
  reauditorLastRun: Date | null = null;
  reauditorNextRun: Date | null = null;
  reauditorLastCycleStats: { audited: number; alerts: number } | null = null;
  reauditorOffset = 0; // rotating cursor — advances each cycle so all agents are covered

  // Reputation Drift Monitor state
  driftHistory: Map<string, DriftRecord[]> = new Map();
  driftSeverityCache: Map<string, DriftSeverity> = new Map(); // last known severity per agent

  // Daily Digest state
  digestTimer: ReturnType<typeof setTimeout> | null = null;
  digestLastSent: Date | null = null;

  constructor(runtime: IAgentRuntime) {
    super(runtime);
  }

  static async start(runtime: IAgentRuntime): Promise<SaidSentinelService> {
    logger.info('*** Starting SaidSentinelService ***');
    const svc = new SaidSentinelService(runtime);
    svc.connection = new Connection(RPC_URL, 'confirmed');
    svc.keypair = loadKeypair();
    svc.saidClient = new SAID({ rpcUrl: RPC_URL, commitment: 'confirmed' });
    logger.info({ pubkey: svc.keypair.publicKey.toString() }, 'Said Sentinel keypair loaded');

    // Load persisted drift history before starting background services
    await svc.loadDriftHistory();

    // Start autonomous background services
    await svc.startWatcher();
    svc.startReauditor();
    svc.startDailyDigest();

    return svc;
  }

  static async stop(_runtime: IAgentRuntime): Promise<void> {
    logger.info('*** Stopping SaidSentinelService ***');
  }

  async stop(): Promise<void> {
    this.stopWatcher();
    this.stopReauditor();
    this.stopDailyDigest();
  }

  // ─── Reputation Drift Monitor ─────────────────────────────────────────────
  async loadDriftHistory(): Promise<void> {
    try {
      const raw = await readFile(DRIFT_HISTORY_FILE, 'utf-8');
      const parsed = JSON.parse(raw) as Record<string, DriftRecord[]>;
      this.driftHistory = new Map(Object.entries(parsed));

      // Restore auditHistory from the latest record so the re-auditor has context
      for (const [wallet, records] of this.driftHistory) {
        if (records.length > 0) {
          const latest = records[records.length - 1];
          this.auditHistory.set(wallet, latest);
          const analysis = computeDriftAnalysis(wallet, records);
          this.driftSeverityCache.set(wallet, analysis.severity);
        }
      }
      logger.info(
        { wallets: this.driftHistory.size },
        'Drift history loaded from disk'
      );
    } catch {
      logger.info('No existing drift history — starting fresh');
    }
  }

  async saveDriftHistory(): Promise<void> {
    try {
      await mkdir('/app/data', { recursive: true });
      const obj = Object.fromEntries(this.driftHistory);
      await writeFile(DRIFT_HISTORY_FILE, JSON.stringify(obj));
    } catch (err) {
      logger.warn({ err }, 'Failed to save drift history');
    }
  }

  appendDriftRecord(wallet: string, record: DriftRecord): DriftAnalysis {
    const records = this.driftHistory.get(wallet) ?? [];
    records.push(record);
    // Keep only the last DRIFT_MAX_RECORDS entries
    if (records.length > DRIFT_MAX_RECORDS) records.splice(0, records.length - DRIFT_MAX_RECORDS);
    this.driftHistory.set(wallet, records);
    return computeDriftAnalysis(wallet, records);
  }

  // ─── New Agent Watcher ─────────────────────────────────────────────────────
  async startWatcher(): Promise<void> {
    logger.info({ pollMs: WATCHER_POLL_MS }, 'New Agent Watcher: initializing...');

    // Seed the known-agents set so we don't re-audit existing agents on startup
    try {
      const existing = await this.saidClient.listAgents();
      for (const agent of existing) {
        this.knownAgentWallets.add(agent.owner);
      }
      logger.info(
        { knownCount: this.knownAgentWallets.size },
        'New Agent Watcher: seeded with existing agents'
      );
    } catch (err) {
      logger.warn({ err }, 'New Agent Watcher: could not seed initial agent list — will audit all on first poll');
    }

    this.watcherStartedAt = new Date();
    this.watcherTimer = setInterval(() => {
      void this.checkForNewAgents();
    }, WATCHER_POLL_MS);

    logger.info(
      { pollIntervalMinutes: WATCHER_POLL_MS / 60000 },
      'New Agent Watcher: running'
    );
  }

  stopWatcher(): void {
    if (this.watcherTimer) {
      clearInterval(this.watcherTimer);
      this.watcherTimer = null;
      logger.info('New Agent Watcher: stopped');
    }
  }

  // ─── Continuous Re-Auditor ─────────────────────────────────────────────────
  startReauditor(): void {
    this.reauditorNextRun = new Date(Date.now() + REAUDIT_INTERVAL_MS);
    this.reauditorTimer = setInterval(() => {
      void this.runReauditCycle();
    }, REAUDIT_INTERVAL_MS);
    logger.info(
      {
        intervalHours: (REAUDIT_INTERVAL_MS / 3600000).toFixed(1),
        batchSize: REAUDIT_BATCH_SIZE,
        delayMs: REAUDIT_DELAY_MS,
        firstRunAt: this.reauditorNextRun.toUTCString(),
      },
      'Continuous Re-Auditor: scheduled'
    );
  }

  stopReauditor(): void {
    if (this.reauditorTimer) {
      clearInterval(this.reauditorTimer);
      this.reauditorTimer = null;
      logger.info('Continuous Re-Auditor: stopped');
    }
  }

  // ─── Daily Digest ──────────────────────────────────────────────────────────
  startDailyDigest(): void {
    const msUntil9amUTC = (): number => {
      const now = new Date();
      const next = new Date(
        Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate(), 9, 0, 0, 0)
      );
      if (next.getTime() <= now.getTime()) next.setUTCDate(next.getUTCDate() + 1);
      return next.getTime() - now.getTime();
    };

    const schedule = (): void => {
      const delay = msUntil9amUTC();
      logger.info({ nextDigestIn: `${(delay / 3600000).toFixed(2)}h` }, 'Daily Digest: scheduled');
      this.digestTimer = setTimeout(() => {
        void this.sendDailyDigest().then(() => schedule());
      }, delay);
    };

    schedule();
  }

  stopDailyDigest(): void {
    if (this.digestTimer) {
      clearTimeout(this.digestTimer);
      this.digestTimer = null;
      logger.info('Daily Digest: stopped');
    }
  }

  async sendDailyDigest(): Promise<void> {
    logger.info('Daily Digest: building...');
    this.digestLastSent = new Date();

    // Registry stats
    let total = 0;
    let verified = 0;
    try {
      const stats = await this.saidClient.getStats();
      total = stats.total;
      verified = stats.verified;
    } catch {
      // non-fatal — proceed with cached counts
    }

    // Re-audit summary
    const cycleStats = this.reauditorLastCycleStats;
    const lastRunStr = this.reauditorLastRun?.toUTCString() ?? 'Not yet run';

    // Top at-risk agents (SEVERE first, then MODERATE, then by score drop)
    const atRisk = Array.from(this.driftHistory.entries())
      .filter(([, records]) => records.length > 0)
      .map(([wallet, records]) => computeDriftAnalysis(wallet, records))
      .filter((a) => severityRank(a.severity) >= severityRank('MODERATE'))
      .sort((a, b) => severityRank(b.severity) - severityRank(a.severity) || b.scoreDrop - a.scoreDrop)
      .slice(0, 3);

    const severityIcon: Record<DriftSeverity, string> = {
      NONE: '✅',
      MILD: '🟡',
      MODERATE: '🟠',
      SEVERE: '🔴',
    };

    const atRiskLines =
      atRisk.length > 0
        ? atRisk.map(
            (a) =>
              `  ${severityIcon[a.severity]} \`${a.wallet.slice(0, 8)}…\` — ${a.severity} (−${(a.scoreDrop * 100).toFixed(0)}pts over ${a.recordCount} audits)`
          )
        : ['  ✅ No high-risk agents detected'];

    const lines = [
      `📋 **Said Sentinel — Daily Digest**`,
      `${new Date().toUTCString()}`,
      ``,
      `**Registry**`,
      `• Total agents: **${total}** | Verified: **${verified}**`,
      `• Watcher tracking: **${this.knownAgentWallets.size}** wallets`,
      ``,
      `**Re-Audit Summary**`,
      `• Last cycle: ${lastRunStr}`,
      cycleStats
        ? `• Audited: **${cycleStats.audited}** | Alerts fired: **${cycleStats.alerts}**`
        : `• No cycle completed yet`,
      `• Coverage: ${this.auditHistory.size}/${this.knownAgentWallets.size} agents in history`,
      ``,
      `**Top At-Risk Agents**`,
      ...atRiskLines,
    ];

    await broadcastToTelegram(lines.join('\n'));
    logger.info('Daily Digest: sent');
  }

  async runReauditCycle(force = false): Promise<{ audited: number; alerts: number }> {
    if (this.reauditorRunning && !force) {
      logger.warn('Continuous Re-Auditor: previous cycle still running, skipping');
      return { audited: 0, alerts: 0 };
    }

    this.reauditorRunning = true;
    this.reauditorLastRun = new Date();
    this.reauditorNextRun = new Date(Date.now() + REAUDIT_INTERVAL_MS);

    const all = Array.from(this.knownAgentWallets);
    const total = all.length;
    let wallets: string[];

    if (total <= REAUDIT_BATCH_SIZE) {
      // Fewer agents than batch size — audit all of them
      wallets = all;
      this.reauditorOffset = 0;
    } else {
      // Rotate: take BATCH_SIZE starting from offset, wrapping around
      const start = this.reauditorOffset % total;
      const end = start + REAUDIT_BATCH_SIZE;
      wallets = end <= total
        ? all.slice(start, end)
        : [...all.slice(start), ...all.slice(0, end - total)];
      this.reauditorOffset = end % total;
    }

    logger.info(
      { total, auditing: wallets.length, offset: this.reauditorOffset },
      'Continuous Re-Auditor: cycle started'
    );

    let audited = 0;
    let alerts = 0;

    try {
      for (const wallet of wallets) {
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
            logger.info(
              { wallet, prevSeverity, newSeverity: driftAnalysis.severity },
              'Drift Monitor: severity worsened, alert broadcast'
            );
          } else {
            this.driftSeverityCache.set(wallet, driftAnalysis.severity);
          }

          // Broadcast only on verdict changes or first-time alerts — never spam unchanged PASSes
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

            logger.info(
              { wallet, prev: prev?.verdict ?? 'NEW', current: verdict },
              'Continuous Re-Auditor: verdict change detected and broadcast'
            );
          }

          audited++;
        } catch (err) {
          logger.warn({ err, wallet }, 'Continuous Re-Auditor: audit failed for wallet, skipping');
        }

        // Rate limit: pause between each agent
        await sleep(REAUDIT_DELAY_MS);
      }
    } finally {
      this.reauditorRunning = false;
      this.reauditorLastCycleStats = { audited, alerts };
      // Persist drift history to disk after every cycle
      await this.saveDriftHistory();
    }

    logger.info(
      { audited, alerts, skipped: wallets.length - audited },
      'Continuous Re-Auditor: cycle complete'
    );

    return { audited, alerts };
  }

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

    for (const agent of newAgents) {
      // Register immediately so concurrent polls don't re-audit the same agent
      this.knownAgentWallets.add(agent.owner);
      await this.auditAndBroadcast(agent);
    }
  }

  async auditAndBroadcast(agent: AgentIdentity): Promise<void> {
    const displayName = agent.card?.name ?? agent.owner.slice(0, 12) + '...';
    logger.info({ wallet: agent.owner, name: displayName }, 'New Agent Watcher: auditing new agent');

    let findings: AuditFinding[] = [];
    let confidenceScore = 1.0;

    try {
      ({ findings, confidenceScore } = await auditIdentityPDA(agent.owner, this.saidClient, this.connection));
    } catch (err) {
      logger.warn({ err, wallet: agent.owner }, 'New Agent Watcher: audit failed');
      findings = [{
        issue: `Audit engine error: ${err instanceof Error ? err.message : String(err)}`,
        severity: 'MEDIUM',
        remediation: 'Retry the audit manually.',
      }];
      confidenceScore = 0.5;
    }

    const verdict = deriveVerdict(findings, confidenceScore);
    const payload: Omit<SaidAuditResult, 'attestation'> = {
      protocol: 'SAID_v1',
      auditId: crypto.randomUUID(),
      timestamp: new Date().toISOString(),
      target: agent.owner,
      verdict,
      confidenceScore: Math.round(confidenceScore * 100) / 100,
      findings,
    };

    const signature = signPayload(payload, this.keypair);
    const auditResult: SaidAuditResult = {
      ...payload,
      attestation: {
        auditor: this.keypair.publicKey.toString(),
        signature,
      },
    };

    const broadcastMessage = formatAuditBroadcast(agent, auditResult);
    await broadcastToTelegram(broadcastMessage);

    logger.info(
      { wallet: agent.owner, verdict, auditId: auditResult.auditId, name: displayName },
      'New Agent Watcher: audit complete'
    );
  }
}

// ─── Provider ─────────────────────────────────────────────────────────────────
const saidTrustProvider: Provider = {
  name: 'SAID_TRUST_PROVIDER',
  description: 'Provides Said Sentinel identity context: Solana balance and Trust Tier.',

  get: async (runtime: IAgentRuntime, _message: Memory, _state: State): Promise<ProviderResult> => {
    const svc = runtime.getService<SaidSentinelService>(SaidSentinelService.serviceType);
    if (!svc) return { text: 'Said Sentinel service not available.', values: {}, data: {} };

    let balance = 0;
    let tier = 'UNKNOWN';

    try {
      const lamports = await svc.connection.getBalance(svc.keypair.publicKey);
      balance = lamports / 1e9;
    } catch (err) {
      logger.warn({ err }, 'Failed to fetch Sentinel SOL balance');
    }

    try {
      const resp = await fetch(
        `${SAID_API_ROOT}/api/verify/${svc.keypair.publicKey.toString()}`,
        { signal: AbortSignal.timeout(5000) }
      );
      if (resp.ok) {
        const data = (await resp.json()) as { isVerified?: boolean; trustTier?: string };
        tier = data.trustTier ?? (data.isVerified ? 'VERIFIED' : 'UNVERIFIED');
      }
    } catch {
      tier = 'API_UNREACHABLE';
    }

    const watcherStatus = svc.watcherTimer
      ? `Running (since ${svc.watcherStartedAt?.toUTCString() ?? 'unknown'}, tracking ${svc.knownAgentWallets.size} agents)`
      : 'Stopped';

    return {
      text: [
        'Said Sentinel Identity:',
        `- Public Key: ${svc.keypair.publicKey.toString()}`,
        `- SOL Balance: ${balance.toFixed(4)} SOL`,
        `- Trust Tier: ${tier}`,
        `- New Agent Watcher: ${watcherStatus}`,
      ].join('\n'),
      values: { balance, tier, pubkey: svc.keypair.publicKey.toString() },
      data: {},
    };
  },
};

// ─── Action: PERFORM_SAID_AUDIT ───────────────────────────────────────────────
const performSaidAuditAction: Action = {
  name: 'PERFORM_SAID_AUDIT',
  similes: ['AUDIT', 'VERIFY_IDENTITY', 'CHECK_TRANSACTION', 'INSPECT_AGENT', 'SAID_AUDIT'],
  description:
    'Audits a Solana transaction signature, agent address, or A2A JSON envelope against Said Protocol rules. Returns a signed SaidAuditResult.',

  validate: async (_runtime: IAgentRuntime, message: Memory): Promise<boolean> => {
    const text = message.content.text ?? '';
    return (
      /audit|verify|check|inspect/i.test(text) ||
      isTxSignature(text) ||
      isSolanaAddress(text) ||
      isJsonEnvelope(text)
    );
  },

  handler: async (
    runtime: IAgentRuntime,
    message: Memory,
    _state: State,
    _options: unknown,
    callback: HandlerCallback
  ): Promise<ActionResult> => {
    const svc = runtime.getService<SaidSentinelService>(SaidSentinelService.serviceType);
    if (!svc) {
      await callback({
        text: 'Said Sentinel service is not running. Cannot perform audit.',
        actions: [],
      });
      return { success: false, text: 'Service unavailable' };
    }

    const text = message.content.text ?? '';
    const target = extractAuditTarget(text) ?? text.trim();

    let findings: AuditFinding[] = [];
    let confidenceScore = 1.0;
    let auditType: 'TRANSACTION' | 'IDENTITY' | 'A2A' = 'IDENTITY';

    if (isTxSignature(target)) {
      auditType = 'TRANSACTION';
      ({ findings, confidenceScore } = await auditTransaction(target, svc.connection));
    } else if (isJsonEnvelope(text)) {
      auditType = 'A2A';
      ({ findings, confidenceScore } = await auditA2AEnvelope(JSON.parse(text) as object));
    } else if (isSolanaAddress(target)) {
      auditType = 'IDENTITY';
      ({ findings, confidenceScore } = await auditIdentityPDA(target, svc.saidClient, svc.connection));
    } else {
      await callback({
        text: `Cannot determine audit target from: "${target}". Provide a transaction signature, Solana address, or A2A JSON envelope.`,
        actions: [],
      });
      return { success: false, text: 'Unrecognized audit target' };
    }

    const verdict = deriveVerdict(findings, confidenceScore);
    const payload: Omit<SaidAuditResult, 'attestation'> = {
      protocol: 'SAID_v1',
      auditId: crypto.randomUUID(),
      timestamp: new Date().toISOString(),
      target,
      verdict,
      confidenceScore: Math.round(confidenceScore * 100) / 100,
      findings,
    };

    const signature = signPayload(payload, svc.keypair);
    const auditResult: SaidAuditResult = {
      ...payload,
      attestation: {
        auditor: svc.keypair.publicKey.toString(),
        signature,
      },
    };

    // Compact signed receipt — the LLM's own response is the primary user-facing message.
    await callback({
      text: `_Signed receipt — ID: \`${auditResult.auditId.slice(0, 8)}\` | ${verdict} | Auditor: \`${svc.keypair.publicKey.toString().slice(0, 8)}…\` | Sig: \`${signature.slice(0, 16)}…\`_`,
      actions: ['PERFORM_SAID_AUDIT'],
    });

    return {
      success: true,
      text: `Audit complete. Verdict: ${verdict}`,
      values: { verdict, confidenceScore, findingCount: findings.length, auditType },
      data: { auditResult },
    };
  },

  examples: [
    [
      { name: '{{name1}}', content: { text: 'Audit this transaction: 5UJdEY2Ywq...' } },
      {
        name: 'Said Sentinel',
        content: {
          text: '**Said Sentinel Audit Report**\nType: TRANSACTION | Verdict: **PASS**...',
          actions: ['PERFORM_SAID_AUDIT'],
        },
      },
    ],
    [
      {
        name: '{{name1}}',
        content: {
          text: 'Verify the identity tier of agent C8duVoymsgD4d1zFVLDTQ66vnF5hFM4PhqQ6jTFUdiec',
        },
      },
      {
        name: 'Said Sentinel',
        content: {
          text: '**Said Sentinel Audit Report**\nType: IDENTITY | Verdict: **PASS**...',
          actions: ['PERFORM_SAID_AUDIT'],
        },
      },
    ],
  ],
};

// ─── Action: LIST_AGENTS ──────────────────────────────────────────────────────
const listAgentsAction: Action = {
  name: 'LIST_AGENTS',
  similes: ['LIST_SAID_AGENTS', 'SHOW_AGENTS', 'GET_AGENTS', 'AGENT_REGISTRY', 'AGENT_STATS'],
  description:
    'Lists all agents registered on the Said Protocol with verification status, stats, and watcher state.',

  validate: async (_runtime: IAgentRuntime, message: Memory): Promise<boolean> => {
    return /list.*agents?|show.*agents?|how many agents?|agent.*registry|all agents?|agent.*stats?|registry/i.test(
      message.content.text ?? ''
    );
  },

  handler: async (
    runtime: IAgentRuntime,
    _message: Memory,
    _state: State,
    _options: unknown,
    callback: HandlerCallback
  ): Promise<ActionResult> => {
    const svc = runtime.getService<SaidSentinelService>(SaidSentinelService.serviceType);
    if (!svc) {
      await callback({ text: 'Said Sentinel service not available.', actions: [] });
      return { success: false, text: 'Service unavailable' };
    }

    let agents: AgentIdentity[] = [];
    let stats = { total: 0, verified: 0 };

    try {
      [agents, stats] = await Promise.all([
        svc.saidClient.listAgents({ includeCards: true }),
        svc.saidClient.getStats(),
      ]);
    } catch (err) {
      const errMsg = err instanceof Error ? err.message : String(err);
      await callback({
        text: `Failed to fetch agent registry: ${errMsg}`,
        actions: [],
      });
      return { success: false, text: 'Failed to fetch agents' };
    }

    const verifiedPct =
      stats.total > 0 ? ((stats.verified / stats.total) * 100).toFixed(0) : '0';

    // Sort by most recently registered
    const sorted = [...agents].sort((a, b) => b.registeredAt - a.registeredAt);
    const recentAgents = sorted.slice(0, 10);

    const lines: string[] = [
      `**Said Protocol Agent Registry**`,
      `Total Registered: **${stats.total}** | Verified: **${stats.verified}** (${verifiedPct}%)`,
      `Watcher Tracking: **${svc.knownAgentWallets.size}** agents`,
      ``,
      `**10 Most Recent Agents:**`,
      ...recentAgents.map((a, i) => {
        const name = a.card?.name ?? `${a.owner.slice(0, 8)}...`;
        const badge = a.isVerified ? '✅' : '⬜';
        const date = new Date(a.registeredAt * 1000).toLocaleDateString();
        const twitter = a.card?.twitter ? ` (@${a.card.twitter})` : '';
        return `${i + 1}. ${badge} **${name}**${twitter} \`${a.owner.slice(0, 10)}...\` _(${date})_`;
      }),
    ];

    const text = lines.join('\n');
    await callback({ text, actions: ['LIST_AGENTS'] });

    return {
      success: true,
      text: `Found ${stats.total} agents (${stats.verified} verified)`,
      values: { total: stats.total, verified: stats.verified },
      data: { agents: recentAgents, stats },
    };
  },

  examples: [
    [
      { name: '{{name1}}', content: { text: 'List all registered agents on Said Protocol' } },
      {
        name: 'Said Sentinel',
        content: {
          text: '**Said Protocol Agent Registry**\nTotal Registered: **42** | Verified: **15** (36%)...',
          actions: ['LIST_AGENTS'],
        },
      },
    ],
  ],
};

// ─── Action: WATCHER_STATUS ───────────────────────────────────────────────────
const watcherStatusAction: Action = {
  name: 'WATCHER_STATUS',
  similes: ['WATCHER_INFO', 'MONITORING_STATUS', 'CHECK_WATCHER', 'REAUDITOR_STATUS'],
  description:
    'Reports the current status of both the New Agent Watcher and the Continuous Re-Auditor.',

  validate: async (_runtime: IAgentRuntime, message: Memory): Promise<boolean> => {
    return /watcher|monitoring|watching|auto.?audit|new agent.*watch|re.?audit.*status|monitoring status/i.test(
      message.content.text ?? ''
    );
  },

  handler: async (
    runtime: IAgentRuntime,
    _message: Memory,
    _state: State,
    _options: unknown,
    callback: HandlerCallback
  ): Promise<ActionResult> => {
    const svc = runtime.getService<SaidSentinelService>(SaidSentinelService.serviceType);
    if (!svc) {
      await callback({ text: 'Said Sentinel service not available.', actions: [] });
      return { success: false, text: 'Service unavailable' };
    }

    const channelConfigured = Boolean(TELEGRAM_AUDIT_CHANNEL);
    const watcherRunning = svc.watcherTimer !== null;
    const reauditorRunning = svc.reauditorTimer !== null;

    const lines = [
      `**Said Sentinel — Monitoring Status**`,
      ``,
      `**New Agent Watcher**`,
      `${watcherRunning ? '🟢' : '🔴'} ${watcherRunning ? 'Running' : 'Stopped'}`,
      `Started: ${svc.watcherStartedAt?.toUTCString() ?? 'N/A'}`,
      `Poll interval: every ${WATCHER_POLL_MS / 60000} min`,
      `Agents tracked: ${svc.knownAgentWallets.size}`,
      ``,
      `**Continuous Re-Auditor**`,
      `${reauditorRunning ? '🟢' : '🔴'} ${reauditorRunning ? 'Scheduled' : 'Stopped'}${svc.reauditorRunning ? ' *(cycle in progress)*' : ''}`,
      `Interval: every ${(REAUDIT_INTERVAL_MS / 3600000).toFixed(1)}h | Batch: ${REAUDIT_BATCH_SIZE} agents | Delay: ${REAUDIT_DELAY_MS}ms`,
      `Last run: ${svc.reauditorLastRun?.toUTCString() ?? 'Not yet run'}`,
      `Next run: ${svc.reauditorNextRun?.toUTCString() ?? 'N/A'}`,
      `Last cycle: ${svc.reauditorLastCycleStats ? `${svc.reauditorLastCycleStats.audited} audited, ${svc.reauditorLastCycleStats.alerts} alerts` : 'N/A'}`,
      `Coverage: ${svc.auditHistory.size}/${svc.knownAgentWallets.size} agents audited | next offset: ${svc.reauditorOffset}`,
      ``,
      `**Broadcast**`,
      `${channelConfigured ? '✅ Telegram channel configured' : '⚠️ TELEGRAM_AUDIT_CHANNEL_ID not set'}`,
    ];

    await callback({ text: lines.join('\n'), actions: ['WATCHER_STATUS'] });

    return {
      success: true,
      text: `Watcher: ${watcherRunning ? 'running' : 'stopped'}, Re-auditor: ${reauditorRunning ? 'scheduled' : 'stopped'}`,
      values: { watcherRunning, reauditorRunning, trackedCount: svc.knownAgentWallets.size },
      data: {},
    };
  },

  examples: [
    [
      { name: '{{name1}}', content: { text: 'What is the monitoring status?' } },
      {
        name: 'Said Sentinel',
        content: {
          text: '**Said Sentinel — Monitoring Status**\n\n**New Agent Watcher**\n🟢 Running...',
          actions: ['WATCHER_STATUS'],
        },
      },
    ],
  ],
};

// ─── Action: REAUDIT_NOW ──────────────────────────────────────────────────────
const reauditNowAction: Action = {
  name: 'REAUDIT_NOW',
  similes: ['RUN_REAUDIT', 'TRIGGER_REAUDIT', 'AUDIT_ALL', 'START_REAUDIT_CYCLE'],
  description:
    'Manually triggers an immediate re-audit cycle across all known agents, ignoring the schedule.',

  validate: async (_runtime: IAgentRuntime, message: Memory): Promise<boolean> => {
    return /re.?audit now|run.*re.?audit|trigger.*re.?audit|audit all agents|force.*re.?audit/i.test(
      message.content.text ?? ''
    );
  },

  handler: async (
    runtime: IAgentRuntime,
    _message: Memory,
    _state: State,
    _options: unknown,
    callback: HandlerCallback
  ): Promise<ActionResult> => {
    const svc = runtime.getService<SaidSentinelService>(SaidSentinelService.serviceType);
    if (!svc) {
      await callback({ text: 'Said Sentinel service not available.', actions: [] });
      return { success: false, text: 'Service unavailable' };
    }

    if (svc.reauditorRunning) {
      await callback({
        text: `A re-audit cycle is already in progress. Check back shortly.`,
        actions: [],
      });
      return { success: false, text: 'Cycle already running' };
    }

    const total = Math.min(svc.knownAgentWallets.size, REAUDIT_BATCH_SIZE);
    await callback({
      text: `Starting re-audit cycle for up to **${total}** agents (${REAUDIT_DELAY_MS}ms between each). I'll report when done.`,
      actions: ['REAUDIT_NOW'],
    });

    // Run in background — don't await in handler
    void svc.runReauditCycle(true).then(({ audited, alerts }) => {
      logger.info({ audited, alerts }, 'REAUDIT_NOW: manual cycle complete');
    });

    return {
      success: true,
      text: `Re-audit cycle started for ${total} agents`,
      values: { total },
      data: {},
    };
  },

  examples: [
    [
      { name: '{{name1}}', content: { text: 'Reaudit all agents now' } },
      {
        name: 'Said Sentinel',
        content: {
          text: 'Starting re-audit cycle for up to **20** agents...',
          actions: ['REAUDIT_NOW'],
        },
      },
    ],
  ],
};

// ─── Action: DRIFT_REPORT ─────────────────────────────────────────────────────
const driftReportAction: Action = {
  name: 'DRIFT_REPORT',
  similes: ['REPUTATION_DRIFT', 'SHOW_DRIFT', 'DRIFT_SUMMARY', 'TRUST_DRIFT', 'SCORE_TREND'],
  description:
    'Shows reputation drift analysis. Without a wallet address: leaderboard of most at-risk agents. With a wallet: full audit history and trend for that agent.',

  validate: async (_runtime: IAgentRuntime, message: Memory): Promise<boolean> => {
    return /drift|reputation.*trend|score.*trend|trust.*trend|at.?risk agents?/i.test(
      message.content.text ?? ''
    );
  },

  handler: async (
    runtime: IAgentRuntime,
    message: Memory,
    _state: State,
    _options: unknown,
    callback: HandlerCallback
  ): Promise<ActionResult> => {
    const svc = runtime.getService<SaidSentinelService>(SaidSentinelService.serviceType);
    if (!svc) {
      await callback({ text: 'Said Sentinel service not available.', actions: [] });
      return { success: false, text: 'Service unavailable' };
    }

    const text = message.content.text ?? '';
    const walletMatch = text.match(/\b([1-9A-HJ-NP-Za-km-z]{32,44})\b/);

    if (walletMatch) {
      // Detailed report for a specific wallet
      const wallet = walletMatch[1];
      const records = svc.driftHistory.get(wallet);
      if (!records || records.length === 0) {
        await callback({
          text: `No drift history found for \`${wallet}\`. It will be tracked after the next re-audit cycle.`,
          actions: [],
        });
        return { success: false, text: 'No history for wallet' };
      }

      const analysis = computeDriftAnalysis(wallet, records);
      const recentRecords = records.slice(-10).reverse();
      const severityIcon: Record<DriftSeverity, string> = { NONE: '✅', MILD: '🟡', MODERATE: '🟠', SEVERE: '🔴' };

      const lines = [
        `**Drift Report — \`${wallet.slice(0, 12)}...\`**`,
        `Severity: ${severityIcon[analysis.severity]} **${analysis.severity}**`,
        `Consecutive alerts: ${analysis.consecutiveAlerts}`,
        `Score: ${(analysis.baselineScore * 100).toFixed(0)}% → ${(analysis.latestScore * 100).toFixed(0)}% (${analysis.scoreDrop > 0 ? '-' : '+'}${(Math.abs(analysis.scoreDrop) * 100).toFixed(0)}%)`,
        `Trend: ${analysis.scoreTrend < 0 ? '📉' : '📈'} ${(analysis.scoreTrend * 100).toFixed(1)}%/audit`,
        ``,
        `**Last ${recentRecords.length} audits:**`,
        ...recentRecords.map((r) => {
          const v = r.verdict === 'PASS' ? '✅' : r.verdict === 'FAIL' ? '❌' : '⚠️';
          return `${v} ${r.verdict} ${(r.confidenceScore * 100).toFixed(0)}% — ${new Date(r.timestamp).toLocaleDateString()}`;
        }),
      ];

      await callback({ text: lines.join('\n'), actions: ['DRIFT_REPORT'] });
      return { success: true, text: `Drift severity: ${analysis.severity}`, values: { severity: analysis.severity }, data: { analysis } };
    }

    // Summary leaderboard — agents sorted by severity then score drop
    if (svc.driftHistory.size === 0) {
      await callback({
        text: 'No drift history yet — run a re-audit cycle first.',
        actions: [],
      });
      return { success: false, text: 'No history' };
    }

    const analyses = Array.from(svc.driftHistory.entries())
      .filter(([, records]) => records.length > 0)
      .map(([wallet, records]) => computeDriftAnalysis(wallet, records))
      .sort((a, b) =>
        severityRank(b.severity) - severityRank(a.severity) ||
        b.scoreDrop - a.scoreDrop
      );

    const atRisk = analyses.filter((a) => a.severity !== 'NONE');
    const severityIcon: Record<DriftSeverity, string> = { NONE: '✅', MILD: '🟡', MODERATE: '🟠', SEVERE: '🔴' };

    const lines = [
      `**Reputation Drift Leaderboard**`,
      `Tracking ${analyses.length} agents | ${atRisk.length} at risk`,
      ``,
      ...analyses.slice(0, 15).map((a, i) => {
        const icon = severityIcon[a.severity];
        const trend = a.scoreTrend < -0.01 ? '📉' : a.scoreTrend > 0.01 ? '📈' : '➡️';
        return `${i + 1}. ${icon} \`${a.wallet.slice(0, 10)}...\` ${trend} ${(a.latestScore * 100).toFixed(0)}% (${a.consecutiveAlerts} alerts)`;
      }),
    ];

    await callback({ text: lines.join('\n'), actions: ['DRIFT_REPORT'] });
    return {
      success: true,
      text: `${atRisk.length} agents at risk`,
      values: { atRisk: atRisk.length, total: analyses.length },
      data: { analyses: analyses.slice(0, 15) },
    };
  },

  examples: [
    [
      { name: '{{name1}}', content: { text: 'Show reputation drift summary' } },
      {
        name: 'Said Sentinel',
        content: {
          text: '**Reputation Drift Leaderboard**\nTracking 27 agents | 3 at risk...',
          actions: ['DRIFT_REPORT'],
        },
      },
    ],
  ],
};

// ─── Evaluator ────────────────────────────────────────────────────────────────
const auditOpportunityEvaluator: Evaluator = {
  name: 'AUDIT_OPPORTUNITY_EVALUATOR',
  description:
    'Scans every incoming message for auditable targets (tx signatures, Solana addresses, A2A envelopes) and flags them for PERFORM_SAID_AUDIT.',
  similes: ['DETECT_AUDIT_TARGET', 'SCAN_FOR_AUDIT'],
  alwaysRun: false,

  validate: async (_runtime: IAgentRuntime, message: Memory): Promise<boolean> => {
    const text = message.content.text ?? '';
    return (
      isTxSignature(text) ||
      isSolanaAddress(text) ||
      isJsonEnvelope(text) ||
      /audit|verify|check.*transaction|inspect.*agent/i.test(text)
    );
  },

  handler: async (_runtime: IAgentRuntime, message: Memory): Promise<void> => {
    const target = extractAuditTarget(message.content.text ?? '');
    logger.info({ messageId: message.id, target }, 'AUDIT_OPPORTUNITY_EVALUATOR: target detected');
  },

  examples: [],
};

// ─── Plugin Export ────────────────────────────────────────────────────────────
const saidPlugin: Plugin = {
  name: 'said-sentinel-plugin',
  description:
    'Said Protocol audit plugin — verifies on-chain identity PDAs, transactions, and A2A message envelopes. Autonomously watches for new agent registrations and broadcasts signed SAID_v1 audit reports.',
  priority: 100,
  config: {
    SOLANA_PRIVATE_KEY: process.env.SOLANA_PRIVATE_KEY,
    SOLANA_PUBLIC_KEY: process.env.SOLANA_PUBLIC_KEY,
    SOLANA_RPC_URL: process.env.SOLANA_RPC_URL,
    SAID_PROGRAM_ID: process.env.SAID_PROGRAM_ID,
    SAID_API_ROOT: process.env.SAID_API_ROOT,
  },
  async init(config: Record<string, string>) {
    logger.info('*** Initializing saidPlugin ***');
    try {
      const validated = await configSchema.parseAsync(config);
      for (const [k, v] of Object.entries(validated)) {
        if (v) process.env[k] = v;
      }
    } catch (err) {
      if (err instanceof z.ZodError) {
        throw new Error(`saidPlugin config error: ${err.issues.map((i) => i.message).join(', ')}`);
      }
      throw err;
    }
  },
  services: [SaidSentinelService],
  actions: [performSaidAuditAction, listAgentsAction, watcherStatusAction, reauditNowAction, driftReportAction],
  providers: [saidTrustProvider],
  evaluators: [auditOpportunityEvaluator],
  routes: [
    // ── JSON API ──────────────────────────────────────────────────────────────
    {
      type: 'GET' as const,
      path: '/api/sentinel/dashboard',
      public: true,
      handler: async (
        _req: { params?: Record<string, string> },
        res: {
          json: (data: unknown) => void;
          status: (code: number) => { json: (data: unknown) => void };
        },
        runtime: IAgentRuntime
      ): Promise<void> => {
        const svc = runtime.getService<SaidSentinelService>(
          SaidSentinelService.serviceType as Parameters<typeof runtime.getService>[0]
        );
        if (!svc) {
          res.status(503).json({ error: 'Service not ready' });
          return;
        }

        let registryTotal = 0;
        let registryVerified = 0;
        try {
          const stats = await svc.saidClient.getStats();
          registryTotal = stats.total;
          registryVerified = stats.verified;
        } catch { /* non-fatal — use zeros */ }

        const leaderboard = Array.from(svc.driftHistory.entries())
          .filter(([, records]) => records.length > 0)
          .map(([wallet, records]) => {
            const a = computeDriftAnalysis(wallet, records);
            return {
              wallet,
              severity: a.severity,
              scoreDrop: Math.round(a.scoreDrop * 100),
              latestVerdict: a.latestVerdict,
              recordCount: a.recordCount,
            };
          })
          .sort(
            (a, b) =>
              severityRank(b.severity) - severityRank(a.severity) || b.scoreDrop - a.scoreDrop
          )
          .slice(0, 20);

        const bySeverity = { NONE: 0, MILD: 0, MODERATE: 0, SEVERE: 0 };
        for (const e of leaderboard) bySeverity[e.severity]++;

        res.json({
          timestamp: new Date().toISOString(),
          registry: {
            total: registryTotal,
            verified: registryVerified,
            watcherTracking: svc.knownAgentWallets.size,
          },
          watcher: {
            running: svc.watcherTimer !== null,
            startedAt: svc.watcherStartedAt?.toISOString() ?? null,
            pollIntervalMs: WATCHER_POLL_MS,
          },
          reauditor: {
            running: svc.reauditorTimer !== null,
            cycleInProgress: svc.reauditorRunning,
            lastRun: svc.reauditorLastRun?.toISOString() ?? null,
            nextRun: svc.reauditorNextRun?.toISOString() ?? null,
            lastCycleStats: svc.reauditorLastCycleStats,
            coverage: {
              audited: svc.auditHistory.size,
              total: svc.knownAgentWallets.size,
            },
          },
          drift: { leaderboard, bySeverity },
          digest: { lastSent: svc.digestLastSent?.toISOString() ?? null },
        });
      },
    },

    // ── Dashboard HTML ────────────────────────────────────────────────────────
    {
      type: 'GET' as const,
      path: '/dashboard',
      public: true,
      handler: async (
        _req: unknown,
        res: {
          setHeader?: (name: string, value: string) => void;
          send: (body: unknown) => void;
        }
      ): Promise<void> => {
        res.setHeader?.('Content-Type', 'text/html; charset=utf-8');
        res.send(DASHBOARD_HTML);
      },
    },
  ],
};

export default saidPlugin;

// ─── Dashboard HTML ────────────────────────────────────────────────────────────
const DASHBOARD_HTML = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Said Sentinel</title>
  <script src="https://cdn.tailwindcss.com"></script>
  <style>body{font-family:monospace}</style>
</head>
<body class="bg-zinc-950 text-zinc-100 min-h-screen p-6">
  <div class="max-w-4xl mx-auto space-y-8">

    <div class="flex items-start justify-between">
      <div>
        <h1 class="text-xl font-bold tracking-tight text-white">🛡 Said Sentinel</h1>
        <p class="text-xs text-zinc-500 mt-1">Autonomous Trust Audit · Said Protocol</p>
      </div>
      <div class="text-right text-xs text-zinc-500">
        <div id="status-line">connecting…</div>
        <div id="next-refresh" class="text-zinc-600 mt-0.5"></div>
      </div>
    </div>

    <div>
      <p class="text-xs text-zinc-500 uppercase tracking-widest mb-3">Registry</p>
      <div class="grid grid-cols-3 gap-3">
        <div class="bg-zinc-900 rounded-xl p-4 border border-zinc-800">
          <div id="reg-total" class="text-3xl font-bold text-white">—</div>
          <div class="text-xs text-zinc-500 mt-1">Total Agents</div>
        </div>
        <div class="bg-zinc-900 rounded-xl p-4 border border-zinc-800">
          <div id="reg-verified" class="text-3xl font-bold text-emerald-400">—</div>
          <div class="text-xs text-zinc-500 mt-1">Verified</div>
        </div>
        <div class="bg-zinc-900 rounded-xl p-4 border border-zinc-800">
          <div id="reg-tracked" class="text-3xl font-bold text-sky-400">—</div>
          <div class="text-xs text-zinc-500 mt-1">Watcher Tracking</div>
        </div>
      </div>
    </div>

    <div>
      <p class="text-xs text-zinc-500 uppercase tracking-widest mb-3">Services</p>
      <div class="grid grid-cols-2 gap-3">
        <div class="bg-zinc-900 rounded-xl p-4 border border-zinc-800">
          <div class="flex items-center gap-2 mb-3">
            <span id="watcher-dot" class="w-2 h-2 rounded-full bg-zinc-600"></span>
            <span class="text-sm font-semibold">New Agent Watcher</span>
          </div>
          <div id="watcher-details" class="text-xs text-zinc-500 space-y-1"></div>
        </div>
        <div class="bg-zinc-900 rounded-xl p-4 border border-zinc-800">
          <div class="flex items-center gap-2 mb-3">
            <span id="reauditor-dot" class="w-2 h-2 rounded-full bg-zinc-600"></span>
            <span class="text-sm font-semibold">Continuous Re-Auditor</span>
          </div>
          <div id="reauditor-details" class="text-xs text-zinc-500 space-y-1"></div>
        </div>
      </div>
    </div>

    <div>
      <p class="text-xs text-zinc-500 uppercase tracking-widest mb-3">Reputation Drift Leaderboard</p>
      <div class="bg-zinc-900 rounded-xl border border-zinc-800 overflow-hidden">
        <table class="w-full text-sm">
          <thead class="border-b border-zinc-800">
            <tr>
              <th class="text-left px-4 py-3 text-xs text-zinc-500 font-normal">Agent</th>
              <th class="text-left px-4 py-3 text-xs text-zinc-500 font-normal">Severity</th>
              <th class="text-left px-4 py-3 text-xs text-zinc-500 font-normal">Score Drop</th>
              <th class="text-left px-4 py-3 text-xs text-zinc-500 font-normal">Audits</th>
              <th class="text-left px-4 py-3 text-xs text-zinc-500 font-normal">Latest</th>
            </tr>
          </thead>
          <tbody id="leaderboard-body">
            <tr><td colspan="5" class="px-4 py-8 text-center text-zinc-600 text-xs">Loading…</td></tr>
          </tbody>
        </table>
      </div>
    </div>

    <div class="text-xs text-zinc-600 text-center pb-4">
      Auto-refreshes every 30s ·
      <a href="https://t.me/SaidSentinelAlerts" class="text-zinc-400 hover:text-white transition-colors">@SaidSentinelAlerts</a>
    </div>

  </div>
<script>
const SC = {NONE:'text-emerald-400',MILD:'text-yellow-400',MODERATE:'text-orange-400',SEVERE:'text-red-400'};
const SI = {NONE:'✅',MILD:'🟡',MODERATE:'🟠',SEVERE:'🔴'};
const VC = {PASS:'text-emerald-400',WARNING:'text-yellow-400',FAIL:'text-red-400',ERROR:'text-zinc-400'};

function ago(iso){
  if(!iso)return'N/A';
  const s=(Date.now()-new Date(iso).getTime())/1000;
  if(s<60)return'just now';
  if(s<3600)return Math.floor(s/60)+'m ago';
  if(s<86400)return Math.floor(s/3600)+'h ago';
  return new Date(iso).toLocaleDateString();
}
function lines(arr){return arr.filter(Boolean).map(l=>'<div>'+l+'</div>').join('');}

async function refresh(){
  try{
    const d=await fetch('/api/sentinel/dashboard').then(r=>r.json());
    document.getElementById('status-line').textContent='updated '+ago(d.timestamp);
    document.getElementById('reg-total').textContent=d.registry.total;
    document.getElementById('reg-verified').textContent=d.registry.verified;
    document.getElementById('reg-tracked').textContent=d.registry.watcherTracking;

    document.getElementById('watcher-dot').className='w-2 h-2 rounded-full '+(d.watcher.running?'bg-emerald-500':'bg-red-500');
    document.getElementById('watcher-details').innerHTML=lines([
      d.watcher.running?'<span class="text-emerald-400">Running</span>':'<span class="text-red-400">Stopped</span>',
      'Started: '+ago(d.watcher.startedAt),
      'Poll every '+Math.round(d.watcher.pollIntervalMs/60000)+'min',
    ]);

    const cov=d.reauditor.coverage;
    const pct=cov.total>0?Math.round(cov.audited/cov.total*100):0;
    document.getElementById('reauditor-dot').className='w-2 h-2 rounded-full '+(d.reauditor.running?'bg-emerald-500':'bg-red-500');
    document.getElementById('reauditor-details').innerHTML=lines([
      d.reauditor.running
        ?'<span class="text-emerald-400">Scheduled</span>'+(d.reauditor.cycleInProgress?' <span class="text-yellow-400">(running)</span>':'')
        :'<span class="text-red-400">Stopped</span>',
      'Last run: '+ago(d.reauditor.lastRun),
      'Next run: '+ago(d.reauditor.nextRun),
      d.reauditor.lastCycleStats?'Last cycle: '+d.reauditor.lastCycleStats.audited+' audited, '+d.reauditor.lastCycleStats.alerts+' alerts':null,
      'Coverage: '+cov.audited+'/'+cov.total+' ('+pct+'%)',
    ]);

    const tbody=document.getElementById('leaderboard-body');
    const lb=d.drift.leaderboard;
    tbody.innerHTML=lb.length===0
      ?'<tr><td colspan="5" class="px-4 py-8 text-center text-zinc-600 text-xs">No drift data yet</td></tr>'
      :lb.map(r=>\`<tr class="border-t border-zinc-800/50 hover:bg-zinc-800/30">
        <td class="px-4 py-3 text-xs text-zinc-300">\${r.wallet.slice(0,8)}…\${r.wallet.slice(-4)}</td>
        <td class="px-4 py-3 text-xs \${SC[r.severity]||''}">\${SI[r.severity]||''} \${r.severity}</td>
        <td class="px-4 py-3 text-xs text-zinc-400">\${r.scoreDrop>0?'−'+r.scoreDrop+'pts':'0pts'}</td>
        <td class="px-4 py-3 text-xs text-zinc-500">\${r.recordCount}</td>
        <td class="px-4 py-3 text-xs \${VC[r.latestVerdict]||''}">\${r.latestVerdict}</td>
      </tr>\`).join('');
  }catch(e){
    document.getElementById('status-line').textContent='error: '+e.message;
  }
}
refresh();
let t=30;
setInterval(()=>{
  t--;
  if(t<=0){t=30;refresh();}
  document.getElementById('next-refresh').textContent='refresh in '+t+'s';
},1000);
</script>
</body>
</html>`;

