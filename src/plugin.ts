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
import { Connection, Keypair, PublicKey } from '@solana/web3.js';
import { SAID } from 'said-sdk';
import nacl from 'tweetnacl';
import { z } from 'zod';

// ─── Constants ────────────────────────────────────────────────────────────────
const SAID_PROGRAM_ID =
  process.env.SAID_PROGRAM_ID ?? '5dpw6KEQPn248pnkkaYyWfHwu2nfb3LUMbTucb6LaA8G';
const SAID_API_ROOT = process.env.SAID_API_ROOT ?? 'https://api.saidprotocol.com';
const RPC_URL = process.env.SOLANA_RPC_URL ?? 'https://api.mainnet-beta.solana.com';

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

// ─── Helpers ──────────────────────────────────────────────────────────────────
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
  saidClient: SAID
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
    'Manages the Solana RPC connection and Sentinel keypair for Said Protocol audits.';
  connection!: Connection;
  keypair!: Keypair;
  saidClient!: SAID;

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
    return svc;
  }

  static async stop(_runtime: IAgentRuntime): Promise<void> {
    logger.info('*** Stopping SaidSentinelService ***');
  }

  async stop(): Promise<void> {}
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

    return {
      text: [
        'Said Sentinel Identity:',
        `- Public Key: ${svc.keypair.publicKey.toString()}`,
        `- SOL Balance: ${balance.toFixed(4)} SOL`,
        `- Trust Tier: ${tier}`,
      ].join('\n'),
      values: { balance, tier, pubkey: svc.keypair.publicKey.toString() },
      data: {},
    };
  },
};

// ─── Action ───────────────────────────────────────────────────────────────────
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
      ({ findings, confidenceScore } = await auditIdentityPDA(target, svc.saidClient));
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

    const findingSummary =
      findings.length > 0
        ? `\nFindings:\n${findings.map((f) => `• [${f.severity}] ${f.issue}`).join('\n')}`
        : '\nNo issues found.';

    const responseText = [
      `**Said Sentinel Audit Report**`,
      `Type: ${auditType} | Verdict: **${verdict}** | Confidence: ${(confidenceScore * 100).toFixed(0)}%`,
      findingSummary,
      `\n\`\`\`json\n${JSON.stringify(auditResult, null, 2)}\n\`\`\``,
    ].join('\n');

    await callback({ text: responseText, actions: ['PERFORM_SAID_AUDIT'] });

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
    'Said Protocol audit plugin — verifies on-chain identity PDAs, transactions, and A2A message envelopes. Produces cryptographically signed SAID_v1 audit reports.',
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
  actions: [performSaidAuditAction],
  providers: [saidTrustProvider],
  evaluators: [auditOpportunityEvaluator],
};

export default saidPlugin;
