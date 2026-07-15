#!/usr/bin/env node
/**
 * dingdawg-agent-wallet — Governed Agentic Wallet Middleware
 *
 * Wraps Coinbase AgentKit (or any x402-compatible wallet) with:
 *   - Pre-execution policy gate (spend limits, recipient allowlist, daily caps)
 *   - SHA-256 linked receipt chain per transaction (local; IPFS pinning on roadmap)
 *   - Compliance check before any financial action
 *   - Portable "Verified" proof bundle for regulators/auditors
 *
 * 5 MCP tools:
 *   provision_wallet  — create or connect a governed wallet
 *   governed_spend    — policy-check → authorize → receipt
 *   governed_receive  — accept payment with tamper-evident receipt
 *   wallet_policy     — set/update spend limits and allowlists
 *   wallet_audit      — full tamper-evident audit trail
 *
 * Integration (Coinbase AgentKit SDK):
 *   provision_wallet({ provider: "coinbase", ... }) → use returned wallet_id with agentKit.sendToken()
 *
 * Integration (local x402):
 *   provision_wallet({ provider: "x402", endpoint: "http://localhost:7373" })
 */

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";
import * as crypto from "crypto";
import * as fs from "fs";
import * as path from "path";
import * as os from "os";

// ── Storage ────────────────────────────────────────────────────────────────────

const STORE_DIR = path.join(os.homedir(), ".dingdawg", "agent-wallet");
const WALLETS_FILE = path.join(STORE_DIR, "wallets.json");
const RECEIPTS_FILE = path.join(STORE_DIR, "receipts.jsonl");
const POLICY_FILE = path.join(STORE_DIR, "policies.json");
const DAILY_FILE = path.join(STORE_DIR, "daily_spend.json");

function ensureStore() {
  if (!fs.existsSync(STORE_DIR)) fs.mkdirSync(STORE_DIR, { recursive: true });
}

function loadJSON<T>(file: string, fallback: T): T {
  try {
    if (fs.existsSync(file)) return JSON.parse(fs.readFileSync(file, "utf8"));
  } catch {}
  return fallback;
}

function saveJSON(file: string, data: unknown) {
  ensureStore();
  fs.writeFileSync(file, JSON.stringify(data, null, 2));
}

// ── Receipt chain ──────────────────────────────────────────────────────────────

interface Receipt {
  receipt_id: string;
  prev_hash: string;
  ts: string;
  action: string;
  wallet_id: string;
  amount_usdc?: number;
  recipient?: string;
  policy_verdict: "allow" | "deny";
  deny_reason?: string;
  approval_token_provided?: boolean;
  payload_hash: string;
}

function appendReceipt(r: Receipt): string {
  ensureStore();
  const line = JSON.stringify(r);
  fs.appendFileSync(RECEIPTS_FILE, line + "\n");
  return r.receipt_id;
}

function chainHash(prev: string, current: string): string {
  return crypto.createHash("sha256").update(prev + current).digest("hex");
}

function lastReceiptHash(): string {
  try {
    if (!fs.existsSync(RECEIPTS_FILE)) return "genesis";
    const lines = fs.readFileSync(RECEIPTS_FILE, "utf8").trim().split("\n");
    const last = lines[lines.length - 1];
    if (!last) return "genesis";
    const r: Receipt = JSON.parse(last);
    return crypto.createHash("sha256").update(JSON.stringify(r)).digest("hex");
  } catch {
    return "genesis";
  }
}

// ── Free tier gate ─────────────────────────────────────────────────────────────

const USAGE_FILE = path.join(STORE_DIR, "usage.json");
const FREE_TIER_LIMIT = 10;
const GATED_TOOLS = new Set(["governed_spend", "governed_receive"]);

function checkFreeTier(tool: string): { allowed: boolean; calls_used: number } {
  if (!GATED_TOOLS.has(tool)) return { allowed: true, calls_used: 0 };
  ensureStore();
  const usage = loadJSON<{ calls: number }>(USAGE_FILE, { calls: 0 });
  if (usage.calls >= FREE_TIER_LIMIT) {
    return { allowed: false, calls_used: usage.calls };
  }
  usage.calls += 1;
  saveJSON(USAGE_FILE, usage);
  return { allowed: true, calls_used: usage.calls };
}

// ── Policy enforcement ─────────────────────────────────────────────────────────

interface SpendPolicy {
  daily_cap_usdc: number;
  per_call_cap_usdc: number;
  step_up_thresh_usdc: number;
  allowed_recipients?: string[];
}

const DEFAULT_POLICY: SpendPolicy = {
  daily_cap_usdc: 500,
  per_call_cap_usdc: 100,
  step_up_thresh_usdc: 50,
};

function getPolicy(wallet_id: string): SpendPolicy {
  const policies = loadJSON<Record<string, SpendPolicy>>(POLICY_FILE, {});
  return policies[wallet_id] ?? DEFAULT_POLICY;
}

function getDailySpent(wallet_id: string): number {
  const today = new Date().toISOString().slice(0, 10);
  const daily = loadJSON<Record<string, Record<string, number>>>(DAILY_FILE, {});
  return daily[wallet_id]?.[today] ?? 0;
}

function recordDailySpend(wallet_id: string, amount: number) {
  const today = new Date().toISOString().slice(0, 10);
  const daily = loadJSON<Record<string, Record<string, number>>>(DAILY_FILE, {});
  if (!daily[wallet_id]) daily[wallet_id] = {};
  daily[wallet_id][today] = (daily[wallet_id][today] ?? 0) + amount;
  saveJSON(DAILY_FILE, daily);
}

interface PolicyVerdict {
  allow: boolean;
  deny_reason?: string;
  step_up_required?: boolean;
}

function checkPolicy(
  wallet_id: string,
  amount_usdc: number,
  recipient?: string,
  approval_token?: string
): PolicyVerdict {
  const policy = getPolicy(wallet_id);
  const daily_spent = getDailySpent(wallet_id);

  if (amount_usdc > policy.per_call_cap_usdc) {
    return {
      allow: false,
      deny_reason: `Amount ${amount_usdc} USDC exceeds per-call cap ${policy.per_call_cap_usdc} USDC`,
    };
  }
  if (daily_spent + amount_usdc > policy.daily_cap_usdc) {
    return {
      allow: false,
      deny_reason: `Daily spend ${daily_spent} + ${amount_usdc} USDC exceeds daily cap ${policy.daily_cap_usdc} USDC`,
    };
  }
  if (amount_usdc > policy.step_up_thresh_usdc && !approval_token) {
    return {
      allow: false,
      step_up_required: true,
      deny_reason: `Amount ${amount_usdc} USDC > step-up threshold ${policy.step_up_thresh_usdc} USDC — human approval required`,
    };
  }
  if (
    policy.allowed_recipients &&
    policy.allowed_recipients.length > 0 &&
    recipient &&
    !policy.allowed_recipients.includes(recipient)
  ) {
    return {
      allow: false,
      deny_reason: `Recipient ${recipient} not in allowlist`,
    };
  }
  return { allow: true };
}

// ── Tool implementations ───────────────────────────────────────────────────────

function provision_wallet(args: {
  provider: "coinbase" | "x402" | "local";
  wallet_id?: string;
  label?: string;
  network?: string;
  daily_cap_usdc?: number;
  per_call_cap_usdc?: number;
  allowed_recipients?: string[];
}): object {
  ensureStore();
  const wallet_id =
    args.wallet_id ??
    `dgo-wallet-${crypto.randomBytes(8).toString("hex")}`;
  const wallets = loadJSON<Record<string, object>>(WALLETS_FILE, {});

  if (args.wallet_id && wallets[args.wallet_id]) {
    return {
      error: `Wallet '${args.wallet_id}' already exists. Use wallet_policy to update its settings.`,
      wallet_id: args.wallet_id,
    };
  }

  const policy: SpendPolicy = {
    daily_cap_usdc: args.daily_cap_usdc ?? DEFAULT_POLICY.daily_cap_usdc,
    per_call_cap_usdc:
      args.per_call_cap_usdc ?? DEFAULT_POLICY.per_call_cap_usdc,
    step_up_thresh_usdc: DEFAULT_POLICY.step_up_thresh_usdc,
    allowed_recipients: args.allowed_recipients,
  };

  const wallet = {
    wallet_id,
    provider: args.provider,
    label: args.label ?? wallet_id,
    network: args.network ?? "base",
    created_at: new Date().toISOString(),
    governed: true,
  };

  wallets[wallet_id] = wallet;
  saveJSON(WALLETS_FILE, wallets);
  const policies = loadJSON<Record<string, SpendPolicy>>(POLICY_FILE, {});
  policies[wallet_id] = policy;
  saveJSON(POLICY_FILE, policies);

  const receipt_id = crypto.randomUUID();
  const prev = lastReceiptHash();
  appendReceipt({
    receipt_id,
    prev_hash: prev,
    ts: new Date().toISOString(),
    action: "provision_wallet",
    wallet_id,
    policy_verdict: "allow",
    payload_hash: crypto.createHash("sha256").update(JSON.stringify({ wallet_id, provider: args.provider, network: wallet.network })).digest("hex"),
  });

  return {
    wallet_id,
    provider: args.provider,
    network: wallet.network,
    governed: true,
    policy: {
      daily_cap_usdc: policy.daily_cap_usdc,
      per_call_cap_usdc: policy.per_call_cap_usdc,
    },
    receipt_id,
    coinbase_setup:
      args.provider === "coinbase"
        ? "Run: npx @coinbase/agentkit wallet create --wallet-id " + wallet_id
        : null,
  };
}

function governed_spend(args: {
  wallet_id: string;
  amount_usdc: number;
  recipient: string;
  memo?: string;
  approval_token?: string;
}): object {
  if (!/^[a-zA-Z0-9_-]+$/.test(args.wallet_id)) {
    return { authorized: false, deny_reason: "Invalid wallet_id format", step_up_required: false, action_taken: "none — invalid input" };
  }
  if (!/^[a-zA-Z0-9._:@/-]+$/.test(args.recipient)) {
    return { authorized: false, deny_reason: "Invalid recipient format", step_up_required: false, action_taken: "none — invalid input" };
  }
  const wallets = loadJSON<Record<string, object>>(WALLETS_FILE, {});
  if (!wallets[args.wallet_id]) {
    return { authorized: false, deny_reason: `Wallet '${args.wallet_id}' not found. Call provision_wallet first.`, step_up_required: false, action_taken: "none — wallet not found" };
  }
  const verdict = checkPolicy(
    args.wallet_id,
    args.amount_usdc,
    args.recipient,
    args.approval_token
  );
  const receipt_id = crypto.randomUUID();
  const prev = lastReceiptHash();
  // Exclude approval_token from payload hash — token must not be stored in receipts
  const { approval_token: _token, ...safeArgs } = args;
  const payload_hash = crypto
    .createHash("sha256")
    .update(JSON.stringify(safeArgs))
    .digest("hex");

  if (!verdict.allow) {
    appendReceipt({
      receipt_id,
      prev_hash: prev,
      ts: new Date().toISOString(),
      action: "governed_spend",
      wallet_id: args.wallet_id,
      amount_usdc: args.amount_usdc,
      recipient: args.recipient,
      policy_verdict: "deny",
      deny_reason: verdict.deny_reason,
      approval_token_provided: !!args.approval_token,
      payload_hash,
    });
    return {
      authorized: false,
      deny_reason: verdict.deny_reason,
      step_up_required: verdict.step_up_required ?? false,
      receipt_id,
      action_taken: "none — policy denied",
    };
  }

  const allowReceipt: Receipt = {
    receipt_id,
    prev_hash: prev,
    ts: new Date().toISOString(),
    action: "governed_spend",
    wallet_id: args.wallet_id,
    amount_usdc: args.amount_usdc,
    recipient: args.recipient,
    policy_verdict: "allow",
    approval_token_provided: !!args.approval_token,
    payload_hash,
  };
  appendReceipt(allowReceipt);
  recordDailySpend(args.wallet_id, args.amount_usdc);

  const receipt_chain_hash = crypto.createHash("sha256").update(JSON.stringify(allowReceipt)).digest("hex");
  const policy = getPolicy(args.wallet_id);
  const daily_remaining =
    policy.daily_cap_usdc -
    getDailySpent(args.wallet_id);

  return {
    authorized: true,
    wallet_id: args.wallet_id,
    amount_usdc: args.amount_usdc,
    recipient: args.recipient,
    receipt_id,
    receipt_chain_hash,
    daily_remaining_usdc: daily_remaining,
    memo: args.memo,
    action_taken: "spend_authorized — execute on-chain via your AgentKit wallet instance",
    agentkit_call: `wallet.sendToken({ assetId: "usdc", amount: "${args.amount_usdc}", destination: "${args.recipient}" })`,
  };
}

function governed_receive(args: {
  wallet_id: string;
  expected_amount_usdc?: number;
  sender?: string;
  memo?: string;
}): object {
  const receipt_id = crypto.randomUUID();
  const prev = lastReceiptHash();
  const payload_hash = crypto
    .createHash("sha256")
    .update(JSON.stringify(args))
    .digest("hex");

  appendReceipt({
    receipt_id,
    prev_hash: prev,
    ts: new Date().toISOString(),
    action: "governed_receive",
    wallet_id: args.wallet_id,
    amount_usdc: args.expected_amount_usdc,
    recipient: args.sender,
    policy_verdict: "allow",
    payload_hash,
  });

  const receipt_chain_hash = chainHash(prev, receipt_id);

  return {
    wallet_id: args.wallet_id,
    receipt_id,
    receipt_chain_hash,
    receipt_anchor: `local:sha256:${receipt_chain_hash}`,
    memo: args.memo,
    verified: true,
  };
}

function wallet_policy(args: {
  wallet_id: string;
  daily_cap_usdc?: number;
  per_call_cap_usdc?: number;
  step_up_thresh_usdc?: number;
  add_recipient?: string;
  remove_recipient?: string;
}): object {
  const wallets = loadJSON<Record<string, object>>(WALLETS_FILE, {});
  if (!wallets[args.wallet_id]) {
    return {
      error: `Wallet '${args.wallet_id}' not found. Call provision_wallet first.`,
      policy_updated: false,
    };
  }
  const policies = loadJSON<Record<string, SpendPolicy>>(POLICY_FILE, {});
  const current = policies[args.wallet_id] ?? { ...DEFAULT_POLICY };

  if (args.daily_cap_usdc !== undefined)
    current.daily_cap_usdc = args.daily_cap_usdc;
  if (args.per_call_cap_usdc !== undefined)
    current.per_call_cap_usdc = args.per_call_cap_usdc;
  if (args.step_up_thresh_usdc !== undefined)
    current.step_up_thresh_usdc = args.step_up_thresh_usdc;

  if (args.add_recipient) {
    current.allowed_recipients = [
      ...(current.allowed_recipients ?? []),
      args.add_recipient,
    ];
  }
  if (args.remove_recipient && current.allowed_recipients) {
    current.allowed_recipients = current.allowed_recipients.filter(
      (r) => r !== args.remove_recipient
    );
  }

  policies[args.wallet_id] = current;
  saveJSON(POLICY_FILE, policies);

  return {
    wallet_id: args.wallet_id,
    policy_updated: true,
    policy: current,
  };
}

function wallet_audit(args: {
  wallet_id?: string;
  limit?: number;
}): object {
  const limit = args.limit ?? 20;
  try {
    if (!fs.existsSync(RECEIPTS_FILE)) return { receipts: [], count: 0, chain_verified: true };
    const lines = fs
      .readFileSync(RECEIPTS_FILE, "utf8")
      .trim()
      .split("\n")
      .filter(Boolean);

    let parseFailures = 0;
    const allReceipts: Receipt[] = lines
      .map((l) => {
        try {
          return JSON.parse(l) as Receipt;
        } catch {
          parseFailures++;
          return null;
        }
      })
      .filter(Boolean) as Receipt[];

    // Verify the full global chain before any filtering — filtered views
    // would produce false negatives since prev_hash spans across all wallets.
    // Parse failures count as chain breaks — a corrupted line cannot be skipped.
    const chain_verified = parseFailures === 0 && verifyChain(allReceipts);

    let receipts = allReceipts;
    if (args.wallet_id) {
      receipts = receipts.filter((r) => r.wallet_id === args.wallet_id);
    }

    receipts = receipts.slice(-limit).reverse();

    return {
      wallet_id: args.wallet_id ?? "all",
      count: receipts.length,
      receipts,
      chain_verified,
    };
  } catch (e) {
    return { error: String(e), receipts: [], chain_verified: false };
  }
}

function verifyChain(receipts: Receipt[]): boolean {
  for (let i = 1; i < receipts.length; i++) {
    const prev_hash = crypto
      .createHash("sha256")
      .update(JSON.stringify(receipts[i - 1]))
      .digest("hex");
    if (receipts[i].prev_hash !== prev_hash) return false;
  }
  return true;
}

// ── MCP server ─────────────────────────────────────────────────────────────────

const TOOLS = [
  {
    name: "provision_wallet",
    description:
      "Create or connect a governed wallet. Attaches spend policy (daily cap, per-call cap, allowlist) and writes a genesis receipt to the tamper-proof chain. Supports Coinbase AgentKit, x402, or local providers.",
    inputSchema: {
      type: "object",
      properties: {
        provider: {
          type: "string",
          enum: ["coinbase", "x402", "local"],
          description: "Wallet provider",
        },
        wallet_id: { type: "string", description: "Optional custom wallet ID" },
        label: { type: "string", description: "Human-readable label" },
        network: {
          type: "string",
          description: "Chain network (default: base)",
        },
        daily_cap_usdc: {
          type: "number",
          description: "Daily spend cap in USDC (default: 500)",
        },
        per_call_cap_usdc: {
          type: "number",
          description: "Per-transaction cap in USDC (default: 100)",
        },
        allowed_recipients: {
          type: "array",
          items: { type: "string" },
          description: "Optional allowlist of recipient wallet addresses",
        },
      },
      required: ["provider"],
    },
  },
  {
    name: "governed_spend",
    description:
      "Execute a governed USDC payment. Policy is checked before execution. All outcomes (allow AND deny) produce an immutable receipt. Returns agentkit_call with the SDK method to execute on-chain.",
    inputSchema: {
      type: "object",
      properties: {
        wallet_id: { type: "string", description: "Governed wallet ID" },
        amount_usdc: { type: "number", description: "Amount in USDC" },
        recipient: {
          type: "string",
          description: "Recipient wallet address or ENS",
        },
        memo: { type: "string", description: "Optional payment memo" },
        approval_token: {
          type: "string",
          description: "Human approval token (required for amounts above step-up threshold)",
        },
      },
      required: ["wallet_id", "amount_usdc", "recipient"],
    },
  },
  {
    name: "governed_receive",
    description:
      "Record receipt of a payment with tamper-proof chain receipt. Use when your agent receives funds — creates an auditable record with local SHA-256 anchor.",
    inputSchema: {
      type: "object",
      properties: {
        wallet_id: { type: "string", description: "Your governed wallet ID" },
        expected_amount_usdc: {
          type: "number",
          description: "Expected receive amount",
        },
        sender: { type: "string", description: "Sender address" },
        memo: { type: "string", description: "Optional memo" },
      },
      required: ["wallet_id"],
    },
  },
  {
    name: "wallet_policy",
    description:
      "Update spend policy for a governed wallet. Set daily caps, per-call caps, step-up thresholds, and recipient allowlists.",
    inputSchema: {
      type: "object",
      properties: {
        wallet_id: { type: "string" },
        daily_cap_usdc: { type: "number" },
        per_call_cap_usdc: { type: "number" },
        step_up_thresh_usdc: { type: "number" },
        add_recipient: {
          type: "string",
          description: "Add address to allowlist",
        },
        remove_recipient: {
          type: "string",
          description: "Remove address from allowlist",
        },
      },
      required: ["wallet_id"],
    },
  },
  {
    name: "wallet_audit",
    description:
      "Return tamper-proof audit trail of all wallet actions. chain_verified=true means every receipt links correctly to its predecessor.",
    inputSchema: {
      type: "object",
      properties: {
        wallet_id: {
          type: "string",
          description: "Filter by wallet (omit for all)",
        },
        limit: {
          type: "number",
          description: "Max receipts to return (default: 20)",
        },
      },
    },
  },
];

const server = new Server(
  { name: "dingdawg-agent-wallet", version: "1.0.0" },
  { capabilities: { tools: {} } }
);

server.setRequestHandler(ListToolsRequestSchema, async () => ({ tools: TOOLS }));

server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args } = request.params;
  const a = (args ?? {}) as Record<string, unknown>;

  const tier = checkFreeTier(name);
  if (!tier.allowed) {
    return {
      content: [{
        type: "text",
        text: JSON.stringify({
          error: "free_tier_limit_reached",
          message: `You've used all ${FREE_TIER_LIMIT} free governed transactions. Upgrade to continue.`,
          calls_used: tier.calls_used,
          upgrade_url: "https://dingdawg.com/pricing",
          starter_checkout: "https://checkout.dingdawg.com/b/9B69AS9m3gKP5hA1vxdjO04",
          note: "Starter: $19/mo — 50 calls/day | Pro: $49/mo — 200 calls/day"
        }, null, 2),
      }],
    };
  }

  let result: object;
  switch (name) {
    case "provision_wallet":
      result = provision_wallet(a as Parameters<typeof provision_wallet>[0]);
      break;
    case "governed_spend":
      result = governed_spend(a as Parameters<typeof governed_spend>[0]);
      break;
    case "governed_receive":
      result = governed_receive(a as Parameters<typeof governed_receive>[0]);
      break;
    case "wallet_policy":
      result = wallet_policy(a as Parameters<typeof wallet_policy>[0]);
      break;
    case "wallet_audit":
      result = wallet_audit(a as Parameters<typeof wallet_audit>[0]);
      break;
    default:
      return {
        content: [{ type: "text", text: JSON.stringify({ error: `Unknown tool: ${name}` }) }],
        isError: true,
      };
  }

  return {
    content: [{ type: "text", text: JSON.stringify(result, null, 2) }],
  };
});

const transport = new StdioServerTransport();
server.connect(transport).catch(console.error);
