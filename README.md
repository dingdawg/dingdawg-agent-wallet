# dingdawg-agent-wallet

**Governed Agentic Wallet Middleware** — the compliance + policy + audit layer that makes AI agents safe to give money to.

Coinbase AgentKit gives your agent a wallet. DingDawg gives it a conscience.

**[Live demo →](https://github.com/dingdawg/agent-wallet-demo)** — clone and run in 30 seconds, no API keys required.

---

## The Problem

AI agents can now hold USDC, send payments, and execute financial actions autonomously. The infrastructure exists. What doesn't exist: **who enforces what the agent is allowed to spend, on what, for whom — and proves it happened correctly.**

Without a governance layer, an agent wallet is a liability. With one, it's a product.

---

## What This Does

5 MCP tools that wrap any agent wallet (Coinbase AgentKit, x402, local) with:

| Tool | What it does |
|------|-------------|
| `provision_wallet` | Create a governed wallet with spend policy attached |
| `governed_spend` | Policy check → execute → immutable receipt (deny AND allow both logged) |
| `governed_receive` | Accept payment with tamper-evident receipt (SHA-256 linked chain) |
| `wallet_policy` | Update daily caps, per-call caps, step-up thresholds, recipient allowlists |
| `wallet_audit` | Full tamper-evident receipt chain — `chain_verified: true` means any modification is detectable |

---

## 5-Line Integration

```typescript
// Your agent already has an AgentKit wallet. Add governance in 5 lines:
import { DingDawgWallet } from 'dingdawg-agent-wallet';

// 1. Provision (once per agent)
await wallet.call('provision_wallet', { provider: 'coinbase', daily_cap_usdc: 5000 });

// 2. Every spend goes through the gate
const auth = await wallet.call('governed_spend', {
  wallet_id: 'my-agent-wallet',
  amount_usdc: 250,
  recipient: '0xVendor',
  memo: 'Invoice #INV-2026-001'
});

// If authorized: auth.agentkit_call gives you the exact AgentKit SDK call to run.
// If denied: auth.deny_reason explains why. Step-up: auth.step_up_required = true.
```

---

## Who This Is For

**SMB Finance Agents** — autonomously pays vendors, chases invoices, reconciles books. Daily cap + vendor allowlist means your agent can't overspend or pay someone new without approval.

**Municipal Fee Collectors** — city permit payments, utility fees, public records compliance. Every transaction is a public receipt. Auditors get `chain_verified: true` in the audit trail.

**Creator Economy Agents** — earns from brand deals, splits royalties to team members, routes tax escrow. Percentage-based splits with immutable proof per payment.

---

## Proof Bundle

Run the scenario forge to generate a verifiable proof bundle for any of the three scenarios:

```bash
npx ts-node tests/scenario_forge.ts
```

Output: signed receipt chain + `chain_verified: true` for every scenario. This is the demo — not slides.

---

## Pricing Anchor

Anchor against the customer's **risk budget**, not competitor SaaS:

- SMB: one ACH dispute costs $500-2,000 in bank fees + accountant time. $299/mo is nothing.
- Municipality: one audit finding costs $50,000 minimum. $999/mo is insurance.
- Creator: one failed royalty split = team member dispute. 0.5% of managed volume.

---

## Roadmap

- [ ] Coinbase AgentKit native bridge (`npx @coinbase/agentkit` wrapper)
- [ ] IPFS receipt pinning (currently local chain)
- [ ] Multi-sig threshold for large transactions
- [ ] Regulatory alignment check per transaction (integrates `dingdawg-compliance` — designed consistent with CO SB 205 and EU AI Act)

---

Part of the DingDawg governed payments ecosystem. Designed to complement [`dingdawg-payments`](https://npmjs.com/package/dingdawg-payments) (x402 payment governance) and [`dingdawg-governance`](https://npmjs.com/package/dingdawg-governance) (IPFS audit trail). Standalone — no additional dependencies required.
