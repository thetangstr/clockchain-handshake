# Live AWS bilateral handoff

This is an Ethereum Sepolia and Clockchain® single-validator testnet exercise.
No money moves. Do not install or use AgentDash. Do not invent success states.
It is not mainnet, court-grade, consensus-secure, trustless, production-ready,
or multi-validator. Every protocol and verdict artifact preserves paymentMoved: false.

Use this page as the short handoff beside the
[full operator runbook](./bilateral-demo-day.md),
[quick start](./bilateral-demo-quick-start.md),
[Payer prompt](../../prompts/run-payer-bilateral-demo.md),
[Requestor prompt](../../prompts/run-requestor-bilateral-demo.md),
[managed relay note](./payer-mcp-external-relay.md), and
[public run page](https://clockchain-research.vercel.app/handshake/run).

## Public facts to confirm

- reviewed immutable 40-character repository SHA;
- Payer signed public discovery URL;
- Requestor signed public discovery URL;
- authenticated AWS operator console URL;
- public Clockchain monitor URL; and
- enough reusable Sepolia treasury balance for four exact `0.01 Sepolia ETH`
  gas allocations.

No token, invitation, capability, launch manifest, private key, TLS key, RPC
URL, private path, or live evidence value belongs in this handoff.

## Live sequence

1. **Start run** in the AWS operator console.
2. Give the Payer stakeholder only the Payer prompt, reviewed SHA, and Payer
   signed discovery URL.
3. Compare the Payer claim fingerprint and select **Approve Payer**.
4. Wait for `PAYER_MCP_READY`.
5. Give the Requestor stakeholder only the Requestor prompt, reviewed SHA, and
   Requestor signed discovery URL.
6. Wait for the Requestor agent to report `HANDSHAKE_REQUIRED`.
7. Compare the Requestor claim fingerprint and select **Approve Requestor**.
8. When the four-address record is ready, select **Fund** once.
9. Watch `PROPOSED` → `ACCEPTED` → `ACKNOWLEDGED`.
10. Select **Verify** once.
11. Require fresh `VERIFIED`, exactly three independently verifiable Clockchain
    anchors in order, three public explorer links, and `paymentMoved:false`.

The exact authority sequence is `PROPOSED` → `ACCEPTED` → `ACKNOWLEDGED` →
fresh verifier. Only the fresh aggregate verifier owns the final verdict.

**Abort** is the only exceptional action. Use it immediately on any mismatch,
ambiguity, stale state, unexpected exit, missing anchor, duplicate anchor,
reordered anchor, expired artifact, malformed artifact, or secret exposure.

The five normal actions are **Start run**, **Approve Payer**, **Approve
Requestor**, **Fund**, and **Verify**. The console provides business progress
but cannot issue the final authorization literal. Only the fresh aggregate
verifier owns the final verdict.

## What stakeholders should say at the end

Payer may say: “My role reached `ACKNOWLEDGED`; I am waiting for independent
verification.”

Requestor may say: “My role reached `ACCEPTED`; I am waiting for Payer
acknowledgment and independent verification.”

Neither stakeholder may claim authorization. Relay, MCP, console, coordinator,
watcher, and role-local output are not the authority.

## Why this does not use A2A

A2A is intentionally absent. Payer MCP is the payment-intake/guidance surface.
Signed relay events and Clockchain receipts are the authority surfaces. Adding
a second advisory messaging protocol would not replace either authority
boundary.
