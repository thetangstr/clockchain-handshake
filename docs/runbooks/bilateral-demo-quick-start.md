# AWS bilateral demo quick start

This is an Ethereum Sepolia and Clockchain® single-validator testnet exercise.
No money moves. Do not install or use AgentDash. Do not invent success states.
It is not mainnet, court-grade, consensus-secure, trustless, production-ready,
or multi-validator. Every protocol and verdict artifact preserves paymentMoved: false.

The hosted demo has three people: a Payer stakeholder, a Requestor stakeholder,
and an operator using the authenticated AWS operator console. No stakeholder
receives a private attachment.

## Before the call

- Both stakeholders use locally installed ChatGPT Codex, Claude Code, or Hermes
  on macOS, Windows, or Linux. Web-only agents are unsupported.
- Everyone uses the public repository and the same reviewed immutable
  40-character SHA.
- Give Payer only the [Payer prompt](../../prompts/run-payer-bilateral-demo.md)
  and its signed public discovery URL.
- Give Requestor only the
  [Requestor prompt](../../prompts/run-requestor-bilateral-demo.md) and its
  signed public discovery URL after Payer is ready.
- Keep the [public run page](https://clockchain-research.vercel.app/handshake/run)
  open for Clockchain progress.

See the [repository overview](../../README.md), [full runbook](../../docs/runbooks/bilateral-demo-day.md),
[live handoff](./bilateral-demo-live-handoff.md), and
[managed Payer MCP relay](./payer-mcp-external-relay.md) for supporting detail.

## Run in this order

1. Operator selects **Start run** in the AWS operator console.
2. Payer pastes the Payer prompt into a fresh local agent and starts its one
   long-lived command.
3. Operator compares the displayed Payer claim fingerprint and selects
   **Approve Payer**.
4. Wait for `PAYER_MCP_READY`.
5. Requestor pastes the Requestor prompt into a fresh local agent and starts its
   one long-lived command.
6. Requestor's agent calls Payer MCP and receives `HANDSHAKE_REQUIRED`.
7. Operator compares the displayed Requestor claim fingerprint and selects
   **Approve Requestor**.
8. When the console shows the signed four-address funding record, operator
   selects **Fund** once. This sends exactly `0.01 Sepolia ETH` to each fresh
   participant address for testnet gas; it does not move the represented
   payment.
9. Watch `PROPOSED` → `ACCEPTED` → `ACKNOWLEDGED`.
10. Operator selects **Verify** once. A fresh aggregate verifier independently
    validates exactly three independently verifiable Clockchain anchors.
11. Stop only at a fresh `VERIFIED` publication with three public explorer
    links. **Abort** is available at every pre-verification stop point.

The five normal actions are **Start run**, **Approve Payer**, **Approve
Requestor**, **Fund**, and **Verify**. **Abort** is the only exceptional action.
The console exposes only actions valid for the current revision and rejects
duplicates, stale actions, and reordering.

## What each status means

- `PAYER_MCP_READY`: Payer's mandate and payment-intake guidance are available.
- `HANDSHAKE_REQUIRED`: Requestor learned the Payer's required process.
- `PROPOSED`: Payer anchored the authorization proposal.
- `ACCEPTED`: Requestor anchored acceptance of the exact proposal.
- `ACKNOWLEDGED`: Payer anchored final acknowledgment.
- `VERIFIED`: a fresh independent verifier validated all three anchors.

Role-local success is not operator authorization. Only the fresh aggregate
verifier may issue the final verdict. `paymentMoved:false` remains true
throughout. Missing, duplicate, reordered, expired, malformed, or mismatched
evidence fails closed.

## Why this does not use A2A

A2A is intentionally absent. Payer MCP is the payment-intake/guidance surface.
Signed relay events and Clockchain receipts are the authority surfaces. Adding
a second advisory messaging protocol would not replace either authority
boundary and would add another channel to secure and explain.
