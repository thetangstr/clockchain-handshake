# AWS bilateral demo-day operator runbook

This is an Ethereum Sepolia and Clockchain® single-validator testnet exercise.
No money moves. Do not install or use AgentDash. Do not invent success states.
It is not mainnet, court-grade, consensus-secure, trustless, production-ready,
or multi-validator. Every protocol and verdict artifact preserves paymentMoved: false.

This runbook is for the human operator. Stakeholders follow the public
[Payer prompt](../../prompts/run-payer-bilateral-demo.md) and
[Requestor prompt](../../prompts/run-requestor-bilateral-demo.md). The
[quick start](./bilateral-demo-quick-start.md), [live handoff](./bilateral-demo-live-handoff.md),
[managed Payer MCP relay](./payer-mcp-external-relay.md), and
[public run page](https://clockchain-research.vercel.app/handshake/run) describe
the same hosted workflow. See the [repository overview](../../README.md) for the
product boundary.

## Operator preflight

Before admitting either stakeholder, confirm in the AWS operator console:

- the console is authenticated and names the reviewed immutable repository SHA;
- relay, coordinator, bootstrap service, tunnel service, publisher, and public
  monitor are healthy;
- the Payer and Requestor signed discovery URLs are public, unexpired, and bound
  to that SHA and immutable image digest;
- the Sepolia treasury has enough gas for four exact `0.01 Sepolia ETH`
  allocations;
- no run is already active; and
- the public monitor is either waiting or clearly stale, never carrying a
  previous run's success forward.

AWS owns the control plane; each stakeholder machine owns only its private role
state and receives only public signed discovery.

## The six console controls

Five actions are the normal path and must be used in order:

1. **Start run** — create one session bound to the reviewed release.
2. **Approve Payer** — compare the exact displayed Payer claim fingerprint
   with the Payer agent's public claim, then approve once.
3. **Approve Requestor** — only after `PAYER_MCP_READY` and
   `HANDSHAKE_REQUIRED`, compare and approve the Requestor fingerprint once.
4. **Fund** — only after the signed four-address record is ready. The funding
   task is journaled and replay-safe; ambiguity stops rather than resends.
5. **Verify** — only after `PROPOSED`, `ACCEPTED`, and `ACKNOWLEDGED` are all
   present in exact order.

**Abort** is the sixth control. Use it for any mismatch, stale release, process
exit, claimant ambiguity, funding ambiguity, evidence defect, or operator
uncertainty. Abort never converts an incomplete run into success.

The console cannot emit the final authorization literal. It submits revision-
bound control actions only. Every action is authenticated, idempotent, and
visible in secret-free business language.

## Business progress to narrate

1. Payer is admitted and its machine starts the Payer-owned payment-intake
   service.
2. `PAYER_MCP_READY` means the signed mandate is available through Payer MCP.
3. Requestor asks for payment. `HANDSHAKE_REQUIRED` means the Payer's process,
   not an operator-authored instruction, is guiding Requestor.
4. `PROPOSED` means Payer anchored the authorization terms on Clockchain.
5. `ACCEPTED` means Requestor anchored acceptance of those exact terms.
6. `ACKNOWLEDGED` means Payer anchored final acknowledgment.
7. The fresh aggregate verifier refetches and validates exactly three
   independently verifiable Clockchain anchors and publishes `VERIFIED`.

The signed mandate and payment request are commercial-intent evidence, not
authorization anchors. Relay fields, MCP guidance, console state, coordinator
state, watcher state, and role-local completion are advisory. Only the fresh
aggregate verifier owns the final verdict. It validates exactly three
independently verifiable Clockchain anchors. Every public and private artifact
preserves `paymentMoved:false`.

## Failure and recovery

Stop and select **Abort** for missing, duplicate, reordered, expired, malformed,
mismatched, or secret-bearing evidence; changed SHA or image digest; a changed
TLS fingerprint; extra tunnel key or listen port; a stale console revision;
nonzero participant nonce; ambiguous funding; more or fewer than three anchors;
or any role, relay, coordinator, publisher, monitor, or verifier exit.

Do not repeat **Fund** after an ambiguous response. Do not repeat **Verify** with
the same attempt ID. Do not reuse a private state root for another role or run.
Start a new session only after the failed run is durably closed and the public
monitor no longer presents it as current.

## Why this does not use A2A

A2A is intentionally absent. Payer MCP is the payment-intake/guidance surface.
Signed relay events and Clockchain receipts are the authority surfaces. Adding
a second advisory messaging protocol would not replace either authority
boundary; it would only add another advisory channel and trust configuration.
