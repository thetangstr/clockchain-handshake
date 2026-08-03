# Hybrid Local Stakeholder Demo

This is the live demo path for the stakeholder session. Yang/Codex runs the real Payer and operator on the local authority machine. The stakeholder runs
only the Requestor agent from the public page at
https://clockchain-research.vercel.app/handshake/run.

Use an installed ChatGPT Codex, Claude Code, or Hermes agent on macOS, Windows,
or Linux. Browser-only and web-only agents are not supported for the live role.

This is an Ethereum Sepolia and Clockchain® single-validator testnet exercise.
No money moves. Do not install or use AgentDash. Do not invent success states.
It is not mainnet, court-grade, consensus-secure, trustless, production-ready,
or multi-validator. Every protocol and verdict artifact preserves paymentMoved: false.

## Operator Command

Run the local authority from a clean reviewed release:

```sh
npm run bilateral:local-operator -- \
  --config .context/hybrid-demo/operator.json \
  --state /absolute/private/new-state-root
```

Operator-visible gates:

1. `RELAY_LISTENING`
2. `PAYER_MCP_READY`
3. `PUBLIC_EDGE_READY`
4. `REQUESTOR_DISCOVERY_PUBLISHED`
5. `REQUESTOR_HANDOFF_READY`

The operator output is business status only. It must not contain role secrets,
raw evidence, or `AUTHORIZED`.

## Stakeholder Requestor Prompt

After `REQUESTOR_HANDOFF_READY`, the stakeholder copies one Requestor prompt
from the public run page. The prompt uses the signed discovery URL and runs this
one-shot command:

```sh
npm run bilateral:request-payment -- \
  --discovery-url "$REQUESTOR_DISCOVERY_URL" \
  --state "$REQUESTOR_STATE_ROOT"
```

The Requestor wrapper calls the Payer-owned MCP, receives exact
`HANDSHAKE_REQUIRED` guidance, validates the signed mandate, starts the
Requestor supervisor, and stays attached until Requestor reaches `ACCEPTED`.
The stakeholder does not run Payer setup, funding, the watcher, or the verifier.

## Live Order

relay -> coordinator -> console -> bootstrap broker -> public edge -> Payer MCP/supervisor -> PAYER_MCP_READY -> signed Requestor discovery -> Requestor request_payment -> HANDSHAKE_REQUIRED -> bootstrap approval -> funding batch -> PROPOSED -> ACCEPTED -> ACKNOWLEDGED -> fresh verification -> public receipts

The Payer publishes terms. The Requestor conforms to those terms. Clockchain
anchors exactly three independently re-verifiable Clockchain anchors in this
order: `PROPOSED`, `ACCEPTED`, `ACKNOWLEDGED`. Payer owns `PROPOSED` and
`ACKNOWLEDGED`; Requestor owns `ACCEPTED`.

Only a fresh aggregate verifier may output `AUTHORIZED`. Role-local completion,
the relay, the console, the public monitor, and the operator launcher cannot
authorize the run.

## Funding

The operator-selected `fund-on-ready` policy funds exactly four fresh addresses with `0.01 Sepolia ETH` each through the replay-safe journal. The launcher waits
for the coordinator-owned funding record, preserves the journal for recovery,
and stops if the record, journal, treasury balance, nonce, amount, or recipient
set is ambiguous.

## Public Evidence

The live monitor publishes `latest.json`. A verified terminal run updates `runs/index.json`, preserves immutable `runs/{runId}.json`, and enables the verified HTML receipt email action. Receipt cards must show three proof links,
three ordered anchors, verifier status `VERIFIED`, and `paymentMoved:false`.

Open the public run page after completion to inspect the verified run history.
The immutable receipt remains readable after local processes stop.

## Stop Conditions

Missing, duplicate, reordered, expired, malformed, replayed, or mismatched evidence fails closed. Also stop on wrong release SHA, dirty checkout, wrong
Node version, changed TLS fingerprint, changed funding record, unresolved
funding journal, unexpected child exit, or any authorization claim outside the
fresh verifier.

AWS stakeholder-Payer hosting is deferred hardening. The current live demo uses
AWS only as a thin public edge and public artifact surface; AWS does not own
Payer terms, role evidence, funding authority, or authorization.

See the [repository overview](../../README.md) and the
[public run page](https://clockchain-research.vercel.app/handshake/run).
