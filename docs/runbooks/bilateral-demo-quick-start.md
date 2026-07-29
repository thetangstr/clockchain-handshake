# Bilateral Clockchain three-computer quick-start

Use this start-here checklist with the [repository overview](../../README.md),
the [full runbook](../../docs/runbooks/bilateral-demo-day.md), the
[Iris prompt](../../prompts/run-iris-bilateral-demo.md), and the
[Billie prompt](../../prompts/run-billie-bilateral-demo.md). The full runbook is
authoritative for recovery and low-level commands. The public
[live-demo helper](https://clockchain-research.vercel.app/handshake/run)
explains these steps without receiving live session evidence.

This is an Ethereum Sepolia and Clockchain® single-validator testnet exercise.
No money moves. Do not install or use AgentDash. Do not invent success states.
It is not mainnet, court-grade, consensus-secure, trustless, production-ready,
or multi-validator. Every protocol and verdict artifact preserves paymentMoved: false.

Runner local state is not operator authorization. For a session that the fresh
aggregate verifier marks `AUTHORIZED`, the verified evidence establishes that
Billie followed Iris's signed mandate, Iris anchored `PROPOSED` and
`ACKNOWLEDGED`, and Billie anchored `ACCEPTED`. The protocol does not download message bytes from Clockchain.

## Before everyone starts

- Use immutable repository SHA `034cdbe4bff8999819d3834f94da5286470b8a99` as the executable release.
- This later handoff/helper is a documentation and test layer for executable SHA 034cdbe4bff8999819d3834f94da5286470b8a99; operators checkout the exact executable SHA, and it does not alter executable runtime bytes.
- Confirm Node.js 22 is installed on all three computers.
- Confirm a clean checkout of exact SHA `034cdbe4bff8999819d3834f94da5286470b8a99` on all three computers.
- Confirm the operator Mac can reach both role computers over the advertised relay IP.
- Publish no secrets, live evidence, or manifest contents.
- Do not claim physical rehearsal passed; report only fresh verifier output and public status words.
- Treat passing deterministic checks as rehearsal-ready, not live-validated.
  Only a funded physical run with fresh independently re-verifiable evidence is
  live-validated.

## Fixed role assignment

- Operator = relay, coordinator, read-only console, funding, watcher, and fresh aggregate verifier.
- Stakeholder 1 = Iris, payer.
- Stakeholder 2 = Billie, payee.
- Do not swap roles, share launch manifests across roles, or add extra role sessions.

## Operator checklist

- Open the full runbook and keep this quick-start beside it.
- Start the relay before the coordinator, then start the read-only advisory
  operator console. Keep all three terminals attached.
- Wait until both role computers are ready because launch manifests expire after 60 minutes.
- Deliver `payer.launch.json` only Iris through Iris's private channel.
- Deliver `payee.launch.json` only Billie through Billie's private channel.
- Keep `funding-addresses.json` coordinator-owned and use that file directly for funding.

## Iris checklist

- Use the Iris prompt and only the Iris private state directory.
- Confirm the clean exact reviewed SHA and Node.js 22 before running the supervisor.
- Use only `payer.launch.json`.
- Stop if Billie's manifest, operator files, funding files, token files, or private bytes are visible.
- Iris may reach local `PROPOSED` and `ACKNOWLEDGED`; Iris never emits `AUTHORIZED`.

## Billie checklist

- Use the Billie prompt and only the Billie private state directory.
- Confirm the clean exact reviewed SHA and Node.js 22 before running the supervisor.
- Use only `payee.launch.json`.
- Stop if Iris's manifest, operator files, funding files, token files, or private bytes are visible.
- Billie may reach local `ACCEPTED`; Billie never emits `AUTHORIZED`.

## Funding and execution order

The startup control order is exactly:
`relay -> coordinator -> console -> funding -> Iris payer supervisor -> Billie payee supervisor`.
Funding at this point means validating and arming the reusable Sepolia
treasury lane; transfers wait for the coordinator's signed address record.

1. Operator starts relay.
2. Operator starts coordinator after relay readiness.
3. Operator starts the loopback-default read-only advisory console.
4. Operator validates and arms the reusable Sepolia treasury funding lane.
5. Operator delivers `payer.launch.json` only to Iris. Iris starts the payer supervisor.
6. Operator delivers `payee.launch.json` only to Billie. Billie starts the payee supervisor.
7. The supervisors automatically create the Iris-signed mandate and matching
   Billie-signed request; no operator-authored terms or manual artifact copy is allowed.
8. Coordinator writes coordinator-owned `funding-addresses.json`.
9. Operator runs `npm run bilateral:fund` once to make exactly four
   `0.01 Sepolia ETH` allocations from the reusable treasury.
10. The protocol order is `PROPOSED` -> `ACCEPTED` -> `ACKNOWLEDGED` -> operator verification -> `AUTHORIZED`.

## What counts as success

- The fresh aggregate verifier independently refetches exactly three independently verifiable Clockchain anchors.
- Those anchors are Iris `PROPOSED`, Billie `ACCEPTED`, and Iris `ACKNOWLEDGED` in that order.
- Only a fresh aggregate verifier may output `AUTHORIZED`.
- The verdict preserves `paymentMoved:false`.
- Any local runner status, watcher line, submitted transaction, or narrative before fresh operator verification is not success.

## Immediate stop conditions

Stop on missing, duplicate, reordered, expired, malformed, or mismatched evidence.
Stop on a dirty checkout, SHA mismatch, wrong Node.js version, wrong role, wrong
manifest recipient, expired manifest, visible secret bytes, live evidence in a
chat or commit, manifest contents in a chat or commit, unexpected role command,
extra role session, unreachable relay, failed funding preflight, nonzero
coordinator exit, or any claim that bypasses the fresh aggregate verifier.
