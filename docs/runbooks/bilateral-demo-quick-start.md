# Bilateral Clockchain three-computer quick-start

Use this start-here checklist with the [repository overview](../../README.md),
the [full runbook](../../docs/runbooks/bilateral-demo-day.md), the
[Iris prompt](../../prompts/run-iris-bilateral-demo.md), and the
[Billie prompt](../../prompts/run-billie-bilateral-demo.md). The full runbook is
authoritative for recovery and low-level commands.

This is an Ethereum Sepolia and Clockchain® single-validator testnet exercise.
No money moves. Do not install or use AgentDash. Do not invent success states.
It is not mainnet, court-grade, consensus-secure, trustless, production-ready,
or multi-validator. Every protocol and verdict artifact preserves paymentMoved: false.

Runner local state is not operator authorization. For a session that the fresh
aggregate verifier marks `AUTHORIZED`, the verified evidence establishes that
Billie followed Iris's signed mandate, Iris anchored `PROPOSED` and
`ACKNOWLEDGED`, and Billie anchored `ACCEPTED`. The protocol does not download message bytes from Clockchain.

## Before everyone starts

- Use immutable repository SHA `76f585d1e729326b5d749a61937c3971d4f34050`.
- Confirm Node.js 22 is installed on all three computers.
- Confirm a clean checkout of exact SHA `76f585d1e729326b5d749a61937c3971d4f34050` on all three computers.
- Confirm the operator Mac can reach both role computers over the advertised relay IP.
- Publish no secrets, live evidence, or manifest contents.
- Do not claim physical rehearsal passed; report only fresh verifier output and public status words.

## Fixed role assignment

- Operator = relay, coordinator, funding, watcher, and fresh aggregate verifier.
- Stakeholder 1 = Iris, payer.
- Stakeholder 2 = Billie, payee.
- Do not swap roles, share launch manifests across roles, or add extra role sessions.

## Operator checklist

- Open the full runbook and keep this quick-start beside it.
- Start the relay before the coordinator, and keep both terminals attached.
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

1. Operator starts relay.
2. Operator starts coordinator after relay readiness.
3. Operator waits until both role computers are ready because manifests expire after 60 minutes.
4. Operator separately delivers `payer.launch.json` only Iris and `payee.launch.json` only Billie.
5. Iris and Billie start their supervisors from the clean exact SHA checkouts.
6. Coordinator writes coordinator-owned `funding-addresses.json`.
7. Operator runs `npm run bilateral:fund` with coordinator-owned `funding-addresses.json`.
8. The protocol order is `PROPOSED` -> `ACCEPTED` -> `ACKNOWLEDGED` -> operator verification -> `AUTHORIZED`.

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
