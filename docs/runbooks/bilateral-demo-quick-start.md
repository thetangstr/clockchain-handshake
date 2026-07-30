# Bilateral Clockchain three-computer quick-start

Use this start-here checklist with the [repository overview](../../README.md),
the [full runbook](../../docs/runbooks/bilateral-demo-day.md), the
[Payer prompt](../../prompts/run-payer-bilateral-demo.md), and the
[Requestor prompt](../../prompts/run-requestor-bilateral-demo.md). Use the
[external Payer MCP relay runbook](./payer-mcp-external-relay.md) when the role
computers are on different networks. The full runbook is
authoritative for recovery and low-level commands. The public
[live-demo helper](https://clockchain-research.vercel.app/handshake/run)
explains these steps without receiving live session evidence.

This is an Ethereum Sepolia and Clockchain® single-validator testnet exercise.
No money moves. Do not install or use AgentDash. Do not invent success states.
It is not mainnet, court-grade, consensus-secure, trustless, production-ready,
or multi-validator. Every protocol and verdict artifact preserves paymentMoved: false.

Runner local state is not operator authorization. For a session that the fresh
aggregate verifier marks `AUTHORIZED`, the verified evidence establishes that
Requestor followed Payer's signed mandate, Payer anchored `PROPOSED` and
`ACKNOWLEDGED`, and Requestor anchored `ACCEPTED`. The protocol does not download message bytes from Clockchain.

This demo uses a Payer-owned TLS MCP `/mcp` endpoint for payment intake. It
binds only to Payer loopback. AWS forwards raw TCP and does not terminate Payer
MCP TLS. The hosted Clockchain MCP server is not used for `request_payment`.
Requestor asks Payer's MCP for payment, receives exact `HANDSHAKE_REQUIRED`, and
only then the Requestor wrapper starts the supervisor that follows Payer's
signed mandate.

Preserve the assigned private state root unchanged. Underfunding is pending
until the bounded eight-minute funding deadline. Do not retry a consumed launch
manifest.

No additional Hermes message is required after operator funding. Payer remains attached until `PARTY_COMPLETE` with `ACKNOWLEDGED`; Requestor remains attached until `PARTY_COMPLETE` with `ACCEPTED`. These endpoints are not authorization; only the fresh aggregate verifier may emit `AUTHORIZED`.

## Before everyone starts

- Use the operator-provided exact reviewed 40-character immutable repository SHA
  in `BILATERAL_REPOSITORY_SHA` as the executable release. The external public page later pins the final
  immutable SHA; this handoff/helper does not alter executable runtime bytes.
- Confirm Node.js 22 is installed on all three computers.
- Confirm a clean detached checkout of the exact operator-provided SHA on all
  three computers after `git clone --no-checkout`, `git fetch --depth 1`,
  `git checkout --detach`, and `npm ci --ignore-scripts`.
- Confirm the operator Mac can reach both role computers over the advertised relay IP.
- Publish no secrets, live evidence, or manifest contents.
- Do not claim physical rehearsal passed; report only fresh verifier output and public status words.
- Treat passing deterministic checks as rehearsal-ready, not live-validated.
  Only a funded physical run with fresh independently re-verifiable evidence is
  live-validated.

## Fixed role assignment

- Human operator = relay, coordinator, read-only console, funding, watcher, and fresh aggregate verifier.
- Stakeholder 1 = Payer, payer.
- Stakeholder 2 = Requestor, requestor.
- Do not swap roles, share launch manifests across roles, or add extra role sessions.

## Human operator checklist

- Open the full runbook and keep this quick-start beside it.
- Start the relay before the coordinator, then start the read-only advisory
  operator console. Keep all three terminals attached.
- Wait until both role computers are ready because launch manifests expire after 60 minutes.
- Deliver `payer.launch.json` only Payer through Payer's private channel.
- Wait for Payer to report exact `PAYER_MCP_READY`, then transfer only the public
  MCP URL, public TLS certificate, and lowercase 64-hex certificate fingerprint
  to Requestor.
- Deliver `payee.launch.json` only Requestor through Requestor's private channel.
- Keep `funding-addresses.json` coordinator-owned and use that file directly for funding.

## Payer checklist

- Use the Payer prompt and only the Payer private state directory.
- Confirm the clean exact reviewed SHA and Node.js 22 before running the supervisor.
- Use only `payer.launch.json` plus Payer-owned local MCP TLS files.
- Start Payer's raw-TCP tunnel, then its MCP/supervisor, and wait for exact
  `PAYER_MCP_READY`.
- Stop if Requestor's manifest, operator files, funding files, token files, or private bytes are visible.
- Payer may reach local `PROPOSED` and `ACKNOWLEDGED`; Payer never emits `AUTHORIZED`.

## Requestor checklist

- Use the Requestor prompt and only the Requestor private state directory.
- Confirm the clean exact reviewed SHA and Node.js 22 before running the
  request-payment wrapper.
- Use only `payee.launch.json` plus Payer's public MCP URL, public TLS
  certificate, and lowercase 64-hex certificate fingerprint.
- Do not start `npm run bilateral:supervisor` directly. Start
  `npm run bilateral:request-payment`, require exact `HANDSHAKE_REQUIRED`, and
  let the wrapper start the Requestor supervisor.
- Stop if Payer's manifest, operator files, funding files, token files, or private bytes are visible.
- Requestor may reach local `ACCEPTED`; Requestor never emits `AUTHORIZED`.

## Funding and execution order

The startup control order is exactly:
`relay -> coordinator -> console -> funding readiness -> Payer raw-TCP tunnel -> Payer MCP/supervisor -> wait PAYER_MCP_READY -> Requestor request_payment -> HANDSHAKE_REQUIRED -> Requestor supervisor -> funding batch when record ready -> PROPOSED -> ACCEPTED -> ACKNOWLEDGED -> fresh verification -> AUTHORIZED`.
Funding readiness means validating and arming the reusable Sepolia treasury
lane; the funding batch transfers only after the coordinator's signed address
record is ready.

1. Human operator starts relay.
2. Human operator starts coordinator after relay readiness.
3. Human operator starts the loopback-default read-only advisory console.
4. Human operator validates and arms the reusable Sepolia treasury funding lane.
5. Human operator delivers `payer.launch.json` only to Payer. Payer starts its
   non-terminating reverse SSH tunnel, then its loopback TLS MCP/supervisor.
6. Payer waits for exact `PAYER_MCP_READY` and shares only the public MCP URL,
   public TLS certificate, and lowercase 64-hex certificate fingerprint.
7. Human operator delivers `payee.launch.json` only to Requestor. Requestor
   starts `npm run bilateral:request-payment`, receives exact
   `HANDSHAKE_REQUIRED`, and the wrapper starts the Requestor supervisor.
8. The supervisors automatically create the Payer-signed mandate and matching
   Requestor-signed request; no operator-authored terms or manual artifact copy is allowed.
9. Coordinator writes coordinator-owned `funding-addresses.json`.
10. Human operator runs `npm run bilateral:fund` once to make exactly four
   `0.01 Sepolia ETH` allocations from the reusable treasury.
11. The protocol order is `PROPOSED` -> `ACCEPTED` -> `ACKNOWLEDGED` -> operator verification -> `AUTHORIZED`.

## What counts as success

- The fresh aggregate verifier independently refetches exactly three independently verifiable Clockchain anchors.
- Those anchors are Payer `PROPOSED`, Requestor `ACCEPTED`, and Payer `ACKNOWLEDGED` in that order.
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
