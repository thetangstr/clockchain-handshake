# Handshake demo runbook

One page. Everything the operator needs to run the bilateral
authorization demo end to end. Two machines max; same-machine works.

## What a run proves

A Requestor asks a Payer for payment. Instead of paying, the Payer's
policy requires the handshake: PROPOSED → ACCEPTED → ACKNOWLEDGED, each
independently anchored on Clockchain, then a **fresh aggregate
verifier** re-checks every artifact and publishes the only AUTHORIZED
verdict. `paymentMoved` stays `false` throughout — authorization
evidence, not money movement. Anything missing, malformed, reordered,
expired, duplicated, or replayed fails closed with a named reason code.

## Cast

- **Operator** (you): runs the relay, funds four fresh Sepolia
  addresses per session, enrolls payer identities, publishes discovery
  + descriptor, runs the fresh verifier. Holds the treasury keystore.
- **Payer**: operator-hosted child by default, or a stakeholder agent
  via `prompts/payer.md` when `externalPayer: true` is set in the
  operator config.
- **Requestor**: a stakeholder agent via `prompts/requestor.md`
  (Hermes, Claude Code, Codex — anything with shell + Node 22).

## Budget (the two regimes, quoted verbatim)

- **Out-of-window (human-paced)**: funding, registration, discovery,
  handoffs, evidence pull, verification. Unbounded waits with
  heartbeat; restart-safe at every step.
- **In-window (machine-paced)**: mandate → intake → signed request →
  descriptor → three anchors. Worst case ≈ 609 s under maximal
  throttling against a 600 s window — named `EXPIRED` by design, not a
  crash. The pinned preflight gate (median-of-5 `get_block` < 1,500 ms,
  p95 < 4,000 ms) keeps runs out of that regime. Measured live:
  ≈ 60–90 s per session.

## Operator steps

1. `npm ci --ignore-scripts` on a clean checkout; confirm
   `git status --porcelain` is empty and `npm run release:pin --
   --kit-repo-url=https://github.com/thetangstr/clockchain-handshake.git`
   names the release SHA you announced.
2. Start the relay: `node scripts/serve-relay.mjs --state <run>/relay
   --port 9777` (loopback; or point `relayUrl` at the public relay).
3. Write `<run>/operator/operator-config.json` (schema
   `handshake-operator-config/v2`; add `"externalPayer": true` for a
   stakeholder payer). Set `CLOCKCHAIN_FUNDING_PASSWORD_FILE`.
4. Start the operator: `node src/roles/operator.mjs --state
   <run>/operator`. It funds batch A, registers both payers, runs the
   rehearsal sub-run, then prints handoffs:
   - `PAYER_HANDOFF handoffDir=...` (external payer only)
   - `REQUESTOR_HANDOFF discoveryUrl=...`
5. Hand the payer prompt + handoff dir to the payer agent; hand the
   requestor prompt + release SHA + discovery URL to the requestor
   agent.
6. Watch for `VERDICT_PUBLISHED AUTHORIZED session=...` and
   `OPERATOR_RUN_COMPLETE`.

## Failure posture

- Any role or the relay may die at any point: everything fails closed
  and resumes by restart with the same state dir. Proven live: relay
  kill -9 mid-session and requestor kill -9 in the anchor window both
  recovered to AUTHORIZED (runs `g2-kr`, `g2-kr3`).
- Never rerun a session with changed terms; discovery and verdicts are
  create-only on the relay. New terms = new session.
- Never paste keys, keystores, passwords, tokens, or evidence into a
  chat or prompt. Handoffs are filesystem paths only.

## Records

Each completed run gets an immutable `runs/<id>.json` (append-only;
never edit a committed record).
