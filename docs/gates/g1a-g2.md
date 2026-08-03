# Gates G1a + G2 — live protocol run and clean-room stakeholder requestor — PASSED 2026-08-03

Plan: ralplan-clockchain-bilateral-handshake-v2.md.
Release under test: `50c28687bcbdeba1231d2e99a08edfb4cc8189dc` (branch `handshake-codex`).

## G2 — fresh-agent clean-room run (g2-run-3)

A **fresh Hermes agent** (profile `handshake_requester`, model k3) started in
an empty directory with nothing but the pasted `prompts/requestor.md` text
(release SHA + signed discovery URL substituted). No coaching, no retries.

- Agent cloned the public kit, checked out the detached release SHA,
  `npm ci --ignore-scripts`, audited the requestor source, created a 0700
  state root, and ran the wrapper: **6m15s, 41 tool calls, exit 0**.
- Agent correctly refused to claim authorization: "only the operator's
  fresh aggregate verifier reports the final verdict."
- Operator side: rehearsal sub-run gated the stakeholder sub-run
  (`VERDICT_PUBLISHED REHEARSAL_PASSED session=95442b9f-…`), then the
  stakeholder session ran against the live Hermes requestor.

### Stakeholder session verdict (session `37d072a8-548f-4d09-a015-f66e7dd4802f`)

`VERDICT_PUBLISHED AUTHORIZED` — signed by fresh verifier key `g1a-live-1`,
`paymentMoved: false`, repositorySha `50c28687`.

| Transition | Clockchain block | Anchored hash (prefix) |
|---|---|---|
| PROPOSED (proposal) | 2706962 | 36201b437fdfa94e… |
| ACCEPTED (acceptance) | 2706983 | 0b1797ee1f68a253… |
| ACKNOWLEDGED (acknowledgment) | 2706985 | 49f374e746e8f63a… |

- Requestor ERC-8004 agentId **9356**; stakeholder payer **9354**;
  rehearsal payer **9353**.
- Replay-safe funding: batch A (4 fresh addresses, nonces 115–118),
  batch B (Hermes requestor + 3 fresh reserves, nonces 119–122).
  Treasury `0x157a…0dce` remained the only funder; no address was
  funded twice (byte-pinned record + journal).
- Operator exited `OPERATOR_RUN_COMPLETE`; evidence + verdicts under
  `state/g2-run-3/operator/verdicts/`.

## G1a — earlier local live run (g1a-run-3)

Same full protocol on live Clockchain with a CLI-driven requestor:
session `ef34cd8f-15e1-46ec-88c6-6f40c4ec11e0`, verdict **AUTHORIZED**,
anchors at blocks 2704854 / 2704887 / 2704897, `paymentMoved: false`,
repositorySha `09d898b`.

## Live-fire defects found and fixed during G1a/G2 (all committed)

1. **Funding resume** (`54143a2`): an interrupted batch rewrote the
   record with observed post-funding balances; the byte-pinned validator
   then rejected its own record and the batch could never resume.
   Resume now reuses the original declaration; the journal drives
   idempotent completion.
2. **Payer registration adoption** (`50c2868`): a crash during
   post-registration verification left a terminal checkpoint unadopted;
   the restart re-registered and bricked the funded payer key on the
   nonce guard. Operator now adopts address-matched terminal checkpoints
   (mirrors the requestor's existing behavior).

## Rate-limit incident (environmental, resolved)

The hosted Clockchain MCP (`clockchain-mcp` Cloud Run) 429'd token mints:
`MCP_TOKEN_MINT_PER_HOUR=10` (per-IP) was exhausted by repeated demo runs
plus a competing harness on the same LAN. Raised `MCP_RATE_PER_MIN` 30→300
and `MCP_TOKEN_MINT_PER_HOUR` 10→240 for the demo window; both reversible.

## Verification

- Full gate suite after both live-fix commits: `npm run verify` →
  **820/820** plus all invariant sweeps clean.
