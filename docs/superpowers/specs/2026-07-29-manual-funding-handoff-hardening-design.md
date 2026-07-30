# Manual funding handoff hardening

## Problem

The first live Hermes rehearsal reached all prerequisite milestones:

- Payer reported `PAYER_MCP_READY`.
- Requestor received exact `HANDSHAKE_REQUIRED` with `paymentMoved:false`.
- Both roles enrolled through the authenticated relay.
- The coordinator published its signed four-address funding record.

The role supervisors then exited before the operator funding batch could confirm.
The coordinator already waits up to eight minutes for funding, but each role
performs only one immediate balance and nonce check after `WAIT_FOR_FUNDING`.
Because the operator cannot fund addresses until the coordinator publishes
them, the one-shot role checks create an unavoidable race in a human-operated
demo.

The failed rehearsal also showed that a general-purpose agent may try to recover
by deleting or recreating its persisted state. Once the one-time launch manifest
has been consumed, deleting role state destroys the only remaining private
recovery material and makes the session unrecoverable.

## Constraints

- Preserve `PROPOSED -> ACCEPTED -> ACKNOWLEDGED -> operator verification ->
  AUTHORIZED`.
- Preserve exactly three independently verifiable Clockchain anchors per run.
- Only the fresh aggregate verifier may output `AUTHORIZED`.
- Preserve `paymentMoved:false` everywhere.
- Keep missing, duplicate, reordered, expired, malformed, mismatched, overfunded,
  or replayed evidence fail closed.
- Never treat relay, watcher, coordinator, console, or agent narration as
  authority.
- Never expose or commit tokens, invitations, private keys, capabilities,
  manifests, RPC URLs, or live evidence.
- Keep the four generated addresses fresh and coordinator-owned.
- Do not add a new protocol event or change the authorization state machine for
  this fix.

## Runtime design

Replace the role-side point-in-time funding check with a bounded
condition-based wait.

Each role verifies only its two enrollment-bound addresses. On every poll it
reads the latest balance and transaction count for both addresses.

The result classification is:

- **Ready:** both balances are between `0.005` and `0.02` Sepolia ETH,
  inclusive, and both nonces are zero.
- **Pending:** every nonce is zero, no balance exceeds `0.02` Sepolia ETH, and
  at least one balance is below `0.005` Sepolia ETH. Zero and partially funded
  states remain pending.
- **Invalid:** malformed RPC data, a nonzero nonce, an overfunded address,
  duplicate or mismatched addresses, changed enrollment/session/repository
  context, or any other validation failure. Invalid input fails immediately.

Pending input is polled at a bounded interval until the existing eight-minute
funding deadline expires. The deadline matches the coordinator funding window.
At expiry, the role fails closed without publishing `FUNDING_INPUTS_READY`.

The role emits `FUNDING_INPUTS_READY` only after both of its addresses are
independently re-read as ready.

## Agent and operator instructions

The Payer and Requestor prompts and runbooks will state:

- Start the one long-lived role process exactly once.
- When the agent environment imposes a foreground command timeout, use that
  environment's background-process facility from the outset while keeping the
  process and sanitized output monitored.
- Never delete, empty, rename, replace, or recreate the assigned supervisor
  state root.
- Never retry a consumed launch manifest, generate a second intake request, or
  start the Requestor supervisor directly.
- If the long-lived process exits before a marker-complete terminal result,
  preserve state and stop for an operator-provided recovery decision.
- Operator funding may take several minutes; a pending funding state is normal
  and must not be treated as a role failure before the bounded deadline.

The public `/handshake/run` page will carry the same operational language in
the Payer and Requestor prompt boxes.

## Verification design

Focused tests will prove:

1. A role beginning with two zero balances waits rather than failing.
2. Partial funding waits without publishing readiness.
3. Both valid balances with zero nonces succeed.
4. A nonzero nonce fails immediately.
5. An overfunded address fails immediately.
6. Malformed or mismatched input fails immediately.
7. The eight-minute deadline fails closed and never publishes readiness.
8. Production dependency wiring supplies the bounded clock and sleeper.
9. Prompt and documentation gates prohibit state deletion and describe
   background execution for timeout-limited agent shells.

After focused tests pass, run the repository verification suite once as the
final local gate. A new live Hermes rehearsal requires a newly funded set of
four addresses and remains a separate acceptance gate; the already funded
failed-session addresses are not reusable.

## Acceptance criteria

- A deterministic test reproduces the former zero-balance race and fails before
  the runtime change.
- The role waits through zero and partial balances and succeeds after funding.
- Every invalid funding condition still fails closed.
- No protocol state, anchor count, authority boundary, or `paymentMoved:false`
  invariant changes.
- Public and repository instructions explicitly preserve role state and support
  long-lived execution in timeout-limited agent environments.
- Focused checks and one fresh `npm run verify` pass.
- The public manual page pins the new reviewed release SHA.

## Out of scope

- Adding an operator `FUNDING_CONFIRMED` relay event.
- Making a consumed Requestor launch manifest reusable.
- Automatically recreating or recovering deleted private role state.
- Reusing the four funded addresses from the failed rehearsal.
- Claiming live-demo validation without a new funded physical rehearsal.
