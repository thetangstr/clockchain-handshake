# Hermes Role Completion Status Design

## Context

The funded bilateral protocol completed and the fresh aggregate verifier produced
`AUTHORIZED`, but the two Hermes conversations did not present a coherent
end-to-end finish. Payer visibly stopped at `PAYER_MCP_READY`. Requestor reached
the Payer MCP, received `HANDSHAKE_REQUIRED`, and started its supervisor, but its
last visible summary still described an operator-funding wait.

Those messages were valid intermediate states, but they were not sufficient
manual-test completion evidence. The underlying supervisors had no final
secret-free status line designed for an unfamiliar human watching the two role
conversations.

## Goals

- Keep the current number and order of Hermes prompts and private handoffs.
- Make each long-lived role process visibly report its own terminal role state.
- Require no additional Hermes message after operator funding.
- Preserve the exact authority boundary:
  - Payer owns `PROPOSED` and `ACKNOWLEDGED`.
  - Requestor owns `ACCEPTED`.
  - Only the fresh aggregate verifier may emit `AUTHORIZED`.
- Keep every role status secret-free and preserve `paymentMoved:false`.
- Fail closed: an incomplete, failed, malformed, or unauthenticated run must
  never emit role completion.

## Non-goals

- Do not merge or shorten the existing public prompt sequence.
- Do not add a local secret inbox, automatic private-path discovery, or another
  credential-delivery mechanism.
- Do not make the operator console authoritative.
- Do not make Payer or Requestor inspect verifier-private inputs or emit the
  authorization verdict.
- Do not alter the three Clockchain anchors or their ordering.

## Completion Status Contract

Each supervisor process may emit one final canonical JSON line:

```json
{
  "paymentMoved": false,
  "role": "payer",
  "state": "ACKNOWLEDGED",
  "status": "PARTY_COMPLETE"
}
```

or:

```json
{
  "paymentMoved": false,
  "role": "payee",
  "state": "ACCEPTED",
  "status": "PARTY_COMPLETE"
}
```

The mapping is fixed:

| Supervisor role | Public handbook name | Required state |
| --- | --- | --- |
| `payer` | Payer | `ACKNOWLEDGED` |
| `payee` | Requestor | `ACCEPTED` |

No other role, state, status, or field set is valid. The status line contains no
paths, tokens, invitations, capabilities, keys, addresses, fingerprints,
digests, ledger identifiers, or live evidence.

## Emission Gate

The completion line is derived only from the authenticated supervisor replay:

1. The supervisor authenticates and validates the complete relay replay.
2. The replay lifecycle reaches exact terminal state `COMPLETE`.
3. The local supervisor role selects its fixed terminal state using the mapping
   above.
4. The supervisor emits one canonical `PARTY_COMPLETE` line and exits normally.

The line is not derived from advisory relay fields, console text, a Hermes
summary, a local state label, or user-provided content. A process that is still
waiting for funding, processing an event, recovering, aborted, or failed emits
no completion line.

`PAYER_MCP_READY`, `WAITING_FOR_PEER`, `PEER_READY`, and
`HANDSHAKE_REQUIRED` remain intermediate statuses. They never imply role
completion.

The Requestor wrapper continues to emit exact `HANDSHAKE_REQUIRED` after its
single accepted MCP call. The supervisor it starts later emits the Requestor
`PARTY_COMPLETE` line. The Payer supervisor emits `PAYER_MCP_READY` when the
Payer-owned MCP endpoint is listening and emits Payer `PARTY_COMPLETE` only
after the authenticated protocol is complete.

## Hermes Behavior

The existing public prompt cards remain separate. Their launch/action prompts
will explicitly tell each agent to:

1. Start its one approved long-lived process exactly once.
2. Keep the process attached through operator funding.
3. Treat every readiness or wait message as intermediate.
4. Wait for the exact role-mapped `PARTY_COMPLETE` JSON line.
5. Present that line as the final role-local result.
6. Never claim that the role-local result is authorization.

Payer must visibly finish at `ACKNOWLEDGED`. Requestor must visibly finish at
`ACCEPTED`. The human operator then reads the separate fresh aggregate-verifier
result for `AUTHORIZED`.

No post-funding prompt is required in either Hermes conversation.

## Error Handling

- The status serializer rejects missing, extra, malformed, or mismatched fields.
- Payer paired with `ACCEPTED` fails closed.
- Requestor/payee paired with `ACKNOWLEDGED` fails closed.
- Any attempt to serialize `AUTHORIZED` through a role status fails closed.
- A supervisor failure preserves the existing
  `COORDINATION_SUPERVISOR_FAILED` output and emits no `PARTY_COMPLETE`.
- A Requestor MCP failure preserves `REQUEST_PAYMENT_FAILED` and emits no
  completion.
- Restart, recovery, and timeout rules remain unchanged. Timed-out manifests,
  role roots, certificates, and operator state are not reused.

## Documentation

Update the repository runbooks and the public manual handbook to distinguish:

- service readiness: `PAYER_MCP_READY`;
- protocol intake: `HANDSHAKE_REQUIRED`;
- peer readiness: `PEER_READY`;
- role completion: `PARTY_COMPLETE`;
- authorization: fresh verifier `AUTHORIZED`.

The public handbook remains secret-free and continues to expose the existing
six copy controls.

## Test Strategy

1. Status-line unit tests:
   - accept only the two exact role/state mappings;
   - preserve canonical JSON and `paymentMoved:false`;
   - reject extra fields, wrong states, wrong roles, and `AUTHORIZED`.
2. Supervisor tests:
   - emit no completion before authenticated replay `COMPLETE`;
   - emit exactly one mapped completion line on `COMPLETE`;
   - emit no completion on abort or failure.
3. Requestor wrapper tests:
   - preserve the initial `HANDSHAKE_REQUIRED` line;
   - allow the started supervisor to emit the later Requestor completion line.
4. Deterministic multiprocess test:
   - observe one Payer completion and one Requestor completion;
   - preserve the three ordered anchors;
   - preserve fresh-verifier-only `AUTHORIZED`.
5. Documentation and public-page tests:
   - both role prompts require waiting for their mapped completion;
   - no additional Hermes prompt is introduced;
   - the operator console remains non-authoritative.

## Acceptance Criteria

- The existing Hermes input sequence is unchanged.
- After operator funding, no further Hermes input is needed.
- Payer visibly ends with exact `PARTY_COMPLETE` and `ACKNOWLEDGED`.
- Requestor visibly ends with exact `PARTY_COMPLETE` and `ACCEPTED`.
- Neither role output contains `AUTHORIZED`.
- The fresh aggregate verifier remains the sole source of `AUTHORIZED`.
- Exactly three independently verifiable Clockchain anchors remain ordered
  `PROPOSED` → `ACCEPTED` → `ACKNOWLEDGED`.
- `paymentMoved:false` remains true everywhere.
- Missing, duplicate, reordered, expired, malformed, mismatched, or
  unauthenticated evidence fails closed.
