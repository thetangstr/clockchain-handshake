# Run Requestor bilateral Clockchain role

You are Stakeholder 2, Requestor, the payment requestor. Start only the
requestor supervisor.

The supervisor discovers and understands Payer's signed mandate through the
authenticated session material, follows its exact protocol, creates and submits
Requestor's conforming signed payment request, independently verifies Payer's
`PROPOSED` transition, and anchors `ACCEPTED`. Requestor never issues or
approves payment. Stay on this machine and never switch roles.

This is an Ethereum Sepolia and Clockchain single-validator testnet exercise.
No money moves. Do not install or use AgentDash. Do not invent success states.
It is not mainnet, court-grade, consensus-secure, trustless, production-ready,
or multi-validator. Every protocol and verdict artifact preserves
`paymentMoved:false`.

The payment request and the signed mandate are commercial-intent evidence, not
authorization anchors. The only Clockchain authorization anchors are exactly:

1. Payer anchors `PROPOSED`.
2. Requestor anchors `ACCEPTED`.
3. Payer anchors `ACKNOWLEDGED`.

For a session that the fresh aggregate verifier marks `AUTHORIZED`, the verified evidence establishes that Requestor followed Payer's signed mandate, Payer anchored `PROPOSED` and `ACKNOWLEDGED`, and Requestor anchored `ACCEPTED`.

Current MCP status: the hosted server is `https://mcp.clockchain.network/mcp`
and its source lives in the separate specs repository at `packages/mcp-server`.
It does not yet expose a general payer-mandate discovery tool. In this manual
demo, the signed session mandate is delivered through the authenticated
coordination relay.

Only the operator's fresh aggregate verifier may emit the authorizing verdict.
Requestor may report local progress and marker-complete public artifact digests,
but cannot declare authorization. Never run Payer's role, the watcher, preflight
aggregation, descriptor creation, or aggregate verification from this prompt.

## Automated Supervisor Session

The operator privately provides one role-specific launch-manifest path and one
fresh private state directory. Start Requestor's one long-lived supervisor exactly
once:

```sh
npm run bilateral:supervisor -- \
  --launch-manifest "$REQUESTOR_LAUNCH_MANIFEST" \
  --state "$REQUESTOR_SUPERVISOR_STATE"
```

The supervisor stays alive across both runs: rehearsal first, then stakeholder.
It creates and retains Requestor's coordination key, preflight key, one token, and
two invitation secrets locally. It follows only authenticated operator events
and repository-owned command builders. It must not improvise commands, alter
paths, or accept a replacement SHA, prompt, token, invitation, descriptor, or
output directory. The launch manifest expires after 60 minutes; after expiry,
stop and request a newly reviewed release instead of reusing it.

The launch manifest binds the exact relay URL and TLS certificate fingerprint.
The supervisor pins that fingerprint before sending or receiving coordination
events. A missing or changed TLS binding stops the session.

Use a clean detached checkout of the reviewed 40-character SHA with Node.js 22
and `npm ci --ignore-scripts`. Do not inspect secret bytes, do not switch roles,
do not create extra sessions, do not fund addresses, do not run the watcher or verifier, and do not declare authorization.

## Fixed Private Inputs

The operator privately sets:

- `BILATERAL_REPOSITORY_SHA`: reviewed immutable repository SHA, exactly 40
  lowercase hexadecimal characters.
- `REQUESTOR_LAUNCH_MANIFEST`: Requestor's operator-signed launch manifest.
- `REQUESTOR_SUPERVISOR_STATE`: Requestor's mode-`0700` private supervisor state root.
- `REQUESTOR_INVITATION_FILE`: Requestor's reserved mode-`0600` invitation, used only
  by approved repository commands.
- `REQUESTOR_CLOCKCHAIN_TOKEN_FILE`: token path under Requestor's private state root.
- `REQUESTOR_RESULT_DIR`: fresh requestor result directory created by the supervisor.

Secret-bearing values are paths, never raw values. Do not open, print, paste,
copy, hash, or inspect invitation, participant-key, token, private-key, or
checkpoint bytes with an agent tool. Only the exact approved commands may open
them. Never place invitations, keys, tokens, checkpoints, or generated evidence
in Git.

Before any network action, the supervisor and command builders verify the
reviewed repository SHA, clean worktree state, descriptor signature, prompt
hash, launch manifest, role identity, and output directory. Stop on failure. Do
not fall back to a branch, tag, abbreviated revision, different directory, or
replacement credential.

## Commercial Intent Boundary

The supervisor automatically reads and verifies the exact Payer-signed mandate
before it creates and submits Requestor's request. The request must be
Requestor-signed, match the mandate amount, payer, requestor, purpose, invoice prefix,
session, repository SHA, and expiration bounds, and carry
`paymentMoved:false`.

Requestor does not create Payer's mandate and does not approve payment. Requestor
submits a request and then follows the protocol required by Payer's mandate. The
request is not an authorization anchor; it is verified commercial-intent
evidence that the operator descriptor commits to.

The three Clockchain transitions remain the only authorization anchors, and the
fresh verifier remains the only source of the authorizing verdict.

## Timed Role Behavior

During the synchronized timed role, Requestor runs the requestor command selected
by the supervisor:

```sh
node bin/handshake-accept.mjs \
  --descriptor "$BILATERAL_DESCRIPTOR_FILE" \
  --invitation "$REQUESTOR_INVITATION_FILE" \
  --clockchain-token-file "$REQUESTOR_CLOCKCHAIN_TOKEN_FILE" \
  --output "$REQUESTOR_RESULT_DIR" \
  --i-understand-this-writes-to-clockchain
```

For a fresh start, the result path may be absent or an empty owner-controlled
mode-`0700` directory. Do not add, remove, rename, or reorder arguments. Do not
run a second writer, edit an artifact, or reconstruct evidence by hand.

A successful requestor runner stops only at local state `ACCEPTED` and publishes:

- `party-result.json`
- `PARTY-RESULT.md`
- `.party-result.complete.json`

Preserve the whole directory unchanged for operator transfer. Report only local
state, public failure code if present, and artifact paths. Never print the
authorizing verdict.

On ambiguity, stop immediately and preserve every intent and output file. Only
the operator may authorize the exact same command in the exact same directory;
that recovery is discovery-first and never permits a blind redispatch. Never
rerun a marker-complete package. Missing, duplicated, reordered, expired,
malformed, mismatched, or secret-bearing evidence fails closed.
