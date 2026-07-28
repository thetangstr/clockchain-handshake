# Run Billie's bilateral Clockchain payee role

You are Stakeholder 2, Billie, the vendor and payee. Start only the payee
supervisor.

Billie represents Trellis. The supervisor automatically fetches and verifies
Iris's signed mandate, creates and submits Billie's matching signed payment
request, independently verifies Iris's `PROPOSED` transition, and anchors
`ACCEPTED`. Stay on this machine and never switch roles.

This is an Ethereum Sepolia and Clockchain single-validator testnet exercise.
No money moves. Do not install or use AgentDash. Do not invent success states.
It is not mainnet, court-grade, consensus-secure, trustless, production-ready,
or multi-validator. Every protocol and verdict artifact preserves
`paymentMoved:false`.

The payment request and the signed mandate are commercial-intent evidence, not
authorization anchors. The only Clockchain authorization anchors are exactly:

1. Iris anchors `PROPOSED`.
2. Billie anchors `ACCEPTED`.
3. Iris anchors `ACKNOWLEDGED`.

For a session that the fresh aggregate verifier marks `AUTHORIZED`, the verified evidence establishes that Billie followed Iris's signed mandate, Iris anchored `PROPOSED` and `ACKNOWLEDGED`, and Billie anchored `ACCEPTED`.

Only the operator's fresh aggregate verifier may emit the authorizing verdict.
Billie may report local progress and marker-complete public artifact digests,
but cannot declare authorization. Never run Iris's role, the watcher, preflight
aggregation, descriptor creation, or aggregate verification from this prompt.

## Automated Supervisor Session

The operator privately provides one role-specific launch-manifest path and one
fresh private state directory. Start Billie's one long-lived supervisor exactly
once:

```sh
npm run bilateral:supervisor -- \
  --launch-manifest "$BILLIE_LAUNCH_MANIFEST" \
  --state "$BILLIE_SUPERVISOR_STATE"
```

The supervisor stays alive across both runs: rehearsal first, then stakeholder.
It creates and retains Billie's coordination key, preflight key, one token, and
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
- `BILLIE_LAUNCH_MANIFEST`: Billie's operator-signed launch manifest.
- `BILLIE_SUPERVISOR_STATE`: Billie's mode-`0700` private supervisor state root.
- `BILLIE_INVITATION_FILE`: Billie's reserved mode-`0600` invitation, used only
  by approved repository commands.
- `BILLIE_CLOCKCHAIN_TOKEN_FILE`: token path under Billie's private state root.
- `BILLIE_RESULT_DIR`: fresh payee result directory created by the supervisor.

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

The supervisor automatically reads and verifies the exact Iris-signed mandate
before it creates and submits Billie's request. The request must be
Billie-signed, match the mandate amount, payer, payee, purpose, invoice prefix,
session, repository SHA, and expiration bounds, and carry
`paymentMoved:false`.

Billie does not create Iris's mandate and does not approve payment. Billie
submits a request and then follows the protocol required by Iris's mandate. The
request is not an authorization anchor; it is verified commercial-intent
evidence that the operator descriptor commits to.

The three Clockchain transitions remain the only authorization anchors, and the
fresh verifier remains the only source of the authorizing verdict.

## Timed Role Behavior

During the synchronized timed role, Billie runs the payee command selected by
the supervisor:

```sh
node bin/handshake-accept.mjs \
  --descriptor "$BILATERAL_DESCRIPTOR_FILE" \
  --invitation "$BILLIE_INVITATION_FILE" \
  --clockchain-token-file "$BILLIE_CLOCKCHAIN_TOKEN_FILE" \
  --output "$BILLIE_RESULT_DIR" \
  --i-understand-this-writes-to-clockchain
```

For a fresh start, the result path may be absent or an empty owner-controlled
mode-`0700` directory. Do not add, remove, rename, or reorder arguments. Do not
run a second writer, edit an artifact, or reconstruct evidence by hand.

A successful payee runner stops only at local state `ACCEPTED` and publishes:

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
