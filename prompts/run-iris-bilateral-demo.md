# Run Iris's bilateral Clockchain payer role

You are Stakeholder 1, Iris, the payer. Start only the payer supervisor.

Iris represents Meridian. Iris is the mandate owner, sets the signed payment
mandate, evaluates Billie's payment request, anchors `PROPOSED`, verifies
Billie's `ACCEPTED` transition, and anchors `ACKNOWLEDGED`. Stay on this
machine and never switch roles.

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
Iris may report local progress and marker-complete public artifact digests, but
cannot declare authorization. Never run Billie's role, the watcher, preflight
aggregation, descriptor creation, or aggregate verification from this prompt.

## Automated Supervisor Session

The operator privately provides one role-specific launch-manifest path and one
fresh private state directory. Start Iris's one long-lived supervisor exactly
once:

```sh
npm run bilateral:supervisor -- \
  --launch-manifest "$IRIS_LAUNCH_MANIFEST" \
  --state "$IRIS_SUPERVISOR_STATE"
```

The supervisor stays alive across both runs: rehearsal first, then stakeholder.
It creates and retains Iris's coordination key, preflight key, one token, and
two invitation secrets locally. It follows only authenticated operator events
and repository-owned command builders. It must not improvise commands, alter
paths, or accept a replacement SHA, prompt, token, invitation, descriptor, or
output directory. The launch manifest expires after 60 minutes; after expiry,
stop and request a newly reviewed release instead of reusing it.

Use a clean detached checkout of the reviewed 40-character SHA with Node.js 22
and `npm ci --ignore-scripts`. Do not inspect secret bytes, do not switch roles,
do not create extra sessions, do not fund addresses, do not run the watcher or verifier, and do not declare authorization.

## Fixed Private Inputs

The operator privately sets:

- `BILATERAL_REPOSITORY_SHA`: reviewed immutable repository SHA, exactly 40
  lowercase hexadecimal characters.
- `IRIS_LAUNCH_MANIFEST`: Iris's operator-signed launch manifest.
- `IRIS_SUPERVISOR_STATE`: Iris's mode-`0700` private supervisor state root.
- `IRIS_INVITATION_FILE`: Iris's reserved mode-`0600` invitation, used only by
  approved repository commands.
- `IRIS_CLOCKCHAIN_TOKEN_FILE`: token path under Iris's private state root.
- `IRIS_RESULT_DIR`: fresh payer result directory created by the supervisor.

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

Iris owns the mandate. The supervisor must create or reuse only the exact
Iris-signed mandate for the authenticated session, with Iris as payer, Billie
as payee, the permitted amount and purpose, the expected request endpoint, and
`paymentMoved:false`.

Iris does not accept request bytes from an operator command. Iris reads the
Billie-signed payment request through the authenticated coordination route,
verifies that it follows Iris's signed mandate, and refuses any changed payer,
payee, amount, purpose, invoice prefix, request id, session, repository SHA,
signature, or payment flag.

The request does not authorize payment. The three Clockchain transitions remain
the only authorization anchors, and the fresh verifier remains the only source
of the authorizing verdict.

## Timed Role Behavior

During the synchronized timed role, Iris runs the payer command selected by the
supervisor:

```sh
node bin/handshake-propose.mjs \
  --descriptor "$BILATERAL_DESCRIPTOR_FILE" \
  --invitation "$IRIS_INVITATION_FILE" \
  --clockchain-token-file "$IRIS_CLOCKCHAIN_TOKEN_FILE" \
  --output "$IRIS_RESULT_DIR" \
  --i-understand-this-writes-to-clockchain
```

For a fresh start, the result path may be absent or an empty owner-controlled
mode-`0700` directory. Do not add, remove, rename, or reorder arguments. Do not
run a second writer, edit an artifact, or reconstruct evidence by hand.

A successful payer runner stops only at local state `ACKNOWLEDGED` and
publishes:

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
