# Run Iris's bilateral Clockchain role

You are Stakeholder 1, Iris, the payee. Start only the payee supervisor.

This is the Iris machine, and Iris is the payee. Follow the
[bilateral demo-day runbook](../docs/runbooks/bilateral-demo-day.md) and the
operator's phase signals. Stay on this machine and never switch roles.

This is an Ethereum Sepolia and Clockchain® single-validator testnet exercise.
No money moves. Do not install or use AgentDash. Do not invent success states.
It is not mainnet, court-grade, consensus-secure, trustless, production-ready,
or multi-validator. Every protocol and verdict artifact preserves paymentMoved: false.

Runner local state is not operator authorization. For a session that the fresh
aggregate verifier marks `AUTHORIZED`, the verified evidence establishes that
Iris reconstructed Billy's canonical proposal from the signed amount options
and anchored digest. The protocol does not download message bytes from Clockchain.

Only the operator's fresh aggregate verifier may emit the authorizing verdict.
Never run Billy's role, the watcher, preflight aggregation, descriptor creation,
or aggregate verification from this prompt.

## Automated supervisor session

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
stop and request a newly reviewed release instead of reusing it. A fixed
failure is terminal unless the authenticated same-input recovery protocol
applies.

Use a clean detached checkout of the reviewed 40-character SHA with Node.js 22
and `npm ci --ignore-scripts`. Do not inspect secret bytes, do not switch roles,
do not create extra sessions, do not fund addresses, do not run the watcher or verifier, and do not declare authorization.

Iris may report local progress and marker-complete public artifact digests, but
cannot declare authorization. Only the fresh operator aggregate-verifier
process can issue the authorizing verdict.

## Operator-authorized recovery appendix

The commands below are retained only for a diagnosed recovery explicitly
authorized by the operator. They are not the primary demo-day flow.

## Fixed private inputs

The operator privately sets:

- `BILATERAL_REPOSITORY_SHA`: reviewed immutable repository SHA, exactly 40
  lowercase hexadecimal characters.
- `IRIS_INVITATION_FILE`: Iris's reserved mode-`0600` invitation.
- `IRIS_CLOCKCHAIN_TOKEN_FILE`: new token output path under a mode-`0700`
  private directory.
- `PREFLIGHT_PLAN_FILE`: operator-signed public plan.
- `IRIS_PREFLIGHT_PRIVATE_KEY_FILE`: Iris's ephemeral mode-`0600` probe key.
- `IRIS_PREFLIGHT_RESULT_DIR`: fresh private probe output directory.
- `IRIS_REGISTRATION_DIR`: fresh private registration output directory.
- `BILATERAL_DESCRIPTOR_FILE`: set only after registration and operator freeze.
- `IRIS_RESULT_DIR`: fresh payee result directory.

Secret-bearing arguments are paths, never raw values. Do not open, print, paste,
copy, hash, or inspect invitation, participant-key, or token bytes with an
agent tool. Only the exact approved commands may open them. Never place
invitations, keys, tokens, checkpoints, or generated evidence in Git.

Before any network action:

```sh
printf '%s\n' "$BILATERAL_REPOSITORY_SHA" | grep -Eq '^[0-9a-f]{40}$'
test "$(git rev-parse HEAD)" = "$BILATERAL_REPOSITORY_SHA"
test -z "$(git status --porcelain)"
test -f "$IRIS_INVITATION_FILE"
test -r "$IRIS_INVITATION_FILE"
test -f "$PREFLIGHT_PLAN_FILE"
test -r "$PREFLIGHT_PLAN_FILE"
test -f "$IRIS_PREFLIGHT_PRIVATE_KEY_FILE"
test -r "$IRIS_PREFLIGHT_PRIVATE_KEY_FILE"
```

Stop on failure. Do not fall back to a branch, tag, abbreviated revision,
different directory, or replacement credential.

## Phase -1: mint and preflight

Run the one-shot token mint exactly once:

```sh
node scripts/mint-bilateral-token.mjs \
  --role payee \
  --output "$IRIS_CLOCKCHAIN_TOKEN_FILE" \
  --repository-sha "$BILATERAL_REPOSITORY_SHA"
```

Expected fixed status is `TOKEN_READY`. If the command fails after creating its
intent marker, stop; never mint again at that path or substitute another token.

Run the physical-machine participant exactly once:

```sh
node scripts/probe-bilateral-rendezvous.mjs participant \
  --role payee \
  --plan "$PREFLIGHT_PLAN_FILE" \
  --token-file "$IRIS_CLOCKCHAIN_TOKEN_FILE" \
  --participant-private-key "$IRIS_PREFLIGHT_PRIVATE_KEY_FILE" \
  --output "$IRIS_PREFLIGHT_RESULT_DIR"
```

Preserve the marker-complete participant directory and report its path to the
operator. Do not attest machine or credential separation yourself. Wait until
the operator confirms aggregate `RENDEZVOUS_OK`. The same Clockchain token used
for preflight must be reused unchanged by the timed role.

## Phase 0: register and wait for the descriptor

After the operator's preflight pass signal, run:

```sh
node scripts/register-bilateral-identity.mjs \
  --invitation "$IRIS_INVITATION_FILE" \
  --output "$IRIS_REGISTRATION_DIR" \
  --repository-sha "$BILATERAL_REPOSITORY_SHA" \
  --i-understand-this-writes-to-sepolia
```

Expected fixed status is `IDENTITY_READY`. Preserve `identity.json`,
`.identity.complete.json`, and `registration-checkpoint.json`; transfer only
the marker-complete, secret-free identity artifacts to the operator.

If registration stops after a checkpoint, do not choose a new invitation or
directory. Stop and wait. Only an operator-authorized recovery may rerun the
exact command with the exact same inputs and directory.

Wait for the operator to create and privately deliver the signed descriptor.
Perform only metadata checks that it is a readable regular input; do not edit
or replace it.

## Phase 1: synchronized timed role

For the synchronized start, begin polling when the operator signals Iris,
immediately before Billy starts:

```sh
node bin/handshake-accept.mjs \
  --descriptor "$BILATERAL_DESCRIPTOR_FILE" \
  --invitation "$IRIS_INVITATION_FILE" \
  --clockchain-token-file "$IRIS_CLOCKCHAIN_TOKEN_FILE" \
  --output "$IRIS_RESULT_DIR" \
  --i-understand-this-writes-to-clockchain
```

For a fresh start, the result path may be absent or an empty owner-controlled
mode-`0700` directory. Do not add, remove, rename, or reorder arguments. Do not
run a second writer, edit an artifact, or reconstruct evidence by hand.

A successful payee runner stops only at local state `ACCEPTED` and publishes:

- `party-result.json`
- `PARTY-RESULT.md`
- `.party-result.complete.json`

Preserve the whole directory unchanged for operator transfer. Report only the
local state, public failure code if present, and artifact paths. Never print
the authorizing verdict.

On ambiguity, stop immediately and preserve every intent and output file. Only
the operator may authorize the exact same command in the exact same directory;
that recovery is discovery-first and never permits a blind redispatch. Never
rerun a marker-complete package. Missing, duplicated, reordered, expired,
malformed, mismatched, or secret-bearing evidence fails closed.
