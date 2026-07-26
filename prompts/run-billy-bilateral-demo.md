# Run Billy's bilateral Clockchain role

This is the Billy machine, and Billy is the payer. Follow the
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
Never run Iris's role, the watcher, preflight aggregation, descriptor creation,
or aggregate verification from this prompt.

## Fixed private inputs

The operator privately sets:

- `BILATERAL_REPOSITORY_SHA`: reviewed immutable repository SHA, exactly 40
  lowercase hexadecimal characters.
- `BILLY_INVITATION_FILE`: Billy's reserved mode-`0600` invitation.
- `BILLY_CLOCKCHAIN_TOKEN_FILE`: new token output path under a mode-`0700`
  private directory.
- `PREFLIGHT_PLAN_FILE`: operator-signed public plan.
- `BILLY_PREFLIGHT_PRIVATE_KEY_FILE`: Billy's ephemeral mode-`0600` probe key.
- `BILLY_PREFLIGHT_RESULT_DIR`: fresh private probe output directory.
- `BILLY_REGISTRATION_DIR`: fresh private registration output directory.
- `BILATERAL_DESCRIPTOR_FILE`: set only after registration and operator freeze.
- `BILLY_RESULT_DIR`: fresh payer result directory.

Secret-bearing arguments are paths, never raw values. Do not open, print, paste,
copy, hash, or inspect invitation, participant-key, or token bytes with an
agent tool. Only the exact approved commands may open them. Never place
invitations, keys, tokens, checkpoints, or generated evidence in Git.

Before any network action:

```sh
printf '%s\n' "$BILATERAL_REPOSITORY_SHA" | grep -Eq '^[0-9a-f]{40}$'
test "$(git rev-parse HEAD)" = "$BILATERAL_REPOSITORY_SHA"
test -z "$(git status --porcelain)"
test -f "$BILLY_INVITATION_FILE"
test -r "$BILLY_INVITATION_FILE"
test -f "$PREFLIGHT_PLAN_FILE"
test -r "$PREFLIGHT_PLAN_FILE"
test -f "$BILLY_PREFLIGHT_PRIVATE_KEY_FILE"
test -r "$BILLY_PREFLIGHT_PRIVATE_KEY_FILE"
```

Stop on failure. Do not fall back to a branch, tag, abbreviated revision,
different directory, or replacement credential.

## Phase -1: mint and preflight

Run the one-shot token mint exactly once:

```sh
node scripts/mint-bilateral-token.mjs \
  --role payer \
  --output "$BILLY_CLOCKCHAIN_TOKEN_FILE" \
  --repository-sha "$BILATERAL_REPOSITORY_SHA"
```

Expected fixed status is `TOKEN_READY`. If the command fails after creating its
intent marker, stop; never mint again at that path or substitute another token.

Run the physical-machine participant exactly once:

```sh
node scripts/probe-bilateral-rendezvous.mjs participant \
  --role payer \
  --plan "$PREFLIGHT_PLAN_FILE" \
  --token-file "$BILLY_CLOCKCHAIN_TOKEN_FILE" \
  --participant-private-key "$BILLY_PREFLIGHT_PRIVATE_KEY_FILE" \
  --output "$BILLY_PREFLIGHT_RESULT_DIR"
```

Preserve the marker-complete participant directory and report its path to the
operator. Do not attest machine or credential separation yourself. Wait until
the operator confirms aggregate `RENDEZVOUS_OK`. The same Clockchain token used
for preflight must be reused unchanged by the timed role.

## Phase 0: register and wait for the descriptor

After the operator's preflight pass signal, run:

```sh
node scripts/register-bilateral-identity.mjs \
  --invitation "$BILLY_INVITATION_FILE" \
  --output "$BILLY_REGISTRATION_DIR" \
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

On the operator's synchronized start signal, run exactly:

```sh
node bin/handshake-propose.mjs \
  --descriptor "$BILATERAL_DESCRIPTOR_FILE" \
  --invitation "$BILLY_INVITATION_FILE" \
  --clockchain-token-file "$BILLY_CLOCKCHAIN_TOKEN_FILE" \
  --output "$BILLY_RESULT_DIR" \
  --i-understand-this-writes-to-clockchain
```

For a fresh start, the result path may be absent or an empty owner-controlled
mode-`0700` directory. Do not add, remove, rename, or reorder arguments. Do not
run a second writer, edit an artifact, or reconstruct evidence by hand.

A successful payer runner stops only at local state `ACKNOWLEDGED` and publishes:

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
