# Bilateral Clockchain demo-day runbook

This operator runbook coordinates the [Billy payer prompt](../../prompts/run-billy-bilateral-demo.md),
the [Iris payee prompt](../../prompts/run-iris-bilateral-demo.md), and the
[repository overview](../../README.md). It covers preparation, rehearsal, and
stakeholder execution; it does not replace deterministic verification.

This is an Ethereum Sepolia and Clockchain® single-validator testnet exercise.
No money moves. Do not install or use AgentDash. Do not invent success states.
It is not mainnet, court-grade, consensus-secure, trustless, production-ready,
or multi-validator. Every protocol and verdict artifact preserves paymentMoved: false.

Runner local state is not operator authorization. For a session that the fresh
aggregate verifier marks `AUTHORIZED`, the verified evidence establishes that
Iris reconstructed Billy's canonical proposal from the signed amount options
and anchored digest. The protocol does not download message bytes from Clockchain.

Only the operator's fresh aggregate-verifier process may issue the final
`AUTHORIZED` verdict after independently refetching all three Clockchain
anchors. Billy's local `ACKNOWLEDGED`, Iris's local `ACCEPTED`, watcher output,
a submitted transaction, or a narrative is never that verdict.

## Automated primary flow

Role cards are fixed for the whole release:

- Stakeholder 1 — Iris — payee.
- Stakeholder 2 — Billy — payer.
- Operator — relay, coordinator, watcher, funding wallet, fresh aggregate verifier.

All three computers use Node.js 22, `npm ci --ignore-scripts`, and a clean
detached checkout of one reviewed 40-character SHA. Stop if any worktree is
dirty, if `git rev-parse HEAD` differs, if the relay IP is not reachable by both
role computers, or if any private input is missing, readable by the wrong user,
or delivered to the wrong role.

Use the existing stable public key pattern and a dated explicit key ID; do not
derive the key ID from the release SHA.

```sh
export OPERATOR_KEY_ID="bilateral-demo-2026-07-28"
export OPERATOR_PRIVATE_KEY_FILE=".context/operator-keys/$OPERATOR_KEY_ID.ed25519.pem"
test -f "$OPERATOR_PRIVATE_KEY_FILE"
test -f "docs/operator-keys/$OPERATOR_KEY_ID.pub"
```

On this Mac, verify and reuse the existing matching committed operator key pair for this prepared release. For a demo-day rerun, do not run keygen against existing files.

Initial provisioning only, before the public-key commit:

```sh
node scripts/create-session.mjs keygen --key-id "$OPERATOR_KEY_ID"
```

Commit only `docs/operator-keys/$OPERATOR_KEY_ID.pub`. Review that public-key
commit, run `npm run verify`, then freeze `BILATERAL_REPOSITORY_SHA` from the
reviewed commit:

```sh
export BILATERAL_REPOSITORY_SHA="$(git rev-parse HEAD)"
printf '%s\n' "$BILATERAL_REPOSITORY_SHA" | grep -Eq '^[0-9a-f]{40}$'

export REPOSITORY_ROOT="$(pwd)"
export BILATERAL_OPERATOR_ROOT="$HOME/.clockchain/bilateral/$BILATERAL_REPOSITORY_SHA"
export BILATERAL_RELEASE_ROOT="$BILATERAL_OPERATOR_ROOT/release"
mkdir -p "$BILATERAL_OPERATOR_ROOT" "$BILATERAL_RELEASE_ROOT" "$BILATERAL_RELEASE_ROOT/relay-state"
chmod 0700 "$BILATERAL_OPERATOR_ROOT" "$BILATERAL_RELEASE_ROOT"
chmod 0700 "$BILATERAL_RELEASE_ROOT/relay-state"

export SEPOLIA_RPC_URL_FILE="$REPOSITORY_ROOT/.context/bilateral-live-2026-07-28/sepolia-rpc.url"
test -f "$SEPOLIA_RPC_URL_FILE"
test -s "$SEPOLIA_RPC_URL_FILE"
test "$(stat -f '%Lp' "$SEPOLIA_RPC_URL_FILE")" = "600"

export SEPOLIA_TREASURY_KEYSTORE="$REPOSITORY_ROOT/.context/sepolia-funding/funding-wallet.json"
export SEPOLIA_TREASURY_PUBLIC_METADATA="$REPOSITORY_ROOT/.context/sepolia-funding/funding-wallet.public.json"
test -f "$SEPOLIA_TREASURY_KEYSTORE"
test -f "$SEPOLIA_TREASURY_PUBLIC_METADATA"
test "$(stat -f '%Lp' "$SEPOLIA_TREASURY_KEYSTORE")" = "600"
test "$(stat -f '%Lp' "$SEPOLIA_TREASURY_PUBLIC_METADATA")" = "600"

export OPERATOR_CLOCKCHAIN_TOKEN_FILE="$BILATERAL_OPERATOR_ROOT/operator.clockchain-token"
node scripts/mint-bilateral-token.mjs \
  --role operator \
  --output "$OPERATOR_CLOCKCHAIN_TOKEN_FILE" \
  --repository-sha "$BILATERAL_REPOSITORY_SHA"
```

The Sepolia RPC endpoint is the already prepared repo-private `$REPOSITORY_ROOT/.context/bilateral-live-2026-07-28/sepolia-rpc.url`; it must be a regular nonempty mode-`0600` file. Do not rewrite it from ambient `SEPOLIA_RPC_URL`.

The treasury keystore and adjacent public metadata are strict private files:
`.context/sepolia-funding/funding-wallet.json` and
`.context/sepolia-funding/funding-wallet.public.json` both stay mode `0600`,
under the repo-root absolute path derived from `pwd`, and out of Git.

Choose one advertised numeric relay endpoint for the two role computers.
`RELAY_ADVERTISED_IP` must be a numeric IP reachable by both role computers;
127.0.0.1 must not be the advertised relay address. The relay process may bind
that advertised interface or, when the host firewall is constrained,
`RELAY_LISTEN_HOST=0.0.0.0` as an explicitly documented all-interface bind.
The TLS certificate subject alternative name must contain the exact advertised
IP, and the coordinator must pin the matching certificate fingerprint:

```sh
export RELAY_ADVERTISED_IP="192.0.2.10"
export RELAY_PORT="8443"
export RELAY_URL="https://$RELAY_ADVERTISED_IP:$RELAY_PORT"
export RELAY_TLS_CERTIFICATE="$BILATERAL_RELEASE_ROOT/relay.crt"
export RELAY_TLS_PRIVATE_KEY="$BILATERAL_RELEASE_ROOT/relay.key"

openssl req -x509 -newkey rsa:3072 -nodes \
  -keyout "$RELAY_TLS_PRIVATE_KEY" \
  -out "$RELAY_TLS_CERTIFICATE" \
  -subj "/CN=$RELAY_ADVERTISED_IP" \
  -addext "subjectAltName=IP:$RELAY_ADVERTISED_IP" \
  -days 1
chmod 0600 "$RELAY_TLS_PRIVATE_KEY"
RELAY_TLS_FINGERPRINT="$(openssl x509 -in "$RELAY_TLS_CERTIFICATE" -outform DER | openssl dgst -sha256 -binary | xxd -p -c 256)"
```

Start the relay and coordinator from the operator Mac in separate terminals.
Keep both processes attached and stop on any nonzero exit.

Terminal 1 - relay:

```sh
npm run bilateral:relay -- \
  --host "${RELAY_LISTEN_HOST:-$RELAY_ADVERTISED_IP}" \
  --port "$RELAY_PORT" \
  --repository-sha "$BILATERAL_REPOSITORY_SHA" \
  --state "$BILATERAL_RELEASE_ROOT/relay-state" \
  --tls-certificate "$RELAY_TLS_CERTIFICATE" \
  --tls-private-key "$RELAY_TLS_PRIVATE_KEY"
```

Start Terminal 2 only after Terminal 1 prints relay readiness with the expected
host, port, repository SHA, and `paymentMoved: false`.

Terminal 2 - coordinator:

```sh
npm run bilateral:coordinator -- \
  --clockchain-token-file "$OPERATOR_CLOCKCHAIN_TOKEN_FILE" \
  --operator-key-id "$OPERATOR_KEY_ID" \
  --operator-private-key "$OPERATOR_PRIVATE_KEY_FILE" \
  --release-root "$BILATERAL_RELEASE_ROOT" \
  --relay-url "https://$RELAY_ADVERTISED_IP:$RELAY_PORT" \
  --repository-sha "$BILATERAL_REPOSITORY_SHA" \
  --rpc-url-file "$SEPOLIA_RPC_URL_FILE" \
  --tls-certificate "$RELAY_TLS_CERTIFICATE" \
  --tls-fingerprint "$RELAY_TLS_FINGERPRINT"
```

The coordinator publishes two private launch manifests under the release root.
Launch manifests expire after 60 minutes. Privately transfer payee.launch.json only to Iris and payer.launch.json only to Billy through separate private
channels; never transfer the other role's manifest, an invitation, a token, a
private key, the Sepolia RPC URL, or the treasury keystore. Each role machine
uses its prompt, one manifest, one private state directory, and the same clean
detached checkout of the reviewed 40-character SHA.

The user has exactly two kinds of demo-day action:

1. Start exactly two supervisor sessions—Billy once with the payer launch
   manifest and Iris once with the payee launch manifest.
2. Fund the four displayed addresses with the reusable Sepolia treasury command.

Billy machine:

```sh
npm run bilateral:supervisor -- \
  --launch-manifest "$BILLY_LAUNCH_MANIFEST" \
  --state "$BILLY_SUPERVISOR_STATE"
```

Iris machine:

```sh
npm run bilateral:supervisor -- \
  --launch-manifest "$IRIS_LAUNCH_MANIFEST" \
  --state "$IRIS_SUPERVISOR_STATE"
```

The same Billy and Iris processes remain alive across both runs. Each supervisor
creates two invitations and one token per role for both runs. After both
authenticated enrollments, the coordinator displays exactly four signed public
addresses and continuously checks their balances and nonce-zero status; there
is no human “funding complete” signal.

Use the coordinator-owned `$BILATERAL_RELEASE_ROOT/funding-addresses.json` file
directly; do not copy or rewrite the funding record. Save the coordinator-owned `$BILATERAL_RELEASE_ROOT/funding-addresses.json` as the mode-`0600` record file for the funding command, then run one treasury funding batch:

```sh
export FUNDING_RECORD_FILE="$BILATERAL_RELEASE_ROOT/funding-addresses.json"
export FUNDING_JOURNAL_DIR="$BILATERAL_OPERATOR_ROOT/funding-journal"

npm run bilateral:fund -- \
  --funding-record "$FUNDING_RECORD_FILE" \
  --journal-directory "$FUNDING_JOURNAL_DIR" \
  --keystore "$SEPOLIA_TREASURY_KEYSTORE" \
  --rpc-url-file "$SEPOLIA_RPC_URL_FILE"
```

0.05 Sepolia ETH covers four `0.01 ETH` allocations plus ordinary treasury
transfer gas for one clean rehearsal-plus-stakeholder release. The demo transactions spend gas from participant balances but never move the represented USD payment, so every protocol and verdict artifact remains `paymentMoved: false`. A second `0.05` drip is a recovery reserve because an ambiguous or
consumed invitation cannot be reused. Fresh invitations and a newly reviewed release are required after an unrecoverable write.

The coordinator then runs one signed physical-machine preflight for both runs,
registers the rehearsal identities, creates the signed USD 100 descriptor,
starts Iris before Billy, collects both marker-complete role packages, and
launches a fresh aggregate verifier. Accept `AUTHORIZED` only from each fresh aggregate verifier. An exact rehearsal verifier pass unlocks the stakeholder
run, which uses fresh registration, descriptor, result, and verdict directories
but the same supervisor keys, tokens, preflight, prompts, release, and
repository SHA. The coordinator completes rehearsal before it starts the
stakeholder run; any attempt to overlap the runs stops the release.

Physical separation is attested by the operator, not cryptographically proven.
Any code or prompt change after preflight aborts the release. Any SHA, key,
token, invitation, descriptor, output-path, event-chain, or evidence mismatch
also aborts it.
Relay, coordinator, watcher, and supervisor states are coordination only. They
never replace independent verification of exactly three ordered Clockchain
anchors, and `paymentMoved: false` remains invariant.

## Operator-authorized recovery appendix

The remainder of this document retains low-level preparation, artifact
transfer, and same-input recovery commands for a diagnosed failure. It is not
the primary happy path. Never use it to add human phase signals, create a fourth
role session, or bypass the two-supervisor workflow.

## Authority boundary

User/operator-only actions are funding the four public addresses, custody and
private delivery of secret files, attesting that credentials and physical
machines are separate, publishing the immutable repository SHA, synchronized
start, artifact transfer, and authorizing a same-directory recovery. Billy and
Iris agents may perform metadata-only path checks and invoke only their exact
preparation and timed-role commands. They must not inspect secret bytes, fund
wallets, attest separation, run the aggregate verifier, or improvise recovery.

Sol owns release review, shared-file coordination, repository publication, and
the final verdict. Run every deterministic check before live preparation. No
live Clockchain or Sepolia write is evidence of protocol success by itself.

## Phase -3: operator key and immutable release

Generate one Ed25519 operator key before freezing the live release:

```sh
node scripts/create-session.mjs keygen --key-id "$OPERATOR_KEY_ID"
```

The command writes the private key only under
`.context/operator-keys/$OPERATOR_KEY_ID.ed25519.pem` and the public key under
`docs/operator-keys/$OPERATOR_KEY_ID.pub`. Commit only the public file. Never
commit, print, paste, or transfer the private key outside the operator's private
channel.

Review that commit, run `npm run verify`, and record its exact 40-character
lowercase SHA as `BILATERAL_REPOSITORY_SHA`. The public operator key must exist
at that exact Git object. Both role machines and the operator machine use a
clean detached checkout of that SHA, Node.js 22, and
`npm ci --ignore-scripts`. Abort on any SHA, dependency, test, or worktree
difference. Never substitute a branch, tag, abbreviated revision, or newer
commit.

Assign roles once:

- Billy machine: payer.
- Iris machine: payee.
- Operator machine: preparation, read-only watcher, artifact custody, and
  fresh aggregate verification.

Use the official ERC-8004 Identity Registry at
`0x8004A818BFB912233c491871b3d84c89A494BD9e`.

## Phase -2: four funded addresses, invitations, and operator funding gate

Create exactly four distinct single-run invitations in canonically separate
public and secret directories:

```sh
node scripts/create-invitations.mjs \
  --output-public "$INVITATION_PUBLIC_DIR" \
  --output-secret "$INVITATION_SECRET_DIR" \
  --ids "billy-rehearsal,iris-rehearsal,billy-stakeholder,iris-stakeholder" \
  --names "Billy Rehearsal,Iris Rehearsal,Billy Stakeholder,Iris Stakeholder"
```

The JSON report contains only the four public addresses. Secret
`*.secret.json` files are mode `0600`; public `*.enc.json` files contain no
decryption code. Do not use `--force`. Do not open a secret invitation with an
agent or general-purpose tool.

The user/operator funds each public address with 0.005 through 0.02 Sepolia ETH
inclusive. Before registration, require nonce zero and the funded balance
inside that band. Registration intentionally consumes the nonce. Stop until all
four addresses are funded:

1. Billy rehearsal.
2. Iris rehearsal.
3. Billy stakeholder.
4. Iris stakeholder.

Each invitation contains the one role signing key for its reserved run. The
approved registration CLI and later timed role may open that same invitation
during that one lifecycle. It is never copied into a second raw-key file and is
never reused for a different attempt after any transaction or ambiguous write.

After funding, publish the immutable reviewed SHA and start one agent session
on each physical role machine with its machine prompt and private inputs.

## Phase -1: distributed two-client rendezvous

The operator prepares one signed public plan and two ephemeral participant
keys:

```sh
node scripts/probe-bilateral-rendezvous.mjs prepare \
  --operator-private-key "$OPERATOR_PRIVATE_KEY_FILE" \
  --operator-key-id "$OPERATOR_KEY_ID" \
  --repository-sha "$BILATERAL_REPOSITORY_SHA" \
  --output "$PREFLIGHT_PREP_DIR"
```

This creates `probe-plan.json`, `payer-participant.ed25519.pem`, and
`payee-participant.ed25519.pem`. Deliver the same plan and only the matching
participant key to each physical machine through a separate private channel.

Mint one role token on each role machine and one dedicated operator token. The
operator uses its token only for watcher and verifier reads; the minting API does
not prove a capability-level read-only scope. Each output path and its intent
marker must be absent, and each parent directory must be mode `0700`.

Billy machine:

```sh
node scripts/mint-bilateral-token.mjs \
  --role payer \
  --output "$BILLY_CLOCKCHAIN_TOKEN_FILE" \
  --repository-sha "$BILATERAL_REPOSITORY_SHA"
```

Iris machine:

```sh
node scripts/mint-bilateral-token.mjs \
  --role payee \
  --output "$IRIS_CLOCKCHAIN_TOKEN_FILE" \
  --repository-sha "$BILATERAL_REPOSITORY_SHA"
```

Operator machine:

```sh
node scripts/mint-bilateral-token.mjs \
  --role operator \
  --output "$OPERATOR_CLOCKCHAIN_TOKEN_FILE" \
  --repository-sha "$BILATERAL_REPOSITORY_SHA"
```

Do not rerun a token mint after its durable intent exists. An interrupted mint
is ambiguous and requires a new reviewed release plan, not another token call.

Run one participant process on each physical machine. These are the only two
pre-approved throwaway writes.

Billy machine:

```sh
node scripts/probe-bilateral-rendezvous.mjs participant \
  --role payer \
  --plan "$PREFLIGHT_PLAN_FILE" \
  --token-file "$BILLY_CLOCKCHAIN_TOKEN_FILE" \
  --participant-private-key "$BILLY_PREFLIGHT_PRIVATE_KEY_FILE" \
  --output "$BILLY_PREFLIGHT_RESULT_DIR"
```

Iris machine:

```sh
node scripts/probe-bilateral-rendezvous.mjs participant \
  --role payee \
  --plan "$PREFLIGHT_PLAN_FILE" \
  --token-file "$IRIS_CLOCKCHAIN_TOKEN_FILE" \
  --participant-private-key "$IRIS_PREFLIGHT_PRIVATE_KEY_FILE" \
  --output "$IRIS_PREFLIGHT_RESULT_DIR"
```

Each role sends its marker-complete `participant-report.json` directory to the
operator. The operator alone runs:

```sh
node scripts/probe-bilateral-rendezvous.mjs aggregate \
  --plan "$PREFLIGHT_PLAN_FILE" \
  --payer-report-dir "$BILLY_PREFLIGHT_RESULT_DIR" \
  --payee-report-dir "$IRIS_PREFLIGHT_RESULT_DIR" \
  --operator-private-key "$OPERATOR_PRIVATE_KEY_FILE" \
  --output "$PREFLIGHT_AGGREGATE_DIR" \
  --attest-separate-credentials \
  --attest-separate-machines
```

Set the attestation flags only after the operator personally verifies distinct
credentials and two physical machines. Continue only when the marker-complete
aggregate report says `RENDEZVOUS_OK` with the derived-reference channel and the
process exits zero. Digest-only, mixed, asymmetric, unattested, malformed, or
unavailable discovery fails closed. Never repeat the two-write probe.

The same per-machine Clockchain token used for preflight is reused unchanged by
that machine's timed role. Do not mint a replacement token between phases.

## Phase 0: registration and signed descriptor

Registration happens before the descriptor is created and before timed M1.
Each role machine runs its approved registration command.

Billy machine:

```sh
node scripts/register-bilateral-identity.mjs \
  --invitation "$BILLY_INVITATION_FILE" \
  --output "$BILLY_REGISTRATION_DIR" \
  --repository-sha "$BILATERAL_REPOSITORY_SHA" \
  --i-understand-this-writes-to-sepolia
```

Iris machine:

```sh
node scripts/register-bilateral-identity.mjs \
  --invitation "$IRIS_INVITATION_FILE" \
  --output "$IRIS_REGISTRATION_DIR" \
  --repository-sha "$BILATERAL_REPOSITORY_SHA" \
  --i-understand-this-writes-to-sepolia
```

Each command must publish `identity.json` and `.identity.complete.json`.
Registration is crash-recoverable only with the exact invitation, repository
SHA, command, and output directory. Never delete or edit
`registration-checkpoint.json`; never choose a new directory after a possible
transaction.

Transfer only the marker-complete, secret-free identity directories to the
operator. Record the address, agent ID, and display name from each verified
artifact. Do not transfer invitations or tokens.

Compute the prompt-bundle digest from the exact committed Billy and Iris prompt
bytes:

```sh
BILATERAL_PROMPT_SHA256="$(node scripts/hash-bilateral-prompts.mjs --repository-sha "$BILATERAL_REPOSITORY_SHA")"
```

Create one descriptor for exactly USD 100:

```sh
node scripts/create-session.mjs create \
  --amounts "USD:100" \
  --key-id "$OPERATOR_KEY_ID" \
  --output "$BILATERAL_DESCRIPTOR_FILE" \
  --payee-address "$IRIS_ADDRESS" \
  --payee-agent-id "$IRIS_AGENT_ID" \
  --payee-name "$IRIS_DISPLAY_NAME" \
  --payer-address "$BILLY_ADDRESS" \
  --payer-agent-id "$BILLY_AGENT_ID" \
  --payer-name "$BILLY_DISPLAY_NAME" \
  --prompt-sha256 "$BILATERAL_PROMPT_SHA256" \
  --repository-sha "$BILATERAL_REPOSITORY_SHA"
```

Distribute the identical signed descriptor bytes to Billy, Iris, the watcher,
and the verifier. Compare the descriptor digest on all three machines. The
descriptor, identities, role assignment, amount, prompt bundle, and repository
SHA are immutable for that session.

## Phase 1: watcher and synchronized timed start

Start the read-only watcher on the operator machine:

```sh
node scripts/watch-bilateral-session.mjs \
  --descriptor-file "$BILATERAL_DESCRIPTOR_FILE" \
  --token-file "$OPERATOR_CLOCKCHAIN_TOKEN_FILE"
```

Watcher JSON lines are advisory. They may display derived keys, cardinality,
verified block heights/times, deadline, and non-authorizing runner states.
Health, cached timestamps, and record status are disclosure only. The watcher
never writes or authorizes.

Confirm the same UTC clock, descriptor digest, and clean immutable checkout.
For the synchronized start, start Iris first so she polls for the exact
proposal, then start Billy immediately.

Billy machine:

```sh
node bin/handshake-propose.mjs \
  --descriptor "$BILATERAL_DESCRIPTOR_FILE" \
  --invitation "$BILLY_INVITATION_FILE" \
  --clockchain-token-file "$BILLY_CLOCKCHAIN_TOKEN_FILE" \
  --output "$BILLY_RESULT_DIR" \
  --i-understand-this-writes-to-clockchain
```

Iris machine:

```sh
node bin/handshake-accept.mjs \
  --descriptor "$BILATERAL_DESCRIPTOR_FILE" \
  --invitation "$IRIS_INVITATION_FILE" \
  --clockchain-token-file "$IRIS_CLOCKCHAIN_TOKEN_FILE" \
  --output "$IRIS_RESULT_DIR" \
  --i-understand-this-writes-to-clockchain
```

Fresh role result paths may be absent or empty owner-controlled mode-`0700`
directories. Do not alter arguments, run a second writer, or manually advance a
state. Expected local endpoints are Billy `ACKNOWLEDGED` and Iris `ACCEPTED`;
neither is authorization.

## Phase 2: artifact transfer

Each role must publish exactly:

- `party-result.json`
- `PARTY-RESULT.md`
- `.party-result.complete.json`

Stop if the completion marker is absent. Transfer each whole result directory
through an authenticated private channel. Keep Billy and Iris separate. Record
and compare SHA-256 inventories before and after transfer. Never edit, rename,
regenerate, or merge files. Do not transfer invitations, participant keys,
tokens, checkpoints, secret canaries, or partial temporary files.

## Phase 3: fresh aggregate verifier

Close any earlier verifier process. In a clean checkout whose HEAD equals the
descriptor repository SHA, use an independent Sepolia RPC endpoint and a fresh
nonexistent verifier output directory:

```sh
node scripts/verify-bilateral-results.mjs \
  --clockchain-token-file "$OPERATOR_CLOCKCHAIN_TOKEN_FILE" \
  --descriptor "$BILATERAL_DESCRIPTOR_FILE" \
  --output "$VERDICT_OUTPUT_DIR" \
  --payee-results "$IRIS_TRANSFERRED_RESULT_DIR" \
  --payer-results "$BILLY_TRANSFERRED_RESULT_DIR" \
  --rpc-url "$SEPOLIA_RPC_URL"
```

The verifier loads only marker-complete packages, validates both signatures and
descriptor bindings, independently refetches the proposed, accepted, and
acknowledged anchors, enforces order and deadline, and requires
`paymentMoved: false`. It publishes:

- `bilateral-verdict.json`
- `BILATERAL-VERDICT.md`
- `.bilateral-verdict.complete.json`

The hashed completion marker is published last. A session succeeds only when
this fresh process emits exact `AUTHORIZED` and all three artifacts agree.
Every other outcome is fixed non-authorization evidence.

## Recovery rules

- Before any write, correct local checkout, install, or path problems and rerun
  metadata-only checks.
- After token-mint intent, preflight intent, registration intent, or protocol
  intent exists, never switch credentials, descriptor, token, or output
  directory.
- A role agent stops immediately on ambiguity and preserves the entire
  directory. Only the operator may authorize rerunning the exact same command
  in the exact same directory.
- Registration recovery reuses its validated checkpoint. Timed-role recovery is
  discovery-first and may adopt only one exact anchor; it never blindly
  redispatches an unresolved write.
- Never rerun a marker-complete registration or role package as recovery.
- If a unique exact anchor cannot be proved, abandon the session.
- A failed rehearsal consumes its attempted invitations. Correct code through
  tests, review, and a new immutable SHA; use a newly reserved pair.
- Never hand-edit evidence or downgrade a verifier failure.

## Abort conditions

Abort on missing, duplicated, reordered, expired, malformed, mismatched,
secret-bearing, or marker-incomplete evidence; an ambiguous anchor; any
role/owner/amount/session/predecessor/digest/height/timestamp mismatch; invalid
signature; dirty/wrong checkout; private value in public output; advisory field
used as authority; runner/watcher authorizing output; or any `paymentMoved`
value other than exactly `false`.

On abort, stop writers, preserve sanitized evidence, record only the public
failure code and stage, and do not improvise success or reuse a consumed
invitation.

## Rehearsal and stakeholder sequence

Run the full two-machine flow once with the rehearsal pair. Transfer both
packages and verify from a fresh operator process. Correct deterministic or
operational defects through tests, review, repeated verification, and a new
immutable SHA. Only after a clean rehearsal may the operator start the two
stakeholder agent sessions with the reserved stakeholder pair and repeat every
gate without shortcuts.
