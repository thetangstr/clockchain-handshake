# Remote Requestor Bootstrap Design

## Outcome

A stakeholder on any macOS, Windows, or Linux computer opens the public
Handshake run page, pastes one Requestor prompt into a local Codex, Claude Code,
or Hermes agent, and performs no private file transfer. The agent calls the
public Payer MCP, receives exact `HANDSHAKE_REQUIRED`, installs its own
role-scoped bootstrap material privately, and continues through the existing
Requestor supervisor.

The public page, prompt, MCP response, public monitor, and agent transcript never
contain a plaintext launch manifest, bootstrap capability, invitation, token,
private key, or live evidence.

## Current Defect

The reviewed release requires `payee.launch.json` before
`bilateral:request-payment` can make the first MCP call. The public run page
therefore cannot be used independently by a remote stakeholder. Replacing an
attachment with a local path only hides the same manual handoff and does not fix
the product.

## Selected Architecture

The first valid Requestor claims the single armed stakeholder slot. This is a
demo availability boundary, not authorization: a caller may consume the slot,
but cannot reorder anchors, act as Payer, move payment, or make the verifier
authorize invalid evidence.

### Public Payer MCP intake

The Payer MCP accepts one canonical `request_payment` call without a pre-shared
bearer capability after the operator arms a fresh session. It retains the
existing strict MCP session ordering, rate limiting, canonical payment terms,
exactly-once intake persistence, reviewed repository SHA binding, and
`paymentMoved:false`.

The Requestor supplies a fresh X25519 public key in the canonical payment intake.
The matching private key stays only in the Requestor's private state root.

### Operator bootstrap broker

An operator-owned loopback broker is started with the fresh
`payee.launch.json`. The broker is not internet-facing. The Payer MCP reaches it
through an operator-created one-time local broker capability.

For the first valid intake, the broker:

1. validates the exact intake ID, reviewed SHA, Payer MCP request, and Requestor
   X25519 public key;
2. reads the bounded private payee launch manifest without returning plaintext
   to the Payer process;
3. encrypts the manifest with X25519 shared-secret derivation,
   HKDF-SHA256, and AES-256-GCM;
4. binds repository SHA, intake ID, release ID, session ID, and
   `paymentMoved:false` as authenticated additional data;
5. journals the exact ciphertext before returning it; and
6. returns identical ciphertext only for an identical retry.

A different key, intake ID, session, repository SHA, duplicate claim, expired
manifest, or malformed input fails closed. The Payer transports only the sealed
bundle and cannot decrypt it.

### Requestor wrapper

`bilateral:request-payment` no longer accepts a launch-manifest path or an MCP
bearer capability from the stakeholder. It:

1. creates a new private Requestor state root;
2. generates and durably pins a fresh X25519 keypair;
3. obtains the current public Payer MCP URL, public certificate, certificate
   fingerprint, and reviewed SHA from the secret-free public monitor;
4. performs the canonical MCP call;
5. requires exact `HANDSHAKE_REQUIRED`;
6. verifies and decrypts the sealed bootstrap bundle;
7. writes the recovered launch manifest as a mode-`0600` private file inside
   the Requestor state root;
8. validates the manifest against the reviewed checkout and MCP intake; and
9. starts the existing Requestor supervisor exactly once.

The private key, decrypted manifest, and capability bytes are never written to
stdout. Existing supervisor retirement removes the recovered manifest after
successful bootstrap.

### Public discovery

The public monitor adds only these public fields:

- reviewed release SHA;
- Payer MCP public URL;
- public certificate download URL; and
- lowercase SHA-256 certificate fingerprint.

The public certificate is uploaded separately with `public-read` semantics; it
contains no secret. The Payer TLS private key remains only on the Payer machine.
The run-page prompt tells the agent to fetch and validate this live discovery
record. No session-specific private value is embedded in the site.

## Authority and Failure Semantics

- The bootstrap broker grants only the Requestor role for the armed session.
- Payer continues to own `PROPOSED` and `ACKNOWLEDGED`.
- Requestor continues to own `ACCEPTED`.
- Only the fresh aggregate verifier may output `AUTHORIZED`.
- The operator console and public monitor remain advisory.
- Exactly three independently verifiable Clockchain anchors remain required.
- Every artifact and status preserves `paymentMoved:false`.
- Missing, duplicate, reordered, expired, malformed, mismatched, replayed, or
  undecryptable bootstrap evidence fails closed.
- A public caller can consume the single demo slot and cause a safe availability
  failure. With no stakeholder credential or private input, the system cannot
  identify a particular human before first contact. It must never convert this
  limitation into weaker protocol authority.

## Operator and Stakeholder Experience

The operator starts relay, coordinator, console, public monitor, bootstrap
broker, Payer tunnel, and Payer supervisor. Once the public monitor reports
`PAYER_MCP_READY`, the stakeholder pastes the one public prompt.

The stakeholder does not attach a manifest or certificate, enter a fingerprint,
copy a local path, run funding, or paste a second command. Their agent remains
attached until `PARTY_COMPLETE`.

## Verification

Focused tests must prove:

- public intake succeeds without a bearer and remains exactly once;
- hostile or reordered MCP calls fail;
- the broker never returns plaintext and identical retries return identical
  ciphertext;
- cross-key, cross-intake, expired, malformed, replayed, and tampered bundles
  fail;
- the wrapper creates private state, decrypts locally, validates the manifest,
  emits only the fixed secret-free `HANDSHAKE_REQUIRED` line, and starts one
  supervisor;
- the monitor publishes only public discovery material;
- the public run page contains one Requestor prompt and no attachment, manifest
  path, certificate attachment, or second-prompt instruction; and
- a deterministic multiprocess run still produces exactly
  `PROPOSED -> ACCEPTED -> ACKNOWLEDGED`, fresh `AUTHORIZED`, and
  `paymentMoved:false`.

The complete suite remains the final release gate. During implementation, only
focused tests run.
