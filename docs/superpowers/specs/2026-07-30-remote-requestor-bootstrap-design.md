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

The first operator-approved Requestor claims the single armed stakeholder slot.
Unapproved public callers may create bounded pending claims but cannot receive
role material, reorder anchors, act as Payer, move payment, or make the verifier
authorize invalid evidence.

### Public sealed-bootstrap route

The Payer TLS service adds a separate, explicitly armed `/bootstrap` route
before the existing authenticated MCP lifecycle. The Requestor supplies a fresh
X25519 public key and claim nonce. The matching private key stays only in the
Requestor's private bootstrap root.

The existing bearer-authenticated `request_payment` tool, exact commercial
intake schema, intake digest, `HANDSHAKE_REQUIRED` result, and supervisor start
remain unchanged. After opening the sealed manifest, the Requestor uses its
recovered Requestor-only MCP intake capability for the existing MCP call.

### Operator bootstrap broker

An operator-owned loopback broker is started with the fresh
`payee.launch.json`. The broker is not internet-facing. The Payer MCP reaches it
through an operator-created one-time local broker capability.

For a pending claim, the broker:

1. validates the exact claim nonce, reviewed SHA, and Requestor X25519 public
   key;
2. records the pending claim and its public-key fingerprint for operator
   approval;
3. requires operator approval bound to that exact fingerprint;
4. reads the bounded private payee launch manifest without returning plaintext
   to the Payer process;
5. encrypts the manifest with X25519 shared-secret derivation,
   HKDF-SHA256, and AES-256-GCM;
6. binds repository SHA, claim nonce, release ID, session ID, and
   `paymentMoved:false` as authenticated additional data;
7. signs the exact envelope and context with the reviewed operator key;
8. journals the exact ciphertext before returning it; and
9. returns identical ciphertext only for an identical retry.

A different key, nonce, session, repository SHA, duplicate claim, expired
manifest, or malformed input fails closed. The Payer transports only the sealed
bundle and cannot decrypt it.

### Requestor wrapper

`bilateral:request-payment` no longer accepts a launch-manifest path or an MCP
bearer capability from the stakeholder. It:

1. creates a new private Requestor state root;
2. generates and durably pins a fresh X25519 keypair;
3. obtains and verifies an operator-signed discovery document containing the
   current public Payer URL, public certificate URL, certificate fingerprint,
   reviewed SHA, release/session scope, and expiry;
4. submits the public sealed-bootstrap claim and waits while the operator
   approves the displayed Requestor-key fingerprint;
5. verifies the operator signature and decrypts the sealed bootstrap bundle;
6. writes the recovered launch manifest as a mode-`0600` private file inside a
   sibling mode-`0700` bootstrap root;
7. validates the manifest against the reviewed checkout and signed discovery;
8. performs the existing bearer-authenticated MCP call;
9. requires exact `HANDSHAKE_REQUIRED`; and
10. starts the existing Requestor supervisor exactly once.

The private key, decrypted manifest, and capability bytes are never written to
stdout. Existing supervisor retirement removes the recovered manifest after
successful bootstrap.

### Public discovery

The operator publishes a separate signed discovery document with only these
public fields:

- reviewed release SHA;
- release/session scope and expiry;
- Payer MCP public URL;
- public certificate download URL; and
- lowercase SHA-256 certificate fingerprint; and
- reviewed operator key ID and signature.

The public certificate is uploaded separately with `public-read` semantics; it
contains no secret. The Payer TLS private key remains only on the Payer machine.
The Requestor verifies the discovery signature against
`docs/operator-keys/<operatorKeyId>.pub` in the reviewed checkout before using
any discovered network value. The advisory public monitor remains advisory and
is not a trust root. No session-specific private value is embedded in the site.

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
- A public caller can submit a pending claim but cannot receive the sealed
  manifest until the operator approves the exact Requestor-key fingerprint.
- The operator compares that fingerprint with the value displayed by the
  stakeholder's agent. This is a pairing confirmation, not a second prompt,
  attachment, private file transfer, or authority verdict.

## Operator and Stakeholder Experience

The operator starts relay, coordinator, console, public monitor, signed
discovery publisher, bootstrap broker, Payer tunnel, and Payer supervisor. Once
the public monitor reports `PAYER_MCP_READY`, the stakeholder pastes the one
public prompt. The Requestor agent displays a short public-key fingerprint while
it waits; the operator approves that exact fingerprint locally.

The stakeholder does not attach a manifest or certificate, enter a fingerprint,
copy a local path, run funding, or paste a second command. Their agent remains
attached until `PARTY_COMPLETE`.

## Verification

Focused tests must prove:

- the public bootstrap claim succeeds without a bearer only after exact
  operator approval and remains exactly once;
- the separate `/bootstrap` claim never changes the existing authenticated MCP
  intake or result schema;
- hostile or reordered MCP calls fail;
- the broker never returns plaintext and identical retries return identical
  ciphertext;
- cross-key, cross-claim, expired, malformed, replayed, and tampered bundles
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
