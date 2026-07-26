# Bilateral Coordination Relay Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use
> `superpowers:subagent-driven-development` (recommended) or
> `superpowers:executing-plans` to implement this plan task-by-task. Steps use
> checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add the authenticated coordination layer that lets one Billy
supervisor and one Iris supervisor complete both the rehearsal and stakeholder
USD 100 authorization runs while the user does only two things: start the two
role sessions and fund the four displayed addresses.

**Architecture:** A Node.js 22 HTTPS relay persists a signed, append-only
mailbox and secret-free content-addressed artifacts without becoming protocol
authority. Two long-lived role supervisors retain all role secrets locally and
execute an exact command allowlist, while a separate operator coordinator
drives funding, preflight, identity registration, descriptors, the two live
runs, and fresh verifier children. Clockchain blocks remain the only
authoritative transition evidence, and the existing aggregate verifier remains
the only production source that may emit `AUTHORIZED`.

**Tech Stack:** Node.js 22 ES modules, `node:test`, Node built-ins
(`node:https`, `node:crypto`, `node:fs/promises`, `node:child_process`), the
existing `viem` dependency, the existing hardened MCP client, and the existing
deterministic fake Clockchain.

---

## Scope and execution contract

This plan implements the user-approved
`docs/superpowers/specs/2026-07-26-bilateral-coordination-relay-design.md`.
It does not change canonical M1/M2/M3 bytes, reference IDs, descriptor
semantics, the 600-second protocol window, identity proof rules, or the
aggregate-verdict trust path.

The following invariants apply to every task:

- `paymentMoved` is exactly `false` in every coordination event, protocol
  message, report, role package, and verdict.
- The relay, coordinator, supervisor, watcher, Billy, and Iris sources and
  runtime output must exclude the authorizing literal.
- The relay transports only signed public bytes. Raw tokens, RPC credentials,
  launch capabilities, invitation secrets, registration checkpoints, and
  private keys remain local.
- An ambiguous Clockchain or Sepolia write is never blindly retried.
- A relay retry is permitted only for byte-identical signed requests.
- Every behavior change follows RED -> GREEN -> refactor.
- No new runtime dependency is added.
- Each writer stages and commits only its assigned paths. Existing dirty Round 3
  work is preserved until Task 0 commits it deliberately.

## File and responsibility map

| Surface | Responsibility |
| --- | --- |
| `src/bilateral/coordination/envelope.mjs` | Canonical coordination events, signatures, sequence-chain validation |
| `src/bilateral/coordination/lifecycle.mjs` | Closed event vocabulary, authority rules, pure release-state reduction |
| `src/bilateral/coordination/artifact.mjs` | Artifact allowlist, size bounds, secret scanning, marker/package validation |
| `src/bilateral/coordination/storage.mjs` | Pinned private state root, capability consumption, append-only log, content-addressed bytes |
| `src/bilateral/coordination/relay.mjs` | Transport-independent bootstrap/event/artifact/session service |
| `src/bilateral/coordination/client.mjs` | Bounded HTTPS requests, TLS fingerprint pinning, idempotent signed requests |
| `src/bilateral/coordination/manifest.mjs` | Exact private launch-manifest schema and capability generation |
| `src/bilateral/coordination/preflight.mjs` | Role-local participant keys, token commitments, public enrollment artifacts |
| `src/bilateral/coordination/supervisor.mjs` | Long-lived payer/payee state machine and exact command policy |
| `src/bilateral/coordination/coordinator.mjs` | Operator workflow, funding polling, phase commands, verifier-child gating |
| `bin/handshake-relay.mjs` | Production TLS relay entrypoint |
| `bin/handshake-supervisor.mjs` | Shared Billy/Iris supervisor entrypoint |
| `bin/handshake-coordinator.mjs` | Operator coordinator entrypoint |
| `test/helpers/fake-bilateral-clockchain-service.mjs` | Persistent localhost façade over the deterministic fake |
| `test/helpers/bilateral-coordination-child.mjs` | Test-only child driver that injects fake adapters into real builders |
| `test/bilateral-coordination-*.test.mjs` | Focused and process-isolated coordination tests |

## Task 0: Freeze the current Round 3 operational baseline

**Files:**

- Modify and commit only the existing Round 3 paths already present in the
  worktree:
  `README.md`, `scripts/check-docs.mjs`, `src/bilateral/evidence.mjs`,
  `src/bilateral/protocol.mjs`, `test/bilateral-evidence.test.mjs`,
  `test/bilateral-protocol.test.mjs`, `test/docs.test.mjs`,
  `bin/handshake-accept.mjs`, `bin/handshake-propose.mjs`,
  `docs/runbooks/bilateral-demo-day.md`,
  `prompts/run-billy-bilateral-demo.md`,
  `prompts/run-iris-bilateral-demo.md`,
  `scripts/hash-bilateral-prompts.mjs`,
  `scripts/mint-bilateral-token.mjs`,
  `scripts/probe-bilateral-rendezvous.mjs`,
  `scripts/register-bilateral-identity.mjs`,
  `scripts/verify-bilateral-results.mjs`,
  `scripts/watch-bilateral-session.mjs`,
  `src/bilateral/roles.mjs`, `src/bilateral/runner.mjs`,
  `src/bilateral/verdict.mjs`, and their existing Round 3 tests.

- [ ] **Step 1: Inspect the exact baseline diff**

Run:

```bash
git status --short
git diff --check
git diff --stat
git diff -- README.md scripts src test prompts docs/runbooks
```

Expected: only the known Round 3 implementation and documentation paths appear;
no invitation, token, key, generated evidence, `.context`, or unrelated file is
included.

- [ ] **Step 2: Re-run the focused Round 3 suite**

Run:

```bash
node --test \
  test/bilateral-machine-prep.test.mjs \
  test/bilateral-preflight.test.mjs \
  test/bilateral-runner.test.mjs \
  test/bilateral-roles.test.mjs \
  test/bilateral-verdict.test.mjs \
  test/bilateral-watcher.test.mjs \
  test/bilateral-operational-e2e.test.mjs \
  test/docs.test.mjs
```

Expected: all tests pass with no skipped hostile-path row.

- [ ] **Step 3: Run one fresh full baseline verification**

Run:

```bash
npm run verify
```

Expected: the complete Node test suite and all documentation gates pass.

- [ ] **Step 4: Audit authorizing output and secret surface**

Run:

```bash
rg -n 'AUTHORIZED' --glob '!test/**' --glob '!docs/**' --glob '!README.md'
git diff --name-only | rg -n '(secret|private|token|invitation|evidence)'
```

Expected: the production authorizing literal appears only in the aggregate
verifier surface; the filename scan is manually reconciled to source code and
tests, never live artifacts.

- [ ] **Step 5: Commit the verified Round 3 baseline**

Stage the exact owned paths from Step 1 and commit:

```text
Make the bilateral demo executable without weakening verification

Constraint: Only the independent aggregate verifier may authorize and no code path moves payment.
Rejected: Manual evidence interpretation | it cannot meet the fail-closed or independently verifiable demo contract
Confidence: high
Scope-risk: broad
Directive: Preserve pinned output directories, marker-last publication, and authorizing-output exclusivity.
Tested: Focused Round 3 suite and fresh npm run verify
Not-tested: Live Clockchain writes, Sepolia registration, funding, and two-machine execution
```

## Task 1: Canonical coordination envelopes and signatures

**Files:**

- Create: `src/bilateral/coordination/envelope.mjs`
- Create: `test/bilateral-coordination-envelope.test.mjs`

- [ ] **Step 1: Write the failing happy-path and exact-shape tests**

Add tests that use fixed Ed25519 test keys and assert this public interface:

```js
import {
  COORDINATION_ENVELOPE_SCHEMA,
  createCoordinationEnvelope,
  eventDigest,
  verifyCoordinationEnvelope,
} from "../src/bilateral/coordination/envelope.mjs";

const event = createCoordinationEnvelope({
  artifactDigest: null,
  kind: "ENROLLMENT_CONFIRMED",
  paymentMoved: false,
  previousEventDigest: null,
  privateKeyPem,
  publicKey,
  publicKeyId: "payer-release-key",
  releaseId: "release-2026-07-26-a",
  repositorySha: "a".repeat(40),
  role: "payer",
  sequence: "0",
  sessionId: "8f953393-86d0-4f99-9d6a-102f525fbecd",
  subjectRun: "release",
});

assert.equal(event.schema, COORDINATION_ENVELOPE_SCHEMA);
assert.equal(event.paymentMoved, false);
assert.equal(event.eventDigest, eventDigest(event));
assert.deepEqual(
  verifyCoordinationEnvelope(event, {
    expectedPublicKey: publicKey,
    expectedReleaseId: "release-2026-07-26-a",
    expectedRepositorySha: "a".repeat(40),
    expectedRole: "payer",
    expectedSessionId: "8f953393-86d0-4f99-9d6a-102f525fbecd",
  }),
  event,
);
```

Add table tests that reject extra/missing/accessor/prototype keys, numbers,
noncanonical decimal sequences, wrong domains, wrong keys, `paymentMoved:true`,
wrong release/session/SHA/role/run, non-64-hex digests, signatures over a
different digest, and canonical envelopes larger than 64 KiB.

- [ ] **Step 2: Run the test and observe RED**

Run:

```bash
node --test test/bilateral-coordination-envelope.test.mjs
```

Expected: `ERR_MODULE_NOT_FOUND` for
`src/bilateral/coordination/envelope.mjs`.

- [ ] **Step 3: Implement the exact canonical envelope**

Implement these exports:

```js
export const COORDINATION_ENVELOPE_SCHEMA =
  "clockchain.bilateral-coordination-event/v1";
export const COORDINATION_SIGNATURE_DOMAIN =
  "clockchain.bilateral-coordination-signature/v1\n";
export const MAX_COORDINATION_ENVELOPE_BYTES = 65_536;

export function eventDigest(envelope) {
  const body = {
    artifactDigest: envelope.artifactDigest,
    kind: envelope.kind,
    paymentMoved: envelope.paymentMoved,
    previousEventDigest: envelope.previousEventDigest,
    releaseId: envelope.releaseId,
    repositorySha: envelope.repositorySha,
    role: envelope.role,
    schema: envelope.schema,
    sequence: envelope.sequence,
    sessionId: envelope.sessionId,
    subjectRun: envelope.subjectRun,
  };
  return createHash("sha256")
    .update(canonicalBytes(body))
    .digest("hex");
}

export function signaturePreimage(digest) {
  assertSha256(digest);
  return Buffer.concat([
    Buffer.from(COORDINATION_SIGNATURE_DOMAIN, "ascii"),
    Buffer.from(digest, "ascii"),
  ]);
}

```

Use `canonicalBytes` from `src/bilateral/canonical.mjs` and Node crypto only.
The `signature` object has exact keys
`algorithm`, `keyId`, `publicKey`, and `value`; `algorithm` is `ed25519`.
`createCoordinationEnvelope(input)` snapshots only the documented own data
properties, validates the closed role/run/kind enums, builds the exact body
shown in `eventDigest`, signs `signaturePreimage(digest)`, rejects a final
canonical byte length above 65,536, and returns a recursively frozen object.
`verifyCoordinationEnvelope(envelope, expected)` performs the same exact-key and
size validation, recomputes the digest, verifies the Ed25519 signature against
the envelope public key, requires every provided expected context field to
match byte-for-byte, and returns the recursively frozen envelope.

- [ ] **Step 4: Run the focused test and syntax check**

Run:

```bash
node --test test/bilateral-coordination-envelope.test.mjs
node --check src/bilateral/coordination/envelope.mjs
```

Expected: all envelope tests pass.

- [ ] **Step 5: Commit**

```text
Make every coordination statement independently attributable

Constraint: Coordination events may order work but may never replace Clockchain evidence.
Rejected: Unsigned relay JSON | it would let transport state impersonate either role
Confidence: high
Scope-risk: narrow
Directive: Keep eventDigest free of circular signature fields and preserve exact-key validation.
Tested: node --test test/bilateral-coordination-envelope.test.mjs; node --check src/bilateral/coordination/envelope.mjs
Not-tested: HTTPS transport and persistent replay handling
```

## Task 2: Closed lifecycle and authority reduction

**Files:**

- Create: `src/bilateral/coordination/lifecycle.mjs`
- Create: `test/bilateral-coordination-lifecycle.test.mjs`

- [ ] **Step 1: Write failing reducer and hostile-authority tests**

Pin the public vocabulary:

```js
import {
  COORDINATION_EVENT_AUTHORITIES,
  RELEASE_STATES,
  initialReleaseView,
  reduceReleaseEvent,
} from "../src/bilateral/coordination/lifecycle.mjs";

let view = initialReleaseView({
  releaseId: "release-a",
  repositorySha: "b".repeat(40),
  sessionId: "0352cfc8-5393-40d0-828f-61a457fcdd03",
});

view = reduceReleaseEvent(view, payerEnrollment);
view = reduceReleaseEvent(view, payeeEnrollment);
assert.equal(view.state, "ADDRESSES_READY");
assert.equal(
  COORDINATION_EVENT_AUTHORITIES.START_REHEARSAL,
  "operator",
);
assert.equal(RELEASE_STATES.at(-1), "ABORTED");
```

Add a complete valid event sequence through `COMPLETE`. Add one test per illegal
edge: wrong role for kind, run mismatch, start before both prerequisites,
stakeholder before rehearsal verifier pass, duplicate identity/role packages,
unknown kind, `paymentMoved:true`, any transition from `ABORTED`, and a
coordinator attempt to treat watcher/relay status as verification.

- [ ] **Step 2: Run RED**

Run:

```bash
node --test test/bilateral-coordination-lifecycle.test.mjs
```

Expected: missing lifecycle module.

- [ ] **Step 3: Implement the pure state machine**

Define the closed constants:

```js
export const RELEASE_STATES = Object.freeze([
  "BOOTSTRAPPING",
  "ADDRESSES_READY",
  "FUNDING_READY",
  "PREFLIGHT_READY",
  "PREFLIGHT_PASSED",
  "REHEARSAL_IDENTITIES_READY",
  "REHEARSAL_DESCRIPTOR_READY",
  "REHEARSAL_RUNNING",
  "REHEARSAL_VERIFIED",
  "STAKEHOLDER_IDENTITIES_READY",
  "STAKEHOLDER_DESCRIPTOR_READY",
  "STAKEHOLDER_RUNNING",
  "STAKEHOLDER_VERIFIED",
  "COMPLETE",
  "ABORTED",
]);

export const COORDINATION_EVENT_AUTHORITIES = Object.freeze({
  DESCRIPTOR_ACCEPTED: "role",
  ENROLLMENT_CONFIRMED: "role",
  FUNDING_INPUTS_READY: "role",
  IDENTITY_PACKAGE_READY: "role",
  PREFLIGHT_PARTICIPANT_READY: "role",
  RECOVERY_REQUIRED: "role",
  ROLE_PACKAGE_READY: "role",
  ROLE_STARTED: "role",
  TERMINAL_FAILURE: "any",
  TOKEN_READY: "role",
  ENROLLMENT_RECEIPT: "operator",
  EXACT_RECOVERY_AUTHORIZATION: "operator",
  PREFLIGHT_PLAN_READY: "operator",
  REGISTER_REHEARSAL: "operator",
  REGISTER_STAKEHOLDER: "operator",
  REHEARSAL_DESCRIPTOR_READY: "operator",
  STAKEHOLDER_DESCRIPTOR_READY: "operator",
  START_REHEARSAL: "operator",
  START_STAKEHOLDER: "operator",
  TERMINAL_ABORT: "operator",
  VERIFICATION_FAILED: "operator",
  VERIFICATION_PASSED: "operator",
  WAIT_FOR_FUNDING: "operator",
});
```

`initialReleaseView` returns a deep-frozen exact-key view with separate payer and
payee readiness for each prerequisite. `reduceReleaseEvent` validates event
authority and context, marks exactly one prerequisite, derives the next state
from all required facts, and permanently maps either terminal event to
`ABORTED`. `VERIFICATION_PASSED` advances only when the matching run has both
role packages and the coordinator-supplied verifier-publication check is true;
the relay never derives that fact itself.

- [ ] **Step 4: Run focused tests**

Run:

```bash
node --test test/bilateral-coordination-lifecycle.test.mjs
node --check src/bilateral/coordination/lifecycle.mjs
```

Expected: the valid chain passes and every hostile edge fails closed.

- [ ] **Step 5: Commit**

```text
Prevent coordination order from being inferred or improvised

Constraint: Rehearsal verification at an unchanged release is the only gate to the stakeholder run.
Rejected: Mutable status flags | they cannot prove prerequisite event order or authority
Confidence: high
Scope-risk: moderate
Directive: Add new event kinds only with explicit authority, run scope, reducer edges, and hostile tests.
Tested: node --test test/bilateral-coordination-lifecycle.test.mjs; node --check src/bilateral/coordination/lifecycle.mjs
Not-tested: Persistence transactions and network delivery
```

## Task 3: Durable capabilities, event log, and artifact store

**Files:**

- Create: `src/bilateral/coordination/artifact.mjs`
- Create: `src/bilateral/coordination/storage.mjs`
- Create: `test/bilateral-coordination-storage.test.mjs`

- [ ] **Step 1: Write failing storage-contract tests**

Create a mode-`0700` temporary root and pin this interface:

```js
const store = await openCoordinationStore({
  repositorySha: "c".repeat(40),
  root: stateRoot,
});

await store.registerCapability({
  capabilityDigest: sha256(rawCapability),
  expiresAtMs: "1785120000000",
  releaseId: "release-a",
  role: "payer",
  sessionId,
});

const first = await store.consumeCapability({
  capability: rawCapability,
  enrollmentDigest,
  receiptBytes,
});
const retry = await store.consumeCapability({
  capability: rawCapability,
  enrollmentDigest,
  receiptBytes,
});
assert.deepEqual(retry, first);
await assert.rejects(
  store.consumeCapability({
    capability: rawCapability,
    enrollmentDigest: "d".repeat(64),
    receiptBytes,
  }),
  { code: "CAPABILITY_REPLAY" },
);

await store.appendEvent(payerEvent0);
assert.deepEqual(await store.readEvents({ after: null, sessionId }), [
  payerEvent0,
]);
```

Add hostile tests for non-`0700` roots, symlink roots/files, reused nonempty
state, expired/cross-role capabilities, concurrent consumption, sequence gap,
same-sequence/different-digest conflict, digest replay, broken previous digest,
partial/torn log tails, noncanonical log bytes, snapshot disagreement, restart
replay, and directory/file replacement around every durable operation.

Pin artifact behavior:

```js
const metadata = await store.putArtifact({
  artifactType: "party-result-package",
  bytes: packageBytes,
  expectedDigest: sha256(packageBytes),
  secretCanaries: [tokenCanary],
});
assert.equal(metadata.digest, sha256(packageBytes));
assert.deepEqual(
  await store.getArtifact(metadata.digest),
  packageBytes,
);
```

Reject over 1 MiB single artifacts, over 3 MiB packages, secret canaries,
private-key/token patterns, archives, unknown files, marker-incomplete packages,
digest mismatches, replacement during write/read, and duplicate digest with
different bytes.

- [ ] **Step 2: Run RED**

Run:

```bash
node --test test/bilateral-coordination-storage.test.mjs
```

Expected: missing storage and artifact modules.

- [ ] **Step 3: Implement artifact policy**

In `artifact.mjs`, export:

```js
export const MAX_RELAY_ARTIFACT_BYTES = 1_048_576;
export const MAX_RELAY_PACKAGE_BYTES = 3_145_728;

export const ARTIFACT_POLICIES = Object.freeze({
  "coordination-enrollment": Object.freeze({ maximum: 65_536 }),
  "coordination-receipt": Object.freeze({ maximum: 65_536 }),
  "identity-package": Object.freeze({ maximum: 1_048_576, markerRequired: true }),
  "invitation-public-bundle": Object.freeze({ maximum: 16_384 }),
  "party-result-package": Object.freeze({ maximum: 3_145_728, markerRequired: true }),
  "preflight-aggregate-report": Object.freeze({ maximum: 1_048_576, markerRequired: true }),
  "preflight-participant-report": Object.freeze({ maximum: 1_048_576, markerRequired: true }),
  "preflight-plan": Object.freeze({ maximum: 65_536 }),
  "preflight-public-key": Object.freeze({ maximum: 65_536 }),
  "signed-descriptor": Object.freeze({ maximum: 1_048_576 }),
  "token-commitment": Object.freeze({ maximum: 65_536 }),
});

```

Do not accept tar, zip, arbitrary JSON, or an artifact name not in the policy.
For multi-file packages, accept canonical package manifests containing exact
allowlisted filenames, individual SHA-256 digests, byte lengths, and the
existing completion marker bytes; never accept a general archive.
`validateRelayArtifact({artifactType, bytes, expectedDigest,
secretCanaries})` requires an own-key-only input object, looks up the exact
policy, enforces its maximum before parsing, recomputes and byte-compares the
SHA-256 digest, parses only the policy's named schema, validates required
completion-marker bytes and per-file digests for packages, runs
`assertSecretFree` over the complete artifact with all active canaries, and
returns frozen `{artifactType, byteLength: String(bytes.length), digest}`.

- [ ] **Step 4: Implement pinned durable storage**

`openCoordinationStore` must:

1. create or open one exact mode-`0700` directory using nofollow directory
   handles;
2. pin device/inode/mode/owner metadata and revalidate it around pathname work;
3. store private metadata at mode `0600`;
4. append canonical length-prefixed log records under an exclusive lock;
5. fsync the record and directory before acknowledgement;
6. treat the log as authoritative and rebuild snapshots from it;
7. store artifacts at `artifacts/<first-two>/<digest>` with exclusive creation,
   reread, rehash, and directory fsync; and
8. provide an idempotent `close()` that fails if a durable close fails.

The returned exact interface is:

```js
{
  appendEvent,
  close,
  consumeCapability,
  getArtifact,
  putArtifact,
  readEvents,
  readReleaseView,
  registerCapability,
}
```

- [ ] **Step 5: Run storage tests and syntax checks**

Run:

```bash
node --test test/bilateral-coordination-storage.test.mjs
node --check src/bilateral/coordination/artifact.mjs
node --check src/bilateral/coordination/storage.mjs
```

Expected: all persistence, restart, race, and artifact hostile cases pass.

- [ ] **Step 6: Commit**

```text
Make relay recovery depend on an append-only durable truth

Constraint: A crash or ambiguous response must never consume a capability twice or reorder signed events.
Rejected: Mutable JSON snapshots | replacement or partial writes could silently invent coordinator state
Confidence: high
Scope-risk: broad
Directive: The event log is authoritative; derived snapshots must always be rebuildable and disposable.
Tested: node --test test/bilateral-coordination-storage.test.mjs; syntax checks for artifact and storage modules
Not-tested: HTTPS routing and cross-process restart
```

## Task 4: Transport-independent relay and production HTTPS entrypoint

**Files:**

- Create: `src/bilateral/coordination/relay.mjs`
- Create: `bin/handshake-relay.mjs`
- Create: `test/bilateral-coordination-relay.test.mjs`

- [ ] **Step 1: Write failing relay-service tests**

Drive `createRelayService` without sockets:

```js
const relay = createRelayService({
  frozenRepositorySha: "e".repeat(40),
  now: () => 1_785_120_000_000,
  receiptSigner: fixedTestReceiptSigner,
  store,
});

const receipt = await relay.bootstrap({
  body: enrollmentRequestBytes,
});
assert.equal(receipt.paymentMoved, false);

const accepted = await relay.appendEvent({
  body: canonicalBytes(payerEvent0),
});
assert.equal(accepted.eventDigest, payerEvent0.eventDigest);

assert.deepEqual(
  await relay.readEvents({ after: null, sessionId, waitMs: 0 }),
  [payerEvent0],
);
```

Add tests for exact bootstrap request shape, invitation proof-of-possession,
coordination signature, atomic byte-identical retry, capability conflict,
unknown kinds, wrong authority, sequence/replay errors, wrong SHA/session/role,
malformed bodies, 64 KiB request limit, artifact routes, long-poll timeout,
aborted release permanence, and fixed secret-free error bodies.

- [ ] **Step 2: Run RED**

Run:

```bash
node --test test/bilateral-coordination-relay.test.mjs
```

Expected: missing relay module.

- [ ] **Step 3: Implement the service methods**

Export:

```js
export function createRelayService({
  frozenRepositorySha,
  now = Date.now,
  receiptSigner,
  store,
}) {
  return Object.freeze({
    appendEvent,
    bootstrap,
    getArtifact,
    putArtifact,
    readEvents,
    readSessionView,
  });
}
```

`bootstrap` validates:

- one raw 256-bit capability;
- exact session/release/role/SHA binding;
- coordination and preflight Ed25519 public keys;
- exactly two role-owned public invitations (`rehearsal`, `stakeholder`);
- EIP-191 proof of control for both invitation addresses;
- coordination signature over the full canonical request; and
- `paymentMoved:false`.

It atomically binds the capability to the request digest and one signed receipt.
`receiptSigner` signs a fixed relay-receipt domain plus the canonical receipt
digest with the HTTPS server private key. The receipt carries the leaf
certificate fingerprint and signature algorithm, and the supervisor verifies
it with the public key from the already pinned leaf certificate. The service
never receives the operator private key and the receipt is never accepted as an
operator command or protocol fact.

The TLS-signed bootstrap receipt and the later operator-signed
`ENROLLMENT_RECEIPT` event are separate objects. The first proves idempotent
capability consumption by the pinned relay; the second acknowledges enrollment
in the operator workflow. Tests reject either object when supplied in place of
the other.

- [ ] **Step 4: Write failing HTTPS parser and startup tests**

Test `bin/handshake-relay.mjs` through an exported `main(arguments_,
dependencies)` with exact arguments:

```text
--host 127.0.0.1
--port 8443
--repository-sha <40 lowercase hex>
--state <0700 directory>
--tls-certificate <regular bounded PEM>
--tls-private-key <0600 regular bounded PEM>
```

Reject missing/unknown/duplicate flags, implicit or wildcard host, plaintext
mode, unreadable TLS files, certificate/key mismatch, nonprivate state, dirty or
wrong checkout, and a production fake transport dependency.

- [ ] **Step 5: Implement the HTTPS routes**

Map only:

```text
POST /v1/bootstrap
POST /v1/events
PUT  /v1/artifacts/:sha256
GET  /v1/artifacts/:sha256
GET  /v1/sessions/:sessionId/events?after=<digest>&waitMs=<bounded>
GET  /v1/sessions/:sessionId/view
```

Use `node:https.createServer`, reject redirects and unknown methods/routes,
apply fixed header/body/total deadlines, stream with maximum-plus-one bounds,
send `application/json` or `application/octet-stream`, and return fixed
non-authorizing error codes. The entrypoint constructs `receiptSigner` from the
same validated TLS private key used by `createServer`; the key is not exported
to storage or any client. No production HTTP listener exists.

- [ ] **Step 6: Run focused relay tests**

Run:

```bash
node --test test/bilateral-coordination-relay.test.mjs
node --check src/bilateral/coordination/relay.mjs
node --check bin/handshake-relay.mjs
```

Expected: all service and HTTPS parser tests pass.

- [ ] **Step 7: Commit**

```text
Expose coordination without granting transport protocol authority

Constraint: Production relay traffic must use a pinned TLS identity and a closed request surface.
Rejected: HTTP or framework fallback | it would add downgrade paths and unnecessary request behavior
Confidence: high
Scope-risk: broad
Directive: Keep relay routes closed, bounded, and unable to invoke protocol commands.
Tested: node --test test/bilateral-coordination-relay.test.mjs; syntax checks for relay source and entrypoint
Not-tested: Real two-role HTTPS process topology
```

## Task 5: Private launch manifests and pinned HTTPS client

**Files:**

- Create: `src/bilateral/coordination/manifest.mjs`
- Create: `src/bilateral/coordination/client.mjs`
- Create: `test/bilateral-coordination-client.test.mjs`

- [ ] **Step 1: Write failing manifest tests**

Pin this schema:

```js
const { manifest, capabilityDigest } = createLaunchManifest({
  expectedTlsFingerprint: "ab:cd:…",
  operatorKeyId: "clockchain-demo-2026",
  releaseId: "release-a",
  relayUrl: "https://relay.example.test:8443",
  repositorySha: "f".repeat(40),
  role: "payer",
  sessionId,
  nowMs: 1_785_120_000_000,
  randomBytes: fixedRandomBytes,
});

assert.equal(manifest.schema, "clockchain.bilateral-launch-manifest/v1");
assert.equal(manifest.bootstrapCapability.length, 64);
assert.equal(
  capabilityDigest,
  sha256(Buffer.from(manifest.bootstrapCapability, "hex")),
);
assert.equal(manifest.expiresAtMs, "1785123600000");
```

Write with `writeLaunchManifest(path, manifest)` and assert exact mode `0600`,
exclusive creation, canonical bytes, fsync, nofollow handling, and no raw
capability in returned public bootstrap state.

- [ ] **Step 2: Write failing TLS client tests**

Generate a self-signed test certificate in a temporary directory during the
test. Assert:

```js
const transport = createPinnedHttpsTransport({
  expectedFingerprint,
  relayUrl,
  ca: testCertificate,
});
const response = await transport.request({
  body: canonicalBytes(request),
  method: "POST",
  path: "/v1/bootstrap",
});
```

Reject wrong fingerprint, `http:`, redirects, hostname changes, proxy
environment influence, alternate certificate, oversized response, slow
connect/header/body/total deadlines, unknown response content type, and a
production option that disables certificate verification.

- [ ] **Step 3: Run RED**

Run:

```bash
node --test test/bilateral-coordination-client.test.mjs
```

Expected: missing manifest/client modules.

- [ ] **Step 4: Implement manifest and client**

`manifest.mjs` exports
`LAUNCH_MANIFEST_SCHEMA =
"clockchain.bilateral-launch-manifest/v1"`,
`UNUSED_CAPABILITY_LIFETIME_MS = 3_600_000`,
`createLaunchManifest(input)`,
`readLaunchManifest(path, dependencies)`, and
`writeLaunchManifest(path, manifest, dependencies)`.

The manifest contains exact schema/protocol/repository/operator-key/role/session
/relay/fingerprint/capability/release/issued/expiry fields. The client exports:
Each role receives a distinct 256-bit one-time capability, both manifests carry
the same coordination session ID, and an unused capability expires exactly
60 minutes after issuance.

```text
createPinnedHttpsTransport(options)
  -> { request({body, method, path}) }

createCoordinationClient({
  coordinationPrivateKeyPem,
  manifest,
  transport
})
  -> {
    appendEvent,
    bootstrap,
    getArtifact,
    putArtifact,
    readEvents,
    readSessionView
  }
```

`createCoordinationClient` owns the sender sequence and previous digest, signs
envelopes, retries only identical bytes, revalidates the returned chain, and
provides exact methods `bootstrap`, `appendEvent`, `putArtifact`, `getArtifact`,
`readEvents`, and `readSessionView`.

- [ ] **Step 5: Run client tests**

Run:

```bash
node --test test/bilateral-coordination-client.test.mjs
node --check src/bilateral/coordination/manifest.mjs
node --check src/bilateral/coordination/client.mjs
```

Expected: manifest, TLS, timeout, and retry tests pass.

- [ ] **Step 6: Commit**

```text
Bind each role start to one release and one TLS relay identity

Constraint: The user starts each machine once with a private role-specific manifest.
Rejected: Reusable bearer login | it would permit role substitution after bootstrap
Confidence: high
Scope-risk: moderate
Directive: Never expose raw capabilities outside mode-0600 launch manifests or accept TLS downgrade switches.
Tested: node --test test/bilateral-coordination-client.test.mjs; syntax checks for manifest and client
Not-tested: Supervisor enrollment and relay restart
```

## Task 6: Role-local preflight identities and token commitments

**Files:**

- Create: `src/bilateral/coordination/preflight.mjs`
- Modify: `scripts/probe-bilateral-rendezvous.mjs`
- Modify: `test/bilateral-preflight.test.mjs`
- Create: `test/bilateral-coordination-preflight.test.mjs`

- [ ] **Step 1: Write failing role-local enrollment tests**

Pin these public artifacts:

```js
const enrollment = await createLocalPreflightEnrollment({
  outputDirectory,
  repositorySha: "1".repeat(40),
  role: "payer",
});
assert.equal(
  enrollment.publicArtifact.schema,
  "clockchain.bilateral-preflight-key-enrollment/v1",
);
assert.equal(enrollment.publicArtifact.paymentMoved, false);
assert.equal((await stat(enrollment.privateKeyPath)).mode & 0o777, 0o600);
assert.equal(Object.hasOwn(enrollment.publicArtifact, "privateKey"), false);

const commitment = await readAndSignTokenCommitment({
  coordinationPrivateKeyPem,
  coordinationPublicKey,
  repositorySha: "1".repeat(40),
  role: "payer",
  tokenPath,
});
assert.equal(commitment.tokenSha256, sha256(tokenBytes));
assert.equal(commitment.paymentMoved, false);
```

Add rejection tests for token over 4096 bytes, nonprintable bytes, swapped token
after commitment, wrong role/SHA/key, extra keys, public/private path
replacement, symlink/FIFO/device files, non-`0600` private files, and secret
canaries in returned artifacts.

- [ ] **Step 2: Add RED tests for operator plan construction**

Change preflight preparation tests so the operator receives only:

- payer/payee preflight public enrollment artifacts;
- payer/payee signed token commitments;
- payer/payee coordination public keys;
- the frozen SHA and operator private-key file.

Assert the prepare stage no longer writes
`payer-participant.ed25519.pem` or `payee-participant.ed25519.pem`.

- [ ] **Step 3: Run RED**

Run:

```bash
node --test \
  test/bilateral-coordination-preflight.test.mjs \
  test/bilateral-preflight.test.mjs
```

Expected: missing preflight module and old operator-generated-key assertions
fail.

- [ ] **Step 4: Implement role-local key and commitment helpers**

Export
`PREFLIGHT_KEY_ENROLLMENT_SCHEMA =
"clockchain.bilateral-preflight-key-enrollment/v1"`,
`TOKEN_COMMITMENT_SCHEMA =
"clockchain.bilateral-token-commitment/v1"`,
`createLocalPreflightEnrollment(input)`,
`readAndSignTokenCommitment(input)`, and
`verifyTokenCommitment(artifact, expected)`.

Use Ed25519, canonical bytes, exact schemas, pinned private directories, exact
`0600` private files, bounded rereads, and `assertSecretFree`.

- [ ] **Step 5: Refactor preflight preparation**

Update the `prepare` parser and builder so the plan contains exact participant
public keys and token SHA-256 commitments supplied in verified signed public
artifacts. Keep `participant` and `aggregate` behavior and marker formats
compatible except for the newly required commitment fields. Before the
preflight write and before both role runs, callers must reread the token and
match the same committed digest.

Keep a test-only direct builder injection for deterministic tests. Do not add a
production fake flag, URL, or environment variable.

- [ ] **Step 6: Run preflight tests**

Run:

```bash
node --test \
  test/bilateral-coordination-preflight.test.mjs \
  test/bilateral-preflight.test.mjs \
  test/bilateral-operational-e2e.test.mjs
node --check src/bilateral/coordination/preflight.mjs
node --check scripts/probe-bilateral-rendezvous.mjs
```

Expected: all old and new preflight behavior passes with participant private
keys created only on role machines.

- [ ] **Step 7: Commit**

```text
Keep preflight proof keys and tokens on their assigned machines

Constraint: One two-write preflight must bind both runs, both role machines, and exact token bytes at one SHA.
Rejected: Operator-generated participant private keys | transfer would violate the two-action and local-secret contract
Confidence: high
Scope-risk: broad
Directive: Token commitments are public; raw token bytes and participant private keys never enter relay or operator artifacts.
Tested: focused coordination/preflight tests, existing preflight suite, operational E2E, and syntax checks
Not-tested: Live two-client Clockchain visibility
```

## Task 7: Long-lived role supervisor and exact command policy

**Files:**

- Create: `src/bilateral/coordination/supervisor.mjs`
- Create: `bin/handshake-supervisor.mjs`
- Create: `test/bilateral-coordination-supervisor.test.mjs`

- [ ] **Step 1: Write failing bootstrap and local-state tests**

Drive `createRoleSupervisor` with injected filesystem, invitation creator,
coordination client, and child-command launcher:

```js
const supervisor = await createRoleSupervisor({
  launchManifestPath,
  stateRoot,
  dependencies: fakes,
});
const enrollment = await supervisor.bootstrap();
assert.equal(enrollment.role, "payer");
assert.equal(enrollment.invitations.length, 2);
assert.deepEqual(
  enrollment.invitations.map(({ subjectRun }) => subjectRun),
  ["rehearsal", "stakeholder"],
);
assert.equal(enrollment.paymentMoved, false);
```

Assert distinct coordination, preflight, rehearsal-invitation, and
stakeholder-invitation keys; raw capabilities disappear from active state only
after a durable verified receipt; retry of an ambiguous bootstrap sends
byte-identical enrollment bytes.

- [ ] **Step 2: Write failing command-policy tests**

Pin a closed dispatcher:

```js
const policy = buildSupervisorCommand({
  event: startRehearsalEvent,
  localState,
});
assert.deepEqual(policy, {
  args: [
    "--clockchain-token-file", localState.tokenPath,
    "--descriptor", localState.rehearsal.descriptorPath,
    "--invitation", localState.rehearsal.invitationPath,
    "--output", localState.rehearsal.resultDirectory,
    "--i-understand-this-anchors-clockchain-evidence",
  ],
  command: localState.role === "payer"
    ? "bin/handshake-propose.mjs"
    : "bin/handshake-accept.mjs",
});
```

Reject arbitrary executable/argv/env/cwd/output overrides, wrong role, changed
SHA, dirty checkout, prompt mismatch, token-commitment mismatch, repeated run,
reused invitation, descriptor mismatch, output-directory change, and any
operator event not in the allowlist.

- [ ] **Step 3: Write failing crash/resume and output tests**

Test restart after each durable boundary. Require signed chain reconciliation
before resume, exact recovery authorization for ambiguous writes, marker
validation before upload, permanent abort on chain divergence, and fixed
non-authorizing stdout/stderr. Scan supervisor source and runtime for the
authorizing literal.

- [ ] **Step 4: Run RED**

Run:

```bash
node --test test/bilateral-coordination-supervisor.test.mjs
```

Expected: missing supervisor module.

- [ ] **Step 5: Implement the supervisor**

Export `SUPERVISOR_STATE_SCHEMA =
"clockchain.bilateral-supervisor-state/v1"` and the exact policy:

```js
export const SUPERVISOR_COMMAND_POLICY = Object.freeze({
  PREFLIGHT_PLAN_READY: "preflight-participant",
  REGISTER_REHEARSAL: "register-identity",
  REHEARSAL_DESCRIPTOR_READY: "accept-descriptor",
  START_REHEARSAL: "run-role",
  REGISTER_STAKEHOLDER: "register-identity",
  STAKEHOLDER_DESCRIPTOR_READY: "accept-descriptor",
  START_STAKEHOLDER: "run-role",
  EXACT_RECOVERY_AUTHORIZATION: "recover-exact-command",
  TERMINAL_ABORT: "abort",
});
```

The module also exports `buildSupervisorCommand(input)`,
`createRoleSupervisor(input)`, and `runSupervisor(input)`. The first returns
only `{args, command}` from repository-owned paths; the latter two return
frozen state snapshots and never return a child process's secret-bearing
stdout.

The supervisor:

1. reads one mode-`0600` manifest and verifies clean SHA;
2. generates role-local coordination/preflight keys and two invitations;
3. bootstraps once and stores the verified receipt;
4. mints or stores one role token locally, then publishes only its commitment;
5. processes signed operator events in sequence;
6. invokes existing exact CLIs with an environment allowlist;
7. uploads only verified marker-complete public packages;
8. rereads the token commitment before preflight and each role run;
9. stays alive across rehearsal and stakeholder; and
10. aborts permanently on any mismatch.

The entrypoint accepts exactly:

```text
--launch-manifest <private manifest path>
--state <private 0700 supervisor root>
```

No secret value is accepted on argv. Tests inject launchers through
`main(arguments_, dependencies)`; production has no arbitrary launcher option.

- [ ] **Step 6: Run supervisor tests**

Run:

```bash
node --test test/bilateral-coordination-supervisor.test.mjs
node --check src/bilateral/coordination/supervisor.mjs
node --check bin/handshake-supervisor.mjs
```

Expected: enrollment, allowlist, recovery, restart, and output-exclusion tests
pass.

- [ ] **Step 7: Commit**

```text
Let each role complete both runs without surrendering local secrets

Constraint: One Billy process and one Iris process must span the rehearsal and stakeholder sessions.
Rejected: Relay-supplied shell commands | they would turn a mailbox into remote code execution
Confidence: high
Scope-risk: broad
Directive: All supervisor commands remain repository-owned exact builders with fixed paths and environment allowlists.
Tested: node --test test/bilateral-coordination-supervisor.test.mjs; syntax checks for supervisor module and CLI
Not-tested: Operator coordinator and full multiprocess execution
```

## Task 8: Operator coordinator and two-run verifier gating

**Files:**

- Create: `src/bilateral/coordination/coordinator.mjs`
- Create: `bin/handshake-coordinator.mjs`
- Create: `test/bilateral-coordination-coordinator.test.mjs`

- [ ] **Step 1: Write failing launch and funding tests**

Pin coordinator setup:

```js
const release = await createCoordinatorRelease({
  operatorKeyId: "clockchain-demo-2026",
  relayUrl,
  releaseRoot,
  repositorySha: "2".repeat(40),
  tlsFingerprint,
});
assert.equal(release.manifests.length, 2);
assert.notEqual(
  release.manifests[0].bootstrapCapability,
  release.manifests[1].bootstrapCapability,
);
assert.equal(release.manifests[0].sessionId, release.manifests[1].sessionId);
```

After both enrollments, assert the coordinator displays exactly four signed
addresses once, continuously polls existing invitation-readiness logic, advances
without a human “funding complete” signal, and rejects any substituted,
overfunded, underfunded, or nonzero-nonce address.

- [ ] **Step 2: Write failing orchestration-order tests**

Use injected exact command launchers and assert:

```text
both enroll
-> all four funded
-> one operator-signed preflight plan
-> exactly two participant writes
-> aggregate preflight pass
-> both rehearsal identities
-> rehearsal descriptor
-> Iris starts before Billy
-> both role packages
-> fresh verifier child and valid marker
-> stakeholder identities and fresh descriptor
-> Iris starts before Billy
-> both role packages
-> second fresh verifier child and valid marker
-> COMPLETE
```

Assert no stakeholder command follows verifier crash, timeout, nonzero exit,
missing marker, verdict/exit disagreement, repository/prompt/token change,
preflight mismatch, relay abort, or live correction. Assert verdict artifacts
remain operator-local and only `VERIFICATION_PASSED`/`VERIFICATION_FAILED`
appears on the relay.

- [ ] **Step 3: Write failing restart and authorizing-output tests**

Restart the coordinator at every state and require event-log reconciliation.
Require distinct descriptor/session/identity/result/verdict directories for the
two runs, but the same release/SHA/prompts/supervisor keys/tokens/preflight.
Scan coordinator source and its own writes for the authorizing literal. The
verifier child may inherit the operator terminal directly; the coordinator may
not copy the child text into its own log or relay artifacts.

- [ ] **Step 4: Run RED**

Run:

```bash
node --test test/bilateral-coordination-coordinator.test.mjs
```

Expected: missing coordinator module.

- [ ] **Step 5: Implement coordinator state and exact commands**

Export `COORDINATOR_STATE_SCHEMA =
"clockchain.bilateral-coordinator-state/v1"`,
`createCoordinatorRelease(input)`, `runCoordinator(input)`, and
`validateVerifierChildResult(input)`. `createCoordinatorRelease` returns the two
private manifests plus public capability digests; `runCoordinator` returns a
frozen non-authorizing release view; `validateVerifierChildResult` returns only
`{publicationDigest, status: "VERIFICATION_PASSED"}` or throws a fixed terminal
failure.

The coordinator entrypoint accepts paths, never secret bytes:

```text
--clockchain-token-file <operator-local 0600 file>
--operator-key-id <pinned key id>
--operator-private-key <operator-local 0600 file>
--release-root <0700 directory>
--relay-url <https URL>
--repository-sha <40 lowercase hex>
--rpc-url-file <operator-local 0600 file>
--tls-fingerprint <sha256 fingerprint>
```

The implementation composes existing invitation checking, preflight
aggregation, registration, prompt hashing, descriptor creation, watcher,
Billy/Iris role commands, and aggregate verifier. It persists public resumable
state, signs every phase command, starts Iris polling before Billy, launches a
new verifier process for each run, validates exit plus marker-complete verdict,
and writes only a non-authorizing verification state to the relay.

- [ ] **Step 6: Run coordinator tests**

Run:

```bash
node --test test/bilateral-coordination-coordinator.test.mjs
node --check src/bilateral/coordination/coordinator.mjs
node --check bin/handshake-coordinator.mjs
```

Expected: both-run ordering, restart, invalidation, and verifier gating pass.

- [ ] **Step 7: Commit**

```text
Automate the demo while preserving independent authorization

Constraint: The user only starts two role sessions and funds the four enrolled addresses.
Rejected: Human phase signaling and artifact copying | both create unverifiable gaps and extra demo-day actions
Confidence: high
Scope-risk: broad
Directive: A verifier process result advances coordination only after independent marker-complete verdict validation.
Tested: node --test test/bilateral-coordination-coordinator.test.mjs; syntax checks for coordinator module and CLI
Not-tested: Persistent fake service and real two-machine live run
```

## Task 9: True multiprocess deterministic session

**Files:**

- Create: `test/helpers/fake-bilateral-clockchain-service.mjs`
- Create: `test/helpers/bilateral-coordination-child.mjs`
- Create: `test/bilateral-coordination-process-e2e.test.mjs`
- Modify only if required by a proven integration gap:
  `src/bilateral/coordination/*.mjs`, `bin/handshake-*.mjs`,
  `scripts/probe-bilateral-rendezvous.mjs`

- [ ] **Step 1: Write the failing process-topology test**

The parent test must spawn:

```js
const fake = spawn(process.execPath, [
  "test/helpers/fake-bilateral-clockchain-service.mjs",
  "--state", fakeState,
  "--listen-file", fakeListenFile,
]);
const relay = spawn(process.execPath, [
  "bin/handshake-relay.mjs",
  "--host", "127.0.0.1",
  "--port", "0",
  "--repository-sha", repositorySha,
  "--state", relayState,
  "--tls-certificate", certificatePath,
  "--tls-private-key", certificateKeyPath,
]);
const coordinator = spawn(process.execPath, [
  "test/helpers/bilateral-coordination-child.mjs",
  "coordinator",
  "--configuration", coordinatorConfigPath,
]);
```

The coordinator child, not the parent, launches payer, payee, and verifier
children through the test-only child driver. Child drivers import the real
production parsers/default builders and inject only a localhost fake adapter.
No production flag/environment/URL selects the fake.

- [ ] **Step 2: Assert the successful three-transition run**

Require:

- six distinct PIDs for fake, relay, coordinator, Billy, Iris, and verifier;
- distinct role working directories, invitation keys, coordination keys,
  preflight keys, and token files;
- exactly three fake Clockchain writes in M1/M2/M3 order;
- exact USD 100 and `paymentMoved:false`;
- recomputed message digests and predecessor triples;
- increasing block heights and authoritative nanosecond timestamps inside the
  deadline;
- Billy local `ACKNOWLEDGED` and Iris local `ACCEPTED`;
- fresh verifier reads of all three fake anchors; and
- the authorizing literal exactly once, from verifier PID output only.

- [ ] **Step 3: Add integrated adversarial rows**

Parameterize:

```js
[
  "capability replay",
  "cross-role capability",
  "wrong TLS fingerprint",
  "plaintext downgrade",
  "sequence gap",
  "previous digest mismatch",
  "relay restart during long poll",
  "dropped event response",
  "duplicated event response",
  "oversized artifact",
  "secret-bearing artifact",
  "marker-incomplete package",
  "artifact replacement",
  "funding mismatch",
  "nonzero invitation nonce",
  "token commitment mismatch",
  "preflight key mismatch",
  "repository change after preflight",
  "prompt change after preflight",
  "ambiguous registration write",
  "ambiguous Clockchain write",
  "missing protocol anchor",
  "duplicate protocol anchor",
  "reordered protocol anchor",
  "expired protocol anchor",
  "package and Clockchain divergence",
  "advisory status trap",
  "cached timestamp trap",
  "role crash",
  "relay crash",
  "coordinator crash",
  "verifier crash",
  "verifier marker disagreement",
]
```

Every row must either execute in the process harness or cite and assert the
exact focused-test name that covers it. No row may be silently omitted.

- [ ] **Step 4: Run RED**

Run:

```bash
node --test test/bilateral-coordination-process-e2e.test.mjs
```

Expected: missing child helpers/process integration.

- [ ] **Step 5: Implement the fake service and test-only drivers**

The fake service wraps `createFakeBilateralClockchain` with a bounded localhost
HTTP API used only by test adapters. It persists deterministic writes and read
counters so the parent can assert verifier independence.

The child driver has a closed first positional mode:

```text
coordinator | payer | payee | verifier
```

It reads one mode-`0600` canonical test configuration, imports the matching real
builder/runner, creates an adapter for the localhost fake, and executes. It is
under `test/helpers`; production entrypoints never import it.

- [ ] **Step 6: Iterate until the process suite passes**

Run:

```bash
node --test test/bilateral-coordination-process-e2e.test.mjs
```

Expected: the happy path and all integrated hostile rows pass with no orphaned
children or leftover sockets.

- [ ] **Step 7: Re-run all coordination and operational tests**

Run:

```bash
node --test \
  test/bilateral-coordination-envelope.test.mjs \
  test/bilateral-coordination-lifecycle.test.mjs \
  test/bilateral-coordination-storage.test.mjs \
  test/bilateral-coordination-relay.test.mjs \
  test/bilateral-coordination-client.test.mjs \
  test/bilateral-coordination-preflight.test.mjs \
  test/bilateral-coordination-supervisor.test.mjs \
  test/bilateral-coordination-coordinator.test.mjs \
  test/bilateral-coordination-process-e2e.test.mjs \
  test/bilateral-operational-e2e.test.mjs
```

Expected: all focused and legacy operational tests pass together.

- [ ] **Step 8: Commit**

```text
Prove the complete handshake across isolated processes before live use

Constraint: Deterministic success must exercise real parsers and builders without a production fake switch.
Rejected: In-memory orchestration E2E | shared objects cannot prove two-role or verifier isolation
Confidence: high
Scope-risk: broad
Directive: Keep fake adapters confined to test-only child drivers and assert verifier read independence.
Tested: full coordination-focused and operational E2E suites
Not-tested: Hosted relay, live Sepolia, and live Clockchain
```

## Task 10: Automated happy-path runbook, prompts, and documentation gates

**Files:**

- Modify: `package.json`
- Modify: `README.md`
- Modify: `docs/runbooks/bilateral-demo-day.md`
- Modify: `prompts/run-billy-bilateral-demo.md`
- Modify: `prompts/run-iris-bilateral-demo.md`
- Modify: `scripts/check-docs.mjs`
- Modify: `test/docs.test.mjs`

- [ ] **Step 1: Write failing documentation gates**

Add tests requiring the primary happy path to state:

```js
assert.match(runbook, /fund (?:the )?four displayed addresses/i);
assert.match(runbook, /start (?:exactly )?two (?:role|agent) sessions/i);
assert.match(runbook, /one .*preflight.*both runs/i);
assert.match(runbook, /one .*token per role.*both runs/i);
assert.match(runbook, /physical separation.*attested.*not cryptographically proven/i);
assert.match(runbook, /code.*prompt.*change.*abort/i);
assert.doesNotMatch(primaryHappyPath, /copy .*artifact|transfer .*private key|start four/i);
```

Add source gates that the authorizing literal appears in production only in the
aggregate verifier module/script, and that package scripts expose relay,
coordinator, and supervisor entrypoints without a fake option.

- [ ] **Step 2: Run RED**

Run:

```bash
node --test test/docs.test.mjs
```

Expected: current manual happy path and missing coordination commands fail.

- [ ] **Step 3: Update package scripts**

Add exact scripts:

```json
{
  "bilateral:coordinator": "node bin/handshake-coordinator.mjs",
  "bilateral:relay": "node bin/handshake-relay.mjs",
  "bilateral:supervisor": "node bin/handshake-supervisor.mjs"
}
```

Preserve all existing scripts and the pinned dependency set.

- [ ] **Step 4: Rewrite the primary runbook flow**

The primary flow must say:

1. the operator freezes one clean SHA and starts the HTTPS relay/coordinator;
2. the user starts Billy once with Billy's private manifest and Iris once with
   Iris's private manifest;
3. both supervisors create and retain their local keys, tokens, and two
   invitations;
4. the coordinator displays exactly four signed addresses;
5. the user funds those four addresses;
6. the coordinator detects funding, runs one preflight, and conducts rehearsal
   then stakeholder;
7. the same two supervisor processes span both runs;
8. descriptors/identities/results/verdict directories remain run-specific;
9. live code/prompt/SHA/token changes abort the release; and
10. only each fresh aggregate verifier output can authorize.

Move manual artifact copying and low-level commands into a clearly labeled
operator-authorized recovery appendix. Do not promise cryptographic hardware
attestation or payload retrieval from Clockchain.

- [ ] **Step 5: Update both machine prompts**

Each prompt invokes only:

```text
npm run bilateral:supervisor -- \
  --launch-manifest <role-specific private path> \
  --state <role-specific private state directory>
```

State that the process stays alive through both runs, must not improvise
commands, must stop on any fixed failure, and cannot declare authorization.

- [ ] **Step 6: Run documentation and focused tests**

Run:

```bash
node --test test/docs.test.mjs
npm run docs:check
node --test \
  test/bilateral-coordination-supervisor.test.mjs \
  test/bilateral-coordination-coordinator.test.mjs \
  test/bilateral-coordination-process-e2e.test.mjs
```

Expected: all documentation and coordination gates pass.

- [ ] **Step 7: Commit**

```text
Make the two-action operator contract executable on demo day

Constraint: The user funds four addresses and starts two role sessions; the system owns every later phase signal.
Rejected: Manual happy-path artifact transfer | it contradicts the approved operational surface
Confidence: high
Scope-risk: moderate
Directive: Keep low-level commands in recovery documentation and preserve one supervisor pair across both runs.
Tested: docs tests, documentation gate, supervisor/coordinator/process E2E tests
Not-tested: Human rehearsal on the two physical demo machines
```

## Task 11: Independent review and deterministic-build completion

**Files:**

- Modify only files required to resolve confirmed review findings.

- [ ] **Step 1: Run independent architecture review**

Review the integrated diff against every section of the approved relay spec.
Require explicit findings for authority boundaries, physical-attestation
wording, two-run invalidation, test-only fake isolation, and the minimal human
action surface.

- [ ] **Step 2: Run independent security review**

Review TLS pinning, capabilities, Ed25519 signatures, invitation proof of
control, sequence/replay handling, path races, file modes, secret scanning,
command injection, environment inheritance, ambiguous writes, verifier output,
and crash recovery. Resolve every Critical, High, and material Medium finding
with RED/GREEN tests.

- [ ] **Step 3: Run independent code review**

Check exact schemas, type/signature consistency, resource cleanup, error
normalization, bounded I/O, module responsibility, and compatibility with the
existing Round 3 commands.

- [ ] **Step 4: Run the complete focused acceptance command**

Run:

```bash
node --test \
  test/bilateral-*.test.mjs \
  test/docs.test.mjs
```

Expected: every bilateral and documentation test passes.

- [ ] **Step 5: Audit dependency, secrets, and authorizing output**

Run:

```bash
npm audit
git ls-files | rg -n '(^|/)(\\.env|.*\\.secret\\.|.*private.*|.*token.*|.*invitation.*)$'
rg -n 'AUTHORIZED' --glob '!test/**' --glob '!docs/**' --glob '!README.md'
git diff --check
```

Expected: audit reports zero known vulnerabilities; tracked-file results contain
no generated secrets; the production literal is confined to the aggregate
verifier; diff check is clean.

- [ ] **Step 6: Run three consecutive fresh full verifications**

Run, from a quiescent worktree:

```bash
npm run verify
npm run verify
npm run verify
```

Expected: all three runs pass. Any failure resets the count after diagnosis and
repair.

- [ ] **Step 7: Create the integrated deterministic-build commit**

If review fixes are uncommitted, stage only the confirmed owned paths and use:

```text
Make two-machine authorization coordination independently testable

Constraint: Live use is gated on a frozen release, one preflight, two long-lived role supervisors, and fresh verifier children.
Rejected: Relay authority or production fake fallback | either would invalidate independent protocol verification
Confidence: high
Scope-risk: broad
Directive: Any post-preflight code, prompt, SHA, key, token, or invitation change requires a new release and write budget.
Tested: All focused bilateral tests, three consecutive npm run verify passes, npm audit, secret scan, authorizing-output scan, architecture/security/code reviews
Not-tested: Live invitation funding, live Clockchain preflight, Sepolia registrations, and physical two-machine execution
```

## Task 12: Live release gate after deterministic completion

These steps occur only after Task 11 is committed and verified. They mutate
external state and remain subject to the approved runbook.

- [ ] Freeze and publish the immutable reviewed repository SHA.
- [ ] Start the production HTTPS relay and operator coordinator.
- [ ] Give the user the two private role-specific start surfaces.
- [ ] Have the user start Billy on machine A and Iris on machine B.
- [ ] Display the four supervisor-generated signed public addresses.
- [ ] Have the user fund exactly those four addresses.
- [ ] Let the coordinator confirm funding and run the one authorized two-write
  preflight.
- [ ] Require the live rehearsal to produce three independently reverified
  anchors and a fresh verifier pass.
- [ ] Abort the release if any correction changes code, prompts, SHA, key,
  token, preflight identity, or invitation.
- [ ] At the unchanged frozen release, run the stakeholder session with fresh
  identities, descriptor, output directories, and verifier.
- [ ] Independently refetch and verify all three stakeholder Clockchain anchors.

**Final stop condition:** The full goal is complete only when the live
stakeholder run has exact PROPOSED -> ACCEPTED -> ACKNOWLEDGED Clockchain
evidence, both role packages preserve `paymentMoved:false`, and the fresh
operator verifier—not Billy, Iris, the relay, watcher, or coordinator—emits
`AUTHORIZED`.
