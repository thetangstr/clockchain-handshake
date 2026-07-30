# Payer-Mandate Live Handshake Demo Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Deliver a turnkey three-computer demo in which Iris owns the payer mandate, Billie requests payment and follows that mandate, exactly three Clockchain transitions authorize the request, and a fresh independent verifier is the only component that can output `AUTHORIZED`.

**Architecture:** Keep the existing repository-native Node.js coordination relay, supervisors, coordinator, watcher, funding workflow, and aggregate verifier. Add two canonical EIP-191-signed pre-protocol artifacts, bind their digests into the operator descriptor and every final verification surface, expose them through a durable payer-owned logical inbox on the relay, then project only validated allowlisted state into a loopback-default operator console. Keep the public Clockchain Research site static and explanatory; it links to the runnable demo but never ingests live evidence.

**Tech Stack:** Node.js 22, ES modules, `node:test`, existing `viem`, Node built-in HTTPS/filesystem/crypto APIs, deterministic fake Clockchain service, Next.js and Vitest in the separate `clockchain-research` repository.

**Source of truth:** `docs/superpowers/specs/2026-07-28-payer-mandate-live-demo-design.md`

**Execution order:** Tasks 1–8 run in `clockchain-handshake`. Task 9 runs in the clean `clockchain-research` worktree only after the runtime contracts are stable. Task 10 integrates, reviews, verifies, deploys, and prepares the physical rehearsal.

---

### Task 1: Canonical signed payer mandate and payment request

**Files:**
- Create: `src/bilateral/payer-mandate.mjs`
- Create: `src/bilateral/payment-request.mjs`
- Create: `test/bilateral-payer-mandate.test.mjs`
- Create: `test/bilateral-payment-request.test.mjs`

- [ ] **Step 1: Write failing exact-schema tests for the Iris mandate**

Define the public API in the test:

```js
import {
  PAYER_MANDATE_SCHEMA,
  payerMandateDigest,
  signPayerMandate,
  validatePayerMandate,
  verifyPayerMandate,
} from "../src/bilateral/payer-mandate.mjs";
```

Use a fixture with the exact keys:

```js
const mandate = {
  amount: { currency: "USD", value: "100" },
  expiresAtMs: "1785297600000",
  invoiceReferencePrefix: "TREL-",
  issuedAtMs: "1785294000000",
  payee: { address: PAYEE.address, agentId: "202" },
  payer: { address: PAYER.address, agentId: "101" },
  paymentMoved: false,
  protocol: "clockchain.bilateral-authorization/v1",
  releaseId: "2026-07-28-live-demo",
  repositorySha: "a".repeat(40),
  requestEndpoint:
    "/v1/sessions/11111111-2222-4333-8444-555555555555/payment-requests",
  schema: PAYER_MANDATE_SCHEMA,
  sessionId: "11111111-2222-4333-8444-555555555555",
  subjectRun: "stakeholder",
  purpose: "freight-services",
};
```

Assert exact-key validation, canonical decimal strings, lowercase addresses,
UUID/session/release/SHA bounds, `issuedAtMs < expiresAtMs`, one allowed
`subjectRun`, the exact session-derived `requestEndpoint`, and
`paymentMoved === false`. Add hostile-object, accessor, proxy, unknown-key,
missing-key, invalid-signature, signer/address mismatch, expired,
not-yet-valid, wrong-role, and `paymentMoved:true` cases.

- [ ] **Step 2: Run the mandate test and observe RED**

Run:

```sh
node --test test/bilateral-payer-mandate.test.mjs
```

Expected: FAIL with `ERR_MODULE_NOT_FOUND` for
`src/bilateral/payer-mandate.mjs`.

- [ ] **Step 3: Implement the smallest exact mandate module**

Export:

```js
export const PAYER_MANDATE_SCHEMA =
  "clockchain.bilateral-payer-mandate/v1";
export const PAYER_MANDATE_ENVELOPE_SCHEMA =
  "clockchain.bilateral-payer-mandate-envelope/v1";

export function validatePayerMandate(mandate) {}
export function payerMandateSigningBytes(mandate) {}
export function payerMandateDigest(envelope) {}
export async function signPayerMandate({ mandate, signMessage }) {}
export async function verifyPayerMandate({
  envelope,
  expected,
  nowMs,
}) {}
```

Use `canonicalBytes` and `digestHex` from `src/bilateral/canonical.mjs`,
`recoverMessageAddress` from `viem`, exact own enumerable data properties, and
one wrapper shape:

```js
{
  mandate,
  schema: "clockchain.bilateral-payer-mandate-envelope/v1",
  signature: {
    address: mandate.payer.address,
    algorithm: "eip191",
    value: "0x..."
  }
}
```

Do not accept an injected digest, advisory validity result, numeric timestamp,
or alternative signature algorithm.

- [ ] **Step 4: Make mandate tests GREEN**

Run:

```sh
node --test test/bilateral-payer-mandate.test.mjs
node --check src/bilateral/payer-mandate.mjs
```

Expected: all mandate tests pass and syntax checking exits zero.

- [ ] **Step 5: Write failing exact-schema tests for Billie's request**

Define:

```js
import {
  PAYMENT_REQUEST_SCHEMA,
  paymentRequestDigest,
  signPaymentRequest,
  validatePaymentRequest,
  verifyPaymentRequest,
} from "../src/bilateral/payment-request.mjs";
```

The request has exactly:

```js
const request = {
  amount: { currency: "USD", value: "100" },
  createdAtMs: "1785294300000",
  expiresAtMs: "1785297000000",
  invoiceReference: "TREL-2026-0001",
  mandateDigest: "b".repeat(64),
  payee: { address: PAYEE.address, agentId: "202" },
  payer: { address: PAYER.address, agentId: "101" },
  paymentMoved: false,
  protocol: "clockchain.bilateral-authorization/v1",
  purpose: "freight-services",
  releaseId: "2026-07-28-live-demo",
  repositorySha: "a".repeat(40),
  requestId: "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",
  schema: PAYMENT_REQUEST_SCHEMA,
  sessionId: "11111111-2222-4333-8444-555555555555",
  subjectRun: "stakeholder",
};
```

Prove it fails closed on every mandate mismatch: amount, payer, payee,
purpose, invoice prefix, session, release, repository SHA, subject run, time
window, and payment flag. Prove byte-identical replay can be recognized by
digest while a same-ID/different-byte request is rejected.

- [ ] **Step 6: Run the request test and observe RED**

Run:

```sh
node --test test/bilateral-payment-request.test.mjs
```

Expected: FAIL with `ERR_MODULE_NOT_FOUND` for
`src/bilateral/payment-request.mjs`.

- [ ] **Step 7: Implement and verify the request module**

Export:

```js
export const PAYMENT_REQUEST_SCHEMA =
  "clockchain.bilateral-payment-request/v1";
export const PAYMENT_REQUEST_ENVELOPE_SCHEMA =
  "clockchain.bilateral-payment-request-envelope/v1";

export function validatePaymentRequest(request) {}
export function paymentRequestSigningBytes(request) {}
export function paymentRequestDigest(envelope) {}
export async function signPaymentRequest({ request, signMessage }) {}
export async function verifyPaymentRequest({
  envelope,
  mandateEnvelope,
  expected,
  nowMs,
}) {}
```

Recover the signer from canonical request bytes and require it to equal the
payee address. Call `verifyPayerMandate` before matching the request. Never
create a Clockchain client or write an anchor from either intent module.

Run:

```sh
node --test \
  test/bilateral-payer-mandate.test.mjs \
  test/bilateral-payment-request.test.mjs
```

Expected: all tests pass.

- [ ] **Step 8: Commit the intent primitives**

Stage only the four Task 1 files and create a Lore commit whose trailers record:

```text
Constraint: The request and mandate are signed pre-protocol evidence, never additional Clockchain anchors.
Rejected: Reuse the operator descriptor as the mandate | The payer must remain the commercial authority.
Confidence: high
Scope-risk: moderate
Directive: Keep both schemas exact, EIP-191-bound to role identities, and paymentMoved:false.
Tested: node --test test/bilateral-payer-mandate.test.mjs test/bilateral-payment-request.test.mjs
Not-tested: Relay transport and live identities are covered by later tasks.
```

### Task 2: Bind intent evidence into descriptors, transitions, and verdicts

**Files:**
- Modify: `src/bilateral/descriptor.mjs`
- Modify: `src/bilateral/messages.mjs`
- Modify: `src/bilateral/evidence.mjs`
- Modify: `src/bilateral/verdict.mjs`
- Modify `createCoordinatorDescriptor` only:
  `src/bilateral/coordination/coordinator-runtime.mjs`
- Modify: `scripts/create-session.mjs`
- Modify: `scripts/verify-bilateral-results.mjs`
- Modify: `test/bilateral-descriptor.test.mjs`
- Modify: `test/bilateral-messages.test.mjs`
- Modify: `test/bilateral-evidence.test.mjs`
- Modify: `test/bilateral-verdict.test.mjs`
- Modify descriptor fixtures only: `test/bilateral-protocol.test.mjs`
- Modify descriptor fixtures only: `test/bilateral-roles.test.mjs`
- Modify descriptor fixtures only: `test/bilateral-runner.test.mjs`
- Modify descriptor fixtures only: `test/bilateral-watcher.test.mjs`
- Modify descriptor fixtures only: `test/bilateral-round2-integration.test.mjs`
- Modify descriptor fixtures only: `test/bilateral-operational-e2e.test.mjs`
- Modify descriptor fixtures only: `test/bilateral-coordination-client.test.mjs`
- Modify descriptor fixtures only: `test/bilateral-coordination-coordinator-runtime.test.mjs`
- Modify descriptor fixtures only: `test/bilateral-coordination-relay.test.mjs`
- Modify descriptor fixtures only: `test/bilateral-coordination-storage.test.mjs`
- Modify descriptor fixtures only: `test/bilateral-coordination-supervisor-runtime.test.mjs`

- [ ] **Step 1: Add RED descriptor commitment tests**

Require exact descriptor fields:

```js
requestDigest: "c".repeat(64),
mandateDigest: "b".repeat(64),
```

Assert both digests enter `dSession(descriptor)`, descriptor signing bytes,
transition `sessionDigest`, party signature preimages, published verdict, and
verdict publication validation. Deleting, swapping, or changing either digest
must fail before any Clockchain read.

- [ ] **Step 2: Observe RED across the focused descriptor chain**

Run:

```sh
node --test \
  test/bilateral-descriptor.test.mjs \
  test/bilateral-messages.test.mjs \
  test/bilateral-evidence.test.mjs \
  test/bilateral-verdict.test.mjs \
  test/bilateral-protocol.test.mjs \
  test/bilateral-roles.test.mjs \
  test/bilateral-runner.test.mjs \
  test/bilateral-watcher.test.mjs \
  test/bilateral-round2-integration.test.mjs \
  test/bilateral-operational-e2e.test.mjs \
  test/bilateral-coordination-client.test.mjs \
  test/bilateral-coordination-coordinator-runtime.test.mjs \
  test/bilateral-coordination-relay.test.mjs \
  test/bilateral-coordination-storage.test.mjs \
  test/bilateral-coordination-supervisor-runtime.test.mjs
```

Expected: FAIL because the new exact fields are rejected or ignored.

- [ ] **Step 3: Add exact descriptor commitments**

Update `DESCRIPTOR_KEYS`, descriptor validation, signing, verification, and
session digest derivation. `createCoordinatorDescriptor` will supply the
values in Task 5; no default, optional, or all-zero digest is permitted.

The aggregate verifier input becomes:

```js
{
  client,
  descriptorEnvelope,
  mandateEnvelope,
  ownerOf,
  payeeDirectory,
  payerDirectory,
  repositoryPublicKey,
  requestEnvelope,
}
```

Before reading party packages or Clockchain, verify the two intent envelopes
and require:

```js
descriptor.mandateDigest === payerMandateDigest(mandateEnvelope);
descriptor.requestDigest === paymentRequestDigest(requestEnvelope);
```

- [ ] **Step 4: Expand verifier CLI inputs without weakening secret handling**

Add exact flags:

```text
--payer-mandate
--payment-request
```

Read both as bounded, no-follow public files. Do not accept raw JSON, signatures,
keys, or digests on argv. Extend verifier context/publication bindings with
`mandateDigest` and `requestDigest`.

Keep the low-level descriptor recovery script usable with schema v2 by adding
exact public `--mandate-digest` and `--request-digest` inputs to
`scripts/create-session.mjs`. It must require lowercase 64-hex values and bind
them into the descriptor. This diagnostic surface may accept public digests;
the verifier still requires and independently verifies the signed envelope
files.

Update `createCoordinatorDescriptor` to require the same two digests and bind
them into schema-v2 descriptors. Do not change coordinator orchestration in
this task.

- [ ] **Step 5: Make the descriptor/verdict chain GREEN**

Run:

```sh
node --test \
  test/bilateral-descriptor.test.mjs \
  test/bilateral-messages.test.mjs \
  test/bilateral-evidence.test.mjs \
  test/bilateral-verdict.test.mjs
node --check scripts/verify-bilateral-results.mjs
```

Expected: all focused tests pass; negative tests prove the verifier does no
Clockchain work after an intent-binding failure.

- [ ] **Step 6: Commit the verifier binding**

Commit only Task 2 files with Lore trailers stating that request and mandate
digests are now authoritative descriptor and verdict inputs while the anchor
count remains exactly three.

### Task 3: Durable relay inbox and exact HTTP endpoints

**Files:**
- Modify: `src/bilateral/coordination/artifact.mjs`
- Modify: `src/bilateral/coordination/storage.mjs`
- Modify: `src/bilateral/coordination/relay.mjs`
- Modify: `src/bilateral/coordination/client.mjs`
- Modify: `src/bilateral/coordination/operator-client.mjs`
- Modify: `src/bilateral/coordination/lifecycle.mjs`
- Modify: `bin/handshake-relay.mjs`
- Modify: `test/bilateral-coordination-storage.test.mjs`
- Modify: `test/bilateral-coordination-relay.test.mjs`
- Modify: `test/bilateral-coordination-client.test.mjs`
- Modify: `test/bilateral-coordination-operator-client.test.mjs`
- Modify: `test/bilateral-coordination-lifecycle.test.mjs`

- [ ] **Step 1: Add RED artifact-policy and lifecycle tests**

Add exact artifact types:

```js
"payer-mandate": { maximum: 65_536 },
"payment-request": { maximum: 65_536 },
```

Add lifecycle events:

```text
PAYER_MANDATE_READY    role authority: payer
PAYMENT_REQUEST_READY role authority: payee
PAYMENT_REQUEST_MATCHED role authority: payer
```

The state cannot reach a run descriptor or `*_RUNNING` until all three facts
are true for that subject run.

- [ ] **Step 2: Add RED durable-store tests**

Specify:

```js
await store.putPayerMandate({
  bytes,
  digest,
  sessionId,
  subjectRun,
});
await store.putPaymentRequest({
  bytes,
  digest,
  requestId,
  sessionId,
  subjectRun,
});
await store.readPayerMandate({ sessionId, subjectRun });
await store.readPaymentRequest({ requestId, sessionId });
```

Prove:

- one mandate and one request per session/run;
- byte-identical retries return the original record;
- same binding with different bytes rejects;
- state survives store reopen;
- partial temp files never become authoritative;
- symlink, permission, size, digest, and canonicality attacks fail closed.

- [ ] **Step 3: Run relay/storage/lifecycle tests and observe RED**

Run:

```sh
node --test \
  test/bilateral-coordination-storage.test.mjs \
  test/bilateral-coordination-relay.test.mjs \
  test/bilateral-coordination-lifecycle.test.mjs
```

Expected: FAIL because the new store methods, artifact validators, and event
kinds do not exist.

- [ ] **Step 4: Implement exact artifact validation and durable storage**

Route both artifact types through `validateRelayArtifactWithFacts`. The
normalized facts must expose only the fully validated envelope and its
authoritative digest. Store canonical bytes under content-addressed paths and
an atomic binding record under the session/run.

Do not store a relay-authored `approved`, `authorized`, or `valid` field.

- [ ] **Step 5: Add RED HTTP-handler tests**

Require:

```text
GET  /v1/sessions/{uuid}/mandate?subjectRun=rehearsal|stakeholder
POST /v1/sessions/{uuid}/payment-requests
GET  /v1/sessions/{uuid}/payment-requests/{requestUuid}
```

`POST` accepts `application/octet-stream`, validates at most 65,536 bytes,
requires the exact Billie signature and prior Iris mandate, and returns a
secret-free receipt containing the stored digest. GET responses return the
exact canonical bytes with `application/octet-stream`.

Assert wrong host, duplicate headers, query ambiguity, wrong method/content
type, oversized body, invalid UUID, absent session, absent mandate, wrong
Billie signer, expired artifact, cross-run replay, and body/query mismatch all
fail closed.

- [ ] **Step 6: Implement relay/client endpoints**

Add service and client methods:

```js
publishPayerMandate({ bytes, sessionId, subjectRun })
readPayerMandate({ sessionId, subjectRun })
submitPaymentRequest({ bytes, sessionId })
readPaymentRequest({ requestId, sessionId })
```

The role client may publish only the artifact owned by its protocol role.
The operator client is read-only for these methods. Neither client may expose
an authorizing helper.

- [ ] **Step 7: Make relay, storage, client, and lifecycle suites GREEN**

Run:

```sh
node --test \
  test/bilateral-coordination-storage.test.mjs \
  test/bilateral-coordination-relay.test.mjs \
  test/bilateral-coordination-client.test.mjs \
  test/bilateral-coordination-operator-client.test.mjs \
  test/bilateral-coordination-lifecycle.test.mjs
node --check bin/handshake-relay.mjs
```

Expected: all focused tests pass, including restart/idempotency cases.

- [ ] **Step 8: Commit the payer-owned logical inbox**

The Lore commit must record that the relay hosts transport but cannot author,
alter, match, or authorize Iris's mandate or Billie's request.

### Task 4: Make protocol roles generic and map Iris/Billie correctly

**Files:**
- Modify: `src/bilateral/roles.mjs`
- Modify: `bin/handshake-propose.mjs`
- Modify: `bin/handshake-accept.mjs`
- Modify: `src/bilateral/coordination/supervisor-runtime.mjs`
- Modify: `test/bilateral-roles.test.mjs`
- Modify: `test/bilateral-coordination-supervisor-runtime.test.mjs`

- [ ] **Step 1: Write RED generic-runner and persona tests**

Require exports:

```js
runPayerRole
runPayeeRole
```

Require CLI dispatch:

```text
payer -> runPayerRole -> PROPOSED + ACKNOWLEDGED
payee -> runPayeeRole -> ACCEPTED
```

Use descriptor fixtures whose display names are:

```js
payer.displayName === "Iris";
payee.displayName === "Billie";
```

Assert no stakeholder-facing output or prompt resolver describes Billy as
payer or Iris as payee.

- [ ] **Step 2: Observe RED**

Run:

```sh
node --test \
  test/bilateral-roles.test.mjs \
  test/bilateral-coordination-supervisor-runtime.test.mjs
```

Expected: FAIL because only persona-bound runner exports and prompt mappings
exist.

- [ ] **Step 3: Introduce generic APIs and remove persona authority from code**

Rename implementations to `runPayerRole` and `runPayeeRole`. Keep
`runBillyRole` and `runIrisRole` only as deprecated non-exported migration
locals if an intermediate test requires them; remove them before Task 8.

Set:

```js
const ROLE_PROMPT_PATHS = Object.freeze({
  payer: "prompts/run-iris-bilateral-demo.md",
  payee: "prompts/run-billie-bilateral-demo.md",
});
```

Rename `prompts/run-billy-bilateral-demo.md` in Task 8 after its content tests
are ready; until then, the test may use a fixture prompt resolver.

- [ ] **Step 4: Make role suites GREEN**

Run:

```sh
node --test \
  test/bilateral-roles.test.mjs \
  test/bilateral-coordination-supervisor-runtime.test.mjs
node --check bin/handshake-propose.mjs
node --check bin/handshake-accept.mjs
```

Expected: role behavior is unchanged at the protocol layer and persona mapping
is canonical.

- [ ] **Step 5: Commit the generic role boundary**

Record that protocol roles are stable while stakeholder names are presentation
data. Do not include prompt or runbook changes in this commit.

### Task 5: Orchestrate mandate, request, descriptor, and supervisor phases

**Files:**
- Modify: `src/bilateral/coordination/supervisor.mjs`
- Modify: `src/bilateral/coordination/coordinator.mjs`
- Modify: `src/bilateral/coordination/coordinator-runtime.mjs`
- Modify: `src/bilateral/coordination/supervisor-runtime.mjs`
- Modify: `test/bilateral-coordination-supervisor.test.mjs`
- Modify: `test/bilateral-coordination-coordinator.test.mjs`
- Modify: `test/bilateral-coordination-coordinator-runtime.test.mjs`
- Modify: `test/bilateral-coordination-supervisor-runtime.test.mjs`

- [ ] **Step 1: Write RED supervisor phase tests**

The exact per-run order is:

```text
Iris/payer publishes signed mandate
Billie/payee fetches and verifies mandate
Billie/payee submits signed payment request
Iris/payer fetches and verifies exact request match
operator creates descriptor bound to both digests
Iris/payer starts proposal role
Billie/payee starts acceptance role
```

Assert no role command launches early, all checkpoints include both digests,
and recovery cannot substitute a different request or mandate.

- [ ] **Step 2: Write RED coordinator descriptor tests**

Change:

```js
createCoordinatorDescriptor({
  mandateEnvelope,
  parties,
  promptSha256,
  repositorySha,
  requestEnvelope,
  sessionId,
})
```

The function verifies both envelopes, derives the exact amount from the
request, and refuses any mismatch. It no longer hardcodes USD 100 without
validated intent evidence.

- [ ] **Step 3: Observe RED**

Run:

```sh
node --test \
  test/bilateral-coordination-supervisor.test.mjs \
  test/bilateral-coordination-coordinator.test.mjs \
  test/bilateral-coordination-coordinator-runtime.test.mjs \
  test/bilateral-coordination-supervisor-runtime.test.mjs
```

Expected: FAIL at the new phases and descriptor inputs.

- [ ] **Step 4: Implement role-owned intent creation**

The payer supervisor signs mandates with the payer invitation account. The
payee supervisor signs requests with the payee invitation account. Both write
canonical public envelope files into their private run roots before publishing
only validated bytes to the relay.

Neither supervisor accepts mandate/request bytes from an operator command.
Operator commands select only the subject run and existing identity bindings.

- [ ] **Step 5: Implement coordinator gates and expanded verifier context**

The coordinator reads both envelopes through the operator client, validates
them independently, creates the bound descriptor, and persists:

```js
{
  descriptorDigest,
  mandateDigest,
  outputDirectory,
  packageDigests: { payee, payer },
  paymentMoved: false,
  publicationDigest,
  releaseId,
  repositorySha,
  requestDigest,
  schema,
  sessionId,
  subjectRun,
}
```

Only after a fresh verifier child exits successfully and its marker-complete
publication matches every binding may the coordinator post
`VERIFICATION_PASSED`.

- [ ] **Step 6: Make orchestration suites GREEN**

Run the four Task 5 test files. Expected: all pass, including crash/restart,
duplicate event, stale artifact, and wrong-role tests.

- [ ] **Step 7: Commit the orchestrated commercial intent**

The Lore message must state that Iris owns mandate creation, Billie owns the
request, and the coordinator only binds and schedules validated evidence.

### Task 6: Secure read-only operator console

**Files:**
- Create: `src/bilateral/coordination/console-projection.mjs`
- Create: `src/bilateral/coordination/console-server.mjs`
- Create: `src/bilateral/coordination/console/index.html`
- Create: `src/bilateral/coordination/console/app.js`
- Create: `src/bilateral/coordination/console/styles.css`
- Create: `bin/handshake-console.mjs`
- Create: `test/bilateral-console-projection.test.mjs`
- Create: `test/bilateral-console-server.test.mjs`
- Modify: `package.json`

- [ ] **Step 1: Write RED projection allowlist tests**

Define:

```js
buildConsoleProjection({
  lifecycleView,
  mandate,
  nowMs,
  request,
  verifierPublication,
  watcherSnapshot,
})
```

Require the exact top-level keys:

```js
[
  "actors",
  "anchors",
  "deadline",
  "failure",
  "mandate",
  "paymentMoved",
  "phase",
  "request",
  "schema",
  "session",
  "verifier",
]
```

Inject canaries under tokens, invitations, capabilities, private paths,
environment variables, TLS/RPC fields, nested error causes, and unknown
properties. Assert none appear in serialized output.

Assert the output does not contain the authorizing literal unless a fresh,
marker-complete publication matches the current release, session, request,
mandate, and all three anchor digests.

- [ ] **Step 2: Observe RED and implement the pure projection**

Run:

```sh
node --test test/bilateral-console-projection.test.mjs
```

Expected: `ERR_MODULE_NOT_FOUND`.

Implement only closed-field reconstruction from previously validated facts.
Never spread relay, watcher, error, or publication objects into the result.
Label relay and watcher observations `advisory`.

- [ ] **Step 3: Write RED console-server tests**

Require loopback by default and exact read-only routes:

```text
GET /                          static index
GET /assets/app.js             fixed asset
GET /assets/styles.css         fixed asset
GET /v1/console/session        sanitized JSON projection
```

All other methods and paths return a fixed safe error. Require
`Cache-Control: no-store`, `X-Content-Type-Options: nosniff`, a restrictive
Content-Security-Policy, no directory traversal, bounded request headers, and
an explicit `--allow-lan` acknowledgement before non-loopback bind.

- [ ] **Step 4: Implement the dependency-free console server and UI**

Use Node built-ins only. The browser polls the same-origin projection endpoint
at a bounded interval and renders:

- Iris, Billie, and operator health;
- mandate and request match;
- `PROPOSED`, `ACCEPTED`, `ACKNOWLEDGED`;
- anchor identifiers and block ordering;
- deadline/freshness;
- failure/recovery state;
- fresh verifier state.

The UI uses `textContent`, never `innerHTML` for runtime data, and has no forms,
mutation controls, storage, analytics, remote scripts, or credential input.

- [ ] **Step 5: Make console tests GREEN**

Run:

```sh
node --test \
  test/bilateral-console-projection.test.mjs \
  test/bilateral-console-server.test.mjs
node --check bin/handshake-console.mjs
```

Expected: all tests pass, including redaction and false-authorization traps.

- [ ] **Step 6: Add and verify the CLI command**

Add:

```json
"bilateral:console": "node bin/handshake-console.mjs"
```

Test exact flags for state root, host, port, TLS inputs when LAN is enabled,
and risk acknowledgement. Do not accept session evidence or secrets on argv.

- [ ] **Step 7: Commit the operator console**

Record that the console is loopback-default, read-only, advisory except for a
validated fresh-verifier publication, and dependency-free.

### Task 7: Deterministic isolated multiprocess end-to-end

**Files:**
- Modify: `test/helpers/bilateral-coordination-child.mjs`
- Modify: `test/bilateral-coordination-process-e2e.test.mjs`
- Modify: `src/bilateral/coordination/supervisor.mjs`
- Modify: `src/bilateral/coordination/coordinator.mjs`
- Modify: `src/bilateral/coordination/coordinator-runtime.mjs`
- Modify: `src/bilateral/coordination/relay.mjs`
- Modify: `src/bilateral/coordination/console-projection.mjs`
- Modify: `src/bilateral/verdict.mjs`

- [ ] **Step 1: Write the new RED success scenario**

Extend the existing real coordinator/supervisor process harness so that:

```js
assert.equal(personas.payer, "Iris");
assert.equal(personas.payee, "Billie");
assert.equal(fakeClockchain.writeCount, 3);
assert.deepEqual(anchorKinds, [
  "proposal",
  "acceptance",
  "acknowledgment",
]);
assert.equal(consoleProjection.paymentMoved, false);
assert.equal(roleStdout.includes("AUTHORIZED"), false);
assert.equal(watcherStdout.includes("AUTHORIZED"), false);
assert.equal(coordinatorStdout.includes("AUTHORIZED"), false);
assert.equal(verifierStdout, "AUTHORIZED\n");
```

Also require signed mandate/request files, descriptor digest bindings, distinct
PIDs and roots, and zero Clockchain writes for the two intent artifacts.

- [ ] **Step 2: Observe RED**

Run:

```sh
node --test test/bilateral-coordination-process-e2e.test.mjs
```

Expected: FAIL before the protocol starts because the child harness lacks the
new intent phases.

- [ ] **Step 3: Extend the child harness**

Replace persona-bound runner imports with generic payer/payee imports. Add
deterministic in-process signing accounts for Iris and Billie, publish the
mandate/request through the real relay paths, and pass their files to the real
fresh verifier process.

Do not add fake-only verifier state or bypass exact validators.

- [ ] **Step 4: Add fail-closed and restart scenarios**

Parameterize:

- missing mandate;
- forged Iris signature;
- wrong Billie signer;
- invoice-prefix mismatch;
- request replay with changed bytes;
- expired mandate/request;
- descriptor digest swap;
- fourth Clockchain write;
- relay restart after mandate;
- relay restart after request;
- coordinator restart before descriptor;
- console restart after the third anchor;
- stale/mismatched verifier publication;
- secret canaries in every advisory source.

Each scenario must produce no authorizing output.

- [ ] **Step 5: Make the process suite GREEN**

Run:

```sh
node --test test/bilateral-coordination-process-e2e.test.mjs
```

Expected: every process scenario passes deterministically with no live
credentials or network.

- [ ] **Step 6: Commit the integrated deterministic flow**

The commit records proof of exactly three writes, physical-role process
isolation as an operational attestation rather than cryptographic proof, and
fresh-process verifier exclusivity.

### Task 8: Prompts, runbooks, funding, and documentation gates

**Files:**
- Rename: `prompts/run-billy-bilateral-demo.md` to `prompts/run-billie-bilateral-demo.md`
- Modify: `prompts/run-iris-bilateral-demo.md`
- Modify: `README.md`
- Modify: `docs/runbooks/bilateral-demo-day.md`
- Modify: `docs/runbooks/bilateral-demo-quick-start.md`
- Modify: `scripts/hash-bilateral-prompts.mjs`
- Modify: `scripts/check-docs.mjs`
- Modify: `test/docs.test.mjs`
- Test: `test/bilateral-funding-cli.test.mjs`

- [ ] **Step 1: Write RED documentation contract tests**

Replace the legacy mapping with exact assertions:

```js
assert.match(irisPrompt, /Iris, the payer and mandate owner/);
assert.match(billiePrompt, /Billie, the vendor and payee/);
assert.match(runbook, /Billie request.*Iris mandate.*PROPOSED.*ACCEPTED.*ACKNOWLEDGED/s);
assert.match(runbook, /exactly three independently verifiable Clockchain anchors/i);
assert.match(runbook, /only a fresh aggregate verifier may output `AUTHORIZED`/i);
assert.match(runbook, /paymentMoved:false/);
assert.match(runbook, /operator console.*read-only.*advisory/i);
```

Require links to the renamed Billie prompt and the public helper route. Add a
negative scan that rejects `Billy.*payer`, `Iris.*payee`, and any claim that
authorization moved payment.

- [ ] **Step 2: Observe RED**

Run:

```sh
node --test test/docs.test.mjs
```

Expected: FAIL on the legacy role mapping and missing request/console material.

- [ ] **Step 3: Rewrite the role prompts**

Iris prompt:

- starts only the payer supervisor;
- owns the mandate and `PROPOSED`/`ACKNOWLEDGED`;
- verifies Billie's request;
- never runs the operator verifier.

Billie prompt:

- starts only the payee supervisor;
- fetches/verifies Iris's mandate;
- signs/submits the request and owns `ACCEPTED`;
- never runs the operator verifier.

Both preserve private launch material, TLS pinning, release SHA validation,
exact recovery, `paymentMoved:false`, and stop-on-ambiguity rules.

- [ ] **Step 4: Update runbooks and prompt hash**

Document the operator startup order:

```text
relay -> coordinator -> console -> funding -> Iris supervisor -> Billie supervisor
```

The long-lived supervisors perform mandate/request orchestration automatically.
Keep the reusable Sepolia treasury instructions and the exact four-address
`0.01` funding distribution. Recompute the two-prompt commitment using the
repository script; never hand-edit a digest.

- [ ] **Step 5: Verify funding remains reusable**

Run the deterministic funding suite:

```sh
node --test test/bilateral-funding-cli.test.mjs
```

Expected: all tests pass. If role labels appear in the funding record, update
only their display names while preserving role/address/order/idempotency and
nonce safety.

- [ ] **Step 6: Make documentation gates GREEN**

Run:

```sh
node --test test/docs.test.mjs
npm run docs:check
```

Expected: all documentation tests pass and the standalone checker reports the
new gated document count.

- [ ] **Step 7: Commit the turnkey role-play surface**

The Lore commit records the public naming migration, automatic request/mandate
flow, console startup, reusable treasury, and the distinction between
rehearsal-ready and physically validated.

### Task 9: Static stakeholder helper on Clockchain Research

**Repository:** `/Users/Kailor/.config/superpowers/worktrees/clockchain-research/bilateral-handshake-client-startup`

**Files:**
- Create: `src/app/handshake/run/page.tsx`
- Create: `src/components/BilateralHandshakeRunbook.tsx`
- Create: `src/data/bilateral-handshake-demo.ts`
- Create: `src/lib/bilateral-handshake-runbook.test.tsx`
- Modify: `src/app/handshake/page.tsx`
- Modify: `src/components/BilateralHandshakeArchitecture.tsx`
- Modify: `docs/product/bilateral-payment-authorization-handshake.md`
- Modify: `src/lib/bilateral-handshake-brief.test.tsx`

- [ ] **Step 1: Re-read the research repository contract**

Read its `AGENTS.md` and required `agents/research-brief/agent.md`. Confirm the
worktree is clean and preserve all unrelated changes. Do not copy runtime code
from the Handshake repository.

- [ ] **Step 2: Write RED canonical-content tests**

Create a single public data module:

```ts
export const bilateralDemo = {
  anchors: [
    { actor: "Iris", state: "PROPOSED" },
    { actor: "Billie", state: "ACCEPTED" },
    { actor: "Iris", state: "ACKNOWLEDGED" },
  ],
  paymentMoved: false,
  roles: {
    payer: { company: "Meridian", name: "Iris" },
    payee: { company: "Trellis", name: "Billie" },
  },
} as const;
```

Assert:

- exactly three anchors;
- `AUTHORIZED` belongs only to a fresh operator verifier and is not an anchor;
- the console is operator-local/LAN and read-only;
- no API route, upload, ingest, wallet, invitation, key, or live identifier is
  requested by the Vercel page;
- `/handshake` contains `href="/handshake/run"`.

- [ ] **Step 3: Observe RED**

Run:

```sh
npx vitest run \
  src/lib/bilateral-handshake-brief.test.tsx \
  src/lib/bilateral-handshake-runbook.test.tsx
```

Expected: FAIL because the helper route/data and canonical role assertions do
not exist.

- [ ] **Step 4: Implement the static helper route**

The helper renders:

- architecture boundary;
- Iris and Billie role cards;
- request/mandate/three-anchor sequence;
- three-computer prerequisites;
- exact copyable prompts and commands from the stable Handshake release;
- four-address reusable-treasury funding explanation;
- operator-console opening instructions;
- success, failure, and recovery conditions;
- ready-now versus roadmap language.

Use the existing site shell and styling patterns. Do not add an API route,
polling, SSE, Vercel KV, analytics, credential input, or live evidence sample.

- [ ] **Step 5: Correct conflicting research material**

Update the architecture component and long-form product document so they no
longer say Billy is payer or Iris is payee. On `/handshake`, preserve the
commercial story but clarify that x402 settlement/payment movement is outside
the runnable authorization demo and that static receipts are illustrative,
not current-session evidence.

- [ ] **Step 6: Run focused and repository validation**

Run:

```sh
npx vitest run \
  src/lib/bilateral-handshake-brief.test.tsx \
  src/lib/bilateral-handshake-runbook.test.tsx
npx eslint \
  src/app/handshake/page.tsx \
  src/app/handshake/run/page.tsx \
  src/components/BilateralHandshakeArchitecture.tsx \
  src/components/BilateralHandshakeRunbook.tsx \
  src/data/bilateral-handshake-demo.ts \
  src/lib/bilateral-handshake-brief.test.tsx \
  src/lib/bilateral-handshake-runbook.test.tsx
npm run typecheck
npm test
npm run validate
NEXT_TELEMETRY_DISABLED=1 npm run build
```

Expected: every command exits zero.

- [ ] **Step 7: Commit and publish through the research repository**

Create a Lore-style commit if that repository accepts the protocol; otherwise
follow its local commit contract. Push the reviewed branch and use its existing
PR/Vercel workflow. Verify the deployed `/handshake` and `/handshake/run`
routes with the browser harness; do not claim deployment from a local build.

### Task 10: Integrated review, final verification, and live handoff

**Files:**
- Review: every file changed by Tasks 1–9
- Create: `docs/runbooks/bilateral-demo-live-handoff.md`
- Modify: `scripts/check-docs.mjs`
- Modify: `test/docs.test.mjs`

- [ ] **Step 1: Add the live-handoff gate**

The handoff contains only public or path-level information:

- pinned Handshake release SHA;
- deployed helper URL;
- operator/private-kit location description without secret values;
- treasury address and balance-check command;
- exact four-address funding command;
- operator relay/coordinator/console commands;
- Iris and Billie supervisor commands;
- expected request, mandate, anchor, and verdict markers;
- stop conditions;
- evidence recheck command;
- “implementation-complete and rehearsal-ready” versus “live-demo validated”
  wording.

- [ ] **Step 2: Run independent specification review**

Use a read-only reviewer that did not implement the work. Require a
requirement-by-requirement verdict against
`docs/superpowers/specs/2026-07-28-payer-mandate-live-demo-design.md`. Fix every
blocking or important gap with focused RED/GREEN tests.

- [ ] **Step 3: Run independent security review**

Review:

- exact parsing and signatures;
- request replay and restart atomicity;
- invitation/token/key/capability handling;
- relay authority separation;
- exactly-three-anchor enforcement;
- verifier freshness and publication binding;
- console redaction, CSP, and method restrictions;
- funding nonce/balance/idempotency safety;
- no authorizing literal outside the verifier.

Fix every critical/high finding and rerun the affected focused suites.

- [ ] **Step 4: Run the one final fresh Handshake verification gate**

Only after all implementation and review fixes are committed, run once:

```sh
npm run verify
```

Expected: all tests and documentation checks pass. Capture the exact test count
and gated-document count. Do not rerun the complete suite during iteration;
if this final gate fails, fix with focused tests and restart the final-gate
claim from a new clean run.

- [ ] **Step 5: Perform final secret and authority scans**

Run:

```sh
git diff --check origin/main...HEAD
rg -n -i \
  'BEGIN .*PRIVATE KEY|Bearer [A-Za-z0-9._-]+|invitationCode|clockchain[_-]?token|api[_-]?key\\s*[:=]' \
  --glob '!node_modules/**' \
  --glob '!.context/**'
rg -l 'AUTHORIZED' src bin scripts
```

Expected: the secret scan has no committed secret values. The authorization
scan identifies only the dedicated aggregate-verifier implementation and
explicitly reviewed fixed safety strings/tests.

- [ ] **Step 6: Prepare the live rehearsal without overclaiming it**

Validate the reusable treasury balance and nonce, generate fresh role
addresses, fund exactly four addresses with `0.01` Sepolia ETH each, and
prepare the two private launch packages. These are credentialed external
actions and must use the existing private kit without printing or committing
its contents.

If the two physical stakeholder computers are not connected, stop at:

```text
implementation-complete and rehearsal-ready
```

with the exact next operator/Iris/Billie commands.

- [ ] **Step 7: Run the physical three-computer rehearsal when available**

Require:

- operator on the operator computer;
- Iris payer supervisor on stakeholder computer one;
- Billie payee supervisor on stakeholder computer two;
- one real request and mandate match;
- exactly three fresh anchors;
- live console agreement;
- one fresh verifier `AUTHORIZED`;
- independent evidence recheck;
- `paymentMoved:false`;
- runbook correction for any discovered operational friction.

Only then may the final report say:

```text
live-demo validated
```

- [ ] **Step 8: Publish the final reviewed release**

Create the final Lore commit for any handoff-only changes, push the Handshake
branch, confirm the research-site deployment, record the exact release SHAs,
and leave all private/live artifacts ignored and outside Git.
