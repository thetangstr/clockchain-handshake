# Fresh-Agent Startup Barrier Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Keep the first physical role supervisor alive until both role enrollments exist, expose only sanitized public progress/failure markers, make operator readiness unambiguous, and prove the corrected handoff with a fresh three-agent live run.

**Architecture:** Add a relay-owned, TLS-pinned enrollment-readiness long poll that reports only an advisory boolean and `paymentMoved:false`. A supervisor waits on that advisory surface, then reads and independently verifies the existing authenticated enrollment set before any protocol action. The relay and coordinator emit exact secret-free readiness lines; the supervisor emits one waiting line, one peer-ready line, or one generic fail-closed line without exception text, paths, or private bytes.

**Tech Stack:** Node.js 22, ES modules, `node:test`, pinned HTTPS relay, canonical JSON, existing coordination relay/client/supervisor runtime, deterministic multiprocess fixtures.

---

## File structure

- `src/bilateral/coordination/relay.mjs`: advisory enrollment-readiness wait and bootstrap notification.
- `bin/handshake-relay.mjs`: readiness HTTP route and repository-SHA-bound relay startup line.
- `src/bilateral/coordination/client.mjs`: exact TLS-pinned readiness client and canonical response validation.
- `src/bilateral/coordination/supervisor.mjs`: peer-enrollment barrier before authenticated enrollment-set retrieval.
- `src/bilateral/coordination/supervisor-runtime.mjs`: secret-free waiting/ready status callbacks for production supervisors.
- `bin/handshake-supervisor.mjs`: generic secret-free failure line.
- `src/bilateral/coordination/coordinator-runtime.mjs`: one callback after both launch manifests are durably created.
- `bin/handshake-coordinator.mjs`: secret-free coordinator readiness line.
- `test/bilateral-coordination-relay.test.mjs`: relay wait, timeout, notification, malformed-store, and signal tests.
- `test/bilateral-coordination-client.test.mjs`: exact readiness request and hostile-response tests.
- `test/bilateral-coordination-supervisor.test.mjs`: first-role wait and fail-closed behavior.
- `test/bilateral-coordination-supervisor-runtime.test.mjs`: exact secret-free status-line tests.
- `test/bilateral-coordination-coordinator-runtime.test.mjs`: exactly-once readiness callback tests.
- `test/bilateral-coordination-cli-readiness.test.mjs`: subprocess-visible relay, coordinator, and supervisor line tests.
- `test/bilateral-coordination-process-e2e.test.mjs`: delayed-peer process regression.
- `test/helpers/bilateral-coordination-child.mjs`: bounded delayed-peer start control for the process test.
- `docs/runbooks/bilateral-demo-quick-start.md`: immediately-start-both wording and exact role state paths.
- `docs/runbooks/bilateral-demo-day.md`: readiness markers, peer barrier, and post-bootstrap failure rule.
- `docs/runbooks/bilateral-demo-live-handoff.md`: exact operator signals and recovery boundary.
- `prompts/run-iris-bilateral-demo.md`: expected waiting/ready/failure lines.
- `prompts/run-billie-bilateral-demo.md`: expected waiting/ready/failure lines.
- `scripts/check-docs.mjs` and `test/docs.test.mjs`: drift gates for the corrected manual flow.

### Task 1: Relay enrollment-readiness long poll

**Files:**
- Modify: `test/bilateral-coordination-relay.test.mjs`
- Modify: `src/bilateral/coordination/relay.mjs`

- [ ] **Step 1: Write the failing relay tests**

Add focused tests that create a capability set, bootstrap only payer, begin a readiness wait, and prove it stays pending until payee bootstrap completes:

```js
test("waits for both durable enrollments without treating readiness as authority", async (t) => {
  const { store } = await storeFixture(t);
  await registerRole(store, { capability: PAYER_CAPABILITY, role: "payer" });
  await registerRole(store, { capability: PAYEE_CAPABILITY, role: "payee" });
  const { relay } = relayFixture(store);
  await bootstrapRole(relay, { capability: PAYER_CAPABILITY, role: "payer", ...payerFixture });

  const waiting = relay.readEnrollmentReadiness({
    sessionId: SESSION_ID,
    waitMs: 30_000,
  });
  await bootstrapRole(relay, { capability: PAYEE_CAPABILITY, role: "payee", ...payeeFixture });

  assert.deepEqual(await waiting, {
    paymentMoved: false,
    ready: true,
    repositorySha: REPOSITORY_SHA,
    schema: "clockchain.bilateral-enrollment-readiness/v1",
    sessionId: SESSION_ID,
  });
});
```

Also prove:

- `waitMs:0` returns `ready:false` when one role is missing.
- timeout returns `ready:false` rather than a malformed enrollment set.
- notification occurs only after durable capability consumption succeeds.
- a non-not-found store error fails closed.
- invalid `waitMs`, extra keys, hostile accessors, and aborted signals fail closed.

- [ ] **Step 2: Run the relay tests and verify RED**

Run:

```sh
node --test test/bilateral-coordination-relay.test.mjs
```

Expected: FAIL because `readEnrollmentReadiness` does not exist.

- [ ] **Step 3: Implement the minimal relay wait**

Add exact input key sets, one exact public schema, and a helper that treats only `COORDINATION_ENROLLMENT_NOT_FOUND` as pending:

```js
const ENROLLMENT_READINESS_SCHEMA =
  "clockchain.bilateral-enrollment-readiness/v1";
const READ_ENROLLMENT_READINESS_KEYS = Object.freeze([
  "sessionId",
  "waitMs",
]);
const READ_ENROLLMENT_READINESS_KEYS_WITH_SIGNAL = Object.freeze([
  "sessionId",
  "signal",
  "waitMs",
]);
```

Create the session waiter before checking storage, check both exact roles, and cancel the waiter in `finally`. Call `notifySession(enrollment.sessionId)` only after `consumeCapability` and receipt verification have succeeded. Return only:

```js
Object.freeze({
  paymentMoved: false,
  ready,
  repositorySha: frozenRepositorySha,
  schema: ENROLLMENT_READINESS_SCHEMA,
  sessionId,
});
```

Do not return enrollment bytes, digests, capabilities, addresses, keys, or receipts.

- [ ] **Step 4: Run the relay tests and verify GREEN**

Run:

```sh
node --test test/bilateral-coordination-relay.test.mjs
```

Expected: all relay tests pass.

### Task 2: TLS-pinned readiness route and client

**Files:**
- Modify: `test/bilateral-coordination-client.test.mjs`
- Modify: `test/bilateral-coordination-relay.test.mjs`
- Modify: `bin/handshake-relay.mjs`
- Modify: `src/bilateral/coordination/client.mjs`

- [ ] **Step 1: Write failing route and client tests**

Require the exact request:

```js
assert.deepEqual(requests.at(-1), {
  body: null,
  method: "GET",
  path: `/v1/sessions/${SESSION_ID}/enrollments/readiness?waitMs=30000`,
});
```

Require the exact canonical response:

```js
{
  paymentMoved: false,
  ready: false,
  repositorySha: REPOSITORY_SHA,
  schema: "clockchain.bilateral-enrollment-readiness/v1",
  sessionId: SESSION_ID,
}
```

Reject `paymentMoved:true`, wrong SHA/session/schema, non-boolean readiness, unknown keys, duplicate JSON keys, noncanonical bytes, redirects, plaintext, wrong certificate/fingerprint, wrong content type, oversized body, and a response mutation after validation.

- [ ] **Step 2: Run route/client tests and verify RED**

Run:

```sh
node --test test/bilateral-coordination-client.test.mjs test/bilateral-coordination-relay.test.mjs
```

Expected: FAIL because the route and client method do not exist.

- [ ] **Step 3: Implement route and client**

Add one GET route before the general enrollment-set route:

```text
/v1/sessions/{sessionId}/enrollments/readiness?waitMs={0..30000}
```

Pass the request abort signal into the relay service. Add `readEnrollmentReadiness({waitMs, signal?})` to the role client only. Validate the exact canonical response and return a frozen snapshot. Keep `readEnrollmentSet()` unchanged as the authoritative follow-up.

- [ ] **Step 4: Run route/client tests and verify GREEN**

Run:

```sh
node --test test/bilateral-coordination-client.test.mjs test/bilateral-coordination-relay.test.mjs
```

Expected: all selected tests pass.

### Task 3: Supervisor peer barrier and public status

**Files:**
- Modify: `test/bilateral-coordination-supervisor.test.mjs`
- Modify: `test/bilateral-coordination-supervisor-runtime.test.mjs`
- Modify: `src/bilateral/coordination/supervisor.mjs`
- Modify: `src/bilateral/coordination/supervisor-runtime.mjs`

- [ ] **Step 1: Write failing supervisor tests**

Use a real supervisor loop with readiness results `false`, `false`, `true`. Assert:

```js
assert.equal(readinessReads, 3);
assert.equal(enrollmentSetReads, 1);
assert.deepEqual(statuses, [
  { paymentMoved: false, role: "payer", status: "WAITING_FOR_PEER" },
  { paymentMoved: false, role: "payer", status: "PEER_READY" },
]);
```

Add separate tests proving:

- a readiness exception exits immediately and never calls `readEnrollmentSet`;
- a malformed readiness result exits immediately;
- `ready:true` never substitutes for parsing and independently verifying the enrollment set;
- pending waits do not append events, create artifacts, mint tokens, or invoke Clockchain;
- a payee-first start has the same safe behavior;
- status output is exact canonical JSON and rejects secret canaries.

- [ ] **Step 2: Run supervisor tests and verify RED**

Run:

```sh
node --test test/bilateral-coordination-supervisor.test.mjs test/bilateral-coordination-supervisor-runtime.test.mjs
```

Expected: FAIL because the supervisor immediately reads the enrollment set.

- [ ] **Step 3: Implement the minimal barrier**

Before the existing `client.readEnrollmentSet()` call:

```js
let waitingReported = false;
for (;;) {
  const readiness = await client.readEnrollmentReadiness({
    waitMs: 30_000,
  });
  if (
    readiness?.paymentMoved !== false ||
    typeof readiness.ready !== "boolean"
  ) invalid();
  if (readiness.ready) {
    await dependencies.reportEnrollmentStatus?.({
      paymentMoved: false,
      role: localState.role,
      status: "PEER_READY",
    });
    break;
  }
  if (!waitingReported) {
    await dependencies.reportEnrollmentStatus?.({
      paymentMoved: false,
      role: localState.role,
      status: "WAITING_FOR_PEER",
    });
    waitingReported = true;
  }
}
const enrollmentSet = await client.readEnrollmentSet();
```

Production status output must reconstruct exact fields and never serialize an exception, manifest, path, environment, or live evidence object.

- [ ] **Step 4: Run supervisor tests and verify GREEN**

Run:

```sh
node --test test/bilateral-coordination-supervisor.test.mjs test/bilateral-coordination-supervisor-runtime.test.mjs
```

Expected: all selected tests pass.

### Task 4: Secret-free CLI readiness and failure lines

**Files:**
- Create: `test/bilateral-coordination-cli-readiness.test.mjs`
- Modify: `bin/handshake-relay.mjs`
- Modify: `bin/handshake-coordinator.mjs`
- Modify: `bin/handshake-supervisor.mjs`
- Modify: `src/bilateral/coordination/coordinator-runtime.mjs`

- [ ] **Step 1: Write failing CLI-line tests**

Require exact one-line canonical JSON projections:

```js
{
  host,
  paymentMoved: false,
  pid,
  port,
  repositorySha,
  schema: "clockchain.bilateral-relay-ready/v1",
}
```

```js
{
  launchManifestsReady: true,
  paymentMoved: false,
  releaseId,
  repositorySha,
  schema: "clockchain.bilateral-coordinator-ready/v1",
  sessionId,
}
```

```js
{
  code: "COORDINATION_SUPERVISOR_FAILED",
  paymentMoved: false,
}
```

Inject a secret-canary exception and prove no message, stack, code getter, path, token, invitation, capability, key, or environment value reaches output.

- [ ] **Step 2: Run CLI-line tests and verify RED**

Run:

```sh
node --test test/bilateral-coordination-cli-readiness.test.mjs test/bilateral-coordination-coordinator-runtime.test.mjs
```

Expected: FAIL because repository-bound relay readiness, coordinator readiness, and supervisor failure output are missing.

- [ ] **Step 3: Implement exact output projections**

Add `repositorySha` to the relay running state and readiness line. Invoke one optional coordinator-ready callback immediately after `loadOrCreateCoordinatorRelease` has durably produced both launch manifests and before coordinator waiting begins. Reconstruct only the fields above.

Replace the supervisor CLI’s silent catch with the constant line above. Never include `error.message`, `error.stack`, `error.code`, `String(error)`, or the thrown object itself.

- [ ] **Step 4: Run CLI-line tests and verify GREEN**

Run:

```sh
node --test test/bilateral-coordination-cli-readiness.test.mjs test/bilateral-coordination-coordinator-runtime.test.mjs
```

Expected: all selected tests pass.

### Task 5: Delayed-peer isolated process regression

**Files:**
- Modify: `test/bilateral-coordination-process-e2e.test.mjs`
- Modify: `test/helpers/bilateral-coordination-child.mjs`

- [ ] **Step 1: Write the failing process test**

Add a success scenario that releases the payer bootstrap first, holds payee beyond the previously observed 0.53-second failure window, and asserts the payer process stays alive:

```js
test("first physical supervisor waits for a delayed peer and the release completes", async (t) => {
  const session = await createProcessSession(t, {
    delayedPeerMs: 1_500,
    scenario: "success",
  });
  assert.equal(session.roles.payer.exitBeforePeer, false);
  assert.equal(session.result.paymentMoved, false);
  assert.deepEqual(
    session.result.transitions.map(({ kind }) => kind),
    ["PROPOSED", "ACCEPTED", "ACKNOWLEDGED"],
  );
});
```

The helper must not weaken existing synchronized, restart, or adversarial scenarios.

- [ ] **Step 2: Run the process test and verify RED**

Run:

```sh
node --test test/bilateral-coordination-process-e2e.test.mjs
```

Expected: the new delayed-peer case fails against the current immediate enrollment-set read.

- [ ] **Step 3: Add the minimal delayed-peer test control**

Add one exact optional configuration field used only by the process test. Release payer, wait for its public `WAITING_FOR_PEER` marker, delay 1.5 seconds, then release payee. Do not add production sleeps or timing assumptions.

- [ ] **Step 4: Run the process test and verify GREEN**

Run:

```sh
node --test test/bilateral-coordination-process-e2e.test.mjs
```

Expected: all process E2E cases pass, including delayed peer, restarts, and all adversarial failures.

### Task 6: Correct the handoff instructions and drift gates

**Files:**
- Modify: `docs/runbooks/bilateral-demo-quick-start.md`
- Modify: `docs/runbooks/bilateral-demo-day.md`
- Modify: `docs/runbooks/bilateral-demo-live-handoff.md`
- Modify: `prompts/run-iris-bilateral-demo.md`
- Modify: `prompts/run-billie-bilateral-demo.md`
- Modify: `scripts/check-docs.mjs`
- Modify: `test/docs.test.mjs`

- [ ] **Step 1: Write failing documentation assertions**

Require all handoff surfaces to state:

- both role humans must be ready before either manifest is delivered;
- Iris is told first and Billie immediately afterward, without waiting for Iris completion;
- the first supervisor may print `WAITING_FOR_PEER` and must remain alive;
- both supervisors must print `PEER_READY` before enrollment-confirmed progress;
- exact examples define `IRIS_SUPERVISOR_STATE` and `BILLIE_SUPERVISOR_STATE` as separate fresh mode-`0700` directories;
- relay readiness includes the reviewed repository SHA;
- coordinator readiness explicitly confirms both launch manifests are ready;
- the only public supervisor failure is `COORDINATION_SUPERVISOR_FAILED`;
- after that failure, do not retry or reuse a retired manifest; preserve state and diagnose exact recovery;
- readiness is advisory and never substitutes for authenticated enrollment-set verification;
- only the fresh aggregate verifier can issue the final verdict;
- exactly three anchors and `paymentMoved:false` remain unchanged.

- [ ] **Step 2: Run docs tests and verify RED**

Run:

```sh
node --test test/docs.test.mjs
```

Expected: FAIL because the corrected barrier and public markers are not documented.

- [ ] **Step 3: Update prompts and runbooks**

Use concise operator language. Keep security/testnet caveats after the primary steps. Do not add manual evidence copying, extra role sessions, a fourth anchor, or an operator-authored commercial term.

- [ ] **Step 4: Run docs tests and verify GREEN**

Run:

```sh
node --test test/docs.test.mjs
npm run docs:check
```

Expected: all documentation gates pass.

### Task 7: Integrated review and deterministic verification

**Files:**
- Review every changed file above.

- [ ] **Step 1: Run the focused integration set**

```sh
node --test \
  test/bilateral-coordination-relay.test.mjs \
  test/bilateral-coordination-client.test.mjs \
  test/bilateral-coordination-supervisor.test.mjs \
  test/bilateral-coordination-supervisor-runtime.test.mjs \
  test/bilateral-coordination-coordinator-runtime.test.mjs \
  test/bilateral-coordination-cli-readiness.test.mjs \
  test/bilateral-coordination-process-e2e.test.mjs \
  test/docs.test.mjs
```

Expected: zero failures.

- [ ] **Step 2: Request independent code and security review**

Reviewers must check:

- readiness remains advisory;
- the authenticated enrollment set remains authoritative;
- missing peer is the only condition that waits;
- malformed, duplicate, mismatched, replayed, expired, or corrupted evidence still fails closed;
- readiness adds no capability replay or secret leakage;
- supervisor output cannot serialize hostile exceptions;
- no console/operator surface emits the verifier-only authorization literal;
- no fourth Clockchain anchor is introduced.

- [ ] **Step 3: Address every critical or important finding**

Use a new failing test before each behavior change. Rerun the affected focused tests after each fix.

### Task 8: Fresh three-agent live retest

**Files:**
- No repository edits during the live run.
- Private live artifacts remain outside Git.

- [ ] **Step 1: Freeze and prepare the corrected immutable release**

Commit the reviewed implementation with a Lore-format message. Create three new clean detached checkouts at that exact 40-character SHA, run Node.js 22 and `npm ci --ignore-scripts`, and verify all are clean.

- [ ] **Step 2: Start three blank-context agents**

Use `fork_turns:"none"`:

- fresh Demo Director reads only the checked-in quick-start, live handoff, and full runbook;
- fresh Iris reads only `prompts/run-iris-bilateral-demo.md`;
- fresh Billie reads only `prompts/run-billie-bilateral-demo.md`.

The root agent provides only checkout paths, private path references, advertised LAN IP, and sibling agent names. It does not translate the procedure.

- [ ] **Step 3: Execute the live flow**

The Director starts relay, coordinator, console, stages funding, delivers payer then payee manifests without waiting for Iris completion, observes both peer-ready markers, waits for the signed funding record, funds exactly four fresh addresses with `0.01 Sepolia ETH` each, and lets both long-lived supervisors complete rehearsal and stakeholder runs.

- [ ] **Step 4: Independently verify live success**

Require:

- exactly three ordered anchors for each subject run: Iris `PROPOSED`, Billie `ACCEPTED`, Iris `ACKNOWLEDGED`;
- fresh aggregate-verifier publication and marker-complete verdict;
- `paymentMoved:false`;
- no missing, duplicate, reordered, expired, malformed, or mismatched evidence;
- no authority taken from relay, readiness, watcher, console, coordinator, or role output;
- no secret bytes in transcripts, Git, docs, or public pages.

If the live run fails, preserve artifacts, diagnose read-only, add a failing regression test, fix through red-green, review again, create a new immutable SHA, and repeat with fresh invitations and addresses.

### Task 9: Final repository gate

- [ ] **Step 1: Run one fresh complete verification**

```sh
npm run verify
```

Expected: exit 0 with zero failures.

- [ ] **Step 2: Audit the completion claims**

Confirm the focused tests, process E2E, docs gates, independent review, fresh-agent live run, three anchors, aggregate verifier, and `paymentMoved:false` are all backed by fresh evidence. Do not declare completion if any item is missing or indirect.
