# Hermes Role Completion Status Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the existing Payer and Requestor Hermes sessions visibly finish at their authenticated role-local terminal states without another human prompt.

**Architecture:** Extend the supervisor's secret-free status projection with one exact `PARTY_COMPLETE` contract, then emit it only when authenticated supervisor replay reaches `COMPLETE`. Keep the current Hermes prompt sequence, but require each role agent to remain attached until that terminal line; the separate fresh aggregate verifier remains the only source of `AUTHORIZED`.

**Tech Stack:** Node.js 22, ES modules, `node:test`, deterministic multiprocess tests, Next.js 16, React 19, Vitest, Vercel.

---

## File Map

### Clockchain Handshake repository

- Modify `src/bilateral/coordination/supervisor-runtime.mjs`
  - Serialize only the two exact secret-free role-completion status mappings.
- Modify `src/bilateral/coordination/supervisor.mjs`
  - Emit role completion only after authenticated replay reaches `COMPLETE`.
- Modify `test/bilateral-coordination-supervisor-runtime.test.mjs`
  - Lock the completion allowlist and hostile rejection cases.
- Modify `test/bilateral-coordination-supervisor.test.mjs`
  - Prove nonterminal supervisor states do not emit completion.
- Modify `test/bilateral-coordination-process-e2e.test.mjs`
  - Prove one terminal completion line per physical role in the integrated flow.
- Modify `prompts/run-payer-bilateral-demo.md`
  - Require Payer to wait for exact `PARTY_COMPLETE` / `ACKNOWLEDGED`.
- Modify `prompts/run-requestor-bilateral-demo.md`
  - Require Requestor to wait for exact `PARTY_COMPLETE` / `ACCEPTED`.
- Modify `docs/runbooks/bilateral-demo-quick-start.md`
- Modify `docs/runbooks/bilateral-demo-day.md`
- Modify `docs/runbooks/bilateral-demo-live-handoff.md`
  - Distinguish intermediate readiness from terminal role completion.
- Modify `test/docs.test.mjs`
- Modify `scripts/check-docs.mjs`
  - Lock the new operational documentation contract.

### Clockchain Research site

- Modify `.context/clockchain-research-site/src/components/BilateralHandshakeRunbook.tsx`
  - Add terminal waiting/reporting instructions without adding prompt cards.
- Modify `.context/clockchain-research-site/src/lib/bilateral-handshake-runbook.test.tsx`
  - Prove both role prompts contain their exact terminal state and the page still has six copy controls.
- Modify `.context/clockchain-research-site/src/data/bilateral-handshake-demo.ts`
  - Pin the new reviewed public release SHA after the Handshake branch is published.

---

### Task 1: Lock the exact secret-free completion status

**Files:**
- Modify: `test/bilateral-coordination-supervisor-runtime.test.mjs`
- Modify: `src/bilateral/coordination/supervisor-runtime.mjs`

- [ ] **Step 1: Write the failing serializer tests**

Extend `projects supervisor status lines through an exact secret-free allowlist`
with the two accepted values:

```js
assert.equal(
  createSupervisorStatusLine({
    paymentMoved: false,
    role: "payer",
    state: "ACKNOWLEDGED",
    status: "PARTY_COMPLETE",
  }),
  '{"paymentMoved":false,"role":"payer","state":"ACKNOWLEDGED","status":"PARTY_COMPLETE"}\n',
);
assert.equal(
  createSupervisorStatusLine({
    paymentMoved: false,
    role: "payee",
    state: "ACCEPTED",
    status: "PARTY_COMPLETE",
  }),
  '{"paymentMoved":false,"role":"payee","state":"ACCEPTED","status":"PARTY_COMPLETE"}\n',
);
for (const value of [
  { paymentMoved: false, role: "payer", state: "ACCEPTED", status: "PARTY_COMPLETE" },
  { paymentMoved: false, role: "payee", state: "ACKNOWLEDGED", status: "PARTY_COMPLETE" },
  { paymentMoved: false, role: "payer", state: "AUTHORIZED", status: "PARTY_COMPLETE" },
  { paymentMoved: false, role: "operator", state: "ACKNOWLEDGED", status: "PARTY_COMPLETE" },
  { paymentMoved: false, privateKeyPem: "secret", role: "payer", state: "ACKNOWLEDGED", status: "PARTY_COMPLETE" },
]) {
  assert.throws(() => createSupervisorStatusLine(value));
}
```

- [ ] **Step 2: Run the focused test and observe RED**

Run:

```sh
node --test test/bilateral-coordination-supervisor-runtime.test.mjs
```

Expected: the accepted `PARTY_COMPLETE` values fail because the serializer does
not yet recognize that status.

- [ ] **Step 3: Implement the exact serializer branch**

In `createSupervisorStatusLine`, add a `PARTY_COMPLETE` branch before the
existing readiness-status validation:

```js
if (value?.status === "PARTY_COMPLETE") {
  const keys = ["paymentMoved", "role", "state", "status"];
  if (
    Object.keys(value).length !== keys.length ||
    keys.some((key) => !Object.hasOwn(value, key)) ||
    value.paymentMoved !== false ||
    !["payer", "payee"].includes(value.role) ||
    value.state !== (value.role === "payer" ? "ACKNOWLEDGED" : "ACCEPTED")
  ) {
    fail();
  }
  return `${canonicalJson(value)}\n`;
}
```

Do not broaden the existing readiness allowlist and do not accept
`AUTHORIZED`.

- [ ] **Step 4: Run the focused test and observe GREEN**

Run:

```sh
node --test test/bilateral-coordination-supervisor-runtime.test.mjs
```

Expected: all tests pass.

- [ ] **Step 5: Commit the serializer contract**

```sh
git add src/bilateral/coordination/supervisor-runtime.mjs test/bilateral-coordination-supervisor-runtime.test.mjs
git commit
```

Use a Lore commit whose intent is to expose terminal role state without leaking
authority or private data.

---

### Task 2: Write the authenticated completion gate tests

**Files:**
- Modify: `test/bilateral-coordination-supervisor.test.mjs`
- Modify: `test/bilateral-coordination-process-e2e.test.mjs`

- [ ] **Step 1: Add the nonterminal regression guard**

In `waits for peer enrollment readiness before the authoritative enrollment
set`, preserve the existing expected statuses and add:

```js
assert.equal(
  status.some((value) => value.status === "PARTY_COMPLETE"),
  false,
);
```

This guard should pass against the current implementation and locks the
nonterminal side of the gate before the terminal behavior is added.

- [ ] **Step 2: Add abort and failure regression guards**

Add a signed `TERMINAL_FAILURE` event to a `replayFixture()` snapshot, return
that snapshot from `readEvents`, collect `writeStatus`, and assert:

```js
assert.equal(result.view.state, "ABORTED");
assert.equal(
  status.some((value) => value.status === "PARTY_COMPLETE"),
  false,
);
```

In `stops Payer MCP when readiness polling fails after listener start`, also
collect `writeStatus` and assert that the failure path emitted no
`PARTY_COMPLETE` value. Preserve its existing listener-cleanup assertions.

Both guards should pass before production changes.

- [ ] **Step 3: Write the failing integrated assertions**

After parsing `payerStdoutLines` and `payeeStdoutLines`, add:

```js
assert.deepEqual(
  payerStdoutLines.filter((line) => line.status === "PARTY_COMPLETE"),
  [{
    paymentMoved: false,
    role: "payer",
    state: "ACKNOWLEDGED",
    status: "PARTY_COMPLETE",
  }],
);
assert.deepEqual(
  payeeStdoutLines.filter((line) => line.status === "PARTY_COMPLETE"),
  [{
    paymentMoved: false,
    role: "payee",
    state: "ACCEPTED",
    status: "PARTY_COMPLETE",
  }],
);
assert.equal(
  [...payerStdoutLines, ...payeeStdoutLines].some(
    (line) => line.state === "AUTHORIZED" || line.status === "AUTHORIZED",
  ),
  false,
);
```

- [ ] **Step 4: Run both gate tests and observe the expected split result**

Run:

```sh
node --test test/bilateral-coordination-supervisor.test.mjs
node --test test/bilateral-coordination-process-e2e.test.mjs
```

Expected: the supervisor unit test passes its nonterminal, abort, and failure
guards, while the integrated process test fails because neither completed
supervisor emits `PARTY_COMPLETE`.

Do not modify production code until this RED result is observed.

---

### Task 3: Emit completion only from authenticated supervisor `COMPLETE`

**Files:**
- Modify: `src/bilateral/coordination/supervisor.mjs`
- Include already-modified tests:
  `test/bilateral-coordination-supervisor.test.mjs`
  and `test/bilateral-coordination-process-e2e.test.mjs`

- [ ] **Step 1: Add the role completion mapper**

Near the other supervisor-local helpers, add:

```js
function partyCompletionStatus(role) {
  if (!["payer", "payee"].includes(role)) invalid();
  return Object.freeze({
    paymentMoved: false,
    role,
    state: role === "payer" ? "ACKNOWLEDGED" : "ACCEPTED",
    status: "PARTY_COMPLETE",
  });
}
```

- [ ] **Step 2: Split terminal replay handling**

Replace the combined terminal return:

```js
if (["COMPLETE", "ABORTED"].includes(replay.view.state)) {
  return Object.freeze({
    ...replay,
    processedEventDigests: Object.freeze([...processed]),
  });
}
```

with:

```js
if (replay.view.state === "COMPLETE") {
  if (typeof dependencies.writeStatus === "function") {
    dependencies.writeStatus(partyCompletionStatus(localState.role));
  }
  return Object.freeze({
    ...replay,
    processedEventDigests: Object.freeze([...processed]),
  });
}
if (replay.view.state === "ABORTED") {
  return Object.freeze({
    ...replay,
    processedEventDigests: Object.freeze([...processed]),
  });
}
```

The immediate return makes completion single-shot for the one approved
supervisor invocation. `ABORTED` emits nothing.

- [ ] **Step 3: Run the unit and integrated tests and observe GREEN**

Run:

```sh
node --test test/bilateral-coordination-supervisor.test.mjs
node --test test/bilateral-coordination-process-e2e.test.mjs
```

Expected: the nonterminal guard passes, there is one mapped completion line
per physical role, no role authorization literal, and all existing
three-anchor assertions pass.

- [ ] **Step 4: Run the Requestor wrapper regression tests**

Run:

```sh
node --test test/bilateral-request-payment-cli.test.mjs
```

Expected: the initial `HANDSHAKE_REQUIRED` projection remains unchanged and the
wrapper still delegates long-lived completion to the supervisor.

- [ ] **Step 5: Commit the integrated proof**

```sh
git add src/bilateral/coordination/supervisor.mjs test/bilateral-coordination-supervisor.test.mjs test/bilateral-coordination-process-e2e.test.mjs
git commit
```

Use a Lore commit recording that authenticated `COMPLETE` is the only role
completion authority, `ABORTED` emits nothing, and physical-role visibility is
the acceptance criterion.

---

### Task 4: Make existing role prompts wait for terminal completion

**Files:**
- Modify: `prompts/run-payer-bilateral-demo.md`
- Modify: `prompts/run-requestor-bilateral-demo.md`
- Modify: `docs/runbooks/bilateral-demo-quick-start.md`
- Modify: `docs/runbooks/bilateral-demo-day.md`
- Modify: `docs/runbooks/bilateral-demo-live-handoff.md`
- Modify: `test/docs.test.mjs`
- Modify: `scripts/check-docs.mjs`

- [ ] **Step 1: Write failing documentation assertions**

Add exact checks to `test/docs.test.mjs`:

```js
assert.match(
  payer,
  /PARTY_COMPLETE[\s\S]*ACKNOWLEDGED[\s\S]*not authorization/i,
);
assert.match(
  requestor,
  /PARTY_COMPLETE[\s\S]*ACCEPTED[\s\S]*not authorization/i,
);
```

Add corresponding `scripts/check-docs.mjs` gates for:

```js
["Payer terminal role status", /PARTY_COMPLETE[\s\S]*ACKNOWLEDGED/i],
["Requestor terminal role status", /PARTY_COMPLETE[\s\S]*ACCEPTED/i],
["No post-funding role prompt", /no additional Hermes (?:message|prompt)/i],
```

- [ ] **Step 2: Run docs checks and observe RED**

Run:

```sh
node --test test/docs.test.mjs
node scripts/check-docs.mjs
```

Expected: the new `PARTY_COMPLETE` documentation requirements are absent.

- [ ] **Step 3: Update both role prompts**

Add this Payer instruction immediately after the long-lived supervisor command:

```md
`PAYER_MCP_READY`, `WAITING_FOR_PEER`, and `PEER_READY` are intermediate.
Keep the same supervisor attached through operator funding. Do not conclude the
role until it emits exact secret-free `PARTY_COMPLETE` with role `payer`, state
`ACKNOWLEDGED`, and `paymentMoved:false`. Report that role-local status as Payer's
finish; it is not authorization. Never emit `AUTHORIZED`.
```

Add this Requestor instruction immediately after the wrapper command:

```md
`HANDSHAKE_REQUIRED`, `WAITING_FOR_PEER`, and `PEER_READY` are intermediate.
Keep the same wrapper/supervisor attached through operator funding. Do not
conclude the role until it emits exact secret-free `PARTY_COMPLETE` with role
`payee`, state `ACCEPTED`, and `paymentMoved:false`. Report that role-local
status as Requestor's finish; it is not authorization. Never emit `AUTHORIZED`.
```

- [ ] **Step 4: Update the three runbooks**

State in each runbook:

```md
No additional Hermes message is required after operator funding. Payer remains
attached until `PARTY_COMPLETE` / `ACKNOWLEDGED`; Requestor remains attached
until `PARTY_COMPLETE` / `ACCEPTED`. These role-local endpoints are not
authorization. Only the fresh aggregate verifier may emit `AUTHORIZED`.
```

Keep the protocol order and exactly-three-anchor language unchanged.

- [ ] **Step 5: Run docs checks and observe GREEN**

Run:

```sh
node --test test/docs.test.mjs
node scripts/check-docs.mjs
```

Expected: both commands pass.

- [ ] **Step 6: Commit the role-facing contract**

```sh
git add prompts/run-payer-bilateral-demo.md prompts/run-requestor-bilateral-demo.md docs/runbooks/bilateral-demo-quick-start.md docs/runbooks/bilateral-demo-day.md docs/runbooks/bilateral-demo-live-handoff.md test/docs.test.mjs scripts/check-docs.mjs
git commit
```

Use a Lore commit recording that no post-funding Hermes message is required.

---

### Task 5: Verify and publish the reviewed Handshake release

**Files:**
- Review all files changed in Tasks 1–4.

- [ ] **Step 1: Run focused security-sensitive tests**

Run:

```sh
node --test \
  test/bilateral-coordination-supervisor-runtime.test.mjs \
  test/bilateral-coordination-supervisor.test.mjs \
  test/bilateral-request-payment-cli.test.mjs \
  test/bilateral-coordination-process-e2e.test.mjs \
  test/docs.test.mjs
node scripts/check-docs.mjs
```

Expected: all focused tests and documentation gates pass.

- [ ] **Step 2: Review the complete diff**

Run:

```sh
git diff 09f7ec92c15baec43cf39703446dd247ee6cbda4...HEAD
git diff --check
```

Confirm:

- no private data or live evidence entered Git;
- no role emits `AUTHORIZED`;
- completion depends only on authenticated `COMPLETE`;
- `ABORTED` and failures emit no completion;
- existing prompt count and order are unchanged.

- [ ] **Step 3: Run one fresh complete repository verification**

Run:

```sh
npm run verify
```

Expected: the complete suite and all documentation gates pass.

- [ ] **Step 4: Obtain independent integrated review**

Request review of the integrated diff against:

- exact Payer/Requestor authority;
- fresh-verifier-only authorization;
- duplicate/premature completion resistance;
- secret-free output;
- manual Hermes acceptance criteria.

Fix accepted findings with focused failing tests before implementation edits.

- [ ] **Step 5: Rerun final verification after any review fixes**

Run:

```sh
npm run verify
```

Expected: complete pass on the final diff.

- [ ] **Step 6: Publish the immutable public release**

Push the reviewed branch:

```sh
git push origin codex/fresh-agent-demo-director
```

Record the exact 40-character branch-head SHA:

```sh
git rev-parse HEAD
```

This SHA becomes the new public handbook release pin.

---

### Task 6: Update and publish the public manual handbook

**Files:**
- Modify: `.context/clockchain-research-site/src/components/BilateralHandshakeRunbook.tsx`
- Modify: `.context/clockchain-research-site/src/lib/bilateral-handshake-runbook.test.tsx`
- Modify: `.context/clockchain-research-site/src/data/bilateral-handshake-demo.ts`

- [ ] **Step 1: Create a site branch**

From `.context/clockchain-research-site`:

```sh
git switch main
git pull --ff-only
git switch -c codex/handshake-party-complete
```

- [ ] **Step 2: Write failing handbook assertions**

Add:

```tsx
expect(html).toContain(
  "Keep the same Payer supervisor attached until exact",
);
expect(html).toContain(
  "<code>PARTY_COMPLETE</code> with state <code>ACKNOWLEDGED</code>",
);
expect(html).toContain(
  "Keep the same Requestor wrapper attached until exact",
);
expect(html).toContain(
  "<code>PARTY_COMPLETE</code> with state <code>ACCEPTED</code>",
);
expect(html).toContain(
  "No additional Hermes message is required after operator funding.",
);
expect(html.match(/class=\"bilateral-runbook__prompt-copy-icon\"/g)).toHaveLength(6);
```

Update the expected reviewed SHA to the exact published Handshake branch head.

- [ ] **Step 3: Run the focused site test and observe RED**

Run:

```sh
npm test -- src/lib/bilateral-handshake-runbook.test.tsx
```

Expected: the terminal role instructions are missing.

- [ ] **Step 4: Update the existing launch/action prompts**

Add the same terminal instructions from Task 4 to `payerLaunchPrompt` and
`requestPaymentPrompt`. In Step 5, add:

```tsx
<p>
  No additional Hermes message is required after operator funding. Payer ends
  at <code>PARTY_COMPLETE</code> / <code>ACKNOWLEDGED</code>; Requestor ends at{" "}
  <code>PARTY_COMPLETE</code> / <code>ACCEPTED</code>. The separate fresh
  aggregate verifier remains the only source of <code>AUTHORIZED</code>.
</p>
```

Do not add or remove prompt cards or copy controls.

- [ ] **Step 5: Pin the new reviewed SHA**

Set `bilateralDemoReleaseEvidence.sha` to the exact 40-character SHA published
in Task 5. Do not use a branch name, tag, or abbreviated revision.

- [ ] **Step 6: Run site verification**

Run:

```sh
npm test
npx eslint src/components/BilateralHandshakeRunbook.tsx src/lib/bilateral-handshake-runbook.test.tsx src/data/bilateral-handshake-demo.ts
npm run typecheck
npm run build
```

Expected: all site tests pass, changed files lint cleanly, typecheck passes, and
the production build succeeds. Record unrelated repository-wide lint failures
separately if the existing baseline remains red.

- [ ] **Step 7: Commit, push, review, merge, and deploy**

Create a Lore commit, push `codex/handshake-party-complete`, open a pull request
to `main`, and merge after the Vercel preview succeeds. Verify the production
page:

```text
https://clockchain-research.vercel.app/handshake/run
```

Check that it contains both terminal role mappings, still exposes six copy
controls, and contains no private paths, tokens, invitations, keys, or live
evidence.

---

### Task 7: Run the corrected fresh Hermes acceptance test

**Files:**
- Generate only fresh private operator and role state outside Git.
- Preserve final verifier evidence outside Git.

- [ ] **Step 1: Confirm live-run prerequisites**

Verify:

- the public Handshake repository resolves the new reviewed SHA;
- the public handbook pins the same SHA;
- the operator, Payer, and Requestor roots are new and separate;
- the treasury can fund four new addresses with `0.01 Sepolia ETH` each plus
  fees;
- the Payer raw-TCP relay is available;
- no prior manifest, role root, certificate, journal, or evidence path is
  reused.

If the treasury is below the required amount, use only the already-approved
single `0.05 Sepolia ETH` faucet replenishment workflow at the eligible window.
Do not retry a rate limit.

- [ ] **Step 2: Start two fresh Hermes conversations**

Use profiles `handshake_payer` and `handshake_requester`. Copy the six existing
public prompts from the production handbook in their existing order and provide
only the two fresh private handoff messages already required by the handbook.
Do not add a post-funding Hermes message.

- [ ] **Step 3: Run the live operator sequence**

Start the fresh relay, coordinator, and read-only console only after both roles
are staged. Fund the coordinator-owned four-address record once through a fresh
mode-`0700` funding journal.

- [ ] **Step 4: Verify both Hermes endings**

Require the visible Payer conversation to end with:

```json
{"paymentMoved":false,"role":"payer","state":"ACKNOWLEDGED","status":"PARTY_COMPLETE"}
```

Require the visible Requestor conversation to end with:

```json
{"paymentMoved":false,"role":"payee","state":"ACCEPTED","status":"PARTY_COMPLETE"}
```

Reject the rehearsal if either conversation remains at readiness, peer wait,
funding wait, or contains `AUTHORIZED`.

- [ ] **Step 5: Run a fresh aggregate verifier**

Use a fresh verifier output directory and independently verify exactly:

```text
PROPOSED → ACCEPTED → ACKNOWLEDGED
```

Require exact `AUTHORIZED` from that verifier and
`paymentMoved:false`. Confirm the operator console remains read-only and does
not emit the authorization literal.

- [ ] **Step 6: Record the acceptance outcome**

Keep the secret-free presentation record with:

- reviewed repository SHA;
- Payer and Requestor terminal status lines;
- three Clockchain ledger IDs and block heights;
- fresh verifier outcome;
- `paymentMoved:false`;
- funding transaction hashes and confirmed receipt count.

Do not commit private paths, tokens, invitations, capabilities, keys,
certificates, fingerprints, generated addresses, or live evidence packages.
