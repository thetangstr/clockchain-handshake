# Bilateral Operational Demo Implementation Plan

> Round 2 is committed at `2ba79dc`. This plan turns the frozen protocol data
> model into two role runners and one independent operator verdict without
> weakening any trust boundary.

**Goal:** Deliver a deterministic and then live two-machine Clockchain demo in
which Billy proposes USD 100, Iris accepts that exact proposal, Billy
acknowledges the exact acceptance, and only a fresh operator verifier can emit
`AUTHORIZED`.

**Invariant:** No code path moves money. Every message, party result, terminal
result, and aggregate verdict must preserve `paymentMoved: false`.

**Architecture:** The role runners share one fail-closed orchestration module
but have separate CLI entrypoints and role prompts. They write only canonical
transition digests, immediately rediscover and independently verify every
anchor, sign the frozen party-signature preimage, and publish marker-complete
party evidence. A separate process consumes neither runner state nor advisory
Clockchain fields: it reloads both packages, verifies signatures and descriptor
provenance, reruns all three Clockchain recipes and audit counts, obtains sharper
deadline upper bounds, and is the sole owner of the authorizing verdict.

**Runtime:** Node.js 22, ES modules, `node:test`, existing `viem` dependency,
existing hardened Clockchain MCP client, and the Round 2 deterministic fake.

## Operating contract

- Sol owns planning, shared-file coordination, integration, final verification,
  commits, publication, and the live completion verdict.
- Terra owns substantive implementation and focused tests under one writable
  owner per file.
- Luna owns read-only audits and independent reviews.
- Every behavior change follows RED -> GREEN -> refactor.
- No invitation, token, private key, generated live address secret, or live
  evidence enters Git.
- Agent CLIs must not contain or print the authorizing verdict literal.
- A failed or ambiguous write is never retried. An existing write-intent marker
  makes that slot discovery-only.
- Empty discovery before the poll deadline means continue; an empty result after
  the deadline is `EXPIRED`. A rate limit is never interpreted as absence.

## Task 1: Shared runner orchestration and write discipline

**Files**

- Create: `src/bilateral/runner.mjs`
- Create: `test/bilateral-runner.test.mjs`

**TDD requirements**

1. Pin exact runner configuration, output, and write-intent marker schemas.
2. Implement an exclusive, fsync'd marker containing only
   `{sessionDigest, slot, digest, referenceId}`.
3. Prove a pre-existing marker prevents every write and switches to discovery.
4. Before a write, search the derived key:
   - zero records permits one write;
   - one digest-identical record is adopted;
   - one mismatched record fails;
   - more than one record is `DUPLICATE`;
   - rate-limit and malformed bodies never become absence.
5. Send the exact `logAction` arguments from design section 4.8, including
   `allow_degraded: true`, and never send `content`, free-form metadata, or
   authorizing text.
6. On timeout, transport error, or unknown result, mark the slot permanently
   discovery-only and return `AMBIGUOUS_WRITE`.
7. Immediately perform mandatory search and cross-party read-back before the
   peer can use the key.
8. Implement a bounded poller with injected monotonic clock/sleeper/jitter:
   minimum 20-second spacing, `Retry-After` support, eight-minute cap, and
   deadline-aware empty-result handling.
9. Compose `verifyTransition`, live upper bounds, state-machine transitions, and
   marker-complete party-result publication without importing advisory APIs.
10. Test crash/resume, marker races, symlinks, output reuse, malformed callbacks,
    hostile errors, and zero blind retries.

**Checks**

```bash
node --test test/bilateral-runner.test.mjs
node --check src/bilateral/runner.mjs
```

## Task 2: Billy and Iris role runners

**Files**

- Create: `bin/handshake-propose.mjs`
- Create: `bin/handshake-accept.mjs`
- Create: `src/bilateral/roles.mjs`
- Create: `test/bilateral-roles.test.mjs`

**Billy flow**

1. Load and verify the signed descriptor and repository-pinned operator key.
2. Resolve both ERC-8004 identities and verify on-chain owners before a network
   write.
3. Choose exactly USD 100 from the signed amount allowlist.
4. Build, write, rediscover, and verify M1.
5. Poll for the exact M2 key; reconstruct and verify M2 against Billy's own
   authoritative M1 triple.
6. Build, write, rediscover, and verify M3.
7. Sign the frozen payer preimage (M1 + M3), emit marker-complete payer evidence,
   and stop at local state `ACKNOWLEDGED`.

**Iris flow**

1. Perform the same descriptor and identity checks.
2. Poll for M1, enumerate at most eight signed amount options, and recover the
   unique proposal by digest.
3. Verify the authoritative M1 before constructing M2.
4. Build, write, rediscover, and verify M2 bound to the exact M1 triple.
5. Optionally observe M3 without treating absence as failure of her acceptance.
6. Sign the frozen payee preimage (M2), emit marker-complete payee evidence, and
   stop at local state `ACCEPTED`.

**CLI gates**

- Exact arguments only: descriptor, invitation path, private-key source,
  output directory, and explicit operator risk acknowledgement.
- Read secrets through no-follow bounded file descriptors; never accept secrets
  on argv or print them.
- Fixed typed stdout/stderr and exit codes.
- The role source and all output tests prove the authorizing literal is absent.

**Checks**

```bash
node --test test/bilateral-roles.test.mjs
node --check bin/handshake-propose.mjs
node --check bin/handshake-accept.mjs
```

## Task 3: Independent aggregate verifier

**Files**

- Create: `src/bilateral/verdict.mjs`
- Create: `scripts/verify-bilateral-results.mjs`
- Create: `test/bilateral-verdict.test.mjs`

**Pure verifier requirements**

1. Load only marker-complete payer/payee result directories and verify marker
   hashes before parsing either package.
2. Revalidate both packages, the signed descriptor, repository key provenance,
   repository SHA, prompt SHA, session digest, protocol version, distinct roles,
   and `paymentMoved: false`.
3. Reconstruct the frozen payer/payee signing preimages and recover both EIP-191
   addresses with `viem`; require agreement with:
   - descriptor address;
   - `resolveAgent(agentId).owner`;
   - direct ERC-8004 `ownerOf(agentId)` call.
4. Require distinct payer and payee owners.
5. Independently rerun the three `verifyTransition` recipes.
6. Require each `generateAuditTrail(K).count === "1"` and all ledger IDs unique.
7. Fetch `getBlock(h + 1)` where available for verifier upper bounds; fall back
   only to the approved conservative live bound when the next block is not
   independently verifiable, and fail closed on ambiguity.
8. Require strict M1 < M2 < M3 heights, exact predecessor triples, exact
   descriptor/message terms, and both later upper bounds at or before deadline.
9. Ignore every banned cache, package, status, advisory, and validation field.
10. Emit exact `clockchain.bilateral-authorization-verdict/v1` JSON and Markdown.
    This module/script is the only repository surface permitted to emit
    `AUTHORIZED`; all failures emit a non-authorizing terminal result.

**Adversarial matrix**

- Missing/extra/incomplete marker files.
- Mismatched packages, SHAs, prompts, sessions, roles, owners, signatures, and
  payment flags.
- Missing, duplicated, reordered, same-block, late, malformed, or forged anchors.
- Audit counts zero or greater than one.
- Wrong-height/correct-hash advisory trap.
- Inactive identities, reused owner, bad `ownerOf`, and live API failures.
- Hostile JSON/object inputs and secret canaries.

**Checks**

```bash
node --test test/bilateral-verdict.test.mjs
node --check scripts/verify-bilateral-results.mjs
```

## Task 4: Mandatory two-client preflight probe

**Files**

- Create: `scripts/probe-bilateral-rendezvous.mjs`
- Create: `test/bilateral-preflight.test.mjs`

**Requirements**

1. Generate one public probe nonce and derive the Billy/Iris probe keys.
2. Consume exactly the two pre-approved throwaway writes, one from each client.
3. From the opposite credential/machine, test derived-reference discovery and
   digest-hash fallback independently.
4. Capture the exact rate-limit wire shape, retry metadata, scope observations,
   and sustainable serialized cadence without exposing credentials.
5. Produce a signed, secret-free preflight report describing channel and tenancy
   conservatively.
6. Fail `RENDEZVOUS_UNAVAILABLE` before invitations/funding/session state if
   neither channel crosses clients within the bounded window.
7. Deterministic fake tests cover same-client, cross-client, unknown tenancy,
   asymmetric visibility, throttling, malformed bodies, and exhausted budget.

## Task 5: Live session watcher

**Files**

- Create: `scripts/watch-bilateral-session.mjs`
- Create: `test/bilateral-watcher.test.mjs`

**Requirements**

- Read-only observer; never owns protocol decisions or writes.
- Display derived keys, discovered cardinality, verified heights/times, deadline,
  and non-authorizing runner states.
- Label advisory health/status fields as disclosure only.
- Redact invitations, tokens, private keys, emails, and canaries.
- Never print the authorizing verdict; only the aggregate verifier may.

## Task 6: Role prompts, runbook, and documentation gates

**Files**

- Create: `prompts/run-billy-bilateral-demo.md`
- Create: `prompts/run-iris-bilateral-demo.md`
- Create: `docs/runbooks/bilateral-demo-day.md`
- Modify: `scripts/check-docs.mjs`
- Modify: `README.md`
- Test: `test/docs.test.mjs`

**Requirements**

1. Add both prompts and the runbook to public document gates in the same commit.
2. Pin machine roles, immutable repository SHA, exact commands, artifact names,
   safe failure language, and prohibition on improvising success.
3. State the honest Clockchain claim: Iris reconstructed and verified Billy's
   anchored proposal; do not claim she downloaded message bytes from Clockchain.
4. Document Phase -1 probe, four funded addresses, invitation handling,
   synchronized start, watcher use, artifact transfer, fresh-process verification,
   recovery rules, and abort conditions.
5. Explicitly distinguish runner local success from operator authorization.

## Task 7: Deterministic end-to-end operational suite

**Files**

- Create: `test/bilateral-operational-e2e.test.mjs`
- Modify only the smallest Round 3 files needed for verified integration gaps.

**Required scenarios**

1. Complete Billy/Iris run through one fake Clockchain and two isolated output
   roots, followed by a fresh aggregate verifier process.
2. Assert exactly three writes, three unique anchors, exact M1/M2/M3 bindings,
   marker-complete party packages, valid signatures, and one aggregate
   `AUTHORIZED`.
3. Assert neither runner output nor watcher output contains that verdict.
4. Parameterize all 28 fail-closed rows plus writer crashes, resume, rate limits,
   malformed packages, incomplete markers, and secret canaries.
5. Prove no test trusts fake-only state unavailable to the production verifier.

**Checks**

```bash
node --test \
  test/bilateral-runner.test.mjs \
  test/bilateral-roles.test.mjs \
  test/bilateral-verdict.test.mjs \
  test/bilateral-preflight.test.mjs \
  test/bilateral-watcher.test.mjs \
  test/bilateral-operational-e2e.test.mjs
```

## Task 8: Review, repeated verification, and deterministic-build commit

1. Fresh spec review against design sections 4.2, 4.8-4.13, 5, 6.4-6.5, 7, and 8.
2. Separate security review of secret handling, irreversible writes, signatures,
   marker publication, aggregate-verifier independence, and authorizing-output
   exclusivity.
3. Fix every Critical or Important finding and rerun review.
4. Run the full targeted suite.
5. Run `npm run verify` three consecutive times; any failure resets the count.
6. Inspect staged diff, generated artifacts, Git history, and secret surface.
7. Create one Sol-owned Lore commit with exact tested/not-tested trailers.

## Task 9: Live preparation and execution gate

These steps mutate external state and occur only after Task 8 is committed.

1. Create four invitations/addresses with existing operator tooling; keep all
   secret artifacts under `.context`.
2. Ask the operator to fund the four generated public addresses.
3. Run the two-write preflight on the two physical machines.
4. If preflight passes, publish the immutable reviewed repository SHA.
5. Run a full two-machine rehearsal, collect both marker-complete packages, and
   verify from a fresh third process.
6. Correct any deterministic or operational defect through the same
   test/review/verify/commit loop.
7. Start the stakeholder run only after the operator starts both clean agent
   sessions.
8. Independently refetch all three anchors and emit the final verdict.

**Stop condition:** The goal is complete only when the live, funded,
two-computer run produces three independently reverified Clockchain anchors and
the operator verifier—not either runner—emits `AUTHORIZED`.
