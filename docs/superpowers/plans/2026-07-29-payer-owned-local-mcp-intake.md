# Payer-owned local MCP intake implementation plan

> **Execution contract:** Follow
> `docs/superpowers/specs/2026-07-29-payer-owned-local-mcp-intake-design.md`
> exactly. Use strict TDD for every behavior change, focused tests during
> iteration, and one complete `npm run verify` only as the final repository
> gate.

**Goal:** Make the manual demo begin with a real Requestor
`request_payment` call to a Payer-owned local MCP server. A valid call returns
`HANDSHAKE_REQUIRED`, binds the exact intake into the later Payer-signed
mandate and Requestor-signed formal request, and only then starts the existing
Requestor supervisor.

**Authority invariant:** The local MCP exchange is authenticated intake, not
authorization. Clockchain still contains exactly Payer `PROPOSED`, Requestor
`ACCEPTED`, and Payer `ACKNOWLEDGED`; only the fresh aggregate verifier may
emit `AUTHORIZED`; every artifact states `paymentMoved:false`.

**Implementation shape:** Node.js 22 ES modules, Node-native HTTPS, MCP
2025-11-25 Streamable HTTP, exact schemas, private filesystem persistence, and
the existing supervisor/coordinator/verifier architecture. Add no dependency
and no fourth Clockchain write.

---

## Task 1: Freeze shared demo policy and exact intake artifacts

**Files**

- Create: `src/bilateral/demo-intent-policy.mjs`
- Create: `src/bilateral/local-mcp/payment-intake.mjs`
- Create: `test/bilateral-local-mcp-payment-intake.test.mjs`
- Modify: `src/bilateral/coordination/supervisor.mjs`
- Modify: `test/bilateral-coordination-supervisor.test.mjs`

**RED**

1. Add tests for the frozen USD 100 / `invoice-` / `Handshake demo` policy.
2. Add exact-shape tests for
   `clockchain.payer-mcp-payment-intake/v1` and
   `clockchain.payer-mcp-handshake-required/v1`.
3. Cover canonical UUIDs, exact keys, hostile objects, accessors, proxies,
   printable-string bounds, wrong commercial terms, `paymentMoved:true`, and
   unknown authorization-sequence values.
4. Prove `intakeDigest` is lowercase SHA-256 over only
   `canonicalBytes(validatedToolInput)`.
5. Prove the structured result and its canonical text content are identical
   and contain no authorization literal.
6. Change the supervisor test to import the same shared policy rather than
   accepting a duplicated local constant.

Run and observe the intended failure:

```bash
node --test test/bilateral-local-mcp-payment-intake.test.mjs test/bilateral-coordination-supervisor.test.mjs
```

**GREEN**

1. Export one deeply frozen `DEMO_INTENT_POLICY`.
2. Implement the exact intake validator, digest, response builder, response
   validator, and canonical tool descriptor.
3. Replace the supervisor's duplicated policy with the shared module.

Run:

```bash
node --test test/bilateral-local-mcp-payment-intake.test.mjs test/bilateral-coordination-supervisor.test.mjs
git diff --check
```

Commit only after both focused files pass.

## Task 2: Generate role-separated MCP intake capability material

**Files**

- Modify: `src/bilateral/coordination/manifest.mjs`
- Modify: `src/bilateral/coordination/coordinator.mjs`
- Modify: `src/bilateral/coordination/coordinator-runtime.mjs`
- Modify: `test/bilateral-coordination-client.test.mjs`
- Modify: `test/bilateral-coordination-coordinator.test.mjs`
- Modify: `test/bilateral-coordination-coordinator-runtime.test.mjs`

**RED**

1. Require a second coordinator-generated random 32-byte capability per
   release.
2. Require the Requestor launch manifest to carry only the raw lowercase-hex
   `payerMcpIntakeCapability`.
3. Require the Payer launch manifest to carry only its lowercase SHA-256
   `payerMcpIntakeCapabilityDigest`.
4. Reject either field on the wrong role, unknown fields, reused bootstrap and
   MCP capabilities, invalid lengths, noncanonical hex, and cross-release or
   cross-session mismatches.
5. Prove public coordinator state, capability registration, console output,
   receipt bytes, and the opposite role's manifest do not contain the raw MCP
   capability in hex, base64, or base64url.
6. Prove interrupted coordinator restart reuses the same pending capability
   pair and never generates split manifests.

Run and observe the intended failure:

```bash
node --test test/bilateral-coordination-client.test.mjs test/bilateral-coordination-coordinator.test.mjs test/bilateral-coordination-coordinator-runtime.test.mjs
```

**GREEN**

1. Add role-conditional exact manifest schemas and validators.
2. Create the capability once in the coordinator's private pending journal.
3. Project raw material only into the Requestor manifest and its digest only
   into the Payer manifest.
4. Preserve existing atomic manifest creation, registration, restart, expiry,
   and secret-isolation guarantees.

Run:

```bash
node --test test/bilateral-coordination-client.test.mjs test/bilateral-coordination-coordinator.test.mjs test/bilateral-coordination-coordinator-runtime.test.mjs
git diff --check
```

## Task 3: Bind intake into both signed commercial-intent artifacts

**Files**

- Modify: `src/bilateral/payer-mandate.mjs`
- Modify: `src/bilateral/payment-request.mjs`
- Modify: `src/bilateral/coordination/supervisor.mjs`
- Modify: `src/bilateral/verdict.mjs`
- Modify: `test/bilateral-payer-mandate.test.mjs`
- Modify: `test/bilateral-payment-request.test.mjs`
- Modify: `test/bilateral-coordination-supervisor.test.mjs`
- Modify: `test/bilateral-verdict.test.mjs`

**RED**

1. Require `intakeDigest` and `intakeRequestId` in the exact Payer mandate
   schema and expected binding.
2. Require the same two fields in the exact formal Requestor payment request.
3. Reject missing, malformed, mismatched, reordered, duplicated, expired, or
   hostile values.
4. Prove both EIP-191 signatures cover the intake fields.
5. Prove `verifyPaymentRequest` requires exact equality among intake, mandate,
   request, session, release, repository, parties, policy, and run.
6. Prove the aggregate verifier rejects an intake mismatch before any
   Clockchain fetch and still requires exactly three anchors.

Run and observe the intended failure:

```bash
node --test test/bilateral-payer-mandate.test.mjs test/bilateral-payment-request.test.mjs test/bilateral-coordination-supervisor.test.mjs test/bilateral-verdict.test.mjs
```

**GREEN**

1. Extend both exact schemas and signing preimages.
2. Thread one validated intake binding into `mandateFor`, `requestFor`, the
   intent journal, artifact verification, and the fresh verdict.
3. Keep the formal per-run `requestId` distinct from `intakeRequestId`.
4. Do not add a verifier input that trusts MCP response bytes directly; the
   signed artifacts remain the verifier's durable source.

Run:

```bash
node --test test/bilateral-payer-mandate.test.mjs test/bilateral-payment-request.test.mjs test/bilateral-coordination-supervisor.test.mjs test/bilateral-verdict.test.mjs
git diff --check
```

## Task 4: Add replay-safe private intake persistence

**Files**

- Create: `src/bilateral/local-mcp/intake-store.mjs`
- Create: `test/bilateral-local-mcp-intake-store.test.mjs`
- Modify: `src/bilateral/coordination/supervisor-runtime.mjs`
- Modify: `test/bilateral-coordination-supervisor-runtime.test.mjs`

**RED**

1. First valid intake creates one mode-`0600` canonical record under the
   Payer's mode-`0700` state root.
2. A byte-identical retry returns the same validated record and response.
3. Reusing `intakeRequestId` with changed canonical bytes fails closed.
4. Restart reopens and fully revalidates the persisted record.
5. Reject temporary files, symlinks, hard links, wrong owners, wrong modes,
   path traversal, pathname replacement, noncanonical JSON, partial files,
   and unexpected additional intake records.
6. Prove capability material never enters the record or error output.

Run and observe the intended failure:

```bash
node --test test/bilateral-local-mcp-intake-store.test.mjs test/bilateral-coordination-supervisor-runtime.test.mjs
```

**GREEN**

1. Implement exclusive-create canonical persistence using existing private
   root/file primitives.
2. Add exact read/adopt behavior for restart.
3. Expose only validated intake read/write dependencies to the Payer
   supervisor.

Run:

```bash
node --test test/bilateral-local-mcp-intake-store.test.mjs test/bilateral-coordination-supervisor-runtime.test.mjs
git diff --check
```

## Task 5: Implement the authenticated Payer-owned MCP server

**Files**

- Create: `src/bilateral/local-mcp/server.mjs`
- Create: `test/bilateral-local-mcp-server.test.mjs`
- Modify: `src/bilateral/coordination/supervisor-runtime.mjs`
- Modify: `test/bilateral-coordination-supervisor-runtime.test.mjs`

**RED**

1. Cover the exact MCP lifecycle: `initialize` first,
   `notifications/initialized`, `tools/list`, one `tools/call`, and
   `DELETE /mcp`.
2. Require protocol `2025-11-25`, exact JSON-RPC objects, one random
   `MCP-Session-Id`, exact `MCP-Protocol-Version`, and
   `Accept: application/json, text/event-stream`.
3. Require TLS; an explicit canonical numeric host; no wildcard bind; exact
   `/mcp`; exact Host header; and no redirects, query, fragment, proxy, DNS,
   or Origin acceptance.
4. Require `Authorization: Bearer <capability>`, hash it, and compare only to
   the Payer-manifest digest using constant-time comparison.
5. Assert the same generic unauthorized response for missing, malformed, and
   wrong capabilities.
6. Cover the exact 32-header, 64-KiB body, five-second header, ten-second
   request, 16-failed-auth/60-second, and eight-request/session limits.
7. Cover GET `405`, session deletion, wrong session/version/method/tool,
   unsupported content and response types, duplicate IDs, malformed JSON,
   oversized inputs, and unexpected SSE.
8. Prove the server never appends a relay event, calls Clockchain, creates a
   verdict, moves payment, logs secrets, or emits the authorization literal.

Run and observe the intended failure:

```bash
node --test test/bilateral-local-mcp-server.test.mjs test/bilateral-coordination-supervisor-runtime.test.mjs
```

**GREEN**

1. Implement a Node-native HTTPS server with the closed MCP surface.
2. Return JSON only, `202` for the initialized notification, `405` for GET,
   and generic secret-free boundary failures.
3. Persist one valid intake through Task 4 and return the exact Task 1 result.
4. Add Payer-only runtime construction and lifecycle hooks; Requestor role
   construction must reject MCP server options.

Run:

```bash
node --test test/bilateral-local-mcp-server.test.mjs test/bilateral-coordination-supervisor-runtime.test.mjs
git diff --check
```

## Task 6: Implement the pinned Requestor MCP client and one-shot command

**Files**

- Create: `src/bilateral/local-mcp/client.mjs`
- Create: `bin/handshake-request-payment.mjs`
- Create: `test/bilateral-local-mcp-client.test.mjs`
- Create: `test/bilateral-request-payment-cli.test.mjs`
- Modify: `package.json`

**RED**

1. Require the exact six CLI options from the design and reject unknown,
   repeated, missing, relative/private-escape, or wrong-role inputs.
2. Require a clean immutable repository at the launch manifest SHA.
3. Prove the client reads the Requestor-only capability without printing or
   separately persisting it.
4. Prove initialize, initialized, `tools/list`, `tools/call`, and DELETE all
   send the raw capability only as
   `Authorization: Bearer <capability>` inside the TLS-pinned request, and
   prove it never appears in URLs, bodies, results, state, status, or logs.
5. Cover TLS certificate and fingerprint pinning, numeric HTTPS URL, exact
   Host, no proxy/environment escape, no redirect, no DNS ambiguity, and
   bounded timeout/body behavior.
6. Cover exact initialize, initialized, tool discovery, tool schema, call,
   result, canonical duplicate text, session cleanup, and protocol headers.
7. Fail closed on SSE, missing/extra tools, response ID mismatch, duplicate
   keys, malformed data, wrong repository SHA, wrong intake terms, wrong
   sequence, `paymentMoved:true`, or any status other than
   `HANDSHAKE_REQUIRED`.
8. Prove the existing Requestor supervisor launcher is never called on any
   prior failure and is called exactly once after a private validated intake
   result exists.

Run and observe the intended failure:

```bash
node --test test/bilateral-local-mcp-client.test.mjs test/bilateral-request-payment-cli.test.mjs
```

**GREEN**

1. Implement the pinned client and exact response validation.
2. Send the Requestor-only raw capability on every MCP lifecycle request only
   in the TLS-protected Authorization header, then discard the retained value
   after session cleanup.
3. Persist the validated public intake result under the Requestor state root.
4. Close the MCP session and invoke `runSupervisor` exactly once.
5. Add `npm run bilateral:request-payment`.
6. Emit only secret-free status codes, including
   `HANDSHAKE_REQUIRED` before supervisor status begins.

Run:

```bash
node --test test/bilateral-local-mcp-client.test.mjs test/bilateral-request-payment-cli.test.mjs
git diff --check
```

## Task 7: Gate supervisor progression on the bound intake

**Files**

- Modify: `bin/handshake-supervisor.mjs`
- Modify: `src/bilateral/coordination/supervisor.mjs`
- Modify: `src/bilateral/coordination/supervisor-runtime.mjs`
- Modify: `test/bilateral-coordination-supervisor.test.mjs`
- Modify: `test/bilateral-coordination-supervisor-runtime.test.mjs`

**RED**

1. Payer CLI accepts the exact four additional MCP host/port/certificate/key
   options; Requestor CLI rejects them.
2. Payer starts the MCP listener after bootstrap state is durable and before
   waiting for peer enrollment.
3. Payer cannot construct either run mandate until exactly one valid intake
   exists plus both authenticated role identities exist.
4. Requestor cannot construct either formal request until its persisted intake
   matches the Payer-signed mandate.
5. Changed intake, duplicate intake, missing intake, restart drift, wrong
   policy, wrong release/session/repository, or wrong role remains fail-closed
   before `PAYMENT_REQUEST_MATCHED`.
6. Listener closes on terminal failure and survives the intended long-lived
   enrollment wait.

Run and observe the intended failure:

```bash
node --test test/bilateral-coordination-supervisor.test.mjs test/bilateral-coordination-supervisor-runtime.test.mjs
```

**GREEN**

1. Parse Payer-only MCP arguments and safely load matching TLS files.
2. Add intake-wait/adopt phases to the existing checkpointed supervisor
   without introducing a second state owner.
3. Thread the validated intake through both rehearsal and stakeholder intent
   phases.
4. Preserve all existing readiness, enrollment, restart, recovery, and
   `paymentMoved:false` gates.

Run:

```bash
node --test test/bilateral-coordination-supervisor.test.mjs test/bilateral-coordination-supervisor-runtime.test.mjs
git diff --check
```

## Task 8: Prove the real isolated multiprocess sequence

**Files**

- Modify: `test/helpers/bilateral-coordination-child.mjs`
- Modify: `test/bilateral-coordination-process-e2e.test.mjs`
- Modify as required by exact artifact schemas:
  `src/bilateral/coordination/artifact.mjs`
- Modify: `test/bilateral-coordination-artifact.test.mjs`

**RED**

1. Start a real TLS Payer MCP listener in the isolated copied repository.
2. Have the real Requestor wrapper initialize, discover, call, validate, and
   only then start the Requestor supervisor child.
3. Record process-safe milestones proving:
   `PAYER_MCP_READY -> HANDSHAKE_REQUIRED -> Requestor supervisor start`.
4. Assert identical intake restart adoption and changed replay rejection.
5. Assert signed mandate/request intake equality for both runs.
6. Assert exactly three Clockchain writes in order, one fresh verifier,
   verifier-only authorization output, and `paymentMoved:false` recursively.
7. Assert no capability or secret canary in reports, logs, evidence, or copied
   public state.
8. Diagnose and remove the existing approximately 90-second timeout rather
   than increasing the deadline.

Run and observe the intended failure:

```bash
node --test test/bilateral-coordination-artifact.test.mjs test/bilateral-coordination-process-e2e.test.mjs
```

**GREEN**

Implement only the smallest helper/process changes needed to make the real
sequence deterministic and fail-closed.

Run twice from clean temporary state:

```bash
node --test test/bilateral-coordination-artifact.test.mjs test/bilateral-coordination-process-e2e.test.mjs
node --test test/bilateral-coordination-process-e2e.test.mjs
git diff --check
```

## Task 9: Replace manual instructions and prompts with the local MCP flow

**Handshake repository files**

- Modify: `README.md`
- Modify: `docs/runbooks/bilateral-demo-day.md`
- Modify: `docs/runbooks/bilateral-demo-quick-start.md`
- Modify: `docs/runbooks/bilateral-demo-live-handoff.md`
- Modify: `prompts/run-payer-bilateral-demo.md`
- Modify: `prompts/run-requestor-bilateral-demo.md`
- Modify: `scripts/check-docs.mjs`
- Modify: `test/docs.test.mjs`

**Public research-site files, in a clean current-main scratch worktree**

- Modify: `src/components/BilateralHandshakeRunbook.tsx`
- Modify: `src/data/bilateral-handshake-demo.ts`
- Modify: `src/lib/bilateral-handshake-runbook.test.tsx`

**RED**

1. Require the Payer prompt to explain its ordinary payment-approval role,
   start the local MCP listener, disclose only its public URL/certificate/
   fingerprint, and remain attached.
2. Require the Requestor prompt to explain its ordinary payment-request role,
   call `request_payment`, visibly confirm `HANDSHAKE_REQUIRED`, and let the
   wrapper start its supervisor.
3. Forbid every claim that the hosted Clockchain MCP provides this flow.
4. Preserve exactly three anchors, verifier-only authorization, funding replay
   safety, exact event authority, and `paymentMoved:false`.
5. Update the public `/handshake/run` tests before editing the page.

Focused Handshake docs check:

```bash
node --test test/docs.test.mjs
node scripts/check-docs.mjs
```

Focused research-site check:

```bash
npm test -- src/lib/bilateral-handshake-runbook.test.tsx
```

**GREEN**

1. Make the handbook start immediately with the two role prompts and manual
   steps.
2. Show the MCP request and `HANDSHAKE_REQUIRED` outcome explicitly.
3. Keep caveats and security notes after the operating steps.
4. Use the existing compact copy icon and role colors; no Demo Director.
5. Keep the research-site change local and reviewable. Do not deploy or merge
   the public page until Task 10 review blockers are fixed and Task 11's final
   repository verification passes.

## Task 10: Independent integrated review and fresh-agent rehearsal

**Review**

1. Request an independent security review of the integrated diff, focusing on
   capability isolation, LAN authentication, replay persistence, exact signed
   bindings, event authority, and verifier-only authorization.
2. Request an independent specification review against the approved design.
3. Fix every blocking issue with a new failing regression first.
4. Rerun only the focused checks affected by each fix.

**Fresh-agent rehearsal**

1. Create two truly fresh blank-context agent sessions.
2. Give each only its published role prompt and its own private handoff.
3. Observe the Payer agent start the local MCP endpoint.
4. Observe the Requestor agent call it and receive
   `HANDSHAKE_REQUIRED` before its supervisor starts.
5. Preserve the full role logs and a secret-free presentation record.
6. Require exact intake binding, three ordered anchors, fresh-verifier-only
   `AUTHORIZED`, and `paymentMoved:false`.

No live transfer or additional Sepolia funding is required to prove the local
MCP intake itself. If the final stakeholder path includes live funding, use
only the already approved replay-safe treasury workflow and never print or
transfer key material.

## Task 11: Final release gate and handoff

1. Confirm all implementation and review commits use Lore trailers.
2. Confirm the worktree contains no secrets, capabilities, invitations,
   private keys, tokens, generated evidence, or live RPC material.
3. Run the complete repository gate exactly once:

```bash
npm run verify
```

4. Confirm a clean immutable release SHA and rerun the deterministic
   multiprocess acceptance command against it if `npm run verify` does not
   already execute that test.
5. Merge and deploy the already reviewed research-site change through its
   normal release path only after the final Handshake repository gate is
   green.
6. Verify the deployed `/handshake/run` page shows the same immutable release
   and local MCP flow.
7. Hand off:
   - exact release SHA;
   - focused and final verification evidence;
   - fresh-agent rehearsal result;
   - public handbook URL;
   - exact operator/Payer/Requestor commands;
   - any live-only gap stated explicitly.

The completion verdict is not green unless the fresh aggregate verifier is
the only component that emitted `AUTHORIZED`, the evidence contains exactly
three independently re-verifiable anchors, and every surface says
`paymentMoved:false`.
