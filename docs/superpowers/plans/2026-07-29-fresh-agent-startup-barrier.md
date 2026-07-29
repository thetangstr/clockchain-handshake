# Fresh-Agent Manual Test Repair Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan with test-first changes.

**Goal:** Make the existing three-person manual Handshake test work when a demo director gives the checked-in prompts to two stakeholders using fresh agents.

**Architecture:** The first role supervisor waits on a secret-free advisory signal until both role enrollments exist, then performs the existing authenticated enrollment-set verification. The manual instructions tell the director what to start, what each stakeholder pastes into their agent, what public markers to expect, and what constitutes a real verifier-backed pass.

**Tech Stack:** Node.js 22, ES modules, `node:test`, existing relay/client/supervisor CLIs, existing Next.js research site.

---

### Task 1: Keep the first supervisor alive

**Files:**
- Modify: `src/bilateral/coordination/relay.mjs`
- Modify: `src/bilateral/coordination/client.mjs`
- Modify: `src/bilateral/coordination/supervisor.mjs`
- Modify: `src/bilateral/coordination/supervisor-runtime.mjs`
- Modify: `bin/handshake-relay.mjs`
- Modify: `bin/handshake-supervisor.mjs`
- Test: existing relay, client, supervisor, and supervisor-runtime test files

- [ ] Write a focused failing test that starts one role before its peer and proves the first role currently exits.
- [ ] Add an exact relay readiness wait that reports only `ready`, the public release binding, and `paymentMoved:false`.
- [ ] Treat only a genuinely missing peer enrollment as pending; malformed or corrupted state still fails immediately.
- [ ] Notify the wait only after an enrollment is durably accepted.
- [ ] Have the supervisor wait, then call the unchanged authenticated `readEnrollmentSet()` before doing anything else.
- [ ] Print one secret-free waiting marker and one peer-ready marker.
- [ ] Replace the silent supervisor catch with one generic secret-free failure line.
- [ ] Run the focused tests and confirm the original failure is green.

Expected public status objects:

```json
{"paymentMoved":false,"role":"payer","status":"WAITING_FOR_PEER"}
{"paymentMoved":false,"role":"payer","status":"PEER_READY"}
{"code":"COORDINATION_SUPERVISOR_FAILED","paymentMoved":false}
```

The same status contract applies to the payee role. Readiness remains advisory; it never replaces the authenticated enrollment set.

### Task 2: Make the human instructions direct

**Files:**
- Modify: `docs/runbooks/bilateral-demo-quick-start.md`
- Modify: `docs/runbooks/bilateral-demo-day.md`
- Modify: `docs/runbooks/bilateral-demo-live-handoff.md`
- Modify: `prompts/run-iris-bilateral-demo.md`
- Modify: `prompts/run-billie-bilateral-demo.md`
- Modify only existing documentation tests/gates as needed

- [ ] Define one exact private state directory for Iris and one for Billie.
- [ ] Tell the director to wait until both humans say READY.
- [ ] Deliver Iris’s manifest and then Billie’s immediately, without waiting for Iris to finish.
- [ ] Explain that the first role may show `WAITING_FOR_PEER` and must remain running.
- [ ] Explain the exact peer-ready, funding, three-anchor, verifier, and `paymentMoved:false` pass signals.
- [ ] Move testnet limitations, security caveats, and recovery rules after the primary numbered flow.
- [ ] Run the existing documentation checks.

### Task 3: Replace the public run page with the manual handbook

**Files:**
- Modify the existing `/handshake/run` page, component, data, and focused tests in the `clockchain-research` repository.

- [ ] Keep one short introduction at the top.
- [ ] Immediately show the three people and what each person gives their agent.
- [ ] Present one numbered start-to-finish flow with exact commands and expected public markers.
- [ ] Show one clear “Did it pass?” section with the three ordered anchors, fresh verifier result, and `paymentMoved:false`.
- [ ] Put troubleshooting, security, testnet limitations, and recovery caveats at the bottom.
- [ ] Keep the page static and secret-free: no forms, uploads, evidence ingestion, or live network action.
- [ ] Run the site’s focused tests, typecheck, lint, and build.

### Task 4: Run the real manual test

- [ ] Commit the reviewed runtime fix and create three clean detached checkouts at that exact SHA.
- [ ] Start a blank-context demo director, blank-context Iris, and blank-context Billie.
- [ ] Give them only the checked-in handbook/runbooks, their own checkout paths, and private path references.
- [ ] Let the director run relay, coordinator, console, funding, and the two supervisors without root coaching.
- [ ] If a concrete failure occurs, preserve state, add one focused regression test, fix it, and repeat with fresh invitations and addresses.
- [ ] Stop only when the fresh verifier confirms exactly Iris `PROPOSED`, Billie `ACCEPTED`, Iris `ACKNOWLEDGED`, with `paymentMoved:false`.

### Task 5: Required final gates

- [ ] Obtain the repository-required independent code/security review.
- [ ] Run one fresh `npm run verify`.
- [ ] Independently recheck the live verifier artifacts and public anchors.
- [ ] Report the working human handoff and any remaining external prerequisites.
