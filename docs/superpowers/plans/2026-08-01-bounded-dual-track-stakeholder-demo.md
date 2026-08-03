# Bounded Dual-Track Stakeholder Demo Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Publish a clear two-track demo architecture, make one bounded AWS activation attempt, and complete one real stakeholder Handshake with a local-Payer fallback ready.

**Architecture:** Payer and Requestor remain independently controlled local agents. AWS is the primary shared control plane; if activation exposes more than one integration defect, Yang operates the same real Payer and operator surfaces locally while the stakeholder remains the remote Requestor. Both tracks require genuine Payer MCP guidance, three ordered Clockchain anchors and receipts, replay-safe funding, `paymentMoved:false`, and fresh-verifier authority.

**Tech Stack:** Node.js 22 ES modules, AWS CDK/ECS/EFS/CloudFront/API Gateway, Next.js 16, React 19, Vitest, Vercel, Sepolia, Clockchain single-validator testnet.

---

## File ownership

- Handshake design and plan: `docs/superpowers/specs/2026-08-01-bounded-dual-track-stakeholder-demo-design.md`, this plan.
- Public architecture copy and presentation: Clockchain Research worktree `src/components/BilateralHandshakeRunbook.tsx`.
- Public readiness state: Clockchain Research worktree `src/data/bilateral-handshake-demo.ts`.
- Focused site contract: Clockchain Research worktree `src/lib/bilateral-handshake-runbook.test.tsx`.
- AWS runtime: no source changes unless a live defect is isolated first.
- Local fallback: existing Handshake commands only; no new framework or mock implementation.

Preserve all unrelated or concurrent changes in the research-site worktree.

### Task 1: Publish the approved architecture as an honest pre-acceptance page

**Files:**
- Modify: `/Users/Kailor/.config/superpowers/worktrees/clockchain-research/aws-stakeholder-run/src/lib/bilateral-handshake-runbook.test.tsx`
- Modify: `/Users/Kailor/.config/superpowers/worktrees/clockchain-research/aws-stakeholder-run/src/data/bilateral-handshake-demo.ts`
- Modify: `/Users/Kailor/.config/superpowers/worktrees/clockchain-research/aws-stakeholder-run/src/components/BilateralHandshakeRunbook.tsx`

- [ ] **Step 1: Add one focused failing site contract**

Change the release assertion to `liveTestReady:false` and add these assertions to the runbook rendering test:

```tsx
expect(html).toContain("Two tracks, one proof standard");
expect(html).toContain("Primary: AWS shared control plane");
expect(html).toContain("Fallback: real local Payer and operator");
expect(html).toContain("Prototype-first verification");
expect(html).toContain("Live acceptance pending");
expect(html).toContain("The proof does not change");
```

- [ ] **Step 2: Run only the focused contract and observe the expected failure**

Run:

```sh
npx vitest run src/lib/bilateral-handshake-runbook.test.tsx
```

Expected: failure because the architecture section is absent and readiness is still `true`.

- [ ] **Step 3: Mark the hosted release as pending live acceptance**

Change exactly this property and leave the repository URL, reviewed SHA, and
script map unchanged:

```ts
liveTestReady: false,
```

Replace the header readiness sentence with:

```tsx
<p className="bilateral-runbook__status">
  Reviewed prototype release <code>{releaseSha}</code> is deployed for activation.
  <strong> Live acceptance pending.</strong> Use the public repository{" "}
  <a href={repositoryUrl}>{repositoryUrl}</a>.
</p>
```

- [ ] **Step 4: Add the architecture section before “1. Payer goes first”**

Add:

```tsx
<section
  className="bilateral-runbook__step bilateral-runbook__architecture"
  aria-labelledby="demo-architecture-title"
>
  <p className="bilateral-runbook__step-actor">Demo architecture</p>
  <h2 id="demo-architecture-title">Two tracks, one proof standard</h2>
  <p>
    Payer and Requestor remain independent local agents in both tracks. The
    shared hosting may change; the Handshake and Clockchain evidence do not.
  </p>
  <div className="bilateral-runbook__architecture-grid">
    <article>
      <p className="bilateral-runbook__architecture-label">Primary</p>
      <h3>Primary: AWS shared control plane</h3>
      <p>
        AWS provides signed discovery, the restricted Payer MCP tunnel,
        operator controls, replay-safe funding, fresh verification, and the
        public monitor. Stakeholders still own and run their local agents.
      </p>
    </article>
    <article>
      <p className="bilateral-runbook__architecture-label">Fallback</p>
      <h3>Fallback: real local Payer and operator</h3>
      <p>
        If hosted activation is unreliable, Yang runs the real Payer and
        operator locally while the stakeholder remains the Requestor. This is
        a fresh live run, not a replay or mocked result.
      </p>
    </article>
  </div>
  <p>
    <strong>The proof does not change:</strong> real Payer MCP guidance,
    <code> PROPOSED -&gt; ACCEPTED -&gt; ACKNOWLEDGED</code>, exactly three receipts
    and anchors, <code>paymentMoved:false</code>, and a fresh verifier.
  </p>
  <p>
    <strong>Prototype-first verification:</strong> prove one real happy path,
    diagnose only the failing surface, then run the broad hardening suite once.
  </p>
</section>
```

Add compact responsive styling inside the component's existing `<style>`:

```css
.bilateral-runbook__architecture {
  border-color: color-mix(in srgb, var(--md-sys-color-primary) 55%, var(--md-sys-color-outline));
  background: color-mix(in srgb, var(--md-sys-color-primary) 5%, var(--md-sys-color-surface-container-low));
}
.bilateral-runbook__architecture-grid {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 0.85rem;
  margin: 1rem 0;
}
.bilateral-runbook__architecture-grid article {
  min-width: 0;
  padding: 1rem;
  border-left: 4px solid var(--md-sys-color-primary);
  background: var(--md-sys-color-surface);
}
.bilateral-runbook__architecture-label {
  margin: 0 0 0.35rem;
  color: var(--md-sys-color-primary);
  font-size: 0.72rem;
  font-weight: 800;
  letter-spacing: 0.08em;
  text-transform: uppercase;
}
@media (max-width: 760px) {
  .bilateral-runbook__architecture-grid {
    grid-template-columns: 1fr;
  }
}
```

- [ ] **Step 5: Run the one focused test and one production build**

Run:

```sh
npx vitest run src/lib/bilateral-handshake-runbook.test.tsx
npm run build
```

Expected: focused test passes and the `/handshake/run` route builds.

- [ ] **Step 6: Commit only the public architecture slice**

Stage only the three owned files and use a Lore commit recording the focused test and build. Do not include unrelated research-site changes.

### Task 2: Activate the reviewed AWS release without rerunning repository tests

**Files:**
- Read only: `/tmp/clockchain-release-s1GBx7/repo/infra/aws/scripts/deploy.mjs`
- Evidence output: `/tmp/clockchain-aws-deploy-RUXdB9/deploy-687da00-active-evidence.json`
- Stack: `ClockchainHandshake`

- [ ] **Step 1: Confirm the inactive safety state**

Run direct AWS queries. Require `UPDATE_COMPLETE`, revision-8 task definitions, and all five long-lived services at desired/running zero.

```sh
aws cloudformation describe-stacks \
  --stack-name ClockchainHandshake \
  --query 'Stacks[0].StackStatus' \
  --output text
```

Expected: `UPDATE_COMPLETE`.

- [ ] **Step 2: Deploy the same exact release with services active**

Use release SHA `687da00b5eb1dd9b394607eb7ea1a5d9b90fc300`, control-plane digest `sha256:188840eff539078ba9d8cf82771f6277a6367ee860f27d55601c27bcfd0c53c7`, tunnel digest `sha256:997e490135332dbd61c181511abe962996fbfc9d7536e25da0858509f381c325`, session `3a383bce-c0f3-4910-bb7b-6bdcf63620e7`, and the already verified public TLS certificate/fingerprint. Run the existing `npm run deploy` from `infra/aws` with `ACTIVATE_SERVICES=true` and the active evidence/output paths. Do not rebuild images and do not run tests.

- [ ] **Step 3: Wait for CloudFormation and ECS stabilization**

Require:

```text
CloudFormation: UPDATE_COMPLETE
Relay: desired 1, running 1
Operator: desired 1, running 1
Bootstrap: desired 1, running 1
Tunnel: desired 1, running 1
Publisher: desired 1, running 1
```

If a service fails, inspect only that service's stopped task reason and latest CloudWatch events.

### Task 3: Apply the bounded health decision

**Files:** none unless one isolated defect is identified.

- [ ] **Step 1: Probe public control-plane surfaces directly**

Probe:

```text
Operator console: https://d1m5klbdr0u06j.cloudfront.net
Public monitor: https://d2theao4m0sxvj.cloudfront.net/latest.json
Payer discovery: https://d2theao4m0sxvj.cloudfront.net/discoveries/payer.json
Requestor discovery: https://d2theao4m0sxvj.cloudfront.net/discoveries/requestor.json
Payer MCP entry: clockc-publi-zy7cx0fg51wv-6631635de11f13ca.elb.us-west-2.amazonaws.com:9443
Relay entry: clockc-publi-zy7cx0fg51wv-6631635de11f13ca.elb.us-west-2.amazonaws.com:8443
```

The monitor may report a waiting state before participants. It must remain secret-free and `paymentMoved:false`.

- [ ] **Step 2: Count integration defects, not cosmetic issues**

An integration defect means a required service cannot stay running, signed discovery cannot be published/validated, or the Payer MCP/relay path cannot carry the expected protocol traffic. Copy, styling, cache delay, or an explanatory label is not an integration defect.

- [ ] **Step 3: Continue or pivot**

- Zero defects: continue Track A.
- One isolated defect: diagnose and repair that surface with one focused test file, then repeat only its probe.
- More than one defect, an architectural change, or untrustworthy discovery: stop Track A and use Track B.

### Task 4: Prepare the real local-Payer fallback without starting a second live session

**Files:**
- Read: `docs/superpowers/specs/2026-08-01-bounded-dual-track-stakeholder-demo-design.md`
- Read: historical operator procedure at `git show 1281f8a:docs/runbooks/bilateral-demo-day.md`
- Use: current `bin/handshake-supervisor.mjs`, `bin/handshake-request-payment.mjs`, `bin/handshake-bootstrap-broker.mjs`, and `scripts/publish-public-monitor.mjs`

- [ ] **Step 1: Preserve the public legacy relay**

Confirm EC2 instance `i-07f8b33e8658127f3` remains present and do not stop, replace, or repurpose it before a successful acceptance run.

- [ ] **Step 2: Stage only path-level local prerequisites**

Confirm private operator key, Clockchain token, Sepolia RPC file, treasury keystore, and funding journal paths exist with their required permissions. Print only existence, file mode, public address, balance, and nonce; never print contents, tokens, URLs, capabilities, private keys, invitations, or evidence.

- [ ] **Step 3: Keep fallback dormant while Track A is healthy**

Prepare isolated operator, Payer, and Requestor state roots and the existing local command sequence, but do not start role supervisors, fund addresses, or create anchors while Track A owns the session.

- [ ] **Step 4: On pivot, run a fresh local operator/Payer session**

Use the existing local relay, coordinator, console, bootstrap broker, real Payer MCP, public raw-TCP relay, sanitized monitor publisher, and current one-shot Requestor wrapper. The stakeholder receives only the Requestor prompt and public discovery URL. This path must create fresh evidence; prior packaged rehearsals are not acceptable.

### Task 5: Execute exactly one live stakeholder acceptance cycle

**Files:** private runtime evidence only; keep outside Git.

- [ ] **Step 1: Start Payer first**

Use the public Payer prompt and signed discovery. Require exact `PAYER_MCP_READY` before starting Requestor.

- [ ] **Step 2: Start Requestor second**

Use the public Requestor prompt and signed discovery. Require exact `HANDSHAKE_REQUIRED` from Payer MCP before Requestor approval.

- [ ] **Step 3: Fund once**

Approve the exact signed four-address record and send exactly `0.01 Sepolia ETH` to each fresh participant address through the replay-safe funding task or local funding journal. Do not retry a submitted batch.

- [ ] **Step 4: Observe party completion**

Require:

```text
Payer: PROPOSED, then ACKNOWLEDGED
Requestor: ACCEPTED
Anchor count: exactly 3
paymentMoved: false
```

- [ ] **Step 5: Launch one fresh verifier**

Only the fresh aggregate verifier may produce the authorization verdict. Require three public explorer links, three receipts, strict order, unique ledger IDs, increasing block heights, exact release/session binding, and `paymentMoved:false`.

- [ ] **Step 6: Capture the public business result**

Require the public monitor and history view to show the real run in business language without exposing private evidence or claiming settlement.

### Task 6: Mark readiness, publish, then harden once

**Files:**
- Modify after acceptance only: Clockchain Research `src/data/bilateral-handshake-demo.ts`
- Modify after acceptance only: Clockchain Research `src/lib/bilateral-handshake-runbook.test.tsx`

- [ ] **Step 1: Flip readiness only after the acceptance evidence passes**

Change `liveTestReady` from `false` to `true` and change “Live acceptance pending” to a concise verified-live statement. Add the new run to the dynamic public history; do not embed private evidence in source.

- [ ] **Step 2: Run the focused site contract and build once**

```sh
npx vitest run src/lib/bilateral-handshake-runbook.test.tsx
npm run build
```

- [ ] **Step 3: Publish the exact validated research-site source**

Use the existing Vercel project and deployment workflow for `clockchain-research.vercel.app`. Confirm `/handshake/run` contains the architecture section, correct readiness state, two ordered role prompts, and the live public monitor.

- [ ] **Step 4: Run post-success hardening**

Run focused negative suites only for surfaces changed during the live diagnosis. Then run root `npm run verify` exactly once as the final Handshake release gate. Do not rerun it if the source remains unchanged.

- [ ] **Step 5: Deliver the handoff**

Report the selected track, release SHA, Payer MCP URL, monitor URL, three explorer links, receipt count, fresh-verifier result, `paymentMoved:false`, deferred hardening, and any remaining operational dependency.
