# Bounded dual-track stakeholder demo design

**Status:** Approved direction, pending written review

**Date:** 2026-08-01

**Repository:** `thetangstr/clockchain-handshake`

## 1. Purpose

Deliver a credible stakeholder demonstration of the Clockchain bilateral
Handshake without turning the prototype into a production-hosting project.

The demonstration proves that a real Payer-owned MCP can tell a Requestor that
Handshake is required, the two parties can complete the signed protocol, and a
fresh verifier can independently validate exactly three Clockchain anchors.
The demo does not claim production availability, settlement, or operational
hardening.

## 2. Non-negotiable proof

Both execution tracks must preserve the same proof boundary:

1. Requestor calls the real Payer MCP and receives `HANDSHAKE_REQUIRED` with
   signed mandate guidance.
2. The parties produce `PROPOSED -> ACCEPTED -> ACKNOWLEDGED` in that exact
   order.
3. Exactly three independently re-verifiable Clockchain anchors and receipts
   exist.
4. A fresh aggregate-verifier process is the only authority that may emit the
   authorization verdict.
5. Every protocol, console, monitor, receipt, and verdict artifact states
   `paymentMoved:false`.
6. Missing, duplicate, reordered, expired, malformed, or mismatched evidence
   fails closed.

A mocked Payer response, fabricated anchor, replayed funding batch, or
operator-authored verdict does not satisfy the demo.

## 3. What runs where

The Payer and Requestor agents remain local in both tracks. Each party owns its
private state and signing material. AWS is shared demo infrastructure; it does
not host either stakeholder agent or take custody of either role's private key.

The AWS track hosts the coordination relay, restricted Payer MCP tunnel
gateway, operator controls, sealed bootstrap approval, funding task, fresh
verifier, and sanitized public monitor.

The fallback track runs the real Payer and operator processes on Yang's Mac,
uses the existing public raw-TCP entry point for the remote Requestor, and
publishes the same sanitized public progress. The fallback changes hosting and
operator convenience, not the protocol or evidence.

## 4. Track A: bounded AWS activation

Track A is the primary path because the reviewed release, container images,
inactive CloudFormation deployment, and revision-pinned task definitions
already exist.

The operator performs one bounded activation attempt:

1. Activate the long-lived AWS services.
2. Confirm relay, bootstrap, tunnel, operator, publisher, Payer MCP discovery,
   and public monitor health.
3. Run one funded Payer and Requestor cycle from fresh local agent contexts.
4. Verify the three anchors and receipts with a fresh verifier.

One isolated, clearly understood runtime defect may be repaired with a focused
check. If activation exposes more than one integration defect, requires an
architecture change, or cannot produce trustworthy public discovery, execution
pivots immediately to Track B. Production polish is not a prerequisite.

## 5. Track B: real local-Payer fallback

Track B is prepared while Track A health is evaluated. Yang operates the real
Payer and operator processes locally. A stakeholder runs the portable
Requestor agent from another macOS, Windows, or Linux computer.

The Requestor still calls the genuine Payer MCP through a public endpoint,
receives the signed mandate and `HANDSHAKE_REQUIRED`, and completes the same
authenticated relay and Clockchain sequence. Funding replay protection,
receipts, public monitoring, and fresh-verifier authority remain mandatory.

Track B may depend on Yang's Mac and the existing public relay. The site must
label that dependency honestly. It must not describe the fallback as a fully
AWS-independent or production deployment.

## 6. Concurrency and replay safety

AWS health checks and fallback preparation may run concurrently. Live protocol
execution may not.

Only one track may own the funded stakeholder session. Do not fund, anchor, or
verify two competing sessions concurrently. Each attempt uses fresh
participant addresses, isolated private state roots, a distinct session
identity, and the existing replay-safe funding journal.

## 7. Public-site presentation

The public run page adds a concise section before the live instructions:

- **What you are seeing:** two local stakeholder agents completing a real
  Payer-directed Handshake.
- **Primary setup:** AWS provides the shared relay, controls, funding,
  verification, and public monitor.
- **Demo fallback:** Yang may operate the real Payer and operator locally while
  the stakeholder remains the remote Requestor.
- **Unchanged proof:** real Payer MCP guidance, three Clockchain anchors and
  receipts, fresh verification, and `paymentMoved:false` remain identical.
- **Prototype boundary:** this demonstrates the workflow on Sepolia and a
  Clockchain single-validator testnet; it does not claim production settlement,
  high availability, or multi-validator security.

The page should show the primary and fallback tracks as two clearly labeled
routes, not as competing simultaneous runs. It should lead with business
meaning and keep infrastructure details secondary.

## 8. Prototype-first verification policy

Verification is staged around evidence value instead of running the broadest
suite after every small change.

The reviewed immutable release already passed its focused runtime,
infrastructure, deployment-plan, typecheck, and independent-review gates before
the inactive AWS deployment. Do not rerun those unchanged checks merely to
start the prototype. Activation begins with direct service health probes and a
live happy-path attempt.

### Stage 1: prove the happy path

Before the first live attempt, probe only the selected track's actual services,
public discovery, Payer MCP TLS endpoint, and public monitor. If code changes
after the reviewed release, run only the smallest test file or files that cover
that changed surface:

- focused Payer wrapper and Requestor wrapper checks;
- focused AWS deployment-plan or local-launch smoke checks for the selected
  track;
- focused public-monitor projection checks; and
- direct health probes for the selected live services.

Copy-only public-site changes require their focused rendering/content check and
a production build, not the Handshake repository's full suite.

### Stage 2: run one real acceptance cycle

The decisive prototype evidence is a fresh funded cycle with genuine Payer MCP
guidance, three receipts and anchors, a fresh verifier result, and a public
monitor view. A failing acceptance run is diagnosed with the narrowest relevant
test rather than restarting the full suite.

### Stage 3: harden after success

After one live happy path succeeds, run the broad security, malformed-input,
restart, replay, and recovery checks. Run the repository's complete
`npm run verify` exactly once as the final release gate, after the integrated
implementation and documentation are stable.

This policy does not permit skipping tests that directly protect funding replay
safety, exact event authority, receipt validation, or fresh-verifier
exclusivity when those surfaces change.

### Why the previous cadence was slow

The root verification command expands to roughly ninety-six test files plus
documentation checks. The deterministic multiprocess suite permits
ninety-second process phases, live funding and readiness paths permit
eight-minute waits, and the AWS runtime-entrypoint suite contains a large
secret and malformed-input matrix. Repeating those gates during connection,
copy, or deployment iteration spends hardening time before the prototype has
proved its happy path.

Those suites remain valuable after success. They are not the default feedback
loop for an unchanged reviewed release, site copy, endpoint health, or a single
runtime diagnosis.

## 9. Acceptance criteria

The demo is ready when either Track A or Track B produces all of the following
from a fresh session:

- a stakeholder Requestor reaches the real Payer MCP through the documented
  public entry point;
- `HANDSHAKE_REQUIRED` is returned from Payer-owned mandate logic;
- Payer reaches `ACKNOWLEDGED` and Requestor reaches `ACCEPTED`;
- exactly three ordered Clockchain anchors and receipts are publicly
  inspectable;
- the public monitor explains the sequence in business language;
- a fresh aggregate verifier independently validates the evidence;
- no non-verifier surface emits the authorization literal;
- `paymentMoved:false` is visible throughout; and
- the operator can hand stakeholders one concise page that accurately states
  which track is running.

## 10. Deferred hardening

The following are deliberately deferred until after the prototype happy path:

- high availability and automatic failover;
- concurrent active demo sessions;
- production certificate lifecycle automation;
- generalized mandate discovery;
- production settlement or mainnet value transfer;
- multi-validator security claims;
- exhaustive browser, platform, restart, and hostile-network matrices; and
- operator-console polish unrelated to completing or understanding the demo.
