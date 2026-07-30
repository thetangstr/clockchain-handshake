# Payer-mandate live Handshake demo design

Date: 2026-07-28

Status: User-approved design specification. This document authorizes local
implementation and deterministic testing after an implementation plan is
approved. It does not authorize mainnet activity, real payment movement,
publication of secrets, or a claim that the physical rehearsal has passed
before it is actually run.

## 1. Purpose

Deliver a turnkey three-computer Clockchain Handshake demonstration that keeps
the product story on the existing Clockchain Research Handshake page:

- **Iris** represents Meridian, the payer and mandate owner.
- **Billie** represents Trellis, the vendor and payment receiver.
- Billie requests payment and follows the protocol required by Iris.
- Clockchain supplies independently verifiable ordering and time evidence.
- A separate operator coordinates the session and performs the only
  authorization-producing verification.

The result must be understandable to stakeholders, executable by coding agents
on two separate stakeholder computers, observable from an operator console,
and honest about what is live versus staged.

Implementation completion and live-demo validation are separate gates.
Implementation completion means the release is verified and rehearsal-ready.
Live-demo validation additionally requires a successful run using the physical
Iris, Billie, and operator computers.

## 2. Required authorization semantics

### 2.1 Canonical sequence

The payment request precedes the authorization protocol and is not an
authorization anchor:

```text
Billie payment request
  -> Iris mandate evaluation
  -> PROPOSED       (Iris)
  -> ACCEPTED       (Billie)
  -> ACKNOWLEDGED   (Iris)
  -> operator verification
  -> AUTHORIZED     (fresh aggregate verifier only)
```

The three protocol transitions are the only authoritative Clockchain anchors:

1. Iris anchors `PROPOSED`.
2. Billie independently verifies it and anchors `ACCEPTED`.
3. Iris independently verifies both predecessors and anchors `ACKNOWLEDGED`.

There must be exactly three ordered, independently verifiable anchors. The
request, mandate, relay events, watcher observations, console projection, and
verifier publication are not additional authorization anchors.

### 2.2 Payment boundary

Every request, mandate, descriptor, transition, party result, aggregate
verdict, watcher snapshot, console projection, and recovery artifact carries or
derives:

```json
{"paymentMoved":false}
```

This release authorizes a proposed payment but never transfers ETH, Sepolia
ETH, USDC, fiat, or any other value. Sepolia ETH is used only to fund the four
generated demo identities that must write testnet evidence.

### 2.3 Sole authorization owner

Only a newly launched aggregate-verifier process may emit the literal
`AUTHORIZED`. It must independently refetch and validate:

- the payer and payee identities;
- the Iris-signed mandate;
- the Billie-signed request;
- the operator-signed session descriptor;
- all three Clockchain anchors;
- both marker-complete party results;
- the exact transition order and predecessor bindings;
- the session time window and freshness;
- the expected release identity; and
- `paymentMoved:false`.

Iris, Billie, the request endpoint, the relay, the coordinator, the watcher,
and the console must never infer or print the authorizing literal.

## 3. Chosen architecture

### 3.1 Logical components

The implementation spans two repositories without importing a runtime from
another Clockchain project:

1. **`clockchain-handshake`**
   - repository-native Node.js 22 CLI runtime;
   - role supervisors and protocol commands;
   - authenticated coordination relay;
   - payer-owned logical request inbox;
   - operator coordinator, watcher, and aggregate verifier;
   - local read-only operator console;
   - deterministic tests, prompts, and runbooks.
2. **`clockchain-research`**
   - public stakeholder explanation;
   - architecture and sequence diagrams;
   - role-specific copyable prompts;
   - prerequisites, expected outputs, and failure guidance;
   - a clear link from the existing `/handshake` narrative to the live-demo
     helper material.

The Handshake runtime must not install, copy, or depend on AgentDash or
Paperclip. The research site may describe historical or proposed surfaces, but
the live-demo helper must identify the repository-native runtime as the
executed system.

### 3.2 Payer-owned logical request inbox

The coordination relay hosts the network endpoint for operational stability,
but Iris owns its policy and authority cryptographically.

The endpoint:

```text
GET  /v1/sessions/{sessionId}/mandate?subjectRun={rehearsal|stakeholder}
POST /v1/sessions/{sessionId}/payment-requests
GET  /v1/sessions/{sessionId}/payment-requests/{requestId}
```

publishes the exact Iris-signed mandate and accepts one exact, Billie-signed
request for the assigned session. The relay may validate shape, signatures,
bounds, replay state, and session membership. It may not approve the request,
create Iris's mandate, or begin the protocol.

Before accepting requests, the inbox requires an Iris-signed mandate
commitment that binds:

- protocol and schema versions;
- session and release identifiers;
- Iris as payer and Billie as payee;
- exact currency and amount policy;
- the permitted purpose/reference;
- not-before and expiration bounds;
- the request endpoint identifier; and
- `paymentMoved:false`.

The relay is therefore the transport host, while Iris remains the source of
the mandate. A compromised relay cannot alter the request or mandate without
invalidating their signatures.

### 3.3 Rejected alternatives

**A full MCP server on the Iris computer.** This gives the payer a visibly
separate server but adds remote reachability, certificate, firewall, lifecycle,
and MCP-tool security concerns that do not strengthen the three-anchor
authorization proof.

**An operator-authored mandate.** This is operationally simple but contradicts
the product story. The operator coordinates and verifies; it does not decide
Meridian's payment policy.

**A request represented as a fourth Clockchain transition.** This would make
the request independently visible but violate the exactly-three-anchor
invariant and blur the boundary between commercial intent and authorization.

## 4. Role and naming migration

All stakeholder-facing surfaces use:

| Protocol role | Display name | Company | Responsibility |
| --- | --- | --- | --- |
| Payer | Iris | Meridian | Sets mandate, proposes, acknowledges |
| Payee | Billie | Trellis | Requests payment, accepts |
| Operator | Operator | Clockchain | Coordinates and freshly verifies |

New internal interfaces should use the stable protocol terms `payer` and
`payee`. Legacy code paths whose filenames or symbols encode the old
Billy-payer/Iris-payee mapping may remain temporarily as compatibility aliases
only when removal would create disproportionate migration risk. No legacy
mapping may appear in generated prompts, console copy, runbook commands, final
artifacts, or public helper content.

The public name is spelled **Billie**. Existing cryptographic identifiers and
previously published evidence are not rewritten.

## 5. Exact request and mandate artifacts

### 5.1 Payment request

The payment request is a canonical signed artifact with:

- an exact schema marker;
- one session identifier and one request identifier;
- the frozen release SHA;
- Billie and Iris identity commitments;
- the mandate commitment it answers;
- exact currency, value, purpose, and invoice reference;
- creation and expiration bounds;
- `paymentMoved:false`;
- Billie's public signing key; and
- Billie's signature over the canonical unsigned payload.

Unknown keys, non-canonical encodings, unsafe integers, ambiguous amounts,
duplicate keys, unsupported algorithms, invalid signatures, and out-of-window
requests fail closed.

### 5.2 Payer mandate

The payer mandate is a canonical Iris-signed artifact with:

- an exact schema marker;
- session, release, payer, and payee bindings;
- exact allowed currency and value;
- an exact purpose/reference policy;
- not-before and expiration bounds;
- the required three-transition protocol version;
- the expected request endpoint identifier;
- `paymentMoved:false`;
- Iris's public signing key; and
- Iris's signature over the canonical unsigned payload.

The operator descriptor commits to the verified request and mandate hashes but
cannot modify their commercial terms.

### 5.3 Validation and recovery

Exact validators must exist for the signed request and mandate. Marker-complete
validators must exist for the preflight, identity, party-result, failure,
recovery, and aggregate-verdict artifacts. Together they must reject missing,
duplicated, reordered, expired, malformed, replayed, or mismatched evidence
before the relay accepts the corresponding event.

Recovery reuses only validated public state. It never reconstructs or
transports role secrets, silently changes a session identifier, or turns an
expired session back into an active one.

## 6. Operator console

### 6.1 Deployment boundary

The live console is served by the repository-native operator process and binds
to loopback by default. An explicit, validated bind is required for LAN
projection. It is not a public Vercel dashboard and does not require role
secrets in a browser.

The public research site explains the console and how to open it, but it does
not ingest live session evidence.

### 6.2 Read-only projection

The browser consumes one sanitized, read-only projection that joins:

- validated enrollment and heartbeat state;
- request and mandate commitments;
- coordinator phase;
- watcher observations;
- the three independently fetched anchor summaries;
- deadlines and terminal failures; and
- durable fresh-verifier publication state.

The projection excludes:

- tokens, invitations, capabilities, private keys, RPC credentials, TLS
  private material, absolute private paths, raw environment values, and
  unrestricted relay controls;
- any field not on an explicit allowlist; and
- the authorizing literal unless a fresh, marker-complete aggregate verdict
  matches the current session, release, request, mandate, and three anchors.

### 6.3 Required views

The console shows:

- Iris, Billie, and operator health;
- request received and mandate matched;
- the current protocol state;
- an actor-labelled timeline;
- all three anchor identifiers, blocks, and verified order;
- the session deadline and freshness;
- visible failure and recovery events;
- an explicit advisory label for relay and watcher data; and
- the final verifier result.

Refresh or operator restart must reconstruct the same public view from durable
validated state. The UI must not fabricate progress while data is unavailable.

## 7. Stakeholder helper page

The Clockchain Research site keeps `/handshake` as the canonical product
narrative and adds an obvious route into the runnable live demo. The helper
surface may be a section of `/handshake` or a dedicated child route, but it
must preserve existing inbound links.

It contains:

- Iris-payer and Billie-vendor role cards;
- the request-to-authorization sequence;
- a boundary diagram for the two role computers, operator services,
  Clockchain MCP, Sepolia, and the console;
- prerequisites for all three computers;
- copyable Iris and Billie coding-agent prompts;
- operator preparation and startup commands;
- reusable treasury and four-address funding instructions;
- expected outputs and stop conditions;
- common failure and recovery guidance;
- a statement that authorization does not move payment;
- a statement that only the fresh verifier authorizes; and
- an honest ready-today versus roadmap distinction.

No static sample receipt may be presented as evidence from the current
session. The helper must not claim that the physical rehearsal passed until a
real run has produced independently re-verifiable evidence.

## 8. Turnkey three-computer operation

### 8.1 Operator

From a clean checkout of the pinned release, the operator can:

1. validate the release SHA and private kit;
2. start the relay, coordinator, watcher, and console;
3. generate role-specific launch material;
4. display exactly four generated Sepolia addresses;
5. fund each address from the reusable treasury;
6. observe preflight, rehearsal, and stakeholder progress;
7. launch one fresh verifier for each completed run; and
8. preserve a secret-free handoff summary.

Ordinary rehearsal reuse must not depend on obtaining fresh faucet funds every
time. The operator checks the treasury balance and nonce before funding and
refuses an unsafe or insufficient distribution.

### 8.2 Stakeholder computers

Each stakeholder receives one private, role-specific package and one prompt:

- the Iris computer starts only the payer supervisor;
- the Billie computer starts only the payee supervisor;
- each supervisor verifies the frozen release and TLS pin;
- each supervisor keeps secrets local for the entire run; and
- no stakeholder manually transfers evidence or edits protocol artifacts.

The two stakeholder actions remain starting their physical role sessions.
Funding is an operator action performed from the reusable treasury.

## 9. Failure behavior

The system stops without authorization when:

- a request or mandate is missing, duplicated, expired, malformed, replayed,
  or mismatched;
- either identity or release binding differs;
- currency, value, purpose, payer, payee, or invoice reference changes;
- a transition is missing, duplicated, reordered, or linked to the wrong
  predecessor;
- an anchor cannot be independently fetched or violates the time window;
- a party result, failure, recovery, or verifier artifact is marker-incomplete;
- the relay or coordinator restarts into inconsistent state;
- the treasury is insufficient or a funding transaction cannot be verified;
- the console sees advisory completion without a matching fresh verdict; or
- any component observes `paymentMoved:true`.

Failures are explicit, durable, and visible in the console without exposing
secrets. Retrying creates or follows an exact recovery artifact; it never
silently rewrites history.

## 10. Verification strategy

Behavior changes follow strict test-driven development:

1. add a failing `node:test` case;
2. observe the intended failure;
3. implement the smallest passing change;
4. refactor only while the targeted suite remains green.

Required automated evidence:

- exact validator unit tests for every new and marker-complete artifact;
- signature, canonicalization, replay, expiry, and mismatch negative tests;
- relay request-endpoint and recovery integration tests;
- payer/payee protocol tests using Iris and Billie in their canonical roles;
- console redaction and fresh-verdict gating tests;
- browser tests for role wording, prompts, links, and failure presentation;
- deterministic isolated multiprocess end-to-end coverage;
- restart and recovery coverage;
- documentation gates;
- independent integrated specification and security reviews; and
- one final fresh `npm run verify` after the integrated diff is complete.

Focused suites are used during iteration. The complete suite runs only as the
final repository gate.

## 11. Completion gates

### 11.1 Implementation-complete and rehearsal-ready

This gate passes only when:

- the canonical Iris-payer/Billie-payee flow works end to end;
- the request boundary and Iris mandate are exact and signed;
- the three-anchor and sole-verifier invariants hold under positive and
  adversarial tests;
- the operator console is secure, accurate, and restart-safe;
- the helper page is deployed and matches the executable system;
- the reusable funding workflow is validated without exposing secrets;
- the deterministic multiprocess test passes;
- independent integrated review has no unresolved blocking finding;
- final fresh verification passes; and
- a precise three-computer handoff identifies the pinned release, private
  inputs, commands, expected evidence, and stop conditions.

### 11.2 Live-demo validated

This gate additionally requires:

- Iris running on stakeholder computer one;
- Billie running on stakeholder computer two;
- the operator running independently;
- a real Billie request reaching the payer-owned logical inbox;
- a live Iris mandate match;
- three fresh independently verifiable Clockchain anchors;
- console progress matching the real session;
- a fresh aggregate-verifier `AUTHORIZED` result;
- independently rechecked evidence after the run;
- confirmation that no payment moved; and
- runbook updates for any operational friction discovered.

Until those physical-session conditions are met, reports must say
“implementation-complete and rehearsal-ready,” not “live-demo validated.”

## 12. Non-goals

This delivery does not:

- transfer payment or implement x402 settlement;
- run AP2 as a live payment rail;
- add a fourth Clockchain authorization anchor;
- make the relay, watcher, dashboard, or coordinator authoritative;
- prove physical separation cryptographically;
- deploy a production multi-validator network;
- publish a reusable public request endpoint for arbitrary vendors;
- commit invitations, capabilities, credentials, private keys, or live
  evidence; or
- claim court-grade, production-grade, or trustless operation.
