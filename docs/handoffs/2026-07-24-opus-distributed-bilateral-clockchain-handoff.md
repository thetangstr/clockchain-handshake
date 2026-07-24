# Opus handoff: distributed bilateral Clockchain payment authorization

Recorded: 2026-07-24, America/Los_Angeles

This is the durable continuation handoff for the next Claude Opus session. It
captures the merged repository state, the limits of the completed live
exercise, the product behavior clarified after that exercise, and the work
that remains. It contains no invitation code, private key, encrypted
invitation ciphertext, Clockchain token, raw client log, or private live
result pair.

## Copy/paste continuation instruction

```text
Continue the Clockchain Handshake project from the distributed bilateral
payment-authorization handoff.

Work from a new branch based on the latest origin/main in the original
repository checkout. Do not continue implementation from the stale Conductor
worktree.

Read, in order:
1. AGENTS.md
2. CLAUDE.md
3. docs/handoffs/2026-07-24-opus-distributed-bilateral-clockchain-handoff.md
4. docs/superpowers/specs/2026-07-22-turnkey-handshake-demo-design.md
5. docs/superpowers/plans/2026-07-22-turnkey-handshake-demo.md
6. DEMO.md
7. prompts/run-turnkey-demo.md
8. docs/demo-evidence/latest.md

The next product is not the existing two-client acceptance harness. Design a
real distributed bilateral protocol in which Billy runs in a Codex coding
session on one physical machine and Iris runs in Claude Code on another
physical machine. Clockchain is where the parties meet and is the timestamped,
verifiable evidence layer.

Approved behavior:
- Billy is the payer and mandates the Clockchain handshake.
- Iris is the payment receiver and must comply before authorization.
- No funds move in this demo.
- Billy publishes a payment intent.
- Iris retrieves and accepts the exact intent through Clockchain.
- Billy independently verifies Iris's acceptance and publishes a final
  acknowledgment.
- Only the final acknowledgment changes the outcome to authorized.
- Every state transition must have independently verifiable Clockchain time
  and anchoring.
- The proposal expires after 10 minutes.
- Missing, mismatched, duplicated, expired, or reordered evidence fails closed.

Do not start implementation until the bilateral protocol design is explicit
and reviewed. First verify the currently deployed Clockchain APIs needed for
rendezvous, receipt discovery, correlation, and read-only verification. Do not
invent unsupported service capabilities.

Preserve the current safety boundary:
- do not reuse either consumed stakeholder invitation;
- do not rerun the prior Billy or Iris wallets;
- do not perform an Ethereum or Clockchain write without an explicitly
  approved fresh live-test step;
- do not claim the prior same-host harness proved the new two-machine flow;
- do not change repository visibility without explicit authorization; and
- do not commit secrets, raw evidence, invitations, tokens, or logs.
```

## Executive status

The first-generation Handshake demo is committed, pushed, merged, and
deterministically verified. It proves that clean Codex and Claude Code clients
can independently create official ERC-8004 identities and independently
produce anchored, re-verifiable Clockchain receipts.

It does **not** implement the newly clarified product:

- the clients were orchestrated sequentially on one host by the operator
  acceptance harness;
- their receipts were independent rather than two transitions in one shared
  bilateral protocol;
- `counterparty` was the literal `clockchain:handshake`, not the peer agent;
- "cross-party verification" meant a keyless Clockchain verification path,
  not Billy verifying Iris;
- there was no payer proposal, payee acceptance, payer acknowledgment, shared
  expiry, or distributed evidence collector; and
- the original live aggregate manifest remained `FAIL` because Claude's valid
  result pair was created outside the harness collection root and was later
  recovered and independently verified with that provenance limitation.

Do not describe the merged first-generation implementation as the requested
two-machine bilateral demo.

## Authoritative repository state at handoff

| Item | State |
| --- | --- |
| Repository | `thetangstr/clockchain-handshake` |
| Original checkout | `/Volumes/home/Projects_Hosted/clockchain/clockchain-handshake/clockchain-handshake` |
| Default branch | `main` |
| Pre-handoff merge commit | `f51de3361f43497a92c81f3a81de3c0caa5423f5` |
| Merged PR | `#1`, `Deliver the independently verifiable Handshake demo` |
| Repository visibility | `PRIVATE` at the start of this handoff |
| Runtime | Node.js 22, ESM |
| Deterministic verification | `407/407` tests and `3` documentation checks passed before this handoff commit |
| Existing live client SHA | `a603572a5d0a2773a273fc68b5312d9f1100d1f1` |
| Final deterministic candidate before merge | `3119ce664acaa8f5872f4cc0f4b98e2b1abba5fd` |
| Existing stakeholder wallets | Both consumed; both had nonce `2`; never reuse |

After this file is committed, use `git rev-parse origin/main` to obtain the new
branch point rather than assuming the pre-handoff SHA above remains current.

## Original checkout versus Conductor worktree

Use the original checkout for the next branch.

The preserved Conductor worktree is:

`/Users/Kailor/conductor/workspaces/clockchain-handshake/maseru`

It remains on old branch state `3fbe7bb1dcfc029f30e9263d69d050955abd2898`
and contains:

- local modifications to `scripts/run-clean-clients.mjs` and
  `test/acceptance-harness.test.mjs`;
- generated `.omc/` state; and
- ignored `.context/` handoff, recovery, and private evidence material.

The two visible source modifications are stale duplicates. Their exact
production-environment fix and regression test are already present on merged
`main`. Do not copy them into a new branch and do not interpret them as missing
product work.

Do not delete or archive the Conductor workspace as part of ordinary feature
work. Its ignored `.context/` directory contains private historical material.
Retention or secure removal is a separate explicit decision.

## What is already built

The merged repository contains:

- one byte-identical public prompt for clean Codex and Claude Code sessions;
- authenticated, encrypted, disposable invitation bundles;
- safe operator invitation creation and readiness checks;
- official ERC-8004 registration on Ethereum Sepolia chain ID `11155111`;
- strict use of Identity Registry
  `0x8004A818BFB912233c491871b3d84c89A494BD9e`;
- checkpointed registration recovery with replay and nonce-gap protection;
- a hosted Clockchain MCP client;
- independent Clockchain timestamp acquisition;
- single-shot receipt submission;
- bounded receipt completion;
- canonical receipt-commitment recomputation;
- receipt verification against an on-chain block;
- keyless Clockchain verification;
- secret redaction and canonical `result.json` plus `RESULT.md` evidence;
- an operator-only same-host clean-client harness;
- an independent two-result verifier bound to that harness manifest;
- deterministic, adversarial, lifecycle, custody, and documentation tests; and
- a sanitized public summary of the prior live evidence and its limitations.

Important current files:

- `src/run.mjs` — unilateral demo orchestration and current receipt payload
- `src/mcp.mjs` — hosted Clockchain MCP transport and verification adapters
- `src/evidence.mjs` — strict `clockchain.handshake-result/v1` evidence schema
- `scripts/run-clean-clients.mjs` — same-host sequential Codex/Claude harness
- `scripts/verify-live-results.mjs` — harness-bound aggregate verification
- `prompts/run-turnkey-demo.md` — current universal unilateral prompt
- `DEMO.md` — current stakeholder and operator safety boundary
- `docs/demo-evidence/latest.md` — sanitized prior live evidence

## Current receipt behavior that must change

The existing receipt input in `src/run.mjs` is conceptually:

```json
{
  "runId": "one-client-run-id",
  "identityReference": "the-current-agent",
  "counterparty": "clockchain:handshake",
  "authorization": {
    "amount": "100",
    "currency": "USD",
    "settlement": "not-executed"
  }
}
```

The existing evidence schema fixes:

```json
{
  "action": "trust_handshake",
  "counterparty": "clockchain:handshake",
  "amount": {
    "value": "100",
    "currency": "USD",
    "moved": false
  }
}
```

These objects describe one agent's action. They do not bind:

- a shared bilateral session;
- payer and payee identity references;
- one canonical payment-intent digest;
- proposal, acceptance, and acknowledgment roles;
- predecessor receipt references;
- a 10-minute deadline;
- monotonic protocol state;
- peer verification results; or
- a distributed aggregate verdict.

Treat the new behavior as a protocol and evidence-schema version change. Do not
silently broaden the meaning of `clockchain.handshake-result/v1`.

## Approved product contract

### Parties

- **Billy** is the payer.
- **Iris** is the payment receiver.
- They run on different physical machines.
- Billy uses a Codex coding session with local terminal and invitation-file
  access. A plain ChatGPT web chat without a coding environment cannot execute
  the current local CLI workflow.
- Iris uses Claude Code with local terminal and invitation-file access.
- Each receives only its own opaque secret invitation.

### Commercial meaning

- Billy wants to authorize a payment of `100 USD`.
- Billy mandates the use of Clockchain as a condition of authorization.
- Iris must comply with the Clockchain handshake to become eligible to receive
  the payment.
- The demo stops at authorization.
- No card, bank, stablecoin, x402, AP2, ERC-20, or other settlement executes.
- `authorized` means the protocol conditions were proven, not that money moved
  or that an external payment processor accepted the transaction.

### Required successful sequence

1. Billy creates a payment intent identifying both roles, the amount and
   currency, the protocol/session identifier, and a 10-minute expiry.
2. Billy publishes the proposal through Clockchain.
3. Clockchain provides an anchored, independently verifiable timestamp for the
   proposal.
4. Iris retrieves the canonical proposal through the Clockchain-mediated
   rendezvous.
5. Iris verifies that she is the intended receiver, the proposal is unexpired,
   the proposal is anchored, and its payment-intent digest is exact.
6. Iris publishes acceptance of that exact proposal through Clockchain.
7. Clockchain provides an anchored, independently verifiable timestamp for the
   acceptance.
8. Billy retrieves Iris's acceptance through Clockchain.
9. Billy verifies Iris's identity, role, exact proposal binding, acceptance
   anchoring, timestamp ordering, and non-expiration.
10. Billy publishes a final acknowledgment through Clockchain.
11. Clockchain anchors and timestamps the acknowledgment.
12. Read-only verification proves all three transitions, their bindings, and
    their order.
13. The final aggregate outcome becomes `AUTHORIZED`, with
    `paymentMoved: false`.

The state sequence is:

```text
PROPOSED -> ACCEPTED -> ACKNOWLEDGED -> AUTHORIZED
```

No earlier state is authorization.

### Failure behavior

The protocol must fail closed for at least:

- expired proposal;
- wrong session;
- wrong payer or payee;
- reused identity where distinct identities are required;
- changed amount, currency, expiry, or commercial terms;
- acceptance that does not bind the exact proposal;
- acknowledgment that does not bind the exact acceptance;
- unanchored, pending, degraded, cache-only, or unverifiable receipt;
- missing consensus time;
- non-monotonic or impossible timestamp ordering;
- duplicate proposal, acceptance, or acknowledgment;
- replay from another session;
- ambiguous write outcome;
- peer evidence that cannot be retrieved through the approved rendezvous;
- mismatched repository or prompt version; or
- any secret finding in public evidence.

An expired or failed session must never produce `AUTHORIZED`.

## Timestamp and verification requirements

Clockchain is not incidental logging. Its timestamped, anchored receipts are a
mandatory protocol condition.

Each of the three transitions must expose enough public data for another reader
to verify:

- the transition type;
- the shared session identifier or commitment;
- payer and payee public identity references;
- the canonical payment-intent digest;
- the predecessor transition reference where applicable;
- the transition's anchored ledger ID and block height;
- the consensus time;
- the canonical event or receipt hash;
- verification against the on-chain block;
- the declared single-validator testnet boundary; and
- that no payment moved.

The aggregate verifier must recompute bindings from the canonical bytes. It
must not trust agent narration, filenames, or copied Markdown.

## Distributed acceptance requirement

The acceptance test must use:

- Machine A: Billy in a clean Codex coding session;
- Machine B: Iris in a clean Claude Code session;
- the exact same immutable public repository SHA;
- the exact same canonical protocol prompt version;
- distinct fresh invitations and identities;
- no shared local filesystem;
- no same-host client launcher standing in for the distributed run;
- Clockchain as the protocol rendezvous/evidence layer;
- sanitized result packages returned to an operator verifier; and
- an aggregate verdict that verifies the public evidence rather than trusting
  either agent.

The old `npm run acceptance:clients` command may remain as a regression or
same-host smoke tool, but it cannot be the acceptance proof for the new
distributed product.

## Recommended protocol shape, not yet approved

The previous design discussion stopped before approving the rendezvous
mechanism. The recommended starting point is:

1. The operator creates one unpredictable public session identifier and gives
   it to both machines.
2. Each agent registers its fresh ERC-8004 identity and announces its role
   under that session through Clockchain.
3. Billy discovers Iris's identity from the session before publishing the
   addressed proposal.
4. Iris discovers Billy's proposal from the same session.
5. Later transitions refer to immutable predecessor receipt identifiers and
   canonical digests.

This is a recommendation, not an approved design decision. Before adopting it,
Opus must verify whether the deployed Clockchain service supports safe,
bounded, public lookup by session and role. If it does not, compare alternatives
without pretending a capability exists.

At minimum compare:

1. Clockchain-indexed shared session rendezvous;
2. operator-prepared public session descriptor containing both eventual
   identity references; and
3. one public Clockchain proposal reference passed out of band, with every
   subsequent fact retrieved and verified through Clockchain.

Prefer the smallest design that honestly satisfies "the parties meet using
Clockchain."

## Open design decisions

Resolve these explicitly before implementation:

1. How both machines obtain the shared session reference.
2. How a proposal addresses Iris if her ERC-8004 agent ID is assigned only
   after she starts.
3. Which deployed Clockchain read API discovers proposals and acceptances
   without sharing raw result files.
4. Whether role announcements are separate receipts or fields in the proposal
   and acceptance.
5. Which time source defines the 10-minute expiry and how clock skew is avoided.
6. Whether the acceptance must occur before the expiry while the final Billy
   acknowledgment may occur within a bounded grace period, or whether all
   three events must anchor before expiry.
7. Idempotency and recovery rules for each irreversible receipt write.
8. The exact canonical digest and serialization rules.
9. The new result schemas and the distributed collection manifest.
10. How the operator verifies client/repository/prompt provenance on separate
    machines without claiming cryptographic remote execution attestation.
11. Whether identity registration remains part of every distributed demo or
    becomes a prerequisite before the session begins.
12. How a decline is represented, if decline is in the first implementation at
    all.

Keep the first implementation narrow. Decline, cancellation, settlement, and
production payment-network integration are not required unless separately
approved.

## Recommended implementation boundaries

After the design is approved, prefer small, separately testable units:

- canonical bilateral session and payment-intent model;
- protocol state-transition validator;
- Clockchain transition writer and read-only retriever;
- payer command/runner;
- payee command/runner;
- distributed result-package format;
- operator-side aggregate verifier;
- role-specific prompts/runbooks; and
- deterministic fake-Clockchain integration tests.

Do not make the existing unilateral `runHandshake` function silently perform
both roles. Preserve the existing demo while the bilateral protocol is added,
or define an explicit versioned migration with compatibility tests.

## Verification strategy

Follow TDD for every behavior change:

1. write the failing `node:test`;
2. observe the expected failure;
3. implement the smallest passing change;
4. refactor while green; and
5. run targeted tests before the complete suite.

The deterministic suite must include:

- canonical serialization and digest fixtures;
- valid proposal/acceptance/acknowledgment ordering;
- every state-transition rejection;
- expiry boundary tests using an injected clock;
- peer identity and role mismatch;
- predecessor receipt mismatch;
- replay across sessions;
- duplicate and ambiguous-write handling;
- missing or unverifiable Clockchain anchors;
- malformed and hostile public payloads;
- secret canaries and redaction;
- separate-machine collection manifest validation;
- repository and prompt provenance checks; and
- preservation of the unilateral demo until its disposition is explicitly
  approved.

The final live acceptance requires fresh invitations. Create and fund them only
after deterministic implementation, security review, and explicit live-test
authorization. Never use the previously consumed Billy and Iris invitations.

## Completion criteria for the next feature

Do not call the distributed bilateral feature complete until:

1. the written protocol design is approved;
2. the required Clockchain rendezvous/read APIs are verified against the
   deployed service or an approved service change is delivered;
3. deterministic tests pass;
4. security and code reviews pass;
5. two fresh invitations are created and safely funded under explicit
   authority;
6. Billy runs on one physical machine in Codex;
7. Iris runs on another physical machine in Claude Code;
8. both use the same immutable repository and prompt versions;
9. all three transitions anchor and verify;
10. the aggregate verifier independently produces `AUTHORIZED`;
11. the evidence states `paymentMoved: false`;
12. no secrets appear in committed or returned public artifacts;
13. the limitations of the current Clockchain validator configuration are
    disclosed; and
14. the live evidence and provenance limitations are recorded truthfully.

## Safety and repository rules

- Use only the official ERC-8004 Identity Registry already pinned by the
  repository.
- Never print, paste, commit, upload, or expose secret invitations.
- Never enumerate unrelated environment variables.
- Never blind-retry an ambiguous Clockchain or Ethereum write.
- Never synthesize a passing manifest from failed or incomplete evidence.
- Never call a submitted, pending, degraded, or cache-only receipt anchored.
- Never claim two-machine acceptance from same-host tests.
- Never claim bilateral verification when only one receipt was independently
  checked.
- Never claim payment execution; this feature authorizes only.
- Never change GitHub visibility without explicit authorization.
- Never remove the preserved Conductor workspace or `.context` evidence as
  incidental cleanup.

## Suggested first Opus deliverable

The first Opus deliverable should be a reviewed design specification, not code.
It should:

1. verify and cite the deployed Clockchain tool/API capabilities available for
   rendezvous and retrieval;
2. compare the three rendezvous approaches above;
3. specify canonical protocol messages and digests;
4. define the state machine, expiry semantics, and recovery rules;
5. define role-specific CLI and prompt experiences on two machines;
6. define versioned evidence and distributed manifest schemas;
7. define deterministic and live acceptance tests; and
8. explicitly record all trust and provenance limits.

Only after that specification is approved should Opus write the implementation
plan and begin TDD implementation on the new branch.
