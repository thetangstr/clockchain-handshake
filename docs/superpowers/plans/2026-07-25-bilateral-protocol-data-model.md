# Bilateral Protocol Data Model Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use
> `superpowers:subagent-driven-development` (recommended) or
> `superpowers:executing-plans` to implement this plan task-by-task. Steps use
> checkbox (`- [ ]`) syntax for tracking.

**Goal:** Complete the deterministic Round 2 protocol data model for
`clockchain.bilateral-authorization/v1`: a signed session descriptor, canonical
three-message chain, strict party-result evidence, deterministic fake
Clockchain, and fail-closed transition verifier.

**Architecture:** The descriptor is the signed root of trust and its canonical
digest derives every reference id. Message constructors build the only three
allowed transition preimages and bind each later message to authoritative
predecessor triples. The protocol verifier consumes only normalized public MCP
reads, while the deterministic fake exposes one-field mutation hooks for every
adversarial branch. Party-result validation preserves the verified transition
chain without allowing either runner to emit an aggregate authorization
verdict.

**Tech Stack:** Node.js 22, ES modules, `node:crypto`, `node:fs/promises`,
`node:test`, repository canonicalization and MCP helpers, no new dependencies.

---

## Ownership and handoff rules

- Sol owns this plan, integration, shared-file sequencing, review, verification,
  and the Round 2 commit.
- Terra is the sole writable implementer for each task below. Only one Terra
  task may be active at a time.
- Luna is read-only and may audit spec coverage or test evidence.
- The inherited untracked files are preserved until their behavior is
  understood. They are not staged merely because they exist.
- No live Clockchain write, repository visibility change, invitation generation,
  or credentialed command belongs to this plan.
- A discarded test-key fixture remains reachable only through local
  `refs/conductor-checkpoints/...` history. The keypairs are permanently
  non-reusable. Do not rewrite or delete Conductor checkpoint refs without a
  separate explicit destructive-action decision; before the final completion
  verdict, confirm the blob is absent from branch/remote history and resolve
  local checkpoint retention through a Conductor-safe cleanup path.
- Every new behavior follows red-green-refactor. Existing inherited red tests
  count only after their failure is reproduced and shown to be caused by the
  missing behavior.
- Terra reports changed files, exact commands/results, self-review findings, and
  concerns. Sol independently reads the diff and reruns verification.

## Task 1: Signed descriptor and session creation

**Files:**

- Create: `src/bilateral/descriptor.mjs`
- Create: `scripts/create-session.mjs`
- Adopt and modify only as needed:
  `test/bilateral-descriptor.test.mjs`
- Remove from the inherited handoff and never stage:
  `test/fixtures/bilateral-test-operator-key.json`

- [ ] **Step 1: Preserve the inherited descriptor red evidence**

Run:

```bash
node --test test/bilateral-descriptor.test.mjs
```

Expected: FAIL because `src/bilateral/descriptor.mjs` does not exist. If the
failure differs, stop and report the new baseline rather than weakening tests.

- [ ] **Step 2: Implement the frozen descriptor schema**

`src/bilateral/descriptor.mjs` must export the constants, exact-key lists, error
types, key conversion helpers, signing helpers, envelope helpers, and
`dSession()` named by `test/bilateral-descriptor.test.mjs`.

The implementation must enforce:

```text
schema          = clockchain.bilateral-session-descriptor/v1
protocol        = clockchain.bilateral-authorization/v1
protocolVersion = 1
namespace       = cbv1
chainId         = 11155111
registry        = 0x8004a818bfb912233c491871b3d84c89a494bd9e
expirySeconds   = 600
settlement      = not-executed
paymentMoved    = false
```

It must reject unknown/missing keys, numbers, noncanonical decimal strings,
non-lowercase addresses and hashes, non-ASCII/trimmed display names, duplicate
party identities, sparse or property-bearing arrays, and
unsorted/duplicate/out-of-range amount options. Positive canonical amount
decimals use an integer part of `0|[1-9][0-9]*` and an optional fractional part
whose final digit is `1-9`: accept `100`, `1.25`, and `0.5`; reject `0`, `0.0`,
`1.0`, `1.00`, `0.50`, leading zeroes, signs, and exponents.

Validation, digesting, signing, verification, and returned envelopes must use
one bounded deep snapshot materialized only from enumerable own data-property
descriptors. Hostile Proxy `get` traps, accessors, symbols, unsupported
prototypes, sparse/property-bearing arrays, or traversal failures must never let
semantic validation inspect values different from the authenticated bytes.

`dSession(descriptor)` must be exactly:

```js
digestHex(descriptor)
```

after strict descriptor validation, using the bilateral canonicalizer.

- [ ] **Step 3: Implement Ed25519 trust-root verification**

Sign `canonicalBytes(descriptor)`. Decode and encode only raw 32-byte Ed25519
public keys and canonical base64 signatures; hexadecimal signatures are
rejected. Reject before decoding unless a signature is exactly 88 characters
and a raw public key is exactly 44 characters. Public-key PEM helpers accept
only canonical SPKI `PUBLIC KEY` input, never a private/secret PEM.
`verifyDescriptorEnvelope()` must require the envelope's public key to
byte-match the repository key selected by
`docs/operator-keys/<keyId>.pub`; a self-consistent key shipped only inside the
envelope is never trusted.

- [ ] **Step 4: Implement the operator session tool**

`scripts/create-session.mjs` must expose explicit `keygen` and `create` modes
with injected filesystem, randomness, Git-at-SHA read, and output dependencies
as exercised by the test.

`keygen` must:

- generate one Ed25519 keypair;
- write the private key mode `0600` only at the gitignored
  `.context/operator-keys/<keyId>.ed25519.pem` path;
- write the raw public key at `docs/operator-keys/<keyId>.pub`;
- reject symlinks in every existing ancestor of either path, physically verify
  containment, enforce the private directory at mode `0700`, and use
  exclusive/no-follow descriptor writes with cleanup after partial failures;
- refuse either existing target; and
- emit only public metadata, never the private path or material.

The operator commits the public-key file before `create` runs.

`create` must:

- accept exactly one of `--prompt-sha256` or `--prompt-file`;
- generate a 128-bit lowercase-hex session id;
- require the existing default private and public files;
- require the derived public key to match the working-tree public file;
- retrieve `docs/operator-keys/<keyId>.pub` from the claimed
  `repositorySha` using `git show` (through an injected seam) and require
  byte equality before signing;
- prove the default `git show` implementation in a temporary-Git integration
  test without ever committing private material;
- bound the amount argument and prompt-file byte length before processing;
- refuse overwrites; and
- emit only the signed public envelope, never a private path or material.

No custom private-key input or output path is accepted; the single coherent
private-key boundary is `.context/operator-keys`.

- [ ] **Step 5: Run and refine the descriptor suite**

Run:

```bash
node --test test/bilateral-descriptor.test.mjs
```

Expected: PASS with no warnings. Fix production behavior, not assertions.

- [ ] **Step 6: Replace private-key fixtures and check output secrecy**

The inherited `test/fixtures/bilateral-test-operator-key.json` contains literal
private-key PEMs and must not be committed. Generate ephemeral Ed25519 operator
and impostor keypairs inside the test process instead, remove the fixture, and
run:

```bash
rg -n -i 'invitation|bearer|api[_-]?key|token|private key' \
  src/bilateral/descriptor.mjs scripts/create-session.mjs \
  test/bilateral-descriptor.test.mjs test/fixtures
```

Expected: only validation/error/test language, never private-key material or a
live credential in a tracked or staged file.

## Task 2: Canonical transition messages and amount recovery

**Files:**

- Create: `src/bilateral/messages.mjs`
- Create: `test/bilateral-messages.test.mjs`

- [ ] **Step 1: Write the frozen message-shape tests**

The test must first import a nonexistent `src/bilateral/messages.mjs` and pin:

```text
TRANSITION_SCHEMA = clockchain.bilateral-transition/v1
kind/sequence      = proposal/1, acceptance/2, acknowledgment/3
decision           = ACCEPT
outcome            = ACKNOWLEDGED
paymentMoved       = false
```

Pin the exact sorted keys for the common head, amount, party, predecessor
triple, M1, M2, and M3. Pin one canonical byte string and SHA-256 digest for
each message using a deterministic descriptor and authoritative triples.

- [ ] **Step 2: Observe the message-suite red state**

Run:

```bash
node --test test/bilateral-messages.test.mjs
```

Expected: FAIL because `src/bilateral/messages.mjs` does not exist.

- [ ] **Step 3: Implement constructors and validation**

Export focused constructors:

```js
buildProposal({ descriptor, sessionDigest, amount })
buildAcceptance({ proposal, proposalTriple })
buildAcknowledgment({ acceptance, acceptanceTriple, proposalTriple })
validateTransition(message)
transitionDigest(message)
authoritativeTriple({ kind, ledgerId, blockHeight, anchoredHash })
```

All constructors must return fresh plain data, validate exact keys, and derive
every field from the descriptor or authoritative predecessor data. They must
never accept a memo, local timestamp, nonce, cache timestamp, write response, or
advisory field.

- [ ] **Step 4: Add and prove the derivability guard**

Export frozen key lists and a frozen `DERIVABLE_TRANSITION_FIELDS` allowlist.
The test must assert every M2 and M3 key path is a subset of this explicit
allowlist. Add negative tests showing that a memo, local timestamp, or nonce is
rejected.

- [ ] **Step 5: Implement bounded proposal amount recovery**

Export:

```js
recoverProposalByDigest({ descriptor, sessionDigest, anchoredHash })
```

It must enumerate at most the eight signed `amountOptions`, construct each M1,
and return a result only when exactly one digest matches. Zero matches and two
or more matches must throw distinct typed errors that the protocol layer maps to
`AMOUNT_UNRESOLVED`.

The exported recovery API accepts only
`{descriptor, sessionDigest, anchoredHash}` and must unconditionally use the
canonical proposal constructor plus real transition digest. Tests may exercise
zero/one/multiple cardinality through a separate pure selector over already
validated candidate records; no test seam may replace production construction
or digest behavior.

- [ ] **Step 6: Run the message suite**

Run:

```bash
node --test test/bilateral-messages.test.mjs
```

Expected: PASS with byte-pinned messages, digest pins, validation failures,
derivability guard, and zero/one/two-match amount-recovery cases.

## Task 3: Bilateral party-result evidence

**Files:**

- Create: `src/bilateral/evidence.mjs`
- Adopt and modify only as needed: `test/bilateral-evidence.test.mjs`

- [ ] **Step 1: Preserve the inherited evidence red state**

Run:

```bash
node --test test/bilateral-evidence.test.mjs
```

Expected: FAIL because `src/bilateral/evidence.mjs` does not exist.

- [ ] **Step 2: Implement exact-key validation**

Export every constant, error type, validator, renderer, and writer named by the
test. Validate `clockchain.bilateral-party-result/v1` recursively with:

- no numbers or integer-like keys;
- printable, trimmed ASCII strings;
- `paymentMoved === false`;
- local verdict limited to `LOCAL_OK` or the frozen terminal-code list;
- at most three ordered proposal/acceptance/acknowledgment entries;
- recomputed message digest equal to both recorded digest and anchored hash;
- strictly increasing decimal-string block heights;
- raw block time parsed only by `parseBlockTime`;
- deadline derived only from M1 block time plus 600 seconds;
- later upper bounds at or before the deadline;
- exact predecessor triples;
- `ackObserved` consistent with the observed chain;
- valid signature and rendezvous disclosure shapes; and
- no secret-shaped or authorizing text anywhere.

- [ ] **Step 3: Derive rendezvous wording from structured facts**

`rendezvousClaimSentence()` must weaken its claim when the channel is
`digest-hash` or `out-of-band-pointer`, or when tenancy is not proven
`cross-client`. Human-supplied prose must not determine the claim.

- [ ] **Step 4: Render and write atomically**

`renderPartyResultMarkdown()` must derive all content byte-for-byte from the
validated JSON object. `writePartyResult()` must validate and redact before
creating either artifact, refuse overwrites, and avoid leaving a partial JSON or
Markdown file when validation fails.

- [ ] **Step 5: Run the evidence suite**

Run:

```bash
node --test test/bilateral-evidence.test.mjs
```

Expected: PASS for the valid payer/payee/terminal fixtures and every inherited
tamper/redaction/deadline/predecessor case.

## Task 4: Deterministic fake and fail-closed transition verification

**Files:**

- Create: `test/helpers/fake-bilateral-clockchain.mjs`
- Modify: `src/bilateral/protocol.mjs`
- Expand: `test/bilateral-protocol.test.mjs`

- [ ] **Step 1: Preserve the inherited protocol red state**

Run:

```bash
node --test test/bilateral-protocol.test.mjs
```

Expected: FAIL because the fake helper does not exist. After the fake is added,
the suite must still fail until the missing `verifyTransition` behavior is
implemented.

- [ ] **Step 2: Implement the deterministic fake**

The fake must implement the normalized methods used by the protocol:

```js
logAction()
searchActions()
verifyCrossParty()
getBlock()
resolveAgent()
generateAuditTrail()
registerAgent()
```

Every write creates deterministic ledger id, block height, anchored hash,
reference id, and nanosecond block time. Expose one-field mutation hooks:

```js
mutateSearch
mutateCrossParty
mutateBlock
```

Hooks must clone data before mutation so one test cannot contaminate another.
The fake must support duplicates, missing records, rate-limit errors, ambiguous
writes, inactive/mismatched identities, missing blocks, and audit counts without
ever becoming a second production implementation.

- [ ] **Step 3: Write the authoritative-recipe tests**

Before implementing `verifyTransition`, add tests for:

- search length 0, 1, and greater than 1;
- non-array and in-body rate-limit search results;
- explicit ledger id and block height passed to `verifyCrossParty`;
- deliberate omission of the `hash` argument;
- `verifiedAgainst === "on-chain block"` and `keyless === true`;
- byte-exact ledger id, height, hash, and reference-id bindings;
- local digest equality;
- independent block-time retrieval;
- active peer and matching owner;
- `get_block` 502/non-verification;
- wrong-height-plus-correct-hash advisory trap;
- forged anchored hash, reference id, and rehydrated event hash; and
- every trust-path banned field proving irrelevant when mutated.

Run the suite and confirm the new assertions fail because
`verifyTransition` is missing or incomplete.

- [ ] **Step 4: Implement `verifyTransition` minimally**

`verifyTransition()` must return only the authoritative transition data required
downstream:

```js
{
  ledgerId,
  blockHeight,
  anchoredHash,
  assetReferenceId,
  blockTimeRaw,
  blockTimeMs
}
```

It must map failures to the frozen terminal codes and must never consult
`advisoryHashCheck`, cache `record`, `verify_package`, `verify_asset`,
`additionalInfo`, cache timestamps, embedded package blocks/validation, or
`get_validation`.

- [ ] **Step 5: Encode all 28 matrix rows at the correct layer**

Rows exercised by descriptor, canonical messages, evidence, transport, or the
runner state machine may cite those targeted tests. Every remaining row must
have a direct protocol/fake test. Add an explicit coverage table in test
comments mapping rows 1-28 to test names; no row may exist only as prose.

- [ ] **Step 6: Run the fake/protocol suite**

Run:

```bash
node --test test/bilateral-protocol.test.mjs
```

Expected: PASS with no authorizing literal in the runner protocol module and no
banned field affecting any verdict.

## Task 5: Round 2 integration, independent review, and commit

**Files:**

- Review all Round 2 files from Tasks 1-4
- Modify only the smallest files required to resolve verified integration gaps

- [ ] **Step 1: Run the complete targeted Round 2 suite**

Run:

```bash
node --test \
  test/bilateral-canonical.test.mjs \
  test/bilateral-blocktime.test.mjs \
  test/bilateral-refid.test.mjs \
  test/bilateral-descriptor.test.mjs \
  test/bilateral-messages.test.mjs \
  test/bilateral-evidence.test.mjs \
  test/bilateral-protocol.test.mjs
```

Expected: PASS.

- [ ] **Step 2: Run spec-compliance review**

A fresh read-only reviewer must compare the full Round 2 diff to design sections
4.4-4.13, 5.1-5.5, 6.2-6.4, and 8.2. Terra fixes every missing or extra
requirement; the reviewer reruns until approved.

- [ ] **Step 3: Run code-quality and security review**

A separate fresh reviewer checks exact-key validation, cryptographic key
handling, canonical-byte stability, input bounds, mutation-hook isolation,
banned-field exclusion, filesystem overwrite behavior, and secret leakage.
Critical and important findings must be fixed and re-reviewed.

- [ ] **Step 4: Run full repository verification three consecutive times**

Run:

```bash
npm run verify
npm run verify
npm run verify
```

Expected on every run: exit 0, all tests pass, and all public documents pass
their gates. A flaky or failed run resets the consecutive count.

- [ ] **Step 5: Inspect the final diff and secret surface**

Run:

```bash
git status --short
git diff --check
git diff --stat
git diff
```

Confirm no unrelated or concurrent file is staged. Confirm the fixture key is
absent and no invitation, live token, operator private key, email, or generated
live evidence is included.

- [ ] **Step 6: Create the Round 2 Lore commit**

Stage only reviewed Round 2 files and use a Lore-format decision record with
fresh `Tested:` and `Not-tested:` trailers. Sol, not an implementer or reviewer,
owns this integration commit.
