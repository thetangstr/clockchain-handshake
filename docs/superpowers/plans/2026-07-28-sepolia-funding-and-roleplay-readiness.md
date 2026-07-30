# Sepolia Funding and Two-Machine Role-Play Readiness Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the existing bilateral authorization demo operationally repeatable by funding the coordinator's four fresh addresses from one encrypted Sepolia treasury and by giving an operator, Stakeholder 1 (Iris), and Stakeholder 2 (Billy) exact two-machine launch instructions.

**Architecture:** Add a funding-only boundary under `src/bilateral/funding/` that validates the coordinator's canonical address record, opens the existing encrypted Web3 keystore through a bounded macOS Keychain reader, plans exact top-ups, persists discovery-first transaction journals, and broadcasts sequential Sepolia transfers. Preserve the existing relay, supervisor, coordinator, three-anchor protocol, and verifier authority; the role-play documentation only packages those existing surfaces for a reachable TLS-pinned relay and two physical role machines.

**Tech Stack:** Node.js 22 ES modules, `node:test`, existing pinned `viem@2.55.8`, macOS Keychain `security` reader, Ethereum Sepolia JSON-RPC, repository-native documentation gates.

---

## File map

- Create `src/bilateral/funding/record.mjs`: exact coordinator-record validation and deterministic top-up planning.
- Create `src/bilateral/funding/keystore.mjs`: strict keystore/public-metadata validation, Keychain password retrieval, and in-memory decryption.
- Create `src/bilateral/funding/journal.mjs`: private batch journal validation, durable state transitions, and recovery classification.
- Create `scripts/fund-bilateral-addresses.mjs`: fail-closed CLI composition and production Sepolia client.
- Create `test/bilateral-funding-record.test.mjs`: record, ordering, balance, nonce, and fee-plan tests.
- Create `test/bilateral-funding-keystore.test.mjs`: keystore, metadata, file-safety, Keychain, and secret-output tests.
- Create `test/bilateral-funding-journal.test.mjs`: durable intent, crash recovery, transaction replacement, and tamper tests.
- Create `test/bilateral-funding-cli.test.mjs`: injected end-to-end funding command tests.
- Modify `src/bilateral/coordination/coordinator.mjs`: canonical Billy/Iris funding order.
- Modify `src/bilateral/coordination/coordinator-runtime.mjs`: enrollment wait and durable funding-record publication.
- Modify `test/bilateral-coordination-coordinator.test.mjs`: canonical order and durable-record expectations.
- Modify `test/bilateral-coordination-coordinator-runtime.test.mjs`: production wait and file-publication tests.
- Modify `test/bilateral-coordination-process-e2e.test.mjs`: start the real coordinator before the two supervisors.
- Modify `package.json`: expose one funding command without adding dependencies.
- Modify `README.md`: name the reusable treasury and the two stakeholder roles.
- Modify `docs/runbooks/bilateral-demo-day.md`: exact remote relay/TLS setup, funding capture command, role-packet handoff, and rehearsal sequence.
- Modify `prompts/run-billy-bilateral-demo.md`: identify Stakeholder 2 as Billy and keep the one-supervisor boundary.
- Modify `prompts/run-iris-bilateral-demo.md`: identify Stakeholder 1 as Iris and keep the one-supervisor boundary.
- Modify `scripts/check-docs.mjs`: gate the new command, physical relay endpoint, role mapping, and authority invariants.
- Modify `test/docs.test.mjs`: prove the new documentation gates fail closed.

### Task 0: Repair the production coordinator startup and publish its canonical funding input

**Files:**
- Modify: `src/bilateral/coordination/coordinator.mjs`
- Modify: `src/bilateral/coordination/coordinator-runtime.mjs`
- Modify: `test/bilateral-coordination-coordinator.test.mjs`
- Modify: `test/bilateral-coordination-coordinator-runtime.test.mjs`
- Modify: `test/bilateral-coordination-process-e2e.test.mjs`

- [ ] **Step 1: Write a failing production-order process test**

Change the process E2E orchestration so it:

1. starts the real relay;
2. starts the real coordinator CLI;
3. waits until `payee.launch.json` and `payer.launch.json` exist;
4. starts the payee and payer supervisor processes;
5. observes both authenticated enrollments;
6. continues to the one funding-address record and the existing isolated protocol completion.

Do not use the test-only shortcut that starts supervisors and waits for both enrollments before invoking the coordinator core.

- [ ] **Step 2: Run the process test and observe RED**

Run:

```sh
node --test --test-name-pattern \
  "real coordinator and supervisors gate one isolated three-transition process session" \
  test/bilateral-coordination-process-e2e.test.mjs
```

Expected: FAIL because the production coordinator tries to read the complete enrollment set before either supervisor can start.

- [ ] **Step 3: Write failing runtime tests for enrollment waiting**

Inject a client whose `readSessionView()` returns:

```js
[
  { facts: { enrollmentConfirmed: { payee: false, payer: false } } },
  { facts: { enrollmentConfirmed: { payee: true, payer: false } } },
  { facts: { enrollmentConfirmed: { payee: true, payer: true } } },
]
```

Assert that the runtime does not call `readEnrollmentSet()` until the third view. Once both advisory readiness bits are true, require one authoritative enrollment-set read and normal cryptographic validation. Timeout, clock regression, malformed view facts, or a view/set disagreement fails closed.

- [ ] **Step 4: Implement bounded enrollment readiness waiting**

In the production coordinator dependencies, wrap the authoritative read:

```js
async function waitForEnrollmentSet() {
  const deadline = now() + COORDINATOR_FUNDING_DEADLINE_MS;
  for (;;) {
    const view = await client.readSessionView();
    const confirmed = view?.facts?.enrollmentConfirmed;
    if (confirmed?.payee === true && confirmed?.payer === true) {
      return client.readEnrollmentSet();
    }
    if (now() >= deadline) fail();
    await sleeper(Math.min(
      COORDINATOR_FUNDING_INTERVAL_MS,
      Math.max(1, deadline - now()),
    ));
  }
}
```

The view remains advisory: it only decides when to attempt the authoritative signed enrollment-set read. It never supplies enrollment identity, keys, invitations, or authorization.

- [ ] **Step 5: Write failing canonical-order tests**

Require the coordinator's four addresses in this order:

```text
Billy rehearsal
Iris rehearsal
Billy stakeholder
Iris stakeholder
```

Expressed in code:

```js
[
  payer.invitations.rehearsal.address,
  payee.invitations.rehearsal.address,
  payer.invitations.stakeholder.address,
  payee.invitations.stakeholder.address,
]
```

This aligns the committed funding design, the durable record, the journal, and the operator-facing role labels.

- [ ] **Step 6: Write failing durable-record tests**

Require one mode-`0600`, single-link, canonical file at:

```text
<release-root>/funding-addresses.json
```

with exact bytes for:

```js
{
  addresses,
  paymentMoved: false,
  schema: "clockchain.bilateral-funding-addresses/v1",
}
```

It must be published before the coordinator enters its funding wait, survive restart byte-for-byte, reject replacement/mismatch, and never contain a capability, token, invitation, private key, RPC URL, or authorization verdict.

- [ ] **Step 7: Implement canonical ordering and exclusive publication**

Build the address array in the committed order and pass the exact frozen record to a runtime dependency that:

- writes a same-directory mode-`0600` temporary with `O_EXCL | O_NOFOLLOW`;
- fsyncs the file;
- renames atomically to `funding-addresses.json`;
- fsyncs the release root;
- on restart, validates the exact existing canonical bytes instead of rewriting.

Continue emitting the same secret-free JSON line to stdout for operator visibility.

- [ ] **Step 8: Run focused coordinator tests and observe GREEN**

Run:

```sh
node --test \
  test/bilateral-coordination-coordinator.test.mjs \
  test/bilateral-coordination-coordinator-runtime.test.mjs \
  test/bilateral-coordination-process-e2e.test.mjs
```

Expected: PASS, including coordinator-first process startup.

- [ ] **Step 9: Commit Task 0 with a Lore message**

Stage only the five owned files and record the focused process evidence.

### Task 1: Validate the canonical four-address record and calculate exact top-ups

**Files:**
- Create: `src/bilateral/funding/record.mjs`
- Test: `test/bilateral-funding-record.test.mjs`

- [ ] **Step 1: Write failing tests for the accepted record**

Create fixtures whose only accepted coordinator record is:

```js
const record = {
  addresses: [
    "0x1111111111111111111111111111111111111111",
    "0x2222222222222222222222222222222222222222",
    "0x3333333333333333333333333333333333333333",
    "0x4444444444444444444444444444444444444444",
  ],
  paymentMoved: false,
  schema: "clockchain.bilateral-funding-addresses/v1",
};
```

Assert that `validateFundingRecord(record)` returns an immutable copy and rejects:

```js
[
  null,
  { ...record, extra: true },
  { ...record, paymentMoved: true },
  { ...record, addresses: record.addresses.slice(0, 3) },
  { ...record, addresses: [record.addresses[0], record.addresses[0], ...record.addresses.slice(2)] },
  { ...record, addresses: record.addresses.map((value, index) => index === 0 ? value.toUpperCase() : value) },
  { ...record, addresses: record.addresses.map((value, index) => index === 0 ? "0x0000000000000000000000000000000000000000" : value) },
];
```

- [ ] **Step 2: Run the focused record test and observe RED**

Run:

```sh
node --test test/bilateral-funding-record.test.mjs
```

Expected: FAIL because `src/bilateral/funding/record.mjs` does not exist.

- [ ] **Step 3: Implement exact record validation**

Export this public surface:

```js
export const FUNDING_RECORD_SCHEMA =
  "clockchain.bilateral-funding-addresses/v1";
export const PARTICIPANT_MINIMUM_WEI = 5_000_000_000_000_000n;
export const PARTICIPANT_TARGET_WEI = 10_000_000_000_000_000n;
export const PARTICIPANT_MAXIMUM_WEI = 20_000_000_000_000_000n;

export class BilateralFundingError extends Error {
  constructor(code = "BILATERAL_FUNDING_INVALID") {
    super("Bilateral funding failed safely.");
    this.name = "BilateralFundingError";
    this.code = code;
  }
}

export function validateFundingRecord(value) {
  // Require a plain data object with exactly addresses, paymentMoved, schema.
  // Require four distinct lowercase nonzero Ethereum addresses in supplied order.
  // Require schema v1 and paymentMoved exactly false.
  // Return a deeply frozen copy; never retain accessors or caller-owned arrays.
}
```

- [ ] **Step 4: Write failing tests for funding facts and top-up planning**

Use `planFundingTransfers({ feePerTransferWei, fundingBalanceWei, fundingNonce, participantFacts, record })` and assert:

```js
const facts = [
  { address: record.addresses[0], balanceWei: 0n, nonce: 0n },
  { address: record.addresses[1], balanceWei: 5_000_000_000_000_000n, nonce: 0n },
  { address: record.addresses[2], balanceWei: 9_000_000_000_000_000n, nonce: 0n },
  { address: record.addresses[3], balanceWei: 10_000_000_000_000_000n, nonce: 0n },
];
```

Expected plans:

```js
[
  { address: record.addresses[0], fundingNonce: 7n, valueWei: 10_000_000_000_000_000n },
  // Addresses already at or above the 0.005 admission floor are adopted without a send.
]
```

Reject any participant with nonzero nonce, balance above `0.02 ETH`, reordered facts, unsafe integer/string coercion, negative values, funding-wallet nonce ambiguity, or a funding balance below total values plus the exact bounded fee envelope.

- [ ] **Step 5: Run the new planning tests and observe RED**

Run:

```sh
node --test test/bilateral-funding-record.test.mjs
```

Expected: FAIL because `planFundingTransfers` is not implemented.

- [ ] **Step 6: Implement the minimal deterministic planner**

Export:

```js
export function planFundingTransfers({
  feePerTransferWei,
  fundingBalanceWei,
  fundingNonce,
  participantFacts,
  record,
}) {
  // Validate every bigint without coercion.
  // Preserve coordinator order.
  // Adopt 0.005–0.02 balances without sending.
  // Top up only balances below 0.005 to exactly 0.01.
  // Allocate explicit sequential funding-wallet nonces.
  // Require total value + feePerTransferWei * plannedCount <= fundingBalanceWei.
  // Return { adopted, paymentMoved:false, transfers, totalFeeWei, totalValueWei }.
}
```

- [ ] **Step 7: Run the focused test and observe GREEN**

Run:

```sh
node --test test/bilateral-funding-record.test.mjs
```

Expected: PASS with zero warnings.

- [ ] **Step 8: Commit Task 1 with a Lore message**

Stage only the two owned files and commit with fresh focused-test evidence.

### Task 2: Open the existing encrypted treasury without exposing secrets

**Files:**
- Create: `src/bilateral/funding/keystore.mjs`
- Test: `test/bilateral-funding-keystore.test.mjs`

- [ ] **Step 1: Write failing strict-file and keystore tests**

Test an injected filesystem and Keychain reader. Require:

```js
const PUBLIC_METADATA_KEYS = [
  "schemaVersion",
  "chainId",
  "fundingAddress",
  "keystoreSha256",
  "createdAt",
];
```

The loader must reject symlinks, FIFOs, multiple hard links, non-`0600` files, oversized files, changing metadata between open/read/close, malformed JSON, additional keys, wrong chain ID, mixed-case address, digest mismatch, non-v3 Web3 keystore, unsupported cipher/KDF parameters, empty Keychain password, bad MAC, and decrypted-address mismatch.

- [ ] **Step 2: Run the focused keystore test and observe RED**

Run:

```sh
node --test test/bilateral-funding-keystore.test.mjs
```

Expected: FAIL because the keystore module does not exist.

- [ ] **Step 3: Implement bounded secure loading**

Export:

```js
export const FUNDING_KEYCHAIN_SERVICE =
  "com.clockchain.handshake.sepolia-funding";
export const FUNDING_KEYCHAIN_ACCOUNT = "riyadh-v3";

export async function openFundingWallet({
  keystorePath,
  metadataPath = `${keystorePath.slice(0, -5)}.public.json`,
  dependencies = {},
}) {
  // Open both files with O_RDONLY | O_NOFOLLOW | O_NONBLOCK.
  // Require regular, single-link, mode-0600 files and bounded byte lengths.
  // Hash the exact keystore bytes and validate exact public metadata.
  // Retrieve the password through dependencies.readKeychainPassword.
  // Production reader executes:
  //   /usr/bin/security find-generic-password
  //     -s FUNDING_KEYCHAIN_SERVICE
  //     -a FUNDING_KEYCHAIN_ACCOUNT
  //     -w
  // Capture stdout in memory and never include it in an error.
  // Derive scrypt, verify the Web3 MAC, decrypt AES-128-CTR, and derive the address.
  // Return a viem account plus public metadata; never return the password/private-key bytes.
}
```

The production reader may emit only fixed public failure codes. It must never place a password, private key, decrypted keystore, invitation, token, or RPC URL in stdout, stderr, thrown messages, or serialized results.

- [ ] **Step 4: Add secret-canary tests**

Inject distinctive password/private-key/RPC canaries and assert none occurs in:

```js
JSON.stringify(result)
error.message
capturedStdout
capturedStderr
```

- [ ] **Step 5: Run the focused keystore test and observe GREEN**

Run:

```sh
node --test test/bilateral-funding-keystore.test.mjs
```

Expected: PASS with zero secret-canary matches.

- [ ] **Step 6: Commit Task 2 with a Lore message**

Stage only the keystore module and its test.

### Task 3: Persist a discovery-first private funding journal

**Files:**
- Create: `src/bilateral/funding/journal.mjs`
- Test: `test/bilateral-funding-journal.test.mjs`

- [ ] **Step 1: Write failing state-machine tests**

Use exactly:

```js
export const FUNDING_JOURNAL_SCHEMA =
  "clockchain.bilateral-funding-journal/v1";
export const FUNDING_STATES = Object.freeze([
  "PLANNED",
  "BROADCAST_INTENT",
  "TRANSACTION_OBSERVED",
  "FUNDED",
]);
```

Bind the journal to:

```js
{
  batchId,
  chainId: 11155111,
  fundingAddress,
  paymentMoved: false,
  recipients,
  repositorySha,
  rpcEndpointSha256,
  targetBalanceWei: "10000000000000000",
}
```

Require immutable per-transfer facts before broadcast:

```js
{
  address,
  feeWei,
  fundingNonce,
  state: "BROADCAST_INTENT",
  transactionDigest,
  transactionHash: null,
  valueWei,
}
```

- [ ] **Step 2: Run the focused journal test and observe RED**

Run:

```sh
node --test test/bilateral-funding-journal.test.mjs
```

Expected: FAIL because the journal module does not exist.

- [ ] **Step 3: Implement exclusive private journal writes**

Export:

```js
export function deriveFundingBatchId(binding) {
  // SHA-256 of canonical public binding facts only.
}

export async function openFundingJournal({
  binding,
  journalDirectory,
  dependencies = {},
}) {
  // Require owner-controlled mode-0700 directory.
  // Create one mode-0600 canonical journal with O_EXCL or validate the exact existing file.
  // Reject symlink, hard-link, replacement, truncation, extra keys, stale temp files,
  // noncanonical bytes, regressed states, or any changed binding fact.
}
```

Every update writes a mode-`0600` temporary in the same directory, fsyncs the file, renames atomically, fsyncs the directory, then verifies the new file identity and canonical bytes.

- [ ] **Step 4: Write recovery-classification tests**

Cover:

- crash before durable intent: no transaction may have been broadcast;
- crash after intent and before returned hash: query the exact funding nonce and recipient;
- hash observed but receipt absent: wait/query only, never resend;
- successful receipt with exact sender, recipient, nonce, value, and chain: advance;
- reverted, replaced, dropped, mismatched, or ambiguous nonce: terminal failure;
- funded balance with recipient nonce still zero: `FUNDED`;
- funded balance with recipient nonce nonzero: terminal failure.

- [ ] **Step 5: Implement recovery decisions**

Export a pure function:

```js
export function classifyFundingRecovery({
  journalTransfer,
  nonceTransaction,
  receipt,
  recipientFact,
}) {
  // Return one of WAIT, OBSERVED, FUNDED.
  // Throw BilateralFundingError for every ambiguous or mismatched case.
  // Never return a resend decision after BROADCAST_INTENT.
}
```

- [ ] **Step 6: Run the focused journal test and observe GREEN**

Run:

```sh
node --test test/bilateral-funding-journal.test.mjs
```

Expected: PASS.

- [ ] **Step 7: Commit Task 3 with a Lore message**

Stage only the journal module and its test.

### Task 4: Compose the funding CLI and sequential Sepolia broadcaster

**Files:**
- Create: `scripts/fund-bilateral-addresses.mjs`
- Create: `test/bilateral-funding-cli.test.mjs`
- Modify: `package.json`

- [ ] **Step 1: Write failing argument and dependency-injection tests**

Accept exactly these path arguments:

```text
--funding-record <path>
--journal-directory <path>
--keystore <path>
--rpc-url-file <path>
```

Reject missing, duplicate, reordered, additional, empty, option-like, relative-to-secret-value, raw address, raw private-key, raw password, and raw RPC URL arguments. Derive the metadata path adjacent to `--keystore`; derive the repository SHA from a clean Git checkout.

- [ ] **Step 2: Run the focused CLI test and observe RED**

Run:

```sh
node --test test/bilateral-funding-cli.test.mjs
```

Expected: FAIL because the CLI does not exist.

- [ ] **Step 3: Implement strict startup and public dependencies**

Export:

```js
export const FUNDING_CLI_FLAGS = Object.freeze([
  "--funding-record",
  "--journal-directory",
  "--keystore",
  "--rpc-url-file",
]);

export async function main(arguments_ = process.argv.slice(2), dependencies = {}) {
  // Parse exact paths.
  // Require clean exact 40-character Git HEAD.
  // Read the RPC endpoint from a single-link mode-0600 file.
  // Require HTTPS, no credentials/query/fragment, and Sepolia chain ID 11155111.
  // Load record, wallet, participant facts, funding balance/nonce, fee envelope.
  // Open or resume the exact journal.
  // Execute sequentially and verify every successful receipt before advancing.
  // Re-query all four balances and latest nonces.
  // Print one secret-free canonical completion line and return it.
}
```

- [ ] **Step 4: Write failing sequential-send and recovery tests**

Inject a fake viem client. Assert:

- no transaction is sent if all four addresses are already inside the admission band;
- only below-floor recipients are topped up to exactly `0.01 ETH`;
- intent is durable before `sendTransaction`;
- explicit funding nonces are sequential;
- the next recipient is not broadcast until the prior receipt succeeds;
- rerunning after every crash point discovers state before deciding;
- no recovery path broadcasts twice for one durable intent;
- wrong chain, changed RPC digest, insufficient balance, unbounded fees, recipient mutation, funding nonce conflict, and failed receipt abort.

- [ ] **Step 5: Implement the production viem adapter**

Use only the existing pinned dependency:

```js
const publicClient = createPublicClient({
  chain: sepolia,
  transport: http(rpcUrl, { retryCount: 0, timeout: 15_000 }),
});
const walletClient = createWalletClient({
  account,
  chain: sepolia,
  transport: http(rpcUrl, { retryCount: 0, timeout: 15_000 }),
});
```

Estimate one bounded EIP-1559 fee envelope before journaling. Persist explicit `gas`, `maxFeePerGas`, `maxPriorityFeePerGas`, `nonce`, `to`, and `value` facts. Never use advisory RPC fields as protocol authority; the funding command is provisioning only.

- [ ] **Step 6: Add the package command**

Add:

```json
"bilateral:fund": "node scripts/fund-bilateral-addresses.mjs"
```

Do not add dependencies or lifecycle hooks.

- [ ] **Step 7: Run all focused funding tests and observe GREEN**

Run:

```sh
node --test \
  test/bilateral-funding-record.test.mjs \
  test/bilateral-funding-keystore.test.mjs \
  test/bilateral-funding-journal.test.mjs \
  test/bilateral-funding-cli.test.mjs
```

Expected: PASS with no skipped tests and no secret canaries.

- [ ] **Step 8: Commit Task 4 with a Lore message**

Stage only the CLI, CLI test, and `package.json`.

### Task 5: Make the two-computer role-play instructions operationally exact

**Files:**
- Modify: `README.md`
- Modify: `docs/runbooks/bilateral-demo-day.md`
- Modify: `prompts/run-billy-bilateral-demo.md`
- Modify: `prompts/run-iris-bilateral-demo.md`
- Modify: `scripts/check-docs.mjs`
- Modify: `test/docs.test.mjs`

- [ ] **Step 1: Write failing documentation gates**

Require the runbook to name:

```text
Stakeholder 1 — Iris — payee
Stakeholder 2 — Billy — payer
Operator — relay, coordinator, watcher, funding wallet, fresh aggregate verifier
```

Require an advertised numeric relay IP reachable by both role computers, a TLS certificate whose subject alternative name contains that exact IP, private delivery of only `payee.launch.json` to Iris and only `payer.launch.json` to Billy, and the rule that both role machines use a clean detached checkout of one reviewed 40-character SHA.

Require the runbook to reject `127.0.0.1` as the advertised relay address for a two-machine run, while permitting the relay process to bind either the advertised interface or an explicitly documented all-interface bind.

- [ ] **Step 2: Run the docs checks and observe RED**

Run:

```sh
node --test test/docs.test.mjs
node scripts/check-docs.mjs
```

Expected: FAIL on the new readiness gates.

- [ ] **Step 3: Document the exact operator preparation**

Add commands that:

1. record the reviewed release SHA;
2. create owner-controlled operator and release directories;
3. create the Ed25519 operator key through `scripts/create-session.mjs keygen`;
4. create a self-signed TLS certificate with `subjectAltName=IP:$RELAY_ADVERTISED_IP`;
5. write the Sepolia RPC URL to a mode-`0600` file;
6. mint the operator Clockchain token once;
7. start the relay on a reachable numeric IP;
8. start the coordinator with the matching `https://IP:port` URL and certificate fingerprint;
9. privately transfer `payee.launch.json` to Iris and `payer.launch.json` to Billy;
10. have each stakeholder start exactly one long-lived supervisor;
11. save the coordinator's single funding-address JSON line to a mode-`0600` record file;
12. run `npm run bilateral:fund` against that record and the reusable treasury;
13. let the coordinator complete rehearsal before it starts the stakeholder run;
14. accept `AUTHORIZED` only from each fresh aggregate verifier.

- [ ] **Step 4: Add role cards to the prompts**

Iris's prompt must say:

```text
You are Stakeholder 1, Iris, the payee. Start only the payee supervisor.
```

Billy's prompt must say:

```text
You are Stakeholder 2, Billy, the payer. Start only the payer supervisor.
```

Both continue to forbid inspecting secret bytes, switching roles, creating extra sessions, funding addresses, running the watcher/verifier, or declaring authorization.

- [ ] **Step 5: Document budget and recovery truthfully**

State:

- `0.05 Sepolia ETH` covers four `0.01 ETH` allocations plus ordinary treasury transfer gas for one clean rehearsal-plus-stakeholder release;
- the demo transactions spend gas from participant balances but never move the represented USD payment;
- a second `0.05` drip is a recovery reserve because an ambiguous/consumed invitation cannot be reused;
- fresh invitations and a newly reviewed release are required after an unrecoverable write.

- [ ] **Step 6: Run documentation checks and observe GREEN**

Run:

```sh
node --test test/docs.test.mjs
node scripts/check-docs.mjs
```

Expected: PASS.

- [ ] **Step 7: Commit Task 5 with a Lore message**

Stage only the documentation, prompt, and documentation-gate files.

### Task 6: Review the integrated funding boundary before live use

**Files:**
- Review all files changed by Tasks 1–5.

- [ ] **Step 1: Run the complete focused funding set**

Run:

```sh
node --test \
  test/bilateral-funding-record.test.mjs \
  test/bilateral-funding-keystore.test.mjs \
  test/bilateral-funding-journal.test.mjs \
  test/bilateral-funding-cli.test.mjs \
  test/docs.test.mjs
```

Expected: PASS.

- [ ] **Step 2: Run an independent specification-compliance review**

Compare every implementation branch against:

```text
docs/superpowers/specs/2026-07-27-sepolia-funding-wallet-design.md
```

Reject any implementation that reuses participant addresses, accepts advisory relay authority, permits duplicate broadcast, prints secrets, weakens `paymentMoved:false`, adds a fourth anchor, or allows a non-verifier process to authorize.

- [ ] **Step 3: Run an independent security/code-quality review**

Review file races, symlinks, hard links, permissions, Keychain handling, canonical bytes, JSON coercion, transaction replacement, fee bounds, nonce recovery, secret canaries, output redaction, and wrong-chain behavior. Fix every finding through a new failing test before implementation.

- [ ] **Step 4: Run the complete suite exactly once as the final code gate**

Run:

```sh
npm run verify
```

Expected: all Node tests and every documentation gate pass with exit code zero.

- [ ] **Step 5: Commit the integrated reviewed release**

Commit any review fixes with a Lore message containing the exact focused and full verification evidence. Record the resulting full 40-character SHA. Do not use the earlier `03ead2f` design-only commit as a live release.

### Task 7: Validate the existing treasury and produce the private live handoff

**Files:**
- Read only: `.context/sepolia-funding/funding-wallet.json`
- Read only: `.context/sepolia-funding/funding-wallet.public.json`
- Create privately when the live coordinator is running: `.context/sepolia-funding/journals/<batch-id>/...`
- Create privately when the live coordinator is running: operator release root and role launch manifests.

- [ ] **Step 1: Verify the treasury without printing secrets**

Run the funding command only after a fresh full-suite release SHA exists. Require:

```text
chainId = 11155111
fundingAddress = 0x157a377e4181f3f87c7f6efed5ddc340ccc00dce
balance >= 0.05 ETH
keystore and metadata = mode 0600, single link
Keychain round trip = valid
```

- [ ] **Step 2: Verify the scheduled reserve drip separately**

At the next eligible Google faucet window, request one `0.05 Sepolia ETH` drip only to the reusable treasury. Stop on login, MFA, account ambiguity, CAPTCHA, rate limit, or any changed faucet rule. Record only the public transaction hash and verified resulting balance.

- [ ] **Step 3: Prepare the exact stakeholder handoff**

Provide:

- Operator: reviewed SHA, relay bind/advertised IP, certificate fingerprint, release-root paths, funding command, and verifier-only authorization rule.
- Stakeholder 1 / Iris: exact SHA, `payee.launch.json`, private state-directory path, and one supervisor command.
- Stakeholder 2 / Billy: exact SHA, `payer.launch.json`, private state-directory path, and one supervisor command.

Do not transfer the treasury keystore, Keychain password, operator private key, Clockchain tokens, invitations, participant keys, journals, or live evidence through Git or an agent chat.

- [ ] **Step 4: Stop at the physical-session boundary**

The only remaining human actions are:

1. start the Iris agent session on Stakeholder 1's computer;
2. start the Billy agent session on Stakeholder 2's computer;
3. personally attest that the credentials and physical machines are separate.

The coordinator, supervisors, funding command, watcher, and verifier perform the remaining normal flow. Any live failure remains non-authorization evidence.
