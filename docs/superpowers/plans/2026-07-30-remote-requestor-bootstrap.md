# Remote Requestor Bootstrap Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let a remote stakeholder paste one public Requestor prompt and complete the Handshake without receiving, attaching, or locating private files.

**Architecture:** The Payer TLS service exposes a separately armed public bootstrap claim before its unchanged authenticated MCP lifecycle. An operator-owned loopback broker approves the Requestor-key fingerprint and seals the fresh payee launch manifest to that key; a separate operator-signed discovery document supplies public MCP/TLS data. The Requestor wrapper discovers, claims, decrypts, calls the existing authenticated `request_payment`, validates exact `HANDSHAKE_REQUIRED`, and starts the existing supervisor without printing secrets.

**Tech Stack:** Node.js 22 ES modules, `node:crypto` X25519/HKDF/AES-256-GCM, `node:https`, existing canonical validators and private-file helpers, `node:test`, AWS S3 public monitor.

---

## File Structure

- Create `src/bilateral/local-mcp/bootstrap-envelope.mjs`: exact sealed-envelope schema, X25519/HKDF/AES-GCM sealing and opening, AAD construction, and zeroization.
- Create `src/bilateral/local-mcp/bootstrap-broker.mjs`: private loopback broker, exactly-once journal, manifest validation, and ciphertext-only response.
- Create `bin/handshake-bootstrap-broker.mjs`: strict broker CLI.
- Modify `src/bilateral/local-mcp/server.mjs`: add a separately armed public `/bootstrap` claim while leaving MCP bearer authentication unchanged.
- Modify `src/bilateral/local-mcp/client.mjs`: public discovery, ephemeral key persistence, TLS download/pinning, and local envelope opening.
- Modify `bin/handshake-request-payment.mjs`: replace manifest/certificate inputs with discovery URL and private state root.
- Modify `src/bilateral/coordination/supervisor-runtime.mjs` and `bin/handshake-supervisor.mjs`: pass the broker client to the Payer MCP without exposing the payee manifest.
- Create `scripts/publish-requestor-discovery.mjs`: publish the operator-signed MCP/TLS discovery and public certificate without changing advisory monitor authority.
- Modify `package.json`: add `bilateral:bootstrap-broker`.
- Modify focused local-MCP, CLI, supervisor-runtime, discovery, and process-E2E tests.
- Modify role prompts and runbooks so Requestor receives one public command path and no private file handoff.

### Task 1: Sealed bootstrap envelope

**Files:**
- Create: `src/bilateral/local-mcp/bootstrap-envelope.mjs`
- Create: `test/bilateral-requestor-bootstrap-envelope.test.mjs`

- [ ] **Step 1: Write failing round-trip and hostile-input tests**

Define the wished-for API:

```js
import {
  createRequestorBootstrapKey,
  openRequestorBootstrapEnvelope,
  sealRequestorBootstrapManifest,
} from "../src/bilateral/local-mcp/bootstrap-envelope.mjs";

const requestor = createRequestorBootstrapKey();
const context = {
  claimNonce: "11111111-1111-4111-8111-111111111111",
  paymentMoved: false,
  releaseId: "release-0123456789abcdef",
  repositorySha: "a".repeat(40),
  sessionId: "11111111-1111-4111-8111-111111111111",
};
const envelope = sealRequestorBootstrapManifest({
  context,
  manifestBytes,
  requestorPublicKey: requestor.publicKey,
});
assert.deepEqual(
  openRequestorBootstrapEnvelope({
    context,
    envelope,
    requestorPrivateKey: requestor.privateKey,
  }),
  manifestBytes,
);
```

Add table tests for extra/missing fields, malformed base64url, wrong key,
wrong claim/release/session/SHA, `paymentMoved:true`, ciphertext/tag mutation,
oversized manifest, and noncanonical bytes. Assert the envelope and errors never
contain manifest or private-key canaries.

- [ ] **Step 2: Run the envelope test and observe the missing-module failure**

Run:

```sh
node --test test/bilateral-requestor-bootstrap-envelope.test.mjs
```

Expected: FAIL because `bootstrap-envelope.mjs` does not exist.

- [ ] **Step 3: Implement the exact envelope**

Use X25519 ephemeral Diffie-Hellman, HKDF-SHA256 with the canonical context as
salt/info, and AES-256-GCM with the same context as AAD. Return exact keys:

```js
{
  algorithm: "X25519-HKDF-SHA256-AES-256-GCM",
  ciphertextBase64url,
  ephemeralPublicKey,
  ivBase64url,
  paymentMoved: false,
  schema: "clockchain.requestor-bootstrap-envelope/v1",
  tagBase64url,
}
```

Validate dense/exact objects, bounded byte lengths, canonical encodings, and
zero temporary shared-secret/key buffers in `finally`.

- [ ] **Step 4: Run the focused test**

Run:

```sh
node --test test/bilateral-requestor-bootstrap-envelope.test.mjs
```

Expected: PASS.

- [ ] **Step 5: Commit**

Commit the two files with a Lore message recording the encryption and AAD
bindings.

### Task 2: Operator-owned exactly-once bootstrap broker

**Files:**
- Create: `src/bilateral/local-mcp/bootstrap-broker.mjs`
- Create: `bin/handshake-bootstrap-broker.mjs`
- Create: `test/bilateral-requestor-bootstrap-broker.test.mjs`
- Modify: `package.json`

- [ ] **Step 1: Write failing broker tests**

Exercise a loopback-only server configured with:

```js
{
  capabilityFile,
  host: "127.0.0.1",
  manifestPath,
  port: 9555,
  repositorySha,
  stateRoot,
}
```

Require `Authorization: Bearer <operator-created broker capability>`, an exact
canonical claim containing `claimNonce`, `requestorPublicKey`,
`repositorySha`, and `paymentMoved:false`, and an explicit pending state. Add an
operator approval operation bound to the exact claim/public-key fingerprint.
Assert identical retry returns byte-identical operator-signed ciphertext after
approval while a second key, nonce, SHA, expired manifest, unapproved claim,
symlink, wrong permissions, duplicate JSON key, or changed manifest fails
closed. Scan responses and journal bytes for plaintext manifest canaries and raw
capabilities.

- [ ] **Step 2: Run the broker test and observe the missing-module failure**

Run:

```sh
node --test test/bilateral-requestor-bootstrap-broker.test.mjs
```

Expected: FAIL because the broker is absent.

- [ ] **Step 3: Implement broker storage and HTTP boundary**

Use existing private-root and stable-file identity patterns. Journal the
canonical request digest and sealed response before replying. Pin the manifest
inode/metadata across read, validate it with `readLaunchManifest`, require role
`payee` and the reviewed SHA, and never include manifest bytes in logs or
errors. Bind only to loopback.

- [ ] **Step 4: Add strict CLI and package script**

Add:

```json
"bilateral:bootstrap-broker": "node bin/handshake-bootstrap-broker.mjs"
```

The CLI supports `serve` and `approve` modes. `serve` accepts exact flags:

```text
--capability-file
--host
--manifest
--port
--repository-sha
--state
```

`approve` accepts exact `--state` and `--claim-fingerprint` flags and records
approval only for one already-pending exact claim.

- [ ] **Step 5: Run focused broker tests**

Run:

```sh
node --test test/bilateral-requestor-bootstrap-broker.test.mjs
```

Expected: PASS.

- [ ] **Step 6: Commit**

Commit broker, CLI, script, and tests.

### Task 3: Public bootstrap route with unchanged authenticated Payer MCP

**Files:**
- Modify: `src/bilateral/local-mcp/server.mjs`
- Modify: `src/bilateral/local-mcp/client.mjs`
- Modify: `src/bilateral/coordination/supervisor-runtime.mjs`
- Modify: `bin/handshake-supervisor.mjs`
- Modify: `test/bilateral-local-mcp-server.test.mjs`
- Modify: `test/bilateral-local-mcp-client.test.mjs`
- Modify: `test/bilateral-coordination-supervisor-runtime.test.mjs`

- [ ] **Step 1: Write failing intake/server tests**

Add an armed `/bootstrap` claim before MCP routing. Require a broker callback:

```js
const result = await claimRequestorBootstrap({
  claimNonce,
  paymentMoved: false,
  repositorySha,
  requestorPublicKey,
});
```

Prove only `/bootstrap` accepts no bearer header when explicitly armed, returns
only a pending state or operator-signed sealed envelope, and fails on broker
error, duplicate claim, extra fields, mismatched context, or replay. Prove every
`/mcp` lifecycle request still requires the recovered manifest's original
bearer and the payment intake/result schema is byte-for-byte unchanged.

- [ ] **Step 2: Run focused tests and observe schema/auth failures**

Run:

```sh
node --test \
  test/bilateral-local-mcp-server.test.mjs \
  test/bilateral-local-mcp-client.test.mjs \
  test/bilateral-coordination-supervisor-runtime.test.mjs
```

Expected: FAIL because `/bootstrap` does not exist.

- [ ] **Step 3: Implement the exact MCP and supervisor wiring**

The server routes the exact armed `/bootstrap` request before its existing MCP
bearer path. All MCP protocol/session/body limits remain. The Payer supervisor
receives only broker URL plus broker capability file and creates the broker
client; it never reads the payee manifest.

- [ ] **Step 4: Run focused tests**

Run the Step 2 command.

Expected: PASS.

- [ ] **Step 5: Commit**

Commit MCP schema, server/client, supervisor wiring, and tests.

### Task 4: Self-bootstrapping Requestor CLI and public discovery

**Files:**
- Modify: `bin/handshake-request-payment.mjs`
- Modify: `src/bilateral/local-mcp/client.mjs`
- Create: `scripts/publish-requestor-discovery.mjs`
- Modify: `test/bilateral-request-payment-cli.test.mjs`
- Create: `test/bilateral-requestor-discovery.test.mjs`

- [ ] **Step 1: Write failing CLI and monitor tests**

Replace the Requestor CLI flags with:

```text
--discovery-url
--intake-request-id
--state
```

The operator-signed discovery record must contain exact public fields:

```js
{
  certificateFingerprint,
  certificateUrl,
  expiresAtMs,
  operatorKeyId,
  publicUrl,
  releaseId,
  repositorySha,
  sessionId,
  signature,
}
```

Tests must prove the CLI generates a private key, downloads and fingerprints
the public certificate, claims bootstrap without a bearer, decrypts to a
mode-`0600` manifest in a sibling bootstrap root, performs the existing MCP
call with the recovered bearer, validates it, emits only the fixed
`HANDSHAKE_REQUIRED` line, and starts the supervisor once. Reject HTTP
discovery/certificate URLs, cross-origin redirects, stale monitor data, wrong
SHA, wrong certificate, existing destination, and stdout secret canaries.

- [ ] **Step 2: Run focused tests and observe legacy-flag failures**

Run:

```sh
node --test \
  test/bilateral-request-payment-cli.test.mjs \
  test/bilateral-requestor-discovery.test.mjs
```

Expected: FAIL because the legacy manifest/certificate flags are still
required.

- [ ] **Step 3: Implement discovery, private key state, decryption, and monitor publication**

The discovery publisher uploads the public certificate to the configured S3
bucket, validates its fingerprint locally, signs the exact discovery with the
reviewed operator key, and publishes it separately from advisory `latest.json`.
It never opens the TLS private key. The Requestor verifies the signature from
the reviewed checkout, writes the decrypted manifest under a sibling private
bootstrap root, and passes that internal path to the unchanged supervisor API.

- [ ] **Step 4: Run focused tests**

Run the Step 2 command.

Expected: PASS.

- [ ] **Step 5: Commit**

Commit CLI, discovery, monitor, and tests.

### Task 5: Protocol integration, prompts, and runbooks

**Files:**
- Modify: `test/bilateral-coordination-process-e2e.test.mjs`
- Modify: `prompts/run-requestor-bilateral-demo.md`
- Modify: `prompts/run-payer-bilateral-demo.md`
- Modify: `docs/runbooks/bilateral-demo-quick-start.md`
- Modify: `docs/runbooks/bilateral-demo-day.md`
- Modify: `docs/runbooks/bilateral-demo-live-handoff.md`
- Modify: `docs/runbooks/payer-mcp-external-relay.md`
- Modify: `scripts/check-docs.mjs`

- [ ] **Step 1: Write the failing process acceptance**

Change the Requestor process fixture to receive only the public discovery URL
and a blank private state directory. Assert:

```js
assert.deepEqual(statuses, [
  "PAYER_MCP_READY",
  "HANDSHAKE_REQUIRED",
  "PROPOSED",
  "ACCEPTED",
  "ACKNOWLEDGED",
  "AUTHORIZED",
]);
assert.equal(attachments, 0);
assert.equal(result.paymentMoved, false);
```

Also assert exactly three independently verified anchors and no
`AUTHORIZED` literal from Payer, Requestor, console, watcher, MCP, or broker.

- [ ] **Step 2: Run the process test and observe the legacy handoff failure**

Run:

```sh
node --test test/bilateral-coordination-process-e2e.test.mjs
```

Expected: FAIL because the fixture still copies `payee.launch.json`.

- [ ] **Step 3: Update docs and prompts**

The public Requestor flow contains one prompt, one discovery URL, and no
instruction to attach, receive, locate, inspect, or paste a manifest,
certificate, fingerprint, token, capability, invitation, or private path.
Operator docs add broker startup before Payer MCP readiness.

- [ ] **Step 4: Run focused integration and documentation checks**

Run:

```sh
node --test \
  test/bilateral-requestor-bootstrap-envelope.test.mjs \
  test/bilateral-requestor-bootstrap-broker.test.mjs \
  test/bilateral-local-mcp-server.test.mjs \
  test/bilateral-local-mcp-client.test.mjs \
  test/bilateral-request-payment-cli.test.mjs \
  test/bilateral-requestor-discovery.test.mjs \
  test/bilateral-coordination-supervisor-runtime.test.mjs \
  test/bilateral-coordination-process-e2e.test.mjs
npm run docs:check
```

Expected: PASS.

- [ ] **Step 5: Commit**

Commit integration, prompts, runbooks, and docs gates.

### Task 6: Release, public page, and dry run

**Files:**
- Modify in `clockchain-research`: Requestor run-page component, evidence data,
  and focused runbook tests.

- [ ] **Step 1: Produce a reviewed immutable release SHA**

Run focused verification, inspect the integrated diff, and push the Handshake
branch. Do not call it reviewed until independent review approves and the
required release checks pass.

- [ ] **Step 2: Write the failing public-page test**

Require exactly one Requestor prompt and reject these strings:

```text
payee.launch.json
payer-mcp.crt
PAYER_MCP_TLS_FINGERPRINT
attach
private file-transfer
second prompt
```

Require the public discovery URL, exact `HANDSHAKE_REQUIRED`, reviewed release
SHA, `PROPOSED -> ACCEPTED -> ACKNOWLEDGED`, and `paymentMoved:false`.

- [ ] **Step 3: Update and deploy the public run page**

The prompt tells the stakeholder's agent to clone the reviewed release, create
a blank private state root, and run:

```sh
npm run bilateral:request-payment -- \
  --discovery-url "https://clockchain-handshake-monitor-570035913370-us-west-2.s3.us-west-2.amazonaws.com/latest.json" \
  --intake-request-id "$(node -e 'console.log(require("node:crypto").randomUUID())')" \
  --state "$REQUESTOR_SUPERVISOR_STATE"
```

- [ ] **Step 4: Run focused site tests, typecheck, build, and public smoke**

Do not run the complete site suite during iteration. Require the deployed page
to contain the new command and none of the rejected handoff strings.

- [ ] **Step 5: Run a fresh physical dry run**

Start a fresh operator root, broker, relay, coordinator, console, monitor, Payer
tunnel, and Payer supervisor. Use a fresh remote-style Requestor workspace with
only the public prompt. Fund exactly once from a new preserved journal after
the funding record is ready. Require exact role completions, exactly three
anchors, fresh verifier `AUTHORIZED`, and `paymentMoved:false`.

- [ ] **Step 6: Final release gate**

Only after the physical dry run passes, run one fresh:

```sh
npm run verify
```

Publish the precise live handoff and remove any expired dry-run private
artifacts outside preserved journals/evidence.
