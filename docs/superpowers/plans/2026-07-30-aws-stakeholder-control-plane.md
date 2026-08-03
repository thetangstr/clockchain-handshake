# AWS Stakeholder Control Plane Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Execution contract:** Sol owns orchestration, file assignment, integration,
verification, and the completion verdict. Sol invokes the required execution
skill and assigns one bounded task with exclusive writable files to a Terra
executor; Luna remains read-only unless Sol explicitly assigns a bounded,
low-risk edit. Executors do not coordinate peers or change this plan.

**Goal:** Deliver a fully AWS-hosted Clockchain Handshake demo in which a Payer stakeholder and a Requestor stakeholder each paste one public prompt into a fresh supported local agent, complete their independently controlled role, and observe a public, independently verified three-anchor result without any demo-time dependency on Kailor's Mac.

**Architecture:** Keep stakeholder keys, state, and the Payer MCP TLS endpoint on stakeholder-owned machines. Run the shared relay, bootstrap approvals, reverse-tunnel gateway, coordinator, funding, watcher, fresh verifier, operator controls, and sanitized publisher on ECS Fargate with EFS persistence, task-specific Secrets Manager access, NLB raw-TCP pass-through, and Cognito-authenticated controls. MCP remains the Payer-owned intake surface; exact signed relay artifacts and Clockchain anchors remain authoritative. A fresh verifier task is the only production process allowed to emit `AUTHORIZED`; every other public or operator surface renders `VERIFIED`.

**Tech Stack:** Node.js 22 ES modules, `node:test`, OpenSSH, OpenSSL, AWS CDK v2 with TypeScript, ECS Fargate, ECR, EFS, NLB, API Gateway, Cognito, Lambda, SQS, DynamoDB, Secrets Manager/KMS, S3, CloudFront, CloudWatch, Sepolia, and the existing Clockchain SDK/relay/verifier modules.

---

## Non-negotiable delivery rules

- Use test-driven development for every behavior change: add the focused failing
  test, observe the expected failure, implement the smallest passing change, and
  rerun only the focused test.
- Preserve `PROPOSED -> ACCEPTED -> ACKNOWLEDGED -> operator verification ->
  AUTHORIZED`.
- Require exactly three independently re-verifiable Clockchain anchors.
- Preserve `paymentMoved:false` in every artifact, status, error, and projection.
- Never treat relay fields, console state, watcher output, SQS messages, health
  checks, or public-monitor fields as authority.
- Fail closed on missing, duplicate, reordered, expired, malformed, replayed, or
  mismatched material.
- Keep Payer and Requestor private keys and private state on their respective
  stakeholder machines.
- Never put capabilities, invitations, tokens, private keys, launch manifests,
  private paths, treasury material, or live evidence in Git, public S3,
  CloudWatch, browser storage, console output, or the public site.
- Use focused tests while implementing. Run the complete Handshake and research
  site suites only in Task 22.
- Do not delete the existing EC2 relay or Mac LaunchAgents in this plan. Prove
  the AWS path first, then stop or disable the legacy path reversibly for live
  acceptance. Permanent deletion is a separately reviewed cleanup.

Unless an existing reviewed schema is intentionally preserved byte-for-byte,
new wire objects are dense exact-key objects; UUIDs are lowercase UUIDv4;
repository SHAs are 40 lowercase hex characters; SHA-256 digests are 64
lowercase hex characters or the prefix `sha256:` followed by 64 lowercase hex
characters where an image digest is required; absolute timestamps ending in
`AtMs` are canonical base-10
millisecond strings; durations ending in `AfterMs` are bounded safe integers;
and duplicate JSON keys are rejected before normal parsing.

## Repository boundaries

### Clockchain Handshake repository

All paths in Tasks 1-18 and 20-22 are relative to the
`clockchain-handshake` repository root.

### Clockchain Research repository

All paths in Task 19 are relative to the `clockchain-research` repository root.
The current implementation checkout is
`/Users/Kailor/.config/superpowers/worktrees/clockchain-research/handshake-run-sequence`.

## Planned file structure

### Participant and shared protocol modules

- Create `src/bilateral/platform-tools.mjs` for cross-platform executable
  discovery and version checks.
- Create `src/bilateral/private-path.mjs` for POSIX-mode and Windows-ACL private
  path enforcement.
- Create `src/bilateral/network-endpoint.mjs` for strict public DNS/IP endpoint
  validation.
- Refactor `src/bilateral/local-mcp/bootstrap-envelope.mjs` around a
  role-neutral sealed-envelope core without changing the Requestor v1 wire
  format.
- Create `src/bilateral/local-mcp/payer-bootstrap-envelope.mjs` for the distinct
  Payer claim/package wire format.
- Create `src/bilateral/local-mcp/payer-bootstrap.mjs` for Payer discovery,
  local key creation, claim polling, sealed-package opening, tunnel lifecycle,
  and supervisor launch.
- Create `bin/handshake-payer-bootstrap.mjs` as the single Payer CLI.

### AWS runtime modules

- Create `src/bilateral/aws/bootstrap-state.mjs` for exact Payer/Requestor claim
  transitions and durable approval state.
- Create `src/bilateral/aws/tunnel-grant.mjs` for grant creation, restricted
  `authorized_keys` rendering, reconnect, revocation, and tombstones.
- Create `src/bilateral/aws/efs-lease.mjs` for task-identity leases that do not
  rely on container PIDs.
- Create `src/bilateral/aws/task-provenance.mjs` for reviewed-SHA and pinned-image
  identity.
- Create `src/bilateral/aws/control-actions.mjs` for action schemas, ordering,
  revision checks, and idempotency.
- Create `src/bilateral/aws/public-history.mjs` for strict immutable public run
  summaries and bounded history indexes.
- Create `src/bilateral/aws/ecs-verifier-launcher.mjs` for one-shot verifier task
  launch and result collection.
- Create `scripts/run-aws-bootstrap-service.mjs`,
  `scripts/run-aws-relay.mjs`, `scripts/run-aws-coordinator.mjs`,
  `scripts/run-aws-tunnel-service.mjs`, `scripts/run-aws-funding-task.mjs`,
  `scripts/run-aws-operator-worker.mjs`, and
  `scripts/publish-aws-public-monitor.mjs` as thin adapters.

### AWS infrastructure package

- Create `infra/aws/package.json`, `infra/aws/package-lock.json`,
  `infra/aws/tsconfig.json`, and `infra/aws/cdk.json`.
- Create `infra/aws/bin/clockchain-handshake.ts`.
- Create `infra/aws/lib/clockchain-handshake-stack.ts`.
- Create `infra/aws/lambda/control-api.mjs`.
- Create `infra/aws/runtime/aws-clients.mjs` and task entrypoints so AWS SDK
  imports remain inside the infrastructure package while root protocol/runtime
  modules stay dependency-injected.
- Create `infra/aws/operator-console/index.html`,
  `infra/aws/operator-console/app.js`, and
  `infra/aws/operator-console/styles.css`.
- Create `infra/aws/docker/control-plane.Dockerfile` and
  `infra/aws/docker/tunnel.Dockerfile`.
- Create CDK, Lambda, console, IAM, and container-focused tests under
  `infra/aws/test/`.

### Public research site

- Modify `src/app/handshake/run/page.tsx`.
- Modify `src/components/BilateralHandshakeRunbook.tsx`.
- Modify `src/components/BilateralPublicMonitor.tsx`.
- Create `src/components/BilateralHandshakeHistory.tsx`.
- Modify `src/lib/bilateral-public-monitor.ts`.
- Create `src/lib/bilateral-public-history.ts`.
- Modify `src/data/bilateral-handshake-demo.ts`.
- Replace the obsolete local-operator content in
  `src/components/BilateralHandshakeOperatorRunbook.tsx` and
  `src/app/handshake/run/operator/page.tsx`.
- Update focused runbook, monitor, history, and operator-page tests.

## Task 1: Cross-platform prerequisites and private state

**Files:**
- Create: `src/bilateral/platform-tools.mjs`
- Create: `src/bilateral/private-path.mjs`
- Create: `test/bilateral-platform-tools.test.mjs`
- Create: `test/bilateral-private-path.test.mjs`
- Modify: `bin/handshake-request-payment.mjs`
- Modify: `test/bilateral-request-payment-cli.test.mjs`

- [ ] **Step 1: Write failing executable-discovery tests**

Define the wished-for API:

```js
const prerequisites = await inspectParticipantPrerequisites({
  execute,
  platform: "win32",
  role: "payer",
});

assert.deepEqual(prerequisites, {
  git: { command: "git.exe", version: "2.50.1" },
  node: { command: process.execPath, major: 22 },
  npm: { command: "npm.cmd", version: "10.9.2" },
  openssh: { command: "ssh.exe", version: "9.8" },
  sshKeygen: { command: "ssh-keygen.exe", version: "9.8" },
  openssl: { command: "openssl.exe", version: "3.4.1" },
});
```

Cover macOS, Linux, and Windows command names; Node major other than 22; a
missing Git/npm/OpenSSH/ssh-keygen/OpenSSL executable; nonzero version commands;
and version output containing control characters. Assert that prerequisite
failure occurs before a state root, key, certificate, or claim is created.
`role:"requestor"` requires only Git, Node.js 22, npm, filesystem, and outbound
HTTPS/TCP; it must not fail merely because OpenSSH or OpenSSL is absent.

- [ ] **Step 2: Write failing private-path tests**

Define:

```js
await preparePrivateDirectory({
  path: stateRoot,
  platform: "win32",
  runIcacls,
});
await writePrivateFile({
  bytes: secretBytes,
  path: capabilityPath,
  platform: "win32",
  runIcacls,
});
```

On POSIX require exact `0700` directories and `0600` files with existing
no-symlink/no-hard-link checks. On Windows require an injected `icacls` adapter
to disable inheritance and grant only the current user plus SYSTEM. Reject
world/group access, inherited access, reparse points, hard links, changed file
identity, and ACL-check failures.

- [ ] **Step 3: Run the focused tests and observe missing-module failures**

Run:

```sh
node --test test/bilateral-platform-tools.test.mjs test/bilateral-private-path.test.mjs
```

Expected: FAIL because both modules are absent.

- [ ] **Step 4: Implement the two modules and migrate the Requestor wrapper**

Resolve executables from the process environment rather than hard-coding
`/usr/bin/git`. Keep command execution injected in the pure functions. Make the
Requestor wrapper run all public prerequisite and detached-clean-checkout
checks before calling any private-path or key-generation dependency.

Change `REQUEST_PAYMENT_CLI_FLAGS` to exactly:

```js
Object.freeze(["--discovery-url", "--state"]);
```

After signed discovery and private-root checks, generate one UUIDv4
`intakeRequestId`, persist it in an exact private
`clockchain.requestor-intake-request/v1` record, and reuse that same value on a
safe restart from the same state root. A new state root creates a fresh value.
The human never supplies or copies an intake request ID.

Add failing Requestor CLI cases before implementation that prove two public
flags succeed, the retired `--intake-request-id` flag fails, restart reuses the
persisted ID, a changed/corrupt record fails closed, and no ID/state file exists
when a public prerequisite fails.

- [ ] **Step 5: Run focused participant tests**

Run:

```sh
node --test test/bilateral-platform-tools.test.mjs test/bilateral-private-path.test.mjs test/bilateral-request-payment-cli.test.mjs
```

Expected: PASS.

- [ ] **Step 6: Commit**

Commit only the files in this task with a Lore message whose intent is to make
the one-shot participant boundary truthful on macOS, Windows, and Linux.

## Task 2: Signed public DNS endpoints

**Files:**
- Create: `src/bilateral/network-endpoint.mjs`
- Create: `test/bilateral-network-endpoint.test.mjs`
- Modify: `src/bilateral/coordination/manifest.mjs`
- Modify: `src/bilateral/local-mcp/server.mjs`
- Modify: `src/bilateral/local-mcp/client.mjs`
- Modify: `bin/handshake-relay.mjs`
- Modify: `test/bilateral-coordination-client.test.mjs`
- Modify: `test/bilateral-coordination-relay.test.mjs`
- Modify: `test/bilateral-local-mcp-server.test.mjs`
- Modify: `test/bilateral-local-mcp-client.test.mjs`

- [ ] **Step 1: Write failing DNS and TLS-name tests**

Use exact canonical results:

```js
assert.deepEqual(
  validatePublicEndpoint("https://payer.example.net:9443/mcp", {
    allowedPaths: ["/mcp"],
    defaultPort: 9443,
    protocols: ["https:"],
  }),
  {
    hostname: "payer.example.net",
    path: "/mcp",
    port: 9443,
    protocol: "https:",
    url: "https://payer.example.net:9443/mcp",
  },
);
```

Accept canonical public DNS names, IPv4, and bracketed IPv6. Reject localhost,
`.local`, wildcard labels, trailing dots, userinfo, fragments, queries,
noncanonical ports, private/link-local/multicast IPs, DNS names resolving to
private addresses in the injected resolution check, and path confusion.
Require TLS verification against the signed hostname and the signed certificate
fingerprint. Permit loopback and IANA documentation addresses only when an
explicit `allowTestAddresses:true` dependency is injected by deterministic
tests; production adapters never set it.

- [ ] **Step 2: Run the focused test and observe failure**

Run:

```sh
node --test test/bilateral-network-endpoint.test.mjs
```

Expected: FAIL because the shared validator is absent.

- [ ] **Step 3: Implement and migrate existing validators**

Use the new validator in launch manifests, relay advertised endpoints, Payer MCP
server public URL validation, and the Requestor client. Keep bind-address
validation separate so `0.0.0.0` is permitted only as a local bind and is never
serialized as a public authority endpoint.

- [ ] **Step 4: Run focused endpoint tests**

Run:

```sh
node --test test/bilateral-network-endpoint.test.mjs test/bilateral-coordination-client.test.mjs test/bilateral-coordination-relay.test.mjs test/bilateral-local-mcp-server.test.mjs test/bilateral-local-mcp-client.test.mjs
```

Expected: PASS, including existing numeric-IP cases.

- [ ] **Step 5: Commit**

Commit the endpoint boundary and migrated tests with a Lore message recording
that signed DNS names are allowed but advisory bind addresses remain
non-authoritative.

## Task 3: Role-neutral sealed-envelope core with Requestor wire compatibility

**Files:**
- Modify: `src/bilateral/local-mcp/bootstrap-envelope.mjs`
- Modify: `test/bilateral-requestor-bootstrap-envelope.test.mjs`
- Create: `src/bilateral/local-mcp/sealed-envelope.mjs`
- Create: `test/bilateral-sealed-envelope.test.mjs`

- [ ] **Step 1: Lock the existing Requestor v1 wire bytes**

Add a deterministic fixture using injected ephemeral key bytes and IV. Assert
the complete canonical serialized Requestor envelope remains byte-identical
before and after the refactor.

- [ ] **Step 2: Add failing hostile-input tests for the generic core**

Define:

```js
const envelope = sealEnvelope({
  aadBytes,
  plaintextBytes,
  recipientPublicKey,
  schema: "clockchain.test-envelope/v1",
});
const opened = openEnvelope({
  aadBytes,
  envelope,
  expectedSchema: "clockchain.test-envelope/v1",
  recipientPrivateKey,
});
```

Cover wrong schema/AAD/key, noncanonical base64url, extra fields, oversized
plaintext, tag/ciphertext/IV mutation, and canary scans of errors. Verify shared
secrets and derived keys are zeroized in `finally`.

- [ ] **Step 3: Run and observe the missing-core failure**

Run:

```sh
node --test test/bilateral-sealed-envelope.test.mjs test/bilateral-requestor-bootstrap-envelope.test.mjs
```

Expected: FAIL because `sealed-envelope.mjs` does not exist.

- [ ] **Step 4: Extract the core and preserve the Requestor adapter**

Keep these existing Requestor exports and schema unchanged:

```js
createRequestorBootstrapKey
sealRequestorBootstrapManifest
openRequestorBootstrapEnvelope
```

The Requestor adapter continues to bind claim nonce, release ID, repository
SHA, session ID, and `paymentMoved:false` as AAD.

- [ ] **Step 5: Run focused envelope tests**

Run:

```sh
node --test test/bilateral-sealed-envelope.test.mjs test/bilateral-requestor-bootstrap-envelope.test.mjs
```

Expected: PASS with the locked wire fixture unchanged.

- [ ] **Step 6: Commit**

Commit the extraction separately so subsequent Payer work cannot accidentally
change the reviewed Requestor bootstrap protocol.

## Task 4: Exact Payer discovery, claim, and sealed package

**Files:**
- Create: `src/bilateral/local-mcp/payer-bootstrap-envelope.mjs`
- Create: `scripts/publish-payer-bootstrap-discovery.mjs`
- Create: `test/bilateral-payer-bootstrap-envelope.test.mjs`
- Create: `test/bilateral-payer-bootstrap-discovery.test.mjs`
- Modify: `package.json`

- [ ] **Step 1: Write failing Payer discovery tests**

Require an exact operator-signed discovery object:

```js
{
  expiresAtMs,
  imageDigest,
  operatorKeyId,
  paymentMoved: false,
  payerClaimUrl,
  publicMcpHostname,
  publicMcpPort: 9443,
  releaseId,
  repositorySha,
  schema: "clockchain.payer-bootstrap-discovery/v1",
  sessionId,
  signature,
  tunnelHost,
  tunnelHostPublicKey,
  tunnelHostKeyFingerprint,
  tunnelPort: 443,
}
```

Validate exact keys, canonical timestamps and URLs, repository SHA, immutable
ECR digest form, operator signature, expiry, public hostname binding, fixed
ports, a canonical Ed25519 tunnel host public key whose SHA-256 fingerprint
matches `tunnelHostKeyFingerprint`, and `paymentMoved:false`. Reject duplicate
JSON keys before parsing.

- [ ] **Step 2: Write failing Payer claim/package tests**

Require the public claim to bind:

```js
{
  claimNonce,
  mcpTlsCertificatePem,
  mcpTlsFingerprint,
  paymentMoved: false,
  releaseId,
  repositorySha,
  role: "payer",
  schema: "clockchain.payer-bootstrap-claim/v1",
  sessionId,
  sshPublicKey,
  sshPublicKeyFingerprint,
  x25519PublicKey,
}
```

The sealed plaintext uses exact schema
`clockchain.payer-bootstrap-package/v1` and contains canonical Payer launch
manifest bytes, the raw operator bootstrap-broker URL and capability, and the
run-scoped tunnel grant. The signed envelope exposes no plaintext manifest,
capability, private path, or key. Test wrong role/session/release/SHA, changed
certificate/key/fingerprint, expired package, replayed nonce, and
`paymentMoved:true`.

- [ ] **Step 3: Run focused tests and observe failures**

Run:

```sh
node --test test/bilateral-payer-bootstrap-envelope.test.mjs test/bilateral-payer-bootstrap-discovery.test.mjs
```

Expected: FAIL because the Payer modules are absent.

- [ ] **Step 4: Implement exact schemas and publisher**

Build the Payer envelope on the generic sealed-envelope core, with distinct
schema and AAD from Requestor v1. Make the publisher accept already prepared
public values plus an injected signer. Retain an optional S3 upload only for the
local CLI adapter; the AWS bootstrap/runner stages signed bytes and the
secret-free AWS publisher copies them later. Add:

```json
"bilateral:publish-payer-discovery": "node scripts/publish-payer-bootstrap-discovery.mjs"
```

- [ ] **Step 5: Run focused Payer protocol tests**

Run:

```sh
node --test test/bilateral-payer-bootstrap-envelope.test.mjs test/bilateral-payer-bootstrap-discovery.test.mjs
```

Expected: PASS.

- [ ] **Step 6: Commit**

Commit with a Lore message recording why Payer bootstrap has a distinct wire
schema rather than overloading Requestor v1.

## Task 5: Exact tunnel grants and restricted SSH authorization

**Files:**
- Create: `src/bilateral/aws/tunnel-grant.mjs`
- Create: `test/aws-tunnel-grant.test.mjs`

- [ ] **Step 1: Write failing grant state-machine tests**

Define:

```js
const approved = consumePayerClaim({
  claim,
  expectedClaimFingerprint,
  nowMs,
  publicMcpHostname,
});
const grant = createTunnelGrant({ approved, expiresAtMs });
const reconnect = authorizeTunnelConnection({
  activeGrant: grant,
  connectionFingerprint: claim.sshPublicKeyFingerprint,
  nowMs,
});
```

Require atomic single consumption, one active tunnel, same-key reconnect during
the same unexpired active session, and permanent tombstones after terminal
success, failure, abort, or expiry. Reject a changed claim, key, certificate,
fingerprint, role, session, release, repository SHA, port, or hostname.

- [ ] **Step 2: Write failing SSH-key renderer tests**

For a valid Ed25519 public key, require exactly:

```js
`restrict,port-forwarding,permitlisten="0.0.0.0:9443" ssh-ed25519 ${canonicalKeyBase64} clockchain-payer`
```

Reject RSA/ECDSA, options supplied by the claimant, extra tokens, embedded
newlines, invalid base64, noncanonical Ed25519 key blobs, multiple keys,
additional ports, local forwarding, wildcard grant inputs, and shell commands.

- [ ] **Step 3: Run and observe the missing-module failure**

Run:

```sh
node --test test/aws-tunnel-grant.test.mjs
```

Expected: FAIL because `tunnel-grant.mjs` does not exist.

- [ ] **Step 4: Implement the pure state machine and renderer**

Keep persistence and `sshd` reload outside this module. Return dense canonical
records for pending, active, revoked, and tombstoned states. Make every public
status object retain `paymentMoved:false`.

- [ ] **Step 5: Run the focused test**

Run:

```sh
node --test test/aws-tunnel-grant.test.mjs
```

Expected: PASS.

- [ ] **Step 6: Commit**

Commit this security boundary independently.

## Task 6: One-shot Payer wrapper

**Files:**
- Create: `src/bilateral/local-mcp/payer-bootstrap.mjs`
- Create: `bin/handshake-payer-bootstrap.mjs`
- Create: `test/bilateral-payer-bootstrap.test.mjs`
- Modify: `package.json`
- Modify: `src/bilateral/coordination/supervisor-runtime.mjs`
- Modify: `test/bilateral-coordination-supervisor-runtime.test.mjs`

- [ ] **Step 1: Write the failing happy-path orchestration test**

Drive the pure orchestrator with injected dependencies and assert this exact
order:

```js
[
  "inspect-prerequisites",
  "verify-clean-detached-release",
  "verify-signed-discovery",
  "prepare-private-state",
  "create-x25519-key",
  "create-ssh-key",
  "create-mcp-tls-key-and-certificate",
  "submit-payer-claim",
  "poll-approved-package",
  "verify-and-open-package",
  "write-private-launch-material",
  "start-restricted-tunnel",
  "start-payer-supervisor",
  "wait-for-terminal-local-status",
]
```

Assert the public status sequence includes claim fingerprint,
`PAYER_MCP_READY`, `PROPOSED`, and `ACKNOWLEDGED`, but contains no secret,
private path, manifest bytes, raw evidence, or authorization literal.

- [ ] **Step 2: Add failing negative and recovery tests**

Cover every prerequisite failure before private material; changed discovery;
invalid operator signature; repository/image mismatch; changed SSH host key;
changed MCP certificate; unapproved/expired claim; package replay; corrupt
private files; tunnel child exit; supervisor child exit; SIGINT/SIGTERM; and a
same-key tunnel reconnect after network interruption. Assert terminal/abort
revokes the grant and zeroizes in-memory bootstrap secrets.

- [ ] **Step 3: Run and observe failure**

Run:

```sh
node --test test/bilateral-payer-bootstrap.test.mjs
```

Expected: FAIL because the Payer wrapper is absent.

- [ ] **Step 4: Implement the orchestrator and thin CLI**

The CLI accepts exactly:

```text
--discovery-url "$PAYER_DISCOVERY_URL"
--state "$PAYER_STATE_ROOT"
```

Generate the Payer MCP certificate with the signed public MCP hostname in its
SAN. Build the private known-hosts file from the operator-signed tunnel host
public key after independently checking its signed fingerprint. Start OpenSSH
with batch mode, strict host-key checking against that file, no shell command,
local MCP target `127.0.0.1:9443`, remote bind `0.0.0.0:9443`, and the signed
tunnel port `443`. Pass the decrypted
operator bootstrap-broker URL/capability to the existing Payer supervisor
through private files. Add:

```json
"bilateral:payer": "node bin/handshake-payer-bootstrap.mjs"
```

- [ ] **Step 5: Run focused Payer and supervisor tests**

Run:

```sh
node --test test/bilateral-payer-bootstrap.test.mjs test/bilateral-coordination-supervisor-runtime.test.mjs
```

Expected: PASS.

- [ ] **Step 6: Commit**

Commit the one-shot Payer path with a Lore directive that future changes may not
reintroduce manual manifests, certificate attachments, or second prompts.

## Task 7: Dual-role AWS bootstrap state and transport

**Files:**
- Create: `src/bilateral/aws/bootstrap-state.mjs`
- Create: `src/bilateral/aws/bootstrap-service.mjs`
- Create: `scripts/run-aws-bootstrap-service.mjs`
- Create: `test/aws-bootstrap-state.test.mjs`
- Create: `test/aws-bootstrap-service.test.mjs`
- Modify: `src/bilateral/local-mcp/server.mjs`
- Modify: `test/bilateral-local-mcp-server.test.mjs`
- Modify: `src/bilateral/local-mcp/bootstrap-broker.mjs`
- Modify: `test/bilateral-requestor-bootstrap-broker.test.mjs`

- [ ] **Step 1: Write failing durable-state tests**

Model exact transitions:

```text
PENDING -> APPROVED -> SEALED -> CONSUMED
PENDING -> REJECTED
PENDING|APPROVED -> EXPIRED
```

Payer claims enter through the public claim API and Requestor claims enter only
through the capability-authenticated Payer MCP bridge. Require atomic claim
fingerprint approval, expected revision, one active session, single sealing,
byte-identical retry of an already sealed response, and replay tombstones.

- [ ] **Step 2: Write failing transport tests**

Require:

```text
POST /v1/payer-claims
GET  /v1/payer-claims/{claimId}
POST /v1/requestor-claims
GET  /v1/requestor-claims/{claimId}
GET  /health
```

Payer polling uses a client-generated bearer poll capability whose digest alone
is persisted. Requestor routes require the operator-created broker capability
from the sealed Payer package. Reject absent/wrong auth, body over limit,
duplicate JSON keys, unknown paths/methods, stale revision, changed claim,
second active session, and any response containing a raw capability or manifest.

- [ ] **Step 3: Run focused tests and observe failures**

Run:

```sh
node --test test/aws-bootstrap-state.test.mjs test/aws-bootstrap-service.test.mjs
```

Expected: FAIL because the AWS state/service modules are absent.

- [ ] **Step 4: Extract reusable state from the loopback broker**

Keep Requestor v1 claim and envelope compatibility. Leave the current loopback
CLI available for local deterministic tests, but move canonical
claim/fingerprint/journal transitions into the shared state module. Add an
authenticated HTTPS broker client for Payer MCP instead of weakening the
existing loopback-only client.

- [ ] **Step 5: Implement the AWS service adapter**

Mount only the bootstrap EFS access point, use the operator signer supplied by
the task adapter, never log request bodies, and write the sealed journal before
replying. The health route is non-authoritative and secret-free.

- [ ] **Step 6: Run focused bootstrap tests**

Run:

```sh
node --test test/aws-bootstrap-state.test.mjs test/aws-bootstrap-service.test.mjs test/bilateral-requestor-bootstrap-broker.test.mjs test/bilateral-local-mcp-server.test.mjs
```

Expected: PASS.

- [ ] **Step 7: Commit**

Commit the shared bootstrap state and AWS transport separately from
infrastructure.

## Task 8: Fargate-safe leases and immutable task provenance

**Files:**
- Create: `src/bilateral/aws/efs-lease.mjs`
- Create: `src/bilateral/aws/task-provenance.mjs`
- Create: `test/aws-efs-lease.test.mjs`
- Create: `test/aws-task-provenance.test.mjs`
- Modify: `src/bilateral/coordination/storage.mjs`
- Modify: `test/bilateral-coordination-storage.test.mjs`
- Modify: `src/bilateral/coordination/coordinator-runtime.mjs`
- Modify: `bin/handshake-relay.mjs`

- [ ] **Step 1: Write failing lease tests**

Require a durable lease record bound to a random lease nonce and ECS task
identity, not `process.pid`:

```js
{
  acquiredAtMs,
  expiresAtMs,
  leaseNonce,
  ownerTaskArn,
  schema: "clockchain.aws-efs-lease/v1",
}
```

Use atomic directory/file creation and identity pinning. Test heartbeat,
unexpired contention, expired takeover, old-owner late heartbeat, PID reuse,
clock rollback, malformed records, symlinks, hard links, and crash recovery.

- [ ] **Step 2: Write failing provenance tests**

Validate an immutable build record:

```js
{
  operatorPublicKeySha256,
  repositorySha,
  schema: "clockchain.aws-build-provenance/v1",
  sourceTreeSha256,
}
```

Compare it with the expected reviewed SHA, operator public key, task-definition
image digest, and ECS metadata `ImageID`. Reject mutable tags, missing digest,
changed source record, dirty local fallback, and mismatched container metadata.

- [ ] **Step 3: Run and observe missing-module failures**

Run:

```sh
node --test test/aws-efs-lease.test.mjs test/aws-task-provenance.test.mjs
```

Expected: FAIL because the AWS lease/provenance modules are absent.

- [ ] **Step 4: Implement and inject the new boundaries**

Preserve the current POSIX PID lease for local mode. Require the AWS adapter to
inject the Fargate lease implementation. Refactor relay/coordinator repository
identity reads behind an injected provenance provider so AWS images do not need
a writable Git checkout at runtime.

- [ ] **Step 5: Run focused storage/runtime tests**

Run:

```sh
node --test test/aws-efs-lease.test.mjs test/aws-task-provenance.test.mjs test/bilateral-coordination-storage.test.mjs test/bilateral-coordination-coordinator-runtime.test.mjs test/bilateral-coordination-relay.test.mjs
```

Expected: PASS.

- [ ] **Step 6: Commit**

Commit with a Lore message explaining the rejection of container PID liveness as
a restart authority.

## Task 9: AWS relay, coordinator, watcher, and external verifier boundary

**Files:**
- Create: `src/bilateral/aws/ecs-verifier-launcher.mjs`
- Create: `scripts/run-aws-relay.mjs`
- Create: `scripts/run-aws-coordinator.mjs`
- Create: `test/aws-verifier-launcher.test.mjs`
- Create: `test/aws-control-plane-adapters.test.mjs`
- Modify: `src/bilateral/coordination/coordinator-runtime.mjs`
- Modify: `test/bilateral-coordination-coordinator-runtime.test.mjs`
- Modify: `scripts/watch-bilateral-session.mjs`
- Modify: `test/bilateral-watcher.test.mjs`

- [ ] **Step 1: Write failing verifier-launcher tests**

Define an injected ECS client boundary that launches one task with:

```js
{
  action: "VERIFY",
  expectedRevision,
  releaseId,
  repositorySha,
  sessionId,
}
```

Require a fresh task ARN, task definition pinned by digest, read-only evidence
mount, separate verdict-output mount, no operator/treasury secrets, and a new
attempt ID after interruption. Reject task reuse, stale revision, multiple
tasks, nonzero exit, absent publication, changed evidence digest, and a verifier
result written before the action.

- [ ] **Step 2: Write failing adapter tests**

Assert relay and coordinator adapters use the Fargate lease and task provenance,
mount only their assigned EFS roots, replay only authenticated durable events,
and write strict sanitized watcher/console projections. The AWS coordinator must
remain waiting until an explicit operator `VERIFY` action; it must not spawn the
existing local verifier child automatically.

- [ ] **Step 3: Run and observe failures**

Run:

```sh
node --test test/aws-verifier-launcher.test.mjs test/aws-control-plane-adapters.test.mjs
```

Expected: FAIL because the AWS adapters are absent.

- [ ] **Step 4: Refactor coordinator verifier injection**

Keep the local child-process verifier adapter for existing deterministic local
tests. Add a production interface:

```js
await verifierLauncher.launch({
  evidenceDescriptor,
  expectedRevision,
  releaseId,
  repositorySha,
  sessionId,
});
```

The AWS implementation stages no authority result itself; it waits for the
fresh verifier's separately validated publication.

- [ ] **Step 5: Implement thin relay/coordinator adapters**

Reuse `createRelayService`, storage validators, coordinator state machine, and
watcher observation core. Do not copy their protocol logic. Redact child errors
and paths before CloudWatch output.

- [ ] **Step 6: Run focused runtime tests**

Run:

```sh
node --test test/aws-verifier-launcher.test.mjs test/aws-control-plane-adapters.test.mjs test/bilateral-coordination-coordinator-runtime.test.mjs test/bilateral-watcher.test.mjs
```

Expected: PASS.

- [ ] **Step 7: Commit**

Commit the AWS runtime adapters with a Lore directive that the operator action
may launch verification but may never synthesize its result.

## Task 10: Operator action authority and secret-free control API

**Files:**
- Create: `src/bilateral/aws/control-actions.mjs`
- Create: `test/aws-control-actions.test.mjs`
- Create: `infra/aws/lambda/control-api.mjs`
- Create: `infra/aws/test/control-api.test.mjs`

- [ ] **Step 1: Write failing pure action tests**

Allow exactly:

```js
const ACTION_TYPES = Object.freeze([
  "START_RUN",
  "APPROVE_PAYER",
  "APPROVE_REQUESTOR",
  "FUND",
  "VERIFY",
  "ABORT",
]);
```

`START_RUN` contains exact `actionId`, `expectedRevision:0`, `releaseId`,
`repositorySha`, `type`, and `paymentMoved:false`; the operator worker creates
the session ID. Every later command also contains that exact `sessionId`.
Approval actions additionally contain the exact claim fingerprint. Test valid
ordering, idempotent same-action retry, conflicting idempotency-key reuse, stale
revision, cross-session action, changed fingerprint, skipped action, duplicate
funding/verification, and action after terminal state.

- [ ] **Step 2: Write failing Lambda tests**

Inject JWT claims, session-state lookup, and SQS sender. Require Cognito issuer,
audience, expiry, and operator group; exact JSON; bounded body; same-origin CORS;
no raw addresses, tokens, manifests, private keys, paths, or evidence fields;
and a redacted response containing only action ID, revision, and status.

- [ ] **Step 3: Run and observe failures**

Run:

```sh
node --test test/aws-control-actions.test.mjs infra/aws/test/control-api.test.mjs
```

Expected: FAIL because the modules are absent.

- [ ] **Step 4: Implement pure validation and thin Lambda**

The Lambda owns no application secret and has no EFS access. It validates the
request against the current public session revision, uses a conditional
DynamoDB idempotency write, and sends only the canonical allowlisted action to
SQS. Disable API Gateway request/response body logging.

- [ ] **Step 5: Run focused action/API tests**

Run:

```sh
node --test test/aws-control-actions.test.mjs infra/aws/test/control-api.test.mjs
```

Expected: PASS.

- [ ] **Step 6: Commit**

Commit the action boundary separately so IAM and worker tests can target it.

## Task 11: Operator worker, funding task, and fresh verifier task

**Files:**
- Create: `scripts/run-aws-operator-worker.mjs`
- Create: `scripts/run-aws-funding-task.mjs`
- Create: `scripts/run-aws-verifier-task.mjs`
- Create: `test/aws-operator-worker.test.mjs`
- Create: `test/aws-funding-task.test.mjs`
- Create: `test/aws-verifier-task.test.mjs`
- Modify: `scripts/fund-bilateral-addresses.mjs`
- Modify: `test/bilateral-funding-cli.test.mjs`
- Modify: `scripts/verify-bilateral-results.mjs`
- Modify: `test/bilateral-verdict.test.mjs`

- [ ] **Step 1: Write failing worker tests**

Feed canonical SQS messages through injected clients. Assert:

- `START_RUN` creates one session and launches coordinator state.
- approval actions call exact bootstrap-state transitions.
- `FUND` starts one isolated funding task.
- `VERIFY` starts one isolated verifier task.
- `ABORT` revokes the tunnel and terminates the session.
- a message is deleted only after the durable transition is committed.
- duplicate, stale, malformed, cross-session, or out-of-order messages are
  durably rejected without a child task.

- [ ] **Step 2: Write failing funding-task tests**

Require exactly four distinct fresh Sepolia addresses, exactly `0.01` ETH each,
zero recipient nonces, expected treasury/chain, sufficient balance, one durable
journal, and confirmed receipts. Inject the Secrets Manager wallet password
instead of macOS Keychain. Confirm an attempted or ambiguous journal is never
automatically retried and `paymentMoved` remains `false`.

- [ ] **Step 3: Write failing verifier-task tests**

Run the production verifier entrypoint with a new attempt root and injected
Clockchain refetch. Require exactly three ordered anchors and validate the
publication before success. Assert:

```js
assert.equal(verifierStdout, "AUTHORIZED\n");
assert.equal(operatorStdout.includes("AUTHORIZED"), false);
assert.equal(publication.verifier.status, "VERIFIED");
```

Cover missing/duplicate/reordered/expired/malformed/mismatched anchors,
non-fresh evidence, extra files, stale attempt ID, and any
`paymentMoved !== false`.

- [ ] **Step 4: Run and observe failures**

Run:

```sh
node --test test/aws-operator-worker.test.mjs test/aws-funding-task.test.mjs test/aws-verifier-task.test.mjs
```

Expected: FAIL because the task adapters are absent.

- [ ] **Step 5: Implement thin task adapters**

Reuse the existing funding record/journal and aggregate verifier. Supply
task-specific secret readers and EFS paths through injected dependencies. Do
not add a second authorization module or output path.

- [ ] **Step 6: Add a production-literal static test**

Scan production source and require the authorization literal to appear only in
the existing aggregate verdict authority and the fresh verifier CLI output.
Exclude tests and documentation from the scan. The console, worker, coordinator,
publisher, Lambda, and monitor modules must not contain it.

- [ ] **Step 7: Run focused worker/funding/verifier tests**

Run:

```sh
node --test test/aws-operator-worker.test.mjs test/aws-funding-task.test.mjs test/aws-verifier-task.test.mjs test/bilateral-funding-cli.test.mjs test/bilateral-verdict.test.mjs
```

Expected: PASS.

- [ ] **Step 8: Commit**

Commit with a Lore message recording funding replay safety and fresh-verifier
isolation.

## Task 12: Sanitized live monitor and immutable run history

**Files:**
- Create: `src/bilateral/aws/public-history.mjs`
- Create: `scripts/publish-aws-public-monitor.mjs`
- Create: `test/aws-public-history.test.mjs`
- Create: `test/aws-public-monitor-publisher.test.mjs`
- Modify: `src/bilateral/coordination/public-monitor.mjs`
- Modify: `test/bilateral-public-monitor.test.mjs`
- Modify: `src/bilateral/coordination/coordinator-runtime.mjs`
- Modify: `scripts/publish-requestor-discovery.mjs`
- Modify: `test/bilateral-requestor-discovery.test.mjs`
- Modify: `scripts/publish-payer-bootstrap-discovery.mjs`

- [ ] **Step 1: Write failing projection tests**

Extend the strict public projection with:

```js
{
  anchors,
  currentStep,
  funding: { status },
  mcp: { status },
  paymentMoved: false,
  publishedAtMs,
  relay: { status },
  requestor: { status },
  payer: { status },
  runId,
  runStatus,
  schema: "clockchain.bilateral-public-monitor/v2",
  staleAfterMs,
  verifier: { status },
}
```

Define a discriminated live-state union. `anchors` may contain only the valid
prefixes `[]`, `[PROPOSED]`, `[PROPOSED, ACCEPTED]`, or
`[PROPOSED, ACCEPTED, ACKNOWLEDGED]`, with exact Payer/Requestor/Payer signer
roles. `verifier.status` is one of `NOT_STARTED`, `RUNNING`, `VERIFIED`,
`FAILED`, or `EXPIRED`. `VERIFIED` requires exactly all three anchors and a
validated fresh verifier publication; pending/failed/expired snapshots may
contain only the authenticated prefix observed so far. Use bounded business
descriptions. Reject extra anchors, wrong order/role, missing explorer data for
an observed anchor, private/internal URLs, non-false payment state, unknown
status, and stale source. Ensure a previously green snapshot becomes visibly
stale once `staleAfterMs` passes.

- [ ] **Step 2: Write failing history tests**

Define:

```text
runs/{runId}.json
runs/index.json
latest.json
discoveries/payer.json
discoveries/requestor.json
certificates/{certificateFingerprint}.crt
```

The immutable summary is created only after terminal validated projection. The
bounded newest-first index contains run ID, completion time, business result,
observed authenticated anchor summaries, and the summary-object URL. A
`VERIFIED` summary requires exactly three anchors; `FAILED` and `EXPIRED`
summaries preserve only the authenticated prefix and must never look green.
Reject overwrite with different bytes, duplicate run ID, index reorder, more
than 25 entries, unvalidated verifier publication, and any secret canary.

Evolve Requestor discovery to exact schema
`clockchain.requestor-discovery/v2` with `schema`, `paymentMoved:false`,
`imageDigest`, release/session/SHA, signed MCP URL, certificate URL/fingerprint,
operator key ID, expiry, and signature. Lock signed discovery bytes before
publication. Payer discovery is staged when the run starts; Requestor discovery
and the public Payer certificate are staged only after the approved Payer claim,
`PAYER_MCP_READY`, and the tunnel service's matching pinned-TLS health
projection. The AWS publisher has no signer: it copies only already signed,
schema-validated bytes from the sanitized staging access point.

- [ ] **Step 3: Run and observe failures**

Run:

```sh
node --test test/aws-public-history.test.mjs test/aws-public-monitor-publisher.test.mjs test/bilateral-public-monitor.test.mjs test/bilateral-requestor-discovery.test.mjs
```

Expected: FAIL because the AWS publisher/history modules and v2 schema are
absent.

- [ ] **Step 4: Implement EFS-to-S3 publication**

Read only the sanitized console and verifier-public EFS access points. Use
conditional S3 writes for immutable summaries and versioned writes for
`latest.json`/`runs/index.json`. Capture object ETags in private publication
records. Separate signing/staging from the existing Requestor discovery CLI's
upload adapter, and apply the same boundary to Payer discovery. Do not call
localhost, probe a Payer port, sign inside the publisher, or read raw evidence.

- [ ] **Step 5: Run focused publication tests**

Run:

```sh
node --test test/aws-public-history.test.mjs test/aws-public-monitor-publisher.test.mjs test/bilateral-public-monitor.test.mjs test/bilateral-requestor-discovery.test.mjs
```

Expected: PASS.

- [ ] **Step 6: Commit**

Commit the public schema and publisher with a Lore directive that public
snapshots are sanitized projections, never authority.

## Task 13: Tunnel service and container entrypoints

**Files:**
- Create: `scripts/run-aws-tunnel-service.mjs`
- Create: `test/aws-tunnel-service.test.mjs`
- Create: `infra/aws/docker/control-plane.Dockerfile`
- Create: `infra/aws/docker/tunnel.Dockerfile`
- Create: `infra/aws/docker/sshd_config`
- Create: `infra/aws/runtime/aws-clients.mjs`
- Create: `infra/aws/runtime/bootstrap-entrypoint.mjs`
- Create: `infra/aws/runtime/operator-worker-entrypoint.mjs`
- Create: `infra/aws/runtime/publisher-entrypoint.mjs`
- Create: `infra/aws/runtime/verifier-launcher.mjs`
- Create: `infra/aws/test/container-contract.test.mjs`
- Modify: `package.json`

- [ ] **Step 1: Write failing tunnel-service tests**

Use a temporary state root and injected process controller. Assert the service:

- reads only approved/tombstoned grants;
- writes one canonical `authorized_keys` line atomically;
- starts `sshd` on container port `2222`;
- exposes a secret-free health listener on `8080`;
- permits only the remote listener on `0.0.0.0:9443`;
- reports MCP ready only after a local raw-TCP probe through the remote listener
  completes a TLS handshake whose certificate fingerprint matches the approved
  grant;
- reloads after same-key reconnect;
- closes and tombstones on abort/terminal/expiry; and
- never logs a key, certificate, grant body, internal path, or SSH command.

- [ ] **Step 2: Write failing container contract tests**

Inspect Dockerfiles/config and require:

```text
Port 2222
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitRootLogin no
AllowTcpForwarding remote
GatewayPorts clientspecified
PermitTTY no
X11Forwarding no
PermitUserRC no
MaxSessions 1
```

Require a non-root/nologin tunnel user, fixed exposed ports `2222`, `9443`,
`8080`, Node 22, immutable build provenance generation, a read-only root
filesystem-compatible layout, and no secret copied into either image.

- [ ] **Step 3: Run and observe failures**

Run:

```sh
node --test test/aws-tunnel-service.test.mjs infra/aws/test/container-contract.test.mjs
```

Expected: FAIL because the service and containers are absent.

- [ ] **Step 4: Implement the tunnel adapter and images**

The tunnel container contains OpenSSH plus the small Node grant/health
controller. The control-plane image contains participant-neutral shared runtime
entrypoints. Generate `/opt/clockchain/release.json` from the exact build SHA
and fail the image build if the working tree is dirty or the SHA differs. Root
runtime modules accept injected AWS clients and do not import AWS SDK packages;
the `infra/aws/runtime/` entrypoints own AWS SDK construction so participant
`npm ci` remains limited to the root dependencies.

The health controller writes only a bounded tunnel/MCP health projection. Port
`8080` returns unhealthy until an approved tunnel is active and the pinned TLS
probe succeeds; it returns unhealthy immediately on disconnect, fingerprint
mismatch, revocation, or expiry. It never terminates or forwards MCP TLS itself.

- [ ] **Step 5: Add package scripts**

Add exact scripts for local image/task testing:

```json
"aws:bootstrap": "node scripts/run-aws-bootstrap-service.mjs",
"aws:coordinator": "node scripts/run-aws-coordinator.mjs",
"aws:fund": "node scripts/run-aws-funding-task.mjs",
"aws:operator-worker": "node scripts/run-aws-operator-worker.mjs",
"aws:public-monitor": "node scripts/publish-aws-public-monitor.mjs",
"aws:relay": "node scripts/run-aws-relay.mjs",
"aws:tunnel": "node scripts/run-aws-tunnel-service.mjs",
"aws:verify": "node scripts/run-aws-verifier-task.mjs"
```

- [ ] **Step 6: Run focused container tests and build both images**

Run:

```sh
node --test test/aws-tunnel-service.test.mjs infra/aws/test/container-contract.test.mjs
docker build --build-arg REPOSITORY_SHA="$(git rev-parse HEAD)" -f infra/aws/docker/control-plane.Dockerfile .
docker build --build-arg REPOSITORY_SHA="$(git rev-parse HEAD)" -f infra/aws/docker/tunnel.Dockerfile .
```

Expected: tests PASS and both builds complete from a clean checkout.

- [ ] **Step 7: Commit**

Commit the runtime images and entrypoints with the recorded local image-build
evidence.

## Task 14: CDK foundation, storage isolation, and least privilege

**Files:**
- Create: `infra/aws/package.json`
- Create: `infra/aws/package-lock.json`
- Create: `infra/aws/tsconfig.json`
- Create: `infra/aws/cdk.json`
- Create: `infra/aws/bin/clockchain-handshake.ts`
- Create: `infra/aws/lib/clockchain-handshake-stack.ts`
- Create: `infra/aws/test/clockchain-handshake-stack.test.ts`
- Create: `infra/aws/test/iam-boundaries.test.ts`
- Create: `infra/aws/test/efs-boundaries.test.ts`

- [ ] **Step 1: Initialize the isolated infrastructure package**

Use these exact lockfile-pinned versions already checked against the official
npm registry on 2026-07-30:

```text
aws-cdk-lib 2.262.2
aws-cdk 2.1134.0
constructs 10.8.0
typescript 7.0.2
tsx 4.23.1
esbuild 0.28.1
@types/node 22.20.1
@aws-sdk/client-cloudwatch-logs 3.1100.0
@aws-sdk/client-dynamodb 3.1100.0
@aws-sdk/client-ecr 3.1100.0
@aws-sdk/client-ecs 3.1100.0
@aws-sdk/client-efs 3.1100.0
@aws-sdk/client-iam 3.1100.0
@aws-sdk/client-s3 3.1100.0
@aws-sdk/client-secrets-manager 3.1100.0
@aws-sdk/client-sqs 3.1100.0
@aws-sdk/client-sts 3.1100.0
@aws-sdk/lib-dynamodb 3.1100.0
```

Keep AWS dependencies out of the participant root package. Provide scripts:

```json
{
  "scripts": {
    "build": "tsc --noEmit",
    "synth": "cdk synth",
    "test": "node --import tsx --test test/*.test.ts",
    "typecheck": "tsc --noEmit"
  }
}
```

- [ ] **Step 2: Write failing CDK topology tests**

Require:

- one two-AZ VPC with public Fargate task subnets, no NAT gateway, and
  `AssignPublicIp.ENABLED` on workloads that require public
  Clockchain/Sepolia/AWS API egress;
- one ECS cluster;
- encrypted EFS with IAM authorization and transit encryption;
- fixed access points for relay, operator/coordinator, bootstrap, tunnel,
  funding record/journal, verifier evidence/output, and publisher projections;
- NLB TCP listeners `443 -> 2222`, `9443 -> 9443`, and coordination relay
  `8443 -> 8443`;
- tunnel target health on `8080`;
- a public throttled bootstrap HTTP API whose exact claim routes cross a VPC
  Link and internal NLB listener `9555 -> 9555` to the private bootstrap ECS
  service, with no request/response body logging;
- a separate Cognito-authorized operator control API;
- Cognito, API Gateway, Lambda, SQS, DynamoDB;
- private operator-console bucket/distribution;
- private monitor bucket/distribution;
- ECR repositories, task definitions, services/jobs;
- CloudWatch log groups, retention, alarms, and dashboard; and
- outputs for public endpoints, bucket/distribution names, task definitions,
  and secret ARNs.

- [ ] **Step 3: Write failing IAM/EFS negative tests**

Encode the approved matrices exactly:

| Workload | Secret access |
| --- | --- |
| API/console | none |
| operator runner | operator Ed25519 only |
| relay | relay TLS only |
| bootstrap | operator Ed25519 only |
| coordinator | operator Ed25519, Clockchain token, RPC |
| tunnel | SSH host key only |
| funding | Sepolia RPC, treasury keystore, treasury password |
| verifier | Clockchain token, RPC |
| publisher | none |

Assert every task role is denied unrelated secret ARNs and EFS access points.
Verifier has read-only evidence plus separate write output; publisher has only
sanitized read plus public-object writes; Lambda has no EFS and only the action
table/queue; no task mounts the EFS root.

- [ ] **Step 4: Run and observe failures**

Run from `infra/aws`:

```sh
npm test
```

Expected: FAIL because the stack is absent.

- [ ] **Step 5: Implement the stack to pass assertions**

Pin production container images by ECR digest supplied as CDK context. Enable
ECS task metadata, read-only root filesystems where compatible, non-root users,
deployment circuit breakers, one desired task per stateful service, and one
active session. Security groups allow public ingress only through the NLB/API
surfaces and minimum inter-service traffic.

- [ ] **Step 6: Run focused infrastructure checks**

Run:

```sh
npm --prefix infra/aws test
npm --prefix infra/aws run typecheck
npm --prefix infra/aws run synth
```

Expected: PASS; synth contains no wildcard secret access and no unscoped EFS
client mount/write permission.

- [ ] **Step 7: Commit**

Commit the infrastructure package with a Lore message listing the exact
secret/EFS boundary tests.

## Task 15: Cognito-authenticated operator console

**Files:**
- Create: `infra/aws/operator-console/index.html`
- Create: `infra/aws/operator-console/app.js`
- Create: `infra/aws/operator-console/styles.css`
- Create: `infra/aws/test/operator-console.test.mjs`
- Modify: `infra/aws/lib/clockchain-handshake-stack.ts`

- [ ] **Step 1: Write failing static-console tests**

Render the static files in a DOM harness and require:

- Cognito Hosted UI sign-in with OAuth authorization-code plus PKCE;
- access token held in `sessionStorage`, never local storage or URL query after
  callback cleanup;
- six allowlisted buttons: Start run, Approve Payer, Approve Requestor, Fund,
  Verify, Abort;
- claim fingerprint comparison and current revision visible before approval;
- buttons disabled when the action is out of order;
- no inputs for address, token, manifest, key, capability, path, or evidence;
- business-language status, explicit pending/failure/stale states, and
  `paymentMoved:false`; and
- no authorization literal in HTML, JavaScript, or CSS.

- [ ] **Step 2: Run and observe failure**

Run:

```sh
node --test infra/aws/test/operator-console.test.mjs
```

Expected: FAIL because the console assets are absent.

- [ ] **Step 3: Implement the static console**

Read public session status from the monitor distribution and send actions only
to the authenticated control API. Require explicit confirmation for funding,
verification, abort, and fingerprint approvals. Redact network errors to bounded
business messages.

- [ ] **Step 4: Wire the static deployment**

Have CDK deploy the assets to a private S3 bucket behind CloudFront and inject
only public configuration: Cognito issuer/client ID, control API URL, monitor
URL, and release SHA.

- [ ] **Step 5: Run focused console and stack tests**

Run:

```sh
node --test infra/aws/test/operator-console.test.mjs
npm --prefix infra/aws test
```

Expected: PASS.

- [ ] **Step 6: Commit**

Commit the console with a Lore directive that it remains an action initiator and
never an authority or secret-handling surface.

## Task 16: Deterministic full-topology and restart integration

**Files:**
- Create: `test/aws-control-plane-integration.test.mjs`
- Create: `test/aws-control-plane-restart.test.mjs`
- Create: `test/aws-control-plane-security.test.mjs`
- Modify: `test/bilateral-coordination-process-e2e.test.mjs`

- [ ] **Step 1: Write a failing fake-service full topology**

Use isolated temporary roots, deterministic fake Clockchain/Sepolia adapters,
and actual child processes for the runtime entrypoints. Run:

```text
START_RUN
Payer claim/approval
PAYER_MCP_READY
Requestor request_payment
HANDSHAKE_REQUIRED
Requestor claim/approval
FUND
PROPOSED
ACCEPTED
ACKNOWLEDGED
VERIFY
VERIFIED public projection
```

Require four funding transfers of exactly `0.01`, exactly three anchors in the
required order, one verifier-only authorization output, and
`paymentMoved:false`.

- [ ] **Step 2: Add failing restart cases**

Kill and restart relay, bootstrap, tunnel controller, coordinator, operator
worker, and publisher independently. Assert authenticated replay, same-key
tunnel reconnect, no duplicate funding, no reused verifier attempt, stale
monitor while publisher is down, and recovery without state regression.

- [ ] **Step 3: Add failing hostile boundary cases**

Exercise an unapproved SSH key, extra listen port, changed MCP fingerprint,
second stakeholder session, changed claim, duplicate/reordered relay evidence,
funding journal ambiguity, mismatched anchor, stale action, secret canaries in
every input, and public/CloudWatch output scans.

- [ ] **Step 4: Run focused integration tests and observe failure**

Run:

```sh
node --test test/aws-control-plane-integration.test.mjs test/aws-control-plane-restart.test.mjs test/aws-control-plane-security.test.mjs
```

Expected: FAIL until all adapters are correctly integrated.

- [ ] **Step 5: Make the smallest integration changes**

Change shared modules only where the failing tests reveal an adapter seam, not
by duplicating authority logic. Preserve existing local process E2E behavior.

- [ ] **Step 6: Run focused integration tests**

Run:

```sh
node --test test/aws-control-plane-integration.test.mjs test/aws-control-plane-restart.test.mjs test/aws-control-plane-security.test.mjs test/bilateral-coordination-process-e2e.test.mjs
```

Expected: PASS.

- [ ] **Step 7: Commit**

Commit deterministic AWS-topology evidence before touching deployment or public
copy.

## Task 17: Two one-shot prompts and AWS runbooks

**Files:**
- Modify: `prompts/run-payer-bilateral-demo.md`
- Modify: `prompts/run-requestor-bilateral-demo.md`
- Modify: `README.md`
- Modify: `docs/runbooks/bilateral-demo-quick-start.md`
- Modify: `docs/runbooks/bilateral-demo-day.md`
- Modify: `docs/runbooks/bilateral-demo-live-handoff.md`
- Modify: `docs/runbooks/payer-mcp-external-relay.md`
- Modify: `scripts/check-docs.mjs`
- Modify: `test/docs.test.mjs`

- [ ] **Step 1: Replace documentation assertions first**

Require exactly one public Payer prompt and one public Requestor prompt. Each
prompt must:

- identify the role before private work;
- accept only its signed public discovery URL;
- validate a clean detached reviewed SHA and Node 22;
- install with `npm ci --ignore-scripts`;
- create its own private state root;
- run exactly one long-lived role command;
- remain attached and explain business progress;
- prohibit role switching, funding, verification, secret display, and
  authorization claims; and
- work only in locally installed Codex, Claude Code, or Hermes on macOS,
  Windows, or Linux, not web-only agents.

Require the operator runbook to describe only the AWS console's five normal
actions plus abort, not Mac terminals, manual manifests, certificate
attachments, SSH aliases, or localhost monitor commands.

Require one concise architecture explanation that A2A is intentionally absent:
Payer MCP is the payment-intake/guidance surface, signed relay events and
Clockchain receipts are the authority surfaces, and adding a second advisory
messaging protocol would not replace either authority boundary.

- [ ] **Step 2: Run docs tests and observe failure**

Run:

```sh
node --test test/docs.test.mjs
```

Expected: FAIL because current documents still encode the local/manual path.

- [ ] **Step 3: Rewrite prompts and runbooks**

The Payer prompt ends in:

```sh
npm run bilateral:payer -- --discovery-url "$PAYER_DISCOVERY_URL" --state "$PAYER_STATE_ROOT"
```

The Requestor prompt ends in:

```sh
npm run bilateral:request-payment -- --discovery-url "$REQUESTOR_DISCOVERY_URL" --state "$REQUESTOR_STATE_ROOT"
```

On macOS/Linux, the agent chooses a new role-specific directory below
`${XDG_STATE_HOME:-$HOME/.local/state}/clockchain-handshake/`; on Windows it
chooses a new role-specific directory below
`$env:LOCALAPPDATA\Clockchain\Handshake\`. The wrapper applies and verifies
the exact private mode or ACL from Task 1; do not ask the human to attach or
paste a private file.

- [ ] **Step 4: Run focused documentation gates**

Run:

```sh
node --test test/docs.test.mjs
npm run docs:check
```

Expected: PASS.

- [ ] **Step 5: Commit**

Commit the public prompt contract separately so deployment can bind its final
URLs and SHA in a later release commit.

## Task 18: Deploy AWS control plane from a frozen release candidate

**Files:**
- Create: `infra/aws/scripts/build-and-push.mjs`
- Create: `infra/aws/scripts/deploy.mjs`
- Create: `infra/aws/scripts/run-integration-checks.mjs`
- Create: `infra/aws/test/deployment-plan.test.mjs`
- Create: `infra/aws/test/live-integration-contract.test.mjs`
- Modify: `infra/aws/package.json`
- Modify: `.gitignore`

- [ ] **Step 1: Write failing deployment-plan tests**

Require the scripts to:

- refuse a dirty tree or non-detached release candidate;
- derive `REPOSITORY_SHA` with `git rev-parse HEAD`;
- build both images from that SHA;
- push immutable SHA tags;
- resolve and record ECR digests;
- synthesize/deploy task definitions pinned to those digests;
- create no secret value on a command line;
- print only public outputs and secret ARNs;
- write private deployment evidence outside Git with `0600`/Windows ACLs; and
- support a read-only `--plan` mode.

Lock the credentialed integration report schema in the same TDD pass. It records
image/SHA binding, stable services, IAM/EFS allow and deny checks, raw TCP/TLS
pass-through, restart behavior, funding replay behavior, public/log canary
scans, and monitor staleness without containing secret values.

- [ ] **Step 2: Run and observe failure**

Run:

```sh
node --test infra/aws/test/deployment-plan.test.mjs
node --test infra/aws/test/live-integration-contract.test.mjs
```

Expected: FAIL because deployment and integration scripts are absent.

- [ ] **Step 3: Implement build, deploy, and integration scripts**

Use AWS SDK/CDK APIs from the infrastructure package. Require an authenticated
AWS session at execution time. Provision secret containers without printing or
committing their values; import the existing operator/treasury material through
interactive or file-descriptor-safe deployment steps outside the command line.
Implement the integration script against injected AWS/network clients first so
the contract test proves report validation, redaction, allow/deny pairing, and
failure propagation before any credentialed call.

- [ ] **Step 4: Run local deployment validation**

Run:

```sh
node --test infra/aws/test/deployment-plan.test.mjs
node --test infra/aws/test/live-integration-contract.test.mjs
npm --prefix infra/aws run typecheck
npm --prefix infra/aws run synth
npm --prefix infra/aws run deploy:plan
```

Expected: PASS and the plan identifies account `570035913370`, region
`us-west-2`, exact resource changes, and no deletion of the legacy EC2 instance.

- [ ] **Step 5: Commit and push the frozen release candidate**

Commit only code/tests. Keep generated plans that contain account-local resource
identifiers, private deployment evidence, and secret input outside Git. Push
the public branch and confirm the exact release-candidate SHA is fetchable from
`https://github.com/thetangstr/clockchain-handshake.git` before building images
or issuing signed discovery.

- [ ] **Step 6: Reauthenticate and deploy**

Run `aws login` only when the deployment step reaches the expired AWS session.
Then build, push, and deploy. Record stack ID, NLB DNS, CloudFront URLs, API URL,
ECR digests, task-definition ARNs, EFS/access-point IDs, bucket names, and
CloudWatch dashboard URL in the private deployment evidence.

- [ ] **Step 7: Run deployed smoke checks**

Verify:

- relay TLS/raw TCP endpoint health;
- tunnel SSH host-key fingerprint on public TCP 443;
- closed Payer MCP TCP 9443 before an approved tunnel;
- signed Payer discovery retrieval;
- authenticated operator sign-in/API rejection without a token;
- public monitor unavailable/stale state;
- no public S3 listing; and
- expected ECS services stable.

## Task 19: Publish the stakeholder run page and live AWS history

**Repository:** Clockchain Research

**Files:**
- Modify: `src/app/handshake/run/page.tsx`
- Modify: `src/components/BilateralHandshakeRunbook.tsx`
- Modify: `src/components/BilateralPublicMonitor.tsx`
- Create: `src/components/BilateralHandshakeHistory.tsx`
- Modify: `src/lib/bilateral-public-monitor.ts`
- Create: `src/lib/bilateral-public-history.ts`
- Modify: `src/data/bilateral-handshake-demo.ts`
- Modify: `src/components/BilateralHandshakeOperatorRunbook.tsx`
- Modify: `src/app/handshake/run/operator/page.tsx`
- Modify: `src/lib/bilateral-handshake-runbook.test.tsx`
- Modify: `src/lib/bilateral-handshake-operator-runbook.test.tsx`
- Modify: `src/lib/bilateral-public-monitor.test.ts`
- Create: `src/lib/bilateral-public-history.test.ts`

- [ ] **Step 1: Write failing public-page tests**

Require the page to begin with a short introduction, then an unmistakable
ordered flow:

```text
1. Payer goes first
2. Wait for PAYER_MCP_READY
3. Requestor goes second
4. Watch Clockchain
```

Show one prominent copyable Payer prompt and one differently colored copyable
Requestor prompt. State that each stakeholder uses a locally installed Codex,
Claude Code, or Hermes on macOS, Windows, or Linux; web-only ChatGPT/Claude are
unsupported. Remove Kailor, Iris, Billie, demo-director, attachment, localhost,
old IP, and manual Payer command language.

- [ ] **Step 2: Write failing monitor/history parser tests**

Parse only the strict AWS monitor v2, history index, and immutable summary
schemas. Reject unknown keys, wrong anchor count/order/role, stale success,
internal/private URLs, non-false payment state, and unrecognized status. The
history list opens one run inline with business explanations, three explorer
links, verifier result, and gas-funding explanation.

- [ ] **Step 3: Run focused site tests and observe failure**

Run from the research site root:

```sh
npm test -- src/lib/bilateral-handshake-runbook.test.tsx src/lib/bilateral-handshake-operator-runbook.test.tsx src/lib/bilateral-public-monitor.test.ts src/lib/bilateral-public-history.test.ts
```

Expected: FAIL because the current page is Requestor-only and uses the old
Mac-backed endpoints/static history.

- [ ] **Step 4: Implement the stakeholder page**

Bind the two prompt boxes to the deployed signed discovery URLs and final
reviewed SHA. Poll the public CloudFront monitor and history index. Display
`VERIFIED` for a valid fresh verifier publication and never render the
authorization literal. Make the operator route redirect or link to the
Cognito-authenticated AWS console rather than expose local commands.

Retain the existing validated local-agent rehearsal summaries as a clearly
labeled, read-only fallback section named `Prior local rehearsals`. Never merge
them into the AWS-live index or imply they prove AWS independence. When the AWS
history index is unavailable, the page may still render those packaged
summaries with their original run IDs and evidence links.

- [ ] **Step 5: Run focused site checks**

Run:

```sh
npm test -- src/lib/bilateral-handshake-runbook.test.tsx src/lib/bilateral-handshake-operator-runbook.test.tsx src/lib/bilateral-public-monitor.test.ts src/lib/bilateral-public-history.test.ts
npm run typecheck
npm run build
```

Expected: PASS.

- [ ] **Step 6: Commit and push the research-site change**

Use the research repository's commit conventions. The pushed commit is the only
source deployed to production.

- [ ] **Step 7: Deploy and browser-smoke the public page**

Deploy through the existing research-site workflow. In a clean browser session,
verify both copy controls, ordered role sequence, live monitor refresh, stale
appearance, history list/detail interaction, mobile layout, AWS console link,
and absence of old IP/localhost/private material.
Record the deployed URL and deployment identifier in the live acceptance
record.

## Task 20: AWS integration, IAM denial, and public canary checks

**Files:**
- Read only: deployed AWS resources and private deployment evidence
- Create privately, outside Git: credentialed integration report

- [ ] **Step 1: Reconfirm the committed integration-check contract**

Require machine-readable results for:

- every image digest equals the reviewed SHA deployment record;
- every long-lived ECS service is stable;
- each task role can read only its allowed secret and EFS access point;
- denied reads fail for every unrelated secret/access point;
- NLB passes Payer TLS bytes unchanged;
- changed/unapproved tunnel keys and listen ports fail;
- task restart preserves authenticated state;
- funding ambiguity does not retry;
- public S3/CloudFront and CloudWatch logs contain no seeded canary; and
- publisher staleness is visible after two missed windows.

- [ ] **Step 2: Rerun the deterministic contract test**

Run:

```sh
node --test infra/aws/test/live-integration-contract.test.mjs
```

Expected: PASS before credentialed execution.

- [ ] **Step 3: Run credentialed AWS checks**

Run the integration script against the deployed stack. Store the complete
machine-readable report privately.

- [ ] **Step 4: Resolve every failed check**

Use focused module or CDK tests for each correction. Re-deploy only the affected
task definition/service/asset, then rerun the failed check plus its adjacent
negative check.

## Task 21: Fresh two-stakeholder live acceptance and Mac cutover proof

**Files:**
- Create privately, outside Git: live acceptance record and stakeholder state
  roots

- [ ] **Step 1: Establish fresh role contexts**

Use two fresh local agent contexts, one Payer and one Requestor, on independently
owned state roots. Give each only its public page prompt. Confirm role and
reviewed SHA before either wrapper creates private material.

- [ ] **Step 2: Start the Payer first**

Approve the exact Payer claim fingerprint in the AWS console. Verify the Payer
wrapper creates its local keys/certificate, establishes the restricted tunnel,
starts MCP/supervisor, and reports `PAYER_MCP_READY` without a second prompt or
file attachment.

- [ ] **Step 3: Start the Requestor second**

Confirm from a network other than Kailor's Mac that the public Payer MCP TLS
certificate/fingerprint match signed discovery. Let the Requestor's one command
call `request_payment`, visibly receive exact `HANDSHAKE_REQUIRED`, submit its
claim, and remain attached. Approve the exact Requestor claim fingerprint in the
AWS console.

- [ ] **Step 4: Fund once from AWS**

When the coordinator-owned record is ready, press Fund once. Verify exactly four
confirmed transfers of `0.01` Sepolia ETH to the four fresh addresses and a
durable funding journal. Confirm this is gas funding only and every protocol
artifact still says `paymentMoved:false`.

- [ ] **Step 5: Observe the exact protocol sequence**

Record independently re-verifiable evidence that:

1. Payer anchored `PROPOSED`.
2. Requestor anchored `ACCEPTED`.
3. Payer anchored `ACKNOWLEDGED`.

Reject and rerun with fresh state if there is any missing, duplicate, reordered,
expired, malformed, or mismatched anchor.

- [ ] **Step 6: Launch one fresh verifier**

Press Verify once. Record its new ECS task ARN, pinned image digest, empty
attempt root, independent Clockchain refetch, exact three-anchor result, and
sole authorization output. Confirm operator console/public monitor show
`VERIFIED` and `paymentMoved:false`.

- [ ] **Step 7: Prove the Mac and legacy EC2 path are not required**

Reversibly stop the old Mac reverse SSH command,
`publish-public-monitor.mjs`, and `handshake-console.mjs`; unload or disable
their LaunchAgent labels; and stop the old EC2 instance or close its public
relay ingress. Do not delete them. While they remain stopped:

- retrieve Payer/Requestor discoveries and the public monitor;
- call Payer MCP externally through AWS;
- operate the authenticated AWS console;
- observe `latest.json` updates across at least two `staleAfterMs` windows;
- open the immutable history summary; and
- match public S3 ETags with private CloudWatch publication records.

- [ ] **Step 8: Complete the private acceptance record**

Record ECS task ARNs and image digests for relay, coordinator, bootstrap,
tunnel, publisher, funding, and verifier; the three public anchor explorer
links; deployment and site IDs; public ETags; legacy process/LaunchAgent/EC2
status; and an explicit secret-scan result. Publish only the sanitized run
summary through the existing public history path.

## Task 22: Independent integrated review, final gates, and release

**Files:**
- Review: every change in the Handshake repository
- Review: every change in the Clockchain Research repository
- Modify only for review findings

- [ ] **Step 1: Freeze the final implementation SHA**

Ensure both worktrees are clean except for the intended integrated changes.
Review the complete diffs for unrelated files, private artifacts, generated
state, secrets, public IPs from the retired path, and mutable image tags.

- [ ] **Step 2: Run independent architecture and security reviews**

Use separate read-only reviewers. Require explicit findings on:

- exact Payer/Requestor event authority;
- MCP advisory versus relay/Clockchain authority;
- funding replay safety;
- tunnel claim consumption/reconnect/revocation;
- task secret and EFS isolation;
- fresh-verifier-only authorization output;
- three-anchor enforcement;
- public sanitization/freshness/history;
- cross-platform one-shot participant behavior; and
- absence of Mac/legacy EC2 runtime dependency.

Record low findings as accepted only when they do not violate completion
criteria.

- [ ] **Step 3: Resolve every review finding before the final gate**

Resolve every high/medium finding with focused tests. If a correction changes
either repository's behavior, repeat the relevant focused checks and
independent review.

- [ ] **Step 4: Redeploy and repeat live acceptance if a reviewed artifact changed**

If review fixes changed the Handshake SHA, rebuild both images, resolve new ECR
digests, first push and verify the new public SHA, update signed discoveries and
sealed manifests, deploy the pinned task definitions, update the public prompt
SHA, and repeat Tasks 20 and 21 in full.
If a site-only fix changed prompt, monitor, or history behavior, redeploy the
site and repeat the affected browser and live acceptance checks. Never label an
earlier image, discovery, or live run with a later SHA.

- [ ] **Step 5: Run the final fresh Handshake gate once**

Run:

```sh
npm run verify
```

Expected: PASS. This is the only complete Handshake suite run during
implementation.

- [ ] **Step 6: Run the final fresh infrastructure gates**

Run:

```sh
npm --prefix infra/aws test
npm --prefix infra/aws run typecheck
npm --prefix infra/aws run synth
```

Expected: PASS.

- [ ] **Step 7: Run the final fresh research-site gates**

Run from the Clockchain Research repository root:

```sh
npm test
npm run typecheck
npm run lint
npm run build
```

Expected: PASS.

- [ ] **Step 8: Push both repositories and deliver the handoff**

Push the final Handshake and research-site branches. The handoff contains:

- final Handshake SHA and ECR digests;
- AWS stack/deployment identifier;
- public Payer and Requestor discovery URLs;
- public run page, live monitor, and history URLs;
- authenticated operator-console URL;
- fresh live run ID and three public anchor links;
- final verifier task ARN and `VERIFIED` monitor evidence;
- final test results;
- proof the Mac/legacy path was outside the run; and
- any bounded remaining operational caveat that does not violate the approved
  completion criteria.

## Completion checklist

- [ ] Payer and Requestor each complete from one public prompt in a fresh
  supported local agent.
- [ ] Payer MCP guides Requestor with exact `HANDSHAKE_REQUIRED`.
- [ ] All shared/operator processes run in AWS.
- [ ] No demo-time process or file on Kailor's Mac is required.
- [ ] The old EC2/Mac path is demonstrably outside the accepted run.
- [ ] Restart and funding replay behavior fail closed.
- [ ] The accepted run contains exactly `PROPOSED`, `ACCEPTED`,
  `ACKNOWLEDGED`, in order and with exact role authority.
- [ ] A fresh isolated verifier alone emits the authorization literal.
- [ ] Public/operator surfaces display `VERIFIED` and `paymentMoved:false`.
- [ ] Monitor freshness and immutable history remain public with the Mac
  stopped.
- [ ] No secret or private evidence is present in Git, S3, CloudWatch, console
  output, or the site.
- [ ] Both public prompts bind the final immutable SHA and signed AWS discovery
  URLs.
- [ ] Independent integrated review is clear.
- [ ] One final fresh `npm run verify` and all infrastructure/site gates pass.
