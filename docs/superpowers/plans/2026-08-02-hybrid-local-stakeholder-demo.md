# Hybrid Local Stakeholder Demo Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Deliver a one-command local Payer/operator runtime that a remote stakeholder Requestor can reach through a thin public edge, while preserving real Payer MCP guidance, exactly three Clockchain anchors, fresh-verifier-only authorization, public receipts, verified receipt email, and `paymentMoved:false`.

**Architecture:** Keep role and verifier authority on the Mac Studio and compose the repository's existing relay, coordinator, console, bootstrap broker, Payer supervisor, funding runner, and verifier. Use a restricted outbound reverse-SSH process only as an opaque raw-TCP edge, then publish signed Requestor discovery and sanitized monitor/history artifacts after pinned-TLS readiness checks. The stakeholder receives one Requestor prompt and never receives private launch material.

**Tech Stack:** Node.js 22 ES modules, `node:test`, existing Clockchain coordination and local-MCP modules, OpenSSH reverse forwarding, Sepolia through `viem`, AWS CLI S3 publication, React/Vite/Vitest in `clockchain-research`, Hermes `handshake_requester` acceptance profile.

---

## Delivery boundaries

The implementation is complete only when the live path proves:

- real Payer MCP returns exact `HANDSHAKE_REQUIRED` guidance from the signed mandate;
- Payer owns `PROPOSED` and `ACKNOWLEDGED`, Requestor owns `ACCEPTED`;
- Clockchain contains exactly three independently re-verifiable anchors in that order;
- a newly launched aggregate verifier is the only process that writes `AUTHORIZED`;
- every artifact and public projection carries `paymentMoved:false`;
- one journaled funding batch sends exactly `0.01 Sepolia ETH` to each of four fresh addresses;
- public monitor, immutable run history, receipt cards, and opted-in receipt email all reflect the verified run; and
- malformed, stale, duplicated, reordered, mismatched, replayed, or incomplete evidence fails closed.

The uncommitted changes in `infra/aws/docker/tunnel.Dockerfile` and `infra/aws/test/container-contract.test.mjs` are deferred AWS hardening. Preserve them, do not stage them in hybrid-demo commits, and do not make the hybrid launcher depend on them.

## File map

### Handshake repository

- Create `src/bilateral/local-demo/operator-config.mjs`: exact-schema, permission-safe reader for path-only operator configuration.
- Create `src/bilateral/local-demo/public-edge.mjs`: restricted reverse-forward argument construction and pinned-TLS readiness probes.
- Create `src/bilateral/local-demo/operator-runtime.mjs`: child lifecycle, business status reporting, funding gate, bootstrap approval, cleanup, and terminal publication coordination.
- Create `bin/handshake-local-operator.mjs`: minimal CLI entry point for the local operator runtime.
- Modify `scripts/publish-public-monitor.mjs`: write immutable terminal summary and index objects in addition to `latest.json`.
- Modify `scripts/publish-requestor-discovery.mjs`: admit the explicit `hybrid-local` run mode without relaxing signature, expiry, release, or certificate binding.
- Modify `package.json`: add `bilateral:local-operator`.
- Create `test/bilateral-local-operator-config.test.mjs`: exact config, permissions, and redaction tests.
- Create `test/bilateral-local-public-edge.test.mjs`: SSH restriction and pinned-TLS probe tests.
- Create `test/bilateral-local-operator-runtime.test.mjs`: child order, readiness, funding, verifier, cleanup, and output-authority tests.
- Modify `test/bilateral-public-monitor.test.mjs`: immutable terminal history publication tests.
- Modify `test/bilateral-request-payment-cli.test.mjs`: `hybrid-local` signed discovery acceptance and mismatch rejection.
- Create `test/bilateral-local-operator-process-e2e.test.mjs`: deterministic isolated multiprocess happy path and bounded negative cases.
- Create `docs/runbooks/hybrid-local-stakeholder-demo.md`: exact operator and stakeholder procedure.
- Modify `scripts/check-docs.mjs` and `test/docs.test.mjs`: enforce the new runbook and prevent reintroduction of stakeholder private material.

### Public-site worktree

- Modify `/Users/Kailor/.config/superpowers/worktrees/clockchain-research/aws-stakeholder-run/src/data/bilateral-handshake-demo.ts`: make the live path Requestor-only and expose the hybrid readiness/public receipt endpoints.
- Modify `/Users/Kailor/.config/superpowers/worktrees/clockchain-research/aws-stakeholder-run/src/components/BilateralHandshakeRunbook.tsx`: render one ordered Requestor action, live readiness, monitor, history, receipt cards, and email action.
- Modify `/Users/Kailor/.config/superpowers/worktrees/clockchain-research/aws-stakeholder-run/src/lib/bilateral-handshake-runbook.test.tsx`: assert ordering, copy behavior, business language, and removal of the stakeholder Payer prompt.

### Live acceptance artifacts

- Write private operator state below a fresh mode-`0700` path outside Git.
- Use the existing public S3 keys `latest.json`, `runs/index.json`, and `runs/{runId}.json`.
- Use the existing receipt-email endpoint only after an immutable `VERIFIED` summary exists.
- Keep the browser-harness recording at `/Users/Kailor/.config/browser-harness/agent-workspace/recordings/stakeholder-handshake-acceptance` until acceptance finishes.

---

### Task 1: Lock the path-only operator configuration

**Files:**
- Create: `test/bilateral-local-operator-config.test.mjs`
- Create: `src/bilateral/local-demo/operator-config.mjs`

- [ ] **Step 1: Write the failing exact-schema tests**

Create fixtures with a mode-`0600` config file and mode-`0600` referenced private files. Assert that the reader returns this exact public shape and does not read secret contents:

```js
assert.deepEqual(config, {
  console: { host: "127.0.0.1", port: 8787 },
  funding: {
    journalDirectory: join(root, "funding-journal"),
    keystoreFile: join(root, "treasury.json"),
    mode: "fund-on-ready",
  },
  operator: {
    clockchainTokenFile: join(root, "clockchain-token"),
    keyId: "operator-yang",
    privateKeyFile: join(root, "operator-private.pem"),
    rpcUrlFile: join(root, "sepolia-rpc"),
  },
  payerMcp: {
    host: "127.0.0.1",
    port: 9443,
    publicUrl: "https://32.186.198.119:9443/mcp",
    tlsCertificateFile: join(root, "payer-mcp.crt"),
    tlsPrivateKeyFile: join(root, "payer-mcp.key"),
  },
  paymentMoved: false,
  publicEdge: {
    coordinationPublicUrl: "https://32.186.198.119:8443",
    host: "32.186.198.119",
    hostKeyFile: join(root, "edge-known-hosts"),
    identityFile: join(root, "edge-identity"),
    payerMcpRemotePort: 9443,
    port: 22,
    relayRemotePort: 8443,
    user: "clockchain-tunnel",
  },
  publishing: {
    bucket: "clockchain-handshake-monitor-570035913370-us-west-2",
    receiptEmailUrl: "https://anhgkkcm46.execute-api.us-west-2.amazonaws.com/v1/receipt-email",
    region: "us-west-2",
    requestorDiscoveryUrl: "https://clockchain-handshake-monitor-570035913370-us-west-2.s3.us-west-2.amazonaws.com/requestor-discovery.json",
  },
  relay: {
    advertisedHost: "32.186.198.119",
    host: "127.0.0.1",
    port: 8443,
    tlsCertificateFile: join(root, "relay.crt"),
    tlsFingerprint: "a".repeat(64),
    tlsPrivateKeyFile: join(root, "relay.key"),
  },
  repositorySha: "b".repeat(40),
  schema: "clockchain.hybrid-local-operator-config/v1",
});
```

Also assert fixed failure for: extra or missing keys, `paymentMoved:true`, relative paths, an existing launcher state root, config mode other than `0600`, symlinks, wrong owner, duplicate JSON keys, embedded `0x` private-key material, embedded bearer tokens, non-loopback local listeners, mismatched public ports, and unsupported funding mode.

- [ ] **Step 2: Run the config test and observe the expected failure**

Run: `node --test test/bilateral-local-operator-config.test.mjs`

Expected: FAIL with `ERR_MODULE_NOT_FOUND` for `src/bilateral/local-demo/operator-config.mjs`.

- [ ] **Step 3: Implement the bounded reader**

Export this interface:

```js
export const HYBRID_OPERATOR_CONFIG_SCHEMA =
  "clockchain.hybrid-local-operator-config/v1";

export class HybridOperatorConfigError extends Error {
  constructor() {
    super("Hybrid local operator configuration failed safely.");
    this.name = "HybridOperatorConfigError";
    this.code = "HYBRID_OPERATOR_CONFIG_INVALID";
    this.category = "configuration";
  }
}

type ReadHybridOperatorConfig = (
  configPath: string,
  stateRoot: string,
  dependencies?: HybridOperatorConfigDependencies,
) => Promise<HybridOperatorConfig>;
```

Use `lstat -> open(O_RDONLY|O_NOFOLLOW) -> fstat -> read -> lstat` and require the same device/inode/mode/owner/size/mtime before and after. Validate only metadata for referenced private files; return their absolute paths without reading their bytes. Require the supplied state root to be absolute, absent, outside the repository, and not `/`, the user home directory, or the config directory itself.

- [ ] **Step 4: Run the focused config tests**

Run: `node --test test/bilateral-local-operator-config.test.mjs`

Expected: PASS; all malformed and secret-bearing fixtures produce only `HYBRID_OPERATOR_CONFIG_INVALID`.

- [ ] **Step 5: Commit the config boundary**

```bash
git add src/bilateral/local-demo/operator-config.mjs test/bilateral-local-operator-config.test.mjs
git commit -m "Keep hybrid demo authority in path-only local configuration

Constraint: Private material must remain in owner-private files outside Git.
Rejected: Embedded secret values in JSON | They are easy to print, upload, or commit.
Confidence: high
Scope-risk: narrow
Tested: node --test test/bilateral-local-operator-config.test.mjs
Not-tested: Live operator startup"
```

### Task 2: Prove the thin public edge without granting it authority

**Files:**
- Create: `test/bilateral-local-public-edge.test.mjs`
- Create: `src/bilateral/local-demo/public-edge.mjs`

- [ ] **Step 1: Write failing reverse-forward and probe tests**

Assert `buildPublicEdgeArguments(config)` returns only this restricted form:

```js
[
  "-N", "-T",
  "-o", "BatchMode=yes",
  "-o", "ExitOnForwardFailure=yes",
  "-o", "ForwardAgent=no",
  "-o", "ClearAllForwardings=yes",
  "-o", `UserKnownHostsFile=${config.hostKeyFile}`,
  "-o", "StrictHostKeyChecking=yes",
  "-o", "ServerAliveInterval=15",
  "-o", "ServerAliveCountMax=2",
  "-i", config.identityFile,
  "-p", String(config.port),
  "-R", `${config.relayRemotePort}:127.0.0.1:8443`,
  "-R", `${config.payerMcpRemotePort}:127.0.0.1:9443`,
  `${config.user}@${config.host}`,
]
```

Assert rejection of arbitrary local destinations, extra remote ports, interactive commands, agent forwarding, wildcard command fragments, and a remote port that differs from either public URL. For `probePinnedTlsEndpoint`, use a local TLS fixture and assert exact SHA-256 certificate pin matching, timeout, connection refusal, and wrong-certificate failure.

- [ ] **Step 2: Run the edge test and observe the expected failure**

Run: `node --test test/bilateral-local-public-edge.test.mjs`

Expected: FAIL with `ERR_MODULE_NOT_FOUND` for `src/bilateral/local-demo/public-edge.mjs`.

- [ ] **Step 3: Implement argument construction and pinned-TLS health**

Export:

```js
type BuildPublicEdgeArguments = (
  publicEdge: PublicEdgeConfig,
  localPorts: { relay: number; payerMcp: number },
) => readonly string[];

type ProbePinnedTlsEndpoint = (
  input: {
    expectedFingerprint: string;
    host: string;
    path: string;
    port: number;
    timeoutMs?: number;
  },
  dependencies?: PublicEdgeProbeDependencies,
) => Promise<{ paymentMoved: false; ready: true }>;

type WaitForPublicEdge = (
  input: {
    coordination: PinnedTlsProbeInput;
    payerMcp: PinnedTlsProbeInput;
    deadlineMs?: number;
  },
  dependencies?: PublicEdgeProbeDependencies,
) => Promise<{
  coordinationReady: true;
  payerMcpReady: true;
  paymentMoved: false;
}>;
```

The coordination probe requests the relay readiness endpoint; the Payer probe requests only a bounded TLS endpoint that cannot create a payment request. Do not accept raw TCP connect as readiness. Return `{ coordinationReady:true, payerMcpReady:true, paymentMoved:false }` only when both pins and protocol responses match.

- [ ] **Step 4: Run the focused edge tests**

Run: `node --test test/bilateral-local-public-edge.test.mjs`

Expected: PASS, including wrong certificate, half-ready edge, deadline, and child-exit cases.

- [ ] **Step 5: Commit the edge proof**

```bash
git add src/bilateral/local-demo/public-edge.mjs test/bilateral-local-public-edge.test.mjs
git commit -m "Treat the public edge as transport instead of authority

Constraint: Remote stakeholders need stable raw-TCP reachability to local TLS services.
Rejected: TLS termination or role state on the edge | Either would expand the demo trust boundary.
Confidence: high
Scope-risk: narrow
Tested: node --test test/bilateral-local-public-edge.test.mjs
Not-tested: Live reverse SSH connection"
```

### Task 3: Add the one-command local operator runtime

**Files:**
- Create: `test/bilateral-local-operator-runtime.test.mjs`
- Create: `src/bilateral/local-demo/operator-runtime.mjs`
- Create: `bin/handshake-local-operator.mjs`
- Modify: `package.json`

- [ ] **Step 1: Write failing lifecycle and authority tests**

Inject fake process handles and record every start, status line, and stop. Require this order:

```js
assert.deepEqual(events, [
  "STATE_ROOT_CREATED",
  "RELAY_LISTENING",
  "COORDINATOR_RELEASE_CREATED",
  "CONSOLE_LISTENING",
  "BOOTSTRAP_BROKER_LISTENING",
  "PUBLIC_EDGE_STARTED",
  "PAYER_SUPERVISOR_STARTED",
  "PAYER_MCP_READY",
  "PUBLIC_EDGE_READY",
  "REQUESTOR_DISCOVERY_PUBLISHED",
  "REQUESTOR_HANDOFF_READY",
]);
```

Assert the launcher prints structured business status lines with `paymentMoved:false`, never prints private paths or configured canaries, and never prints the string `AUTHORIZED`. Assert that a failed child, changed public certificate, stale discovery, or lost edge causes reverse-order cleanup and a single fixed terminal status.

- [ ] **Step 2: Run the runtime test and observe the expected failure**

Run: `node --test test/bilateral-local-operator-runtime.test.mjs`

Expected: FAIL with `ERR_MODULE_NOT_FOUND` for `src/bilateral/local-demo/operator-runtime.mjs`.

- [ ] **Step 3: Implement the runtime state machine**

Export the following public surface:

```js
export const HYBRID_OPERATOR_STATUS_SCHEMA =
  "clockchain.hybrid-local-operator-status/v1";

type RunHybridLocalOperator = (
  input: {
    config: HybridOperatorConfig;
    stateRoot: string;
  },
  dependencies?: HybridOperatorDependencies,
) => Promise<{
  paymentMoved: false;
  status: "VERIFICATION_PASSED";
}>;
```

Use existing implementation boundaries instead of reproducing protocol logic:

- `readCoordinatorRuntimeConfig`, `loadOrCreateCoordinatorRelease`, and `runCoordinatorUntilComplete` from `src/bilateral/coordination/coordinator-runtime.mjs`;
- `createBootstrapBroker` and `approveBootstrapClaim` from `src/bilateral/local-mcp/bootstrap-broker.mjs`;
- `createConsoleServer` and `createStateRootProjection` from `src/bilateral/coordination/console-server.mjs`;
- `main` from `bin/handshake-supervisor.mjs` through a fresh child process for the Payer;
- `createSignedRequestorDiscovery` and `publishRequestorDiscovery` from `scripts/publish-requestor-discovery.mjs`; and
- `buildPublicEdgeArguments` and `waitForPublicEdge` from Task 2.

Generate child state beneath the fresh root with mode `0700`; private files are mode `0600`. Obtain Payer and Requestor manifests from the coordinator release. Start the Payer supervisor with the real Payer manifest and local MCP certificate/key. Publish signed Requestor discovery only after the Payer emits exact `PAYER_MCP_READY` and both public probes pass. Automatically approve exactly one bootstrap claim whose repository SHA, release ID, session ID, certificate fingerprint, and intake request ID match the active release.

- [ ] **Step 4: Implement the minimal CLI**

`bin/handshake-local-operator.mjs` must accept only the ordered flags below and return a fixed safe failure:

```js
export async function main(
  argv = process.argv.slice(2),
  dependencies = {},
) {
  const { configPath, stateRoot } = parseArguments(argv);
  const config = await readHybridOperatorConfig(
    configPath,
    stateRoot,
    dependencies,
  );
  await runHybridLocalOperator({ config, stateRoot }, dependencies);
  return 0;
}
```

Add to `package.json`:

```json
"bilateral:local-operator": "node bin/handshake-local-operator.mjs"
```

The supported invocation is exactly:

```sh
npm run bilateral:local-operator -- \
  --config .context/hybrid-demo/operator.json \
  --state /absolute/private/new-state-root
```

- [ ] **Step 5: Run the focused runtime tests**

Run: `node --test test/bilateral-local-operator-config.test.mjs test/bilateral-local-public-edge.test.mjs test/bilateral-local-operator-runtime.test.mjs`

Expected: PASS; no captured output contains `AUTHORIZED` or any secret canary.

- [ ] **Step 6: Commit the one-command runtime**

```bash
git add package.json bin/handshake-local-operator.mjs src/bilateral/local-demo/operator-runtime.mjs test/bilateral-local-operator-runtime.test.mjs
git commit -m "Make the stakeholder proof a one-command local operation

Constraint: Existing protocol, role, funding, and verifier code remains authoritative.
Rejected: Another hosted orchestrator | Hosted orchestration caused most recent demo failures.
Confidence: medium
Scope-risk: moderate
Tested: focused local operator config, edge, and runtime tests
Not-tested: Real public edge and Sepolia funding"
```

### Task 4: Gate funding and the fresh verifier inside the attached runtime

**Files:**
- Modify: `src/bilateral/local-demo/operator-runtime.mjs`
- Modify: `test/bilateral-local-operator-runtime.test.mjs`

- [ ] **Step 1: Add failing funding replay-safety tests**

Feed the runtime a signed funding record and assert it invokes `scripts/fund-bilateral-addresses.mjs` exactly once with these path arguments:

```js
[
  "--funding-record", fundingRecordPath,
  "--journal-directory", config.funding.journalDirectory,
  "--keystore", config.funding.keystoreFile,
  "--rpc-url-file", config.operator.rpcUrlFile,
]
```

Require exactly four distinct addresses and an amount of `10000000000000000` wei per address. Assert no invocation for an existing submitted journal, an ambiguous journal, a changed funding record, insufficient treasury balance, reused participant address, extra address, wrong amount, or a second readiness event.

- [ ] **Step 2: Add failing verifier-authority tests**

Drive the fake coordinator through `PROPOSED`, `ACCEPTED`, and `ACKNOWLEDGED`. Assert the runtime launches one new verifier child only after all three authenticated role events exist and passes the exact evidence paths produced by the coordinator. Assert only captured verifier stdout may contain this record:

```json
{"outcome":"AUTHORIZED","paymentMoved":false,"schema":"clockchain.bilateral-authorization-verdict/v2"}
```

Assert the operator status stream reports `VERIFICATION_PASSED` and never repeats the authorization literal. Duplicate, reordered, expired, mismatched-role, wrong-session, fourth-anchor, and missing-marker inputs must stop before publication.

- [ ] **Step 3: Run the tests and observe the new failures**

Run: `node --test test/bilateral-local-operator-runtime.test.mjs`

Expected: FAIL at the funding and verifier expectations while startup tests remain green.

- [ ] **Step 4: Wire the existing funding and verifier boundaries**

Use the existing `bilateral:fund` subprocess and its journal; do not duplicate nonce, recovery, or transfer logic. Let `runCoordinatorUntilComplete` launch `scripts/verify-bilateral-results.mjs` as a fresh child using its existing pinned verifier path. The operator runtime may translate verified state into business language, but it must treat the coordinator's marker-complete verifier publication as the only terminal authority.

Emit only these terminal operator statuses:

```js
const TERMINAL_OPERATOR_STATUS = Object.freeze({
  failure: "RUN_STOPPED_SAFELY",
  success: "VERIFICATION_PASSED",
});
```

- [ ] **Step 5: Run the focused runtime tests**

Run: `node --test test/bilateral-local-operator-runtime.test.mjs test/bilateral-funding*.test.mjs test/bilateral-verdict*.test.mjs`

Expected: PASS; funding invocation count is one, anchor count is three, and authorization output comes only from the fresh verifier fixture.

- [ ] **Step 6: Commit funding and verifier gating**

```bash
git add src/bilateral/local-demo/operator-runtime.mjs test/bilateral-local-operator-runtime.test.mjs
git commit -m "Keep funding replay safety and authorization authority intact

Constraint: Demo simplification may remove hosting layers but not proof invariants.
Rejected: Launcher-authored success | Only fresh aggregate verification can authorize.
Confidence: high
Scope-risk: moderate
Tested: focused runtime, funding, and verdict tests
Not-tested: Live Sepolia transfer batch"
```

### Task 5: Publish immutable local-run receipts and enable verified email

**Files:**
- Modify: `scripts/publish-public-monitor.mjs`
- Modify: `test/bilateral-public-monitor.test.mjs`

- [ ] **Step 1: Write failing terminal-history publication tests**

Inject object-storage dependencies and drive `publishOnce` with a terminal `VERIFIED` projection. Assert writes occur in this order:

```js
assert.deepEqual(puts.map(({ key }) => key), [
  "latest.json",
  `runs/${snapshot.runId}.json`,
  "runs/index.json",
]);
```

Parse each body with `observePublicMonitorSnapshot` or `observeImmutableRunSummary`. Require exactly three anchors, three explorer URLs, `VERIFIED`, verifier status `VERIFIED`, and `paymentMoved:false`. Assert an unavailable, nonterminal, stale, wrong-cardinality, or unvalidated-verifier snapshot updates only `latest.json` and cannot create history.

- [ ] **Step 2: Run the test and observe the expected failure**

Run: `node --test test/bilateral-public-monitor.test.mjs`

Expected: FAIL because the local publisher currently writes only `latest.json`.

- [ ] **Step 3: Reuse the immutable history validators**

Import and call:

```js
import {
  appendPublicRunIndex,
  createImmutableRunSummary,
} from "../src/bilateral/aws/public-history.mjs";
```

Extend `publishOnce` dependencies with `readRunIndex`, `putObject`, and `publicObjectUrl`. Use conditional creation for `runs/{runId}.json`; if the key already exists, read and require byte-identical content. Update `runs/index.json` only after the summary write succeeds. Never overwrite an immutable summary with different bytes.

- [ ] **Step 4: Prove compatibility with verified HTML receipt email**

In the test, pass the new summary to `renderVerifiedReceiptEmail` from `src/bilateral/aws/receipt-email.mjs` and assert the HTML contains the three signer/kind cards, the run ID, three independent proof links, and “No represented payment moved.” Assert failed and expired summaries are rejected.

- [ ] **Step 5: Run focused publication and email tests**

Run: `node --test test/bilateral-public-monitor.test.mjs test/aws-public-history.test.mjs test/aws-receipt-email.test.mjs infra/aws/test/receipt-email-handler.test.mjs`

Expected: PASS with no AWS control-plane process required.

- [ ] **Step 6: Commit receipt publication**

```bash
git add scripts/publish-public-monitor.mjs test/bilateral-public-monitor.test.mjs
git commit -m "Preserve verified local runs as public receipts

Constraint: Receipt email must read immutable independently validated history.
Rejected: Emailing live monitor state | Live state is advisory and mutable.
Confidence: high
Scope-risk: narrow
Tested: public monitor, public history, receipt email, and email handler tests
Not-tested: Live S3 and SES delivery"
```

### Task 6: Make signed Requestor discovery explicitly hybrid-local

**Files:**
- Modify: `scripts/publish-requestor-discovery.mjs`
- Modify: `test/bilateral-request-payment-cli.test.mjs`
- Modify: `src/bilateral/local-demo/operator-runtime.mjs`

- [ ] **Step 1: Write failing hybrid discovery tests**

Create a signed discovery with `runMode:"hybrid-local"` and assert the one-shot Requestor wrapper accepts it only when all of these match: repository SHA, release ID, session ID, public Payer MCP URL, certificate URL, certificate fingerprint, operator key ID, signature, and expiry. Assert `aws-stakeholder-only`, `local-two-run`, and `hybrid-local` cannot be silently substituted after signing.

- [ ] **Step 2: Run the focused Requestor tests and observe failure**

Run: `node --test test/bilateral-request-payment-cli.test.mjs`

Expected: FAIL because `hybrid-local` is not in the signed discovery run-mode set.

- [ ] **Step 3: Add the explicit run mode and publish it from the launcher**

Change only the closed set:

```js
const RUN_MODES = Object.freeze(new Set([
  "aws-stakeholder-only",
  "hybrid-local",
  "local-two-run",
]));
```

The launcher must sign `hybrid-local` only after Payer MCP and public-edge readiness. The Requestor wrapper remains responsible for calling Payer MCP, requiring exact `HANDSHAKE_REQUIRED`, validating mandate guidance, and starting the Requestor supervisor. Do not add a human copy/paste step for launch material.

- [ ] **Step 4: Run discovery, MCP, and Requestor tests**

Run: `node --test test/bilateral-request-payment-cli.test.mjs test/bilateral-local-mcp-client.test.mjs test/bilateral-local-mcp-payment-intake.test.mjs`

Expected: PASS; mismatched signature, certificate, session, release, and role inputs fail closed.

- [ ] **Step 5: Commit hybrid discovery**

```bash
git add scripts/publish-requestor-discovery.mjs src/bilateral/local-demo/operator-runtime.mjs test/bilateral-request-payment-cli.test.mjs
git commit -m "Name the local-authoritative Requestor discovery mode

Constraint: Stakeholder agents must receive one signed public entry point.
Rejected: Manual manifest or certificate attachment | It exposes private workflow detail and creates operator errors.
Confidence: high
Scope-risk: narrow
Tested: Requestor CLI and local MCP intake/client tests
Not-tested: Remote stakeholder network"
```

### Task 7: Prove the hybrid path in an isolated multiprocess test

**Files:**
- Create: `test/bilateral-local-operator-process-e2e.test.mjs`
- Modify: `test/bilateral-coordination-process-e2e.test.mjs` only if a reusable fixture must be exported without changing its existing cases

- [ ] **Step 1: Write the deterministic happy-path process test**

Use a fresh temporary Git clone, four isolated state roots, local TLS listeners, mock Clockchain transport, and the real CLI entry points. Start the local operator, then invoke the real `bilateral:request-payment` wrapper using only the published signed discovery URL and a new Requestor state root.

Assert this exact observable sequence:

```js
assert.deepEqual(milestones, [
  "PAYER_MCP_READY",
  "HANDSHAKE_REQUIRED",
  "REQUESTOR_SUPERVISOR_START",
  "PROPOSED",
  "ACCEPTED",
  "ACKNOWLEDGED",
  "VERIFICATION_PASSED",
]);
assert.equal(anchors.length, 3);
assert.deepEqual(anchors.map(({ kind }) => kind), [
  "PROPOSED", "ACCEPTED", "ACKNOWLEDGED",
]);
assert.equal(verdict.outcome, "AUTHORIZED");
assert.equal(verdict.paymentMoved, false);
```

Also assert every serialized status, result, receipt, summary, and email model contains `paymentMoved:false`; the operator output does not contain `AUTHORIZED`; and public history remains readable after all local children stop.

- [ ] **Step 2: Run the process test and observe the first missing integration**

Run: `node --test test/bilateral-local-operator-process-e2e.test.mjs`

Expected: FAIL at the first unimplemented launcher-to-existing-process boundary, with all earlier unit tasks green.

- [ ] **Step 3: Fix only the observed integration boundary**

Adjust `operator-runtime.mjs` or its dependency adapter so the production call matches the already-tested existing CLI/module contract. Do not alter protocol validators, role ownership, receipt cardinality, funding journal behavior, or verifier authorization rules to make the process test pass.

- [ ] **Step 4: Add the bounded negative matrix**

Run separate fresh fixtures for:

- wrong public TLS certificate fingerprint;
- Requestor discovery signed for another session;
- duplicate bootstrap claim;
- changed funding record after journal creation;
- duplicate `ACCEPTED` event;
- `ACKNOWLEDGED` before `ACCEPTED`;
- expired mandate or payment request;
- fourth anchor; and
- verifier child exit before marker completion.

Each fixture must end with `paymentMoved:false`, no public `VERIFIED` summary, and no authorization output from the launcher.

- [ ] **Step 5: Run focused process verification**

Run: `node --test test/bilateral-local-operator-process-e2e.test.mjs test/bilateral-coordination-process-e2e.test.mjs`

Expected: PASS for the happy path and all bounded negative fixtures.

- [ ] **Step 6: Commit the integrated local proof**

```bash
git add test/bilateral-local-operator-process-e2e.test.mjs src/bilateral/local-demo/operator-runtime.mjs
git commit -m "Prove the stakeholder flow without the hosted control plane

Constraint: The demo must exercise fresh independent agents and real protocol ownership.
Rejected: Historical replay or mocked receipt success | Neither proves a live stakeholder handshake.
Confidence: high
Scope-risk: moderate
Tested: isolated hybrid process happy path and bounded negative matrix
Not-tested: Public internet, live Clockchain, or Sepolia"
```

### Task 8: Publish the operator runbook and Requestor-only stakeholder page

**Files:**
- Create: `docs/runbooks/hybrid-local-stakeholder-demo.md`
- Modify: `scripts/check-docs.mjs`
- Modify: `test/docs.test.mjs`
- Modify: `/Users/Kailor/.config/superpowers/worktrees/clockchain-research/aws-stakeholder-run/src/data/bilateral-handshake-demo.ts`
- Modify: `/Users/Kailor/.config/superpowers/worktrees/clockchain-research/aws-stakeholder-run/src/components/BilateralHandshakeRunbook.tsx`
- Modify: `/Users/Kailor/.config/superpowers/worktrees/clockchain-research/aws-stakeholder-run/src/lib/bilateral-handshake-runbook.test.tsx`

- [ ] **Step 1: Write failing repository documentation gates**

Require the runbook to contain the exact one-command operator invocation, the one-shot Requestor invocation, the ordered sequence, `paymentMoved:false`, exactly-three-anchor rule, verifier-only authorization rule, replay-safe funding rule, monitor/history/email checks, failure stop conditions, and no private values. Reject instructions that ask the stakeholder to attach a certificate, manifest, token, invitation, capability, private path, AWS credential, or live evidence.

- [ ] **Step 2: Write failing public-page component tests**

Assert the primary procedure has one copied prompt labeled `Requestor`, no stakeholder Payer prompt, and this visible order:

```js
[
  "Yang starts the Payer and operator",
  "Wait for PAYER_MCP_READY",
  "Stakeholder copies the Requestor prompt",
  "Watch PROPOSED → ACCEPTED → ACKNOWLEDGED",
  "Open the verified receipts",
]
```

Assert the page explains in business language that the Payer publishes terms, the Requestor conforms to those terms, Clockchain anchors the three decisions, and the fresh verifier authorizes without moving payment. Assert the AWS stakeholder-Payer path is labeled deferred hardening and is not presented as the current live procedure.

- [ ] **Step 3: Run the docs and component tests and observe failure**

Run:

```bash
node --test test/docs.test.mjs
npm --prefix /Users/Kailor/.config/superpowers/worktrees/clockchain-research/aws-stakeholder-run test -- --run src/lib/bilateral-handshake-runbook.test.tsx
```

Expected: FAIL because the hybrid runbook does not exist and the page still exposes the prior multi-role flow.

- [ ] **Step 4: Write the exact operator runbook**

The top section must begin with the command and the five operator-visible gates. Follow with the single stakeholder prompt. Put operational caveats, testnet limitations, single-validator limitation, email opt-in, and deferred AWS architecture at the bottom. State that installed Codex, Claude Code, or Hermes on macOS, Windows, or Linux is required; browser-only agents are not supported for the live role.

- [ ] **Step 5: Replace the public page's primary flow**

Keep the existing live monitor, historical run list/detail rendering, receipt cards, and email form. Replace the side-by-side role prompts with one prominent Requestor prompt and a numbered readiness sequence. Use the live `latest.json` status to show `PAYER_MCP_READY`; use immutable `runs/index.json` and `runs/{runId}.json` as the source of terminal receipt cards.

- [ ] **Step 6: Run focused docs, UI, and production build checks**

Run:

```bash
node --test test/docs.test.mjs
node scripts/check-docs.mjs
npm --prefix /Users/Kailor/.config/superpowers/worktrees/clockchain-research/aws-stakeholder-run test -- --run src/lib/bilateral-handshake-runbook.test.tsx
npm --prefix /Users/Kailor/.config/superpowers/worktrees/clockchain-research/aws-stakeholder-run run build
```

Expected: PASS; the build renders `/handshake/run` with one Requestor action and no stakeholder Payer setup.

- [ ] **Step 7: Commit each repository independently**

Handshake repository:

```bash
git add docs/runbooks/hybrid-local-stakeholder-demo.md scripts/check-docs.mjs test/docs.test.mjs
git commit -m "Make the live stakeholder handoff Requestor-only

Constraint: Yang and Codex operate the local Payer for this demo.
Rejected: Two stakeholder role setup | It adds manual failure points without strengthening the proof.
Confidence: high
Scope-risk: narrow
Tested: docs tests and docs checker
Not-tested: Public site deployment"
```

Research-site worktree:

```bash
git -C /Users/Kailor/.config/superpowers/worktrees/clockchain-research/aws-stakeholder-run add src/data/bilateral-handshake-demo.ts src/components/BilateralHandshakeRunbook.tsx src/lib/bilateral-handshake-runbook.test.tsx
git -C /Users/Kailor/.config/superpowers/worktrees/clockchain-research/aws-stakeholder-run commit -m "Present the stakeholder handshake as one Requestor action

Constraint: The live Payer and operator are run by Yang and Codex.
Rejected: Side-by-side role prompts | They imply unsafe concurrent startup.
Confidence: high
Scope-risk: narrow
Tested: focused runbook component test and production build
Not-tested: Live production data"
```

### Task 9: Run the live Hermes stakeholder acceptance cycle

**Files:**
- Do not write live private evidence into either repository
- Preserve browser recording: `/Users/Kailor/.config/browser-harness/agent-workspace/recordings/stakeholder-handshake-acceptance`

- [ ] **Step 1: Establish a clean reviewed release**

Run:

```bash
git status --short
git rev-parse HEAD
node --version
npm ci --ignore-scripts
```

Expected: only the two explicitly parked AWS tunnel files may remain modified; the release commit is pushed to the public repository; Node reports `v22.x`; install succeeds. Create a clean detached clone of the pushed release for the live operator so the funding code's clean-repository gate remains true.

- [ ] **Step 2: Start the local authority with one command**

Run from the clean detached clone:

```bash
npm run bilateral:local-operator -- \
  --config .context/hybrid-demo/operator.json \
  --state /absolute/private/new-state-root
```

Expected public milestones: `RELAY_LISTENING`, `PAYER_MCP_READY`, `PUBLIC_EDGE_READY`, `REQUESTOR_DISCOVERY_PUBLISHED`, and `REQUESTOR_HANDOFF_READY`, all with `paymentMoved:false`. No output contains private paths or the authorization literal.

- [ ] **Step 3: Verify public readiness independently**

Use browser-harness to fetch the production `/handshake/run` page, signed discovery URL, and live `latest.json`. Confirm the page displays `PAYER_MCP_READY`, the reviewed release SHA, the one Requestor prompt, and no private material. Confirm a pinned TLS request reaches the public Payer MCP listener.

- [ ] **Step 4: Run the fresh Hermes Requestor**

Open the installed Hermes profile `handshake_requester`, paste only the production page's Requestor prompt, and observe it clone a blank folder, detach at the reviewed SHA, install with Node 22, create a fresh private state root, and invoke `bilateral:request-payment` once.

Expected Requestor milestones: `HANDSHAKE_REQUIRED`, `REQUESTOR_SUPERVISOR_START`, and `ACCEPTED`. No additional prompt, certificate attachment, manifest, token, invitation, capability, AWS credential, or private path is supplied.

- [ ] **Step 5: Observe funding and the three anchors**

Keep the operator attached. Confirm the funding journal records one batch for exactly four fresh addresses at `0.01 Sepolia ETH` each. Independently check the transaction status before accepting funding completion. Then confirm `PROPOSED`, `ACCEPTED`, and `ACKNOWLEDGED` each appear once and in order.

- [ ] **Step 6: Observe fresh authorization and public receipts**

Confirm a newly launched verifier process produces the sole `AUTHORIZED` verdict. Confirm `latest.json` becomes `VERIFIED`, `runs/{runId}.json` has exactly three receipt cards/explorer URLs, and `runs/index.json` includes the new run. Stop local processes and confirm the immutable run still renders on the public page.

- [ ] **Step 7: Send and observe opted-in verified email**

Submit the verified run ID separately for `yt@d4d.group` and `thetangstr@gmail.com` through the public form. Expected API status: `RECEIPT_EMAIL_ACCEPTED`. Independently confirm both mailboxes receive HTML containing the same run ID, three receipt cards, three explorer links, and the no-payment-moved statement.

- [ ] **Step 8: Run five live fail-closed checks without another funding batch**

Against fresh private state, exercise wrong certificate fingerprint, expired discovery, duplicate intake request ID, mismatched release SHA, and replayed funding record. Expected: fixed safe failure, no fourth anchor, no new verified history entry, no email eligibility, and no second funding submission.

- [ ] **Step 9: Record the acceptance evidence**

Record only public/sanitized identifiers: reviewed SHA, run ID, funding transaction hash, three anchor ledger IDs, three blocks, three explorer URLs, verifier publication digest, public summary URL, public index URL, email acceptance statuses, and browser recording path. Do not copy private role state or live evidence into Git.

### Task 10: Perform integrated review and the single final broad gate

**Files:**
- Review all hybrid-demo commits in both repositories

- [ ] **Step 1: Review the integrated diff against the approved design**

Run:

```bash
git diff --check origin/main...HEAD
git diff --stat origin/main...HEAD
git grep -nE 'AUTHORIZED|paymentMoved|HANDSHAKE_REQUIRED|PAYER_MCP_READY' -- bin src scripts docs test
```

Expected: no whitespace errors; `AUTHORIZED` emission remains confined to verifier-owned code/tests; new public status and docs preserve `paymentMoved:false`; MCP and readiness gates are explicit.

- [ ] **Step 2: Run one fresh full verification**

Run: `npm run verify`

Expected: all repository tests and documentation gates pass from the clean detached release used for the live run.

- [ ] **Step 3: Re-run the public-site focused test and build**

Run:

```bash
npm --prefix /Users/Kailor/.config/superpowers/worktrees/clockchain-research/aws-stakeholder-run test -- --run src/lib/bilateral-handshake-runbook.test.tsx
npm --prefix /Users/Kailor/.config/superpowers/worktrees/clockchain-research/aws-stakeholder-run run build
```

Expected: PASS with the Requestor-only live page and verified receipt rendering.

- [ ] **Step 4: Push and deploy the reviewed artifacts**

Push the handshake release branch and research-site branch. Deploy the public page using the existing Vercel project only after both repositories are clean and their recorded checks pass. Confirm the production page shows the pushed release SHA and fresh verified history.

- [ ] **Step 5: Issue the completion verdict**

Report completion only when the live Hermes cycle, three live anchors, fresh verifier, public immutable receipts, both email deliveries, five negative checks, final `npm run verify`, site test, and site build have fresh evidence. If any item is absent, report the exact remaining gap and keep the goal active.
