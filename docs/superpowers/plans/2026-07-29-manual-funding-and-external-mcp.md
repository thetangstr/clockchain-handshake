# Manual Funding and External MCP Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the human-operated funding pause reliable and expose the Payer-owned MCP across networks without moving Payer authority or private state into shared infrastructure.

**Architecture:** Replace the role-side one-shot balance check with an injected, bounded condition waiter that treats only valid underfunding as pending. Separately decouple the MCP bind address from its advertised public URL so a loopback-only server can be reached through an AWS raw-TCP reverse tunnel while preserving end-to-end certificate and fingerprint pinning.

**Tech Stack:** Node.js 22, ES modules, `node:test`, Node HTTPS/TLS and crypto APIs, `viem`, OpenSSH reverse forwarding, AWS EC2 with an Elastic IP, Next.js/Vitest for the public handbook.

---

## File structure

### Clockchain Handshake repository

- `src/bilateral/coordination/supervisor-runtime.mjs`: classify funding
  observations and wait with an injected clock and sleeper.
- `test/bilateral-coordination-supervisor-runtime.test.mjs`: deterministic
  funding-wait and production-wiring tests.
- `src/bilateral/local-mcp/server.mjs`: separate loopback bind authority from
  the exact public URL and Host authority.
- `bin/handshake-supervisor.mjs`: accept the optional public MCP URL.
- `test/bilateral-local-mcp-server.test.mjs`: server validation and raw-TCP
  relay coverage.
- `test/bilateral-coordination-supervisor-runtime.test.mjs`: supervisor CLI
  and MCP construction coverage.
- `prompts/run-payer-bilateral-demo.md`: long-lived Payer process,
  state-preservation, and raw-TCP relay instructions.
- `prompts/run-requestor-bilateral-demo.md`: long-lived wrapper,
  state-preservation, and public MCP endpoint instructions.
- `docs/runbooks/bilateral-demo-quick-start.md`: concise operator sequence.
- `docs/runbooks/bilateral-demo-day.md`: complete manual execution and recovery
  sequence.
- `docs/runbooks/bilateral-demo-live-handoff.md`: exact live handoff fields and
  stop conditions.
- `scripts/check-docs.mjs` and `test/docs.test.mjs`: documentation contract
  gates.
- `docs/runbooks/payer-mcp-external-relay.md`: one-time AWS relay and per-run
  reverse-tunnel procedure.

### Clockchain Research repository

- `src/components/BilateralHandshakeRunbook.tsx`: public Payer and Requestor
  prompts, funding wait, monitor, and external MCP instructions.
- `src/lib/bilateral-handshake-runbook.test.tsx`: public handbook release,
  prompt, safety, and ordering gates.
- `src/data/bilateral-handshake-demo.ts`: reviewed immutable release SHA and
  `liveTestReady` state.

## Task 1: Prove and implement the bounded role-side funding wait

**Files:**

- Modify: `test/bilateral-coordination-supervisor-runtime.test.mjs`
- Modify: `src/bilateral/coordination/supervisor-runtime.mjs`

- [ ] **Step 1: Write the zero, partial, ready, and deadline tests**

Add deterministic tests that import
`createFundingInputVerifier`, build an exact two-address enrollment fixture,
and drive an injected clock:

```js
const clock = {
  nowMs: 0,
  sleeps: [],
  now() {
    return this.nowMs;
  },
  async sleeper(milliseconds) {
    this.sleeps.push(milliseconds);
    this.nowMs += milliseconds;
  },
};

const verifier = createFundingInputVerifier({
  intervalMs: 5_000,
  now: () => clock.now(),
  sepoliaRpc: sequencedFundingRpc([
    { balances: [0n, 0n], nonces: [0n, 0n] },
    {
      balances: [10_000_000_000_000_000n, 0n],
      nonces: [0n, 0n],
    },
    {
      balances: [
        10_000_000_000_000_000n,
        10_000_000_000_000_000n,
      ],
      nonces: [0n, 0n],
    },
  ]),
  sleeper: (milliseconds) => clock.sleeper(milliseconds),
});

assert.deepEqual(await verifier(validFundingInput()), {
  paymentMoved: false,
});
assert.deepEqual(clock.sleeps, [5_000, 5_000]);
```

The deadline test must keep returning zero balances, advance the injected clock
to exactly eight minutes, assert rejection, and assert no
`FUNDING_INPUTS_READY` append occurred.

- [ ] **Step 2: Run the focused test and observe the expected failure**

Run:

```sh
node --test test/bilateral-coordination-supervisor-runtime.test.mjs
```

Expected: fail because `createFundingInputVerifier` is not exported and the
current production verifier performs only one observation.

- [ ] **Step 3: Implement the smallest bounded verifier**

In `src/bilateral/coordination/supervisor-runtime.mjs`, add:

```js
export const SUPERVISOR_FUNDING_DEADLINE_MS = 8 * 60_000;
export const SUPERVISOR_FUNDING_INTERVAL_MS = 5_000;

export function createFundingInputVerifier({
  intervalMs = SUPERVISOR_FUNDING_INTERVAL_MS,
  now = Date.now,
  sepoliaRpc,
  sleeper = (milliseconds) =>
    new Promise((resolve_) => setTimeout(resolve_, milliseconds)),
} = {}) {
  if (
    typeof sepoliaRpc !== "function" ||
    typeof now !== "function" ||
    typeof sleeper !== "function" ||
    !Number.isSafeInteger(intervalMs) ||
    intervalMs < 1
  ) {
    fail();
  }

  return async (input) => {
    const addresses = validateFundingInput(input);
    const startedAt = now();
    if (!Number.isSafeInteger(startedAt) || startedAt < 0) fail();
    const deadline = startedAt + SUPERVISOR_FUNDING_DEADLINE_MS;

    for (;;) {
      let pending = false;
      for (const address of addresses) {
        const [balance, nonce] = await Promise.all([
          sepoliaRpc({
            method: "eth_getBalance",
            params: [address, "latest"],
          }),
          sepoliaRpc({
            method: "eth_getTransactionCount",
            params: [address, "latest"],
          }),
        ]);
        const wei = rpcQuantity(balance);
        if (
          wei > 20_000_000_000_000_000n ||
          rpcQuantity(nonce) !== 0n
        ) {
          fail();
        }
        pending ||= wei < 5_000_000_000_000_000n;
      }
      if (!pending) return Object.freeze({ paymentMoved: false });

      const current = now();
      if (
        !Number.isSafeInteger(current) ||
        current < startedAt ||
        current >= deadline
      ) {
        fail();
      }
      await sleeper(Math.min(intervalMs, deadline - current));
    }
  };
}
```

Extract the existing enrollment/address validation into
`validateFundingInput(input)` and preserve exact canonical address ordering.
Do not convert malformed RPC results, nonzero nonces, overfunding, duplicate
addresses, or enrollment mismatches into pending states.

- [ ] **Step 4: Wire the production dependencies**

Extend `createProductionSupervisorDependencies` with optional `now` and
`sleeper` injections and construct:

```js
verifyFundingInputs: createFundingInputVerifier({
  now,
  sepoliaRpc:
    sepoliaRpc ??
    createProductionSepoliaRpc({ createClient: createSepoliaClient }),
  sleeper,
}),
```

Use `Date.now` and the native bounded `setTimeout` promise as production
defaults. Do not change the coordinator deadline or event model.

- [ ] **Step 5: Run the focused tests and confirm green**

Run:

```sh
node --test \
  test/bilateral-coordination-supervisor-runtime.test.mjs \
  test/bilateral-coordination-supervisor.test.mjs
```

Expected: all tests pass; the role publishes `FUNDING_INPUTS_READY` only after
both exact addresses are ready.

- [ ] **Step 6: Commit the funding wait**

```sh
git add \
  src/bilateral/coordination/supervisor-runtime.mjs \
  test/bilateral-coordination-supervisor-runtime.test.mjs
git commit
```

Use a Lore message that records the human funding race, immediate invalid-input
failure, the eight-minute bound, and the exact focused test result.

## Task 2: Decouple the Payer MCP bind address from its public URL

**Files:**

- Modify: `test/bilateral-local-mcp-server.test.mjs`
- Modify: `test/bilateral-coordination-supervisor-runtime.test.mjs`
- Modify: `src/bilateral/local-mcp/server.mjs`
- Modify: `src/bilateral/coordination/supervisor-runtime.mjs`
- Modify: `bin/handshake-supervisor.mjs`

- [ ] **Step 1: Write failing public-URL server tests**

Generate a one-day self-signed certificate with `127.0.0.1` as its SAN.
Construct the server with a loopback bind port and a distinct relay port:

```js
const payerMcp = createPayerMcpServer({
  capabilityDigest,
  host: "127.0.0.1",
  intakeStore,
  port: 0,
  publicUrl: `https://127.0.0.1:${relayPort}/mcp`,
  repositorySha,
  tlsCertificatePem,
  tlsPrivateKeyPem,
});

const listen = await payerMcp.start();
assert.equal(listen.host, "127.0.0.1");
assert.equal(listen.url, `https://127.0.0.1:${relayPort}/mcp`);
```

Use a separate construction-only fixture whose certificate SAN is
`203.0.113.10` to prove that an IP-literal AWS public URL is accepted. Also
assert fail-closed rejection for:

```js
[
  "http://203.0.113.10:19443/mcp",
  "https://203.0.113.10/mcp",
  "https://203.0.113.10:19443/other",
  "https://127.0.0.1:19443/mcp?proxy=true",
  "https://user@203.0.113.10:19443/mcp",
  "https://0.0.0.0:19443/mcp",
]
```

Add a certificate-mismatch case whose SAN does not contain the public IP.

- [ ] **Step 2: Write a failing raw-TCP relay lifecycle test**

Create a test-only `net.createServer` relay that listens on loopback, connects
to the MCP's loopback bind port, and pipes both sockets without inspecting or
terminating TLS. Use the relay's advertised port in `publicUrl`, then call
`requestPaymentThroughPayerMcp` with the transferred certificate,
fingerprint, and capability.

Assert:

```js
assert.equal(result.status, "HANDSHAKE_REQUIRED");
assert.equal(result.paymentMoved, false);
assert.equal(storedIntakes.length, 1);
assert.equal(relayTlsTerminations, 0);
```

The relay may count bytes but must not parse HTTP, JSON-RPC, authorization
headers, or TLS records.

- [ ] **Step 3: Run focused tests and observe the expected failures**

Run:

```sh
node --test \
  test/bilateral-local-mcp-server.test.mjs \
  test/bilateral-local-mcp-client.test.mjs \
  test/bilateral-coordination-supervisor-runtime.test.mjs
```

Expected: fail because the server reports and validates only its bind authority,
and the supervisor CLI does not accept a public URL.

- [ ] **Step 4: Implement exact public URL validation**

In `src/bilateral/local-mcp/server.mjs`, import `X509Certificate` and add a
validator restricted to an exact IP-literal HTTPS URL:

```js
function validatePublicEndpoint(value, certificatePem) {
  if (value === undefined) return null;
  if (typeof value !== "string") fail();
  const url = new URL(value);
  if (
    url.protocol !== "https:" ||
    url.pathname !== "/mcp" ||
    url.search ||
    url.hash ||
    url.username ||
    url.password ||
    url.port === "" ||
    net.isIP(url.hostname) === 0 ||
    url.hostname === "0.0.0.0"
  ) {
    fail();
  }
  const certificate = new X509Certificate(certificatePem);
  if (certificate.checkIP(url.hostname) !== url.hostname) fail();
  return Object.freeze({
    authority: hostAuthority(url.hostname, Number(url.port)),
    url: url.href,
  });
}
```

At construction, store:

```js
const publicEndpoint = validatePublicEndpoint(publicUrl, certificate);
```

Resolve the request and status values after the listener has its actual port:

```js
function advertisedAuthority() {
  return publicEndpoint?.authority ?? hostAuthority(bindHost, currentPort());
}

function advertisedUrl() {
  return (
    publicEndpoint?.url ??
    `https://${hostAuthority(bindHost, currentPort())}/mcp`
  );
}
```

Use `advertisedAuthority()` in `validateCommonHeaders`, return
`advertisedUrl()` from `start()`, and continue binding only to the separately
validated numeric `host`. This preserves current port-zero test behavior when
no public URL is provided.

- [ ] **Step 5: Add the optional supervisor CLI flag**

Change the CLI to accept either no MCP options, the existing four MCP options,
or the same four plus:

```text
--payer-mcp-public-url https://<AWS_ELASTIC_IP>:<PUBLIC_PORT>/mcp
```

Pass `publicUrl` through
`createProductionSupervisorDependencies` into `createPayerMcpServer`. Reject
the public URL when the other four MCP options are absent, reject duplicates,
and keep Payer-only construction.

- [ ] **Step 6: Run the focused tests and confirm green**

Run:

```sh
node --test \
  test/bilateral-local-mcp-server.test.mjs \
  test/bilateral-local-mcp-client.test.mjs \
  test/bilateral-coordination-supervisor-runtime.test.mjs \
  test/bilateral-coordination-supervisor.test.mjs
```

Expected: all tests pass, including the complete pinned MCP lifecycle through
the raw-TCP relay.

- [ ] **Step 7: Commit external MCP transport support**

```sh
git add \
  bin/handshake-supervisor.mjs \
  src/bilateral/coordination/supervisor-runtime.mjs \
  src/bilateral/local-mcp/server.mjs \
  test/bilateral-coordination-supervisor-runtime.test.mjs \
  test/bilateral-local-mcp-server.test.mjs
git commit
```

Use a Lore message recording that AWS is a byte-forwarding relay only, Payer
retains TLS termination and state, and DNS/reverse-proxy fallback was rejected.

## Task 3: Make manual execution preserve state and survive human funding

**Files:**

- Modify: `scripts/check-docs.mjs`
- Modify: `test/docs.test.mjs`
- Modify: `prompts/run-payer-bilateral-demo.md`
- Modify: `prompts/run-requestor-bilateral-demo.md`
- Modify: `docs/runbooks/bilateral-demo-quick-start.md`
- Modify: `docs/runbooks/bilateral-demo-day.md`
- Modify: `docs/runbooks/bilateral-demo-live-handoff.md`
- Create: `docs/runbooks/payer-mcp-external-relay.md`

- [ ] **Step 1: Add failing documentation gates**

Require both role prompts and all three live runbooks to contain the exact
operational boundaries:

```text
Start this long-lived process exactly once.
Preserve the assigned private state root unchanged.
Underfunding is pending until the bounded funding deadline.
Do not retry a consumed launch manifest.
Do not start a replacement supervisor.
AWS forwards raw TCP and does not terminate Payer MCP TLS.
```

Require the Payer command to contain `--payer-mcp-public-url`, require the
Requestor to accept only the exact `PAYER_MCP_READY` public URL/certificate/
fingerprint tuple, and forbid instructions to bind Payer MCP to `0.0.0.0`.

- [ ] **Step 2: Run the documentation checks and observe failure**

Run:

```sh
node --test test/docs.test.mjs
node scripts/check-docs.mjs
```

Expected: fail because the current documents describe LAN-only MCP reachability
and do not prohibit destructive state recovery.

- [ ] **Step 3: Write the external relay runbook**

Document one-time AWS relay prerequisites:

```text
- one dedicated minimal EC2 instance
- one attached Elastic IP
- IMDSv2 required
- encrypted EBS
- inbound SSH restricted to the Payer's current public IP
- inbound public MCP port restricted to the Requestor's public IP when known
- sshd GatewayPorts clientspecified
- no TLS certificate or MCP capability stored on the instance
```

Document the per-run command without embedding a private-key path:

```sh
ssh -N \
  -o ExitOnForwardFailure=yes \
  -o ServerAliveInterval=30 \
  -o ServerAliveCountMax=3 \
  -R "0.0.0.0:${PAYER_MCP_PUBLIC_PORT}:127.0.0.1:${PAYER_MCP_PORT}" \
  "$PAYER_MCP_RELAY_SSH_HOST"
```

Require a preconfigured SSH host alias so an agent never opens or prints the
SSH key. Require the tunnel to run as a monitored long-lived process and stop
the session if it exits.

- [ ] **Step 4: Update Payer and Requestor prompts**

Payer must:

```text
1. preserve its state root;
2. create the certificate SAN for the AWS Elastic IP;
3. start the raw-TCP tunnel;
4. start one supervisor with loopback bind plus the exact public URL;
5. publish only PAYER_MCP_READY public URL, certificate, and fingerprint;
6. wait through valid underfunding.
```

Requestor must:

```text
1. preserve its state root;
2. call request_payment exactly once through the exact public URL;
3. require normal certificate/IP validation plus fingerprint pinning;
4. let the wrapper start the supervisor;
5. wait through valid underfunding without replacing state or processes.
```

For timeout-limited agent shells, require the environment's background process
facility from the outset and continuous sanitized-output monitoring.

- [ ] **Step 5: Update operator runbooks**

Place the sequence in this order:

```text
relay -> coordinator -> console -> Payer tunnel -> Payer supervisor
-> PAYER_MCP_READY -> Requestor request_payment wrapper
-> HANDSHAKE_REQUIRED -> funding record -> one funding batch
-> both roles FUNDING_INPUTS_READY -> preflight -> three anchors
-> fresh aggregate verification
```

State that no address from the failed rehearsal is reusable and no role state
may be deleted to recover a consumed manifest.

- [ ] **Step 6: Run documentation checks and confirm green**

Run:

```sh
node --test test/docs.test.mjs
node scripts/check-docs.mjs
```

Expected: both commands exit zero.

- [ ] **Step 7: Commit the manual execution contract**

```sh
git add \
  docs/runbooks/bilateral-demo-day.md \
  docs/runbooks/bilateral-demo-live-handoff.md \
  docs/runbooks/bilateral-demo-quick-start.md \
  docs/runbooks/payer-mcp-external-relay.md \
  prompts/run-payer-bilateral-demo.md \
  prompts/run-requestor-bilateral-demo.md \
  scripts/check-docs.mjs \
  test/docs.test.mjs
git commit
```

Use a Lore message recording state preservation, bounded funding, raw-TCP
relay authority, and documentation test evidence.

## Task 4: Verify the release before changing public readiness

**Files:**

- Review: all committed changes since `2be61f8`
- No public-site changes in this task

- [ ] **Step 1: Run the complete focused regression set**

Run:

```sh
node --test \
  test/bilateral-local-mcp-payment-intake.test.mjs \
  test/bilateral-local-mcp-intake-store.test.mjs \
  test/bilateral-local-mcp-server.test.mjs \
  test/bilateral-local-mcp-client.test.mjs \
  test/bilateral-request-payment-cli.test.mjs \
  test/bilateral-coordination-supervisor-runtime.test.mjs \
  test/bilateral-coordination-supervisor.test.mjs \
  test/docs.test.mjs
node scripts/check-docs.mjs
```

Expected: every test and documentation gate passes.

- [ ] **Step 2: Review the complete diff**

Run:

```sh
git diff --check 2be61f8..HEAD
git diff --stat 2be61f8..HEAD
git status --short
```

Confirm no tokens, capabilities, invitations, private keys, live evidence,
treasury material, RPC URLs, or AWS credentials appear.

- [ ] **Step 3: Run the one final repository gate**

Run exactly once after focused checks are green:

```sh
npm run verify
```

Expected: exit zero with the complete repository suite passing.

- [ ] **Step 4: Record the reviewed immutable SHA**

Run:

```sh
git rev-parse HEAD
git status --short
```

Expected: a clean worktree and one exact 40-character SHA. Do not set public
`liveTestReady:true` yet.

## Task 5: Provision and externally verify the stable raw-TCP relay

**Files:**

- Follow: `docs/runbooks/payer-mcp-external-relay.md`
- Do not commit generated certificates, SSH material, endpoints, or live output

- [ ] **Step 1: Reauthenticate AWS CLI**

Run:

```sh
aws login
aws sts get-caller-identity
```

Expected: successful authenticated identity. Stop for the user on account
selection, consent, MFA ambiguity, or an unexpected AWS account.

- [ ] **Step 2: Inspect before creating infrastructure**

Run read-only EC2 queries for an existing dedicated relay, Elastic IP, security
group, and keyless/approved access path. Reuse only an explicitly named relay
whose configuration matches the runbook. Do not modify unrelated instances.

- [ ] **Step 3: Create only missing dedicated relay resources**

If no matching relay exists, create the minimal dedicated instance, encrypted
volume, Elastic IP, and narrowly scoped security group described by the
runbook. Require IMDSv2, disable application credentials on the instance, and
configure `GatewayPorts clientspecified`.

- [ ] **Step 4: Prove end-to-end public MCP intake**

Start a fresh local Payer MCP and reverse tunnel, then execute the real
Requestor MCP client through the AWS Elastic IP. Assert exact:

```json
{"paymentMoved":false,"status":"HANDSHAKE_REQUIRED"}
```

Inspect the relay only for connection metadata and byte counts. Confirm it has
no TLS key, certificate, capability, request JSON, response JSON, or intake
record.

- [ ] **Step 5: Preserve the stable relay and remove ephemeral test state**

Stop the test MCP and tunnel. Preserve the dedicated relay for subsequent demo
runs, but remove only explicitly created ephemeral certificates, capabilities,
and private test state through their repository-owned cleanup path. Record no
secret or live evidence in Git.

## Task 6: Publish the reviewed handbook and run a fresh physical rehearsal

**Files:**

- Modify in Clockchain Research:
  `src/components/BilateralHandshakeRunbook.tsx`
- Modify in Clockchain Research:
  `src/lib/bilateral-handshake-runbook.test.tsx`
- Modify in Clockchain Research:
  `src/data/bilateral-handshake-demo.ts`

- [ ] **Step 1: Write failing public handbook tests**

Update the expected release SHA and require:

```text
liveTestReady:true
Payer MCP uses an externally reachable raw-TCP relay
AWS does not terminate Payer MCP TLS
Preserve the assigned private state root unchanged
Underfunding remains pending for up to eight minutes
Payer starts exactly one long-lived supervisor
Requestor starts exactly one request-payment wrapper
```

Require the Payer prompt box to contain the public-URL supervisor flag and the
Requestor box to consume the exact `PAYER_MCP_READY` tuple.

- [ ] **Step 2: Run the focused site test and observe failure**

Run in the Clockchain Research repository:

```sh
npm test -- --run src/lib/bilateral-handshake-runbook.test.tsx
```

Expected: fail against the old release SHA and LAN-only instructions.

- [ ] **Step 3: Update the page from the reviewed repository artifacts**

Replace the stale LAN-only and `liveTestReady:false` language. Keep one
introduction followed immediately by the two role prompts and manual sequence.
Keep caveats at the bottom, keep the Payer and Requestor color distinction, and
keep icon-only copy controls.

- [ ] **Step 4: Run public-site verification**

Run:

```sh
npm test -- --run src/lib/bilateral-handshake-runbook.test.tsx
npm run build
```

Expected: focused tests and production build pass.

- [ ] **Step 5: Commit and publish the public site**

Commit only the three owned site files with a Lore-style decision record, push
the branch, merge through the repository's normal review path, and wait for the
Vercel deployment.

- [ ] **Step 6: Verify the deployed page**

Open:

```text
https://clockchain-research.vercel.app/handshake/run
```

Verify the deployed HTML shows the reviewed SHA, `liveTestReady:true`, exact
Payer and Requestor prompts, raw-TCP TLS boundary, bounded funding wait, and no
secret input or evidence collection.

- [ ] **Step 7: Run the new funded physical rehearsal**

Use four newly generated addresses and a single funding batch. Start the AWS
reverse tunnel, Payer supervisor, and Requestor wrapper exactly once; keep all
processes and private state roots intact. Require:

```text
PAYER_MCP_READY
HANDSHAKE_REQUIRED
FUNDING_INPUTS_READY from both roles
PROPOSED
ACCEPTED
ACKNOWLEDGED
fresh aggregate verifier AUTHORIZED
paymentMoved:false
exactly three independently verifiable Clockchain anchors
```

If any process exits early or any evidence differs, preserve state and report
the exact failure without retrying a consumed manifest or claiming completion.
