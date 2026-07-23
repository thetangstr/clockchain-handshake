# Turnkey Handshake Demo Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Publish and prove a one-prompt stakeholder exercise that creates a fresh official ERC-8004 identity and a fresh independently verified Clockchain receipt without AgentDash.

**Architecture:** A small Node.js 22 ESM application decrypts a pre-funded testnet invitation in memory, registers and verifies an ERC-8004 identity on Ethereum Sepolia, calls the hosted Clockchain MCP over SSE JSON-RPC, and emits redacted evidence. The repository also carries the universal GitHub prompt, Codex/Claude role routing, operator-only invitation tooling, deterministic tests, and an acceptance harness that runs the unchanged prompt through real Codex and Claude Code CLIs.

**Tech Stack:** Node.js 22, npm, ESM JavaScript, `viem` 2.55.8, Node `crypto`, Node `test`, Ethereum Sepolia, ERC-8004 v2, Clockchain hosted MCP, Codex CLI, Claude Code CLI.

---

## File map

| Path | Responsibility |
|---|---|
| `package.json` | Scripts, Node version, and the single runtime dependency |
| `package-lock.json` | Reproducible dependency graph |
| `.gitignore` | Secret, state, dependency, and generated-artifact exclusions |
| `.conductor/settings.toml` | Shared setup and verification commands |
| `AGENTS.md` | Sol/Terra/Luna ownership and verification contract |
| `.codex/config.toml` | Project Codex leader and default subagent settings |
| `.codex/agents/*.toml` | Planner, verifier, Terra executor, Luna explorer/light executor |
| `CLAUDE.md` | Claude Code routing contract importing project guidance |
| `.claude/agents/*.md` | Native Claude role mirrors |
| `src/constants.mjs` | Fixed testnet, registry, endpoint, schema, and limit constants |
| `src/redact.mjs` | Recursive secret detection and artifact redaction |
| `src/invitation.mjs` | Invitation parsing, `scrypt`, AES-GCM decryption, and validation |
| `src/registration.mjs` | ERC-8004 ABI, metadata, register/finalize/read-back flow |
| `src/mcp.mjs` | Demo-token acquisition, SSE parsing, JSON-RPC tool calls |
| `src/evidence.mjs` | Result schema validation and Markdown rendering |
| `src/run.mjs` | Ordered fail-closed orchestration |
| `bin/handshake-demo.mjs` | CLI entry point and deterministic exit codes |
| `scripts/create-invitations.mjs` | Operator-only wallet/bundle/secret generation |
| `scripts/check-invitations.mjs` | Read-only balance, nonce, and bundle readiness check |
| `scripts/verify-live-results.mjs` | Independent live re-verification of sanitized results |
| `scripts/run-clean-clients.mjs` | Empty-directory Codex/Claude acceptance harness |
| `test/*.test.mjs` | Unit and mock integration tests |
| `test/fixtures/*.json` | Sanitized deterministic protocol fixtures |
| `invites/*.enc.json` | Publishable encrypted testnet invitation bundles |
| `prompts/run-turnkey-demo.md` | Exact prompt consumed by both coding agents |
| `README.md` | GitHub landing page and copy/paste prompt |
| `DEMO.md` | Operator/stakeholder runbook and honesty constraints |

### Task 1: Establish the repository and agent contracts

**Files:**
- Create: `.gitignore`
- Create: `package.json`
- Create: `.conductor/settings.toml`
- Create: `AGENTS.md`
- Create: `.codex/config.toml`
- Create: `.codex/agents/planner.toml`
- Create: `.codex/agents/verifier.toml`
- Create: `.codex/agents/executor.toml`
- Create: `.codex/agents/explore.toml`
- Create: `.codex/agents/lightweight-executor.toml`
- Create: `CLAUDE.md`
- Create: `.claude/agents/planner.md`
- Create: `.claude/agents/verifier.md`
- Create: `.claude/agents/executor.md`
- Create: `.claude/agents/explore.md`
- Create: `.claude/agents/lightweight-executor.md`

- [x] **Step 1: Add exclusions before generating local state**

```gitignore
node_modules/
.context/
.omx/
.env
.env.*
!.env.example
result.json
RESULT.md
artifacts/
coverage/
*.secret.json
*.key
*.token
```

- [x] **Step 2: Add the minimal package contract**

```json
{
  "name": "@clockchain/handshake-demo",
  "version": "0.1.0",
  "private": true,
  "type": "module",
  "engines": {
    "node": ">=22"
  },
  "scripts": {
    "demo": "node bin/handshake-demo.mjs",
    "invitations:create": "node scripts/create-invitations.mjs",
    "invitations:check": "node scripts/check-invitations.mjs",
    "results:verify": "node scripts/verify-live-results.mjs",
    "acceptance:clients": "node scripts/run-clean-clients.mjs",
    "test": "node --test",
    "test:unit": "node --test test/*.test.mjs",
    "verify": "npm test && npm run docs:check",
    "docs:check": "node scripts/check-docs.mjs"
  },
  "dependencies": {
    "viem": "2.55.8"
  }
}
```

- [x] **Step 3: Install dependencies and verify the lockfile is reproducible**

Run: `npm install --ignore-scripts`

Expected: `package-lock.json` is created and `npm ci --ignore-scripts` exits 0.

- [x] **Step 4: Add shared Conductor commands**

```toml
"$schema" = "https://conductor.build/schemas/settings.repo.schema.json"

[scripts]
setup = "npm ci --ignore-scripts"
run_mode = "concurrent"

[scripts.run.verify]
command = "npm run verify"
default = true
icon = "test-tube"

[scripts.run.demo]
command = "npm run demo"
icon = "terminal"
```

- [x] **Step 5: Add the Codex leader contract**

```toml
model = "gpt-5.6-sol"
model_reasoning_effort = "high"

[agents.executor]
description = "Terra executor for substantive, scoped implementation and tests"
config_file = "agents/executor.toml"
```

Conductor's bundled Codex 0.144.1 predates the global `[agents]` scalar
settings supported by current Codex. Use the documented explicit
`[agents.<role>]` registration form so both installed CLIs accept the project.
Register the five roles below plus `worker` as an alias for `executor` and
`explorer` as an alias for `explore`.

Create the five custom agent configuration layers with these model assignments:

```text
planner              gpt-5.6-sol    high
verifier             gpt-5.6-sol    high
executor              gpt-5.6-terra  medium
explore               gpt-5.6-luna   low, read-only
lightweight-executor  gpt-5.6-luna   low
```

The root registration defines each role's name and description. Each referenced
file defines `model`, `model_reasoning_effort`, and scoped
`developer_instructions`; the Luna explorer also sets
`sandbox_mode = "read-only"`. `AGENTS.md` must state that Sol alone owns
orchestration, synthesis, shared-file coordination, and the final completion
verdict.

- [x] **Step 6: Add Claude Code role mirrors**

`CLAUDE.md` begins with:

```md
@AGENTS.md

# Claude Code model mapping

Claude Code mirrors the repository roles with native model tiers:
planner/verifier use Opus, substantive executor uses Sonnet, and
explore/lightweight-executor use Haiku. The canonical GPT-5.6 model contract is
enforced by Codex project configuration, not by native Claude model names.
```

Use `model: opus`, `model: sonnet`, and `model: haiku` in the corresponding
Claude agent frontmatter.

- [x] **Step 7: Validate configuration discovery**

Run:

```bash
"/Users/Kailor/Library/Application Support/com.conductor.app/bin/codex" mcp list >/dev/null
/Applications/ChatGPT.app/Contents/Resources/codex mcp list >/dev/null
test -f .codex/config.toml
test -f .codex/agents/executor.toml
test -f .claude/agents/executor.md
```

Expected: all commands exit 0.

- [x] **Step 8: Commit**

```bash
git add .gitignore package.json package-lock.json .conductor AGENTS.md .codex CLAUDE.md .claude
git commit -m "Make execution ownership explicit before building the demo" \
  -m "Constraint: Sol coordinates and verifies while Terra implements and Luna handles bounded work.
Confidence: high
Scope-risk: narrow
Tested: npm ci and repository configuration presence checks.
Not-tested: Runtime demo behavior is implemented in later tasks."
```

### Task 2: Build invitation encryption and redaction with TDD

**Files:**
- Create: `src/constants.mjs`
- Create: `src/redact.mjs`
- Create: `src/invitation.mjs`
- Create: `test/invitation.test.mjs`
- Create: `test/redact.test.mjs`

- [ ] **Step 1: Write failing invitation tests**

```js
import test from "node:test";
import assert from "node:assert/strict";
import { encryptInvitation, decryptInvitation } from "../src/invitation.mjs";

test("round-trips a testnet invitation without changing its address", async () => {
  const payload = {
    privateKey: `0x${"11".repeat(32)}`,
    address: "0x1111111111111111111111111111111111111111",
    displayName: "Billy",
  };
  const bundle = await encryptInvitation(payload, "correct horse battery staple");
  assert.equal((await decryptInvitation(bundle, "correct horse battery staple")).address, payload.address);
});

test("rejects a modified ciphertext", async () => {
  const bundle = await encryptInvitation({
    privateKey: `0x${"22".repeat(32)}`,
    address: "0x2222222222222222222222222222222222222222",
    displayName: "Iris",
  }, "secret");
  bundle.crypto.ciphertext = `${bundle.crypto.ciphertext.slice(0, -2)}00`;
  await assert.rejects(() => decryptInvitation(bundle, "secret"), /authentication/i);
});
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `node --test test/invitation.test.mjs`

Expected: FAIL with `ERR_MODULE_NOT_FOUND`.

- [ ] **Step 3: Implement constants and invitation crypto**

`src/constants.mjs` exports exact immutable values:

```js
export const CHAIN_ID = 11155111;
export const CHAIN_NAME = "ethereum-sepolia";
export const REGISTRY_ADDRESS = "0x8004A818BFB912233c491871b3d84c89A494BD9e";
export const RPC_URL = "https://ethereum-sepolia-rpc.publicnode.com";
export const MCP_BASE_URL = "https://mcp.clockchain.network";
export const MCP_URL = `${MCP_BASE_URL}/mcp`;
export const RESULT_SCHEMA = "clockchain.handshake-result/v1";
export const INVITATION_SCHEMA = "clockchain.handshake-invitation/v1";
export const SINGLE_VALIDATOR_DISCLAIMER =
  "Single-validator testnet: anchored and independently re-verifiable; not mainnet, court-grade, consensus-secure, or trustless.";
```

`src/invitation.mjs` uses:

```js
import { randomBytes, scrypt as scryptCallback, createCipheriv, createDecipheriv } from "node:crypto";
import { promisify } from "node:util";

const scrypt = promisify(scryptCallback);
const KDF = { N: 16384, r: 8, p: 1, keyLength: 32 };
```

The public API is:

```js
export async function encryptInvitation(payload, secret) {}
export async function decryptInvitation(bundle, secret) {}
export async function readSecretInvitation(path) {}
```

`readSecretInvitation` accepts JSON containing only `bundle` and `code`, rejects
group/world-readable files on POSIX, and never includes `code` in thrown errors.

- [ ] **Step 4: Write failing redaction tests**

```js
import test from "node:test";
import assert from "node:assert/strict";
import { assertSecretFree, redact } from "../src/redact.mjs";

test("redacts nested keys and exact secret canaries", () => {
  const value = { nested: { privateKey: "CANARY", token: "cc_secret" }, safe: "ok" };
  const clean = redact(value, ["CANARY", "cc_secret"]);
  assert.deepEqual(clean, { nested: { privateKey: "[REDACTED]", token: "[REDACTED]" }, safe: "ok" });
  assert.doesNotThrow(() => assertSecretFree(clean, ["CANARY", "cc_secret"]));
});

test("rejects a secret embedded inside a longer string", () => {
  assert.throws(() => assertSecretFree({ message: "prefix-CANARY-suffix" }, ["CANARY"]), /secret/i);
});
```

- [ ] **Step 5: Implement recursive redaction**

`src/redact.mjs` exports:

```js
export const SENSITIVE_KEY = /private.?key|secret|token|authorization|invite.?code|ciphertext/i;
export function redact(value, canaries = []) {}
export function assertSecretFree(value, canaries = []) {}
```

Arrays, plain objects, errors, and strings must be traversed. Sensitive values
become `[REDACTED]`; keys remain so diagnostics preserve structure.

- [ ] **Step 6: Run the focused tests**

Run: `node --test test/invitation.test.mjs test/redact.test.mjs`

Expected: 4 tests pass.

- [ ] **Step 7: Commit**

```bash
git add src/constants.mjs src/invitation.mjs src/redact.mjs test/invitation.test.mjs test/redact.test.mjs
git commit -m "Keep stakeholder invitations local and non-exportable" \
  -m "Constraint: Testnet wallet material must never enter Git, logs, prompts, or result artifacts.
Rejected: Plaintext private keys in environment variables | They are too easy for coding-agent tooling to echo.
Confidence: high
Scope-risk: narrow
Tested: Invitation round-trip, tamper rejection, nested redaction, and secret-canary rejection."
```

### Task 3: Implement and verify official ERC-8004 registration

**Files:**
- Create: `src/registration.mjs`
- Create: `test/registration.test.mjs`
- Create: `test/fixtures/registered-log.json`

- [ ] **Step 1: Write failing metadata and event tests**

```js
import test from "node:test";
import assert from "node:assert/strict";
import {
  buildRegistrationDocument,
  identityReference,
  parseRegisteredAgentId,
} from "../src/registration.mjs";

test("builds a final registration document bound to the official registry", () => {
  const ref = identityReference(42n);
  assert.equal(ref, "eip155:11155111:0x8004A818BFB912233c491871b3d84c89A494BD9e:42");
  const doc = buildRegistrationDocument({ displayName: "Billy", address: "0x1111111111111111111111111111111111111111", agentId: 42n });
  assert.deepEqual(doc.registrations, [{
    agentRegistry: "eip155:11155111:0x8004A818BFB912233c491871b3d84c89A494BD9e",
    agentId: 42,
  }]);
});

test("extracts agentId only from the official Registered event", () => {
  const fixture = JSON.parse(readFileSync(new URL("./fixtures/registered-log.json", import.meta.url)));
  assert.equal(parseRegisteredAgentId(fixture), 42n);
});
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `node --test test/registration.test.mjs`

Expected: FAIL with `ERR_MODULE_NOT_FOUND`.

- [ ] **Step 3: Implement pinned ABI and pure helpers**

The ABI includes only:

```text
getVersion()
register(string)
setAgentURI(uint256,string)
ownerOf(uint256)
tokenURI(uint256)
getAgentWallet(uint256)
Registered(uint256,string,address)
```

Export:

```js
export const ERC8004_ABI = [];
export function registryNamespace() {}
export function identityReference(agentId) {}
export function buildRegistrationDocument({ displayName, address, agentId = null }) {}
export function registrationDataUri(document) {}
export function parseRegisteredAgentId(receipt) {}
```

The document type is
`https://eips.ethereum.org/EIPS/eip-8004#registration-v1`, advertises no live
MCP/A2A endpoint for the ephemeral demo agent, sets `x402Support: false`, and
sets `active: true`.

- [ ] **Step 4: Write failing RPC invariant tests with a mock viem client**

Cover:

```text
wrong chain id -> reject
empty registry bytecode -> reject
version other than 2.0.0 -> reject
nonzero sender nonce before registration -> reject
owner mismatch -> reject
agentWallet mismatch -> reject
tokenURI mismatch -> reject
```

- [ ] **Step 5: Implement the live registration adapter**

Export:

```js
export async function registerIdentity({
  privateKey,
  expectedAddress,
  displayName,
  rpcUrl,
  publicClient,
  walletClient,
}) {}
```

The ordered implementation:

1. Construct the account with `privateKeyToAccount`.
2. Assert the derived address matches the encrypted bundle.
3. Assert chain ID, registry bytecode, `getVersion()`, nonce, and balance.
4. Estimate and send `register(initialDataUri)`.
5. Wait for a successful receipt and decode exactly one `Registered` event.
6. Build final metadata containing the resulting `agentId`.
7. Estimate and send `setAgentURI(agentId, finalDataUri)`.
8. Wait for success.
9. Read `ownerOf`, `getAgentWallet`, and `tokenURI`.
10. Return only public evidence: address, full identity reference, agentId,
    transaction hashes, block numbers, and final registration document.

- [ ] **Step 6: Run focused tests**

Run: `node --test test/registration.test.mjs`

Expected: all registration tests pass with no network calls.

- [ ] **Step 7: Commit**

```bash
git add src/registration.mjs test/registration.test.mjs test/fixtures/registered-log.json
git commit -m "Bind demo agents to the official ERC-8004 registry" \
  -m "Constraint: The stakeholder wallet must remain the on-chain owner and agent wallet.
Rejected: Clockchain DID minting | The product consumes ERC-8004 identity instead of competing with it.
Confidence: high
Scope-risk: moderate
Tested: Metadata, event decoding, chain/contract checks, and owner-wallet-URI invariants.
Not-tested: Live registration waits for funded invitations."
```

### Task 4: Implement the hosted Clockchain MCP client

**Files:**
- Create: `src/mcp.mjs`
- Create: `test/mcp.test.mjs`
- Create: `test/fixtures/mcp-sse.txt`

- [ ] **Step 1: Write failing SSE parsing tests**

```js
import test from "node:test";
import assert from "node:assert/strict";
import { parseSseJsonRpc, parseToolResult } from "../src/mcp.mjs";

test("uses the final SSE data event and parses nested tool JSON", () => {
  const raw = "event: message\\ndata: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"content\":[{\"type\":\"text\",\"text\":\"{\\\\\"status\\\\\":\\\\\"active\\\\\"}\"}]}}\\n\\n";
  assert.deepEqual(parseToolResult(parseSseJsonRpc(raw)), { status: "active" });
});

test("rejects JSON-RPC errors", () => {
  assert.throws(() => parseSseJsonRpc('data: {\"jsonrpc\":\"2.0\",\"id\":1,\"error\":{\"message\":\"no\"}}\\n'), /no/);
});
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `node --test test/mcp.test.mjs`

Expected: FAIL with `ERR_MODULE_NOT_FOUND`.

- [ ] **Step 3: Implement token acquisition and JSON-RPC calls**

Export:

```js
export function parseSseJsonRpc(raw) {}
export function parseToolResult(jsonRpc) {}
export async function mintDemoToken({ fetchImpl = fetch, subject }) {}
export function createMcpClient({ token, fetchImpl = fetch }) {}
```

`createMcpClient` returns:

```js
{
  call: async (name, args) => {},
  resolveAgent: async (agentId) => {},
  getTimestamp: async () => {},
  attestAction: async (args) => {},
  completeAttestation: async (receipt) => {},
  verifyReceipt: async (receipt) => {},
  verifyCrossParty: async ({ ledgerId, blockHeight }) => {},
}
```

The client sends `accept: application/json, text/event-stream`, never exposes
the token in an error, fails immediately on 401/403, honors `Retry-After` on a
429 without minting another token, and retries only transient 5xx responses a
bounded two times.

- [ ] **Step 4: Add receipt-completion tests**

The mock responses prove:

```text
resolved identity must be active
attest_action pending -> complete_attestation polling
anchored receipt requires anchor.confirmed true and non-null blockHeight
verify_receipt must report match true
verify_cross_party must report verifiedAgainst on-chain block and keyless true
```

- [ ] **Step 5: Implement strict completion helpers**

Export:

```js
export function assertResolvedIdentity(identity, expected) {}
export function assertAnchoredReceipt(receipt) {}
export function assertReceiptVerification(result) {}
export function assertCrossPartyVerification(result) {}
export async function completeReceipt(client, receipt, { attempts = 8, intervalMs = 1500 } = {}) {}
```

- [ ] **Step 6: Run focused tests**

Run: `node --test test/mcp.test.mjs`

Expected: all MCP tests pass.

- [ ] **Step 7: Commit**

```bash
git add src/mcp.mjs test/mcp.test.mjs test/fixtures/mcp-sse.txt
git commit -m "Fail closed unless Clockchain confirms and re-verifies the receipt" \
  -m "Constraint: A submitted or cache-only record must never be narrated as success.
Confidence: high
Scope-risk: moderate
Directive: Preserve the distinction between keyless cryptographic verification and token-gated MCP transport.
Tested: SSE parsing, auth/rate-limit errors, pending polling, anchor, commitment, and on-chain verification gates."
```

### Task 5: Compose the runner and sanitized evidence

**Files:**
- Create: `src/evidence.mjs`
- Create: `src/run.mjs`
- Create: `bin/handshake-demo.mjs`
- Create: `test/evidence.test.mjs`
- Create: `test/run.test.mjs`

- [ ] **Step 1: Write failing result-schema tests**

The expected result shape is:

```js
{
  schema: "clockchain.handshake-result/v1",
  status: "PASS",
  runId: "uuid",
  startedAt: "RFC3339",
  completedAt: "RFC3339",
  elapsedMs: 1234,
  scenario: {
    action: "trust_handshake",
    amount: { value: "100", currency: "USD", moved: false },
    counterparty: "clockchain:handshake",
  },
  identity: {
    reference: "eip155:11155111:0x...:42",
    agentId: "42",
    displayName: "Billy",
    owner: "0x...",
    registerTx: "0x...",
    metadataTx: "0x...",
  },
  clockchain: {
    ledgerId: "uuid",
    blockHeight: "123",
    consensusTime: "Clockchain timestamp",
    receiptStatus: "anchored",
    receiptVerified: true,
    crossPartyVerified: true,
    verifiedAgainst: "on-chain block",
    keyless: true,
  },
  disclaimer: "Single-validator testnet: ...",
}
```

Tests reject missing transaction hashes, null block height, false verification,
or forbidden secret canaries.

- [ ] **Step 2: Implement evidence validation and Markdown rendering**

Export:

```js
export function validatePassResult(result) {}
export function renderResultMarkdown(result) {}
export async function writeEvidence({ directory, result, canaries }) {}
```

`writeEvidence` redacts first, asserts secret-free second, writes to temporary
files, re-reads and validates them, then atomically renames them to
`result.json` and `RESULT.md`.

- [ ] **Step 3: Write a failing orchestration test**

Use injected fake registration and MCP adapters. Assert this exact call order:

```text
decrypt -> register -> mint token -> resolve -> timestamp -> attest ->
complete if needed -> verify receipt -> verify cross-party -> write evidence
```

Assert no evidence is written after any failed stage.

- [ ] **Step 4: Implement `runHandshake`**

```js
export async function runHandshake({
  invitationFile,
  outputDirectory = process.cwd(),
  adapters = {},
  now = () => new Date(),
  randomUUID,
}) {}
```

The receipt inputs include:

```js
{
  runId,
  identityReference,
  counterparty: "clockchain:handshake",
  authorization: { amount: "100", currency: "USD", settlement: "not-executed" },
}
```

The outputs include:

```js
{
  decision: "approved-for-demo",
  scope: "identity-and-time-receipt-only",
  paymentMoved: false,
}
```

- [ ] **Step 5: Implement the CLI**

The CLI:

```text
requires HANDSHAKE_INVITE_FILE or --invite-file <path>
accepts --output <directory>
never accepts a private key, invite code, chain, registry, transfer, or RPC method
prints stage names and public transaction/receipt identifiers
prints PASS only after evidence is atomically written and validated
returns exit 0 on PASS, 2 on safe user/config error, 3 on network failure,
4 on protocol verification failure, and 5 on redaction failure
```

- [ ] **Step 6: Run focused and full tests**

Run:

```bash
node --test test/evidence.test.mjs test/run.test.mjs
npm test
```

Expected: all tests pass and no network request occurs.

- [ ] **Step 7: Commit**

```bash
git add src/evidence.mjs src/run.mjs bin/handshake-demo.mjs test/evidence.test.mjs test/run.test.mjs
git commit -m "Produce a receipt only after every identity and anchor check passes" \
  -m "Constraint: Stakeholders need a self-contained evidence artifact, not a success narrative.
Confidence: high
Scope-risk: moderate
Tested: Ordered orchestration, fail-closed stages, result schema, atomic writes, and secret-canary rejection."
```

### Task 6: Add operator invitation tooling

**Files:**
- Create: `scripts/create-invitations.mjs`
- Create: `scripts/check-invitations.mjs`
- Create: `test/operator-tools.test.mjs`
- Create: `invites/README.md`
- Generate: `invites/codex.enc.json`
- Generate: `invites/claude.enc.json`
- Generate outside Git: `.context/invitations/codex.secret.json`
- Generate outside Git: `.context/invitations/claude.secret.json`

- [ ] **Step 1: Write failing operator-tool tests**

Tests use a temporary directory and assert:

```text
two distinct wallets and invitation codes
public bundle contains address but no private key/code
secret file mode is 0600
secret file references the matching bundle
existing bundle paths are never overwritten without --force
```

- [ ] **Step 2: Implement deterministic operator interfaces**

`create-invitations.mjs` supports:

```text
--output-public invites
--output-secret .context/invitations
--names Billy,Iris
```

It uses `generatePrivateKey` and `privateKeyToAccount`, generates 32 random
bytes for each invitation code, encrypts with `encryptInvitation`, and prints
only bundle ID plus public address.

`check-invitations.mjs` reads public addresses only and reports:

```text
chain id
balance
nonce
official registry bytecode present
ready true only when nonce is 0 and balance is within the configured pilot range
```

- [ ] **Step 3: Run operator tests**

Run: `node --test test/operator-tools.test.mjs`

Expected: all tests pass.

- [ ] **Step 4: Generate the two real invitation bundles**

Run:

```bash
npm run invitations:create -- \
  --output-public invites \
  --output-secret .context/invitations \
  --names Billy,Iris
```

Expected:

```text
invites/codex.enc.json
invites/claude.enc.json
.context/invitations/codex.secret.json mode 0600
.context/invitations/claude.secret.json mode 0600
```

- [ ] **Step 5: Verify no secret is tracked**

Run:

```bash
git status --short
git grep -n -i 'privateKey\\|inviteCode' -- invites || true
git check-ignore -q .context/invitations/codex.secret.json
```

Expected: only encrypted public bundles are eligible for commit; secret files
are ignored.

- [ ] **Step 6: Commit**

```bash
git add scripts/create-invitations.mjs scripts/check-invitations.mjs test/operator-tools.test.mjs invites
git commit -m "Issue bounded testnet invitations without publishing wallet secrets" \
  -m "Constraint: Two stakeholders need independent funded wallets while using one public prompt.
Rejected: Public faucet during the run | It makes completion dependent on third-party login and rate limits.
Confidence: high
Scope-risk: moderate
Tested: Distinct wallets, authenticated encryption, secret-file permissions, overwrite refusal, and Git exclusion.
Not-tested: Funding and live consumption occur after platform preflight."
```

### Task 7: Publish the universal prompt and docs

**Files:**
- Create: `prompts/run-turnkey-demo.md`
- Create: `README.md`
- Create: `DEMO.md`
- Create: `scripts/check-docs.mjs`
- Create: `test/docs.test.mjs`

- [ ] **Step 1: Write failing documentation contract tests**

Tests assert that all three public documents:

```text
say Clockchain®
say single-validator testnet
say no money moves
say no AgentDash
do not say court-grade, trustless, mainnet, or consensus-secure as present capabilities
reference the official registry address
use the same demo command and result filenames
```

- [ ] **Step 2: Write the exact coding-agent prompt**

The prompt begins. `HANDSHAKE_REPO_URL` and `HANDSHAKE_REPO_REF` are optional
acceptance-only overrides; stakeholders use the public defaults:

```md
Run the Clockchain Agent Trust Handshake demo exactly as documented.

Work in a new temporary directory. Do not inspect or modify my current project.
Do not install or use AgentDash. Do not invent success states.

1. Clone `${HANDSHAKE_REPO_URL:-https://github.com/thetangstr/clockchain-handshake.git}`
   at `${HANDSHAKE_REPO_REF:-main}` with depth 1.
2. Read DEMO.md and follow its safety boundary.
3. Confirm HANDSHAKE_INVITE_FILE points to my separately delivered invitation file.
   Never print or open that file in chat; pass its path to the runner.
4. Run npm ci --ignore-scripts.
5. Run npm run demo.
6. Return only the sanitized RESULT.md summary and the paths to RESULT.md/result.json.
7. If any identity, anchor, or verification check fails, report the failed stage and
   do not call the demo successful.
```

- [ ] **Step 3: Write README and DEMO runbook**

`README.md` puts the prompt in one copyable fenced block. `DEMO.md` documents:

```text
Node 22 prerequisite
separate invitation delivery
testnet transactions that will occur
expected 30-90 second budget
exact PASS fields
rate-limit and RPC recovery
single-validator limitation
identity registration is not capability validation
no AgentDash/payment/ZK/Validation Registry writeback
```

- [ ] **Step 4: Implement doc checks**

`scripts/check-docs.mjs` loads the public documents, enforces required and
forbidden phrases, verifies relative links and referenced files, and exits
non-zero with exact failures.

- [ ] **Step 5: Run documentation verification**

Run:

```bash
node --test test/docs.test.mjs
npm run docs:check
```

Expected: all documentation checks pass.

- [ ] **Step 6: Commit**

```bash
git add README.md DEMO.md prompts scripts/check-docs.mjs test/docs.test.mjs
git commit -m "Give every coding agent one honest Handshake instruction set" \
  -m "Constraint: Codex and Claude must execute the same public instructions without AgentDash.
Confidence: high
Scope-risk: narrow
Directive: Keep public claims generated from the verified exercise boundary.
Tested: Required/forbidden claims, command parity, link integrity, and file references."
```

### Task 8: Add clean-client acceptance and independent verification

**Files:**
- Create: `scripts/run-clean-clients.mjs`
- Create: `scripts/verify-live-results.mjs`
- Create: `test/acceptance-harness.test.mjs`

- [ ] **Step 1: Write failing harness command tests**

Given temporary directories and fake executables, assert:

```text
Codex and Claude use different working directories
both receive identical prompt bytes
each receives only its own HANDSHAKE_INVITE_FILE path
timeouts terminate the child process group
stdout/stderr are saved after redaction
one failed client makes the aggregate verdict fail
```

- [ ] **Step 2: Implement the client harness**

The harness runs sequentially to avoid shared-IP token bursts:

```text
codex exec --ephemeral --skip-git-repo-check - < prompts/run-turnkey-demo.md
claude -p --no-session-persistence < prompts/run-turnkey-demo.md
```

It uses a minimal inherited environment allowlist plus:

```text
PATH
HOME
TMPDIR
HANDSHAKE_INVITE_FILE
HANDSHAKE_REPO_URL
HANDSHAKE_REPO_REF
```

Before the Handshake PR merges, the acceptance harness sets
`HANDSHAKE_REPO_REF` to the pushed feature branch. The published stakeholder
path omits both repository overrides and therefore consumes `main`.

It records prompt SHA-256, CLI version, start/end time, exit code, and result
paths. It never records the invite file content.

- [ ] **Step 3: Implement independent result verification**

For each `result.json`, `verify-live-results.mjs`:

1. Validates the local result schema and disclaimer.
2. Reads `ownerOf`, `getAgentWallet`, and `tokenURI` from Ethereum Sepolia.
3. Calls Clockchain `verify_cross_party` using a new demo token.
4. Compares every public identity/receipt field.
5. Scans the result directory for secret canaries.
6. Produces an aggregate `artifacts/acceptance-verdict.json`.

- [ ] **Step 4: Run deterministic harness tests**

Run: `node --test test/acceptance-harness.test.mjs`

Expected: all tests pass without launching real agents.

- [ ] **Step 5: Commit**

```bash
git add scripts/run-clean-clients.mjs scripts/verify-live-results.mjs test/acceptance-harness.test.mjs
git commit -m "Make client independence part of the Handshake acceptance test" \
  -m "Constraint: Native subagent success cannot substitute for actual Codex and Claude Code behavior.
Confidence: high
Scope-risk: moderate
Tested: Prompt identity, environment isolation, timeout cleanup, redacted logs, and aggregate failure semantics.
Not-tested: Live client runs require funded invitations."
```

### Task 9: Run full deterministic verification

**Files:**
- Modify only if verification exposes a defect

- [ ] **Step 1: Install from the lockfile**

Run: `rm -rf node_modules && npm ci --ignore-scripts`

Expected: clean install exits 0.

- [ ] **Step 2: Run all verification**

Run:

```bash
npm run verify
git diff --check
git status --short
```

Expected: all tests and docs checks pass; only intentional invitation bundles
or plan tracking changes remain.

- [ ] **Step 3: Run a security scan for forbidden material**

Run:

```bash
git grep -n -i -E 'BEGIN (RSA|EC|OPENSSH) PRIVATE KEY|0x[0-9a-fA-F]{64}|cc_[A-Za-z0-9_-]{20,}' -- ':!package-lock.json' || true
```

Expected: no real private key or Clockchain token appears. Test fixtures may use
explicit repeated-byte dummy values only inside test files.

- [ ] **Step 4: Commit any verification-only fixes**

Use a Lore commit that states the exact failed invariant and fresh command
evidence.

### Task 10: Execute the live stakeholder acceptance

**Files:**
- Generate outside Git: `artifacts/codex/*`
- Generate outside Git: `artifacts/claude/*`
- Generate outside Git: `artifacts/acceptance-verdict.json`

Prerequisite: complete
`docs/superpowers/plans/2026-07-22-official-erc8004-resolver.md`.

- [ ] **Step 1: Fund invitation wallets**

Use an official Ethereum Sepolia faucet or a testnet-only operator wallet.
Record funding transaction hashes under `.context/invitations/funding.json`.
Transfer only enough for `register` and `setAgentURI` plus bounded gas margin.

- [ ] **Step 2: Verify invitations are unused and ready**

Run: `npm run invitations:check`

Expected: both invitations report official chain/registry, nonce 0, and
`ready: true`.

- [ ] **Step 3: Run an operator live smoke test**

Use a third non-stakeholder invitation or a disposable operator wallet. Confirm
official registration, MCP resolution, anchored receipt, and both verification
paths before consuming stakeholder invitations.

- [ ] **Step 4: Run actual Codex and Claude Code clients**

Run:

```bash
npm run acceptance:clients -- \
  --codex-invite .context/invitations/codex.secret.json \
  --claude-invite .context/invitations/claude.secret.json
```

Expected: both clients exit 0 and create separate PASS artifacts.

- [ ] **Step 5: Independently re-verify both outputs**

Run: `npm run results:verify -- artifacts/codex/result.json artifacts/claude/result.json`

Expected: aggregate verdict `PASS`, distinct identity references, distinct
Clockchain ledger IDs and block heights, and no secret findings.

- [ ] **Step 6: Commit only public evidence**

Do not commit raw agent logs or stakeholder result files. Add a sanitized
`docs/demo-evidence/latest.md` containing:

```text
run date
prompt SHA-256
CLI versions
public identity transaction links
public Clockchain ledger/block identifiers
aggregate PASS
single-validator testnet disclaimer
```

Commit with a Lore message whose `Tested:` trailer lists the two actual client
commands and independent verifier.

### Task 11: Publish the stable GitHub instructions

**Files:**
- No new implementation files

- [ ] **Step 1: Run final verification from a clean checkout**

Clone the branch into a temporary directory and run:

```bash
npm ci --ignore-scripts
npm run verify
```

Expected: all checks pass without local-only files.

- [ ] **Step 2: Push and open the Handshake PR**

```bash
git push -u origin kailortang-prog/handshake-demo-plan
gh pr create --repo thetangstr/clockchain-handshake --base main \
  --head kailortang-prog/handshake-demo-plan \
  --title "Make the Handshake demo executable from one prompt" \
  --body-file .context/handshake-pr.md
```

- [ ] **Step 3: Require green checks and review the GitHub rendering**

Verify the README copy block, relative links, invitation downloads, and raw
prompt URL directly on the PR.

- [ ] **Step 4: Merge and re-run from `origin/main`**

After checks pass, squash-merge the PR. Create two new empty directories,
fetch the raw prompt from `main`, and run a non-writing preflight to prove the
published paths resolve.

- [ ] **Step 5: Record the stable stakeholder handoff**

The final handoff contains:

```text
GitHub README URL
raw prompt URL
separate secure delivery instruction for each invitation file
expected duration
testnet disclaimer
support/retry instruction
```
