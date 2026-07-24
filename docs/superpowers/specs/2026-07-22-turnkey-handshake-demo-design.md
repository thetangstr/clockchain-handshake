# Turnkey Agent Trust Handshake demo

Date: 2026-07-22

Status: Approved for implementation by the `/goal` directive

## Outcome

The first standalone Handshake milestone is a CLI-first, independently verifiable
stakeholder exercise. A stakeholder opens the public GitHub page, copies one prompt
into Codex or Claude Code, supplies a separately delivered testnet invitation, and
receives a fresh ERC-8004 identity plus a fresh Clockchain® Agent Attested Receipt.

The same public prompt must work in both coding agents. AgentDash is not installed,
called, displayed, or required.

This milestone precedes UI extraction from Research. It establishes the canonical
facts, protocol boundary, evidence format, and repeatable live flow before any old
page or component is copied into this repository.

## Turnkey acceptance contract

A run passes only when all of the following are true:

1. It starts in a new temporary directory with no Handshake checkout, project
   instructions, Clockchain token, or prior run artifacts.
2. It follows the prompt published in this repository without private operator
   instructions.
3. It decrypts a testnet-only invitation locally without printing the invitation
   secret or wallet private key.
4. It registers a new identity in the official ERC-8004 Identity Registry on
   Ethereum Sepolia.
5. It proves that `ownerOf(agentId)` equals the invitation wallet and that
   `tokenURI(agentId)` matches the registration document produced by the run.
6. Clockchain's hosted MCP independently resolves the same numeric `agentId`
   against that official registry.
7. It creates a fresh `trust_handshake` receipt with a unique run identifier.
8. The receipt reaches an anchored state with a non-null block height and
   independently attested consensus time.
9. `verify_receipt` recomputes the receipt commitment successfully.
10. `verify_cross_party` verifies against the immutable on-chain block and reports
    `keyless: true`. The hosted MCP transport still uses a demo token; “keyless”
    describes the cryptographic verification path, not anonymous HTTP access.
11. It writes a sanitized `result.json` and human-readable `RESULT.md` containing
    transaction links, identity references, receipt identifiers, block evidence,
    verification results, elapsed time, and the required testnet disclaimer.
12. Neither artifact contains an invitation, wallet private key, decrypted
    keystore, Clockchain demo token, authorization header, or unrelated environment
    value.

The final acceptance run uses the actual locally installed `codex exec` and
`claude -p` CLIs in separate temporary directories. Native subagents are useful
for implementation, but do not substitute for this client-level test.

## Canonical truth for this exercise

### Identity

ERC-8004 supplies the durable “who.” The demo targets the official Ethereum
Sepolia Identity Registry:

```text
chain: Ethereum Sepolia
chainId: 11155111
registry: 0x8004A818BFB912233c491871b3d84c89A494BD9e
identity reference: eip155:11155111:<registry>:<agentId>
```

Registration creates an ERC-721 identity owned by the stakeholder's invitation
wallet. Registration proves wallet ownership and metadata linkage. It does not
prove that advertised agent capabilities are safe, accurate, or trustworthy.

The existing legacy registry at `0x7177…` is not used for new demo identities.
Clockchain's hosted MCP is temporarily configured through a reversible Cloud Run
environment override, and the corrected official default is then committed to
`clockchain-developer-tools`.

### Receipt

Clockchain supplies the independently timed “what happened and when.” The exercise
uses:

```text
resolve_agent
get_timestamp
attest_action
complete_attestation, when polling is required
verify_receipt
verify_cross_party
```

Every write uses a unique run identifier and waits for confirmation. A submitted,
pending, degraded-without-a-block, or cache-only record is a failed demo, not a
partial success.

Clockchain currently runs a single-validator testnet. The artifacts must say
“single-validator testnet” and “anchored and independently re-verifiable.” They
must not say court-grade, consensus-secure, trustless, production-ready, or
mainnet.

### Scenario

The exercise records a `$100 authorization handshake` between a newly registered
stakeholder agent and the fixed demonstration counterparty `clockchain:handshake`.
No money moves. The amount is scenario data committed into the receipt, not an
x402 settlement.

The exercise does not claim that a hidden transaction limit was proven. The
server-side Semaphore/Groth16 work is a separate application-side capability; the
specific `amount <= private limit` predicate is not part of this turnkey milestone.

Canonical names are `Billy` and `Iris`. The run assigns one of those display names
from its invitation metadata while keeping the cryptographic identity equal to the
fully qualified ERC-8004 reference.

## Approaches considered

### 1. Pre-funded encrypted invitation bundles

Selected for the two-stakeholder milestone.

An operator setup command creates two testnet-only wallets, derives an encryption
key from each random high-entropy invitation secret with `scrypt`, encrypts the
wallet as an AES-256-GCM invitation bundle, and funds each address with only enough
Sepolia ETH for registration and metadata finalization. Encrypted bundles may be
published; invitation secrets are delivered out of band.

The runner decrypts only in memory, never prints the key, and does not persist a
plaintext keystore. The wallet begins with no mainnet assets and is never reused
outside this exercise.

Trade-off: this is turnkey for the two invited stakeholders, not permissionless
public onboarding.

### 2. One-use faucet broker

Deferred until the demo needs public self-service.

A dedicated broker could transactionally redeem hashed stakeholder vouchers and
call a supported testnet faucet API for a locally generated address. This preserves
local ownership but adds an external provider account, secrets, durable claim
storage, abuse controls, monitoring, and another deployed service.

### 3. Manual faucet or bring-your-own wallet

Rejected for the primary exercise. It removes infrastructure but introduces an
unbounded human pause, third-party login requirements, faucet rate limits, and
private-key handling differences between stakeholders.

## Components and ownership

### Public GitHub surface

The Handshake repository owns:

- `README.md`, which explains the exercise and exposes the universal copy/paste
  prompt.
- `DEMO.md`, which states prerequisites, evidence fields, honesty constraints, and
  troubleshooting.
- `prompts/run-turnkey-demo.md`, the exact prompt used by both client acceptance
  tests.
- `invites/*.enc.json`, encrypted testnet-only invitation bundles with no plaintext
  secret or private key.

### Local runner

The Handshake repository owns a small Node.js command-line application:

- Configuration and invariant checks.
- Invitation decryption and secret redaction.
- ERC-8004 registration, event decoding, metadata finalization, and read-back
  verification.
- Hosted Clockchain MCP token acquisition and SSE JSON-RPC calls.
- Receipt creation, completion, and both verification paths.
- Sanitized evidence output and deterministic exit codes.

The runner uses Node.js 22 and `viem`. It pins the chain, registry address, ABI
fragments, MCP endpoint, output schema, and testnet-only safety checks. It does not
accept arbitrary chains, registries, RPC methods, contract calls, or transfer
destinations.

### Operator invitation tooling

Operator-only commands generate encrypted bundles, print the public wallet
addresses, and validate that funding is sufficient. Generated invitation secrets
are written only to a gitignored operator artifact under `.context/`.

Funding the two wallets is an operator setup action. The setup report records only
wallet addresses, balances, and funding transaction hashes.

### Platform dependency

`thetangstr/clockchain-developer-tools` owns the hosted MCP resolver and receipt
implementation. The demo repository does not copy or fork that implementation.

The immediate platform change is a reversible Cloud Run environment override that
sets the official registry address. The durable source change updates the default,
tests it, and ships through the existing GitHub Actions build/test/deploy gate from
a clean `origin/main` checkout.

## Data flow

```text
GitHub prompt
    |
    v
clean Codex or Claude Code process
    |
    +--> clone Handshake into a temporary directory
    +--> read invitation secret without echoing it
    +--> decrypt testnet wallet in memory
    +--> verify chain id + official registry bytecode
    +--> register ERC-8004 identity
    +--> finalize metadata + verify owner/URI/wallet
    +--> mint one public Clockchain demo transport token
    +--> resolve the new agentId through Clockchain MCP
    +--> fetch Clockchain time
    +--> create + confirm a unique trust_handshake receipt
    +--> verify receipt commitment
    +--> verify against the immutable Clockchain block
    +--> redact secrets and write result.json + RESULT.md
```

Each run is independent. The Codex run and Claude run do not share wallets,
identities, demo tokens, temporary directories, result files, or run identifiers.

## Security boundaries

- Testnet only: the runner exits unless chain ID is `11155111`.
- Registry allowlist: only the official configured ERC-8004 registry is callable.
- Contract method allowlist: only registration, URI finalization, and required
  read-back calls are available.
- No arbitrary value transfer is exposed by the stakeholder runner.
- Invitation secrets are read through hidden input or a dedicated file descriptor;
  they are not accepted as command-line arguments.
- Decrypted keys exist only in process memory.
- Output redaction traverses all result and error objects before persistence.
- Git ignores operator secrets, plaintext wallets, MCP tokens, temporary results,
  and `.context/`.
- Tests include high-entropy secret canaries and fail if a canary reaches logs or
  artifacts.
- The runner refuses wallets with unexpected existing transaction history or
  non-testnet funding above the configured pilot ceiling.
- The public prompt authorizes only the documented testnet identity and Clockchain
  writes. It does not grant the coding agent general wallet authority.

## Error handling

The CLI exits non-zero and withholds PASS when any of these occur:

- Invitation authentication or decryption fails.
- Wallet address does not match the encrypted bundle.
- RPC chain ID, registry bytecode, or registry interface check differs.
- Available balance cannot cover the estimated registration flow with margin.
- Registration or URI-finalization receipt reverts or times out.
- The emitted `agentId`, owner, agent wallet, or URI fails read-back verification.
- Clockchain token minting is rate-limited and no safe cached token exists.
- Clockchain resolves the new identity as unknown or to a different owner/URI.
- Validator-pool health is degraded and the write is not explicitly marked
  `allow_degraded`.
- Clockchain returns a null block height, unconfirmed anchor, mismatched commitment,
  or verification source other than the on-chain block.
- Redaction detects a forbidden secret in a pending artifact.

Failures produce a sanitized diagnostic report with the failed stage and safe
recovery instruction. The runner never changes a failure into a green narrative.

## Agent orchestration contract

Project-local Codex configuration uses:

- `gpt-5.6-sol` for the primary planner, orchestrator, synthesizer, and verifier.
- `gpt-5.6-terra` for substantive scoped implementation.
- `gpt-5.6-luna` for read-only exploration and small explicit low-risk edits.

`AGENTS.md`, `.codex/config.toml`, and `.codex/agents/*.toml` make this routing
durable. The primary agent owns the plan, shared-file assignments, integration,
fresh verification, and final verdict.

Claude Code receives equivalent role instructions through `CLAUDE.md` and
`.claude/agents/*.md`, using its native model tiers. Claude cannot natively select
Codex GPT model identifiers unless its configured provider exposes those models.

Conductor repository settings provide setup and verification commands but do not
claim to enforce repository-level model defaults, which Conductor does not support.

## Testing

### Deterministic tests

- Invitation encryption/decryption and tamper rejection.
- Secret and token redaction, including nested errors.
- ERC-8004 registration document construction and event decoding.
- Chain, registry, owner, wallet, and URI invariant checks.
- Clockchain SSE response parsing and JSON-RPC error handling.
- Pending-to-anchored receipt polling.
- Result schema validation and Markdown rendering.
- Fail-closed behavior for every completion gate.

### Mock integration test

A local HTTP fixture simulates Ethereum JSON-RPC and Clockchain MCP responses. It
exercises the complete runner without network writes and proves deterministic
failure behavior.

### Live platform smoke test

Before consuming stakeholder invitations:

1. Confirm Cloud Run health.
2. Confirm `resolve_agent` resolves a known identity from the official registry.
3. Mint a no-signup Clockchain demo token.
4. Create and independently verify one operator smoke receipt.

### Clean-client acceptance test

Run the public prompt unchanged in:

1. `codex exec` from a fresh temporary directory with invitation A.
2. `claude -p` from a different fresh temporary directory with invitation B.

Sol then independently validates both result files against live Ethereum and
Clockchain reads. Both must pass before the demo is called turnkey.

## Deployment and rollback

The Handshake deliverable is published on the repository's default branch, so the
README and raw prompt URLs are stable.

The initial MCP resolver change uses a Cloud Run environment-only revision. It
preserves existing secrets and can be rolled back by restoring traffic to revision
`clockchain-mcp-00010-w5b`.

The durable developer-tools change is merged only after build and tests pass. Its
existing workflow deploys from `main` and preserves service environment overrides.
No deploy is sourced from the dirty network-volume checkout.

## Explicit exclusions

This milestone does not include:

- AgentDash or Paperclip.
- UI extraction from Research.
- AP2, x402, card, USDC, or other settlement.
- Transfer of the scenario's `$100`.
- A private-limit ZK predicate.
- ERC-8004 Validation Registry writeback.
- A public faucet broker or account-abstraction paymaster.
- Mainnet, multi-validator, court-grade, consensus-secure, or trustless claims.

These exclusions keep the first stakeholder exercise real, reproducible, and
auditable instead of presenting a larger narrated stack as shipped software.

## Completion criteria

The milestone is complete only when:

1. Canonical truth and scope are documented without the known Handshake
   contradictions.
2. The repository contains no copied Research runtime or AgentDash dependency.
3. Project model routing and Conductor commands are committed and validated.
4. The official ERC-8004 registry resolves through the hosted MCP.
5. Two encrypted, funded, testnet-only invitations exist and their secrets remain
   outside Git.
6. Unit, mock integration, build, security-redaction, and documentation checks pass.
7. The public GitHub prompt works unchanged in clean Codex and Claude Code sessions.
8. Each session creates a different new ERC-8004 identity and a different fresh
   anchored Clockchain receipt.
9. Both evidence packages independently re-verify and contain no secret material.
10. The default branch exposes stable README and prompt URLs suitable for sending
    directly to the two stakeholders.
