# Handshake demo runbook

This runbook defines the safety boundary and evidence contract for the
Clockchain® Agent Trust Handshake exercise. Use the
[published universal prompt](prompts/run-turnkey-demo.md) from a clean coding-agent
session. The [README](README.md) provides the one-block copy surface, and the
[invitation notes](invites/README.md) explain how disposable bundles are handled.
The public evidence is available as a
[sanitized recovery evidence summary](docs/demo-evidence/latest.md).

## Operator-only clean-client acceptance

The stakeholder `npm run demo` path is unaffected. Do not direct stakeholders to
this operator-only harness.

`npm run acceptance:clients` deliberately launches Codex and Claude with
permission-bypass flags. It inherits selected local auth material, the real
`HOME`, and each invitation path. Its temporary directories are not an OS or
container sandbox.

`npm run acceptance:clients` is supported on macOS and Linux only. The core
`npm run demo` stakeholder flow remains platform-neutral.

Redaction protects captured artifacts after the clients execute, but it cannot
prevent a malicious or compromised client from reading or exfiltrating accessible
data. Run it only with a trusted repository commit, trusted prompt, and trusted
invitations.

Operator command:

```sh
npm run acceptance:clients -- --codex-invite /trusted/codex.secret.json --claude-invite /trusted/claude.secret.json --repo-ref COMMIT_SHA --acknowledge-agent-permission-risk
```

Do not encourage stakeholders to use it.

## Safety boundary

This is an Ethereum Sepolia and Clockchain® single-validator testnet exercise.
No money moves. Do not install or use AgentDash. It is not mainnet, court-grade,
consensus-secure, or trustless.

The only Ethereum write target is the official ERC-8004 Identity Registry:
`0x8004A818BFB912233c491871b3d84c89A494BD9e` on chain ID `11155111`.
The stakeholder runner can register an identity and finalize its metadata; it
cannot choose another chain, registry, contract method, or value-transfer
destination.

The `$100 authorization handshake` is receipt scenario data. It is not a payment,
settlement, or proof of a hidden spending limit. The run performs no AP2, x402,
card, USDC, private-limit ZK, or ERC-8004 Validation Registry writeback.

## Prerequisites

- Node.js 22 and npm must be available.
- Run in a new temporary directory, not inside another project.
- The stakeholder must receive a unique invitation file through a separate,
  private delivery channel. Set its path in `HANDSHAKE_INVITE_FILE` before the
  coding agent starts. Never paste the file, invitation code, or its contents
  into chat.
- The machine needs outbound HTTPS access to the pinned Ethereum Sepolia RPC,
  GitHub, and the hosted Clockchain MCP service.
- The disposable invitation wallet must already hold from `0.005` through `0.02`
  Sepolia ETH, inclusive, as described in the invitation notes. The runner reads
  this fresh balance immediately before its first chain write and stops outside
  that range.

No Clockchain token is supplied by the stakeholder. The runner mints one ephemeral
demo transport token and keeps it out of logs and evidence.

## What the run does

`npm run demo` performs the following ordered checks and actions:

1. Opens the separately delivered invitation safely, authenticates it, and
   decrypts the disposable testnet key in process memory.
2. Confirms Ethereum Sepolia, deployed bytecode, ERC-8004 version `2.0.0`, wallet
   ownership, a zero starting nonce, and a fresh balance within the inclusive
   `0.005`–`0.02` Sepolia ETH pilot range immediately before the first write.
3. Sends one `register(string)` transaction and one `setAgentURI` transaction to
   the official registry, then reads back owner, agent wallet, and token URI.
4. Resolves the resulting numeric agent ID through Clockchain®, obtains an
   independently attested timestamp, and submits a unique `trust_handshake`
   receipt.
5. Waits for a confirmed non-null Clockchain block anchor and consensus time,
   recomputes the receipt commitment, and verifies it against the immutable
   on-chain block through the keyless verification path.
6. Applies the secret-redaction gate and writes `result.json` plus `RESULT.md`.

Registration proves control of the invitation wallet and the linkage of the
published metadata. ERC-8004 registration does not validate the agent's advertised
capabilities, safety, accuracy, or trustworthiness.

## PASS evidence

The terminal prints `PASS` only after both artifacts have been written, read back,
and validated. `result.json` must contain:

- schema `clockchain.handshake-result/v1`, status `PASS`, a unique run ID, start
  and completion timestamps, and elapsed milliseconds;
- scenario action `trust_handshake`, counterparty `clockchain:handshake`, amount
  `100 USD`, and `moved: false`;
- the full ERC-8004 identity reference, numeric agent ID, display name, owner,
  registration transaction, and metadata transaction;
- the Clockchain ledger ID, non-null decimal block height, consensus time,
  `anchored` receipt status, successful commitment and cross-party verification,
  `on-chain block` verification source, `keyless: true`, and validator-pool
  health captured at submission; and
- the single-validator testnet disclaimer.

`RESULT.md` presents the same sanitized facts for a human reader, including
Sepolia transaction links. Neither artifact may contain an invitation code,
private key, encrypted keystore, authorization header, Clockchain token, or
unrelated environment value. A transaction hash, pending receipt, unconfirmed
anchor, degraded record without a block, or agent narrative is not PASS evidence.

## Timing and bounded recovery

A healthy live run normally takes 30–90 seconds. Ethereum confirmation time,
public RPC load, and Clockchain token rate limits can extend that budget. Read
operations use bounded retries; receipt writes are single-shot so an ambiguous
network response cannot silently create a duplicate.

That 30–90 second figure describes a healthy run, not the ceiling. Receipt
completion carries an explicit elapsed-time budget of 120 seconds, and the poll
already in flight when that budget is crossed adds a 1.5 second poll interval
plus one bounded transport call of at most 102 seconds. A throttled
receipt-completion stage is therefore bounded at 223.5 seconds, roughly
3 minutes 43 seconds, and then fails closed as
`HANDSHAKE_RECEIPT_COMPLETION_FAILED` with exit `4`. Other stages carry their own
bounded waits. Do not stop the process at 90 seconds; wait for the terminal
`PASS` line or the `FAILED [CODE]` line.

On a public RPC or token rate-limit failure before receipt submission, preserve
the temporary directory and its `.handshake-registration-recovery.json` file.
That file holds either the pre-broadcast registration intent recorded before the
first Ethereum write or the public checkpoint recorded after it; both are public
records, and deleting either one can strand an already-broadcast registration.
Wait 30 seconds, then run `npm run demo` once more in that same directory with the
same `HANDSHAKE_INVITE_FILE`. The runner verifies the public checkpoint against
Ethereum before resuming and does not repeat a confirmed registration.

If that one recovery attempt fails, or the public failure code names attestation,
receipt completion, receipt verification, or cross-party verification, stop.
Those stages begin at or after the single-shot receipt write, so a blind rerun
could record another action. Do not delete the checkpoint, submit a manual
transaction, change the registry or RPC target, or claim success. Preserve only
the public failure code and ask the operator to inspect live state before another
write.

## Failure codes

A failed run prints the machine-readable line `FAILED [CODE]` and then one
`Hint:` line for the operator. The process exit code follows the failure
category: `2` configuration, `3` network, `4` protocol or verification, and `5`
redaction. The table lists the exit each code normally produces. A stage that
fails through a differently typed cause exits with that cause's category
instead, so a redaction fault while writing evidence exits `5` while still
reporting `HANDSHAKE_EVIDENCE_FAILED`.

| Code | Cause | Exit | Next action |
| --- | --- | --- | --- |
| `HANDSHAKE_CONFIGURATION` | Invalid arguments, invitation environment value, or an output path that is not a usable directory. | 2 | Correct the invocation, name a usable output directory, and start the run again. |
| `HANDSHAKE_INVITATION_READ_FAILED` | The invitation file could not be read safely. | 2 | Ask the operator to confirm its path and permissions; do not open the file. |
| `HANDSHAKE_INVITATION_DECRYPTION_FAILED` | The invitation failed local authentication. | 2 | Ask the operator for a fresh invitation. |
| `HANDSHAKE_OUTPUT_DIRECTORY_IN_USE` | The directory already holds result.json or RESULT.md from an earlier run. | 2 | Start again in a new empty directory; the existing evidence was left untouched and no chain or receipt write happened. |
| `HANDSHAKE_REGISTRATION_RECOVERY_FAILED` | The public checkpoint could not be written or read back. | 2 | Keep the directory and ask the operator to inspect it. |
| `HANDSHAKE_REGISTRATION_FAILED` | The Ethereum identity write did not complete. | 4 | Keep the directory, wait 30 seconds, then run once more here. |
| `HANDSHAKE_TOKEN_MINT_FAILED` | The ephemeral Clockchain token was refused or rate limited. | 3 | Keep the directory, wait 30 seconds, then run once more here. |
| `HANDSHAKE_MCP_CLIENT_FAILED` | The Clockchain client could not be prepared. | 2 | Confirm outbound HTTPS access, then run once more here. |
| `HANDSHAKE_IDENTITY_RESOLUTION_FAILED` | Clockchain did not resolve the registered identity as expected. | 4 | Stop and ask the operator to inspect live state. |
| `HANDSHAKE_TIMESTAMP_FAILED` | Clockchain consensus time was unavailable. | 3 | Keep the directory, wait 30 seconds, then run once more here. |
| `HANDSHAKE_ATTESTATION_FAILED` | The single-shot receipt write failed or had already started in this directory, so a receipt may exist. | 4 | Stop and ask the operator to inspect live state before any further write. |
| `HANDSHAKE_RECEIPT_COMPLETION_FAILED` | The receipt reached no confirmed block anchor. | 4 | Stop and ask the operator to inspect the receipt. |
| `HANDSHAKE_RECEIPT_VERIFICATION_FAILED` | The recomputed commitment did not match the recorded receipt. | 4 | Stop, ask the operator to inspect the receipt, and do not rerun. |
| `HANDSHAKE_CROSS_PARTY_VERIFICATION_FAILED` | Verification against the immutable block failed. | 4 | Stop, ask the operator to inspect the block, and do not rerun. |
| `HANDSHAKE_EVIDENCE_FAILED` | Sanitized evidence failed validation or could not be written into the prepared output directory. | 4 | Keep the directory, report the code, and do not call the run successful. |
| `HANDSHAKE_STAGE_FAILED` | The runner reported an unknown stage. | 4 | Treat it as a defect and report the terminal output. |
| `HANDSHAKE_UNEXPECTED_FAILURE` | The runner raised an untyped error. | 4 | Treat it as a defect and report the terminal output. |

No code is evidence of success, and no code discloses an invitation, key, or
token.

## Interpretation

Clockchain currently has one testnet validator. “Anchored and independently
re-verifiable” means another reader can recompute the commitment and inspect the
recorded block; it does not turn the current testnet into a multi-validator
security guarantee.

The run submits the `trust_handshake` receipt with `allow_degraded: true`.
Deployed Clockchain write tools refuse a degraded validator pool by default; this
demo opts in, so it writes the receipt even when the pool reports one node and
zero node participation. `result.json` records the pool health observed at
submission, including `totalNodes`, `nodeParticipationPct`, and
`degradedAtSubmission`. An anchored receipt still means the commitment is
recorded in an immutable block and can be re-verified independently by another
reader; it does not mean the anchor carries multi-validator consensus strength.

The `keyless` result describes receipt verification against public block data. It
does not mean anonymous access to the hosted MCP transport, and it does not grant
authority over the ERC-8004 wallet.
