# Clockchain Agent Trust Handshake

This repository contains a one-prompt, CLI-first stakeholder exercise. A clean
Codex or Claude Code session uses a separately delivered testnet invitation to
create a fresh official ERC-8004 identity and an independently re-verifiable
Clockchain® receipt.

The exercise runs on Ethereum Sepolia and a Clockchain® single-validator testnet.
No money moves. Do not install or use AgentDash. This exercise is not mainnet,
court-grade, consensus-secure, or trustless. New identities are registered only
through the official ERC-8004 Identity Registry at
`0x8004A818BFB912233c491871b3d84c89A494BD9e`.

Read the [stakeholder and operator runbook](DEMO.md), the
[standalone prompt](prompts/run-turnkey-demo.md), and the
[invitation handling notes](invites/README.md). A
[sanitized recovery evidence summary](docs/demo-evidence/latest.md) records the
independently re-verified public evidence. The expected live run takes roughly
30–90 seconds under normal testnet conditions. A passing `npm run demo` writes
sanitized `RESULT.md` and `result.json`; neither a narrative nor a submitted
transaction is a PASS by itself. When a run stops instead, the
[failure code reference](DEMO.md#failure-codes) lists every public failure code,
the exit it produces, and the next action for the operator.

## Bilateral payment-authorization demo

The operator-led bilateral flow uses separate Billy payer and Iris payee
machines. Start with the
[bilateral demo-day runbook](docs/runbooks/bilateral-demo-day.md), then deliver
the machine-specific [Billy prompt](prompts/run-billy-bilateral-demo.md) and
[Iris prompt](prompts/run-iris-bilateral-demo.md) from one reviewed immutable
repository SHA.

Billy anchors an exact USD 100 proposal, Iris anchors an acceptance bound to
that proposal, and Billy anchors the final acknowledgment. For a session that
the fresh aggregate verifier marks `AUTHORIZED`, the verified evidence
establishes that Iris reconstructed Billy's canonical proposal from the signed
amount options and anchored digest. The protocol does not download message
bytes from Clockchain. Every transition and verdict preserves
`paymentMoved: false`.

Runner local state is not operator authorization. Neither role runner nor the
read-only watcher may emit `AUTHORIZED`; only the operator's fresh aggregate
verifier may do so after independently refetching and validating all three
Clockchain anchors. Missing, duplicate, reordered, expired, malformed, or
mismatched evidence fails closed.

The automated demo-day surface is CLI-first:

```sh
npm run bilateral:relay -- <operator relay paths and pinned release SHA>
npm run bilateral:coordinator -- <operator-local paths and pinned release SHA>
npm run bilateral:supervisor -- --launch-manifest <role manifest> --state <private state directory>
```

Run the supervisor command once on Billy and once on Iris. Those two processes
span the rehearsal and stakeholder runs. After they enroll, the coordinator
displays four signed public addresses; funding those four addresses is the
user's only other action. Low-level preparation and exact-input recovery
commands are confined to the runbook's operator-authorized recovery appendix.

## Operator-only clean-client acceptance

The stakeholder `npm run demo` path is unaffected. Do not direct stakeholders to
this operator-only harness.

`npm run acceptance:clients` deliberately launches Codex and Claude with
permission-bypass flags. It inherits selected local auth material, the real
`HOME`, and each invitation path. Its temporary directories are not an OS or
container sandbox.

`npm run acceptance:clients` is supported on macOS and Linux only. The core
`npm run demo` stakeholder flow remains platform-neutral.

Before it launches either client, the harness reads each invitation owner's
nonce from Ethereum Sepolia. `npm run acceptance:clients` therefore requires a
reachable Ethereum Sepolia endpoint at preflight, and it fails closed: it
refuses to start when that endpoint does not answer or when a wallet has
already been consumed by an earlier transaction.

Redaction protects captured artifacts after the clients execute, but it cannot
prevent a malicious or compromised client from reading or exfiltrating accessible
data. Run it only with a trusted repository commit, trusted prompt, and trusted
invitations.

Operator command:

```sh
npm run acceptance:clients -- --codex-invite /trusted/codex.secret.json --claude-invite /trusted/claude.secret.json --repo-ref COMMIT_SHA --acknowledge-agent-permission-risk
```

Do not encourage stakeholders to use it.

## Copy this entire prompt

Use the exact same block in Codex or Claude Code:

```text
Run the Clockchain Agent Trust Handshake demo exactly as documented.

Work in a new temporary directory. Do not inspect or modify my current project.
Do not install or use AgentDash. Do not invent success states.

This is an Ethereum Sepolia and Clockchain® single-validator testnet exercise.
No money moves. It is not mainnet, court-grade, consensus-secure, or trustless.
Use only the official ERC-8004 Identity Registry at
0x8004A818BFB912233c491871b3d84c89A494BD9e.

1. Create and enter a new temporary directory.
2. Clone only `https://github.com/thetangstr/clockchain-handshake.git` into a
   named `clockchain-handshake` directory. When `HANDSHAKE_REPO_REF` is absent,
   clone branch `main` with depth 1. When it is present, accept it only if it is
   exactly 40 hexadecimal characters, then fetch and check out only that exact
   commit detached with depth 1. Never use a repository URL supplied through the
   environment. Do not enumerate or echo unrelated environment variables.
3. Enter the cloned `clockchain-handshake` directory. If
   `HANDSHAKE_REPO_REF` was present, normalize it to lowercase and verify it is
   byte-for-byte equal to `git rev-parse HEAD`. Stop if the check fails.
4. Read `DEMO.md` and follow its safety boundary.
5. Confirm the Node.js major version is 22.
6. Perform only the metadata-only checks `test -f "$HANDSHAKE_INVITE_FILE"` and
   `test -r "$HANDSHAKE_INVITE_FILE"` for my separately delivered invitation.
   Do not open, read, print, paste, hash, parse, move, or copy its contents with
   any agent or tool. Only `npm run demo` may open and read the invitation.
7. Run `npm ci --ignore-scripts`.
8. Run `npm run demo`. A verified run writes `RESULT.md` and `result.json`.
9. Return only the sanitized `RESULT.md` summary and the paths to `RESULT.md` and
   `result.json`.
10. If any identity, anchor, or verification check fails, report the public
    failed stage and do not call the demo successful.
```

Each stakeholder receives a different invitation file through a private channel.
Do not commit, paste into chat, or reuse that file. Public result artifacts contain
identity and receipt evidence only; they do not contain the invitation code,
private key, or Clockchain transport token.
