# Run the Payer role

You are the Payer. Say that role out loud and confirm the reviewed immutable
40-character SHA before creating or receiving private material. Stay in this
role for the entire run.

Use a locally installed ChatGPT Codex, Claude Code, or Hermes agent on macOS,
Windows, or Linux. Web-only ChatGPT and Claude sessions are unsupported because
this role needs a local working folder, shell, private filesystem, and one
long-lived process.

This is an Ethereum Sepolia and Clockchain single-validator testnet exercise.
No money moves. Do not install or use AgentDash. Do not invent success states.
It is not mainnet, court-grade, consensus-secure, trustless, production-ready,
or multi-validator. Every protocol and verdict artifact preserves
`paymentMoved:false`.

## What you receive

Accept only these public inputs:

- `BILATERAL_REPOSITORY_SHA`: the reviewed immutable 40-character SHA.
- `PAYER_DISCOVERY_URL`: the operator-signed public discovery URL for Payer.

Do not accept a launch manifest, invitation, token, capability, certificate,
private key, private path, or evidence attachment. The one-shot wrapper obtains
sealed role material only after the operator approves your public claim
fingerprint.

## Prepare the reviewed release

1. Confirm: “I am the Payer. I will not act as Requestor.”
2. Clone only `https://github.com/thetangstr/clockchain-handshake.git`.
3. Fetch the exact `BILATERAL_REPOSITORY_SHA`, check it out detached, and require
   a clean working tree.
4. Require Node.js 22.
5. Run `npm ci --ignore-scripts`.

Do all five checks before the wrapper creates private state. Stop if the role,
repository, SHA, detached state, clean state, Node version, package install, or
signed discovery validation fails.

## Choose private state and start once

Set `PAYER_STATE_ROOT` to a new role-specific absolute path. On macOS/Linux,
choose it below
`${XDG_STATE_HOME:-$HOME/.local/state}/clockchain-handshake/`. On Windows,
choose it below
`$env:LOCALAPPDATA\Clockchain\Handshake\`. Do not reuse a state root from
another role or run. The wrapper creates and verifies the required private mode
or Windows ACL.

From the clean detached checkout, run exactly one long-lived role command:

```sh
npm run bilateral:payer -- --discovery-url "$PAYER_DISCOVERY_URL" --state "$PAYER_STATE_ROOT"
```

Remain attached. Do not start a second wrapper if it is still running. If it
exits, preserve the state root and report the public failure status.

## Explain business progress

Translate each secret-free status into plain business progress:

- claim pending: your machine is asking the operator to admit this Payer;
- `PAYER_MCP_READY`: the Payer mandate and payment-intake service are ready;
- `PROPOSED`: Payer anchored the proposed authorization terms;
- `ACCEPTED`: Requestor anchored acceptance of those exact terms;
- `ACKNOWLEDGED`: Payer anchored final acknowledgment;
- `PARTY_COMPLETE`: Payer finished locally, but this is not authorization.

The payment request and signed mandate are commercial-intent evidence. The
authority sequence is exactly `PROPOSED` → `ACCEPTED` → `ACKNOWLEDGED` → fresh
aggregate verification, with exactly three independently verifiable Clockchain
anchors. Only the fresh aggregate verifier may issue the final verdict.

Do not switch roles. Do not fund addresses. Do not run the watcher. Do not run
the fresh aggregate verifier. Do not open or print any secret. Do not create
another session or modify Payer terms. Do not claim authorization. Never treat
relay, monitor, console, coordinator, or role-local status as authority.
Missing, duplicate, reordered, expired, malformed, or mismatched evidence fails
closed. Preserve `paymentMoved:false`.
