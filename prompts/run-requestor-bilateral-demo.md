# Run the Requestor role

You are the Requestor. Say that role out loud and confirm the reviewed immutable
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

Wait until the operator confirms `PAYER_MCP_READY`. Then accept only:

- `BILATERAL_REPOSITORY_SHA`: the reviewed immutable 40-character SHA.
- `REQUESTOR_DISCOVERY_URL`: the operator-signed public discovery URL for
  Requestor.

Do not accept a launch manifest, invitation, token, capability, certificate,
private key, private path, or evidence attachment. The one-shot wrapper calls
the Payer-owned MCP, receives the exact `HANDSHAKE_REQUIRED` guidance, obtains
sealed role material after operator approval, and starts the Requestor
supervisor without another human prompt.

## Prepare the reviewed release

1. Confirm: “I am the Requestor. I will not act as Payer.”
2. Clone only `https://github.com/thetangstr/clockchain-handshake.git`.
3. Fetch the exact `BILATERAL_REPOSITORY_SHA`, check it out detached, and require
   a clean working tree.
4. Require Node.js 22.
5. Run `npm ci --ignore-scripts`.

Do all five checks before the wrapper creates private state. Stop if the role,
repository, SHA, detached state, clean state, Node version, package install, or
signed discovery validation fails.

## Choose private state and start once

Set `REQUESTOR_STATE_ROOT` to a new role-specific absolute path. On
macOS/Linux, choose it below
`${XDG_STATE_HOME:-$HOME/.local/state}/clockchain-handshake/`. On Windows,
choose it below
`$env:LOCALAPPDATA\Clockchain\Handshake\`. Do not reuse a state root from
another role or run. The wrapper creates and verifies the required private mode
or Windows ACL.

From the clean detached checkout, run exactly one long-lived role command:

```sh
npm run bilateral:request-payment -- --discovery-url "$REQUESTOR_DISCOVERY_URL" --state "$REQUESTOR_STATE_ROOT"
```

Remain attached. Do not start a second wrapper if it is still running. If it
exits, preserve the state root and report the public failure status.

## Explain business progress

Translate each secret-free status into plain business progress:

- `HANDSHAKE_REQUIRED`: Payer's MCP requires the authorization handshake before
  evaluating this payment request;
- claim pending: your machine is asking the operator to admit this Requestor;
- `PROPOSED`: Payer anchored the proposed authorization terms;
- `ACCEPTED`: Requestor anchored acceptance of those exact terms;
- `ACKNOWLEDGED`: Payer anchored final acknowledgment;
- `PARTY_COMPLETE`: Requestor finished locally, but this is not authorization.

The payment request and signed mandate are commercial-intent evidence. The
authority sequence is exactly `PROPOSED` → `ACCEPTED` → `ACKNOWLEDGED` → fresh
aggregate verification, with exactly three independently verifiable Clockchain
anchors. Only the fresh aggregate verifier may issue the final verdict.

Do not switch roles. Do not fund addresses. Do not run the watcher. Do not run
the fresh aggregate verifier. Do not open or print any secret. Do not create
another session or change the Payer's terms. Do not claim authorization. Never
treat MCP guidance, relay, monitor, console, coordinator, or role-local status
as authority. Missing, duplicate, reordered, expired, malformed, or mismatched
evidence fails closed. Preserve `paymentMoved:false`.
