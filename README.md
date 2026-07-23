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
[invitation handling notes](invites/README.md). The expected live run takes
roughly 30–90 seconds under normal testnet conditions. A passing `npm run demo`
writes sanitized `RESULT.md` and `result.json`; neither a narrative nor a
submitted transaction is a PASS by itself.

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
2. Use the process environment values `HANDSHAKE_REPO_URL` and
   `HANDSHAKE_REPO_REF` when they are set. Otherwise use
   `https://github.com/thetangstr/clockchain-handshake.git` and `main`.
   Clone that repository and ref with depth 1. Do not enumerate or echo unrelated
   environment variables.
3. Read `DEMO.md` and follow its safety boundary.
4. Confirm the Node.js major version is 22.
5. Confirm `HANDSHAKE_INVITE_FILE` points to my separately delivered invitation
   file. Never print, paste, copy, or open that file in chat; pass its path to the
   runner.
6. Run `npm ci --ignore-scripts`.
7. Run `npm run demo`. A verified run writes `RESULT.md` and `result.json`.
8. Return only the sanitized `RESULT.md` summary and the paths to `RESULT.md` and
   `result.json`.
9. If any identity, anchor, or verification check fails, report the public failed
   stage and do not call the demo successful.
```

Each stakeholder receives a different invitation file through a private channel.
Do not commit, paste into chat, or reuse that file. Public result artifacts contain
identity and receipt evidence only; they do not contain the invitation code,
private key, or Clockchain transport token.
