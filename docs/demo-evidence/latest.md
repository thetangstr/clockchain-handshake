# Sanitized Handshake demo evidence — 2026-07-23

This summary records a prior private independent verification performed on
2026-07-23. It does not publish the raw result pairs or manifest needed to
reproduce that verification.

## Reproducibility boundary

The live client runs exercised immutable repository SHA
`a603572a5d0a2773a273fc68b5312d9f1100d1f1` with prompt SHA-256
`8aac14d00c5de105422af7c6d8f312cc72025e1bec30bfd298cd49c1f1152711`.
Subsequent release-hardening commits were verified deterministically and were
not exercised by another live client run.
They used Ethereum Sepolia chain ID `11155111` and the official registry
`0x8004A818BFB912233c491871b3d84c89A494BD9e`.

## Public result summary

Codex CLI `0.144.1` ran Billy, agent `8677`, owned by
`0x706Ae524866Dd3921Fa40B4AC2831538D8AD1cB1`.

- [Registration transaction](https://sepolia.etherscan.io/tx/0x511c1c379295c0ac1cb9a162a3e45f45c700e4e07eaa41dc3b2e0d1500c6af46)
- [Metadata transaction](https://sepolia.etherscan.io/tx/0xb4a5f37e6356c0d3e1291e1038bc85017f558b16b9fda5b09192adab5aa03c5b)
- Clockchain ledger `02313136-82d8-4eb0-a571-94c836661fc9`, block `1781135`

Claude Code `2.1.218` ran Iris, agent `8679`, owned by
`0x8Ebb593AE8e55B0a93d320e05d2a7BCCA7CE8B99`.

- [Registration transaction](https://sepolia.etherscan.io/tx/0x6981f9250589fc550a68e6ee2b0146323066c64332c3542e4bbb6d9f9f47c676)
- [Metadata transaction](https://sepolia.etherscan.io/tx/0xbb9435c8f9d46f0f57e0aab6208610f2b4c37177b33d27319f1b0311db16b160)
- Clockchain ledger `737bf7e6-4ac2-4e41-8c8c-e6eb8b2b58a1`, block `1781359`

Scenario: `100 USD`; `moved: false`.

Both receipts have status `anchored`, commitment verification `true`,
cross-party verification `true`, verification against an on-chain block, and
`keyless: true`.

## Provenance

The repository SHA, prompt SHA, and client/version attributions are provenance
records from the original harness, not cryptographic execution attestations.

The original aggregate harness remains `FAIL`. Codex is the original
harness-bound `PASS`. Claude exited 0 and produced a schema-valid `PASS` pair,
but that pair was outside the harness collection root; it was recovered from
its captured temporary path, remained hash-preserved, and was independently
verified. Claude is **not** harness-bound and is not an original aggregate
`PASS`.

No invitation rerun, Ethereum transaction, or Clockchain receipt write occurred during recovery verification.

No raw JSON/Markdown result pairs, manifest, logs, invitation material, keys, or
tokens are published here.

## Interpretation

The private verification checked anchoring and cross-party re-verification. The
Clockchain testnet used for these receipts has a single validator; within that
trust boundary, this summary does not prove multi-validator consensus, mainnet
security, court-grade evidence, or trustless security.
