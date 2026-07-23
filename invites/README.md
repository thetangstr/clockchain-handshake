# Handshake invitation bundles

This directory holds encrypted, Ethereum Sepolia-only invitation bundles for the
turnkey Handshake demo. A bundle exposes its display name and public wallet
address, but it does not contain a plaintext private key or invitation code.
For the actual exercise, deliver the matching mode-`0600`
`<id>.secret.json` file privately as one opaque stakeholder input. That file
combines the public bundle with its invitation code so the operator never needs
to paste or transmit the code separately.

Operators create named bundles with explicit, path-safe IDs:

```sh
npm run invitations:create -- \
  --output-public invites \
  --output-secret .context/invitations \
  --ids codex,claude \
  --names Billy,Iris
```

The command writes public `<id>.enc.json` files and mode-`0600` operator-only
`<id>.secret.json` files. It refuses existing targets by default. `--force`
replaces existing regular files only; it never follows symlinks or replaces
directories and other special files. The command prints only each ID and public
address. Treat a delivered secret file as opaque: do not open it in chat or
split its code from its bundle. Public and secret output directories must be
canonically distinct and must not contain one another, including through a
symlinked parent.

Creation takes owner-only exclusive locks in both canonical output directories,
using the same deterministic order for every process. It holds those locks
through preflight, generation, staged publication, exact public/secret pair
verification, artifact cleanup, and directory synchronization. A concurrent
creator fails closed instead of waiting or interleaving with the active batch.

After funding, check the public bundles without reading their secret files:

```sh
npm run invitations:check
```

The checker verifies Ethereum Sepolia (`11155111`), confirms bytecode at the
official ERC-8004 Identity Registry, and reads each wallet balance and nonce.
An invitation is ready only when its nonce is zero and its balance is between
`0.005` and `0.02` Sepolia ETH, inclusive. These intentionally narrow pilot
bounds provide testnet transaction headroom while catching an unfunded, consumed,
or accidentally overfunded wallet. It refuses to contact RPC when the public
directory contains an adjacent `*.secret.json` file or a `.tmp`, `.bak`, or
`.lock` transaction artifact.

An abrupt process termination or power loss can leave a lock, staged `.tmp`
file, or forced-replacement `.bak` recovery copy. There is deliberately no
automatic stale-lock timeout: every later create or readiness check fails closed
until an operator resolves the interrupted batch.

Before recovery, confirm that no invitation creator is running and copy both
output directories to a separate operator-only recovery location. For every ID,
either restore both old files from their corresponding hidden `.bak` copies or
retain a current pair only after confirming that the secret file's `bundle`
exactly equals the public JSON bundle. Never restore or delete just one side of
a pair. Remove residual `.tmp`, `.bak`, and lock files only after all requested
pairs match, then rerun creation or the readiness check.

These wallets are disposable testnet identities. They hold no mainnet assets,
move no scenario money, and must not be reused outside this exercise.
