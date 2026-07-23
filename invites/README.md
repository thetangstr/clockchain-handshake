# Handshake invitation bundles

This directory holds encrypted, Ethereum Sepolia-only invitation bundles for the
turnkey Handshake demo. A bundle exposes its display name and public wallet
address, but it does not contain a plaintext private key or invitation code.
Deliver each matching invitation code separately and privately.

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
address.

After funding, check the public bundles without reading their secret files:

```sh
npm run invitations:check
```

The checker verifies Ethereum Sepolia (`11155111`), confirms bytecode at the
official ERC-8004 Identity Registry, and reads each wallet balance and nonce.
An invitation is ready only when its nonce is zero and its balance is between
`0.005` and `0.02` Sepolia ETH, inclusive. These intentionally narrow pilot
bounds provide testnet transaction headroom while catching an unfunded, consumed,
or accidentally overfunded wallet.

These wallets are disposable testnet identities. They hold no mainnet assets,
move no scenario money, and must not be reused outside this exercise.
