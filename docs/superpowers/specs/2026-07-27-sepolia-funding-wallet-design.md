# Reusable Sepolia funding wallet design

## Purpose

The bilateral demo creates four fresh participant addresses for every immutable
release: Billy rehearsal, Iris rehearsal, Billy stakeholder, and Iris
stakeholder. Each address must have a zero transaction nonce and between 0.005
and 0.02 Sepolia ETH inclusive before registration.

Google's Sepolia faucet currently dispenses 0.05 Sepolia ETH per successful
request. A faucet drip therefore cannot go directly to a participant address:
0.05 exceeds the demo's maximum permitted balance. Repeating manual faucet and
transfer work also creates avoidable mistakes.

This design introduces one reusable, operator-owned Sepolia funding wallet and
a repository-native funding command. The wallet receives faucet drips
occasionally and distributes an exact 0.01 Sepolia ETH target balance to each
fresh participant address. It is never a protocol participant, never signs a
Clockchain artifact, and never becomes an authorization source.

## Goals

- Reuse one funding wallet across rehearsals and stakeholder demonstrations.
- Preserve fresh, single-use participant addresses and nonce-zero admission.
- Fund exactly four coordinator-published addresses to 0.01 Sepolia ETH.
- Make retries discovery-first and prevent duplicate transfers.
- Keep all wallet secrets and live funding evidence outside Git.
- Preserve `paymentMoved: false` for the bilateral business-payment protocol.
- Require the fresh aggregate verifier for the only authorizing verdict.

## Non-goals

- Reusing participant invitations, keys, identities, or result directories.
- Treating faucet or funding success as protocol success.
- Funding Ethereum mainnet or moving a commercial payment.
- Managing arbitrary treasury payments or supporting networks other than
  Ethereum Sepolia.
- Replacing the coordinator's independent balance and nonce checks.

## Architecture

### Private funding wallet

The operator creates one random Ethereum private key and stores it only as an
encrypted Web3 Secret Storage keystore under:

```text
.context/sepolia-funding/funding-wallet.json
```

The directory is owner-controlled mode `0700`; the keystore is a regular,
single-link mode-`0600` file. The keystore password is a high-entropy random
value stored in macOS Keychain under a fixed, repository-specific service and
account name. The password is never accepted as a command-line argument,
environment variable, or repository file.

A separate mode-`0600` public metadata file records only:

- schema version;
- Ethereum Sepolia chain ID `11155111`;
- lowercase funding address;
- keystore SHA-256 digest;
- creation timestamp.

The private key, password, mnemonic, and decrypted keystore bytes must never be
printed, logged, committed, copied into a test fixture, or sent to an agent
tool.

### Funding command

Add a repository-native command:

```text
node scripts/fund-bilateral-addresses.mjs
```

The command accepts paths for:

- the coordinator's canonical four-address funding record;
- the encrypted funding keystore;
- a private RPC URL file;
- a private journal directory.

It does not accept raw addresses, private keys, passwords, or RPC URLs on the
command line. It reads the keystore password from macOS Keychain through a
bounded dependency.

The command uses the existing pinned `viem` dependency. No new package is
introduced.

### Private journal

Every funding batch has a private journal bound to:

- the exact repository SHA;
- Sepolia chain ID;
- funding-wallet address;
- the canonical ordered set of four participant addresses;
- the target balance of 0.01 Sepolia ETH;
- the RPC endpoint digest, not the raw endpoint;
- one immutable batch ID derived from those public facts.

The journal records a state machine for each recipient:

```text
PLANNED -> BROADCAST_INTENT -> TRANSACTION_OBSERVED -> FUNDED
```

Before broadcasting, the command durably records the exact recipient, value,
funding-wallet nonce, fee envelope, and unsigned transaction digest. After
broadcast it records the transaction hash. A restart first queries Sepolia for
the recorded nonce, transaction, receipt, recipient balance, and recipient
nonce. It never blindly resends an unresolved transaction.

## Funding flow

1. Load and validate the four-address coordinator record.
2. Require exactly four distinct lowercase Ethereum addresses in the fixed
   Billy/Iris rehearsal/stakeholder order.
3. Verify the repository is clean at the exact release SHA.
4. Open the encrypted keystore and confirm its address matches private public
   metadata.
5. Require Sepolia chain ID `11155111`.
6. Query all participant balances and latest nonces.
7. Fail closed if any participant nonce is nonzero or any balance exceeds 0.02
   Sepolia ETH.
8. Treat an address already inside the 0.005–0.02 band as ready without sending
   another transaction.
9. For an address below 0.005, calculate only the amount required to reach the
   exact 0.01 target.
10. Require the funding wallet to cover all planned values plus the bounded fee
    envelope.
11. Broadcast sequentially using explicit funding-wallet nonces and wait for a
    successful receipt before advancing.
12. Re-query all four participants and require balances inside the admission
    band and nonces still equal to zero.
13. Publish a secret-free operator summary containing addresses, balances,
    funding transaction hashes, and `paymentMoved: false`.
14. Allow the existing coordinator and both supervisors to independently
    re-check the same balances and nonces before registration.

The funding transfers are testnet gas provisioning. They are not the bilateral
business payment represented by the protocol, so every protocol and operator
summary continues to state `paymentMoved: false`.

## Faucet replenishment

The operator uses the official Google Sepolia faucet only for the reusable
funding wallet. The current 0.05 drip is enough to fund four empty participant
addresses to 0.01 each plus ordinary transfer gas.

Faucet requests are manual, externally rate-limited replenishment events. The
tool displays only the public funding-wallet address and current balance. It
does not automate Google login, CAPTCHA handling, eligibility checks, or
repeated requests. If Google applies its optional 0.001 mainnet ETH anti-abuse
check, the operator stops and uses a separately approved source; participant
addresses must never receive a 0.05 drip directly.

## Failure handling

The command fails closed on:

- malformed or noncanonical coordinator output;
- missing, duplicate, reordered, or changed participant addresses;
- dirty or mismatched repository SHA;
- wrong chain ID or RPC endpoint mutation;
- funding-wallet or keystore mismatch;
- participant nonce other than zero;
- participant balance above 0.02 Sepolia ETH;
- insufficient funding balance or unbounded fees;
- ambiguous funding-wallet nonce;
- missing, reverted, replaced, or mismatched transactions;
- journal replacement, truncation, permission failure, or inconsistent state.

After any broadcast intent, recovery must reuse the same repository SHA,
keystore, RPC file, journal, recipients, target balance, and transaction facts.
An unresolved transaction is an operator-visible terminal ambiguity until the
chain proves its outcome.

## Security boundaries

- The reusable wallet is funding authority only.
- Relay fields, watcher output, funding receipts, and coordinator state remain
  advisory for protocol authorization.
- Participant private keys remain confined to their long-lived supervisors.
- The funding command cannot load invitations, Clockchain tokens, operator
  signing keys, descriptors, party results, or verifier output.
- The funding wallet never signs participant registration or protocol
  transactions.
- Exactly three Clockchain anchors remain the independently verifiable protocol
  evidence.
- Only the fresh aggregate verifier may emit `AUTHORIZED`.

## Testing

Use test-driven development with injected Keychain, filesystem, clock, and
Sepolia RPC dependencies.

Focused tests cover:

- encrypted wallet creation and strict private-file metadata;
- rejection of raw secret arguments and secret-bearing output;
- exact four-address and repository-SHA binding;
- correct 0.01 top-up calculation;
- no-op adoption for balances already inside the allowed band;
- rejection above 0.02 or with nonzero participant nonce;
- funding-wallet balance and fee-envelope checks;
- durable intent before broadcast;
- successful receipt and final balance verification;
- crash before broadcast, after broadcast, and after receipt;
- replacement, dropped, reverted, and nonce-conflicting transactions;
- journal tampering and same-input recovery;
- canonical secret-free completion summary;
- continued `paymentMoved: false` and verifier-only authorization.

After focused tests and independent security review, run one fresh
`npm run verify`. The reviewed commit becomes a new immutable release SHA before
any live faucet or funding transaction is used for the bilateral rehearsal.

## Operational handoff

For each new release:

1. Start the relay and coordinator at the reviewed immutable SHA.
2. Start exactly one long-lived Billy supervisor and one long-lived Iris
   supervisor.
3. Capture the coordinator's four-address canonical funding record.
4. Run the funding command once with the reusable funding wallet.
5. Let the coordinator and supervisors independently observe funding readiness.
6. Continue through rehearsal and stakeholder verification without reusing
   participant addresses or rerunning completed funding batches.

The user's recurring actions remain limited to replenishing the reusable
funding wallet when necessary and starting the two physical supervisor
sessions. Routine per-address funding becomes deterministic operator tooling.
