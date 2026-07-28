# Bilateral Clockchain live handoff

Use this operator handoff with the [full runbook](./bilateral-demo-day.md), the
[three-computer quick-start](./bilateral-demo-quick-start.md), the
[Iris prompt](../../prompts/run-iris-bilateral-demo.md), and the
[Billie prompt](../../prompts/run-billie-bilateral-demo.md). The canonical
stakeholder helper route is
[https://clockchain-research.vercel.app/handshake/run](https://clockchain-research.vercel.app/handshake/run).
The route is the required public start surface; live session evidence never goes
there.

This is an Ethereum Sepolia and Clockchain® single-validator testnet exercise.
No money moves. Do not install or use AgentDash. Do not invent success states.
It is not mainnet, court-grade, consensus-secure, trustless, production-ready,
or multi-validator. Every protocol and verdict artifact preserves paymentMoved: false.

Runner local state is not operator authorization. For a session that the fresh
aggregate verifier marks `AUTHORIZED`, the verified evidence establishes that
Billie followed Iris's signed mandate, Iris anchored `PROPOSED` and
`ACKNOWLEDGED`, and Billie anchored `ACCEPTED`. The protocol does not download message bytes from Clockchain.

## Release and computers

Pinned executable Handshake release SHA:
`54d3476de9309d386fe3e903a843b473b3851c15`.

A clean detached checkout of immutable repository SHA
`54d3476de9309d386fe3e903a843b473b3851c15`, Node.js 22, and
`npm ci --ignore-scripts` is required on all three computers. Stop on a dirty
worktree, wrong SHA, branch checkout, wrong Node.js major version, dependency
install drift, or any extra command.

The startup control order is exactly:
`relay -> coordinator -> console -> funding -> Iris payer supervisor -> Billie payee supervisor`.

`implementation-complete and rehearsal-ready` means local code, tests, docs, and
release packaging are ready, but the physical funded run has not passed. Only a
successful 3-computer run with exact fresh evidence may be called `live-demo validated`.

Private/live artifacts remain ignored/outside Git.

## Private kit locations

Use only path-level references with agents. Never print, read, paste, or inspect
private contents with an agent. No token, invitation, capability, private key,
TLS key, RPC URL, or live evidence value belongs in a chat, commit, document, or
agent transcript.

- Operator release/RPC material: repository-private `.context/bilateral-live-2026-07-28/`.
- Treasury keystore and public metadata: repository-private `.context/sepolia-funding/`.
- Directories that contain private material must be mode `0700`.
- Secret files, keystores, RPC URL files, TLS private keys, tokens, invitations,
  and capabilities must be mode `0600`.

## Treasury preflight

Public reusable Sepolia treasury address:
`0x157a377e4181f3f87c7f6efed5ddc340ccc00dce`.

Before funding, the operator may run this safe balance/nonce check. It reads the
RPC endpoint locally from `$SEPOLIA_RPC_URL_FILE` and prints only chain ID, the
public funding address, balance ETH, and nonce. It must not print the RPC URL or
key material.

```sh
node --input-type=module <<'NODE'
import { readFile } from "node:fs/promises";

const fundingAddress = "0x157a377e4181f3f87c7f6efed5ddc340ccc00dce";
let id = 0;

try {
  const rpcUrl = (await readFile(process.env.SEPOLIA_RPC_URL_FILE, "utf8")).trim();

  async function rpc(method, params = []) {
    const response = await fetch(rpcUrl, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        jsonrpc: "2.0",
        id: ++id,
        method,
        params,
      }),
    });
    const payload = await response.json();
    if (payload.error) {
      throw new Error("rpc failed");
    }
    return payload.result;
  }

  const [chainIdHex, balanceHex, nonceHex] = await Promise.all([
    rpc("eth_chainId"),
    rpc("eth_getBalance", [fundingAddress, "latest"]),
    rpc("eth_getTransactionCount", [fundingAddress, "latest"]),
  ]);
  const balanceWei = BigInt(balanceHex);
  const whole = balanceWei / 10n ** 18n;
  const fraction = (balanceWei % 10n ** 18n).toString().padStart(18, "0").replace(/0+$/, "");
  console.log(JSON.stringify({
    chainId: BigInt(chainIdHex).toString(10),
    fundingAddress,
    balanceEth: fraction === "" ? whole.toString() : `${whole}.${fraction}`,
    nonce: BigInt(nonceHex).toString(10),
  }, null, 2));
} catch {
  console.error("SAFE_SEPOLIA_TREASURY_CHECK_FAILED");
  process.exit(1);
}
NODE
```

## Operator startup

Set path placeholders locally. Do not paste private values.

```sh
export OPERATOR_KEY_ID="bilateral-demo-2026-07-28"
export OPERATOR_PRIVATE_KEY_FILE=".context/operator-keys/$OPERATOR_KEY_ID.ed25519.pem"
export BILATERAL_REPOSITORY_SHA="54d3476de9309d386fe3e903a843b473b3851c15"
export REPOSITORY_ROOT="$(pwd)"
export BILATERAL_OPERATOR_ROOT="$HOME/.clockchain/bilateral/$BILATERAL_REPOSITORY_SHA"
export BILATERAL_RELEASE_ROOT="$BILATERAL_OPERATOR_ROOT/release"
export SEPOLIA_RPC_URL_FILE="$REPOSITORY_ROOT/.context/bilateral-live-2026-07-28/sepolia-rpc.url"
export SEPOLIA_TREASURY_KEYSTORE="$REPOSITORY_ROOT/.context/sepolia-funding/funding-wallet.json"
export SEPOLIA_TREASURY_PUBLIC_METADATA="$REPOSITORY_ROOT/.context/sepolia-funding/funding-wallet.public.json"
export OPERATOR_CLOCKCHAIN_TOKEN_FILE="$BILATERAL_OPERATOR_ROOT/operator.clockchain-token"
export RELAY_ADVERTISED_IP="192.0.2.10"
export RELAY_PORT="8443"
export RELAY_TLS_CERTIFICATE="$BILATERAL_RELEASE_ROOT/relay.crt"
export RELAY_TLS_PRIVATE_KEY="$BILATERAL_RELEASE_ROOT/relay.key"
```

`192.0.2.10` is a documentation-only placeholder. The operator agent must
replace it with a numeric LAN IP reachable by both role computers. Stop if the
advertised relay address is `127.0.0.1`, localhost, a documentation range, or
any other non-routable address.

Generate the relay certificate for the final advertised IP and derive the
fingerprint before starting the coordinator:

```sh
openssl req -x509 -newkey rsa:3072 -nodes \
  -keyout "$RELAY_TLS_PRIVATE_KEY" \
  -out "$RELAY_TLS_CERTIFICATE" \
  -subj "/CN=$RELAY_ADVERTISED_IP" \
  -addext "subjectAltName=IP:$RELAY_ADVERTISED_IP" \
  -days 1
chmod 0600 "$RELAY_TLS_PRIVATE_KEY"
RELAY_TLS_FINGERPRINT="$(openssl x509 -in "$RELAY_TLS_CERTIFICATE" -outform DER | openssl dgst -sha256 -binary | xxd -p -c 256)"
```

Terminal 1 - relay:

```sh
npm run bilateral:relay -- \
  --host "${RELAY_LISTEN_HOST:-$RELAY_ADVERTISED_IP}" \
  --port "$RELAY_PORT" \
  --repository-sha "$BILATERAL_REPOSITORY_SHA" \
  --state "$BILATERAL_RELEASE_ROOT/relay-state" \
  --tls-certificate "$RELAY_TLS_CERTIFICATE" \
  --tls-private-key "$RELAY_TLS_PRIVATE_KEY"
```

Terminal 2 - coordinator:

```sh
npm run bilateral:coordinator -- \
  --clockchain-token-file "$OPERATOR_CLOCKCHAIN_TOKEN_FILE" \
  --operator-key-id "$OPERATOR_KEY_ID" \
  --operator-private-key "$OPERATOR_PRIVATE_KEY_FILE" \
  --release-root "$BILATERAL_RELEASE_ROOT" \
  --relay-url "https://$RELAY_ADVERTISED_IP:$RELAY_PORT" \
  --repository-sha "$BILATERAL_REPOSITORY_SHA" \
  --rpc-url-file "$SEPOLIA_RPC_URL_FILE" \
  --tls-certificate "$RELAY_TLS_CERTIFICATE" \
  --tls-fingerprint "$RELAY_TLS_FINGERPRINT"
```

Terminal 3 - read-only operator console:

```sh
npm run bilateral:console -- \
  --state-root "$BILATERAL_RELEASE_ROOT"
```

Relay/watcher/console fields are advisory. They are coordination and display
surfaces, not authority sources.

## Role supervisors

Iris payer supervisor:

```sh
npm run bilateral:supervisor -- \
  --launch-manifest "$IRIS_LAUNCH_MANIFEST" \
  --state "$IRIS_SUPERVISOR_STATE"
```

Billie payee supervisor:

```sh
npm run bilateral:supervisor -- \
  --launch-manifest "$BILLIE_LAUNCH_MANIFEST" \
  --state "$BILLIE_SUPERVISOR_STATE"
```

The user eventual actions are only funding four generated addresses and
starting two physical supervisors. Operator owns everything else.

## Funding command

Use the coordinator-owned `$BILATERAL_RELEASE_ROOT/funding-addresses.json` file
directly; do not copy or rewrite the funding record. There is no manual address
copying.

```sh
export FUNDING_RECORD_FILE="$BILATERAL_RELEASE_ROOT/funding-addresses.json"
export FUNDING_JOURNAL_DIR="$BILATERAL_OPERATOR_ROOT/funding-journal"

npm run bilateral:fund -- \
  --funding-record "$FUNDING_RECORD_FILE" \
  --journal-directory "$FUNDING_JOURNAL_DIR" \
  --keystore "$SEPOLIA_TREASURY_KEYSTORE" \
  --rpc-url-file "$SEPOLIA_RPC_URL_FILE"
```

The treasury funds exactly four freshly generated addresses with
`0.01 Sepolia ETH` each. The current `0.05 Sepolia ETH` budget is sufficient
only if preflight still reports balance/nonce safe.

## Expected evidence

Expected commercial-intent markers:

1. `PAYER_MANDATE_READY`
2. `PAYMENT_REQUEST_READY`
3. `PAYMENT_REQUEST_MATCHED`

Exact protocol anchors:

1. Iris `PROPOSED`
2. Billie `ACCEPTED`
3. Iris `ACKNOWLEDGED`

The role packages must be marker-complete role files, including
`party-result.json`, `PARTY-RESULT.md`, and `.party-result.complete.json`.
The verifier files must include the fresh aggregate verdict directory and
`.bilateral-verdict.complete.json`. The result is `AUTHORIZED` only from fresh
aggregate verifier output, and every verdict preserves `paymentMoved:false`.

Independent evidence recheck command:

```sh
SEPOLIA_RPC_URL="$(node --input-type=module <<'NODE'
import { readFile } from "node:fs/promises";
process.stdout.write((await readFile(process.env.SEPOLIA_RPC_URL_FILE, "utf8")).trim());
NODE
)"

node scripts/verify-bilateral-results.mjs \
  --clockchain-token-file "$OPERATOR_CLOCKCHAIN_TOKEN_FILE" \
  --descriptor "$BILATERAL_DESCRIPTOR_FILE" \
  --output "$VERDICT_OUTPUT_DIR" \
  --payer-results "$IRIS_TRANSFERRED_RESULT_DIR" \
  --payee-results "$BILLIE_TRANSFERRED_RESULT_DIR" \
  --rpc-url "$SEPOLIA_RPC_URL"
```

Relay/watcher/console fields are advisory.

## Immediate stop conditions

Stop immediately on missing, duplicate, reordered, expired, malformed,
mismatched, dirty/wrong SHA, wrong Node, wrong role/manifest, secret exposure,
unexpected extra session/command/write, changed TLS fingerprint/relay binding,
funding mismatch/nonzero recipient nonce, nonzero process exit, absent
completion marker, or any authority claim from relay/watcher/console/coordinator/role.
