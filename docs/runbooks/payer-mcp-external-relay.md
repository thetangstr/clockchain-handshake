# Payer MCP external raw-TCP relay

Use this runbook to make Payer's loopback-only MCP endpoint reachable by a
Requestor on another network. Payer remains the MCP owner and TLS authority.
AWS forwards raw TCP and does not terminate Payer MCP TLS. The hosted
Clockchain MCP server is not part of this payment-intake flow.

Preserve the assigned private state root unchanged. Underfunding is pending
until the bounded eight-minute funding deadline. Do not retry a consumed launch
manifest.

## Authority boundary

The long-lived Payer supervisor binds MCP only to `127.0.0.1`. A long-lived
reverse SSH connection forwards one stable AWS Elastic IP and public port to
that loopback listener. The Requestor connects to the public URL, validates the
Payer-generated certificate normally, and pins its lowercase SHA-256
fingerprint. The AWS instance cannot create mandates, approve requests, alter
handshake state, or emit `AUTHORIZED`.

The relay never stores the MCP capability, TLS private key, request, response,
or intake record. Do not copy tokens, invitations, capabilities, launch
manifests, private keys, RPC URLs, or live evidence onto the instance.

## One-time AWS setup

Use a dedicated minimal EC2 instance with:

- one stable Elastic IP;
- an encrypted root volume;
- Instance Metadata Service v2 required;
- SSH allowed only from Payer's current public IP;
- the chosen public MCP port allowed only from Requestor's current public IP
  when it is known;
- no application, database, proxy, TLS certificate, MCP secret, or session
  state installed.

If Requestor's public IP cannot be fixed for the manual test, opening only the
single MCP port temporarily is acceptable for the test window because the
Payer-generated capability and pinned TLS endpoint still fail closed. Restore
the source restriction immediately after the test.

On the relay, set the OpenSSH server option:

```text
GatewayPorts clientspecified
```

Restart `sshd`, then verify the effective setting with `sshd -T`. The stable
Elastic IP and public port may be reused, but every new release uses fresh role
state, fresh launch manifests, a fresh MCP capability, and a fresh one-day TLS
certificate.

## One-time Payer SSH alias

Configure a Payer-owned SSH host alias outside the repository. The agent may use
the alias but must not open, print, paste, upload, or transfer the private key:

```text
Host clockchain-payer-mcp-relay
  HostName <AWS_ELASTIC_IP>
  User <RELAY_USER>
  IdentityFile <PAYER_OWNED_PRIVATE_KEY_PATH>
  IdentitiesOnly yes
```

Confirm the alias interactively before consuming a launch manifest:

```sh
ssh clockchain-payer-mcp-relay true
```

## Per-run Payer tunnel

Payer receives the public IP, public port, and preconfigured alias name from the
operator. Payer starts this non-terminating process before the supervisor:

```sh
export PAYER_MCP_HOST="127.0.0.1"
export PAYER_MCP_PORT="9443"
export PAYER_MCP_PUBLIC_IP="${PAYER_MCP_PUBLIC_IP:?set operator-provided AWS Elastic IP}"
export PAYER_MCP_PUBLIC_PORT="${PAYER_MCP_PUBLIC_PORT:?set operator-provided public relay port}"
export PAYER_MCP_PUBLIC_URL="https://$PAYER_MCP_PUBLIC_IP:$PAYER_MCP_PUBLIC_PORT/mcp"
export PAYER_MCP_RELAY_SSH_HOST="${PAYER_MCP_RELAY_SSH_HOST:?set preconfigured Payer-owned SSH host alias}"

ssh -N \
  -o ExitOnForwardFailure=yes \
  -o ServerAliveInterval=30 \
  -o ServerAliveCountMax=3 \
  -R "0.0.0.0:${PAYER_MCP_PUBLIC_PORT}:127.0.0.1:${PAYER_MCP_PORT}" \
  "$PAYER_MCP_RELAY_SSH_HOST"
```

Keep the terminal attached. Start this long-lived process exactly once. Do not
start a replacement supervisor. If SSH exits or reports a forwarding failure,
stop the role, preserve its state unchanged, and report the exit. Do not retry
the consumed launch manifest.

In a second terminal, generate Payer's certificate with an IP SAN equal to
`PAYER_MCP_PUBLIC_IP`, then start the Payer supervisor with both
`--payer-mcp-host "$PAYER_MCP_HOST"` and
`--payer-mcp-public-url "$PAYER_MCP_PUBLIC_URL"`. The supervisor must report
that public URL in exact `PAYER_MCP_READY`.

## Requestor handoff and validation

After exact `PAYER_MCP_READY`, the operator approves the pending bootstrap
claim fingerprint in the loopback broker and publishes one signed Requestor
discovery URL. Transfer only that signed discovery URL. Requestor supplies that
URL to `npm run bilateral:request-payment -- --discovery-url ...`. Success at
this layer is exact `HANDSHAKE_REQUIRED`; it is not authorization.

The operator broker uses the production CLI:

```sh
npm run bilateral:bootstrap-broker -- serve \
  --capability-file "$PAYER_MCP_BOOTSTRAP_BROKER_CAPABILITY_FILE" \
  --host 127.0.0.1 \
  --manifest "$REQUESTOR_LAUNCH_MANIFEST" \
  --operator-key-id "$OPERATOR_KEY_ID" \
  --operator-private-key "$OPERATOR_PRIVATE_KEY_FILE" \
  --port 0 \
  --repository-sha "$BILATERAL_REPOSITORY_SHA" \
  --state "$PAYER_MCP_BOOTSTRAP_BROKER_STATE"
```

After Requestor starts the one-shot wrapper, inspect the journal read-only and
approve exactly one public pending fingerprint:

```sh
BOOTSTRAP_CLAIM_FINGERPRINT="$(node -e '
const fs = require("node:fs");
const journal = JSON.parse(fs.readFileSync(process.argv[1], "utf8"));
if (journal.schema !== "clockchain.requestor-bootstrap-broker-journal/v1") process.exit(1);
const pending = Object.values(journal.claims).filter((claim) => claim.status === "PENDING_APPROVAL" && claim.paymentMoved === false);
if (pending.length !== 1 || !/^[0-9a-f]{64}$/.test(pending[0].claimFingerprint)) process.exit(1);
console.log(pending[0].claimFingerprint);
' "$PAYER_MCP_BOOTSTRAP_BROKER_STATE/bootstrap-broker-journal.json")"
npm run bilateral:bootstrap-broker -- approve \
  --state "$PAYER_MCP_BOOTSTRAP_BROKER_STATE" \
  --claim-fingerprint "$BOOTSTRAP_CLAIM_FINGERPRINT"
```

Fail closed if:

- the signed discovery URL is missing, expired, malformed, or not operator-signed;
- the public URL in discovery differs from `PAYER_MCP_READY`;
- the broker claim fingerprint is missing, duplicated, or mismatched;
- the endpoint returns anything other than exact `HANDSHAKE_REQUIRED`;
- the tunnel or either long-lived role process exits;
- any participant address is underfunded after the eight-minute deadline,
  overfunded, already used, duplicated, reordered, or mismatched.

Only the final fresh aggregate verifier can emit `AUTHORIZED`, and every
artifact preserves `paymentMoved:false`.
