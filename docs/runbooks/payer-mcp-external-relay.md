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

Transfer only the exact `PAYER_MCP_READY` public URL, certificate, and
fingerprint tuple. Requestor supplies those three values to
`npm run bilateral:request-payment`. Success at this layer is exact
`HANDSHAKE_REQUIRED`; it is not authorization.

Fail closed if:

- the public URL IP or port differs from `PAYER_MCP_READY`;
- the certificate SAN does not match the public IP;
- the fingerprint differs;
- the endpoint returns anything other than exact `HANDSHAKE_REQUIRED`;
- the tunnel or either long-lived role process exits;
- any participant address is underfunded after the eight-minute deadline,
  overfunded, already used, duplicated, reordered, or mismatched.

Only the final fresh aggregate verifier can emit `AUTHORIZED`, and every
artifact preserves `paymentMoved:false`.
