# Managed AWS Payer MCP relay

Stakeholders do not configure this relay. The AWS control plane provides a
stable public raw-TCP entry point while the Payer wrapper creates its own local
TLS identity and opens one restricted outbound tunnel. AWS forwards opaque TCP
bytes and never terminates Payer MCP TLS.

The tunnel service admits only the operator-approved, session-bound public key.
Its forced command allows one reverse-forward target and one listen port.
Changed keys, extra ports, shells, commands, agents, and alternate destinations
fail closed. The service never stores the MCP capability, TLS private key,
payment request, response, or intake record.

The public Payer discovery artifact signs the public MCP hostname and port, TLS
certificate fingerprint, reviewed immutable repository SHA, immutable image
digest, release, session, and expiry. Requestor verifies all of those fields
before sending a claim or payment request.

Preserve the assigned private state root unchanged. Underfunding is pending
until the bounded thirty-minute funding deadline. Do not retry consumed bootstrap
material. `paymentMoved:false` applies throughout.

A2A is intentionally absent. Payer MCP is the payment-intake/guidance surface.
Signed relay events and Clockchain receipts are the authority surfaces. Adding
a second advisory messaging protocol would not replace either authority
boundary.
