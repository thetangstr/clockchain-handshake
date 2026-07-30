# Public Handshake Monitor Design

## Goal

Keep the Payer MCP reachable through the existing AWS Elastic IP and let anyone
view sanitized live Clockchain handshake progress on the public run page.

## Architecture

The Payer MCP remains local and Payer-owned. A supervised reverse SSH tunnel
publishes TCP port `9443` through `32.186.198.119`; it reconnects without
restarting the Payer supervisor.

The operator runs a separate publisher that reads only the existing read-only
console projection, reduces it to an exact public schema, and uploads
`latest.json` to a public-read, private-write S3 object. The research site polls
that object and marks it stale when updates stop.

## Public fields

- Actor and watcher health
- Payer-MCP local readiness
- Mandate-ready, request-ready, and request-matched markers
- Exactly three anchor roles, states, verified flags, and block heights
- Fresh-verifier status
- `paymentMoved:false`
- Observation time and staleness threshold

Names, amounts, purposes, invoice references, identifiers, digests, tokens,
keys, capabilities, paths, manifests, and evidence bytes are never published.

## Authority boundary

The public monitor is advisory. It never emits the authorization literal.
Only the fresh aggregate verifier remains authoritative. Missing, malformed,
extra, reordered, or stale data fails closed.

