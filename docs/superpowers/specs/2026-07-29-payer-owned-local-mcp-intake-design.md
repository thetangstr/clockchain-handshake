# Payer-owned local MCP payment-intake design

## 1. Goal

Deliver a manual Handshake demo in which the Requestor first asks a
Payer-owned MCP server for payment, the MCP server responds that the exact
Handshake protocol is required, and the Requestor then starts the existing
bilateral supervisor flow.

The server is a small repository-native demo component running on the Payer
computer. It does not use, extend, proxy, or depend on
`https://mcp.clockchain.network/mcp`.

The end-to-end proof remains:

```text
Requestor calls Payer MCP request_payment
  -> HANDSHAKE_REQUIRED
  -> Requestor starts its supervisor
  -> Payer PROPOSED
  -> Requestor ACCEPTED
  -> Payer ACKNOWLEDGED
  -> fresh aggregate verification
  -> AUTHORIZED
```

Every artifact and public status preserves `paymentMoved:false`.

## 2. Scope

### 2.1 In scope

- A Payer-owned local MCP server with one tool: `request_payment`.
- MCP Streamable HTTP over TLS on one `/mcp` endpoint.
- A Requestor CLI that initializes MCP, discovers the exact tool, calls it,
  validates `HANDSHAKE_REQUIRED`, and only then starts the Requestor
  supervisor.
- A single fixed repository-reviewed demo policy shared by the MCP response
  and the existing Payer/Requestor supervisors.
- An exact intake digest and intake request identifier carried into both the
  Payer-signed session mandate and the Requestor-signed formal payment request.
- A coordinator-generated 256-bit MCP intake capability whose raw value is
  delivered only to the Requestor and whose SHA-256 digest is delivered to the
  Payer.
- Replay-safe persistence of the non-authoritative intake request on the
  Payer computer.
- Updated Payer and Requestor prompts, runbooks, documentation checks, and the
  public manual-test page.
- Focused protocol tests, isolated multiprocess tests, and one fresh-agent
  rehearsal.

### 2.2 Out of scope

- Adding mandate tools to the hosted Clockchain MCP service.
- Building a general mandate directory, marketplace, or production payment
  API.
- Moving money.
- Adding a fourth Clockchain write or authorization anchor.
- Allowing MCP to create, approve, or verify an authorization verdict.
- Returning launch-manifest capabilities, invitations, tokens, private keys,
  TLS private keys, RPC URLs, or generated live evidence through MCP.
- Accepting arbitrary runtime policy terms in the first demo. The Payer still
  owns and signs the authoritative session mandate; this version uses one
  fixed reviewed policy so the MCP preview and both supervisors cannot drift.

## 3. Chosen approach

### 3.1 Recommended: one-tool Payer ingress

Add a deliberately small MCP 2025-11-25 Streamable HTTP server inside the
long-running Payer supervisor process with one tool, `request_payment`. It
implements only:

- `initialize`;
- `notifications/initialized`;
- `tools/list`;
- `tools/call` for `request_payment`;
- `DELETE /mcp` for session cleanup; and
- `GET /mcp` returning `405 Method Not Allowed` because the demo does not need
  SSE.

The server uses JSON responses rather than SSE. It advertises only the
`tools` capability and assigns a cryptographically random `MCP-Session-Id`.
The client sends `MCP-Protocol-Version: 2025-11-25` after initialization.
Every client POST sends
`Accept: application/json, text/event-stream`, as required by Streamable HTTP.
The pinned local server always returns `application/json`. An SSE response is a
contract mismatch and the Requestor client fails closed rather than falling
back to a different server behavior.

The canonical intake digest and identifier are later repeated in the
Payer-signed session mandate and Requestor-signed formal payment request. The
existing descriptor commits to both signed artifacts, so the intake becomes
causally bound to the proof without becoming a Clockchain anchor.

This is the smallest genuine MCP surface that makes the Payer the visible
payment-intake owner without adding another process with access to Payer state
or changing Handshake authority.

### 3.2 Rejected: add the tool to the coordination relay

The relay already has TLS, persistence, and session state, but hosting
`request_payment` there would make the operator appear to own the payment
entry point. That contradicts the requirement that the MCP server be owned by
the Payer.

### 3.3 Rejected: general reusable-mandate service

A reusable mandate directory needs publication, discovery, versioning,
revocation, durable multi-instance storage, and a larger security model. That
is useful future product work but unnecessary for this manual proof.

## 4. Components

### 4.1 Shared demo policy

Create one small module exporting the frozen policy already implicit in the
supervisor:

```json
{
  "amount": {
    "currency": "USD",
    "value": "100"
  },
  "invoiceReferencePrefix": "invoice-",
  "purpose": "Handshake demo"
}
```

The MCP intake validator, MCP response, Payer supervisor, and Requestor
supervisor all consume this same module. The Payer still creates and signs the
authoritative session mandate later. The MCP result is a policy preview, not
that signed session mandate.

### 4.2 Payer MCP server

Add:

- `src/bilateral/local-mcp/payment-intake.mjs` for exact schemas, request
  validation, response construction, and byte-identical replay rules;
- `src/bilateral/local-mcp/server.mjs` for MCP lifecycle and HTTP handling;
  and
- Payer-only local MCP lifecycle support in
  `src/bilateral/coordination/supervisor-runtime.mjs` and
  `bin/handshake-supervisor.mjs`.

The Payer supervisor retains its existing flags and accepts this additional
closed set only when its launch manifest role is `payer`:

```text
--payer-mcp-host
--payer-mcp-port
--payer-mcp-tls-certificate
--payer-mcp-tls-private-key
```

The server:

- requires TLS for LAN binding;
- binds only to the explicit numeric Payer LAN address;
- never defaults to `0.0.0.0`;
- validates the exact repository SHA before listening;
- requires `Authorization: Bearer <capability>` and compares only
  `sha256(capability)` to the exact digest in the Payer launch manifest using
  constant-time comparison;
- rejects every request carrying an `Origin` header because the demo has no
  browser MCP client;
- permits only `POST`, `GET`, and `DELETE` on `/mcp`;
- accepts at most 32 request headers and a 64-KiB request body;
- uses a five-second header deadline and a ten-second whole-request deadline;
- permits at most 16 failed authentication attempts across the process in any
  rolling 60-second window, then returns one generic `429` response without
  parsing the body; and
- permits each authenticated MCP session at most eight HTTP requests total,
  including initialization and deletion, before retiring that session;
- rejects unsupported MCP versions, methods, tools, fields, content types,
  and response modes;
- returns `405` to GET because no SSE stream is implemented; and
- stores no secret in response bodies or logs.

The Payer supervisor starts this listener after validating and persisting its
local bootstrap state but before it waits for peer enrollment. It accepts one
canonical intake request, persists it under the same private supervisor state
root, and continues waiting safely until the Requestor enrolls.

The Requestor supervisor can never start the server, and a standalone MCP
server process is not added. This avoids two processes sharing Payer secrets
or racing the Payer checkpoint.

### 4.3 Requestor intake client

Add:

- `src/bilateral/local-mcp/client.mjs` for TLS-pinned MCP initialization,
  tool discovery, tool call, and exact response validation; and
- `bin/handshake-request-payment.mjs` for one Requestor-facing command.

The Requestor command accepts only:

```text
--launch-manifest
--intake-request-id
--mcp-url
--state
--tls-certificate
--tls-fingerprint
```

It performs these steps:

1. Verify the clean immutable checkout and validate all path inputs without
   printing their contents.
2. Read the Requestor-only MCP intake capability through the approved
   launch-manifest parser, retain it only for the MCP exchange, and never
   print or persist it separately.
3. Open a TLS-pinned connection to the Payer MCP endpoint.
4. Send MCP `initialize` and require protocol version `2025-11-25`, the
   `tools` capability, exact server identity, and one secure session ID.
5. Send `notifications/initialized`.
6. Call `tools/list` and require exactly one tool named `request_payment`
   with the repository-owned exact input and output schemas.
7. Call `request_payment` once with the fixed demo request.
8. Validate the exact structured result and its duplicate text
   representation.
9. Require `status:"HANDSHAKE_REQUIRED"`, the same intake request ID and
   commercial terms, the exact three-transition sequence, the reviewed
   repository SHA, the correct canonical intake digest, and
   `paymentMoved:false`.
10. Persist the exact validated intake result at a fixed private path owned by
   the Requestor supervisor state.
11. Close the MCP session.
12. Start the existing Requestor supervisor once using the supplied launch
    manifest and private state path.

Any failure before step 12 prevents the supervisor from starting.

### 4.4 Intake capability

The coordinator creates one cryptographically random 32-byte intake
capability when it creates the two launch manifests.

- The Requestor launch manifest contains the lowercase hexadecimal raw
  capability under a role-conditional exact field.
- The Payer launch manifest contains only the lowercase hexadecimal SHA-256
  digest under the corresponding role-conditional exact field.
- The operator never sends the raw capability to the Payer.
- The Requestor client sends the raw value only in the TLS-protected
  `Authorization` header.
- The Payer server hashes the header value, performs a constant-time digest
  comparison, and discards the raw value.
- The capability and digest are bound to one repository SHA, release ID, and
  coordination session by their respective launch manifests.
- Neither value appears in MCP results, intake records, supervisor status
  lines, console projections, logs, committed files, or public documentation.

Byte-identical retries may reuse the capability while the launch manifest is
valid. Changed duplicate intake bytes still fail closed.

### 4.5 Binding into the signed session artifacts

The exact Payer mandate schema gains:

```json
{
  "intakeDigest": "64-lowercase-hex",
  "intakeRequestId": "canonical-uuid"
}
```

The exact Requestor payment-request schema gains the same two fields.

The Payer supervisor may construct a session mandate only after:

1. its MCP server has persisted exactly one valid intake;
2. both authenticated role enrollments and identity packages exist; and
3. the intake terms match the shared policy.

The Requestor supervisor may construct its formal signed request only after:

1. the Requestor intake client has persisted the validated MCP result;
2. the Payer-signed session mandate repeats the same intake digest and
   identifier; and
3. every commercial term matches both the intake and mandate.

`verifyPaymentRequest` requires equality of both intake fields. The aggregate
verifier uses the existing signed mandate and signed formal request inputs to
recheck those bindings before evaluating the three Clockchain anchors.

The MCP response itself is not a signed authorization artifact. Its immediate
integrity comes from the Payer-owned TLS-pinned connection; the Payer's later
EIP-191 mandate signature is the durable proof that the Payer accepted that
exact intake.

## 5. Exact MCP tool contract

### 5.1 Tool

```text
request_payment
```

The tool is model-controlled but non-authorizing. Its description states:

> Ask this Payer to process the fixed demo payment request. A successful
> intake requires the Requestor to complete Clockchain Handshake; it does not
> move or authorize payment.

### 5.2 Input

```json
{
  "amount": {
    "currency": "USD",
    "value": "100"
  },
  "intakeRequestId": "00000000-0000-4000-8000-000000000000",
  "invoiceReference": "invoice-001",
  "paymentMoved": false,
  "purpose": "Handshake demo",
  "schema": "clockchain.payer-mcp-payment-intake/v1"
}
```

Rules:

- The object and all nested objects use exact keys.
- `intakeRequestId` is a canonical UUID and is the idempotency key.
- Currency, value, purpose, and invoice prefix must match the shared policy.
- `paymentMoved` must be exactly `false`.
- Unknown, duplicate, accessor-backed, proxied, oversized, malformed, or
  noncanonical input fails closed.

The exact digest is:

```text
intakeDigest =
  lowercase_hex(
    SHA-256(
      bilateral_canonical_bytes(validated request_payment input)
    )
  )
```

The digest preimage is only the exact validated tool input object shown above.
It excludes the JSON-RPC envelope, HTTP headers, MCP session ID, tool result,
and text content block. `bilateral_canonical_bytes` is the repository's
existing UTF-8 JSON profile: lexicographically ordered keys, no trailing
newline, printable bounded strings, no numbers, and exact nested data
properties.

### 5.3 Structured result

```json
{
  "authorizationSequence": [
    "PROPOSED",
    "ACCEPTED",
    "ACKNOWLEDGED"
  ],
  "intakeDigest": "64-lowercase-hex",
  "intakeRequestId": "canonical-uuid",
  "mandatePreview": {
    "amount": {
      "currency": "USD",
      "value": "100"
    },
    "invoiceReferencePrefix": "invoice-",
    "purpose": "Handshake demo"
  },
  "nextAction": "START_REQUESTOR_SUPERVISOR",
  "paymentMoved": false,
  "protocol": "clockchain.bilateral-authorization/v1",
  "repositorySha": "40-lowercase-hex",
  "schema": "clockchain.payer-mcp-handshake-required/v1",
  "status": "HANDSHAKE_REQUIRED"
}
```

The MCP tool result contains this object in `structuredContent` and the exact
canonical JSON serialization in one text content block. The client validates
both and requires byte-equivalent values.

`HANDSHAKE_REQUIRED` means only that the Payer accepted the intake request for
the Handshake path. The later Payer-signed mandate proves which intake the
Payer accepted. The result is not `PROPOSED`, `ACCEPTED`, `ACKNOWLEDGED`,
`VERIFICATION_PASSED`, or `AUTHORIZED`.

## 6. Replay and persistence

The Payer MCP server stores intake records under its private mode-`0700` state
root. Each record is canonical JSON in a mode-`0600` file keyed by
`intakeRequestId`.

- A first valid request creates one record with exclusive-create semantics.
- A byte-identical retry returns the identical structured result.
- Reusing the same `intakeRequestId` with changed bytes fails closed.
- A restart revalidates the persisted record before returning it.
- Partial, temporary, symlinked, hard-linked, non-owner, wrong-mode, or
  changed files fail closed.
- MCP intake records are never relay events or Clockchain anchors.

For both the rehearsal and stakeholder runs:

- the Payer-signed session mandate includes the exact `intakeDigest` and
  `intakeRequestId`;
- the Requestor-signed formal payment request repeats both values;
- the request validator requires equality with the signed mandate;
- the descriptor's existing mandate and request digests transitively commit to
  the intake; and
- the fresh verifier rechecks both signed artifacts before any authorization
  verdict.

The formal payment request retains its own per-run `requestId`. The one
`intakeRequestId` may be referenced by both runs without colliding with the
relay's per-run formal request storage.

## 7. Trust and authority

The manual demo has three distinct trust layers:

1. **Payer MCP intake:** TLS-pinned discovery, policy preview, and canonical
   commercial-intent commitment.
2. **Authenticated coordination:** role enrollment, signed session mandate,
   signed Requestor payment request, exact matching, and supervisor control.
3. **Clockchain authorization proof:** exactly three independently
   re-verifiable anchors and a fresh aggregate verifier.

The MCP server cannot:

- publish a coordination event;
- write to Clockchain;
- sign or publish a session mandate before both role identities are
  authenticated;
- create a signed Requestor payment request;
- start the Payer or Requestor role command;
- publish verifier evidence; or
- emit the authorization literal.

Only the fresh aggregate verifier may output `AUTHORIZED`.

## 8. Manual operating flow

The human operator starts the existing relay, coordinator, and read-only
console and privately distributes the two role launch manifests.

The Payer agent then:

1. verifies its clean exact checkout;
2. creates or receives its public TLS certificate and keeps the TLS private key
   local;
3. starts the Payer supervisor with the additional Payer-only MCP bind and TLS
   arguments;
4. reports only the public MCP URL, certificate, and fingerprint after the
   supervisor reports `PAYER_MCP_READY`; and
5. remains attached while the supervisor waits safely for the intake request
   and Requestor enrollment.

The Requestor agent then:

1. verifies its clean exact checkout;
2. receives the public Payer MCP URL, certificate, fingerprint, and its own
   private launch-manifest path;
3. runs `npm run bilateral:request-payment` once; and
4. observes `HANDSHAKE_REQUIRED` and the validated intake commitment before
   the command starts its Requestor supervisor.

The supervisors complete the existing signed mandate, signed request, exact
match, rehearsal, stakeholder run, and verifier sequence.

## 9. Failure behavior

Failures expose one generic, secret-free code per boundary:

- `PAYER_MCP_STARTUP_FAILED`
- `PAYER_MCP_REQUEST_INVALID`
- `PAYER_MCP_PROTOCOL_FAILED`
- `REQUEST_PAYMENT_FAILED`

No raw exception, request body, path contents, capability, invitation, token,
private key, certificate private key, RPC URL, or live evidence is printed.

The Requestor supervisor must not start on:

- TLS or fingerprint mismatch;
- DNS, redirect, proxy, or hostname ambiguity;
- unsupported MCP version or capability;
- absent or extra tools;
- malformed tool schemas;
- missing, duplicate, reordered, expired, malformed, or mismatched tool
  results;
- `paymentMoved:true`;
- any result other than `HANDSHAKE_REQUIRED`;
- changed duplicate request bytes; or
- MCP timeout or premature disconnect.

The server returns the same generic unauthorized response and consumes no
intake state for missing, malformed, or incorrect capabilities. It applies
the exact process-wide and per-session limits from section 4.2 before
expensive parsing and never distinguishes unknown capability values.

The Payer supervisor also fails closed if it reaches commercial-intent
construction without exactly one validated intake or if its persisted intake
differs from the Requestor's repeated intake commitment.

## 10. Testing

### 10.1 Unit tests

- Exact intake request and response validation.
- Shared policy used by both MCP and supervisor.
- Byte-identical replay versus changed duplicate rejection.
- Hostile objects, unknown keys, unsafe strings, wrong terms, wrong sequence,
  wrong repository SHA, and `paymentMoved:true`.
- Payer mandate and formal payment request must carry the exact intake digest
  and identifier.

### 10.2 MCP transport tests

- Initialization must be first.
- Exact protocol-version negotiation and session header behavior.
- Every POST sends
  `Accept: application/json, text/event-stream`; the pinned server returns
  JSON, and an unexpected SSE response fails closed.
- `notifications/initialized` returns `202`.
- `tools/list` exposes exactly one tool with exact schemas.
- `tools/call` accepts only `request_payment`.
- GET returns `405`; DELETE retires the session.
- Missing or wrong session IDs, versions, methods, paths, Accept headers,
  content types, origins, and body limits fail closed.
- TLS certificate and fingerprint pinning rejects hostname changes, alternate
  certificates, redirects, and proxy escape hatches.
- Missing, malformed, and wrong intake capabilities fail before tool
  execution without revealing which value was wrong.
- The seventeenth failed authentication attempt inside one rolling 60-second
  window receives the generic rate-limit response, and a valid capability
  works again after the window expires.
- An authenticated MCP session is retired after its eighth HTTP request.

### 10.3 Integration tests

- Payer MCP server and real Requestor client complete one intake.
- Requestor supervisor launch is observed only after a valid
  `HANDSHAKE_REQUIRED` response.
- MCP failure leaves the Requestor supervisor unstarted.
- Restart returns one identical intake result.
- Payer waits for exactly one intake and binds it into both run mandates.
- Requestor repeats the same intake commitment in both formal requests.
- A changed intake commitment fails before `PAYMENT_REQUEST_MATCHED`.
- The isolated multiprocess Handshake still produces exactly three Clockchain
  writes.
- The console, coordinator, Payer, Requestor, watcher, and MCP source contain
  no unauthorized construction of the authorization literal.

### 10.4 Manual acceptance

Using one human operator and two fresh blank-context agents:

1. Payer agent starts its Payer supervisor, which starts the local MCP server.
2. Requestor agent calls `request_payment`.
3. Requestor visibly receives `HANDSHAKE_REQUIRED`.
4. Requestor supervisor starts only afterward.
5. The exact intake digest and identifier appear in the Payer-signed session
   mandate and Requestor-signed formal payment request.
6. The exact signed session mandate and Requestor payment request match.
7. Clockchain contains exactly Payer `PROPOSED`, Requestor `ACCEPTED`, and
   Payer `ACKNOWLEDGED`, in order.
8. A fresh verifier independently refetches all three anchors.
9. Only that verifier outputs `AUTHORIZED`.
10. Every result states `paymentMoved:false`.
11. The public handbook shows the Payer MCP step, both role prompts, exact
    expected output, failure outcomes, and no hosted-MCP claim.

## 11. Completion criteria

The feature is complete only when:

- the local MCP server and Requestor client pass focused tests;
- independent review confirms MCP has no authority path;
- the corrected isolated multiprocess test passes;
- the fresh Payer/Requestor agent rehearsal passes;
- the public handbook is deployed with the local MCP flow;
- the repository is clean at an immutable release SHA; and
- one final fresh `npm run verify` passes.

Passing deterministic tests alone means rehearsal-ready, not live-validated.

## 12. Protocol references

- [MCP 2025-11-25 lifecycle](https://modelcontextprotocol.io/specification/2025-11-25/basic/lifecycle)
- [MCP 2025-11-25 Streamable HTTP transport](https://modelcontextprotocol.io/specification/2025-11-25/basic/transports)
- [MCP 2025-11-25 tools contract](https://modelcontextprotocol.io/specification/2025-11-25/server/tools)
