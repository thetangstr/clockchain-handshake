# Live Receipt and Email Design

**Date:** 2026-08-01  
**Status:** Approved for implementation planning  
**Repositories:** `clockchain-handshake`, `clockchain-research`

## Purpose

Make the stakeholder demo legible while it is running. The public monitor will show one business-readable Clockchain proof card as each protocol anchor is independently observed. After the fresh aggregate verifier confirms the complete run, the page will offer an opt-in form that sends one richer HTML receipt to the stakeholder's email address.

The display and email are evidence views. They do not participate in the protocol and cannot authorize a run.

## Product Result

The public run page shows the exact protocol order:

1. Payer `PROPOSED`
2. Requestor `ACCEPTED`
3. Payer `ACKNOWLEDGED`
4. Fresh aggregate verifier result

Each completed anchor becomes a receipt card containing:

- signer role;
- transition name;
- Clockchain ledger ID;
- Clockchain block height;
- exact cardinality of one;
- independently observed status;
- public explorer link; and
- the run-wide `paymentMoved:false` boundary.

An incomplete card is never presented as a receipt. Cards appear only for an authenticated, ordered prefix of the three anchors. A missing, duplicate, reordered, malformed, mismatched, or unverified anchor makes the projection unavailable rather than partially trusted.

After the run becomes freshly `VERIFIED`, the page reveals an email field and **Email verified receipt** action. One submitted address receives one HTML email with the complete three-card proof, the fresh verifier result, the run ID, the testnet/no-settlement explanation, and a plain-text fallback.

At completion, the page switches the final receipt view from the expiring live snapshot to the immutable `runs/{runId}.json` summary. The same receipt and email action remain available in the historical run detail after the live services stop.

## Considered Approaches

### 1. Public proof cards plus one final email — selected

The monitor publishes compact public receipt fields as each anchor validates. Email delivery is enabled only after the immutable verified run summary exists.

This provides live business visibility without sending provisional claims or exposing raw evidence.

### 2. Full receipt JSON in the live page

This maximizes technical detail but makes the demo harder to read and expands the public schema to material the stakeholder does not need. Raw role evidence also creates an avoidable disclosure surface.

### 3. One email per anchor

This provides push updates but can make provisional progress look final, produces three messages per run, and complicates failure and expiry semantics. It is rejected for the demo.

## Public Monitor Contract

The public monitor schema advances from `clockchain.bilateral-public-monitor/v2` to `clockchain.bilateral-public-monitor/v3`.

Each public anchor has exactly these fields:

```json
{
  "block": "2553516",
  "cardinality": "1",
  "explorerUrl": "https://sepolia.etherscan.io/block/2553516",
  "kind": "ACCEPTED",
  "ledgerId": "b5b34a59-4e10-482e-bb1a-e1b2b7374c20",
  "signerRole": "Requestor",
  "verified": true
}
```

The producer already validates ledger IDs, blocks, cardinality, order, uniqueness, and verification in the AWS watcher projection. Version 3 retains those values in the sanitized public projection instead of discarding them.

The research site parser accepts exact version 2 and exact version 3 snapshots during rollout. Version 2 remains a block-link display. Version 3 becomes a receipt card. Unknown versions or additional keys fail closed.

The page continues polling the CloudFront `latest.json` object every two seconds. A newly validated anchor therefore appears without a page reload. A receipt card never changes after it appears except when the complete run moves into verifier-confirmed status.

## Email Delivery Contract

### Public form

The form is hidden until a validated immutable run summary satisfies all of the following:

- `runStatus` is `VERIFIED`;
- verifier status is `VERIFIED`;
- exactly three ordered receipt cards are present;
- every card is independently verified with cardinality one; and
- `paymentMoved` is exactly `false`.

The browser submits only:

```json
{
  "email": "stakeholder@example.com",
  "runId": "run-0123456789abcdef"
}
```

The browser cannot submit receipt fields, verifier claims, HTML, subject lines, or links.

### AWS receipt endpoint

A dedicated public API Gateway route invokes a receipt-email Lambda. The Lambda:

1. validates the request shape and bounded email syntax;
2. reads the immutable public run summary for the supplied run ID from the existing public artifact store;
3. applies the exact public summary and anchor validators;
4. refuses non-`VERIFIED`, stale, malformed, mismatched, or non-three-anchor runs;
5. renders fixed HTML and plain-text templates from the validated summary;
6. sends with Amazon SES from a configured, verified Clockchain sender identity; and
7. records only a one-way recipient digest for idempotency, never the plaintext address.

The endpoint has a narrow CORS allowlist for the research site, a bounded request size, API throttling, one delivery per `runId + normalized recipient`, and a small maximum number of recipients per run. It returns the same generic success response for a first send and an idempotent replay.

Email addresses are not written to Git, the public monitor, the immutable run summary, application logs, analytics, or role state. Structured logs record only the run ID, outcome code, and recipient digest. SES receives the plaintext destination only for delivery.

### Email content

The HTML email uses a fixed Clockchain template containing:

- `Clockchain Handshake Receipt` heading;
- `Verified` result issued only from the immutable verified summary;
- a short business explanation of the Payer mandate and Requestor acceptance;
- the three ordered proof cards;
- full ledger IDs and block heights;
- public explorer links;
- run ID and completion time;
- `paymentMoved:false` shown as **No represented payment moved**; and
- a Sepolia/testnet/single-validator/no-settlement disclaimer.

The email never uses the authorization literal as an operator or page claim. It states that the fresh aggregate verifier confirmed the evidence. The verifier remains the only component that produces the authorization result.

## Failure Behavior

- Before fresh verification, the email form is absent and the endpoint returns `RECEIPT_NOT_READY`.
- A malformed email, run ID, summary, or anchor returns a generic failure without reflecting supplied values.
- SES failure leaves the run unchanged and permits a bounded retry; it never changes protocol or verifier state.
- A duplicate request does not send a duplicate message.
- An expired or failed run may remain visible as failed/expired history but cannot send a verified receipt.
- Monitor publication failure makes the public view unavailable. It cannot fall back to advisory relay fields or agent prose.

## Component Boundaries

### `clockchain-handshake`

- Preserve ledger ID, cardinality, and verified state in the sanitized version 3 projection.
- Validate version 3 snapshots and immutable run summaries exactly.
- Add the receipt-email renderer, request validator, idempotency record, Lambda handler, SES permission, API route, and deployment outputs.
- Keep private protocol artifacts outside the email and public publication paths.

### `clockchain-research`

- Parse exact version 2 and version 3 monitor snapshots.
- Render one receipt card per validated version 3 anchor.
- Keep fresh verifier status visually separate from anchor receipts.
- Show the final email form only for a complete verified version 3 run.
- Submit only email and run ID, show bounded success/failure feedback, and never persist the email in browser storage.

## Rollout

1. Deploy the research site parser and UI with dual version 2/version 3 support.
2. Deploy the AWS version 3 publisher and receipt-email endpoint.
3. Confirm `latest.json` produces an ordered prefix during a live run.
4. Confirm all three proof cards and the verifier result appear at completion.
5. Send one receipt to a controlled test address and verify the HTML and plain-text content.
6. Confirm a repeated submission is idempotent and a non-verified run is rejected.

## Verification

Targeted checks cover:

- exact version 3 public snapshot parsing;
- rejection of missing, extra, reordered, duplicated, unverified, non-cardinality-one, private, or malformed receipt fields;
- ordered prefix rendering as anchors complete;
- form absence before fresh verification;
- endpoint refusal of browser-supplied receipt content;
- immutable summary revalidation before send;
- HTML escaping and plain-text rendering;
- no email address in logs or public artifacts;
- idempotent duplicate submissions;
- SES failure and bounded retry; and
- `paymentMoved:false` throughout.

After focused checks pass, deployment receives a public monitor smoke check and one controlled delivery smoke check. The full repository verification suite remains the final integration gate, not the first iteration loop.

## Non-Goals

- Production payment settlement.
- A general notification service or mailing list.
- Per-anchor emails.
- Public raw role receipts, signatures, tokens, manifests, paths, keys, capabilities, or agent transcripts.
- Email-based authorization or approval.
- Long-term storage or analytics of stakeholder email addresses.
