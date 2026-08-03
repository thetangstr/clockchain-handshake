# Live Receipt, Email, and Hermes Acceptance Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Publish a business-readable Clockchain proof card as each Handshake anchor completes, send one opt-in HTML receipt only after fresh aggregate verification, deploy the result, and prove the stakeholder path with a fresh Hermes `handshake_requester` run.

**Architecture:** The Handshake producer upgrades its sanitized monitor and immutable history contracts to retain only the public receipt fields already validated by the watcher. A dedicated API Gateway HTTP API invokes a small Node.js 22 Lambda that re-reads an immutable verified summary, claims an idempotent delivery record in DynamoDB, and sends a fixed HTML/plain-text message through SES. The research site accepts old and new public contracts during rollout, renders live receipt cards, and shows the email form only from a verified immutable summary.

**Tech Stack:** Node.js 22 ES modules, `node:test`, AWS CDK v2, API Gateway HTTP API, Lambda, DynamoDB, S3, Amazon SES v2, AWS SDK for JavaScript v3, Next.js 16, React 19, TypeScript, Vitest, Vercel, browser-harness, local Hermes `handshake_requester` profile.

---

## Workspaces and guardrails

- Handshake repository: `/Users/Kailor/conductor/workspaces/clockchain-handshake/riyadh-v3`
- Research-site worktree: `/Users/Kailor/.config/superpowers/worktrees/clockchain-research/aws-stakeholder-run`
- The research worktree already contains uncommitted stakeholder-runbook work. Inspect and preserve it before every edit; never reset or overwrite it.
- Treat all public monitor, history, email, and UI fields as untrusted until exact validation succeeds.
- The browser submits only `email` and `runId`; it never submits receipt data, HTML, a verdict, or links.
- Only the fresh aggregate verifier produces the authorization result. Page, email handler, monitor, operator, Payer, and Requestor only report verifier-confirmed evidence.
- Keep `paymentMoved:false` in every public artifact, response, test, display, and email.
- Use focused checks during Tasks 1–8. Run the complete Handshake verification suite once in Task 9.
- AWS deployment is a deliberate demo mutation. Production Clockchain data remains read-only; only Sepolia gas, the demo AWS stack, the public research site, and one user-authorized receipt email are in mutation scope.

## File responsibility map

### Handshake producer and public contracts

- `src/bilateral/coordination/public-monitor.mjs` — exact v2/v3 monitor projection and observation.
- `src/bilateral/coordination/console-projection.mjs` — preserve watcher ledger ID and cardinality through the verified console path.
- `src/bilateral/coordination/coordinator-runtime.mjs` — include exact watcher receipt facts in final public staging.
- `src/bilateral/aws/public-history.mjs` — exact immutable v2 summary/index validators and public artifact creation.
- `scripts/publish-aws-public-monitor.mjs` — publish the new live and immutable artifacts without private evidence.

### Receipt email

- `src/bilateral/aws/receipt-email.mjs` — pure request validation, verified-summary gate, HTML/plain-text rendering, and dependency-injected delivery state machine.
- `infra/aws/lambda/receipt-email-handler.mjs` — thin AWS SDK adapter for S3, DynamoDB, and SES v2.
- `infra/aws/lib/clockchain-handshake-stack.ts` — table, Lambda, API, throttling, CORS, IAM, logs, alarm, and outputs.
- `infra/aws/scripts/deploy.mjs` — validate and pass the configured sender identity.
- `infra/aws/package.json` and `infra/aws/package-lock.json` — pin `@aws-sdk/client-sesv2` to the existing SDK version family.

### Public site

- `src/lib/bilateral-public-monitor.ts` — dual exact v2/v3 parser.
- `src/lib/bilateral-public-history.ts` — dual exact v1/v2 history parser.
- `src/components/BilateralReceiptCard.tsx` — one reusable business-readable proof card.
- `src/components/BilateralPublicMonitor.tsx` — append cards live as ordered anchors appear.
- `src/components/BilateralHandshakeHistory.tsx` — durable final cards and email action from immutable verified history.
- `src/components/VerifiedReceiptEmailForm.tsx` — bounded email input and submission feedback without persistence.
- `src/data/bilateral-handshake-demo.ts` — published receipt endpoint and final reviewed release SHA.

### Acceptance evidence

- `docs/demo-evidence/latest.md` — final public URLs, reviewed SHA, Hermes evidence, three Clockchain receipts, verifier result, email delivery result, and remaining caveats.

---

### Task 1: Preserve exact receipt facts in public monitor v3

**Files:**
- Modify: `src/bilateral/coordination/public-monitor.mjs`
- Modify: `src/bilateral/coordination/console-projection.mjs`
- Modify: `src/bilateral/coordination/coordinator-runtime.mjs`
- Test: `test/bilateral-public-monitor.test.mjs`
- Test: `test/bilateral-console-projection.test.mjs`
- Test: `test/bilateral-watcher.test.mjs`
- Test: `test/helpers/aws-control-plane-child.mjs`

- [ ] **Step 1: Write the failing monitor contract assertions**

Update the AWS watcher snapshot assertions so every verified anchor has exactly these public fields:

```js
assert.deepEqual(snapshot.anchors[0], {
  block: "101",
  cardinality: "1",
  explorerUrl: "https://sepolia.etherscan.io/block/101",
  kind: "PROPOSED",
  ledgerId: "00000000-0000-4000-8000-000000000001",
  signerRole: "Payer",
  verified: true,
});
assert.equal(
  snapshot.schema,
  "clockchain.bilateral-public-monitor/v3",
);
```

Add rejection cases that remove `ledgerId`, change `cardinality` to `"2"`, set `verified:false`, duplicate a ledger ID, add an unknown field, or reorder anchors.

- [ ] **Step 2: Run the focused tests and observe the expected failure**

Run:

```bash
node --test \
  test/bilateral-public-monitor.test.mjs \
  test/bilateral-console-projection.test.mjs \
  test/bilateral-watcher.test.mjs
```

Expected: FAIL because the current v2 projection discards `ledgerId`, `cardinality`, and `verified`.

- [ ] **Step 3: Implement the exact v3 anchor shape**

Use these exact public keys in `public-monitor.mjs`:

```js
export const PUBLIC_MONITOR_SCHEMA =
  "clockchain.bilateral-public-monitor/v3";

const PUBLIC_ANCHOR_KEYS = Object.freeze([
  "block",
  "cardinality",
  "explorerUrl",
  "kind",
  "ledgerId",
  "signerRole",
  "verified",
]);
```

Map only watcher-validated facts:

```js
anchors.push(Object.freeze({
  block: transition.blockHeight,
  cardinality: "1",
  explorerUrl:
    `https://sepolia.etherscan.io/block/${transition.blockHeight}`,
  kind: expected.kind,
  ledgerId: transition.ledgerId,
  signerRole: expected.signerRole,
  verified: true,
}));
```

Extend the console-projection anchor validator to require the same `ledgerId`, `cardinality:"1"`, and `verified:true`, and include those facts when `coordinator-runtime.mjs` constructs final verified anchors. Keep digest only in the private console projection; do not add it to the public anchor.

- [ ] **Step 4: Run the focused monitor tests**

Run the command from Step 2.

Expected: PASS with ordered prefixes of zero through three anchors and fail-closed rejection of malformed receipt facts.

- [ ] **Step 5: Commit the monitor contract**

```bash
git add \
  src/bilateral/coordination/public-monitor.mjs \
  src/bilateral/coordination/console-projection.mjs \
  src/bilateral/coordination/coordinator-runtime.mjs \
  test/bilateral-public-monitor.test.mjs \
  test/bilateral-console-projection.test.mjs \
  test/bilateral-watcher.test.mjs \
  test/helpers/aws-control-plane-child.mjs
git commit -m "Keep each public anchor independently verifiable" \
  -m "Constraint: Public receipt cards require ledger identity and exact cardinality without exposing raw role evidence.
Rejected: Publishing full role receipts | They broaden disclosure and are unnecessary for verification.
Confidence: high
Scope-risk: moderate
Directive: Preserve exact ordered-prefix validation and paymentMoved:false.
Tested: focused public monitor, console projection, and watcher tests
Not-tested: AWS deployment and stakeholder UI"
```

### Task 2: Make immutable public history receipt-complete

**Files:**
- Modify: `src/bilateral/aws/public-history.mjs`
- Modify: `scripts/publish-aws-public-monitor.mjs`
- Test: `test/aws-public-history.test.mjs`
- Test: `test/aws-public-monitor-publisher.test.mjs`
- Test: `test/aws-public-staging.test.mjs`
- Test: `test/aws-publisher-runtime.test.mjs`

- [ ] **Step 1: Write failing immutable-summary tests**

Require version 2 immutable artifacts and the complete anchor shape:

```js
assert.equal(
  summary.schema,
  "clockchain.aws-public-run-summary/v2",
);
assert.equal(
  index.schema,
  "clockchain.aws-public-run-index/v2",
);
assert.deepEqual(summary.anchors[1], {
  block: "102",
  cardinality: "1",
  explorerUrl: "https://sepolia.etherscan.io/block/102",
  kind: "ACCEPTED",
  ledgerId: "00000000-0000-4000-8000-000000000002",
  signerRole: "Requestor",
  verified: true,
});
```

Add a public `observeImmutableRunSummary(value)` test that accepts only exact version 2 terminal summaries and rejects a `VERIFIED` summary with fewer than three valid receipts.

- [ ] **Step 2: Run focused history tests and observe failure**

```bash
node --test \
  test/aws-public-history.test.mjs \
  test/aws-public-monitor-publisher.test.mjs \
  test/aws-public-staging.test.mjs \
  test/aws-publisher-runtime.test.mjs
```

Expected: FAIL because current history is version 1 and lacks the new receipt fields.

- [ ] **Step 3: Implement exact version 2 history**

Set:

```js
export const AWS_PUBLIC_RUN_SUMMARY_SCHEMA =
  "clockchain.aws-public-run-summary/v2";
export const AWS_PUBLIC_RUN_INDEX_SCHEMA =
  "clockchain.aws-public-run-index/v2";
```

Export an observer that reuses exact summary validation and returns a frozen copy:

```js
export function observeImmutableRunSummary(value) {
  try {
    const summary = exact(value, SUMMARY_KEYS);
    if (
      summary.schema !== AWS_PUBLIC_RUN_SUMMARY_SCHEMA ||
      summary.paymentMoved !== false
    ) fail();
    const checked = indexEntry({
      anchors: summary.anchors,
      businessResult: summary.businessResult,
      completedAtMs: summary.completedAtMs,
      runId: summary.runId,
      runStatus: summary.runStatus,
      summaryUrl: summary.summaryUrl,
    });
    if (
      checked.runStatus === "VERIFIED" &&
      checked.anchors.length !== 3
    ) fail();
    return Object.freeze({ ...summary, anchors: checked.anchors });
  } catch (error) {
    if (error instanceof AwsPublicHistoryError) throw error;
    fail();
  }
}
```

Ensure `indexEntry` validates each anchor with the v3 public monitor observer rather than merely checking array length.

- [ ] **Step 4: Run focused history tests**

Run the Step 2 command.

Expected: PASS; publisher writes `latest.json`, `runs/index.json`, and `runs/{runId}.json` with no secret canary leakage.

- [ ] **Step 5: Commit immutable receipt history**

```bash
git add \
  src/bilateral/aws/public-history.mjs \
  scripts/publish-aws-public-monitor.mjs \
  test/aws-public-history.test.mjs \
  test/aws-public-monitor-publisher.test.mjs \
  test/aws-public-staging.test.mjs \
  test/aws-publisher-runtime.test.mjs
git commit -m "Keep verified receipts durable after the live run" \
  -m "Constraint: Email and historical views must re-read immutable verified public evidence.
Rejected: Reusing expiring latest.json | It disappears after live services stop.
Confidence: high
Scope-risk: moderate
Directive: Do not weaken exact terminal-summary validation.
Tested: focused public history, staging, publisher, and runtime tests
Not-tested: SES delivery and public UI"
```

### Task 3: Build the pure receipt-email boundary

**Files:**
- Create: `src/bilateral/aws/receipt-email.mjs`
- Create: `test/aws-receipt-email.test.mjs`

- [ ] **Step 1: Write failing request, rendering, and idempotency tests**

Define a dependency-injected handler contract:

```js
const handler = createReceiptEmailHandler({
  allowedOrigin: "https://clockchain-research.vercel.app",
  claimDelivery: async () => "CLAIMED",
  completeDelivery: async () => undefined,
  failDelivery: async () => undefined,
  fromEmail: "receipts@clockchain.network",
  readSummary: async () => verifiedSummary(),
  sendEmail: async (message) => calls.push(message),
});

const response = await handler({
  body: JSON.stringify({
    email: "stakeholder@example.com",
    runId: "run-0123456789abcdef",
  }),
  headers: {
    "content-type": "application/json",
    origin: "https://clockchain-research.vercel.app",
  },
  httpMethod: "POST",
  path: "/receipt-email",
});

assert.equal(response.statusCode, 202);
assert.equal(calls.length, 1);
assert.match(calls[0].html, /Clockchain Handshake Receipt/);
assert.match(calls[0].html, /b5b34a59-4e10-482e-bb1a-e1b2b7374c20/);
assert.doesNotMatch(calls[0].html, /AUTHORIZED/);
assert.match(calls[0].text, /No represented payment moved/);
```

Add cases for malformed email/run ID/body/headers, extra keys, wrong origin, non-verified/failed/expired summary, fewer than three receipts, duplicate claim, SES failure, HTML injection, plaintext email in dependency logs, and `paymentMoved:true`.

- [ ] **Step 2: Run the new test and observe failure**

```bash
node --test test/aws-receipt-email.test.mjs
```

Expected: FAIL because `receipt-email.mjs` does not exist.

- [ ] **Step 3: Implement the pure handler**

Export exactly:

```js
import { createHash } from "node:crypto";
import {
  observeImmutableRunSummary,
} from "./public-history.mjs";

const EMAIL =
  /^(?=.{3,254}$)[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+$/;
const RUN_ID = /^run-[0-9a-f]{16}$/;

export const RECEIPT_EMAIL_PATH = "/receipt-email";

function digest(value) {
  return createHash("sha256")
    .update(value, "utf8")
    .digest("hex");
}

function escapeHtml(value) {
  return value
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

function reply(statusCode, status, allowedOrigin) {
  return {
    body: JSON.stringify({ paymentMoved: false, status }),
    headers: {
      "access-control-allow-origin": allowedOrigin,
      "content-type": "application/json",
    },
    statusCode,
  };
}

function request(value) {
  if (
    value === null ||
    typeof value !== "object" ||
    Array.isArray(value) ||
    Reflect.ownKeys(value).length !== 2 ||
    !Object.hasOwn(value, "email") ||
    !Object.hasOwn(value, "runId") ||
    typeof value.email !== "string" ||
    !EMAIL.test(value.email) ||
    typeof value.runId !== "string" ||
    !RUN_ID.test(value.runId)
  ) throw new Error("invalid");
  return {
    email: value.email.toLowerCase(),
    runId: value.runId,
  };
}

export function renderVerifiedReceiptEmail(value) {
  const summary = observeImmutableRunSummary(value);
  if (
    summary.runStatus !== "VERIFIED" ||
    summary.paymentMoved !== false ||
    summary.anchors.length !== 3
  ) throw new Error("not ready");
  const cards = summary.anchors.map((anchor) => `
    <section>
      <h2>${escapeHtml(anchor.signerRole)} ${escapeHtml(anchor.kind)}</h2>
      <p>Ledger ID: <code>${escapeHtml(anchor.ledgerId)}</code></p>
      <p>Block: ${escapeHtml(anchor.block)}</p>
      <p>Cardinality: Exactly 1</p>
      <p><a href="${escapeHtml(anchor.explorerUrl)}">Open independent proof</a></p>
    </section>`).join("");
  const textCards = summary.anchors.map((anchor) =>
    `${anchor.signerRole} ${anchor.kind}\nLedger ID: ${anchor.ledgerId}\nBlock: ${anchor.block}\nCardinality: Exactly 1\n${anchor.explorerUrl}`,
  ).join("\n\n");
  return Object.freeze({
    html: `<!doctype html><html><body><h1>Clockchain Handshake Receipt</h1><p>Fresh aggregate verification confirmed all three independently verifiable anchors.</p>${cards}<p>No represented payment moved.</p><p>Sepolia testnet, single validator, no settlement.</p></body></html>`,
    subject: `Clockchain Handshake Receipt — ${summary.runId}`,
    text: `Clockchain Handshake Receipt\n\nFresh aggregate verification confirmed all three independently verifiable anchors.\n\n${textCards}\n\nNo represented payment moved.\nSepolia testnet, single validator, no settlement.`,
  });
}

export function createReceiptEmailHandler(dependencies) {
  const {
    allowedOrigin,
    claimDelivery,
    completeDelivery,
    failDelivery,
    fromEmail,
    readSummary,
    sendEmail,
  } = dependencies;
  return async function handle(input) {
    if (
      input?.httpMethod !== "POST" ||
      input?.path !== RECEIPT_EMAIL_PATH ||
      input?.headers?.origin !== allowedOrigin ||
      input?.headers?.["content-type"] !== "application/json" ||
      typeof input.body !== "string" ||
      Buffer.byteLength(input.body, "utf8") > 2_048
    ) return reply(400, "RECEIPT_EMAIL_INVALID", allowedOrigin);
    let parsed;
    try {
      parsed = request(JSON.parse(input.body));
    } catch {
      return reply(400, "RECEIPT_EMAIL_INVALID", allowedOrigin);
    }
    let summary;
    let message;
    try {
      summary = observeImmutableRunSummary(
        await readSummary(parsed.runId),
      );
      message = renderVerifiedReceiptEmail(summary);
    } catch {
      return reply(409, "RECEIPT_NOT_READY", allowedOrigin);
    }
    const recipientDigest = digest(parsed.email);
    const deliveryId = digest(`${parsed.runId}\0${parsed.email}`);
    const claim = await claimDelivery({
      deliveryId,
      recipientDigest,
      runId: parsed.runId,
    });
    if (claim === "SENT") {
      return reply(202, "RECEIPT_EMAIL_ACCEPTED", allowedOrigin);
    }
    try {
      await sendEmail({
        fromEmail,
        html: message.html,
        subject: message.subject,
        text: message.text,
        toEmail: parsed.email,
      });
      await completeDelivery({ deliveryId });
      return reply(202, "RECEIPT_EMAIL_ACCEPTED", allowedOrigin);
    } catch {
      await failDelivery({ deliveryId });
      return reply(502, "RECEIPT_EMAIL_FAILED", allowedOrigin);
    }
  };
}
```

Use this bounded email rule:

```js
const EMAIL =
  /^(?=.{3,254}$)[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+$/;
```

Normalize with `email.toLowerCase()`, derive `recipientDigest` from `sha256(normalizedEmail)`, derive `deliveryId` from `sha256(runId + "\0" + normalizedEmail)`, and pass only those digests to delivery-state dependencies. Escape `&`, `<`, `>`, `"`, and `'` before inserting any validated public string into HTML.

The exact success body is:

```js
{
  body: JSON.stringify({
    paymentMoved: false,
    status: "RECEIPT_EMAIL_ACCEPTED",
  }),
  headers: {
    "access-control-allow-origin": allowedOrigin,
    "content-type": "application/json",
  },
  statusCode: 202,
}
```

Return the same response for `CLAIMED`, `SENT`, and an idempotent duplicate. Return generic bounded codes for invalid/not-ready/send-failed paths without reflecting email or receipt input.

- [ ] **Step 4: Run the pure email tests**

```bash
node --test test/aws-receipt-email.test.mjs
```

Expected: PASS with no plaintext recipient in public responses or captured structured log values.

- [ ] **Step 5: Commit the pure email boundary**

```bash
git add src/bilateral/aws/receipt-email.mjs test/aws-receipt-email.test.mjs
git commit -m "Send only verifier-confirmed public receipts" \
  -m "Constraint: The browser cannot author receipt content or a verdict.
Rejected: Client-rendered email payloads | They let untrusted callers define evidence.
Confidence: high
Scope-risk: moderate
Directive: Re-read and exactly validate immutable public history before every send.
Tested: focused request, rendering, injection, readiness, and idempotency tests
Not-tested: live SES delivery"
```

### Task 4: Add the AWS receipt-email adapter and infrastructure

**Files:**
- Create: `infra/aws/lambda/receipt-email-handler.mjs`
- Modify: `infra/aws/lib/clockchain-handshake-stack.ts`
- Modify: `infra/aws/scripts/deploy.mjs`
- Modify: `infra/aws/package.json`
- Modify: `infra/aws/package-lock.json`
- Test: `infra/aws/test/receipt-email-handler.test.mjs`
- Test: `infra/aws/test/clockchain-handshake-stack.test.ts`
- Test: `infra/aws/test/iam-boundaries.test.ts`
- Test: `infra/aws/test/deployment-plan.test.mjs`

- [ ] **Step 1: Add failing thin-adapter and CDK assertions**

The handler test injects fake clients and asserts these commands only:

```js
assert.deepEqual(calls.map(({ command }) => command), [
  "GetObjectCommand",
  "TransactWriteCommand",
  "SendEmailCommand",
  "UpdateCommand",
]);
assert.equal(JSON.stringify(calls).includes("stakeholder@example.com"), true);
assert.equal(JSON.stringify(logs).includes("stakeholder@example.com"), false);
```

The stack test requires:

```ts
template.hasResourceProperties("AWS::ApiGatewayV2::Route", {
  RouteKey: "POST /v1/receipt-email",
});
template.hasResourceProperties("AWS::Lambda::Function", {
  Environment: {
    Variables: Match.objectLike({
      ALLOWED_ORIGIN: "https://clockchain-research.vercel.app",
      PUBLIC_BUCKET_NAME: Match.anyValue(),
      RECEIPT_DELIVERY_TABLE_NAME: Match.anyValue(),
      RECEIPT_SENDER_EMAIL: "receipts@clockchain.network",
    }),
  },
  Runtime: "nodejs22.x",
  Timeout: 10,
});
```

Also assert S3 read-only access to the public bucket, DynamoDB read/write access only to the delivery table, `ses:SendEmail`, 30-day encrypted logs, HTTP API CORS restricted to the research site, route throttling, and a `ReceiptEmailApiUrl` output.

- [ ] **Step 2: Run focused infrastructure tests and observe failure**

```bash
npm --prefix infra/aws test -- \
  receipt-email-handler.test.mjs \
  clockchain-handshake-stack.test.ts \
  iam-boundaries.test.ts \
  deployment-plan.test.mjs
```

Expected: FAIL because the adapter, SES dependency, CDK resources, and sender prop do not exist.

- [ ] **Step 3: Add the pinned SES v2 client**

```bash
npm --prefix infra/aws install --save-exact @aws-sdk/client-sesv2@3.1100.0
```

Expected: `infra/aws/package.json` and lockfile contain the same pinned SDK version family as S3/DynamoDB.

- [ ] **Step 4: Implement the Lambda adapter**

Initialize `S3Client`, `DynamoDBDocumentClient`, and `SESv2Client` outside the handler. Read and consume the S3 body once:

```js
const result = await s3.send(new GetObjectCommand({
  Bucket: publicBucketName,
  Key: `runs/${runId}.json`,
}));
const body = await result.Body.transformToString();
if (Buffer.byteLength(body, "utf8") > 65_536) throw new Error("invalid");
return JSON.parse(body);
```

Use a DynamoDB transaction for a new recipient: conditionally create `DELIVERY#${runId}#${recipientDigest}` and increment a `RUN#${runId}` recipient counter only while it is below five. Store only digest, status, attempt count, and TTL. On SES success update status to `SENT`; on failure update to `FAILED` and permit at most two additional conditional retries.

Send fixed UTF-8 HTML and text with `SendEmailCommand`; never pass request-supplied subject, sender, HTML, or links.

- [ ] **Step 5: Implement the CDK resources without replacing existing stateful resources**

Add a new retained on-demand DynamoDB table with TTL, a dedicated 256 MB Node.js 22 `NodejsFunction` with 10-second timeout and reserved concurrency 5, an HTTP API with Vercel-only CORS, default stage throttling of 2 requests/second and burst 4, and a 30-day KMS-encrypted log group. Use stable new construct IDs; do not rename existing constructs.

Add `receiptSenderEmail` to `ClockchainHandshakeStackProps` and `createDeploymentPlan`, validated by the same bounded email syntax. Add `ReceiptEmailApiUrl` and `ReceiptSenderEmail` outputs.

- [ ] **Step 6: Run typecheck, synth, and focused infrastructure tests**

```bash
npm --prefix infra/aws run typecheck
npm --prefix infra/aws test -- \
  receipt-email-handler.test.mjs \
  clockchain-handshake-stack.test.ts \
  iam-boundaries.test.ts \
  deployment-plan.test.mjs
npm --prefix infra/aws run deploy:plan
```

Expected: PASS; the deployment plan includes the sender identity but prints no credentials or recipients.

- [ ] **Step 7: Inspect the CDK diff before deployment**

Run the repository deployment plan and `cdk diff` with a separate output directory. Expected: only new receipt API/Lambda/table/log/IAM/output resources plus in-place policy/environment changes; no replacement of the public monitor bucket, distribution, EFS, Cognito, or existing tables.

- [ ] **Step 8: Commit the AWS adapter and infrastructure**

```bash
git add \
  infra/aws/lambda/receipt-email-handler.mjs \
  infra/aws/lib/clockchain-handshake-stack.ts \
  infra/aws/scripts/deploy.mjs \
  infra/aws/package.json \
  infra/aws/package-lock.json \
  infra/aws/test/receipt-email-handler.test.mjs \
  infra/aws/test/clockchain-handshake-stack.test.ts \
  infra/aws/test/iam-boundaries.test.ts \
  infra/aws/test/deployment-plan.test.mjs
git commit -m "Deliver verified receipts through a bounded AWS endpoint" \
  -m "Constraint: Public email delivery must be idempotent, rate-limited, and independent of protocol state.
Rejected: Function URL without API Gateway | It lacks the required public throttling boundary.
Confidence: high
Scope-risk: broad
Directive: Inspect CDK diff before every deployment and never persist plaintext recipients.
Tested: focused adapter, CDK, IAM, typecheck, and deployment-plan checks
Not-tested: live SES and public-browser delivery"
```

### Task 5: Parse receipt-complete live and immutable artifacts on the research site

**Files:**
- Modify: `src/lib/bilateral-public-monitor.ts`
- Modify: `src/lib/bilateral-public-monitor.test.ts`
- Modify: `src/lib/bilateral-public-history.ts`
- Modify: `src/lib/bilateral-public-history.test.ts`

- [ ] **Step 1: Preserve the existing research worktree before editing**

```bash
git status --short
git diff -- \
  src/lib/bilateral-public-monitor.ts \
  src/lib/bilateral-public-monitor.test.ts \
  src/lib/bilateral-public-history.ts \
  src/lib/bilateral-public-history.test.ts
```

Expected: existing user/concurrent changes are understood and retained. Stop only on an overlapping edit that cannot be merged safely.

- [ ] **Step 2: Write failing dual-version parser tests**

Add a v3 receipt fixture:

```ts
const receipt = {
  block: "102",
  cardinality: "1",
  explorerUrl: "https://clockchain.example/explorer/102",
  kind: "ACCEPTED",
  ledgerId: "00000000-0000-4000-8000-000000000002",
  signerRole: "Requestor",
  verified: true,
};
```

Assert exact v2 monitor/v1 history compatibility during rollout, exact v3 monitor/v2 history receipt parsing, and rejection of extra/missing/duplicate/reordered/bad-cardinality/unverified receipt fields.

- [ ] **Step 3: Run focused Vitest and observe failure**

```bash
npm test -- \
  src/lib/bilateral-public-monitor.test.ts \
  src/lib/bilateral-public-history.test.ts
```

Expected: FAIL because current parsers know only v2 monitor and v1 history shapes.

- [ ] **Step 4: Implement exact discriminated parsers**

Use explicit schema unions:

```ts
const monitorSchemaV2 = "clockchain.bilateral-public-monitor/v2";
const monitorSchemaV3 = "clockchain.bilateral-public-monitor/v3";
const summarySchemaV1 = "clockchain.aws-public-run-summary/v1";
const summarySchemaV2 = "clockchain.aws-public-run-summary/v2";
```

For old artifacts accept only old exact anchor keys. For new artifacts accept only:

```ts
type PublicReceiptAnchor = {
  block: string;
  cardinality: "1";
  explorerUrl: string;
  kind: "PROPOSED" | "ACCEPTED" | "ACKNOWLEDGED";
  ledgerId: string;
  signerRole: "Payer" | "Requestor";
  verified: true;
};
```

Return a discriminant such as `receiptVersion: 2 | 3` for monitor data and `receiptVersion: 1 | 2` for history. Never synthesize a ledger ID for legacy artifacts.

- [ ] **Step 5: Run focused parser tests**

Run the Step 3 command.

Expected: PASS for exact legacy and receipt-complete contracts; malformed new data fails closed.

- [ ] **Step 6: Commit site parsing compatibility**

```bash
git add \
  src/lib/bilateral-public-monitor.ts \
  src/lib/bilateral-public-monitor.test.ts \
  src/lib/bilateral-public-history.ts \
  src/lib/bilateral-public-history.test.ts
git commit -m "Keep receipt rollout compatible and fail closed" \
  -m "Constraint: The site must accept the old public artifacts while AWS moves to receipt-complete versions.
Rejected: Loose optional receipt fields | They make malformed v3 data look like valid v2.
Confidence: high
Scope-risk: moderate
Directive: Dispatch by exact schema before validating exact keys.
Tested: focused live-monitor and immutable-history parser tests
Not-tested: browser rendering and deployed AWS artifacts"
```

### Task 6: Render live receipt cards and the final email form

**Files:**
- Create: `src/components/BilateralReceiptCard.tsx`
- Create: `src/components/VerifiedReceiptEmailForm.tsx`
- Modify: `src/components/BilateralPublicMonitor.tsx`
- Modify: `src/components/BilateralHandshakeHistory.tsx`
- Modify: `src/components/BilateralHandshakeRunbook.tsx`
- Modify: `src/data/bilateral-handshake-demo.ts`
- Modify: `src/lib/bilateral-public-monitor.test.ts`
- Modify: `src/lib/bilateral-public-history.test.ts`
- Modify: `src/lib/bilateral-handshake-runbook.test.tsx`

- [ ] **Step 1: Write failing rendering and form-gating tests**

Require each live v3 anchor to render:

```ts
expect(html).toContain("CLOCKCHAIN RECEIPT");
expect(html).toContain("Requestor accepted the Payer mandate");
expect(html).toContain("00000000-0000-4000-8000-000000000002");
expect(html).toContain("Block 102");
expect(html).toContain("Exactly 1");
expect(html).toContain("No represented payment moved");
```

Render a verified v2 immutable summary and require one email form. Render running, failed, expired, legacy, and missing-summary states and require no email form.

Mock `fetch` for the form and assert the request body is exactly:

```json
{"email":"stakeholder@example.com","runId":"run-0123456789abcdef"}
```

Assert no receipt, verifier, HTML, subject, or explorer field is sent and the email is never written to localStorage, sessionStorage, query parameters, or rendered after successful submission.

- [ ] **Step 2: Run focused component tests and observe failure**

```bash
npm test -- \
  src/lib/bilateral-public-monitor.test.ts \
  src/lib/bilateral-public-history.test.ts \
  src/lib/bilateral-handshake-runbook.test.tsx
```

Expected: FAIL because the cards and form do not exist.

- [ ] **Step 3: Implement the reusable proof card**

`BilateralReceiptCard` accepts only `PublicReceiptAnchor` plus `paymentMoved:false`. It renders business copy, full copyable ledger ID, formatted block, exactly-one badge, and public explorer link. It never renders the verifier authorization literal.

Use the approved hierarchy:

```tsx
<article className="bilateral-receipt" aria-label={`${anchor.kind} Clockchain receipt`}>
  <p className="bilateral-receipt__eyebrow">CLOCKCHAIN RECEIPT · VERIFIED</p>
  <h4>{anchor.kind}</h4>
  <p>{businessExplanation(anchor.kind)}</p>
  <dl>
    <div><dt>Ledger ID</dt><dd><code>{anchor.ledgerId}</code></dd></div>
    <div><dt>Block</dt><dd>{Number(anchor.block).toLocaleString()}</dd></div>
    <div><dt>Cardinality</dt><dd>Exactly 1</dd></div>
    <div><dt>Payment</dt><dd>No represented payment moved</dd></div>
  </dl>
  <a href={anchor.explorerUrl}>Open independent proof</a>
</article>
```

- [ ] **Step 4: Implement the opt-in form**

`VerifiedReceiptEmailForm` receives only `runId` and `endpoint`. It keeps the email in component state, submits with `content-type:application/json`, clears the value after a 202 response, and displays bounded `Sending`, `Receipt email accepted`, or `Email could not be sent` states.

The component must not render when endpoint is empty or the parent summary is not exact verified version 2 with three receipts.

- [ ] **Step 5: Integrate live and historical views**

Render receipt cards immediately from the v3 live ordered prefix. Render durable cards and the email form from the immutable v2 summary. Keep the separate verifier status panel below the three receipts and label it `Fresh aggregate verifier`.

Add `receiptEmailUrl` to `bilateralAwsEndpoints` after AWS deployment provides the exact URL. Until then, use an empty string so dual-version site parsing can deploy safely with the form hidden.

- [ ] **Step 6: Run focused tests, typecheck, and build**

```bash
npm test -- \
  src/lib/bilateral-public-monitor.test.ts \
  src/lib/bilateral-public-history.test.ts \
  src/lib/bilateral-handshake-runbook.test.tsx
npm run typecheck
npm run build
```

Expected: PASS. Build output includes `/handshake/run`; no server-side secret or recipient appears in generated content.

- [ ] **Step 7: Inspect the run page visually**

Start the site locally, use browser-harness to open `/handshake/run`, inject fixture responses for zero/one/two/three/verified receipts, and capture the live page at desktop and mobile widths. Confirm the ordered receipt hierarchy, long ledger-ID wrapping, final form gating, error text, keyboard focus, and no layout shift that hides the Requestor prompt.

- [ ] **Step 8: Commit the site UI**

```bash
git add \
  src/components/BilateralReceiptCard.tsx \
  src/components/VerifiedReceiptEmailForm.tsx \
  src/components/BilateralPublicMonitor.tsx \
  src/components/BilateralHandshakeHistory.tsx \
  src/components/BilateralHandshakeRunbook.tsx \
  src/data/bilateral-handshake-demo.ts \
  src/lib/bilateral-public-monitor.test.ts \
  src/lib/bilateral-public-history.test.ts \
  src/lib/bilateral-handshake-runbook.test.tsx
git commit -m "Show stakeholders proof as the handshake completes" \
  -m "Constraint: Live receipts must remain readable while final email remains verifier-gated.
Rejected: Raw JSON as the primary view | It obscures the business sequence during a demo.
Confidence: high
Scope-risk: moderate
Directive: Keep live anchors, immutable history, and verifier result visually distinct.
Tested: focused rendering tests, typecheck, build, and local browser inspection
Not-tested: deployed public artifacts and live email"
```

### Task 7: Publish the reviewed release, AWS stack, and public site

**Files:**
- Modify: `src/data/bilateral-handshake-demo.ts` in the research worktree with the final reviewed Handshake SHA and receipt API URL.
- Modify: `docs/demo-evidence/latest.md` in the Handshake repository after deployment evidence exists.

- [ ] **Step 1: Verify AWS identity and SES readiness read-only**

```bash
aws sts get-caller-identity
aws sesv2 get-account --region us-west-2
aws sesv2 list-email-identities --region us-west-2
```

Expected: account `570035913370`; a verified sender identity usable for `receipts@clockchain.network`; production sending enabled for arbitrary stakeholder recipients. If SES remains sandboxed, use a verified controlled address for the smoke test and treat arbitrary stakeholder email as a real blocker rather than claiming it works.

- [ ] **Step 2: Create the reviewed public Handshake release SHA**

In the Handshake repository, confirm a clean tree, run all focused tests from Tasks 1–4, then push the current commit to the public GitHub repository. Record:

```bash
git rev-parse HEAD
git ls-remote origin "$(git branch --show-current)"
```

Expected: the exact commit is reachable in `https://github.com/thetangstr/clockchain-handshake.git` before any stakeholder prompt references it.

- [ ] **Step 3: Build and publish the matching AWS image**

Use the repository's existing image plan/push commands from the clean reviewed checkout. Record the immutable ECR image digest and bind the CDK deployment to the same repository SHA.

- [ ] **Step 4: Preview and deploy CDK safely**

```bash
npm --prefix infra/aws run typecheck
npm --prefix infra/aws run deploy:plan
```

Inspect the CloudFormation change set. Deploy only after confirming no unintended replacements. Expected outputs include the existing monitor/discovery endpoints plus `ReceiptEmailApiUrl`.

- [ ] **Step 5: Smoke the AWS receipt API without sending provisional evidence**

Call the new endpoint with a nonexistent or non-verified run ID and a controlled email. Expected: `RECEIPT_NOT_READY`, no SES send, no delivery record marked `SENT`, and no plaintext email in CloudWatch logs.

- [ ] **Step 6: Update and deploy the research site**

Set the exact public Handshake SHA and `ReceiptEmailApiUrl` in `bilateral-handshake-demo.ts`, run the focused site checks and build again, commit, push, and deploy the current research worktree to Vercel production.

Expected public page: `https://clockchain-research.vercel.app/handshake/run` contains the exact reviewed SHA, AWS public MCP/discovery endpoints, live monitor, immutable history, and receipt-email endpoint; no loopback or private material appears.

- [ ] **Step 7: Browser-smoke the production page**

Use browser-harness against the public page. Confirm the page loads, prompts copy cleanly, monitor and history requests return CORS-accessible JSON, old artifacts remain readable during rollout, and the email form is absent until a verified immutable version 2 summary exists.

- [ ] **Step 8: Commit deployment references**

Use a Lore commit in each repository recording exact deployed URLs, SHA, tests, and known gaps. Do not commit AWS credentials, email addresses, state paths, discovery private material, or live role evidence.

### Task 8: Run the full stakeholder acceptance through Hermes

**Files:**
- Modify after the run: `docs/demo-evidence/latest.md`
- Runtime-only state: fresh private directories outside both repositories.

- [ ] **Step 1: Establish the managed-agent guardrails**

Lead: this Codex session. Worker: the local Hermes profile `handshake_requester`. Target: the public reviewed SHA from Task 7. Production Clockchain is read-only; Sepolia and the dedicated demo AWS stack are the only live mutation surfaces. Never paste private state, tokens, keys, capabilities, manifests, invitations, or raw evidence into Hermes, the site, email, logs, or Git.

- [ ] **Step 2: Start one fresh Payer run and wait for readiness**

Use the reviewed Payer wrapper and fresh private Payer state. Start it exactly once and keep it attached. Do not start Requestor until the exact `PAYER_MCP_READY` signal is independently visible and the signed Requestor discovery points to the expected public MCP URL and reviewed SHA.

- [ ] **Step 3: Obtain the Requestor prompt from the production page**

Use browser-harness to load `https://clockchain-research.vercel.app/handshake/run`, activate the Requestor copy control, and compare the copied prompt to the visible reviewed SHA, discovery URL, and public MCP endpoint. Do not use a locally edited prompt.

- [ ] **Step 4: Drive the local Hermes worker like a stakeholder**

Use Computer Use to open Hermes, select the exact `handshake_requester` profile, paste the single public Requestor prompt, and submit it once. Do not manually supply launch manifests, certificate files, tokens, invitations, state paths from the operator, or lower-level commands. The MCP-guided wrapper must take the agent from discovery through `HANDSHAKE_REQUIRED` and the Requestor role.

- [ ] **Step 5: Monitor and repair only reproducible launch blockers**

Read the Hermes output without interrupting a healthy long-lived process. If it stops, capture the exact command, release SHA, stage, expected/actual result, and bounded logs. Fix one blocker at a time with a focused regression test, publish a new reviewed SHA, refresh the public prompt, and rerun from fresh role/operator state. Do not paper over a failed stage with manual private inputs.

- [ ] **Step 6: Perform the operator-owned funding step once**

When the coordinator reaches `ADDRESSES_READY`, use the durable exactly-once funding journal. On RPC interruption, inspect the journal and balances and resume the same journal; never recreate it or resend already funded transfers. Confirm four exact 0.01 Sepolia balances and `paymentMoved:false` before continuing.

- [ ] **Step 7: Observe receipts on the public page as they complete**

With browser-harness, keep the production run page open and record the ordered appearance of:

```text
Payer PROPOSED        -> ledger ID, block, cardinality 1, verified
Requestor ACCEPTED    -> ledger ID, block, cardinality 1, verified
Payer ACKNOWLEDGED    -> ledger ID, block, cardinality 1, verified
Fresh verifier result -> verified immutable summary
```

At every intermediate state, confirm the page does not claim final authorization and displays `paymentMoved:false`.

- [ ] **Step 8: Confirm both role completions and the verifier boundary**

Expected Payer marker:

```json
{"paymentMoved":false,"role":"payer","state":"ACKNOWLEDGED","status":"PARTY_COMPLETE"}
```

Expected Requestor marker:

```json
{"paymentMoved":false,"role":"payee","state":"ACCEPTED","status":"PARTY_COMPLETE"}
```

Only the fresh aggregate verifier may emit the authorization result. Confirm exactly three distinct ledger IDs, strictly increasing blocks, cardinality one for each transition, and a terminal immutable history entry.

- [ ] **Step 9: Send and verify one HTML receipt**

Ask the user for the destination email only at this point. Enter it into the verified run's public form. Confirm a 202 acceptance, one SES send, no duplicate on an immediate replay, HTML and plain-text parts, all three full ledger IDs/blocks/explorer links, fresh-verifier wording, testnet/no-settlement explanation, and `No represented payment moved`. Confirm CloudWatch and public artifacts do not contain the plaintext address.

- [ ] **Step 10: Publish the acceptance record**

Update `docs/demo-evidence/latest.md` with the exact public reviewed SHA and run ID emitted by this run, Payer `PARTY_COMPLETE / ACKNOWLEDGED`, Requestor `PARTY_COMPLETE / ACCEPTED`, the three public ledger IDs/blocks/explorer URLs/cardinality-one facts, the fresh aggregate-verifier confirmation, the delivered-once email result, `paymentMoved:false`, and `Production data touched: no`.

Do not include the destination email or any private runtime material.

### Task 9: Final integrated verification and completion verdict

**Files:**
- Review all changed files in both repositories.
- Finalize: `docs/demo-evidence/latest.md`

- [ ] **Step 1: Review the complete diffs**

In both repositories run `git status --short`, `git diff --check`, and inspect every changed file. Confirm no unrelated user changes were staged, no recipient address or private material is present, and all schema/version references agree.

- [ ] **Step 2: Run the complete Handshake gate once**

```bash
npm run verify
```

Expected: all Node, AWS infrastructure, and documentation checks pass from a clean reviewed checkout.

- [ ] **Step 3: Run the complete site gates**

```bash
npm test
npm run lint
npm run typecheck
npm run build
```

Expected: PASS with the production run page statically/build-time valid.

- [ ] **Step 4: Recheck public deployment evidence**

Use direct HTTP reads for monitor/history/API JSON and browser-harness for the rendered production page. Confirm the public reviewed SHA, three receipt cards, immutable run detail, verifier result, email UI, and no stale/legacy fallback masquerading as the completed live run.

- [ ] **Step 5: Record the final evidence and remaining risks**

The final report must include:

- Handshake and research-site commit SHAs;
- deployed AWS and Vercel URLs;
- Hermes profile and target machine;
- exact tests and results;
- three public receipt ledger IDs and blocks;
- Payer/Requestor completion markers;
- fresh aggregate-verifier result;
- email accepted/delivered/idempotent result without the address;
- `paymentMoved:false`;
- production touched: no; and
- any open blocker or verification gap.

- [ ] **Step 6: Complete the goal only after every required result is real**

Mark the goal complete only when the deployed public page, live Hermes stakeholder path, immutable Clockchain receipts, fresh verifier, and HTML email have all been verified. If SES production access, AWS authority, or recipient inbox confirmation is unavailable, keep the goal active and report the precise blocker.
