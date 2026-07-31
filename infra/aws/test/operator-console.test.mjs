import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { test } from "node:test";
import {
  controlActionBytes,
} from "../../../src/bilateral/aws/control-actions.mjs";

const ROOT = new URL("../operator-console/", import.meta.url);

async function asset(name) {
  return readFile(new URL(name, ROOT), "utf8");
}

test("renders exactly six ordered operator actions without secret or evidence inputs", async () => {
  const html = await asset("index.html");
  const actions = [
    ...html.matchAll(
      /<button[^>]+data-action="([^"]+)"[^>]*>([\s\S]*?)<\/button>/g,
    ),
  ].map((match) => [
    match[1],
    match[2].replace(/<[^>]+>/g, "").trim(),
  ]);
  assert.deepEqual(actions, [
    ["START_RUN", "Start run"],
    ["APPROVE_PAYER", "Approve Payer"],
    [
      "APPROVE_REQUESTOR",
      "Approve Requestor",
    ],
    ["FUND", "Fund"],
    ["VERIFY", "Verify"],
    ["ABORT", "Abort"],
  ]);
  assert.equal(/<input\b/i.test(html), false);
  for (const forbidden of [
    "address",
    "token",
    "manifest",
    "private key",
    "capability",
    "evidence",
    "path",
  ]) {
    assert.equal(
      html.toLowerCase().includes(forbidden),
      false,
      forbidden,
    );
  }
});

test("uses Hosted UI authorization code with PKCE and session-only token storage", async () => {
  const app = await asset("app.js");
  assert.match(app, /response_type", "code"/);
  assert.match(app, /code_challenge_method", "S256"/);
  assert.match(
    app,
    /crypto\.subtle\.digest\(\s*"SHA-256"/,
  );
  assert.match(app, /sessionStorage/);
  assert.equal(app.includes("localStorage"), false);
  assert.match(app, /history\.replaceState/);
  assert.match(app, /\/oauth2\/token/);
});

test("shows revision and claim fingerprints before approval and disables out-of-order actions", async () => {
  const module = await import(
    new URL("../operator-console/app.js", import.meta.url)
  );
  const view = module.deriveView({
    control: {
      allowedActions: [
        "APPROVE_PAYER",
      ],
      claims: {
        payer: {
          fingerprint: "a".repeat(64),
          status: "PENDING",
        },
        requestor: {
          fingerprint: null,
          status: "WAITING",
        },
      },
      releaseId: "release-0123456789abcdef",
      repositorySha:
        "abcdef0123456789abcdef0123456789abcdef01",
      revision: 1,
      sessionId:
        "11111111-2222-4333-8444-555555555555",
    },
    currentStep:
      "The Payer claim is ready for review.",
    paymentMoved: false,
    publishedAtMs: String(Date.now()),
    runStatus: "WAITING",
    staleAfterMs: 10_000,
  });
  assert.equal(view.revision, 1);
  assert.equal(
    view.claims.payer.fingerprint,
    "a".repeat(64),
  );
  assert.deepEqual(view.allowedActions, [
    "APPROVE_PAYER",
  ]);
  assert.equal(view.kind, "PENDING");
});

test("renders bounded business states and explicit paymentMoved false", async () => {
  const [html, app, css] = await Promise.all([
    asset("index.html"),
    asset("app.js"),
    asset("styles.css"),
  ]);
  for (const status of [
    "PENDING",
    "FAILURE",
    "STALE",
  ]) {
    assert.equal(app.includes(status), true);
  }
  assert.match(html, /paymentMoved:<strong>false<\/strong>/);
  assert.match(app, /confirm\(/);
  assert.match(
    app,
    /Could not reach the hosted control plane\./,
  );
  for (const source of [html, app, css]) {
    assert.equal(
      source.includes(
        ["AUTHOR", "IZED"].join(""),
      ),
      false,
    );
  }
});

test("encodes every console action in the protocol's exact canonical order", async () => {
  const { actionBody } = await import(
    new URL("../operator-console/app.js", import.meta.url)
  );
  const actionId =
    "11111111-1111-4111-8111-111111111111";
  const view = {
    claims: {
      payer: {
        fingerprint: "a".repeat(64),
      },
      requestor: {
        fingerprint: "b".repeat(64),
      },
    },
    releaseId: "release-0123456789abcdef",
    repositorySha:
      "abcdef0123456789abcdef0123456789abcdef01",
    revision: 2,
    sessionId:
      "11111111-2222-4333-8444-555555555555",
  };
  for (const type of [
    "START_RUN",
    "APPROVE_PAYER",
    "APPROVE_REQUESTOR",
    "FUND",
    "VERIFY",
    "ABORT",
  ]) {
    const value = actionBody(
      type,
      type === "START_RUN"
        ? { ...view, revision: 0 }
        : view,
      actionId,
    );
    assert.equal(
      JSON.stringify(value),
      controlActionBytes(value).toString(
        "utf8",
      ),
      type,
    );
  }
});

test("maps the Cognito access-token client_id into the validated audience field", async () => {
  const handler = await readFile(
    new URL("../lambda/handler.mjs", import.meta.url),
    "utf8",
  );
  assert.match(
    handler,
    /aud:\s*jwt\?\.aud\s*\?\?\s*jwt\?\.client_id/,
  );
});
