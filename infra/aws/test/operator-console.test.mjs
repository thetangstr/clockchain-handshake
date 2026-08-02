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

function tokenWithExp(exp) {
  const payload = Buffer.from(
    JSON.stringify({ exp }),
  )
    .toString("base64url");
  return `header.${payload}.signature`;
}

function installBrowserGlobals(t) {
  const original = {
    confirm: globalThis.confirm,
    crypto: globalThis.crypto,
    document: globalThis.document,
    fetch: globalThis.fetch,
    history: globalThis.history,
    location: globalThis.location,
    sessionStorage: globalThis.sessionStorage,
  };
  t.after(() => {
    for (const [key, value] of Object.entries(
      original,
    )) {
      if (value === undefined) {
        delete globalThis[key];
      } else {
        Object.defineProperty(globalThis, key, {
          configurable: true,
          value,
          writable: true,
        });
      }
    }
  });
  const storage = new Map();
  Object.defineProperty(
    globalThis,
    "sessionStorage",
    {
      configurable: true,
      value: {
        getItem(key) {
          return storage.has(key)
            ? storage.get(key)
            : null;
        },
        removeItem(key) {
          storage.delete(key);
        },
        setItem(key, value) {
          storage.set(key, value);
        },
      },
      writable: true,
    },
  );
  Object.defineProperty(globalThis, "crypto", {
    configurable: true,
    value: {
      getRandomValues(bytes) {
        bytes.fill(7);
        return bytes;
      },
      randomUUID() {
        return "11111111-2222-4333-8444-555555555555";
      },
      subtle: {
        async digest() {
          return new Uint8Array(32).buffer;
        },
      },
    },
    writable: true,
  });
  Object.defineProperty(globalThis, "history", {
    configurable: true,
    value: {
      replaceState() {},
    },
    writable: true,
  });
  return { storage };
}

test("rejects malformed or nearly expired access tokens before confirming an action", async (t) => {
  const { sendAction } = await import(
    new URL("../operator-console/app.js", import.meta.url)
  );
  installBrowserGlobals(t);
  const assigned = [];
  globalThis.location = {
    assign(value) {
      assigned.push(value);
    },
    origin: "https://console.example",
    pathname: "/",
    search: "",
  };
  let confirms = 0;
  let requests = 0;
  globalThis.confirm = () => {
    confirms += 1;
    return true;
  };
  globalThis.fetch = async () => {
    requests += 1;
    return {
      ok: true,
      async json() {
        return {};
      },
    };
  };
  for (const token of [
    "not-a-jwt",
    tokenWithExp(2_000_000_299),
  ]) {
    sessionStorage.setItem(
      "clockchain.access-token",
      token,
    );
    await assert.rejects(
      sendAction(
        {
          cognitoClientId: "client-123",
          cognitoHostedUiUrl:
            "https://auth.example",
          controlApiUrl:
            "https://control.example",
        },
        "APPROVE_PAYER",
        {
          claims: {
            payer: {
              fingerprint: "a".repeat(64),
            },
          },
          releaseId:
            "release-0123456789abcdef",
          repositorySha:
            "abcdef0123456789abcdef0123456789abcdef01",
          revision: 2,
          sessionId:
            "11111111-2222-4333-8444-555555555555",
        },
        2_000_000_000_000,
      ),
      /REAUTH_STARTED/,
    );
    assert.equal(
      sessionStorage.getItem(
        "clockchain.access-token",
      ),
      null,
    );
  }
  assert.equal(confirms, 0);
  assert.equal(requests, 0);
  assert.equal(assigned.length, 2);
  assert.match(
    assigned[0],
    /^https:\/\/auth\.example\/oauth2\/authorize\?/,
  );
});

test("schedules proactive re-auth at the five minute token threshold", async (t) => {
  const { scheduleTokenReauth } = await import(
    new URL("../operator-console/app.js", import.meta.url)
  );
  installBrowserGlobals(t);
  const assigned = [];
  globalThis.location = {
    assign(value) {
      assigned.push(value);
    },
    origin: "https://console.example",
    pathname: "/",
    search: "",
  };
  let scheduled;
  sessionStorage.setItem(
    "clockchain.access-token",
    tokenWithExp(2_000_000_600),
  );

  scheduleTokenReauth(
    {
      cognitoClientId: "client-123",
      cognitoHostedUiUrl:
        "https://auth.example",
    },
    sessionStorage.getItem(
      "clockchain.access-token",
    ),
    2_000_000_000_000,
    (callback, ms) => {
      scheduled = { callback, ms };
      return 1;
    },
  );

  assert.equal(scheduled.ms, 300_000);
  scheduled.callback();
  await new Promise((resolve) =>
    setImmediate(resolve));
  assert.equal(
    sessionStorage.getItem(
      "clockchain.access-token",
    ),
    null,
  );
  assert.equal(assigned.length, 1);
});

function installConsoleDom(t) {
  installBrowserGlobals(t);
  const elements = new Map();
  const ids = [
    "status-title",
    "status-pill",
    "current-step",
    "run-id",
    "revision",
    "payer-claim-status",
    "payer-fingerprint",
    "requestor-claim-status",
    "requestor-fingerprint",
  ];
  for (const id of ids) {
    elements.set(id, {
      className: "",
      textContent: "",
    });
  }
  const buttons = [
    {
      dataset: { action: "START_RUN" },
      disabled: false,
    },
    {
      dataset: { action: "FUND" },
      disabled: true,
    },
  ];
  globalThis.document = {
    getElementById(id) {
      return elements.get(id) ?? null;
    },
    querySelectorAll(selector) {
      assert.equal(selector, "[data-action]");
      return buttons;
    },
  };
  return { buttons, elements };
}

function snapshot({ revision, action }) {
  return {
    control: {
      allowedActions: [action],
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
      revision,
      sessionId:
        "11111111-2222-4333-8444-555555555555",
    },
    currentStep: "Ready.",
    paymentMoved: false,
    publishedAtMs: String(Date.now()),
    runId: "run-123",
    runStatus: "WAITING",
    staleAfterMs: 10_000,
  };
}

test("refreshes the live monitor view and disables actions after fetch failures", async (t) => {
  const { refreshMonitor } = await import(
    new URL("../operator-console/app.js", import.meta.url)
  );
  const { buttons, elements } =
    installConsoleDom(t);
  globalThis.fetch = async () => ({
    async json() {
      return snapshot({
        action: "FUND",
        revision: 3,
      });
    },
    ok: true,
  });

  await refreshMonitor(
    { monitorUrl: "https://monitor.example" },
    true,
  );

  assert.equal(
    elements.get("revision").textContent,
    "3",
  );
  assert.deepEqual(
    buttons.map((button) => button.disabled),
    [true, false],
  );

  globalThis.fetch = async () => {
    throw new Error("network down");
  };
  await assert.rejects(
    refreshMonitor(
      { monitorUrl: "https://monitor.example" },
      true,
    ),
    /network down/,
  );
  assert.deepEqual(
    buttons.map((button) => button.disabled),
    [true, true],
  );
});

test("keeps accepted action message when the immediate monitor refresh fails", async () => {
  const { handleActionClick } = await import(
    new URL("../operator-console/app.js", import.meta.url)
  );
  let disabled = false;
  const message = {
    textContent: "",
  };
  let currentView = {
    revision: 2,
  };

  const nextView = await handleActionClick({
    action: "FUND",
    config: {},
    disableActions() {
      disabled = true;
    },
    message,
    refreshMonitor: async () => {
      throw new Error("network down");
    },
    sendAction: async () => true,
    setView(view) {
      currentView = view;
    },
    signedIn: true,
    view: currentView,
  });

  assert.equal(nextView, currentView);
  assert.equal(disabled, true);
  assert.equal(
    message.textContent,
    "Step accepted. Waiting for a fresh hosted update.",
  );
});
