const TOKEN_KEY = "clockchain.access-token";
const PKCE_KEY = "clockchain.pkce-verifier";
const STATE_KEY = "clockchain.oauth-state";
const ACTIONS = Object.freeze([
  "START_RUN",
  "APPROVE_PAYER",
  "APPROVE_REQUESTOR",
  "FUND",
  "VERIFY",
  "ABORT",
]);

function text(value, fallback) {
  return typeof value === "string" &&
    value.length > 0
    ? value
    : fallback;
}

function claim(value) {
  return Object.freeze({
    fingerprint:
      typeof value?.fingerprint === "string"
        ? value.fingerprint
        : null,
    status: text(value?.status, "WAITING"),
  });
}

export function deriveView(
  snapshot,
  nowMs = Date.now(),
) {
  if (
    snapshot === null ||
    typeof snapshot !== "object" ||
    snapshot.paymentMoved !== false ||
    snapshot.control === null ||
    typeof snapshot.control !== "object" ||
    !Number.isSafeInteger(
      snapshot.control.revision,
    ) ||
    snapshot.control.revision < 0 ||
    !Array.isArray(
      snapshot.control.allowedActions,
    ) ||
    snapshot.control.allowedActions.some(
      (action) => !ACTIONS.includes(action),
    )
  ) {
    throw new Error("INVALID_SNAPSHOT");
  }
  const publishedAt = Number(
    snapshot.publishedAtMs,
  );
  const staleAfter =
    snapshot.staleAfterMs;
  const stale =
    !Number.isSafeInteger(publishedAt) ||
    !Number.isSafeInteger(staleAfter) ||
    staleAfter < 1_000 ||
    nowMs > publishedAt + staleAfter;
  const failed =
    snapshot.runStatus === "FAILED";
  return Object.freeze({
    allowedActions: stale || failed
      ? Object.freeze([])
      : Object.freeze([
          ...snapshot.control.allowedActions,
        ]),
    claims: Object.freeze({
      payer: claim(
        snapshot.control.claims?.payer,
      ),
      requestor: claim(
        snapshot.control.claims?.requestor,
      ),
    }),
    currentStep: text(
      snapshot.currentStep,
      "Waiting for the hosted control plane.",
    ),
    kind: stale
      ? "STALE"
      : failed
        ? "FAILURE"
        : snapshot.runStatus === "VERIFIED"
          ? "SUCCESS"
          : "PENDING",
    releaseId: text(
      snapshot.control.releaseId,
      "",
    ),
    repositorySha: text(
      snapshot.control.repositorySha,
      "",
    ),
    revision: snapshot.control.revision,
    runId: text(
      snapshot.runId,
      "Not started",
    ),
    sessionId:
      typeof snapshot.control.sessionId ===
      "string"
        ? snapshot.control.sessionId
        : null,
  });
}

function base64Url(bytes) {
  let value = "";
  for (const byte of bytes) {
    value += String.fromCharCode(byte);
  }
  return btoa(value)
    .replaceAll("+", "-")
    .replaceAll("/", "_")
    .replaceAll("=", "");
}

function verifier() {
  const bytes = new Uint8Array(48);
  crypto.getRandomValues(bytes);
  return base64Url(bytes);
}

export async function pkceChallenge(
  value,
) {
  const digest = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(value),
  );
  return base64Url(new Uint8Array(digest));
}

function callbackUrl() {
  return `${location.origin}/`;
}

function cleanCallbackUrl() {
  history.replaceState(
    {},
    "",
    location.pathname || "/",
  );
}

async function beginSignIn(config) {
  const secret = verifier();
  const state = crypto.randomUUID();
  sessionStorage.setItem(PKCE_KEY, secret);
  sessionStorage.setItem(STATE_KEY, state);
  const query = new URLSearchParams();
  query.set("client_id", config.cognitoClientId);
  query.set(
    "code_challenge",
    await pkceChallenge(secret),
  );
  query.set("code_challenge_method", "S256");
  query.set("redirect_uri", callbackUrl());
  query.set("response_type", "code");
  query.set("scope", "openid email");
  query.set("state", state);
  location.assign(
    `${config.cognitoHostedUiUrl}/oauth2/authorize?${query}`,
  );
}

async function finishSignIn(config) {
  const query = new URLSearchParams(
    location.search,
  );
  const code = query.get("code");
  if (code === null) return;
  const expectedState =
    sessionStorage.getItem(STATE_KEY);
  const secret =
    sessionStorage.getItem(PKCE_KEY);
  if (
    expectedState === null ||
    query.get("state") !== expectedState ||
    secret === null
  ) {
    cleanCallbackUrl();
    throw new Error("CALLBACK_REJECTED");
  }
  const body = new URLSearchParams();
  body.set("client_id", config.cognitoClientId);
  body.set("code", code);
  body.set("code_verifier", secret);
  body.set("grant_type", "authorization_code");
  body.set("redirect_uri", callbackUrl());
  const response = await fetch(
    `${config.cognitoHostedUiUrl}/oauth2/token`,
    {
      body,
      headers: {
        "content-type":
          "application/x-www-form-urlencoded",
      },
      method: "POST",
    },
  );
  const result = await response.json();
  cleanCallbackUrl();
  sessionStorage.removeItem(PKCE_KEY);
  sessionStorage.removeItem(STATE_KEY);
  if (
    !response.ok ||
    typeof result.access_token !== "string"
  ) {
    throw new Error("TOKEN_REJECTED");
  }
  sessionStorage.setItem(
    TOKEN_KEY,
    result.access_token,
  );
}

export function actionBody(
  action,
  view,
  actionId = crypto.randomUUID(),
) {
  const common = {
    actionId,
    expectedRevision: view.revision,
    paymentMoved: false,
    releaseId: view.releaseId,
    repositorySha: view.repositorySha,
  };
  if (action === "START_RUN") {
    return {
      ...common,
      type: action,
    };
  }
  if (
    action === "APPROVE_PAYER" ||
    action === "APPROVE_REQUESTOR"
  ) {
    return {
      actionId,
      claimFingerprint:
        action === "APPROVE_PAYER"
          ? view.claims.payer.fingerprint
          : view.claims.requestor
              .fingerprint,
      expectedRevision: view.revision,
      paymentMoved: false,
      releaseId: view.releaseId,
      repositorySha: view.repositorySha,
      sessionId: view.sessionId,
      type: action,
    };
  }
  return {
    ...common,
    sessionId: view.sessionId,
    type: action,
  };
}

function confirmation(action, view) {
  if (action === "APPROVE_PAYER") {
    return `Approve this exact Payer claim?\n\n${view.claims.payer.fingerprint}`;
  }
  if (action === "APPROVE_REQUESTOR") {
    return `Approve this exact Requestor claim?\n\n${view.claims.requestor.fingerprint}`;
  }
  if (action === "FUND") {
    return "Fund exactly four fresh Sepolia addresses with 0.01 each?";
  }
  if (action === "VERIFY") {
    return "Launch one fresh independent verification task?";
  }
  if (action === "ABORT") {
    return "Abort this run and revoke its active access?";
  }
  return null;
}

async function sendAction(
  config,
  action,
  view,
) {
  const token =
    sessionStorage.getItem(TOKEN_KEY);
  if (token === null) {
    throw new Error("SIGNED_OUT");
  }
  const prompt = confirmation(action, view);
  if (
    prompt !== null &&
    !confirm(prompt)
  ) {
    return false;
  }
  const response = await fetch(
    `${config.controlApiUrl}/v1/actions`,
    {
      body: JSON.stringify(
        actionBody(action, view),
      ),
      headers: {
        authorization: `Bearer ${token}`,
        "content-type": "application/json",
      },
      method: "POST",
    },
  );
  if (!response.ok) {
    throw new Error("ACTION_REJECTED");
  }
  return true;
}

function element(id) {
  const value = document.getElementById(id);
  if (value === null) {
    throw new Error("CONSOLE_MARKUP_INVALID");
  }
  return value;
}

function render(view, signedIn) {
  element("status-title").textContent =
    view.kind === "STALE"
      ? "Update is stale"
      : view.kind === "FAILURE"
        ? "Run stopped safely"
        : view.kind === "SUCCESS"
          ? "Run verified"
          : "Run in progress";
  const pill = element("status-pill");
  pill.textContent = view.kind;
  pill.className = `pill ${view.kind.toLowerCase()}`;
  element("current-step").textContent =
    view.currentStep;
  element("run-id").textContent = view.runId;
  element("revision").textContent =
    String(view.revision);
  for (const role of [
    "payer",
    "requestor",
  ]) {
    const current = view.claims[role];
    element(
      `${role}-claim-status`,
    ).textContent = current.status;
    element(
      `${role}-fingerprint`,
    ).textContent =
      current.fingerprint ??
      "No fingerprint yet";
  }
  for (const button of document.querySelectorAll(
    "[data-action]",
  )) {
    button.disabled =
      !signedIn ||
      !view.allowedActions.includes(
        button.dataset.action,
      );
  }
}

async function start() {
  const message = element("action-message");
  let config;
  let view;
  try {
    const response = await fetch(
      "./config.json",
      { cache: "no-store" },
    );
    config = await response.json();
    await finishSignIn(config);
    const monitor = await fetch(
      `${config.monitorUrl}/control.json`,
      { cache: "no-store" },
    );
    view = deriveView(await monitor.json());
  } catch {
    message.textContent =
      "Could not reach the hosted control plane.";
    return;
  }
  const signedIn =
    sessionStorage.getItem(TOKEN_KEY) !== null;
  element("auth-state").textContent =
    signedIn ? "Signed in" : "Signed out";
  element("sign-in").hidden = signedIn;
  element("sign-out").hidden = !signedIn;
  render(view, signedIn);
  message.textContent = signedIn
    ? "Choose the single available next step."
    : "Sign in to operate the hosted run.";
  element("sign-in").addEventListener(
    "click",
    () => {
      void beginSignIn(config);
    },
  );
  element("sign-out").addEventListener(
    "click",
    () => {
      sessionStorage.removeItem(TOKEN_KEY);
      location.reload();
    },
  );
  for (const button of document.querySelectorAll(
    "[data-action]",
  )) {
    button.addEventListener(
      "click",
      async () => {
        message.textContent =
          "Submitting the selected step…";
        try {
          if (
            await sendAction(
              config,
              button.dataset.action,
              view,
            )
          ) {
            message.textContent =
              "Step accepted. Waiting for a fresh hosted update.";
          } else {
            message.textContent =
              "No change was made.";
          }
        } catch {
          message.textContent =
            "The hosted control plane rejected this step safely.";
        }
      },
    );
  }
}

if (typeof document !== "undefined") {
  void start();
}
