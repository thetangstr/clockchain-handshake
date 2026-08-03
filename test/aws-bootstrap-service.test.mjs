import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import {
  createHash,
  generateKeyPairSync,
  X509Certificate,
} from "node:crypto";
import {
  chmodSync,
  linkSync,
  lstatSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";

import {
  createAwsBootstrapService,
  createAwsBootstrapStateFileStore,
} from "../src/bilateral/aws/bootstrap-service.mjs";
import {
  createBootstrapState,
  submitRequestorBootstrapClaim,
} from "../src/bilateral/aws/bootstrap-state.mjs";
import {
  createRequestorBootstrapKey,
} from "../src/bilateral/local-mcp/bootstrap-envelope.mjs";
import {
  BOOTSTRAP_BROKER_RESPONSE_SCHEMA,
  bootstrapClaimFingerprint,
} from "../src/bilateral/local-mcp/bootstrap-broker.mjs";
import {
  createPayerBootstrapKey,
  payerBootstrapClaimFingerprint,
  sshEd25519Fingerprint,
} from "../src/bilateral/local-mcp/payer-bootstrap-envelope.mjs";
import {
  createAwsBootstrapServiceFromEnvironment,
} from "../scripts/run-aws-bootstrap-service.mjs";

const REPOSITORY_SHA = "abcdef0123456789abcdef0123456789abcdef01";
const RELEASE_ID = "release-aws-bootstrap";
const SESSION_ID = "22222222-2222-4222-8222-222222222222";
const NOW = 2_000_000_000_000;
const POLL_CAPABILITY = "a".repeat(64);
const BROKER_CAPABILITY = "b".repeat(64);
const PRIVATE_CANARY = "never-return-bootstrap-private-canary";
const MAX_BODY_BYTES = 262_144;

function certificatePem() {
  const root = mkdtempSync(join(tmpdir(), "aws-bootstrap-service-"));
  try {
    const certificatePath = join(root, "payer.crt");
    const privateKeyPath = join(root, "payer.key");
    execFileSync("openssl", [
      "req", "-x509", "-newkey", "ed25519",
      "-keyout", privateKeyPath,
      "-out", certificatePath,
      "-nodes", "-days", "1",
      "-subj", "/CN=payer.clockchain.network",
      "-addext", "subjectAltName=DNS:payer.clockchain.network",
    ], { stdio: "ignore" });
    return readFileSync(certificatePath, "utf8");
  } finally {
    rmSync(root, { force: true, recursive: true });
  }
}

const CERTIFICATE_PEM = certificatePem();

function sshString(value) {
  const bytes = Buffer.from(value);
  const length = Buffer.alloc(4);
  length.writeUInt32BE(bytes.length);
  return Buffer.concat([length, bytes]);
}

function openSshPublicKey(pair) {
  const raw = pair.publicKey
    .export({ format: "der", type: "spki" })
    .subarray(-32);
  return `ssh-ed25519 ${Buffer.concat([
    sshString("ssh-ed25519"),
    sshString(raw),
  ]).toString("base64")}`;
}

function payerClaim(overrides = {}) {
  const bootstrap = createPayerBootstrapKey();
  const ssh = generateKeyPairSync("ed25519");
  const sshPublicKey = openSshPublicKey(ssh);
  return {
    claimNonce: "11111111-1111-4111-8111-111111111111",
    mcpTlsCertificatePem: CERTIFICATE_PEM,
    mcpTlsFingerprint: createHash("sha256")
      .update(new X509Certificate(CERTIFICATE_PEM).raw)
      .digest("hex"),
    paymentMoved: false,
    releaseId: RELEASE_ID,
    repositorySha: REPOSITORY_SHA,
    role: "payer",
    schema: "clockchain.payer-bootstrap-claim/v1",
    sessionId: SESSION_ID,
    sshPublicKey,
    sshPublicKeyFingerprint: sshEd25519Fingerprint(sshPublicKey),
    x25519PublicKey: bootstrap.publicKey,
    ...overrides,
  };
}

function requestorClaim(overrides = {}) {
  return {
    claimNonce: "33333333-3333-4333-8333-333333333333",
    paymentMoved: false,
    repositorySha: REPOSITORY_SHA,
    requestorPublicKey: createRequestorBootstrapKey().publicKey,
    ...overrides,
  };
}

function requestorSealedResponse(claim) {
  return {
    claimFingerprint: bootstrapClaimFingerprint(claim),
    context: {
      claimNonce: claim.claimNonce,
      paymentMoved: false,
      releaseId: RELEASE_ID,
      repositorySha: REPOSITORY_SHA,
      sessionId: SESSION_ID,
    },
    envelope: {
      algorithm: "X25519-HKDF-SHA256-AES-256-GCM",
      ciphertextBase64url: Buffer.from("sealed-launch-manifest")
        .toString("base64url"),
      ephemeralPublicKey: Buffer.alloc(32, 1).toString("base64url"),
      ivBase64url: Buffer.alloc(12, 2).toString("base64url"),
      paymentMoved: false,
      schema: "clockchain.requestor-bootstrap-envelope/v1",
      tagBase64url: Buffer.alloc(16, 3).toString("base64url"),
    },
    paymentMoved: false,
    repositorySha: REPOSITORY_SHA,
    schema: BOOTSTRAP_BROKER_RESPONSE_SCHEMA,
    signature: {
      algorithm: "ed25519",
      keyId: "operator",
      value: Buffer.alloc(64, 4).toString("base64"),
    },
    status: "SEALED",
  };
}

function payerPackageResponse(claim) {
  return {
    claimFingerprint: payerBootstrapClaimFingerprint(claim),
    envelope: {
      algorithm: "X25519-HKDF-SHA256-AES-256-GCM",
      ciphertextBase64url: Buffer.from("sealed-payer-package")
        .toString("base64url"),
      ephemeralPublicKey: Buffer.alloc(32, 5).toString("base64url"),
      ivBase64url: Buffer.alloc(12, 6).toString("base64url"),
      paymentMoved: false,
      schema: "clockchain.payer-bootstrap-package/v1",
      tagBase64url: Buffer.alloc(16, 7).toString("base64url"),
    },
    expiresAtMs: String(NOW + 60_000),
    operatorKeyId: "operator",
    paymentMoved: false,
    schema: "clockchain.payer-bootstrap-response/v1",
    signature: {
      algorithm: "ed25519",
      keyId: "operator",
      value: Buffer.alloc(64, 8).toString("base64"),
    },
  };
}

function createStore() {
  let value = createBootstrapState({
    paymentMoved: false,
    releaseId: RELEASE_ID,
    repositorySha: REPOSITORY_SHA,
    schema: "clockchain.aws-bootstrap-state/v1",
    sessionId: SESSION_ID,
  });
  let writes = 0;
  return {
    get value() {
      return value;
    },
    get writes() {
      return writes;
    },
    async readState() {
      return value;
    },
    async writeState({ expectedRevision, state }) {
      if (value.revision !== expectedRevision) return false;
      value = state;
      writes += 1;
      return true;
    },
  };
}

async function fixture(t) {
  const store = createStore();
  const service = createAwsBootstrapService({
    brokerCapabilityDigest: createHash("sha256")
      .update(BROKER_CAPABILITY)
      .digest("hex"),
    claimExpiresAfterMs: 60_000,
    host: "127.0.0.1",
    nowMs: () => NOW,
    port: 0,
    store,
  });
  const listening = await service.start();
  t.after(() => service.stop());
  return { ...listening, service, store };
}

async function request(url, {
  authorization,
  body,
  method = "GET",
  rawBody,
} = {}) {
  const headers = {
    Accept: "application/json",
  };
  if (authorization !== undefined) {
    headers.Authorization = `Bearer ${authorization}`;
  }
  const bytes = rawBody === undefined
    ? body === undefined
      ? undefined
      : Buffer.from(JSON.stringify(body), "utf8")
    : Buffer.from(rawBody);
  if (bytes !== undefined) {
    headers["Content-Type"] = "application/json";
  }
  const response = await fetch(url, {
    body: bytes,
    headers,
    method,
  });
  const text = await response.text();
  return {
    body: text === "" ? null : JSON.parse(text),
    status: response.status,
    text,
  };
}

test("persists Payer polling authority by digest and consumes a sealed package before reply", async (t) => {
  const { service, store, url } = await fixture(t);
  const claim = payerClaim();
  const fingerprint = payerBootstrapClaimFingerprint(claim);
  const submitted = await request(`${url}/v1/payer-claims`, {
    body: {
      claim,
      paymentMoved: false,
      pollCapability: POLL_CAPABILITY,
    },
    method: "POST",
  });
  assert.equal(submitted.status, 200);
  assert.deepEqual(submitted.body, {
    claimFingerprint: fingerprint,
    paymentMoved: false,
    status: "PENDING",
  });
  assert.equal(store.writes, 1);
  assert.equal(
    store.value.claims[fingerprint].authCapabilityDigest,
    createHash("sha256").update(POLL_CAPABILITY).digest("hex"),
  );
  assert.doesNotMatch(JSON.stringify(store.value), new RegExp(POLL_CAPABILITY));

  const pending = await request(
    `${url}/v1/payer-claims/${fingerprint}`,
    { authorization: POLL_CAPABILITY },
  );
  assert.equal(pending.status, 200);
  assert.deepEqual(pending.body, submitted.body);
  const denied = await request(
    `${url}/v1/payer-claims/${fingerprint}`,
    { authorization: BROKER_CAPABILITY },
  );
  assert.equal(denied.status, 401);
  assert.equal(denied.body.paymentMoved, false);

  await service.approveClaim({
    claimFingerprint: fingerprint,
    expectedRevision: "1",
    paymentMoved: false,
  });
  const packageResponse = payerPackageResponse(claim);
  await service.sealClaim({
    claimFingerprint: fingerprint,
    expectedRevision: "2",
    paymentMoved: false,
    response: {
      claimFingerprint: fingerprint,
      packageResponse,
      paymentMoved: false,
      status: "SEALED",
    },
  });
  assert.equal(store.value.claims[fingerprint].status, "SEALED");
  const writesBeforePoll = store.writes;

  const sealed = await request(
    `${url}/v1/payer-claims/${fingerprint}`,
    { authorization: POLL_CAPABILITY },
  );
  assert.equal(sealed.status, 200);
  assert.deepEqual(sealed.body, {
    claimFingerprint: fingerprint,
    packageResponse,
    paymentMoved: false,
    status: "SEALED",
  });
  assert.equal(store.value.claims[fingerprint].status, "CONSUMED");
  assert.equal(store.writes, writesBeforePoll + 1);
  const retry = await request(
    `${url}/v1/payer-claims/${fingerprint}`,
    { authorization: POLL_CAPABILITY },
  );
  assert.equal(retry.status, 200);
  assert.equal(retry.text, sealed.text);
  assert.equal(store.writes, writesBeforePoll + 1);
  assert.doesNotMatch(sealed.text, new RegExp(PRIVATE_CANARY));
  assert.doesNotMatch(sealed.text, new RegExp(POLL_CAPABILITY));
});

test("accepts Requestor claims only through broker authentication and preserves v1 sealed bytes", async (t) => {
  const { service, store, url } = await fixture(t);
  const claim = requestorClaim();
  const fingerprint = bootstrapClaimFingerprint(claim);
  for (const authorization of [undefined, POLL_CAPABILITY]) {
    const denied = await request(`${url}/v1/requestor-claims`, {
      authorization,
      body: claim,
      method: "POST",
    });
    assert.equal(denied.status, 401);
    assert.equal(denied.body.paymentMoved, false);
  }

  const pending = await request(`${url}/v1/requestor-claims`, {
    authorization: BROKER_CAPABILITY,
    body: claim,
    method: "POST",
  });
  assert.equal(pending.status, 202);
  assert.deepEqual(pending.body, {
    claimFingerprint: fingerprint,
    paymentMoved: false,
    repositorySha: REPOSITORY_SHA,
    schema: BOOTSTRAP_BROKER_RESPONSE_SCHEMA,
    status: "PENDING_APPROVAL",
  });
  assert.equal(store.value.claims[fingerprint].role, "requestor");

  await service.approveClaim({
    claimFingerprint: fingerprint,
    expectedRevision: "1",
    paymentMoved: false,
  });
  const response = requestorSealedResponse(claim);
  await service.sealClaim({
    claimFingerprint: fingerprint,
    expectedRevision: "2",
    paymentMoved: false,
    response,
  });
  const sealed = await request(
    `${url}/v1/requestor-claims/${fingerprint}`,
    { authorization: BROKER_CAPABILITY },
  );
  assert.equal(sealed.status, 200);
  assert.deepEqual(sealed.body, response);
  assert.equal(store.value.claims[fingerprint].status, "CONSUMED");

  const retry = await request(`${url}/v1/requestor-claims`, {
    authorization: BROKER_CAPABILITY,
    body: claim,
    method: "POST",
  });
  assert.equal(retry.status, 200);
  assert.equal(retry.text, sealed.text);
  assert.doesNotMatch(retry.text, new RegExp(BROKER_CAPABILITY));
  assert.doesNotMatch(retry.text, new RegExp(PRIVATE_CANARY));
});

test("rejects malformed transport, replays, stale writes, and secret-bearing responses", async (t) => {
  const { service, store, url } = await fixture(t);
  const claim = payerClaim();
  const fingerprint = payerBootstrapClaimFingerprint(claim);
  const health = await request(`${url}/health`);
  assert.equal(health.status, 200);
  assert.deepEqual(health.body, {
    paymentMoved: false,
    status: "HEALTHY",
  });
  assert.equal(store.writes, 0);

  for (const input of [
    {
      body: {
        claim,
        paymentMoved: true,
        pollCapability: POLL_CAPABILITY,
      },
      method: "POST",
      path: "/v1/payer-claims",
      status: 400,
    },
    {
      method: "POST",
      path: "/health",
      status: 405,
    },
    {
      method: "GET",
      path: "/unknown",
      status: 404,
    },
    {
      method: "POST",
      path: "/v1/payer-claims",
      rawBody:
        `{"claim":${JSON.stringify(claim)},"paymentMoved":false,` +
        `"paymentMoved":false,"pollCapability":"${POLL_CAPABILITY}"}`,
      status: 400,
    },
    {
      method: "POST",
      path: "/v1/payer-claims",
      rawBody: `"${"x".repeat(MAX_BODY_BYTES + 1)}"`,
      status: 413,
    },
  ]) {
    const result = await request(`${url}${input.path}`, input);
    assert.equal(result.status, input.status);
    assert.equal(result.body.paymentMoved, false);
    assert.doesNotMatch(result.text, new RegExp(PRIVATE_CANARY));
  }

  const accepted = await request(`${url}/v1/payer-claims`, {
    body: {
      claim,
      paymentMoved: false,
      pollCapability: POLL_CAPABILITY,
    },
    method: "POST",
  });
  assert.equal(accepted.status, 200);
  const changed = await request(`${url}/v1/payer-claims`, {
    body: {
      claim: payerClaim({
        claimNonce: "44444444-4444-4444-8444-444444444444",
      }),
      paymentMoved: false,
      pollCapability: POLL_CAPABILITY,
    },
    method: "POST",
  });
  assert.equal(changed.status, 409);
  await assert.rejects(
    service.approveClaim({
      claimFingerprint: fingerprint,
      expectedRevision: "0",
      paymentMoved: false,
    }),
    /AWS bootstrap service failed safely/,
  );
  await service.approveClaim({
    claimFingerprint: fingerprint,
    expectedRevision: "1",
    paymentMoved: false,
  });
  await assert.rejects(
    service.sealClaim({
      claimFingerprint: fingerprint,
      expectedRevision: "2",
      paymentMoved: false,
      response: {
        claimFingerprint: fingerprint,
        manifest: PRIVATE_CANARY,
        paymentMoved: false,
        status: "SEALED",
      },
    }),
    /AWS bootstrap service failed safely/,
  );
  const malformedPackage = payerPackageResponse(claim);
  await assert.rejects(
    service.sealClaim({
      claimFingerprint: fingerprint,
      expectedRevision: "2",
      paymentMoved: false,
      response: {
        claimFingerprint: fingerprint,
        packageResponse: {
          ...malformedPackage,
          signature: {
            ...malformedPackage.signature,
            value: "not-base64",
          },
        },
        paymentMoved: false,
        status: "SEALED",
      },
    }),
    /AWS bootstrap service failed safely/,
  );
  await assert.rejects(
    service.sealClaim({
      claimFingerprint: fingerprint,
      expectedRevision: "2",
      paymentMoved: false,
      response: {
        claimFingerprint: fingerprint,
        packageResponse: payerPackageResponse(claim),
        paymentMoved: false,
        status: "SEALED",
        unexpected: "not-authority",
      },
    }),
    /AWS bootstrap service failed safely/,
  );
  assert.equal(store.value.claims[fingerprint].status, "APPROVED");
});

test("persists canonical bootstrap state atomically in the mounted private state file", async (t) => {
  const root = mkdtempSync(
    join(tmpdir(), "aws-bootstrap-file-store-"),
  );
  chmodSync(root, 0o700);
  t.after(() =>
    rmSync(root, { force: true, recursive: true }));
  const statePath = join(root, "bootstrap-state.json");
  const initial = createBootstrapState({
    paymentMoved: false,
    releaseId: RELEASE_ID,
    repositorySha: REPOSITORY_SHA,
    schema: "clockchain.aws-bootstrap-state/v1",
    sessionId: SESSION_ID,
  });
  const store = await createAwsBootstrapStateFileStore({
    initialState: initial,
    statePath,
  });
  assert.deepEqual(await store.readState(), initial);
  assert.equal(lstatSync(statePath).mode & 0o777, 0o600);
  assert.equal(
    readFileSync(statePath, "utf8"),
    JSON.stringify(initial),
  );

  const next = submitRequestorBootstrapClaim({
    authCapabilityDigest: createHash("sha256")
      .update(BROKER_CAPABILITY)
      .digest("hex"),
    claim: requestorClaim(),
    expectedRevision: "0",
    expiresAtMs: String(NOW + 60_000),
    nowMs: NOW,
    releaseId: RELEASE_ID,
    sessionId: SESSION_ID,
    state: initial,
  });
  assert.equal(
    await store.writeState({
      expectedRevision: "0",
      state: next,
    }),
    true,
  );
  assert.equal(
    await store.writeState({
      expectedRevision: "0",
      state: initial,
    }),
    false,
  );
  await assert.rejects(
    store.writeState({
      expectedRevision: "01",
      state: next,
    }),
    /AWS bootstrap service failed safely/,
  );
  assert.deepEqual(await store.readState(), next);

  const lockPath = `${statePath}.lock`;
  writeFileSync(lockPath, "other-writer\n", {
    mode: 0o600,
  });
  await assert.rejects(
    store.writeState({
      expectedRevision: "1",
      state: next,
    }),
    /AWS bootstrap service failed safely/,
  );
  assert.equal(
    readFileSync(lockPath, "utf8"),
    "other-writer\n",
  );
  rmSync(lockPath);

  const linkedPath = join(root, "linked-state.json");
  linkSync(statePath, linkedPath);
  await assert.rejects(
    store.readState(),
    /AWS bootstrap service failed safely/,
  );
  rmSync(linkedPath);

  const symlinkPath = join(root, "symlink-state.json");
  symlinkSync(statePath, symlinkPath);
  await assert.rejects(
    createAwsBootstrapStateFileStore({
      initialState: initial,
      statePath: symlinkPath,
    }),
    /AWS bootstrap service failed safely/,
  );
});

test("builds the Fargate bootstrap adapter from exact public configuration and a capability digest", async () => {
  const stores = [];
  const services = [];
  const service = await createAwsBootstrapServiceFromEnvironment({
    createService(input) {
      services.push(input);
      return { start: async () => undefined };
    },
    createStore: async (input) => {
      stores.push(input);
      return {
        readState: async () => input.initialState,
        writeState: async () => true,
      };
    },
    env: {
      AWS_BOOTSTRAP_BIND_HOST: "0.0.0.0",
      AWS_BOOTSTRAP_BROKER_CAPABILITY_DIGEST:
        createHash("sha256")
          .update(BROKER_CAPABILITY)
          .digest("hex"),
      AWS_BOOTSTRAP_CLAIM_EXPIRES_AFTER_MS: "1800000",
      AWS_BOOTSTRAP_PORT: "8080",
      AWS_BOOTSTRAP_STATE_PATH:
        "/bootstrap-private/bootstrap-state.json",
      BILATERAL_RELEASE_ID: RELEASE_ID,
      BILATERAL_REPOSITORY_SHA: REPOSITORY_SHA,
      BILATERAL_SESSION_ID: SESSION_ID,
    },
  });
  assert.equal(typeof service.start, "function");
  assert.equal(stores.length, 1);
  assert.deepEqual(stores[0], {
    initialState: createBootstrapState({
      paymentMoved: false,
      releaseId: RELEASE_ID,
      repositorySha: REPOSITORY_SHA,
      schema: "clockchain.aws-bootstrap-state/v1",
      sessionId: SESSION_ID,
    }),
    statePath:
      "/bootstrap-private/bootstrap-state.json",
  });
  assert.equal(services.length, 1);
  assert.equal(services[0].host, "0.0.0.0");
  assert.equal(services[0].port, 8080);
  assert.equal(
    services[0].claimExpiresAfterMs,
    1_800_000,
  );
  assert.equal(
    services[0].brokerCapabilityDigest,
    createHash("sha256")
      .update(BROKER_CAPABILITY)
      .digest("hex"),
  );
  assert.equal(
    JSON.stringify({ stores, services })
      .includes(BROKER_CAPABILITY),
    false,
  );
});

test("permits a Fargate wildcard bind without treating it as a public authority", () => {
  const service = createAwsBootstrapService({
    brokerCapabilityDigest: createHash("sha256")
      .update(BROKER_CAPABILITY)
      .digest("hex"),
    claimExpiresAfterMs: 60_000,
    host: "0.0.0.0",
    nowMs: () => NOW,
    port: 8080,
    store: createStore(),
  });
  assert.equal(typeof service.start, "function");
});

test("accepts a 30 minute bootstrap claim lifetime at the real service boundary", () => {
  const service = createAwsBootstrapService({
    brokerCapabilityDigest: createHash("sha256")
      .update(BROKER_CAPABILITY)
      .digest("hex"),
    claimExpiresAfterMs: 1_800_000,
    host: "127.0.0.1",
    nowMs: () => NOW,
    port: 0,
    store: createStore(),
  });
  assert.equal(typeof service.start, "function");
});
