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
  createAwsOperatorBootstrapAdapter,
} from "../infra/aws/runtime/operator-bootstrap-adapter.mjs";
import {
  createAwsBootstrapStateFileStore,
} from "../src/bilateral/aws/bootstrap-service.mjs";
import {
  createBootstrapState,
  requestorBootstrapClaimFingerprint,
  submitPayerBootstrapClaim,
  submitRequestorBootstrapClaim,
  validateBootstrapState,
} from "../src/bilateral/aws/bootstrap-state.mjs";
import {
  canonicalizeReceiptEventValue,
} from "../src/canonical.mjs";
import {
  validateTunnelGrantRecord,
} from "../src/bilateral/aws/tunnel-grant.mjs";
import {
  createLaunchManifest,
} from "../src/bilateral/coordination/manifest.mjs";
import {
  createRequestorBootstrapKey,
} from "../src/bilateral/local-mcp/bootstrap-envelope.mjs";
import {
  createPayerBootstrapKey,
  payerBootstrapClaimFingerprint,
  sshEd25519Fingerprint,
} from "../src/bilateral/local-mcp/payer-bootstrap-envelope.mjs";

const NOW = 2_000_000_000_000;
const RELEASE_ID = "release-0123456789abcdef";
const REPOSITORY_SHA =
  "abcdef0123456789abcdef0123456789abcdef01";
const SESSION_ID =
  "11111111-2222-4333-8444-555555555555";
const POLL_DIGEST = "a".repeat(64);
const BROKER_DIGEST = "b".repeat(64);
const BROKER_CAPABILITY = "d".repeat(64);

function canonicalBytes(value) {
  return Buffer.from(
    JSON.stringify(
      canonicalizeReceiptEventValue(value),
    ),
    "utf8",
  );
}

function certificate(host) {
  const root = mkdtempSync(
    join(tmpdir(), "aws-operator-bootstrap-adapter-cert-"),
  );
  try {
    const certificatePath = join(root, "cert.pem");
    execFileSync("openssl", [
      "req",
      "-x509",
      "-newkey",
      "ed25519",
      "-keyout",
      join(root, "key.pem"),
      "-out",
      certificatePath,
      "-nodes",
      "-days",
      "1",
      "-subj",
      `/CN=${host}`,
      "-addext",
      `subjectAltName=DNS:${host}`,
    ], { stdio: "ignore" });
    return readFileSync(certificatePath, "utf8");
  } finally {
    rmSync(root, { force: true, recursive: true });
  }
}

function sshString(value) {
  const bytes = Buffer.from(value);
  const length = Buffer.alloc(4);
  length.writeUInt32BE(bytes.length);
  return Buffer.concat([length, bytes]);
}

function sshPublicKey(pair) {
  const raw = pair.publicKey
    .export({ format: "der", type: "spki" })
    .subarray(-32);
  return `ssh-ed25519 ${Buffer.concat([
    sshString("ssh-ed25519"),
    sshString(raw),
  ]).toString("base64")}`;
}

function payerClaim(overrides = {}) {
  const payer = createPayerBootstrapKey();
  const ssh = generateKeyPairSync("ed25519");
  const publicKey = sshPublicKey(ssh);
  const tlsCertificatePem =
    certificate("payer.example.test");
  return {
    claimNonce:
      "22222222-2222-4222-8222-222222222222",
    mcpTlsCertificatePem: tlsCertificatePem,
    mcpTlsFingerprint: createHash("sha256")
      .update(new X509Certificate(tlsCertificatePem).raw)
      .digest("hex"),
    paymentMoved: false,
    releaseId: RELEASE_ID,
    repositorySha: REPOSITORY_SHA,
    role: "payer",
    schema: "clockchain.payer-bootstrap-claim/v1",
    sessionId: SESSION_ID,
    sshPublicKey: publicKey,
    sshPublicKeyFingerprint:
      sshEd25519Fingerprint(publicKey),
    x25519PublicKey: payer.publicKey,
    ...overrides,
  };
}

function requestorClaim(overrides = {}) {
  return {
    claimNonce:
      "33333333-3333-4333-8333-333333333333",
    paymentMoved: false,
    repositorySha: REPOSITORY_SHA,
    requestorPublicKey:
      createRequestorBootstrapKey().publicKey,
    ...overrides,
  };
}

function tempRoot() {
  const root = mkdtempSync(
    join(tmpdir(), "aws-operator-bootstrap-adapter-"),
  );
  chmodSync(root, 0o700);
  return root;
}

function launchManifest(role, capabilityField) {
  const relayCertificate =
    certificate("relay.example.test");
  return createLaunchManifest({
    expectedTlsFingerprint: createHash("sha256")
      .update(new X509Certificate(relayCertificate).raw)
      .digest("hex"),
    nowMs: NOW,
    operatorKeyId: "operator",
    randomBytes: () =>
      role === "payer"
        ? Buffer.alloc(32, 2)
        : Buffer.alloc(32, 3),
    relayUrl: "https://relay.example.test:8443",
    releaseId: RELEASE_ID,
    repositorySha: REPOSITORY_SHA,
    role,
    sessionId: SESSION_ID,
    tlsCertificatePem: relayCertificate,
    ...capabilityField,
  }).manifest;
}

async function fixture({ claims = [] } = {}) {
  const root = tempRoot();
  const operator = generateKeyPairSync("ed25519");
  const payerLaunchManifestPath = join(root, "payer.json");
  const payeeLaunchManifestPath = join(root, "payee.json");
  const bootstrapStatePath = join(root, "bootstrap.json");
  const tunnelGrantPath = join(root, "grant.json");
  writeFileSync(
    payerLaunchManifestPath,
    canonicalBytes(
      launchManifest("payer", {
        payerMcpIntakeCapabilityDigest:
          "e".repeat(64),
      }),
    ),
    { mode: 0o600 },
  );
  writeFileSync(
    payeeLaunchManifestPath,
    canonicalBytes(
      launchManifest("payee", {
        payerMcpIntakeCapability: "c".repeat(64),
      }),
    ),
    { mode: 0o600 },
  );
  let state = createBootstrapState({
    paymentMoved: false,
    releaseId: RELEASE_ID,
    repositorySha: REPOSITORY_SHA,
    schema: "clockchain.aws-bootstrap-state/v1",
    sessionId: SESSION_ID,
  });
  for (const item of claims) {
    state =
      item.role === "payer"
        ? submitPayerBootstrapClaim({
            authCapabilityDigest: POLL_DIGEST,
            claim: item.claim,
            expectedRevision: state.revision,
            expiresAtMs: String(NOW + 60_000),
            nowMs: NOW,
            state,
          })
        : submitRequestorBootstrapClaim({
            authCapabilityDigest: BROKER_DIGEST,
            claim: item.claim,
            expectedRevision: state.revision,
            expiresAtMs: String(NOW + 60_000),
            nowMs: NOW,
            releaseId: RELEASE_ID,
            sessionId: SESSION_ID,
            state,
          });
  }
  writeFileSync(
    bootstrapStatePath,
    JSON.stringify(state),
    { mode: 0o600 },
  );
  const config = {
    bootstrapStatePath,
    payerLaunchManifestPath,
    payeeLaunchManifestPath,
    tunnelGrantPath,
    releaseId: RELEASE_ID,
    repositorySha: REPOSITORY_SHA,
    sessionId: SESSION_ID,
    operatorKeyId: "operator",
    publicMcpHostname: "payer.example.test",
    bootstrapBrokerUrl:
      "https://bootstrap.example.test/v1/requestor-claims",
    bootstrapBrokerCapability: BROKER_CAPABILITY,
    operatorPrivateKeyPem:
      operator.privateKey.export({
        format: "pem",
        type: "pkcs8",
      }),
    nowMs: () => NOW + 1,
  };
  const adapter =
    createAwsOperatorBootstrapAdapter(config);
  return {
    adapter,
    config,
    root,
    statePath: bootstrapStatePath,
  };
}

test("approves and seals a Payer claim with an atomic grant that exposes no operator authority", async () => {
  const claim = payerClaim();
  const claimFingerprint =
    payerBootstrapClaimFingerprint(claim);
  const fx = await fixture({
    claims: [{ claim, role: "payer" }],
  });

  assert.equal(
    await fx.adapter.readExpectedClaimFingerprint({
      releaseId: RELEASE_ID,
      sessionId: SESSION_ID,
      state: { status: "RUN_STARTED" },
    }),
    claimFingerprint,
  );
  assert.deepEqual(
    await fx.adapter.approveAndSeal({
      claimFingerprint,
      paymentMoved: false,
      releaseId: RELEASE_ID,
      repositorySha: REPOSITORY_SHA,
      role: "payer",
      sessionId: SESSION_ID,
    }),
    { paymentMoved: false, status: "APPROVED" },
  );
  const state = validateBootstrapState(
    JSON.parse(readFileSync(fx.statePath, "utf8")),
  );
  assert.equal(
    state.claims[claimFingerprint].status,
    "SEALED",
  );
  const grantBytes = readFileSync(
    fx.config.tunnelGrantPath,
  );
  assert.equal(
    lstatSync(fx.config.tunnelGrantPath).mode & 0o777,
    0o600,
  );
  const grant = validateTunnelGrantRecord(
    JSON.parse(grantBytes.toString("utf8")),
  );
  assert.equal(grant.claimFingerprint, claimFingerprint);
  assert.equal(grant.paymentMoved, false);
  const serialized = Buffer.concat([
    grantBytes,
    Buffer.from(
      state.claims[claimFingerprint]
        .sealedResponseBase64,
      "base64",
    ),
  ]).toString("utf8");
  for (const secret of [
    BROKER_CAPABILITY,
    fx.config.operatorPrivateKeyPem,
    readFileSync(
      fx.config.payerLaunchManifestPath,
      "utf8",
    ),
  ]) {
    assert.equal(serialized.includes(secret), false);
  }
});

test("rejects config keys that are not enumerable own data properties without invoking accessors", async () => {
  const fx = await fixture();
  const hidden = { ...fx.config };
  Object.defineProperty(hidden, "releaseId", {
    enumerable: false,
    value: RELEASE_ID,
  });
  assert.throws(
    () => createAwsOperatorBootstrapAdapter(hidden),
    /AWS operator bootstrap adapter failed safely/,
  );

  let accessed = false;
  const accessor = { ...fx.config };
  Object.defineProperty(accessor, "repositorySha", {
    enumerable: true,
    get() {
      accessed = true;
      return REPOSITORY_SHA;
    },
  });
  assert.throws(
    () => createAwsOperatorBootstrapAdapter(accessor),
    /AWS operator bootstrap adapter failed safely/,
  );
  assert.equal(accessed, false);
});

test("approves and seals a Requestor claim using payee role without writing a tunnel grant", async () => {
  const claim = requestorClaim();
  const claimFingerprint =
    requestorBootstrapClaimFingerprint(claim);
  const fx = await fixture({
    claims: [{ claim, role: "requestor" }],
  });

  assert.equal(
    await fx.adapter.readExpectedClaimFingerprint({
      releaseId: RELEASE_ID,
      sessionId: SESSION_ID,
      state: { status: "PAYER_APPROVED" },
    }),
    claimFingerprint,
  );
  const input = {
    claimFingerprint,
    paymentMoved: false,
    releaseId: RELEASE_ID,
    repositorySha: REPOSITORY_SHA,
    role: "payee",
    sessionId: SESSION_ID,
  };
  assert.deepEqual(
    await fx.adapter.approveAndSeal(input),
    { paymentMoved: false, status: "APPROVED" },
  );
  const state = validateBootstrapState(
    JSON.parse(readFileSync(fx.statePath, "utf8")),
  );
  assert.equal(
    state.claims[claimFingerprint].status,
    "SEALED",
  );
  assert.throws(
    () => readFileSync(fx.config.tunnelGrantPath),
    /ENOENT/,
  );
  assert.deepEqual(
    await createAwsOperatorBootstrapAdapter(
      fx.config,
    ).approveAndSeal(input),
    { paymentMoved: false, status: "APPROVED" },
  );
  assert.throws(
    () => readFileSync(fx.config.tunnelGrantPath),
    /ENOENT/,
  );
});

test("adopts a sealed Payer grant on restart and rejects missing, malformed, symlink, hardlink, and changed grants", async () => {
  const claim = payerClaim();
  const claimFingerprint =
    payerBootstrapClaimFingerprint(claim);
  const fx = await fixture({
    claims: [{ claim, role: "payer" }],
  });
  const input = {
    claimFingerprint,
    paymentMoved: false,
    releaseId: RELEASE_ID,
    repositorySha: REPOSITORY_SHA,
    role: "payer",
    sessionId: SESSION_ID,
  };
  await fx.adapter.approveAndSeal(input);
  const grantBytes = readFileSync(
    fx.config.tunnelGrantPath,
  );
  assert.deepEqual(
    await createAwsOperatorBootstrapAdapter(
      fx.config,
    ).approveAndSeal(input),
    { paymentMoved: false, status: "APPROVED" },
  );
  writeFileSync(
    fx.config.tunnelGrantPath,
    grantBytes
      .toString("utf8")
      .replace(claimFingerprint, "f".repeat(64)),
  );
  await assert.rejects(
    createAwsOperatorBootstrapAdapter(
      fx.config,
    ).approveAndSeal(input),
    /AWS operator bootstrap adapter failed safely/,
  );

  const missing = await fixture({
    claims: [{ claim, role: "payer" }],
  });
  await missing.adapter.approveAndSeal(input);
  rmSync(missing.config.tunnelGrantPath);
  await assert.rejects(
    createAwsOperatorBootstrapAdapter(
      missing.config,
    ).approveAndSeal(input),
    /AWS operator bootstrap adapter failed safely/,
  );

  const malformed = await fixture({
    claims: [{ claim, role: "payer" }],
  });
  await malformed.adapter.approveAndSeal(input);
  writeFileSync(
    malformed.config.tunnelGrantPath,
    "{\"paymentMoved\":false}",
    { mode: 0o600 },
  );
  await assert.rejects(
    createAwsOperatorBootstrapAdapter(
      malformed.config,
    ).approveAndSeal(input),
    /AWS operator bootstrap adapter failed safely/,
  );

  const symlink = await fixture({
    claims: [{ claim, role: "payer" }],
  });
  await symlink.adapter.approveAndSeal(input);
  const symlinkTarget = `${symlink.config.tunnelGrantPath}.target`;
  writeFileSync(symlinkTarget, grantBytes, {
    mode: 0o600,
  });
  rmSync(symlink.config.tunnelGrantPath);
  symlinkSync(
    symlinkTarget,
    symlink.config.tunnelGrantPath,
  );
  await assert.rejects(
    createAwsOperatorBootstrapAdapter(
      symlink.config,
    ).approveAndSeal(input),
    /AWS operator bootstrap adapter failed safely/,
  );
});

test("reuses an existing Payer grant when retrying after grant persistence succeeded but state sealing crashed", async () => {
  const claim = payerClaim();
  const claimFingerprint =
    payerBootstrapClaimFingerprint(claim);
  const fx = await fixture({
    claims: [{ claim, role: "payer" }],
  });
  const input = {
    claimFingerprint,
    paymentMoved: false,
    releaseId: RELEASE_ID,
    repositorySha: REPOSITORY_SHA,
    role: "payer",
    sessionId: SESSION_ID,
  };
  let currentNow = NOW + 1;
  let writes = 0;
  const crashAfterGrant =
    createAwsOperatorBootstrapAdapter(
      {
        ...fx.config,
        nowMs: () => currentNow,
      },
      {
        createAwsBootstrapStateFileStore:
          async (options) => {
            const store =
              await createAwsBootstrapStateFileStore(
                options,
              );
            return {
              async readState() {
                return store.readState();
              },
              async writeState(input) {
                writes += 1;
                if (writes === 2) {
                  throw new Error(
                    "simulated crash after grant persistence",
                  );
                }
                return store.writeState(input);
              },
            };
          },
      },
    );

  await assert.rejects(
    crashAfterGrant.approveAndSeal(input),
    /AWS operator bootstrap adapter failed safely/,
  );
  const grantBytes = readFileSync(
    fx.config.tunnelGrantPath,
  );
  let state = validateBootstrapState(
    JSON.parse(readFileSync(fx.statePath, "utf8")),
  );
  assert.equal(
    state.claims[claimFingerprint].status,
    "APPROVED",
  );

  currentNow = NOW + 10_000;
  assert.deepEqual(
    await createAwsOperatorBootstrapAdapter({
      ...fx.config,
      nowMs: () => currentNow,
    }).approveAndSeal(input),
    { paymentMoved: false, status: "APPROVED" },
  );
  assert.equal(
    readFileSync(fx.config.tunnelGrantPath).equals(
      grantBytes,
    ),
    true,
  );
  state = validateBootstrapState(
    JSON.parse(readFileSync(fx.statePath, "utf8")),
  );
  assert.equal(
    state.claims[claimFingerprint].status,
    "SEALED",
  );
});

test("rejects unsafe launch manifests and unsafe grant files", async () => {
  const claim = payerClaim();
  const claimFingerprint =
    payerBootstrapClaimFingerprint(claim);
  const fx = await fixture({
    claims: [{ claim, role: "payer" }],
  });
  const input = {
    claimFingerprint,
    paymentMoved: false,
    releaseId: RELEASE_ID,
    repositorySha: REPOSITORY_SHA,
    role: "payer",
    sessionId: SESSION_ID,
  };
  symlinkSync(
    fx.config.payeeLaunchManifestPath,
    `${fx.config.payerLaunchManifestPath}.link`,
  );
  await assert.rejects(
    createAwsOperatorBootstrapAdapter({
      ...fx.config,
      payerLaunchManifestPath:
        `${fx.config.payerLaunchManifestPath}.link`,
    }).approveAndSeal(input),
    /AWS operator bootstrap adapter failed safely/,
  );
  const hardlinkPath =
    `${fx.config.payerLaunchManifestPath}.hardlink`;
  linkSync(
    fx.config.payerLaunchManifestPath,
    hardlinkPath,
  );
  await assert.rejects(
    createAwsOperatorBootstrapAdapter({
      ...fx.config,
      payerLaunchManifestPath: hardlinkPath,
    }).approveAndSeal(input),
    /AWS operator bootstrap adapter failed safely/,
  );

  const safe = await fixture({
    claims: [{ claim, role: "payer" }],
  });
  await safe.adapter.approveAndSeal(input);
  linkSync(
    safe.config.tunnelGrantPath,
    `${safe.config.tunnelGrantPath}.hardlink`,
  );
  await assert.rejects(
    safe.adapter.assertTunnelGrant(input),
    /AWS operator bootstrap adapter failed safely/,
  );
});

test("infers the exact claim role from control state and returns null outside approval windows", async () => {
  const none = await fixture();
  assert.equal(
    await none.adapter.readExpectedClaimFingerprint({
      releaseId: RELEASE_ID,
      sessionId: SESSION_ID,
      state: { status: "REQUESTOR_APPROVED" },
    }),
    null,
  );

  const payer = payerClaim();
  const payerFingerprint =
    payerBootstrapClaimFingerprint(payer);
  const requestor = requestorClaim();
  const requestorFingerprint =
    requestorBootstrapClaimFingerprint(requestor);
  const both = await fixture({
    claims: [
      { claim: payer, role: "payer" },
      { claim: requestor, role: "requestor" },
    ],
  });
  assert.equal(
    await both.adapter.readExpectedClaimFingerprint({
      releaseId: RELEASE_ID,
      sessionId: SESSION_ID,
      state: { status: "RUN_STARTED" },
    }),
    payerFingerprint,
  );
  assert.equal(
    await both.adapter.readExpectedClaimFingerprint({
      releaseId: RELEASE_ID,
      sessionId: SESSION_ID,
      state: { status: "PAYER_APPROVED" },
    }),
    requestorFingerprint,
  );

  const alternatePayer = payerClaim({
    claimNonce:
      "44444444-4444-4444-8444-444444444444",
  });
  const initial = createBootstrapState({
    paymentMoved: false,
    releaseId: RELEASE_ID,
    repositorySha: REPOSITORY_SHA,
    schema: "clockchain.aws-bootstrap-state/v1",
    sessionId: SESSION_ID,
  });
  const first = submitPayerBootstrapClaim({
    authCapabilityDigest: POLL_DIGEST,
    claim: payer,
    expectedRevision: "0",
    expiresAtMs: String(NOW + 60_000),
    nowMs: NOW,
    state: initial,
  });
  const second = submitPayerBootstrapClaim({
    authCapabilityDigest: POLL_DIGEST,
    claim: alternatePayer,
    expectedRevision: "0",
    expiresAtMs: String(NOW + 60_000),
    nowMs: NOW,
    state: initial,
  });
  const duplicateState = {
    claims: {
      [payerBootstrapClaimFingerprint(payer)]:
        first.claims[
          payerBootstrapClaimFingerprint(payer)
        ],
      [payerBootstrapClaimFingerprint(alternatePayer)]:
        second.claims[
          payerBootstrapClaimFingerprint(
            alternatePayer,
          )
        ],
    },
    paymentMoved: false,
    releaseId: RELEASE_ID,
    repositorySha: REPOSITORY_SHA,
    revision: "1",
    schema: "clockchain.aws-bootstrap-state/v1",
    sessionId: SESSION_ID,
  };
  const injected =
    createAwsOperatorBootstrapAdapter(
      none.config,
      {
        createAwsBootstrapStateFileStore:
          async () => ({
            async readState() {
              return duplicateState;
            },
            async writeState() {
              return true;
            },
          }),
      },
    );
  await assert.rejects(
    injected.readExpectedClaimFingerprint({
      releaseId: RELEASE_ID,
      sessionId: SESSION_ID,
      state: { status: "RUN_STARTED" },
    }),
    /AWS operator bootstrap adapter failed safely/,
  );
});
