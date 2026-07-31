import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { createHash, generateKeyPairSync, sign, X509Certificate } from "node:crypto";
import { chmod, lstat, mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { test } from "node:test";

import { main, REQUEST_PAYMENT_CLI_FLAGS } from "../bin/handshake-request-payment.mjs";
import { canonicalBytes } from "../src/bilateral/canonical.mjs";
import { createLaunchManifest } from "../src/bilateral/coordination/manifest.mjs";
import { bootstrapClaimFingerprint } from "../src/bilateral/local-mcp/bootstrap-broker.mjs";
import { sealRequestorBootstrapManifest } from "../src/bilateral/local-mcp/bootstrap-envelope.mjs";
import { canonicalizeReceiptEventValue } from "../src/canonical.mjs";

const REPOSITORY_SHA = "abcdef0123456789abcdef0123456789abcdef01";
const INTAKE_REQUEST_ID = "00000000-0000-4000-8000-000000000000";
const RELEASE_ID = "release-requestor-bootstrap";
const SESSION_ID = "22222222-2222-4222-8222-222222222222";
const OPERATOR_KEY_ID = "operator";
const CAPABILITY = "ab".repeat(32);
const REPOSITORY_ROOT = resolve(new URL("../", import.meta.url).pathname);

function rawEd25519PublicKey(pair) {
  return pair.publicKey.export({ format: "der", type: "spki" }).subarray(-32).toString("base64");
}

function signatureValue(privateKey, value) {
  return sign(null, canonicalBytes(value), privateKey).toString("base64");
}

function signedDiscovery({ certificateFingerprint, certificateUrl, expiresAtMs, operator, publicUrl }) {
  const unsigned = {
    certificateFingerprint,
    certificateUrl,
    expiresAtMs,
    operatorKeyId: OPERATOR_KEY_ID,
    publicUrl,
    releaseId: RELEASE_ID,
    repositorySha: REPOSITORY_SHA,
    sessionId: SESSION_ID,
  };
  return {
    ...unsigned,
    signature: {
      algorithm: "ed25519",
      keyId: OPERATOR_KEY_ID,
      value: signatureValue(operator.privateKey, unsigned),
    },
  };
}

async function fixture(t) {
  const root = await mkdtemp(join(tmpdir(), "request-payment-one-shot-"));
  await chmod(root, 0o700);
  t.after(() => rm(root, { force: true, recursive: true }));
  const certificatePath = join(root, "cert.pem");
  const privateKeyPath = join(root, "key.pem");
  execFileSync("openssl", [
    "req",
    "-x509",
    "-newkey",
    "ed25519",
    "-keyout",
    privateKeyPath,
    "-out",
    certificatePath,
    "-nodes",
    "-days",
    "1",
    "-subj",
    "/CN=127.0.0.1",
    "-addext",
    "subjectAltName=IP:127.0.0.1",
  ], { stdio: "ignore" });
  const tlsCertificatePem = await readFile(certificatePath, "utf8");
  const certificateFingerprint = createHash("sha256").update(new X509Certificate(tlsCertificatePem).raw).digest("hex");
  const operator = generateKeyPairSync("ed25519");
  const stateRoot = join(root, "requestor-state");
  const discovery = signedDiscovery({
    certificateFingerprint,
    certificateUrl: "https://payer.example.test/payer-mcp.crt",
    expiresAtMs: String(Date.now() + 60_000),
    operator,
    publicUrl: "https://127.0.0.1:9443/mcp",
  });
  const { manifest } = createLaunchManifest({
    expectedTlsFingerprint: certificateFingerprint,
    nowMs: Date.now(),
    operatorKeyId: OPERATOR_KEY_ID,
    randomBytes: () => Buffer.alloc(32, 9),
    relayUrl: "https://127.0.0.1:8443",
    releaseId: RELEASE_ID,
    repositorySha: REPOSITORY_SHA,
    role: "payee",
    sessionId: SESSION_ID,
    tlsCertificatePem,
    payerMcpIntakeCapability: CAPABILITY,
  });
  return {
    args: [
      "--discovery-url", "https://payer.example.test/discovery.json",
      "--intake-request-id", INTAKE_REQUEST_ID,
      "--state", stateRoot,
    ],
    certificateFingerprint,
    discovery,
    manifestBytes: Buffer.from(JSON.stringify(canonicalizeReceiptEventValue(manifest)), "utf8"),
    operator,
    operatorPublicKey: rawEd25519PublicKey(operator),
    root,
    stateRoot,
    tlsCertificatePem,
  };
}

function sealedBrokerResponse({ claim, manifestBytes, operator }) {
  const context = {
    claimNonce: claim.claimNonce,
    paymentMoved: false,
    releaseId: RELEASE_ID,
    repositorySha: REPOSITORY_SHA,
    sessionId: SESSION_ID,
  };
  const unsigned = {
    claimFingerprint: bootstrapClaimFingerprint(claim),
    context,
    envelope: sealRequestorBootstrapManifest({
      context,
      manifestBytes,
      requestorPublicKey: claim.requestorPublicKey,
    }),
    paymentMoved: false,
    repositorySha: REPOSITORY_SHA,
    schema: "clockchain.requestor-bootstrap-broker-response/v1",
    status: "SEALED",
  };
  return {
    ...unsigned,
    signature: {
      algorithm: "ed25519",
      keyId: OPERATOR_KEY_ID,
      value: sign(null, Buffer.from(JSON.stringify(canonicalizeReceiptEventValue(unsigned)), "utf8"), operator.privateKey).toString("base64"),
    },
  };
}

test("Requestor CLI exposes only one-shot discovery flags and completes bootstrap before unchanged MCP and supervisor", async (t) => {
  const fx = await fixture(t);
  const calls = [];
  let bootstrapAttempts = 0;
  let capturedClaim;
  const result = await main(fx.args, {
    async inspectRepository(repositoryRoot) {
      calls.push(["inspectRepository", repositoryRoot]);
      return { clean: true, detached: true, head: REPOSITORY_SHA };
    },
    async fetchJson(url) {
      calls.push(["fetchJson", url]);
      assert.equal(url, "https://payer.example.test/discovery.json");
      return fx.discovery;
    },
    async readOperatorPublicKey(repositorySha, keyId) {
      calls.push(["readOperatorPublicKey", repositorySha, keyId]);
      return fx.operatorPublicKey;
    },
    async fetchText(url) {
      calls.push(["fetchText", url]);
      assert.equal(url, fx.discovery.certificateUrl);
      return fx.tlsCertificatePem;
    },
    async requestBootstrap(input) {
      calls.push(["requestBootstrap", input.bootstrapUrl, input.claim.paymentMoved]);
      assert.equal(input.bootstrapUrl, "https://127.0.0.1:9443/bootstrap");
      assert.equal(Object.hasOwn(input, "capability"), false);
      capturedClaim = input.claim;
      bootstrapAttempts += 1;
      return bootstrapAttempts === 1
        ? {
            claimFingerprint: bootstrapClaimFingerprint(input.claim),
            paymentMoved: false,
            repositorySha: REPOSITORY_SHA,
            schema: "clockchain.requestor-bootstrap-broker-response/v1",
            status: "PENDING_APPROVAL",
          }
        : sealedBrokerResponse({ claim: input.claim, manifestBytes: fx.manifestBytes, operator: fx.operator });
    },
    async requestPayment(input) {
      calls.push(["requestPayment", input.capability, input.mcpUrl]);
      assert.equal(input.capability, CAPABILITY);
      assert.equal(input.mcpUrl, fx.discovery.publicUrl);
      assert.equal(input.tlsFingerprint, fx.discovery.certificateFingerprint);
      assert.equal(input.stateRoot, fx.stateRoot);
      return { paymentMoved: false, status: "HANDSHAKE_REQUIRED" };
    },
    async runSupervisor(input) {
      calls.push(["runSupervisor", input.launchManifestPath, input.stateRoot]);
      assert.equal(input.stateRoot, fx.stateRoot);
      assert.equal(input.launchManifestPath.endsWith("requestor-state.bootstrap/payee.launch.json"), true);
      const manifestStats = await lstat(input.launchManifestPath);
      assert.equal(manifestStats.mode & 0o777, 0o600);
      assert.equal((await readFile(input.launchManifestPath)).equals(fx.manifestBytes), true);
      return { paymentMoved: false, supervisor: "started" };
    },
    writeStatus(value) {
      calls.push(["writeStatus", value]);
      assert.deepEqual(value, { paymentMoved: false, status: "HANDSHAKE_REQUIRED" });
      assert.equal(JSON.stringify(value).includes(CAPABILITY), false);
      assert.equal(JSON.stringify(value).includes(fx.operatorPublicKey), false);
    },
  });
  assert.deepEqual(result, { paymentMoved: false, supervisor: "started" });
  assert.deepEqual(REQUEST_PAYMENT_CLI_FLAGS, ["--discovery-url", "--intake-request-id", "--state"]);
  assert.match(capturedClaim.claimNonce, /^[0-9a-f]{8}-[0-9a-f]{4}-4/);
  assert.equal(capturedClaim.paymentMoved, false);
  assert.equal(capturedClaim.repositorySha, REPOSITORY_SHA);
  assert.deepEqual(calls.map((entry) => entry[0]), [
    "inspectRepository",
    "fetchJson",
    "readOperatorPublicKey",
    "fetchText",
    "requestBootstrap",
    "requestBootstrap",
    "requestPayment",
    "writeStatus",
    "runSupervisor",
  ]);
  assert.equal(calls[0][1], REPOSITORY_ROOT);
});

test("Requestor CLI rejects dirty repo before discovery, network, private state, or supervisor work", async (t) => {
  const fx = await fixture(t);
  const calls = [];
  await assert.rejects(
    main(fx.args, {
      async inspectRepository() {
        calls.push("inspectRepository");
        return { clean: false, detached: true, head: REPOSITORY_SHA };
      },
      async fetchJson() {
        calls.push("fetchJson");
      },
      async requestBootstrap() {
        calls.push("requestBootstrap");
      },
      async runSupervisor() {
        calls.push("runSupervisor");
      },
    }),
    /Request payment startup failed safely/,
  );
  assert.deepEqual(calls, ["inspectRepository"]);
});

test("Requestor CLI fails closed on malformed args, stale discovery, wrong SHA, and wrong certificate", async (t) => {
  const fx = await fixture(t);
  for (const args of [
    fx.args.slice(0, -2),
    [...fx.args, "--launch-manifest", "/tmp/secret.json"],
    fx.args.map((value) => value === fx.stateRoot ? "relative" : value),
  ]) {
    await assert.rejects(main(args, {}), /Request payment startup failed safely/);
  }

  for (const mutate of [
    (discovery) => ({ ...discovery, expiresAtMs: "1" }),
    (discovery) => ({ ...discovery, repositorySha: "b".repeat(40) }),
    (discovery) => ({ ...discovery, certificateFingerprint: "0".repeat(64) }),
    (discovery) => ({ ...discovery, publicUrl: "http://127.0.0.1:9443/mcp" }),
  ]) {
    await assert.rejects(
      main(fx.args, {
        async inspectRepository() {
          return { clean: true, detached: true, head: REPOSITORY_SHA };
        },
        async fetchJson() {
          return mutate(fx.discovery);
        },
        async readOperatorPublicKey() {
          return fx.operatorPublicKey;
        },
        async fetchText() {
          return fx.tlsCertificatePem;
        },
      }),
      /Request payment startup failed safely/,
    );
  }
});

test("Requestor CLI refuses to overwrite an existing decrypted manifest destination", async (t) => {
  const fx = await fixture(t);
  const bootstrapRoot = `${fx.stateRoot}.bootstrap`;
  await mkdir(bootstrapRoot, { mode: 0o700 });
  await writeFile(join(bootstrapRoot, "payee.launch.json"), "existing", { mode: 0o600 });
  let requestPaymentCalls = 0;
  let supervisorCalls = 0;
  await assert.rejects(
    main(fx.args, {
      async inspectRepository() {
        return { clean: true, detached: true, head: REPOSITORY_SHA };
      },
      async fetchJson() {
        return fx.discovery;
      },
      async readOperatorPublicKey() {
        return fx.operatorPublicKey;
      },
      async fetchText() {
        return fx.tlsCertificatePem;
      },
      async requestBootstrap(input) {
        return sealedBrokerResponse({ claim: input.claim, manifestBytes: fx.manifestBytes, operator: fx.operator });
      },
      async requestPayment() {
        requestPaymentCalls += 1;
      },
      async runSupervisor() {
        supervisorCalls += 1;
      },
    }),
    /Request payment startup failed safely/,
  );
  assert.equal(requestPaymentCalls, 0);
  assert.equal(supervisorCalls, 0);
  assert.equal(await readFile(join(bootstrapRoot, "payee.launch.json"), "utf8"), "existing");
});
