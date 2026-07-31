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
import { buildPaymentIntakeToolResult } from "../src/bilateral/local-mcp/payment-intake.mjs";
import { canonicalizeReceiptEventValue } from "../src/canonical.mjs";

const REPOSITORY_SHA = "abcdef0123456789abcdef0123456789abcdef01";
const INTAKE_REQUEST_ID = "00000000-0000-4000-8000-000000000000";
const RELEASE_ID = "release-requestor-bootstrap";
const SESSION_ID = "22222222-2222-4222-8222-222222222222";
const OPERATOR_KEY_ID = "operator";
const CAPABILITY = "ab".repeat(32);
const REPOSITORY_ROOT = resolve(new URL("../", import.meta.url).pathname);

function paymentInput(intakeRequestId = INTAKE_REQUEST_ID) {
  return {
    amount: { currency: "USD", value: "100" },
    intakeRequestId,
    invoiceReference: "invoice-001",
    paymentMoved: false,
    purpose: "Handshake demo",
    schema: "clockchain.payer-mcp-payment-intake/v1",
  };
}

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
    relayUrl: "https://8.8.8.8:8443",
    releaseId: RELEASE_ID,
    repositorySha: REPOSITORY_SHA,
    role: "payee",
    sessionId: SESSION_ID,
    tlsCertificatePem,
    payerMcpIntakeCapability: CAPABILITY,
  }, { allowTestAddresses: true });
  return {
    args: [
      "--discovery-url", "https://payer.example.test/discovery.json",
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
      assert.match(input.intakeRequestId, /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);
      return buildPaymentIntakeToolResult({
        repositorySha: REPOSITORY_SHA,
        toolInput: paymentInput(input.intakeRequestId),
      }).structuredContent;
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
      assert.equal(value.status, "HANDSHAKE_REQUIRED");
      assert.equal(value.paymentMoved, false);
      assert.equal(value.requestorInstructions.summary, "The Payer requires Clockchain Handshake before this payment request can be evaluated.");
      assert.equal(value.requestorInstructions.requiredCommand.includes("npm run bilateral:request-payment"), true);
      assert.equal(JSON.stringify(value).includes(CAPABILITY), false);
      assert.equal(JSON.stringify(value).includes(fx.operatorPublicKey), false);
    },
  });
  assert.deepEqual(result, { paymentMoved: false, supervisor: "started" });
  assert.deepEqual(REQUEST_PAYMENT_CLI_FLAGS, ["--discovery-url", "--state"]);
  const intakeRecordPath = join(`${fx.stateRoot}.bootstrap`, "requestor-intake-request.json");
  const intakeRecordStats = await lstat(intakeRecordPath);
  assert.equal(intakeRecordStats.mode & 0o777, 0o600);
  const intakeRecord = JSON.parse(await readFile(intakeRecordPath, "utf8"));
  assert.deepEqual(Object.keys(intakeRecord), [
    "intakeRequestId",
    "paymentMoved",
    "schema",
  ]);
  assert.match(intakeRecord.intakeRequestId, /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);
  assert.equal(intakeRecord.paymentMoved, false);
  assert.equal(intakeRecord.schema, "clockchain.requestor-intake-request/v1");
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

test("Requestor CLI polls pending bootstrap without a second prompt until sealed", async (t) => {
  const fx = await fixture(t);
  const sleeps = [];
  const claims = [];
  let attempts = 0;
  let clockMs = Date.now();
  let supervisorCalls = 0;
  const result = await main(fx.args, {
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
      attempts += 1;
      claims.push(input.claim);
      if (attempts < 4) {
        return {
          claimFingerprint: bootstrapClaimFingerprint(input.claim),
          paymentMoved: false,
          repositorySha: REPOSITORY_SHA,
          schema: "clockchain.requestor-bootstrap-broker-response/v1",
          status: "PENDING_APPROVAL",
        };
      }
      return sealedBrokerResponse({ claim: input.claim, manifestBytes: fx.manifestBytes, operator: fx.operator });
    },
    async requestPayment() {
      return { paymentMoved: false, status: "HANDSHAKE_REQUIRED" };
    },
    async runSupervisor() {
      supervisorCalls += 1;
      return { paymentMoved: false, supervisor: "started" };
    },
    async sleep(ms) {
      sleeps.push(ms);
      clockMs += ms;
    },
    nowMs: () => clockMs,
    writeStatus() {},
  });
  assert.deepEqual(result, { paymentMoved: false, supervisor: "started" });
  assert.equal(attempts, 4);
  assert.deepEqual(sleeps, [2_000, 2_000, 2_000]);
  assert.equal(new Set(claims.map((claim) => JSON.stringify(claim))).size, 1);
  assert.equal(supervisorCalls, 1);
});

test("Requestor CLI fails closed when pending bootstrap exceeds approval deadline", async (t) => {
  const fx = await fixture(t);
  const sleeps = [];
  let clockMs = Date.now();
  let requestPaymentCalls = 0;
  await assert.rejects(
    main(fx.args, {
      async inspectRepository() {
        return { clean: true, detached: true, head: REPOSITORY_SHA };
      },
      async fetchJson() {
        return signedDiscovery({
          certificateFingerprint: fx.certificateFingerprint,
          certificateUrl: fx.discovery.certificateUrl,
          expiresAtMs: String(clockMs + 4_100),
          operator: fx.operator,
          publicUrl: fx.discovery.publicUrl,
        });
      },
      async readOperatorPublicKey() {
        return fx.operatorPublicKey;
      },
      async fetchText() {
        return fx.tlsCertificatePem;
      },
      async requestBootstrap(input) {
        return {
          claimFingerprint: bootstrapClaimFingerprint(input.claim),
          paymentMoved: false,
          repositorySha: REPOSITORY_SHA,
          schema: "clockchain.requestor-bootstrap-broker-response/v1",
          status: "PENDING_APPROVAL",
        };
      },
      async requestPayment() {
        requestPaymentCalls += 1;
      },
      async sleep(ms) {
        sleeps.push(ms);
        clockMs += ms;
      },
      nowMs: () => clockMs,
    }),
    /Request payment startup failed safely/,
  );
  assert.deepEqual(sleeps, [2_000, 2_000]);
  assert.equal(requestPaymentCalls, 0);
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
  await assert.rejects(lstat(`${fx.stateRoot}.bootstrap`), { code: "ENOENT" });
});

test("Requestor CLI fails closed on malformed args, stale discovery, wrong SHA, and wrong certificate", async (t) => {
  const fx = await fixture(t);
  for (const args of [
    fx.args.slice(0, -2),
    [...fx.args, "--launch-manifest", "/tmp/secret.json"],
    [
      "--discovery-url", "https://payer.example.test/discovery.json",
      "--intake-request-id", INTAKE_REQUEST_ID,
      "--state", fx.stateRoot,
    ],
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

test("Requestor CLI reuses one private intake request ID after an interrupted bootstrap", async (t) => {
  const fx = await fixture(t);
  let firstClaim;
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
        firstClaim = input.claim;
        throw new Error("interrupted");
      },
    }),
    /Request payment startup failed safely/,
  );

  const persisted = JSON.parse(
    await readFile(join(`${fx.stateRoot}.bootstrap`, "requestor-intake-request.json"), "utf8"),
  );
  let secondIntakeRequestId;
  await main(fx.args, {
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
      assert.deepEqual(input.claim, firstClaim);
      return sealedBrokerResponse({
        claim: input.claim,
        manifestBytes: fx.manifestBytes,
        operator: fx.operator,
      });
    },
    async requestPayment(input) {
      secondIntakeRequestId = input.intakeRequestId;
      return buildPaymentIntakeToolResult({
        repositorySha: REPOSITORY_SHA,
        toolInput: paymentInput(input.intakeRequestId),
      }).structuredContent;
    },
    async runSupervisor() {
      return { paymentMoved: false, supervisor: "started" };
    },
    writeStatus() {},
  });
  assert.equal(secondIntakeRequestId, persisted.intakeRequestId);
});

test("Requestor CLI creates a fresh intake request ID for each new private state root", async (t) => {
  const first = await fixture(t);
  const second = await fixture(t);
  const sequences = [
    [
      "11111111-1111-4111-8111-111111111111",
      "22222222-2222-4222-8222-222222222222",
    ],
    [
      "33333333-3333-4333-8333-333333333333",
      "44444444-4444-4444-8444-444444444444",
    ],
  ];
  for (const [index, fx] of [first, second].entries()) {
    const identifiers = [...sequences[index]];
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
        randomUUID() {
          return identifiers.shift();
        },
        async requestBootstrap() {
          throw new Error("interrupted");
        },
      }),
      /Request payment startup failed safely/,
    );
    assert.equal(identifiers.length, 0);
  }

  const firstRecord = JSON.parse(
    await readFile(join(`${first.stateRoot}.bootstrap`, "requestor-intake-request.json"), "utf8"),
  );
  const secondRecord = JSON.parse(
    await readFile(join(`${second.stateRoot}.bootstrap`, "requestor-intake-request.json"), "utf8"),
  );
  assert.equal(firstRecord.intakeRequestId, sequences[0][1]);
  assert.equal(secondRecord.intakeRequestId, sequences[1][1]);
  assert.notEqual(firstRecord.intakeRequestId, secondRecord.intakeRequestId);
});

test("Requestor CLI rejects an intake request ID that collides with its bootstrap claim", async (t) => {
  const fx = await fixture(t);
  const identifier = "11111111-1111-4111-8111-111111111111";
  let bootstrapCalls = 0;
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
      randomUUID() {
        return identifier;
      },
      async requestBootstrap() {
        bootstrapCalls += 1;
      },
    }),
    /Request payment startup failed safely/,
  );
  assert.equal(bootstrapCalls, 0);
});

test("Requestor CLI rejects a changed private intake request record before bootstrap or MCP", async (t) => {
  const fx = await fixture(t);
  const bootstrapRoot = `${fx.stateRoot}.bootstrap`;
  await mkdir(bootstrapRoot, { mode: 0o700 });
  await writeFile(
    join(bootstrapRoot, "requestor-intake-request.json"),
    `${JSON.stringify({
      intakeRequestId: INTAKE_REQUEST_ID,
      paymentMoved: true,
      schema: "clockchain.requestor-intake-request/v1",
    })}\n`,
    { mode: 0o600 },
  );
  const calls = [];
  await assert.rejects(
    main(fx.args, {
      async inspectRepository() {
        calls.push("inspectRepository");
        return { clean: true, detached: true, head: REPOSITORY_SHA };
      },
      async fetchJson() {
        calls.push("fetchJson");
        return fx.discovery;
      },
      async readOperatorPublicKey() {
        calls.push("readOperatorPublicKey");
        return fx.operatorPublicKey;
      },
      async fetchText() {
        calls.push("fetchText");
        return fx.tlsCertificatePem;
      },
      async requestBootstrap() {
        calls.push("requestBootstrap");
      },
      async requestPayment() {
        calls.push("requestPayment");
      },
    }),
    /Request payment startup failed safely/,
  );
  assert.deepEqual(calls, [
    "inspectRepository",
    "fetchJson",
    "readOperatorPublicKey",
    "fetchText",
  ]);
});

test("Requestor CLI validates discovery candidate before operator-key lookup", async (t) => {
  const fx = await fixture(t);
  for (const operatorKeyId of ["../outside", "operator/key", "Operator", ""]) {
    const calls = [];
    await assert.rejects(
      main(fx.args, {
        async inspectRepository() {
          calls.push("inspectRepository");
          return { clean: true, detached: true, head: REPOSITORY_SHA };
        },
        async fetchJson() {
          calls.push("fetchJson");
          return { ...fx.discovery, operatorKeyId };
        },
        async readOperatorPublicKey() {
          calls.push("readOperatorPublicKey");
          return fx.operatorPublicKey;
        },
        async fetchText() {
          calls.push("fetchText");
          return fx.tlsCertificatePem;
        },
      }),
      /Request payment startup failed safely/,
    );
    assert.deepEqual(calls, ["inspectRepository", "fetchJson"]);
  }
});

test("Requestor CLI rejects duplicate-key and noncanonical raw discovery JSON before operator key or certificate use", async (t) => {
  const fx = await fixture(t);
  for (const text of [
    `{"certificateFingerprint":"${fx.discovery.certificateFingerprint}","certificateFingerprint":"${fx.discovery.certificateFingerprint}","certificateUrl":"${fx.discovery.certificateUrl}","expiresAtMs":"${fx.discovery.expiresAtMs}","operatorKeyId":"${OPERATOR_KEY_ID}","publicUrl":"${fx.discovery.publicUrl}","releaseId":"${RELEASE_ID}","repositorySha":"${REPOSITORY_SHA}","sessionId":"${SESSION_ID}","signature":${JSON.stringify(fx.discovery.signature)}}`,
    JSON.stringify({
      signature: fx.discovery.signature,
      sessionId: SESSION_ID,
      repositorySha: REPOSITORY_SHA,
      releaseId: RELEASE_ID,
      publicUrl: fx.discovery.publicUrl,
      operatorKeyId: OPERATOR_KEY_ID,
      expiresAtMs: fx.discovery.expiresAtMs,
      certificateUrl: fx.discovery.certificateUrl,
      certificateFingerprint: fx.discovery.certificateFingerprint,
    }),
  ]) {
    const calls = [];
    await assert.rejects(
      main(fx.args, {
        async inspectRepository() {
          calls.push("inspectRepository");
          return { clean: true, detached: true, head: REPOSITORY_SHA };
        },
        async fetchJson() {
          calls.push("fetchJson");
          return text;
        },
        async readOperatorPublicKey() {
          calls.push("readOperatorPublicKey");
          return fx.operatorPublicKey;
        },
        async fetchText() {
          calls.push("fetchText");
          return fx.tlsCertificatePem;
        },
      }),
      /Request payment startup failed safely/,
    );
    assert.deepEqual(calls, ["inspectRepository", "fetchJson"]);
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
