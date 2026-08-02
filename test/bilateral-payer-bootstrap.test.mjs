import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import {
  createHash,
  generateKeyPairSync,
  X509Certificate,
} from "node:crypto";
import {
  mkdtempSync,
  readFileSync,
  rmSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";

import {
  main as payerBootstrapMain,
  PAYER_BOOTSTRAP_CLI_FLAGS,
} from "../bin/handshake-payer-bootstrap.mjs";
import {
  runPayerBootstrap,
} from "../src/bilateral/local-mcp/payer-bootstrap.mjs";
import * as payerBootstrapProduction from
  "../src/bilateral/local-mcp/payer-bootstrap-production.mjs";
import {
  createPayerBootstrapKey,
  PAYER_BOOTSTRAP_CLAIM_SCHEMA,
  payerBootstrapClaimFingerprint,
  sshEd25519Fingerprint,
} from "../src/bilateral/local-mcp/payer-bootstrap-envelope.mjs";

const REPOSITORY_SHA = "abcdef0123456789abcdef0123456789abcdef01";
const RELEASE_ID = "release-payer-bootstrap";
const SESSION_ID = "22222222-2222-4222-8222-222222222222";
const CLAIM_NONCE = "11111111-1111-4111-8111-111111111111";
const STATE_ROOT = "/private/payer-state";
const SECRET_CANARY = "private-bootstrap-capability-canary";
const {
  buildMcpCertificateArguments,
  buildPayerSupervisorArguments,
  buildRestrictedTunnelArguments,
} = payerBootstrapProduction;

function certificatePem() {
  const root = mkdtempSync(join(tmpdir(), "payer-bootstrap-"));
  try {
    const certificatePath = join(root, "payer-mcp.crt");
    const privateKeyPath = join(root, "payer-mcp.key");
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

function payerClaimFixture() {
  const sshPair = generateKeyPairSync("ed25519");
  const sshPublicKey = openSshPublicKey(sshPair);
  const x25519 = createPayerBootstrapKey();
  return Object.freeze({
    claimNonce: CLAIM_NONCE,
    mcpTlsCertificatePem: CERTIFICATE_PEM,
    mcpTlsFingerprint: createHash("sha256")
      .update(new X509Certificate(CERTIFICATE_PEM).raw)
      .digest("hex"),
    paymentMoved: false,
    releaseId: RELEASE_ID,
    repositorySha: REPOSITORY_SHA,
    role: "payer",
    schema: PAYER_BOOTSTRAP_CLAIM_SCHEMA,
    sessionId: SESSION_ID,
    sshPublicKey,
    sshPublicKeyFingerprint:
      sshEd25519Fingerprint(sshPublicKey),
    x25519PublicKey: x25519.publicKey,
  });
}

function fixtureDependencies({
  failAt = null,
  statuses = ["PAYER_MCP_READY", "PROPOSED", "ACKNOWLEDGED"],
} = {}) {
  const calls = [];
  const output = [];
  const stopped = [];
  const zeroized = [];
  const x25519 = createPayerBootstrapKey();
  const sshPair = generateKeyPairSync("ed25519");
  const sshPublicKey = openSshPublicKey(sshPair);
  const tlsFingerprint = createHash("sha256")
    .update(new X509Certificate(CERTIFICATE_PEM).raw)
    .digest("hex");

  const step = (name, result) => async (...args) => {
    calls.push(name);
    if (failAt === name) {
      throw new Error(`${SECRET_CANARY}:${name}`);
    }
    return typeof result === "function"
      ? result(...args)
      : result;
  };
  const dependencies = {
    createMcpTlsIdentity: step("create-mcp-tls-key-and-certificate", {
      certificatePem: CERTIFICATE_PEM,
      fingerprint: tlsFingerprint,
      privateKeyPath: `${STATE_ROOT}/payer-mcp.key`,
    }),
    createSshIdentity: step("create-ssh-key", {
      fingerprint: sshEd25519Fingerprint(sshPublicKey),
      privateKeyPath: `${STATE_ROOT}/payer-tunnel`,
      publicKey: sshPublicKey,
    }),
    createX25519Key: step("create-x25519-key", x25519),
    inspectPrerequisites: step("inspect-prerequisites", {
      git: { command: "/usr/bin/git", version: "2.50.0" },
      node: { command: "/usr/bin/node", major: 22 },
      npm: { command: "/usr/bin/npm", version: "10.9.0" },
      openssh: { command: "/usr/bin/ssh", version: "9.9" },
      openssl: { command: "/usr/bin/openssl", version: "3.5.0" },
      sshKeygen: { command: "/usr/bin/ssh-keygen", version: "9.9" },
    }),
    pollApprovedPackage: step("poll-approved-package", {
      packageResponse: { sealed: true },
    }),
    preparePrivateState: step("prepare-private-state", {
      stateRoot: STATE_ROOT,
    }),
    randomUUID: () => CLAIM_NONCE,
    startPayerSupervisor: step("start-payer-supervisor", {
      id: "supervisor",
    }),
    startRestrictedTunnel: step("start-restricted-tunnel", {
      id: "tunnel",
    }),
    stopPayerSupervisor: async () => stopped.push("supervisor"),
    stopRestrictedTunnel: async () => stopped.push("tunnel"),
    submitPayerClaim: step("submit-payer-claim", ({ claim }) => ({
      claimFingerprint: payerBootstrapClaimFingerprint(claim),
      pollCapability: SECRET_CANARY,
    })),
    verifyAndOpenPackage: step("verify-and-open-package", {
      bootstrapBrokerCapability: SECRET_CANARY,
      bootstrapBrokerUrl: "https://bootstrap.internal.example/v1/requestor-claims",
      launchManifestBytes: Buffer.from('{"paymentMoved":false}'),
      paymentMoved: false,
      tunnelGrantBytes: Buffer.from('{"paymentMoved":false}'),
    }),
    verifyCleanDetachedRelease: step("verify-clean-detached-release", {
      clean: true,
      detached: true,
      repositorySha: REPOSITORY_SHA,
    }),
    verifySignedDiscovery: step("verify-signed-discovery", {
      expiresAtMs: "2000000060000",
      imageDigest:
        "123456789012.dkr.ecr.us-west-2.amazonaws.com/clockchain-handshake@sha256:" +
        "a".repeat(64),
      operatorKeyId: "operator",
      paymentMoved: false,
      payerClaimUrl: "https://bootstrap.clockchain.network/v1/payer-claims",
      publicMcpHostname: "payer.clockchain.network",
      publicMcpPort: 9443,
      releaseId: RELEASE_ID,
      repositorySha: REPOSITORY_SHA,
      schema: "clockchain.payer-bootstrap-discovery/v1",
      sessionId: SESSION_ID,
      signature: {
        algorithm: "ed25519",
        keyId: "operator",
        value: Buffer.alloc(64).toString("base64"),
      },
      tunnelHost: "tunnel.clockchain.network",
      tunnelHostPublicKey: sshPublicKey,
      tunnelHostKeyFingerprint: sshEd25519Fingerprint(sshPublicKey),
      tunnelPort: 443,
    }),
    waitForTerminalLocalStatus: step(
      "wait-for-terminal-local-status",
      async ({ writeStatus }) => {
        for (const status of statuses) {
          writeStatus({ paymentMoved: false, status });
        }
        return { paymentMoved: false, status: "COMPLETED" };
      },
    ),
    writePrivateLaunchMaterial: step("write-private-launch-material", {
      bootstrapBrokerCapabilityPath: `${STATE_ROOT}/broker.capability`,
      launchManifestPath: `${STATE_ROOT}/payer.launch.json`,
      knownHostsPath: `${STATE_ROOT}/known_hosts`,
      tunnelGrantPath: `${STATE_ROOT}/tunnel-grant.json`,
    }),
    writeStatus: (value) => output.push(value),
    zeroizeBootstrapSecrets: async (value) => zeroized.push(value),
  };
  return {
    calls,
    dependencies,
    output,
    stopped,
    zeroized,
  };
}

test("runs the one-shot Payer bootstrap in the exact reviewed order", async () => {
  const fixture = fixtureDependencies();
  const result = await runPayerBootstrap({
    discoveryUrl: "https://public.example/payer-bootstrap.json",
    stateRoot: STATE_ROOT,
  }, fixture.dependencies);

  assert.deepEqual(fixture.calls, [
    "inspect-prerequisites",
    "verify-clean-detached-release",
    "verify-signed-discovery",
    "prepare-private-state",
    "create-x25519-key",
    "create-ssh-key",
    "create-mcp-tls-key-and-certificate",
    "submit-payer-claim",
    "poll-approved-package",
    "verify-and-open-package",
    "write-private-launch-material",
    "start-restricted-tunnel",
    "start-payer-supervisor",
    "wait-for-terminal-local-status",
  ]);
  assert.deepEqual(
    fixture.output.map((entry) => entry.status),
    [
      "PAYER_CLAIM_PENDING",
      "PAYER_MCP_READY",
      "PROPOSED",
      "ACKNOWLEDGED",
      "COMPLETED",
    ],
  );
  assert.equal(result.status, "COMPLETED");
  assert.equal(result.paymentMoved, false);
  assert.deepEqual(fixture.stopped, ["supervisor", "tunnel"]);
  assert.equal(fixture.zeroized.length, 1);

  const publicText = JSON.stringify(fixture.output);
  assert.equal(publicText.includes(SECRET_CANARY), false);
  assert.equal(publicText.includes(STATE_ROOT), false);
  assert.equal(publicText.includes("PRIVATE KEY"), false);
  assert.equal(publicText.includes("AUTHORIZED"), false);
});

test("builds the exact Payer claim from locally generated public identities", async () => {
  const fixture = fixtureDependencies();
  let submitted;
  fixture.dependencies.submitPayerClaim = async (input) => {
    fixture.calls.push("submit-payer-claim");
    submitted = input;
    return {
      claimFingerprint:
        payerBootstrapClaimFingerprint(input.claim),
      pollCapability: SECRET_CANARY,
    };
  };
  await runPayerBootstrap({
    discoveryUrl: "https://public.example/payer-bootstrap.json",
    stateRoot: STATE_ROOT,
  }, fixture.dependencies);

  assert.deepEqual(Object.keys(submitted.claim), [
    "claimNonce",
    "mcpTlsCertificatePem",
    "mcpTlsFingerprint",
    "paymentMoved",
    "releaseId",
    "repositorySha",
    "role",
    "schema",
    "sessionId",
    "sshPublicKey",
    "sshPublicKeyFingerprint",
    "x25519PublicKey",
  ]);
  assert.equal(submitted.claim.paymentMoved, false);
  assert.equal(submitted.claim.role, "payer");
  assert.equal(submitted.claim.repositorySha, REPOSITORY_SHA);
  assert.equal(submitted.claim.sessionId, SESSION_ID);
});

test("production Payer claim submit replays the same body once after a transport failure", async () => {
  const requestBodies = [];
  const serializedBodies = [];
  const claim = payerClaimFixture();
  const dependencies =
    await payerBootstrapProduction.createProductionPayerBootstrapDependencies({
      async submitHttpRequest({ body }) {
        requestBodies.push(body);
        serializedBodies.push(JSON.stringify(body));
        if (requestBodies.length === 1) {
          throw new Error("connection reset after accept");
        }
        return {
          claimFingerprint:
            payerBootstrapClaimFingerprint(claim),
          paymentMoved: false,
          status: "PENDING",
        };
      },
    });

  const result = await dependencies.submitPayerClaim({
    claim,
    payerClaimUrl: "https://127.0.0.1/v1/payer-claims",
  });

  assert.equal(requestBodies.length, 2);
  assert.strictEqual(requestBodies[0].claim, claim);
  assert.strictEqual(requestBodies[1].claim, claim);
  assert.equal(serializedBodies[1], serializedBodies[0]);
  assert.equal(
    requestBodies[1].pollCapability,
    requestBodies[0].pollCapability,
  );
  assert.deepEqual(result, {
    claimFingerprint: payerBootstrapClaimFingerprint(claim),
    pollCapability: requestBodies[0].pollCapability,
  });
});

test("production Payer claim submit fails closed after repeated or altered retry rejection", async () => {
  for (const retryResult of [
    async () => {
      throw new Error("second rejection leaked");
    },
    async () => ({
      claimFingerprint: "b".repeat(64),
      paymentMoved: false,
      status: "PENDING",
    }),
  ]) {
    const claim = payerClaimFixture();
    let attempts = 0;
    const dependencies =
      await payerBootstrapProduction.createProductionPayerBootstrapDependencies({
        async submitHttpRequest() {
          attempts += 1;
          if (attempts === 1) {
            throw new Error("first rejection after accept");
          }
          return retryResult();
        },
      });

    await assert.rejects(
      dependencies.submitPayerClaim({
        claim,
        payerClaimUrl: "https://127.0.0.1/v1/payer-claims",
      }),
      /Payer production bootstrap failed safely/,
    );
    assert.equal(attempts, 2);
  }
});

test("production Payer approval polling continues for the 30 minute demo window", async (t) => {
  const realNow = Date.now;
  const realSetTimeout = globalThis.setTimeout;
  const startMs = 2_000_000_000_000;
  let clockMs = startMs;
  const sleeps = [];
  const claimFingerprint = "b".repeat(64);
  t.after(() => {
    Date.now = realNow;
    globalThis.setTimeout = realSetTimeout;
  });
  Date.now = () => clockMs;
  globalThis.setTimeout = (callback, ms) => {
    sleeps.push(ms);
    clockMs += ms;
    queueMicrotask(callback);
    return { unref() {} };
  };
  const dependencies =
    await payerBootstrapProduction.createProductionPayerBootstrapDependencies({
      async httpsRequest() {
        return clockMs >= startMs + 302_000
          ? {
              claimFingerprint,
              packageResponse: {
                sealed: true,
              },
              paymentMoved: false,
              status: "SEALED",
            }
          : {
              paymentMoved: false,
              status: "PENDING",
            };
      },
    });

  assert.deepEqual(
    await dependencies.pollApprovedPackage({
      claimFingerprint,
      expiresAtMs: String(startMs + 1_800_000),
      payerClaimUrl: "https://127.0.0.1/v1/payer-claims",
      pollCapability: SECRET_CANARY,
    }),
    {
      claimFingerprint,
      packageResponse: {
        sealed: true,
      },
      paymentMoved: false,
      status: "SEALED",
    },
  );
  assert.equal(clockMs, startMs + 302_000);
  assert.equal(
    sleeps.every((value) => value === 2_000),
    true,
  );
});

test("fails safely, cleans up children, and zeroizes bootstrap material at every boundary", async () => {
  const orderedSteps = [
    "inspect-prerequisites",
    "verify-clean-detached-release",
    "verify-signed-discovery",
    "prepare-private-state",
    "create-x25519-key",
    "create-ssh-key",
    "create-mcp-tls-key-and-certificate",
    "submit-payer-claim",
    "poll-approved-package",
    "verify-and-open-package",
    "write-private-launch-material",
    "start-restricted-tunnel",
    "start-payer-supervisor",
    "wait-for-terminal-local-status",
  ];
  for (const failAt of orderedSteps) {
    const fixture = fixtureDependencies({ failAt });
    await assert.rejects(
      runPayerBootstrap({
        discoveryUrl: "https://public.example/payer-bootstrap.json",
        stateRoot: STATE_ROOT,
      }, fixture.dependencies),
      /Payer bootstrap failed safely/,
    );
    assert.equal(
      JSON.stringify(fixture.output).includes(SECRET_CANARY),
      false,
    );
    assert.equal(
      fixture.output.at(-1)?.status,
      "PAYER_BOOTSTRAP_FAILED",
    );
    assert.equal(fixture.zeroized.length, 1);
    if (
      orderedSteps.indexOf(failAt) >
      orderedSteps.indexOf("start-payer-supervisor")
    ) {
      assert.equal(fixture.stopped.includes("supervisor"), true);
    }
    if (
      orderedSteps.indexOf(failAt) >
      orderedSteps.indexOf("start-restricted-tunnel")
    ) {
      assert.equal(fixture.stopped.includes("tunnel"), true);
    }
  }
});

test("rejects changed discovery identity, package authority, and non-protocol statuses", async () => {
  for (const mutate of [
    (fixture) => {
      const original = fixture.dependencies.verifySignedDiscovery;
      fixture.dependencies.verifySignedDiscovery = async (...args) => ({
        ...(await original(...args)),
        repositorySha: "b".repeat(40),
      });
    },
    (fixture) => {
      fixture.dependencies.submitPayerClaim = async () => ({
        claimFingerprint: "b".repeat(64),
        pollCapability: SECRET_CANARY,
      });
    },
    (fixture) => {
      fixture.dependencies.verifyAndOpenPackage = async () => ({
        paymentMoved: true,
      });
    },
  ]) {
    const fixture = fixtureDependencies();
    mutate(fixture);
    await assert.rejects(
      runPayerBootstrap({
        discoveryUrl: "https://public.example/payer-bootstrap.json",
        stateRoot: STATE_ROOT,
      }, fixture.dependencies),
      /Payer bootstrap failed safely/,
    );
    assert.equal(
      fixture.output.at(-1)?.status,
      "PAYER_BOOTSTRAP_FAILED",
    );
  }

  const fixture = fixtureDependencies({
    statuses: ["PAYER_MCP_READY", "AUTHORIZED"],
  });
  await assert.rejects(
    runPayerBootstrap({
      discoveryUrl: "https://public.example/payer-bootstrap.json",
      stateRoot: STATE_ROOT,
    }, fixture.dependencies),
    /Payer bootstrap failed safely/,
  );
  assert.equal(
    JSON.stringify(fixture.output).includes("AUTHORIZED"),
    false,
  );
});

test("Payer CLI accepts only one public discovery URL and one private state root", async () => {
  assert.deepEqual(PAYER_BOOTSTRAP_CLI_FLAGS, [
    "--discovery-url",
    "--state",
  ]);
  const calls = [];
  const result = await payerBootstrapMain([
    "--discovery-url",
    "https://public.example/payer-bootstrap.json",
    "--state",
    STATE_ROOT,
  ], {
    async createProductionDependencies(input) {
      calls.push(["dependencies", input]);
      return { production: true };
    },
    async runBootstrap(input, dependencies) {
      calls.push(["run", input, dependencies]);
      return { paymentMoved: false, status: "COMPLETED" };
    },
  });
  assert.deepEqual(result, {
    paymentMoved: false,
    status: "COMPLETED",
  });
  assert.deepEqual(calls, [
    [
      "dependencies",
      {
        discoveryUrl: "https://public.example/payer-bootstrap.json",
        stateRoot: STATE_ROOT,
      },
    ],
    [
      "run",
      {
        discoveryUrl: "https://public.example/payer-bootstrap.json",
        stateRoot: STATE_ROOT,
      },
      { production: true },
    ],
  ]);

  for (const arguments_ of [
    [],
    ["--discovery-url", "http://public.example/discovery.json", "--state", STATE_ROOT],
    ["--discovery-url", "https://public.example/discovery.json", "--state", "relative"],
    ["--discovery-url", "https://public.example/discovery.json", "--state", "/"],
    ["--discovery-url", "https://public.example/discovery.json", "--state", STATE_ROOT, "--state", STATE_ROOT],
    ["--manifest", "/private/manifest", "--state", STATE_ROOT],
  ]) {
    await assert.rejects(
      payerBootstrapMain(arguments_, {
        async createProductionDependencies() {
          assert.fail("invalid arguments reached production setup");
        },
        async runBootstrap() {
          assert.fail("invalid arguments reached orchestration");
        },
      }),
      /Payer bootstrap CLI failed safely/,
    );
  }
});

test("SIGINT or SIGTERM aborts the active Payer path and runs the same cleanup", async () => {
  for (const signal of ["SIGINT", "SIGTERM"]) {
    const fixture = fixtureDependencies();
    let onSignal;
    let removed = false;
    fixture.dependencies.installSignalHandlers = (callback) => {
      onSignal = callback;
      return () => {
        removed = true;
      };
    };
    const originalStart =
      fixture.dependencies.startRestrictedTunnel;
    fixture.dependencies.startRestrictedTunnel =
      async (...arguments_) => {
        const handle = await originalStart(...arguments_);
        onSignal(signal);
        return handle;
      };

    await assert.rejects(
      runPayerBootstrap({
        discoveryUrl: "https://public.example/payer-bootstrap.json",
        stateRoot: STATE_ROOT,
      }, fixture.dependencies),
      /Payer bootstrap failed safely/,
    );
    assert.deepEqual(fixture.stopped, ["tunnel"]);
    assert.equal(fixture.zeroized.length, 1);
    assert.equal(removed, true);
    assert.equal(
      fixture.output.at(-1)?.status,
      "PAYER_BOOTSTRAP_FAILED",
    );
  }
});

test("Payer MCP certificates keep the public hostname in SAN when it exceeds the CN limit", () => {
  assert.equal(
    typeof buildMcpCertificateArguments,
    "function",
  );
  const hostname =
    "clockc-publi-zy7cx0fg51wv-6631635de11f13ca.elb.us-west-2.amazonaws.com";
  assert.deepEqual(
    buildMcpCertificateArguments({
      certificatePath: `${STATE_ROOT}/payer-mcp.crt`,
      hostname,
      privateKeyPath: `${STATE_ROOT}/payer-mcp.key`,
    }),
    [
      "req",
      "-x509",
      "-newkey",
      "ed25519",
      "-keyout",
      `${STATE_ROOT}/payer-mcp.key`,
      "-out",
      `${STATE_ROOT}/payer-mcp.crt`,
      "-nodes",
      "-days",
      "1",
      "-subj",
      "/CN=clockchain-payer-mcp",
      "-addext",
      `subjectAltName=DNS:${hostname}`,
    ],
  );
});

test("production commands pin one reverse listener and pass private material only by path", () => {
  const discovery = {
    publicMcpHostname: "payer.clockchain.network",
    publicMcpPort: 9443,
    tunnelHost: "tunnel.clockchain.network",
    tunnelPort: 443,
  };
  const paths = {
    bootstrapBrokerCapabilityPath: `${STATE_ROOT}/broker.capability`,
    bootstrapBrokerUrl: "https://bootstrap.internal.example/v1/requestor-claims",
    knownHostsPath: `${STATE_ROOT}/known_hosts`,
    launchManifestPath: `${STATE_ROOT}/payer.launch.json`,
  };
  const sshIdentity = {
    privateKeyPath: `${STATE_ROOT}/payer-tunnel.ed25519`,
  };
  const tlsIdentity = {
    certificatePath: `${STATE_ROOT}/payer-mcp.crt`,
    privateKeyPath: `${STATE_ROOT}/payer-mcp.key`,
  };
  const ssh = buildRestrictedTunnelArguments({
    discovery,
    paths,
    sshIdentity,
  });
  assert.deepEqual(ssh, [
    "-N",
    "-T",
    "-o",
    "BatchMode=yes",
    "-o",
    "ExitOnForwardFailure=yes",
    "-o",
    "IdentitiesOnly=yes",
    "-o",
    "StrictHostKeyChecking=yes",
    "-o",
    `UserKnownHostsFile=${paths.knownHostsPath}`,
    "-o",
    "PasswordAuthentication=no",
    "-o",
    "KbdInteractiveAuthentication=no",
    "-o",
    "PreferredAuthentications=publickey",
    "-i",
    sshIdentity.privateKeyPath,
    "-p",
    "443",
    "-R",
    "0.0.0.0:9443:127.0.0.1:9443",
    "clockchain-payer@tunnel.clockchain.network",
  ]);
  assert.equal(ssh.includes("-L"), false);
  assert.equal(ssh.includes("-A"), false);
  assert.equal(ssh.includes("-X"), false);

  const supervisor = buildPayerSupervisorArguments({
    discovery,
    paths,
    stateRoot: STATE_ROOT,
    tlsIdentity,
  });
  const modeIndex = supervisor.indexOf("--run-mode");
  assert.notEqual(modeIndex, -1);
  assert.equal(supervisor[modeIndex + 1], "aws-stakeholder-only");
  const commandText = JSON.stringify(supervisor);
  assert.equal(
    commandText.includes(
      "https://payer.clockchain.network:9443/mcp",
    ),
    true,
  );
  assert.equal(
    commandText.includes(
      paths.bootstrapBrokerCapabilityPath,
    ),
    true,
  );
  assert.equal(commandText.includes(SECRET_CANARY), false);
  assert.equal(commandText.includes("PRIVATE KEY"), false);
});
