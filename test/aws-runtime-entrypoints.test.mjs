import assert from "node:assert/strict";
import {
  execFile,
  execFileSync,
  spawn,
} from "node:child_process";
import {
  createHash,
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  X509Certificate,
} from "node:crypto";
import {
  lstat,
  mkdtemp,
  readFile,
  rm,
  writeFile,
} from "node:fs/promises";
import {
  mkdtempSync,
  readFileSync,
  rmSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { test } from "node:test";
import { promisify } from "node:util";

import {
  installPrivateFile,
  installSecretFile,
  parseRuntimeInput,
} from "../infra/aws/runtime/runtime-input.mjs";
import {
  main as coordinatorEntrypoint,
} from "../infra/aws/runtime/coordinator-entrypoint.mjs";
import {
  main as fundingEntrypoint,
} from "../infra/aws/runtime/funding-entrypoint.mjs";
import {
  main as relayEntrypoint,
  prepareRelayStateRoot,
} from "../infra/aws/runtime/relay-entrypoint.mjs";
import {
  main as operatorWorkerEntrypoint,
} from "../infra/aws/runtime/operator-worker-entrypoint.mjs";
import {
  main as operatorBootstrapApprovalEntrypoint,
} from "../infra/aws/runtime/operator-bootstrap-approval-entrypoint.mjs";
import {
  main as verifierEntrypoint,
} from "../infra/aws/runtime/verifier-entrypoint.mjs";
import {
  validateTunnelRuntimeConfiguration,
} from "../infra/aws/runtime/tunnel-entrypoint.mjs";

const execFileAsync = promisify(execFile);
const VERIFIER_ATTEMPT_ID =
  "11111111-1111-4111-8111-111111111111";
const VERIFIER_TASK_ARN =
  "arn:aws:ecs:us-west-2:123456789012:task/clockchain/11111111111111111111111111111111";
const OPERATOR_SESSION_ID =
  "22222222-2222-4222-8222-222222222222";
const OPERATOR_RELEASE_ID = `release-${createHash("sha256").update(OPERATOR_SESSION_ID, "utf8").digest("hex").slice(0, 16)}`;
const OPERATOR_PUBLIC_ROOT =
  `/var/lib/clockchain/public/releases/${OPERATOR_RELEASE_ID}`;
const OPERATOR_APPROVED_PAYER_PUBLIC_PATH =
  `/var/lib/clockchain/approved-payer/releases/${OPERATOR_RELEASE_ID}/approved-payer.json`;
const OPERATOR_TUNNEL_HEALTH_PATH =
  `/var/lib/clockchain/tunnel-health/releases/${OPERATOR_RELEASE_ID}/tunnel-health.json`;
const TUNNEL_HOST_PUBLIC_KEY =
  "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILzWMEVEge8QmmJQH5at7CDm9iuX7O4hop0rjeJ95xnC";
const TUNNEL_HOST_KEY_FINGERPRINT =
  "SHA256:UgP8WeC7EtU7Ik6LFbMNeUckAOfLBKJvnaP1ez/1MwU";
const COORDINATOR_SESSION_ID =
  "33333333-3333-4333-8333-333333333333";
const COORDINATOR_RELEASE_ID = `release-${createHash("sha256").update(COORDINATOR_SESSION_ID, "utf8").digest("hex").slice(0, 16)}`;
const COORDINATOR_RELEASE_ROOT =
  `/var/lib/clockchain/operator/releases/${COORDINATOR_RELEASE_ID}`;
const RELAY_RELEASE_ID = "release-4444444444444444";
const RELAY_REPOSITORY_SHA =
  "abcdef0123456789abcdef0123456789abcdef01";
const RELAY_CERTIFICATE_PATH =
  "/var/lib/clockchain/relay/runtime/tls.crt";
const RELAY_PRIVATE_KEY_PATH =
  "/var/lib/clockchain/relay/runtime/tls.key";
const RELAY_STATE_PATH =
  `/var/lib/clockchain/relay/releases/${RELAY_RELEASE_ID}/relay-state.json`;
const TREASURY_ADDRESS =
  "0x157a377e4181f3f87c7f6efed5ddc340ccc00dce";

test("private runtime installation creates a strict missing parent directory", async (t) => {
  const root = await mkdtemp(
    join(tmpdir(), "clockchain-runtime-input-"),
  );
  t.after(() =>
    rm(root, { force: true, recursive: true }));
  const path = join(root, "runtime", "secret");
  await installPrivateFile({
    path,
    value: "secret-canary",
  });
  assert.equal(await readFile(path, "utf8"), "secret-canary");
  assert.equal(
    (await lstat(dirname(path))).mode & 0o777,
    0o700,
  );
  assert.equal(
    (await lstat(path)).mode & 0o777,
    0o600,
  );
});

let cachedEd25519PrivateKeyPem;

function ed25519PrivateKeyPem() {
  cachedEd25519PrivateKeyPem ??=
    generateKeyPairSync("ed25519")
      .privateKey.export({
        format: "pem",
        type: "pkcs8",
      });
  return cachedEd25519PrivateKeyPem;
}

function coordinatorOperatorPublicKey() {
  return createPublicKey(
    createPrivateKey(ed25519PrivateKeyPem()),
  )
    .export({ format: "der", type: "spki" })
    .subarray(-32)
    .toString("base64");
}

function relayTlsMaterial() {
  const root = mkdtempSync(
    join(tmpdir(), "clockchain-relay-cert-"),
  );
  try {
    const certificatePath = join(root, "relay.crt");
    const privateKeyPath = join(root, "relay.key");
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
      "/CN=relay.clockchain.network",
      "-addext",
      "subjectAltName=DNS:relay.clockchain.network",
    ], { stdio: "ignore" });
    return Object.freeze({
      certificatePem:
        readFileSync(certificatePath, "utf8"),
      privateKeyPem:
        readFileSync(privateKeyPath, "utf8"),
    });
  } finally {
    rmSync(root, {
      force: true,
      recursive: true,
    });
  }
}

const RELAY_TLS_MATERIAL = relayTlsMaterial();
const RELAY_TLS_CERTIFICATE_PEM =
  RELAY_TLS_MATERIAL.certificatePem;
const RELAY_TLS_PRIVATE_KEY_PEM =
  RELAY_TLS_MATERIAL.privateKeyPem;
const RELAY_TLS_FINGERPRINT = createHash("sha256")
  .update(
    new X509Certificate(
      RELAY_TLS_CERTIFICATE_PEM,
    ).raw,
  )
  .digest("hex");
const RELAY_OPERATOR_PUBLIC_KEY =
  Buffer.alloc(32, 7).toString("base64");

function relayArgv(overrides = {}) {
  const values = {
    "--advertised-host": "relay.clockchain.network",
    "--host": "0.0.0.0",
    "--port": "8443",
    "--repository-sha": RELAY_REPOSITORY_SHA,
    "--state": RELAY_STATE_PATH,
    "--tls-certificate": RELAY_CERTIFICATE_PATH,
    "--tls-private-key": RELAY_PRIVATE_KEY_PATH,
    ...overrides,
  };
  return [
    "--advertised-host",
    values["--advertised-host"],
    "--host",
    values["--host"],
    "--port",
    values["--port"],
    "--repository-sha",
    values["--repository-sha"],
    "--state",
    values["--state"],
    "--tls-certificate",
    values["--tls-certificate"],
    "--tls-private-key",
    values["--tls-private-key"],
  ];
}

function relayRuntimeInput(overrides = {}) {
  const relay = {
    argv: relayArgv(),
    certificatePath: RELAY_CERTIFICATE_PATH,
    privateKeyPath: RELAY_PRIVATE_KEY_PATH,
    provenance: {
      imageDigest: `sha256:${"1".repeat(64)}`,
      operatorKeyId: "clockchain-demo-2026",
      operatorPublicKey: RELAY_OPERATOR_PUBLIC_KEY,
      repositorySha: RELAY_REPOSITORY_SHA,
      sourceTreeSha256: "2".repeat(64),
    },
    tlsFingerprint: RELAY_TLS_FINGERPRINT,
    tlsSecretArn:
      "arn:aws:secretsmanager:us-west-2:123456789012:secret:relay-tls",
    ...overrides,
  };
  return JSON.stringify({
    paymentMoved: false,
    relay,
    schema: "clockchain.aws-runtime-input/v1",
  });
}

function relayTlsSecret(overrides = {}) {
  return JSON.stringify({
    certificatePem: RELAY_TLS_CERTIFICATE_PEM,
    privateKeyPem: RELAY_TLS_PRIVATE_KEY_PEM,
    ...overrides,
  });
}

function fundingKeystore(address = TREASURY_ADDRESS) {
  return JSON.stringify({
    version: 3,
    id: "demo-wallet",
    address: address.slice(2),
    crypto: {
      ciphertext: "a".repeat(64),
      cipherparams: {
        iv: "b".repeat(32),
      },
      cipher: "aes-128-ctr",
      kdf: "scrypt",
      kdfparams: {
        dklen: 32,
        salt: "c".repeat(64),
        n: 262144,
        r: 8,
        p: 1,
      },
      mac: "d".repeat(64),
    },
  });
}

function mutateFundingKeystore(mutator) {
  const value = JSON.parse(fundingKeystore());
  mutator(value);
  return JSON.stringify(value);
}

function fundingRuntimeInput(overrides = {}) {
  const funding = {
    actionAtMs: 2_000_000_000_000,
    actionId:
      "22222222-2222-4222-8222-222222222222",
    createdAt: "2026-07-31T00:00:00.000Z",
    expectedTreasuryAddress: TREASURY_ADDRESS,
    fundingRecordPath: "/operator/funding-record.json",
    journalDirectory: "/operator/funding-journal",
    keystoreSecretArn:
      "arn:aws:secretsmanager:us-west-2:123456789012:secret:treasury-keystore",
    passwordSecretArn:
      "arn:aws:secretsmanager:us-west-2:123456789012:secret:treasury-password",
    releaseIdentity: {
      releaseId: OPERATOR_RELEASE_ID,
      sessionId: OPERATOR_SESSION_ID,
    },
    repositorySha:
      "abcdef0123456789abcdef0123456789abcdef01",
    resultPath:
      `/var/lib/clockchain/funding-result/releases/${OPERATOR_RELEASE_ID}/actions/22222222-2222-4222-8222-222222222222/funding-result.json`,
    rpcSecretArn:
      "arn:aws:secretsmanager:us-west-2:123456789012:secret:rpc-url",
    ...overrides,
  };
  return JSON.stringify({
    funding,
    paymentMoved: false,
    schema: "clockchain.aws-runtime-input/v1",
  });
}

function operatorRuntimeInput(overrides = {}) {
  const operator = {
    actionQueueUrl:
      "https://sqs.us-west-2.amazonaws.com/123456789012/clockchain-actions",
    actionTableName:
      "ClockchainHandshakeControl",
    paymentMoved: false,
    publicMonitorBucketName:
      "clockchain-public-monitor",
    publicMonitorControlKey: "control.json",
    releaseId: OPERATOR_RELEASE_ID,
    repositorySha:
      "abcdef0123456789abcdef0123456789abcdef01",
    schema:
      "clockchain.aws-operator-runtime/v1",
    sessionId: OPERATOR_SESSION_ID,
    ...overrides,
  };
  return JSON.stringify({
    operator,
    paymentMoved: false,
    schema: "clockchain.aws-runtime-input/v1",
  });
}

function operatorProductionRuntimeInput(overrides = {}) {
  const operator = {
    actionQueueUrl:
      "https://sqs.us-west-2.amazonaws.com/123456789012/clockchain-actions",
    actionTableName:
      "ClockchainHandshakeControl",
    bootstrap: {
      abortMarkerPath:
        `/var/lib/clockchain/tunnel/grants/${OPERATOR_RELEASE_ID}/abort-marker.json`,
      approvedPayerPublicPath:
        OPERATOR_APPROVED_PAYER_PUBLIC_PATH,
      bootstrapBrokerCapabilitySecretArn:
        "arn:aws:secretsmanager:us-west-2:123456789012:secret:bootstrap-capability",
      bootstrapBrokerUrl:
        "https://bootstrap.clockchain.network/v1/",
      bootstrapStatePath:
        `/var/lib/clockchain/bootstrap/releases/${OPERATOR_RELEASE_ID}/bootstrap-state.json`,
      operatorKeyId: "clockchain-demo-2026",
      operatorKeySecretArn:
        "arn:aws:secretsmanager:us-west-2:123456789012:secret:operator-key",
      payeeLaunchManifestPath:
        `/var/lib/clockchain/operator/releases/${OPERATOR_RELEASE_ID}/requestor-launch-manifest.json`,
      payerLaunchManifestPath:
        `/var/lib/clockchain/operator/releases/${OPERATOR_RELEASE_ID}/payer-launch-manifest.json`,
      publicMcpHostname:
        "payer.clockchain.network",
      tunnelGrantPath:
        `/var/lib/clockchain/tunnel/grants/${OPERATOR_RELEASE_ID}/tunnel-grant.json`,
    },
    children: {
      abort: {
        containerName: "abort-tunnel",
        securityGroupId:
          "sg-0123456789abcdef0",
        subnetIds: [
          "subnet-0123456789abcdef0",
          "subnet-11111111111111111",
        ],
        taskDefinitionArn:
          "arn:aws:ecs:us-west-2:123456789012:task-definition/abort-tunnel:7",
      },
      bootstrapApproval: {
        containerName: "bootstrap-approval",
        securityGroupId:
          "sg-0123456789abcdef0",
        subnetIds: [
          "subnet-0123456789abcdef0",
          "subnet-11111111111111111",
        ],
        taskDefinitionArn:
          "arn:aws:ecs:us-west-2:123456789012:task-definition/bootstrap-approval:7",
      },
      clusterArn:
        "arn:aws:ecs:us-west-2:123456789012:cluster/clockchain",
      funding: {
        containerName: "funding",
        createdAt:
          "2026-07-31T00:00:00.000Z",
        expectedTreasuryAddress:
          TREASURY_ADDRESS,
        fundingRecordPath:
          `/var/lib/clockchain/funding-record/releases/${OPERATOR_RELEASE_ID}/funding-record.json`,
        journalDirectory:
          `/var/lib/clockchain/funding-journal/releases/${OPERATOR_RELEASE_ID}/journal`,
        keystoreSecretArn:
          "arn:aws:secretsmanager:us-west-2:123456789012:secret:treasury-keystore",
        passwordSecretArn:
          "arn:aws:secretsmanager:us-west-2:123456789012:secret:treasury-password",
        securityGroupId:
          "sg-0123456789abcdef0",
        subnetIds: [
          "subnet-0123456789abcdef0",
          "subnet-11111111111111111",
        ],
        taskDefinitionArn:
          "arn:aws:ecs:us-west-2:123456789012:task-definition/funding:7",
      },
      rpcSecretArn:
        "arn:aws:secretsmanager:us-west-2:123456789012:secret:rpc-url",
      verifier: {
        clockchainTokenSecretArn:
          "arn:aws:secretsmanager:us-west-2:123456789012:secret:clockchain-token",
        containerName: "verifier",
        securityGroupId:
          "sg-0123456789abcdef0",
        subnetIds: [
          "subnet-0123456789abcdef0",
          "subnet-11111111111111111",
        ],
        taskDefinitionArn:
          "arn:aws:ecs:us-west-2:123456789012:task-definition/verifier:7",
      },
    },
    coordinator: {
      clockchainTokenSecretArn:
        "arn:aws:secretsmanager:us-west-2:123456789012:secret:clockchain-token",
      clusterArn:
        "arn:aws:ecs:us-west-2:123456789012:cluster/clockchain",
      containerName: "coordinator",
      operatorKeyId: "clockchain-demo-2026",
      operatorKeySecretArn:
        "arn:aws:secretsmanager:us-west-2:123456789012:secret:operator-key",
      provenance: {
        imageDigest: `sha256:${"a".repeat(64)}`,
        operatorPublicKey:
          coordinatorOperatorPublicKey(),
        repositorySha:
          "abcdef0123456789abcdef0123456789abcdef01",
        sourceTreeSha256: "b".repeat(64),
      },
      publicStaging:
        operatorPublicStaging(),
      relayUrl:
        "https://relay.clockchain.network:8443",
      rpcSecretArn:
        "arn:aws:secretsmanager:us-west-2:123456789012:secret:rpc-url",
      securityGroupId:
        "sg-0123456789abcdef0",
      subnetIds: [
        "subnet-0123456789abcdef0",
        "subnet-11111111111111111",
      ],
      taskDefinitionArn:
        "arn:aws:ecs:us-west-2:123456789012:task-definition/coordinator:7",
      tlsCertificatePem:
        RELAY_TLS_CERTIFICATE_PEM,
      tlsFingerprint: RELAY_TLS_FINGERPRINT,
    },
    paymentMoved: false,
    publicMonitorBucketName:
      "clockchain-public-monitor",
    publicMonitorControlKey: "control.json",
    releaseId: OPERATOR_RELEASE_ID,
    repositorySha:
      "abcdef0123456789abcdef0123456789abcdef01",
    schema:
      "clockchain.aws-operator-runtime/v1",
    sessionId: OPERATOR_SESSION_ID,
    ...overrides,
  };
  return JSON.stringify({
    operator,
    paymentMoved: false,
    schema: "clockchain.aws-runtime-input/v1",
  });
}

function operatorBootstrapApprovalRuntimeInput(
  overrides = {},
) {
  const bootstrapApproval = {
    claimFingerprint: "b".repeat(64),
    approvedPayerPublicPath:
      OPERATOR_APPROVED_PAYER_PUBLIC_PATH,
    operatorKeySecretArn:
      "arn:aws:secretsmanager:us-west-2:123456789012:secret:operator-key",
    bootstrapBrokerCapabilitySecretArn:
      "arn:aws:secretsmanager:us-west-2:123456789012:secret:bootstrap-capability",
    bootstrapBrokerUrl:
      "https://bootstrap.clockchain.network/v1/",
    bootstrapStatePath:
      `/var/lib/clockchain/bootstrap/releases/${OPERATOR_RELEASE_ID}/bootstrap-state.json`,
    expectedRevision: 7,
    operatorKeyId: "clockchain-demo-2026",
    paymentMoved: false,
    payeeLaunchManifestPath:
      `/var/lib/clockchain/operator/releases/${OPERATOR_RELEASE_ID}/requestor-launch-manifest.json`,
    payerLaunchManifestPath:
      `/var/lib/clockchain/operator/releases/${OPERATOR_RELEASE_ID}/payer-launch-manifest.json`,
    publicMcpHostname:
      "payer.clockchain.network",
    releaseId: OPERATOR_RELEASE_ID,
    repositorySha:
      "abcdef0123456789abcdef0123456789abcdef01",
    role: "payer",
    sessionId: OPERATOR_SESSION_ID,
    tunnelGrantPath:
      `/var/lib/clockchain/tunnel/grants/${OPERATOR_RELEASE_ID}/tunnel-grant.json`,
    ...overrides,
  };
  return JSON.stringify({
    bootstrapApproval,
    paymentMoved: false,
    schema: "clockchain.aws-runtime-input/v1",
  });
}

function operatorPublicStaging(overrides = {}) {
  return {
    approvedPayerPublicPath:
      OPERATOR_APPROVED_PAYER_PUBLIC_PATH,
    bootstrapPayerClaimUrl:
      "https://bootstrap.clockchain.network/v1/payer-claims",
    imageDigest:
      `123456789012.dkr.ecr.us-west-2.amazonaws.com/clockchain-handshake-control-plane@sha256:${"a".repeat(64)}`,
    paths: {
      certificate:
        `${OPERATOR_PUBLIC_ROOT}/payer-mcp.crt`,
      gate:
        `${OPERATOR_PUBLIC_ROOT}/publication-gate.json`,
      input:
        `${OPERATOR_PUBLIC_ROOT}/publisher-input.json`,
      payer:
        `${OPERATOR_PUBLIC_ROOT}/payer.json`,
      requestor:
        `${OPERATOR_PUBLIC_ROOT}/requestor.json`,
    },
    publicBaseUrl:
      "https://public.clockchain.network/",
    publicMcpHostname:
      "relay.clockchain.network",
    publicMcpUrl:
      "https://relay.clockchain.network:9443/mcp",
    tunnelHealthPath:
      OPERATOR_TUNNEL_HEALTH_PATH,
    tunnelHostKeyFingerprint:
      TUNNEL_HOST_KEY_FINGERPRINT,
    tunnelHostPublicKey:
      TUNNEL_HOST_PUBLIC_KEY,
    ...overrides,
  };
}

function coordinatorRuntimeInput(overrides = {}) {
  const coordinator = {
    clockchainTokenSecretArn:
      "arn:aws:secretsmanager:us-west-2:123456789012:secret:clockchain-token",
    operatorKeyId: "clockchain-demo-2026",
    operatorKeySecretArn:
      "arn:aws:secretsmanager:us-west-2:123456789012:secret:operator-key",
    provenance: {
      imageDigest: `sha256:${"a".repeat(64)}`,
      operatorPublicKey:
        coordinatorOperatorPublicKey(),
      repositorySha:
        "abcdef0123456789abcdef0123456789abcdef01",
      sourceTreeSha256: "b".repeat(64),
    },
    publicStaging: coordinatorPublicStaging(),
    releaseIdentity: {
      releaseId: COORDINATOR_RELEASE_ID,
      sessionId: COORDINATOR_SESSION_ID,
    },
    releaseRoot:
      COORDINATOR_RELEASE_ROOT,
    relayUrl:
      "https://relay.clockchain.network:8443",
    repositorySha:
      "abcdef0123456789abcdef0123456789abcdef01",
    rpcSecretArn:
      "arn:aws:secretsmanager:us-west-2:123456789012:secret:rpc-url",
    tlsCertificatePem:
      RELAY_TLS_CERTIFICATE_PEM,
    tlsFingerprint: RELAY_TLS_FINGERPRINT,
    ...overrides,
  };
  return JSON.stringify({
    coordinator,
    paymentMoved: false,
    schema: "clockchain.aws-runtime-input/v1",
  });
}

function coordinatorPublicStaging(overrides = {}) {
  const publicRoot =
    `/var/lib/clockchain/public/releases/${COORDINATOR_RELEASE_ID}`;
  return {
    approvedPayerPublicPath:
      `/var/lib/clockchain/approved-payer/releases/${COORDINATOR_RELEASE_ID}/approved-payer.json`,
    bootstrapPayerClaimUrl:
      "https://bootstrap.clockchain.network/v1/payer-claims",
    imageDigest:
      `123456789012.dkr.ecr.us-west-2.amazonaws.com/clockchain-handshake-control-plane@sha256:${"a".repeat(64)}`,
    paths: {
      certificate:
        `${publicRoot}/payer-mcp.crt`,
      gate: `${publicRoot}/publication-gate.json`,
      input: `${publicRoot}/publisher-input.json`,
      payer: `${publicRoot}/payer.json`,
      requestor: `${publicRoot}/requestor.json`,
    },
    publicBaseUrl:
      "https://public.clockchain.network/",
    publicMcpHostname: "relay.clockchain.network",
    publicMcpUrl:
      "https://relay.clockchain.network:9443/mcp",
    tunnelHealthPath:
      `/var/lib/clockchain/tunnel-health/releases/${COORDINATOR_RELEASE_ID}/tunnel-health.json`,
    tunnelHostKeyFingerprint:
      TUNNEL_HOST_KEY_FINGERPRINT,
    tunnelHostPublicKey:
      TUNNEL_HOST_PUBLIC_KEY,
    ...overrides,
  };
}

function coordinatorRuntimeInputWithPublicStaging(
  publicStaging = coordinatorPublicStaging(),
  overrides = {},
) {
  return coordinatorRuntimeInput({
    publicStaging,
    ...overrides,
  });
}

function publicBootstrapTestDependencies(overrides = {}) {
  const stager = {
    async close() {},
    async stagePayerReady() {},
    async stageStart() {},
    async stageTerminalFailure() {},
  };
  return {
    approvedPayerReader: async () =>
      approvedCoordinatorPayerProjection(),
    createPublicReleaseRoot: async () => {},
    holdLifecycleOpen: async () => {},
    now: () => 2_000_000_000_000,
    publicStagerFactory: () => stager,
    scratchRoot: tmpdir(),
    sleeper: async () => {},
    tunnelHealthReader: async () =>
      readyCoordinatorTunnelHealth(),
    ...overrides,
  };
}

function approvedCoordinatorPayerProjection(overrides = {}) {
  return {
    certificateFingerprint: RELAY_TLS_FINGERPRINT,
    certificatePem: RELAY_TLS_CERTIFICATE_PEM,
    claimFingerprint: "c".repeat(64),
    expiresAtMs: "2000000600000",
    paymentMoved: false,
    releaseId: COORDINATOR_RELEASE_ID,
    repositorySha:
      "abcdef0123456789abcdef0123456789abcdef01",
    schema: "clockchain.aws-approved-payer-public/v1",
    sessionId: COORDINATOR_SESSION_ID,
    status: "APPROVED",
    ...overrides,
  };
}

function readyCoordinatorTunnelHealth(overrides = {}) {
  return {
    schema: "clockchain.payer-tunnel-health/v1",
    releaseId: COORDINATOR_RELEASE_ID,
    repositorySha:
      "abcdef0123456789abcdef0123456789abcdef01",
    sessionId: COORDINATOR_SESSION_ID,
    claimFingerprint: "c".repeat(64),
    mcpTlsFingerprint: RELAY_TLS_FINGERPRINT,
    observedAtMs: "2000000000000",
    expiresAtMs: "2000000600000",
    paymentMoved: false,
    status: "READY",
    ...overrides,
  };
}

function waitingCoordinatorTunnelHealth() {
  return {
    schema: "clockchain.payer-tunnel-health/v1",
    releaseId: null,
    repositorySha: null,
    sessionId: null,
    claimFingerprint: null,
    mcpTlsFingerprint: null,
    observedAtMs: "2000000000000",
    expiresAtMs: "2000000600000",
    paymentMoved: false,
    status: "WAITING",
  };
}

function verifierRuntimeInput(overrides = {}) {
  const verifier = {
    actionAtMs: 2_000_000_000_000,
    attemptId: VERIFIER_ATTEMPT_ID,
    attemptRoot: `/verdict/${VERIFIER_ATTEMPT_ID}`,
    clockchainTokenSecretArn:
      "arn:aws:secretsmanager:us-west-2:123456789012:secret:clockchain-token",
    descriptorPath: "/evidence/descriptor.json",
    evidenceDigest: "d".repeat(64),
    expectedRevision: 5,
    mandateDigest: "e".repeat(64),
    payerMandatePath: "/evidence/payer-mandate.json",
    payeeResultsPath: "/evidence/payee-results",
    payerResultsPath: "/evidence/payer-results",
    paymentRequestPath: "/evidence/payment-request.json",
    publicationPath: "/verdict/task-publication.json",
    repositorySha:
      "abcdef0123456789abcdef0123456789abcdef01",
    requestDigest: "f".repeat(64),
    rpcSecretArn:
      "arn:aws:secretsmanager:us-west-2:123456789012:secret:rpc-url",
    sessionDigest: "a".repeat(64),
    ...overrides,
  };
  return JSON.stringify({
    paymentMoved: false,
    schema: "clockchain.aws-runtime-input/v1",
    verifier,
  });
}

test("every AWS task entrypoint is present and no production entrypoint is a placeholder", async () => {
  for (const name of [
    "bootstrap",
    "coordinator",
    "funding",
    "operator-worker",
    "operator-abort",
    "operator-bootstrap-approval",
    "publisher",
    "relay",
    "tunnel",
    "verifier",
  ]) {
    const path =
      `infra/aws/runtime/${name}-entrypoint.mjs`;
    const source = await readFile(path, "utf8");
    assert.doesNotMatch(
      source,
      /wiring is supplied by the deployed task definition/i,
      path,
    );
    const module = await import(
      `../${path}?test=${Date.now()}-${name}`
    );
    assert.equal(
      typeof module.main,
      "function",
      path,
    );
  }
});

test("operator bootstrap approval entrypoint validates revision but sends only authority fields to adapter", async () => {
  const calls = [];
  const configs = [];
  const result =
    await operatorBootstrapApprovalEntrypoint({
      createAdapter: (config) => {
        configs.push(config);
        return {
          approveAndSeal: async (input) => {
            calls.push(input);
            return {
              paymentMoved: false,
              status: "APPROVED",
            };
          },
        };
      },
      createClients: async () => ({
        secrets: {
          async send(command) {
            if (
              command.input.SecretId.endsWith(
                "operator-key",
              )
            ) {
              return {
                SecretString:
                  ed25519PrivateKeyPem(),
              };
            }
            if (
              command.input.SecretId.endsWith(
                "bootstrap-capability",
              )
            ) {
              return {
                SecretString: "c".repeat(64),
              };
            }
            assert.fail(
              `unexpected secret read ${command.input.SecretId}`,
            );
          },
        },
      }),
      env: {
        AWS_RUNTIME_INPUT:
          operatorBootstrapApprovalRuntimeInput(),
      },
      publishApprovedPayer: async () => {},
    });

  assert.deepEqual(result, {
    paymentMoved: false,
    status: "APPROVED",
  });
  assert.deepEqual(
    Reflect.ownKeys(configs[0]),
    [
      "bootstrapStatePath",
      "payerLaunchManifestPath",
      "payeeLaunchManifestPath",
      "tunnelGrantPath",
      "releaseId",
      "repositorySha",
      "sessionId",
      "operatorKeyId",
      "publicMcpHostname",
      "bootstrapBrokerUrl",
      "bootstrapBrokerCapability",
      "operatorPrivateKeyPem",
      "nowMs",
    ],
  );
  assert.deepEqual(calls, [
    {
      claimFingerprint: "b".repeat(64),
      paymentMoved: false,
      releaseId: OPERATOR_RELEASE_ID,
      repositorySha:
        "abcdef0123456789abcdef0123456789abcdef01",
      role: "payer",
      sessionId: OPERATOR_SESSION_ID,
    },
  ]);
});

test("operator bootstrap approval entrypoint rejects malformed revisions before adapter invocation", async () => {
  for (const expectedRevision of [
    -1,
    1.25,
    Number.MAX_SAFE_INTEGER + 1,
    "7",
    null,
  ]) {
    await assert.rejects(
      operatorBootstrapApprovalEntrypoint({
        createAdapter: () => ({
          approveAndSeal: async () => {
            assert.fail(
              "invalid expectedRevision must not reach adapter",
            );
          },
        }),
        createClients: async () => {
          assert.fail(
            "invalid expectedRevision must not read secrets",
          );
        },
        env: {
          AWS_RUNTIME_INPUT:
            operatorBootstrapApprovalRuntimeInput({
              expectedRevision,
            }),
        },
        publishApprovedPayer: async () => {},
      }),
      /AWS operator bootstrap approval entrypoint failed safely/,
    );
  }
});

test("runtime input accepts one exact canonical JSON object and rejects ambiguous environment data", () => {
  assert.deepEqual(
    parseRuntimeInput({
      AWS_RUNTIME_INPUT:
        '{"paymentMoved":false,"schema":"clockchain.aws-runtime-input/v1"}',
    }),
    {
      paymentMoved: false,
      schema: "clockchain.aws-runtime-input/v1",
    },
  );
  for (const value of [
    "",
    " {}",
    "{}\n",
    '{"schema":"clockchain.aws-runtime-input/v1","paymentMoved":false}',
    '{"paymentMoved":true,"schema":"clockchain.aws-runtime-input/v1"}',
  ]) {
    assert.throws(
      () =>
        parseRuntimeInput({
          AWS_RUNTIME_INPUT: value,
        }),
      /AWS runtime input failed safely/,
    );
  }
});

test("tunnel entrypoint requires an absolute runtime health projection path", () => {
  assert.deepEqual(
    validateTunnelRuntimeConfiguration({
      AWS_TUNNEL_HEALTH_PATH:
        "/var/lib/clockchain/tunnel/health/payer-mcp-ready.json",
      TUNNEL_HOST_KEY_SECRET_ARN:
        "arn:aws:secretsmanager:us-west-2:123456789012:secret:tunnel-host-key",
    }),
    {
      healthPath:
        "/var/lib/clockchain/tunnel/health/payer-mcp-ready.json",
      hostKeySecretArn:
        "arn:aws:secretsmanager:us-west-2:123456789012:secret:tunnel-host-key",
    },
  );
  for (const value of [
    "",
    "relative/health.json",
    "/tmp/health.json ",
    "/tmp/health.json\0",
  ]) {
    assert.throws(
      () =>
        validateTunnelRuntimeConfiguration({
          AWS_TUNNEL_HEALTH_PATH: value,
          TUNNEL_HOST_KEY_SECRET_ARN:
            "arn:aws:secretsmanager:us-west-2:123456789012:secret:tunnel-host-key",
        }),
      /AWS tunnel entrypoint configuration invalid/,
    );
  }
});

test("secret material is installed atomically with mode 0600 and never returned", async () => {
  const root = await mkdtemp(
    join(tmpdir(), "clockchain-runtime-"),
  );
  const path = join(root, "secret");
  const calls = [];
  const result = await installSecretFile({
    client: {
      async send(command) {
        calls.push(command.input);
        return {
          SecretString: "secret-canary",
        };
      },
    },
    commandFactory: (input) => ({
      input,
    }),
    path,
    secretArn:
      "arn:aws:secretsmanager:us-west-2:123456789012:secret:demo",
    validate: (value) =>
      value === "secret-canary",
  });
  assert.equal(result, undefined);
  assert.deepEqual(calls, [
    {
      SecretId:
        "arn:aws:secretsmanager:us-west-2:123456789012:secret:demo",
    },
  ]);
  assert.equal(
    (await lstat(path)).mode & 0o777,
    0o600,
  );
  assert.equal(
    await readFile(path, "utf8"),
    "secret-canary",
  );
  await writeFile(
    join(root, "already"),
    "existing",
    { mode: 0o600 },
  );
  await assert.rejects(
    installSecretFile({
      client: {
        async send() {
          return {
            SecretString: "replacement",
          };
        },
      },
      commandFactory: (input) => ({
        input,
      }),
      path: join(root, "already"),
      secretArn:
        "arn:aws:secretsmanager:us-west-2:123456789012:secret:demo",
      validate: () => true,
    }),
    /AWS runtime input failed safely/,
  );
});

test("coordinator entrypoint materializes validated secrets into unique private argv files", async () => {
  const operatorKey = ed25519PrivateKeyPem();
  const secretReads = [];
  const runCalls = [];
  for (let index = 0; index < 2; index += 1) {
    await coordinatorEntrypoint({
      ...publicBootstrapTestDependencies(),
      client: {
        async send(command) {
          secretReads.push(command.input);
          if (
            command.input.SecretId.endsWith(
              "clockchain-token",
            )
          ) {
            return {
              SecretString: `clockchain-token-${index}`,
            };
          }
          if (
            command.input.SecretId.endsWith(
              "operator-key",
            )
          ) {
            return {
              SecretString: operatorKey,
            };
          }
          if (
            command.input.SecretId.endsWith(
              "rpc-url",
            )
          ) {
            return {
              SecretString:
                "https://ethereum-rpc.publicnode.com/",
            };
          }
          assert.fail(
            `unexpected secret read ${command.input.SecretId}`,
          );
        },
      },
      env: {
        AWS_RUNTIME_INPUT:
          coordinatorRuntimeInput(),
      },
      run: async (argv, dependencies) => {
        const values = Object.fromEntries(
          Array.from(
            { length: argv.length / 2 },
            (_, pair) => [
              argv[pair * 2],
              argv[pair * 2 + 1],
            ],
          ),
        );
        runCalls.push({
          argv,
          dependencies,
          values,
        });
        assert.deepEqual(
          await dependencies.provenanceProvider.verify({
            operatorKeyId: "clockchain-demo-2026",
            repositorySha:
              "abcdef0123456789abcdef0123456789abcdef01",
          }),
          {
            imageDigest: `sha256:${"a".repeat(64)}`,
            operatorPublicKey:
              coordinatorOperatorPublicKey(),
            repositorySha:
              "abcdef0123456789abcdef0123456789abcdef01",
            sourceTreeSha256: "b".repeat(64),
          },
        );
        assert.equal(
          (await lstat(
            values["--clockchain-token-file"],
          )).mode & 0o777,
          0o600,
        );
        assert.equal(
          (await lstat(
            values["--operator-private-key"],
          )).mode & 0o777,
          0o600,
        );
        assert.equal(
          (await lstat(
            values["--rpc-url-file"],
          )).mode & 0o777,
          0o600,
        );
        assert.equal(
          await readFile(
            values["--clockchain-token-file"],
            "utf8",
          ),
          `clockchain-token-${index}`,
        );
        assert.equal(
          await readFile(
            values["--operator-private-key"],
            "utf8",
          ),
          operatorKey,
        );
        assert.equal(
          await readFile(
            values["--rpc-url-file"],
            "utf8",
          ),
          "https://ethereum-rpc.publicnode.com/\n",
        );
        return 0;
      },
    });
  }

  assert.deepEqual(secretReads, [
    {
      SecretId:
        "arn:aws:secretsmanager:us-west-2:123456789012:secret:clockchain-token",
    },
    {
      SecretId:
        "arn:aws:secretsmanager:us-west-2:123456789012:secret:operator-key",
    },
    {
      SecretId:
        "arn:aws:secretsmanager:us-west-2:123456789012:secret:rpc-url",
    },
    {
      SecretId:
        "arn:aws:secretsmanager:us-west-2:123456789012:secret:clockchain-token",
    },
    {
      SecretId:
        "arn:aws:secretsmanager:us-west-2:123456789012:secret:operator-key",
    },
    {
      SecretId:
        "arn:aws:secretsmanager:us-west-2:123456789012:secret:rpc-url",
    },
  ]);
  assert.equal(runCalls.length, 2);
  const expectedPublicArgv = (values) => [
    "--clockchain-token-file",
    values["--clockchain-token-file"],
    "--operator-key-id",
    "clockchain-demo-2026",
    "--operator-private-key",
    values["--operator-private-key"],
    "--release-root",
    COORDINATOR_RELEASE_ROOT,
    "--relay-url",
    "https://relay.clockchain.network:8443",
    "--repository-sha",
    "abcdef0123456789abcdef0123456789abcdef01",
    "--rpc-url-file",
    values["--rpc-url-file"],
    "--tls-certificate",
    values["--tls-certificate"],
    "--tls-fingerprint",
    RELAY_TLS_FINGERPRINT,
  ];
  for (const call of runCalls) {
    assert.deepEqual(
      call.argv,
      expectedPublicArgv(call.values),
    );
    assert.deepEqual(call.dependencies.releaseIdentity, {
      releaseId: COORDINATOR_RELEASE_ID,
      sessionId: COORDINATOR_SESSION_ID,
    });
    assert.equal(
      call.dependencies.abortSignal instanceof AbortSignal,
      true,
    );
    assert.equal(
      typeof call.dependencies.publicStager.stageStart,
      "function",
    );
    await assert.rejects(
      lstat(
        call.values["--clockchain-token-file"],
      ),
      { code: "ENOENT" },
    );
    await assert.rejects(
      lstat(
        call.values["--operator-private-key"],
      ),
      { code: "ENOENT" },
    );
    await assert.rejects(
      lstat(call.values["--rpc-url-file"]),
      { code: "ENOENT" },
    );
    await assert.rejects(
      lstat(
        call.values["--tls-certificate"],
      ),
      { code: "ENOENT" },
    );
  }
  assert.notEqual(
    dirname(
      runCalls[0].values[
        "--clockchain-token-file"
      ],
    ),
    dirname(
      runCalls[1].values[
        "--clockchain-token-file"
      ],
    ),
  );
});

test("coordinator entrypoint rejects an operator key that does not match deployment provenance", async () => {
  let ran = false;
  await assert.rejects(
    coordinatorEntrypoint({
      ...publicBootstrapTestDependencies(),
      client: {
        async send(command) {
          if (
            command.input.SecretId.endsWith(
              "clockchain-token",
            )
          ) {
            return { SecretString: "clockchain-token" };
          }
          if (
            command.input.SecretId.endsWith(
              "operator-key",
            )
          ) {
            const { privateKey } =
              generateKeyPairSync("ed25519");
            return {
              SecretString: privateKey.export({
                format: "pem",
                type: "pkcs8",
              }),
            };
          }
          return {
            SecretString:
              "https://ethereum-rpc.publicnode.com/",
          };
        },
      },
      env: {
        AWS_RUNTIME_INPUT:
          coordinatorRuntimeInput(),
      },
      run: async () => {
        ran = true;
        return 0;
      },
    }),
    /AWS coordinator entrypoint failed safely/,
  );
  assert.equal(ran, false);
});

test("coordinator entrypoint stages initial public monitor and opens Requestor discovery only after exact Payer evidence", async () => {
  const operatorKey = ed25519PrivateKeyPem();
  const calls = [];
  const stager = {
    async close() {
      calls.push(["close"]);
    },
    async stagePayerReady(value) {
      calls.push(["stagePayerReady", value]);
    },
    async stageStart(value) {
      calls.push(["stageStart", value]);
    },
    async stageTerminalFailure() {
      calls.push(["stageTerminalFailure"]);
    },
  };
  let approvedReads = 0;
  let tunnelReads = 0;

  const result = await coordinatorEntrypoint({
    approvedPayerReader: async (path) => {
      calls.push(["approvedReader", path]);
      approvedReads += 1;
      return approvedReads === 1
        ? null
        : approvedCoordinatorPayerProjection();
    },
    client: {
      async send(command) {
        if (
          command.input.SecretId.endsWith(
            "clockchain-token",
          )
        ) {
          return {
            SecretString: "clockchain-token",
          };
        }
        if (
          command.input.SecretId.endsWith(
            "operator-key",
          )
        ) {
          return { SecretString: operatorKey };
        }
        return {
          SecretString:
            "https://ethereum-rpc.publicnode.com/",
        };
      },
    },
    createPublicReleaseRoot: async (path) => {
      calls.push(["createPublicReleaseRoot", path]);
    },
    env: {
      AWS_RUNTIME_INPUT:
        coordinatorRuntimeInputWithPublicStaging(),
    },
    holdLifecycleOpen: async () => {},
    now: () => 2_000_000_000_000,
    publicStagerFactory: (config) => {
      calls.push(["publicStagerFactory", {
        operatorKeyType:
          config.operatorPrivateKey.asymmetricKeyType,
        payerClaimUrl: config.payerClaimUrl,
        tunnelHost: config.tunnelHost,
      }]);
      return stager;
    },
    run: async (argv, dependencies) => {
      calls.push([
        "run",
        dependencies.releaseIdentity,
        dependencies.publicStager === stager,
        argv.includes("--release-root"),
      ]);
      return 0;
    },
    scratchRoot: tmpdir(),
    sleeper: async () => {
      calls.push(["sleep"]);
    },
    tunnelHealthReader: async (path) => {
      calls.push(["tunnelReader", path]);
      tunnelReads += 1;
      return tunnelReads === 1
        ? waitingCoordinatorTunnelHealth()
        : readyCoordinatorTunnelHealth();
    },
  });

  assert.equal(result, 0);
  assert.deepEqual(calls[0], [
    "createPublicReleaseRoot",
    `/var/lib/clockchain/public/releases/${COORDINATOR_RELEASE_ID}`,
  ]);
  assert.deepEqual(calls[1], ["publicStagerFactory", {
    operatorKeyType: "ed25519",
    payerClaimUrl:
      "https://bootstrap.clockchain.network/v1/payer-claims",
    tunnelHost: "relay.clockchain.network",
  }]);
  assert.equal(calls[2][0], "stageStart");
  assert.equal(
    calls[2][1].snapshot.currentStep,
    "Waiting for the Payer and Requestor to join the run.",
  );
  assert.equal(calls[2][1].expiresAtMs, "2000001800000");
  assert.equal(
    calls.some((call) => call[0] === "run"),
    true,
  );
  const readyCall = calls.find(
    (call) => call[0] === "stagePayerReady",
  );
  assert.equal(readyCall[1].approvedPayer.claimFingerprint, "c".repeat(64));
  assert.equal(readyCall[1].tunnelHealth.mcpTlsFingerprint, RELAY_TLS_FINGERPRINT);
  assert.deepEqual(calls.at(-1), ["close"]);
});

test("coordinator entrypoint stays alive after setup and payer readiness complete", async () => {
  const operatorKey = ed25519PrivateKeyPem();
  const calls = [];
  let releaseHold;
  let settled = false;
  const result = coordinatorEntrypoint({
    ...publicBootstrapTestDependencies({
      publicStagerFactory: () => ({
        async close() {
          calls.push(["close"]);
        },
        async stagePayerReady() {
          calls.push(["stagePayerReady"]);
        },
        async stageStart() {
          calls.push(["stageStart"]);
        },
        async stageTerminalFailure() {
          calls.push(["stageTerminalFailure"]);
        },
      }),
    }),
    client: {
      async send(command) {
        if (
          command.input.SecretId.endsWith(
            "clockchain-token",
          )
        ) {
          return {
            SecretString: "clockchain-token",
          };
        }
        if (
          command.input.SecretId.endsWith(
            "operator-key",
          )
        ) {
          return { SecretString: operatorKey };
        }
        return {
          SecretString:
            "https://ethereum-rpc.publicnode.com/",
        };
      },
    },
    env: {
      AWS_RUNTIME_INPUT:
        coordinatorRuntimeInputWithPublicStaging(),
    },
    holdLifecycleOpen: async () =>
      new Promise((resolve) => {
        releaseHold = resolve;
      }),
    run: async () => {
      calls.push(["run"]);
      return 0;
    },
  }).then((value) => {
    settled = true;
    return value;
  });

  for (let attempt = 0; attempt < 50 && calls.length < 3; attempt += 1) {
    await new Promise((resolve) => setTimeout(resolve, 0));
  }

  assert.deepEqual(
    calls.map((call) => call[0]),
    ["stageStart", "run", "stagePayerReady"],
  );
  assert.equal(settled, false);

  releaseHold();

  assert.equal(await result, 0);
  assert.deepEqual(
    calls.map((call) => call[0]),
    ["stageStart", "run", "stagePayerReady", "close"],
  );
});

test("coordinator entrypoint default hold keeps a subprocess alive until SIGTERM cleanup", async (t) => {
  const root = await mkdtemp(
    join(tmpdir(), "clockchain-coordinator-liveness-"),
  );
  t.after(() =>
    rm(root, { force: true, recursive: true }));
  const script = join(root, "coordinator-liveness.mjs");
  const entrypointUrl = new URL(
    "../infra/aws/runtime/coordinator-entrypoint.mjs",
    import.meta.url,
  ).href;
  await writeFile(
    script,
    `import { main } from ${JSON.stringify(entrypointUrl)};
import { tmpdir } from "node:os";
const operatorKey = ${JSON.stringify(ed25519PrivateKeyPem())};
const runtimeInput = ${JSON.stringify(coordinatorRuntimeInputWithPublicStaging())};
const approved = ${JSON.stringify(approvedCoordinatorPayerProjection())};
const tunnel = ${JSON.stringify(readyCoordinatorTunnelHealth())};
main({
  approvedPayerReader: async () => approved,
  client: {
    async send(command) {
      if (command.input.SecretId.endsWith("clockchain-token")) return { SecretString: "clockchain-token" };
      if (command.input.SecretId.endsWith("operator-key")) return { SecretString: operatorKey };
      return { SecretString: "https://ethereum-rpc.publicnode.com/" };
    },
  },
  createPublicReleaseRoot: async () => {},
  env: { AWS_RUNTIME_INPUT: runtimeInput },
  now: () => 2_000_000_000_000,
  publicStagerFactory: () => ({
    async close() { process.stdout.write("CLOSED\\n"); },
    async stagePayerReady() { process.stdout.write("READY\\n"); },
    async stageStart() {},
    async stageTerminalFailure() { process.stdout.write("FAILED\\n"); },
  }),
  run: async () => 0,
  scratchRoot: tmpdir(),
  sleeper: async () => {},
  tunnelHealthReader: async () => tunnel,
}).then((value) => {
  process.stdout.write(\`RESULT:\${value}\\n\`);
}).catch((error) => {
  process.stderr.write(\`\${error?.message ?? error}\\n\`);
  process.exitCode = 1;
});
`,
  );

  const child = spawn(process.execPath, [script], {
    stdio: ["ignore", "pipe", "pipe"],
  });
  t.after(() => {
    if (child.exitCode === null && child.signalCode === null) {
      child.kill("SIGKILL");
    }
  });
  let stdout = "";
  let stderr = "";
  child.stdout.setEncoding("utf8");
  child.stderr.setEncoding("utf8");
  child.stdout.on("data", (chunk) => {
    stdout += chunk;
  });
  child.stderr.on("data", (chunk) => {
    stderr += chunk;
  });
  const close = new Promise((resolve) => {
    child.once("close", (code, signal) => {
      resolve({ code, signal });
    });
  });
  const ready = new Promise((resolve, reject) => {
    const timeout = setTimeout(() => {
      reject(new Error(`coordinator child did not become ready; stdout=${stdout} stderr=${stderr}`));
    }, 2_000);
    child.stdout.on("data", () => {
      if (stdout.includes("READY\n")) {
        clearTimeout(timeout);
        resolve();
      }
    });
    child.once("exit", (code, signal) => {
      if (!stdout.includes("READY\n")) {
        clearTimeout(timeout);
        reject(new Error(`coordinator child exited before ready code=${code} signal=${signal} stdout=${stdout} stderr=${stderr}`));
      }
    });
  });

  await ready;
  await new Promise((resolve) => setTimeout(resolve, 200));
  assert.equal(child.exitCode, null);
  assert.equal(child.signalCode, null);

  child.kill("SIGTERM");
  const exit = await close;
  assert.deepEqual(exit, { code: 0, signal: null });
  assert.match(stdout, /CLOSED\nRESULT:0\n$/);
  assert.equal(stderr, "");
});

test("coordinator entrypoint terminal-stages public failure when Payer evidence is mismatched", async () => {
  const calls = [];
  await assert.rejects(
    coordinatorEntrypoint({
      approvedPayerReader: async () =>
        approvedCoordinatorPayerProjection(),
      client: {
        async send(command) {
          if (
            command.input.SecretId.endsWith(
              "clockchain-token",
            )
          ) {
            return {
              SecretString: "clockchain-token",
            };
          }
          if (
            command.input.SecretId.endsWith(
              "operator-key",
            )
          ) {
            return {
              SecretString: ed25519PrivateKeyPem(),
            };
          }
          return {
            SecretString:
              "https://ethereum-rpc.publicnode.com/",
          };
        },
      },
      createPublicReleaseRoot: async () => {},
      env: {
        AWS_RUNTIME_INPUT:
          coordinatorRuntimeInputWithPublicStaging(),
      },
      now: () => 2_000_000_000_000,
      publicStagerFactory: () => ({
        async close() {
          calls.push(["close"]);
        },
        async stagePayerReady() {
          calls.push(["stagePayerReady"]);
        },
        async stageStart() {
          calls.push(["stageStart"]);
        },
        async stageTerminalFailure(value) {
          calls.push(["stageTerminalFailure", value]);
        },
      }),
      run: async () => {
        calls.push(["run"]);
        return 0;
      },
      scratchRoot: tmpdir(),
      sleeper: async () => {},
      tunnelHealthReader: async () =>
        readyCoordinatorTunnelHealth({
          claimFingerprint: "d".repeat(64),
        }),
    }),
    (error) => {
      assert.match(
        error.message,
        /AWS coordinator entrypoint failed safely/,
      );
      assert.doesNotMatch(
        String(error),
        /clockchain-token|ethereum-rpc|PRIVATE KEY|AUTHORIZED/,
      );
      return true;
    },
  );
  assert.deepEqual(
    calls.map((call) => call[0]),
    ["stageStart", "run", "stageTerminalFailure", "close"],
  );
});

test("coordinator entrypoint drains an aborted readiness poll before cleanup after run failure", async () => {
  const calls = [];
  await assert.rejects(
    coordinatorEntrypoint({
      ...publicBootstrapTestDependencies({
        approvedPayerReader: async () => null,
        publicStagerFactory: () => ({
          async close() {
            calls.push(["close"]);
          },
          async stagePayerReady() {
            calls.push(["stagePayerReady"]);
          },
          async stageStart() {
            calls.push(["stageStart"]);
          },
          async stageTerminalFailure() {
            calls.push(["stageTerminalFailure"]);
          },
        }),
        sleeper: async (_ms, { signal }) =>
          new Promise((resolve, reject) => {
            signal.addEventListener("abort", () => {
              calls.push(["pollAbort"]);
              reject(new Error("poll abort canary"));
            }, { once: true });
          }),
        tunnelHealthReader: async () => null,
      }),
      client: {
        async send(command) {
          if (
            command.input.SecretId.endsWith(
              "clockchain-token",
            )
          ) {
            return {
              SecretString: "clockchain-token",
            };
          }
          if (
            command.input.SecretId.endsWith(
              "operator-key",
            )
          ) {
            return {
              SecretString: ed25519PrivateKeyPem(),
            };
          }
          return {
            SecretString:
              "https://ethereum-rpc.publicnode.com/",
          };
        },
      },
      env: {
        AWS_RUNTIME_INPUT:
          coordinatorRuntimeInput(),
      },
      run: async () => {
        calls.push(["run"]);
        return 1;
      },
    }),
    /AWS coordinator entrypoint failed safely/,
  );
  assert.deepEqual(
    calls.map((call) => call[0]),
    [
      "stageStart",
      "run",
      "pollAbort",
      "stageTerminalFailure",
      "close",
    ],
  );
});

test("coordinator entrypoint aborts and drains a long-lived run before terminal staging after poll failure", async () => {
  const calls = [];
  await assert.rejects(
    coordinatorEntrypoint({
      ...publicBootstrapTestDependencies({
        approvedPayerReader: async () =>
          approvedCoordinatorPayerProjection(),
        publicStagerFactory: () => ({
          async close() {
            calls.push(["close"]);
          },
          async stagePayerReady() {
            calls.push(["stagePayerReady"]);
          },
          async stageStart() {
            calls.push(["stageStart"]);
          },
          async stageTerminalFailure() {
            calls.push(["stageTerminalFailure"]);
          },
        }),
        tunnelHealthReader: async () =>
          readyCoordinatorTunnelHealth({
            claimFingerprint: "d".repeat(64),
          }),
      }),
      client: {
        async send(command) {
          if (
            command.input.SecretId.endsWith(
              "clockchain-token",
            )
          ) {
            return {
              SecretString: "clockchain-token",
            };
          }
          if (
            command.input.SecretId.endsWith(
              "operator-key",
            )
          ) {
            return {
              SecretString: ed25519PrivateKeyPem(),
            };
          }
          return {
            SecretString:
              "https://ethereum-rpc.publicnode.com/",
          };
        },
      },
      env: {
        AWS_RUNTIME_INPUT:
          coordinatorRuntimeInput(),
      },
      run: async (_argv, { abortSignal }) => {
        assert.equal(abortSignal instanceof AbortSignal, true);
        assert.equal(Object.getPrototypeOf(abortSignal), AbortSignal.prototype);
        calls.push(["run"]);
        return new Promise((_resolve, reject) => {
          abortSignal.addEventListener("abort", () => {
            calls.push(["runAbort"]);
            reject(new Error("coordinator run aborted"));
          }, { once: true });
        });
      },
    }),
    (error) => {
      assert.match(
        error.message,
        /AWS coordinator entrypoint failed safely/,
      );
      assert.doesNotMatch(
        String(error),
        /clockchain-token|ethereum-rpc|PRIVATE KEY|AUTHORIZED/,
      );
      return true;
    },
  );
  assert.deepEqual(
    calls.map((call) => call[0]),
    ["stageStart", "run", "runAbort", "stageTerminalFailure", "close"],
  );
});

test("coordinator entrypoint rejects malformed runtime input before secret reads", async () => {
  const cases = [
    coordinatorRuntimeInput({
      releaseIdentity: {
        releaseId: "release-0000000000000000",
        sessionId: COORDINATOR_SESSION_ID,
      },
    }),
    coordinatorRuntimeInput({
      releaseRoot:
        "/var/lib/clockchain/operator/releases/release-0000000000000000",
    }),
    coordinatorRuntimeInput({
      tlsCertificatePem: "not-a-certificate",
    }),
    coordinatorRuntimeInput({
      tlsFingerprint: "0".repeat(64),
    }),
    coordinatorRuntimeInput({
      relayUrl:
        "https://relay.clockchain.network:8443?x=1",
    }),
    coordinatorRuntimeInput({
      relayUrl:
        "https://relay.clockchain.network",
    }),
    coordinatorRuntimeInput({
      operatorKeyId: "Clockchain-Demo-2026",
    }),
    coordinatorRuntimeInput({
      operatorKeyId: "-clockchain-demo-2026",
    }),
    coordinatorRuntimeInput({
      tlsCertificatePem:
        `${RELAY_TLS_CERTIFICATE_PEM}\nextra`,
    }),
    coordinatorRuntimeInput({
      tlsFingerprint: "B".repeat(64),
    }),
    coordinatorRuntimeInput({
      rpcSecretArn: "not-an-arn",
    }),
    JSON.stringify({
      coordinator: JSON.parse(
        coordinatorRuntimeInput(),
      ).coordinator,
      paymentMoved: false,
      schema:
        "clockchain.aws-runtime-input/v1",
      z: "unknown",
    }),
  ];
  for (const runtimeInput of cases) {
    let secretReads = 0;
    await assert.rejects(
      coordinatorEntrypoint({
        ...publicBootstrapTestDependencies(),
        client: {
          async send() {
            secretReads += 1;
            return { SecretString: "secret" };
          },
        },
        env: {
          AWS_RUNTIME_INPUT: runtimeInput,
        },
        run: async () => {
          assert.fail("run must not start");
        },
      }),
      /AWS coordinator entrypoint failed safely|AWS runtime input failed safely/,
    );
    assert.equal(secretReads, 0);
  }
});

test("coordinator entrypoint rejects invalid secrets before scratch creation or run", async () => {
  const operatorKey = ed25519PrivateKeyPem();
  const rsaKey = generateKeyPairSync("rsa", {
    modulusLength: 2048,
  }).privateKey.export({
    format: "pem",
    type: "pkcs8",
  });
  const cases = [
    {
      token: "clockchain-token\nsecond-line",
      operatorKey,
      rpc: "https://ethereum-rpc.publicnode.com/",
    },
    {
      token: "clockchain-token",
      operatorKey: rsaKey,
      rpc: "https://ethereum-rpc.publicnode.com/",
    },
    {
      token: "clockchain-token",
      operatorKey,
      rpc: "https://127.0.0.1/",
    },
    {
      token: "clockchain-token",
      operatorKey,
      rpc: "https://[::ffff:7f00:1]/",
    },
    {
      token: "clockchain-token",
      operatorKey,
      rpc: "https://[2001:db8::1]/",
    },
  ];
  for (const value of cases) {
    const calls = [];
    await assert.rejects(
      coordinatorEntrypoint({
        ...publicBootstrapTestDependencies(),
        client: {
          async send(command) {
            calls.push(command.input.SecretId);
            if (
              command.input.SecretId.endsWith(
                "clockchain-token",
              )
            ) {
              return { SecretString: value.token };
            }
            if (
              command.input.SecretId.endsWith(
                "operator-key",
              )
            ) {
              return {
                SecretString: value.operatorKey,
              };
            }
            return { SecretString: value.rpc };
          },
        },
        createTempDir: async () => {
          calls.push("createTempDir");
          throw new Error(
            "scratch should not be created",
          );
        },
        env: {
          AWS_RUNTIME_INPUT:
            coordinatorRuntimeInput(),
        },
        run: async () => {
          calls.push("run");
        },
      }),
      (error) => {
        assert.match(
          error.message,
          /AWS coordinator entrypoint failed safely|AWS runtime input failed safely/,
        );
        assert.doesNotMatch(
          String(error),
          /clockchain-token|ethereum-rpc|PRIVATE KEY|127\.0\.0\.1/,
        );
        return true;
      },
    );
    assert.deepEqual(
      calls.filter(
        (call) => call === "createTempDir" || call === "run",
      ),
      [],
    );
  }
});

test("coordinator entrypoint rejects non-public RPC IP literals before scratch creation or run", async () => {
  const operatorKey = ed25519PrivateKeyPem();
  for (const rpc of [
    "https://100.64.0.1/",
    "https://192.0.0.1/",
    "https://192.0.2.1/",
    "https://192.88.99.1/",
    "https://198.18.0.1/",
    "https://198.51.100.1/",
    "https://203.0.113.1/",
    "https://224.0.0.1/",
    "https://240.0.0.1/",
    "https://[100::1]/",
    "https://[2001::1]/",
    "https://[2002::1]/",
    "https://[ff02::1]/",
    "https://[::ffff:100.64.0.1]/",
    "https://[::ffff:c612:1]/",
  ]) {
    const calls = [];
    await assert.rejects(
      coordinatorEntrypoint({
        client: {
          async send(command) {
            calls.push(command.input.SecretId);
            if (
              command.input.SecretId.endsWith(
                "clockchain-token",
              )
            ) {
              return {
                SecretString: "clockchain-token",
              };
            }
            if (
              command.input.SecretId.endsWith(
                "operator-key",
              )
            ) {
              return { SecretString: operatorKey };
            }
            return { SecretString: rpc };
          },
        },
        createTempDir: async () => {
          calls.push("createTempDir");
          throw new Error(
            "scratch should not be created",
          );
        },
        env: {
          AWS_RUNTIME_INPUT:
            coordinatorRuntimeInput(),
        },
        run: async () => {
          calls.push("run");
        },
      }),
      /AWS coordinator entrypoint failed safely|AWS runtime input failed safely/,
      rpc,
    );
    assert.deepEqual(
      calls.filter(
        (call) => call === "createTempDir" || call === "run",
      ),
      [],
      rpc,
    );
  }
});

test("coordinator entrypoint accepts known public IPv4 and IPv6 RPC literals", async () => {
  const operatorKey = ed25519PrivateKeyPem();
  const calls = [];
  for (const rpc of [
    "https://8.8.8.8/",
    "https://[2606:4700:4700::1111]/",
  ]) {
    await coordinatorEntrypoint({
      ...publicBootstrapTestDependencies(),
      client: {
        async send(command) {
          if (
            command.input.SecretId.endsWith(
              "clockchain-token",
            )
          ) {
            return {
              SecretString: "clockchain-token",
            };
          }
          if (
            command.input.SecretId.endsWith(
              "operator-key",
            )
          ) {
            return { SecretString: operatorKey };
          }
          return { SecretString: rpc };
        },
      },
      env: {
        AWS_RUNTIME_INPUT:
          coordinatorRuntimeInput(),
      },
      run: async (argv) => {
        const values = Object.fromEntries(
          Array.from(
            { length: argv.length / 2 },
            (_, pair) => [
              argv[pair * 2],
              argv[pair * 2 + 1],
            ],
          ),
        );
        calls.push(
          await readFile(
            values["--rpc-url-file"],
            "utf8",
          ),
        );
        return 0;
      },
    });
  }
  assert.deepEqual(calls, [
    "https://8.8.8.8/\n",
    "https://[2606:4700:4700::1111]/\n",
  ]);
});

test("coordinator entrypoint accepts a known public IPv6 RPC literal", async () => {
  const operatorKey = ed25519PrivateKeyPem();
  const calls = [];
  await coordinatorEntrypoint({
    ...publicBootstrapTestDependencies(),
    client: {
      async send(command) {
        if (
          command.input.SecretId.endsWith(
            "clockchain-token",
          )
        ) {
          return {
            SecretString: "clockchain-token",
          };
        }
        if (
          command.input.SecretId.endsWith(
            "operator-key",
          )
        ) {
          return { SecretString: operatorKey };
        }
        return {
          SecretString:
            "https://[2606:4700:4700::1111]/",
        };
      },
    },
    env: {
      AWS_RUNTIME_INPUT: coordinatorRuntimeInput(),
    },
    run: async (argv) => {
      const values = Object.fromEntries(
        Array.from(
          { length: argv.length / 2 },
          (_, pair) => [
            argv[pair * 2],
            argv[pair * 2 + 1],
          ],
        ),
      );
      calls.push(
        await readFile(
          values["--rpc-url-file"],
          "utf8",
        ),
      );
      return 0;
    },
  });
  assert.deepEqual(calls, [
    "https://[2606:4700:4700::1111]/\n",
  ]);
});

test("coordinator entrypoint attempts all cleanup and fails closed when cleanup fails", async () => {
  const root = await mkdtemp(
    join(
      tmpdir(),
      "clockchain-coordinator-entrypoint-",
    ),
  );
  const scratch = join(
    root,
    "clockchain-coordinator-",
  );
  const calls = [];
  try {
    await assert.rejects(
      coordinatorEntrypoint({
        ...publicBootstrapTestDependencies(),
        scratchRoot: "/dev/shm",
        client: {
          async send(command) {
            if (
              command.input.SecretId.endsWith(
                "clockchain-token",
              )
            ) {
              return {
                SecretString: "clockchain-token",
              };
            }
            if (
              command.input.SecretId.endsWith(
                "operator-key",
              )
            ) {
              return {
                SecretString: ed25519PrivateKeyPem(),
              };
            }
            return {
              SecretString:
                "https://ethereum-rpc.publicnode.com/",
            };
          },
        },
        createTempDir: async (prefix) => {
          const path = await mkdtemp(
            `${scratch}-`,
          );
          calls.push([
            "createTempDir",
            prefix,
            path,
          ]);
          return path;
        },
        env: {
          AWS_RUNTIME_INPUT:
            coordinatorRuntimeInput(),
        },
        removeDir: async (path) => {
          calls.push(["removeDir", path]);
          throw new Error("cleanup canary");
        },
        removeFile: async (path) => {
          calls.push([
            "removeFile",
            path,
          ]);
          throw new Error("cleanup canary");
        },
        run: async () => {
          calls.push(["run"]);
          return 0;
        },
      }),
      (error) => {
        assert.equal(
          error.message,
          "AWS coordinator entrypoint failed safely.",
        );
        assert.doesNotMatch(
          String(error),
          /cleanup canary|clockchain-token|ethereum-rpc|PRIVATE KEY/,
        );
        return true;
      },
    );
  } finally {
    await rm(root, {
      force: true,
      recursive: true,
    });
  }
  const scratchDir = calls[0][2];
  assert.deepEqual(calls, [
    [
      "createTempDir",
      join("/dev/shm", "clockchain-coordinator-"),
      scratchDir,
    ],
    ["run"],
    [
      "removeFile",
      join(scratchDir, "clockchain-token"),
    ],
    [
      "removeFile",
      join(
        scratchDir,
        "operator-private-key.pem",
      ),
    ],
    [
      "removeFile",
      join(scratchDir, "sepolia-rpc-url"),
    ],
    [
      "removeFile",
      join(
        scratchDir,
        "relay-public-certificate.pem",
      ),
    ],
    ["removeDir", scratchDir],
  ]);
});

test("coordinator production CLI fails closed without leaking runtime values", async () => {
  const result = await execFileAsync(
    process.execPath,
    ["infra/aws/runtime/coordinator-entrypoint.mjs"],
    {
      env: {
        ...process.env,
        AWS_RUNTIME_INPUT: coordinatorRuntimeInput(),
      },
    },
  ).catch((error) => error);
  assert.equal(result.code, 1);
  assert.equal(
    result.stderr,
    "AWS_COORDINATOR_ENTRYPOINT_FAILED\n",
  );
  assert.equal(result.stdout, "");
});

test("relay entrypoint validates exact runtime input, installs TLS secrets, and runs canonical argv", async () => {
  const calls = [];
  let removed = [];
  await relayEntrypoint({
    client: {
      async send(command) {
        calls.push(["secret", command.input]);
        return {
          SecretString: relayTlsSecret(),
        };
      },
    },
    env: {
      AWS_RUNTIME_INPUT: relayRuntimeInput(),
    },
    installFile: async (input) => {
      calls.push(["install", input]);
    },
    prepareStateRoot: async (path) => {
      calls.push(["prepare-state", path]);
    },
    removeFile: async (path) => {
      removed.push(path);
    },
    run: async (argv, dependencies) => {
      calls.push(["run", argv]);
      assert.deepEqual(
        await dependencies.provenanceProvider.assertRepository({
          repositorySha: RELAY_REPOSITORY_SHA,
        }),
        {
          imageDigest: `sha256:${"1".repeat(64)}`,
          operatorPublicKey: RELAY_OPERATOR_PUBLIC_KEY,
          repositorySha: RELAY_REPOSITORY_SHA,
          sourceTreeSha256: "2".repeat(64),
        },
      );
      assert.deepEqual(
        await dependencies.provenanceProvider.verify({
          operatorKeyId: "clockchain-demo-2026",
          repositorySha: RELAY_REPOSITORY_SHA,
        }),
        {
          imageDigest: `sha256:${"1".repeat(64)}`,
          operatorPublicKey: RELAY_OPERATOR_PUBLIC_KEY,
          repositorySha: RELAY_REPOSITORY_SHA,
          sourceTreeSha256: "2".repeat(64),
        },
      );
      return {
        address: {
          host: "0.0.0.0",
          port: 8443,
        },
      };
    },
    stdout: {
      write(value) {
        calls.push(["stdout", value]);
      },
    },
  });
  assert.deepEqual(calls, [
    [
      "secret",
      {
        SecretId:
          "arn:aws:secretsmanager:us-west-2:123456789012:secret:relay-tls",
      },
    ],
    ["prepare-state", RELAY_STATE_PATH],
    [
      "install",
      {
        path: RELAY_CERTIFICATE_PATH,
        value: RELAY_TLS_CERTIFICATE_PEM,
      },
    ],
    [
      "install",
      {
        path: RELAY_PRIVATE_KEY_PATH,
        value: RELAY_TLS_PRIVATE_KEY_PEM,
      },
    ],
    ["run", relayArgv()],
    [
      "stdout",
      `{"host":"0.0.0.0","paymentMoved":false,"pid":${process.pid},"port":8443,"schema":"clockchain.bilateral-relay-ready/v1"}\n`,
    ],
  ]);
  assert.deepEqual(removed.sort(), [
    RELAY_CERTIFICATE_PATH,
    RELAY_PRIVATE_KEY_PATH,
  ].sort());
});

test("relay state root preparation creates the private release hierarchy in order", async () => {
  const prepared = [];
  await prepareRelayStateRoot(
    RELAY_STATE_PATH,
    async ({ path }) => {
      prepared.push(path);
    },
  );
  assert.deepEqual(prepared, [
    "/var/lib/clockchain/relay/releases",
    `/var/lib/clockchain/relay/releases/${RELAY_RELEASE_ID}`,
    RELAY_STATE_PATH,
  ]);
});

test("relay entrypoint rejects malformed runtime input before secret reads", async () => {
  const valid = JSON.parse(relayRuntimeInput());
  const reorderedRelay = {
    paymentMoved: false,
    relay: {
      certificatePath: RELAY_CERTIFICATE_PATH,
      argv: relayArgv(),
      privateKeyPath: RELAY_PRIVATE_KEY_PATH,
      provenance: valid.relay.provenance,
      tlsFingerprint: RELAY_TLS_FINGERPRINT,
      tlsSecretArn: valid.relay.tlsSecretArn,
    },
    schema: "clockchain.aws-runtime-input/v1",
  };
  const reorderedProvenance = {
    ...valid,
    relay: {
      ...valid.relay,
      provenance: {
        operatorKeyId: "clockchain-demo-2026",
        imageDigest: `sha256:${"1".repeat(64)}`,
        operatorPublicKey: RELAY_OPERATOR_PUBLIC_KEY,
        repositorySha: RELAY_REPOSITORY_SHA,
        sourceTreeSha256: "2".repeat(64),
      },
    },
  };
  const cases = [
    JSON.stringify({
      relay: valid.relay,
      paymentMoved: false,
      schema:
        "clockchain.aws-runtime-input/v1",
    }),
    JSON.stringify({
      paymentMoved: true,
      relay: valid.relay,
      schema:
        "clockchain.aws-runtime-input/v1",
    }),
    JSON.stringify({
      paymentMoved: false,
      relay: {
        ...valid.relay,
        extra: true,
      },
      schema:
        "clockchain.aws-runtime-input/v1",
    }),
    JSON.stringify(reorderedRelay),
    JSON.stringify(reorderedProvenance),
    relayRuntimeInput({
      argv: relayArgv({
        "--repository-sha": "0".repeat(40),
      }),
    }),
    relayRuntimeInput({
      argv: [
        "--host",
        "0.0.0.0",
        "--advertised-host",
        "relay.clockchain.network",
        ...relayArgv().slice(4),
      ],
    }),
    relayRuntimeInput({
      certificatePath: "/tmp/relay.crt",
    }),
    relayRuntimeInput({
      privateKeyPath: "/tmp/relay.key",
    }),
    relayRuntimeInput({
      tlsFingerprint: "B".repeat(64),
    }),
    relayRuntimeInput({
      tlsSecretArn: "not-an-arn",
    }),
    relayRuntimeInput({
      provenance: {
        ...valid.relay.provenance,
        operatorPublicKey: "not-base64",
      },
    }),
    relayRuntimeInput({
      provenance: {
        ...valid.relay.provenance,
        repositorySha: "0".repeat(40),
      },
    }),
  ];
  for (const runtimeInput of cases) {
    let secretReads = 0;
    let installs = 0;
    await assert.rejects(
      relayEntrypoint({
        client: {
          async send() {
            secretReads += 1;
            return { SecretString: relayTlsSecret() };
          },
        },
        env: {
          AWS_RUNTIME_INPUT: runtimeInput,
        },
        installFile: async () => {
          installs += 1;
        },
        run: async () => {
          assert.fail("run must not start");
        },
      }),
      /AWS relay entrypoint failed safely|AWS runtime input failed safely/,
    );
    assert.equal(secretReads, 0, runtimeInput);
    assert.equal(installs, 0, runtimeInput);
  }
});

test("relay entrypoint rejects invalid TLS secrets before file install or run without leaking secret material", async () => {
  const cases = [
    {
      input: relayRuntimeInput({
        tlsFingerprint: "0".repeat(64),
      }),
      secret: relayTlsSecret(),
    },
    {
      secret: relayTlsSecret({
        certificatePem: `${RELAY_TLS_CERTIFICATE_PEM}\nextra`,
      }),
    },
    {
      secret: relayTlsSecret({
        certificatePem: "not-a-certificate",
      }),
    },
    {
      secret: relayTlsSecret({
        privateKeyPem: "not-a-private-key",
      }),
    },
    {
      secret: relayTlsSecret({
        privateKeyPem: ed25519PrivateKeyPem(),
      }),
    },
    {
      secret: relayTlsSecret({
        certificatePem: RELAY_TLS_CERTIFICATE_PEM,
        extra: "unknown",
      }),
    },
    {
      secret: JSON.stringify({
        privateKeyPem: RELAY_TLS_PRIVATE_KEY_PEM,
        certificatePem: RELAY_TLS_CERTIFICATE_PEM,
      }),
    },
    {
      secret: JSON.stringify({
        certificatePem: RELAY_TLS_CERTIFICATE_PEM,
        privateKeyPem: "",
      }),
    },
  ];
  for (const { input, secret } of cases) {
    const calls = [];
    await assert.rejects(
      relayEntrypoint({
        client: {
          async send(command) {
            calls.push(["secret", command.input.SecretId]);
            return { SecretString: secret };
          },
        },
        env: {
          AWS_RUNTIME_INPUT:
            input ?? relayRuntimeInput(),
        },
        installFile: async () => {
          calls.push(["install"]);
        },
        run: async () => {
          calls.push(["run"]);
        },
      }),
      (error) => {
        assert.match(
          error.message,
          /AWS relay entrypoint failed safely|AWS runtime input failed safely/,
        );
        assert.doesNotMatch(
          String(error),
          /PRIVATE KEY|private-key-canary|not-a-certificate|BEGIN CERTIFICATE/,
        );
        return true;
      },
    );
    assert.deepEqual(calls, [
      [
        "secret",
        "arn:aws:secretsmanager:us-west-2:123456789012:secret:relay-tls",
      ],
    ]);
  }
});

test("relay entrypoint removes partial TLS material when private-key installation fails", async () => {
  const removed = [];
  let installs = 0;
  await assert.rejects(
    relayEntrypoint({
      client: {
        async send() {
          return { SecretString: relayTlsSecret() };
        },
      },
      env: {
        AWS_RUNTIME_INPUT: relayRuntimeInput(),
      },
      installFile: async () => {
        installs += 1;
        if (installs === 2) {
          throw new Error("install canary");
        }
      },
      prepareStateRoot: async () => {},
      removeFile: async (path) => {
        removed.push(path);
      },
      run: async () => {
        assert.fail("run must not start");
      },
    }),
    /AWS relay entrypoint failed safely/,
  );
  assert.deepEqual(removed.sort(), [
    RELAY_CERTIFICATE_PATH,
    RELAY_PRIVATE_KEY_PATH,
  ].sort());
});

test("operator worker entrypoint composes exact AWS clients and loop dependencies", async () => {
  const sqs = { send: async () => ({}) };
  const dynamodb = {
    name: "dynamodb",
    send: async () => ({}),
  };
  const s3 = { send: async () => ({}) };
  const documentClient = { send: async () => ({}) };
  const buildTransitions = async () => ({});
  const signal = AbortSignal.abort();
  const calls = [];
  await operatorWorkerEntrypoint({
    buildTransitions,
    createClients: async () => {
      calls.push(["createClients"]);
      return {
        dynamodb,
        ecs: { send: async () => ({}) },
        s3,
        secrets: { send: async () => ({}) },
        sqs,
      };
    },
    createDocumentClient: (client) => {
      calls.push([
        "createDocumentClient",
        client,
      ]);
      return documentClient;
    },
    env: {
      AWS_RUNTIME_INPUT: operatorRuntimeInput(),
    },
    run: async (config, dependencies) => {
      assert.deepEqual(Object.keys(config), [
        "actionQueueUrl",
        "actionTableName",
        "paymentMoved",
        "publicMonitorBucketName",
        "publicMonitorControlKey",
        "releaseId",
        "repositorySha",
        "schema",
        "sessionId",
      ]);
      calls.push([
        "run",
        config,
        dependencies,
      ]);
      return {
        paymentMoved: false,
        status: "IDLE",
      };
    },
    signal,
  });
  assert.deepEqual(calls, [
    ["createClients"],
    ["createDocumentClient", dynamodb],
    [
      "run",
      {
        actionQueueUrl:
          "https://sqs.us-west-2.amazonaws.com/123456789012/clockchain-actions",
        actionTableName:
          "ClockchainHandshakeControl",
        paymentMoved: false,
        publicMonitorBucketName:
          "clockchain-public-monitor",
        publicMonitorControlKey:
          "control.json",
        releaseId: OPERATOR_RELEASE_ID,
        repositorySha:
          "abcdef0123456789abcdef0123456789abcdef01",
        schema:
          "clockchain.aws-operator-runtime/v1",
        sessionId: OPERATOR_SESSION_ID,
      },
      {
        buildTransitions,
        documentClient,
        s3,
        signal,
        sqs,
      },
    ],
  ]);
});

test("operator worker entrypoint provides default transition composition when not injected", async () => {
  const calls = [];
  await operatorWorkerEntrypoint({
    createClients: async () => ({
      dynamodb: { send: async () => ({}) },
      ecs: { send: async () => ({}) },
      s3: { send: async () => ({}) },
      sqs: { send: async () => ({}) },
    }),
    createDocumentClient: (client) => ({
      client,
      send: async () => ({}),
    }),
    env: {
      AWS_RUNTIME_INPUT:
        operatorProductionRuntimeInput(),
    },
    run: async (config, dependencies) => {
      assert.deepEqual(Object.keys(config), [
        "actionQueueUrl",
        "actionTableName",
        "paymentMoved",
        "publicMonitorBucketName",
        "publicMonitorControlKey",
        "releaseId",
        "repositorySha",
        "schema",
        "sessionId",
      ]);
      calls.push([
        config.releaseId,
        typeof dependencies.buildTransitions,
      ]);
      const transitions =
        await dependencies.buildTransitions(config);
      for (const name of [
        "abortSession",
        "approveBootstrapClaim",
        "createSession",
        "launchCoordinator",
        "launchFundingTask",
        "launchVerifierTask",
        "readExpectedClaimFingerprint",
      ]) {
        assert.equal(typeof transitions[name], "function");
      }
      return {
        paymentMoved: false,
        status: "IDLE",
      };
    },
  });
  assert.deepEqual(calls, [
    [OPERATOR_RELEASE_ID, "function"],
  ]);
});

test("operator worker default transitions launch approval and coordinator with public staging overrides", async () => {
  const launched = [];
  await operatorWorkerEntrypoint({
    createClients: async () => ({
      dynamodb: { send: async () => ({}) },
      ecs: {
        async send(command) {
          if (
            Object.hasOwn(
              command.input,
              "taskDefinition",
            )
          ) {
            const runtimeInput = JSON.parse(
              command.input.overrides.containerOverrides[0]
                .environment[0].value,
            );
            launched.push({
              container:
                command.input.overrides.containerOverrides[0]
                  .name,
              runtimeInput,
            });
            return {
              failures: [],
              tasks: [
                {
                  taskArn:
                    "arn:aws:ecs:us-west-2:123456789012:task/clockchain/11111111111111111111111111111111",
                },
              ],
            };
          }
          if (
            Object.hasOwn(command.input, "tasks")
          ) {
            return {
              failures: [],
              tasks: [
                {
                  containers: [
                    {
                      exitCode: 0,
                      name: "bootstrap-approval",
                    },
                  ],
                  lastStatus: "STOPPED",
                  taskArn:
                    "arn:aws:ecs:us-west-2:123456789012:task/clockchain/11111111111111111111111111111111",
                },
              ],
            };
          }
          assert.fail(
            `unexpected ECS command ${command.constructor.name}`,
          );
        },
      },
      s3: { send: async () => ({}) },
      sqs: { send: async () => ({}) },
    }),
    createDocumentClient: (client) => ({
      client,
      send: async () => ({}),
    }),
    env: {
      AWS_RUNTIME_INPUT:
        operatorProductionRuntimeInput(),
    },
    run: async (config, dependencies) => {
      const transitions =
        await dependencies.buildTransitions(config);
      const common = {
        expectedRevision: 7,
        paymentMoved: false,
        releaseId: OPERATOR_RELEASE_ID,
        repositorySha:
          "abcdef0123456789abcdef0123456789abcdef01",
        sessionId: OPERATOR_SESSION_ID,
      };
      await transitions.approveBootstrapClaim({
        ...common,
        claimFingerprint: "b".repeat(64),
        role: "payee",
      });
      await transitions.launchCoordinator({
        ...common,
        actionId:
          "55555555-5555-4555-8555-555555555555",
      });
      return {
        paymentMoved: false,
        status: "IDLE",
      };
    },
  });

  assert.deepEqual(
    launched.map((item) => item.container),
    ["bootstrap-approval", "coordinator"],
  );
  assert.equal(
    launched[0].runtimeInput.bootstrapApproval
      .approvedPayerPublicPath,
    OPERATOR_APPROVED_PAYER_PUBLIC_PATH,
  );
  assert.deepEqual(
    launched[1].runtimeInput.coordinator
      .publicStaging,
    operatorPublicStaging(),
  );
  assert.doesNotMatch(
    JSON.stringify(launched),
    /TUNNEL_HOST_KEY_SECRET_ARN|privateKey/i,
  );
});

test("operator worker entrypoint accepts the default operator loop with an aborted signal", async () => {
  await operatorWorkerEntrypoint({
    buildTransitions: async () => ({}),
    createClients: async () => ({
      dynamodb: { send: async () => ({}) },
      s3: { send: async () => ({}) },
      sqs: { send: async () => ({}) },
    }),
    createDocumentClient: (client) => ({
      client,
      send: async () => ({}),
    }),
    env: {
      AWS_RUNTIME_INPUT: operatorRuntimeInput(),
    },
    signal: AbortSignal.abort(),
  });
});

test("operator worker entrypoint accepts SQS queue names at the standard and FIFO length boundaries", async () => {
  const acceptedQueueNames = [
    "a".repeat(80),
    `${"a".repeat(75)}.fifo`,
  ];
  for (const queueName of acceptedQueueNames) {
    const calls = [];
    await operatorWorkerEntrypoint({
      buildTransitions: async () => ({}),
      createClients: async () => ({
        dynamodb: { send: async () => ({}) },
        s3: { send: async () => ({}) },
        sqs: { send: async () => ({}) },
      }),
      createDocumentClient: (client) => ({
        client,
        send: async () => ({}),
      }),
      env: {
        AWS_RUNTIME_INPUT: operatorRuntimeInput({
          actionQueueUrl:
            `https://sqs.us-west-2.amazonaws.com/123456789012/${queueName}`,
        }),
      },
      run: async (config) => {
        calls.push(config.actionQueueUrl);
        return {
          paymentMoved: false,
          status: "IDLE",
        };
      },
    });
    assert.deepEqual(calls, [
      `https://sqs.us-west-2.amazonaws.com/123456789012/${queueName}`,
    ]);
  }
});

test("operator worker entrypoint rejects malformed operator runtime input before client creation", async () => {
  const cases = [
    operatorRuntimeInput({
      releaseId: "release-0000000000000000",
    }),
    operatorRuntimeInput({
      paymentMoved: true,
    }),
    operatorRuntimeInput({
      actionQueueUrl:
        "http://sqs.us-west-2.amazonaws.com/123456789012/clockchain-actions",
    }),
    operatorRuntimeInput({
      actionQueueUrl:
        "https://sqs.us-west-2.amazonaws.com/",
    }),
    operatorRuntimeInput({
      actionQueueUrl:
        "https://sqs.us-west-2.amazonaws.com/123456789012",
    }),
    operatorRuntimeInput({
      actionQueueUrl:
        "https://sqs.us-west-2.amazonaws.com/123456789012/",
    }),
    operatorRuntimeInput({
      actionQueueUrl:
        "https://sqs.us-west-2.amazonaws.com/12345678901/clockchain-actions",
    }),
    operatorRuntimeInput({
      actionQueueUrl:
        "https://sqs.us-west-2.amazonaws.com/123456789012/clockchain-actions/extra",
    }),
    operatorRuntimeInput({
      actionQueueUrl:
        "https://sqs.us-west-2.amazonaws.com/123456789012//clockchain-actions",
    }),
    operatorRuntimeInput({
      actionQueueUrl:
        "https://sqs.us-west-2.amazonaws.com/123456789012/clockchain actions",
    }),
    operatorRuntimeInput({
      actionQueueUrl:
        `https://sqs.us-west-2.amazonaws.com/123456789012/${"a".repeat(81)}`,
    }),
    operatorRuntimeInput({
      actionQueueUrl:
        `https://sqs.us-west-2.amazonaws.com/123456789012/${"a".repeat(76)}.fifo`,
    }),
    operatorRuntimeInput({
      actionTableName: "no spaces",
    }),
    operatorRuntimeInput({
      repositorySha: "a".repeat(39),
    }),
    JSON.stringify({
      operator: JSON.parse(
        operatorRuntimeInput(),
      ).operator,
      paymentMoved: false,
      schema:
        "clockchain.aws-runtime-input/v1",
      z: "unknown",
    }),
    JSON.stringify({
      paymentMoved: false,
      operator: JSON.parse(
        operatorRuntimeInput(),
      ).operator,
      schema:
        "clockchain.aws-runtime-input/v1",
    }),
  ];
  for (const runtimeInput of cases) {
    let clientCreations = 0;
    await assert.rejects(
      operatorWorkerEntrypoint({
        buildTransitions: async () => ({}),
        createClients: async () => {
          clientCreations += 1;
          return {};
        },
        env: {
          AWS_RUNTIME_INPUT: runtimeInput,
        },
        run: async () => {
          assert.fail("run must not start");
        },
      }),
      /AWS operator worker entrypoint failed safely|AWS runtime input failed safely/,
    );
    assert.equal(clientCreations, 0);
  }
});

test("operator worker entrypoint rejects invalid dependency composition safely", async () => {
  const cases = [
    {
      createClients: null,
    },
    {
      createClients: async () => ({
        dynamodb: {},
        sqs: { send: async () => ({}) },
      }),
    },
    {
      createClients: async () => ({
        dynamodb: { send: async () => ({}) },
      }),
    },
    {
      createDocumentClient: null,
    },
    {
      buildTransitions: null,
    },
    {
      run: null,
    },
  ];
  for (const overrides of cases) {
    await assert.rejects(
      operatorWorkerEntrypoint({
        buildTransitions: async () => ({}),
        createClients: async () => ({
          dynamodb: { send: async () => ({}) },
          sqs: { send: async () => ({}) },
        }),
        createDocumentClient: () => ({
          send: async () => ({}),
        }),
        env: {
          AWS_RUNTIME_INPUT: operatorRuntimeInput(),
        },
        run: async () => {},
        ...overrides,
      }),
      /AWS operator worker entrypoint failed safely|AWS runtime input failed safely/,
    );
  }
});

test("operator worker production CLI fails closed without live runtime dependencies", async () => {
  const result = await execFileAsync(
    process.execPath,
    ["infra/aws/runtime/operator-worker-entrypoint.mjs"],
    {
      env: {
        ...process.env,
        AWS_RUNTIME_INPUT: operatorRuntimeInput(),
      },
      reject: false,
    },
  ).catch((error) => error);
  assert.equal(result.code, 1);
  assert.equal(
    result.stderr,
    "AWS_OPERATOR_WORKER_ENTRYPOINT_FAILED\n",
  );
  assert.equal(result.stdout, "");
});

test("funding entrypoint materializes keystore metadata and RPC secrets into private scratch paths", async () => {
  const secretReads = [];
  const runCalls = [];
  const keystore = fundingKeystore();
  const client = {
    async send(command) {
      secretReads.push(command.input);
      if (
        command.input.SecretId.endsWith(
          "treasury-keystore",
        )
      ) {
        return { SecretString: keystore };
      }
      if (command.input.SecretId.endsWith("rpc-url")) {
        return {
          SecretString:
            "https://ethereum-rpc.publicnode.com/path",
        };
      }
      assert.fail(
        `unexpected eager secret read: ${command.input.SecretId}`,
      );
    },
  };
  for (let index = 0; index < 2; index += 1) {
    await fundingEntrypoint({
      client,
      env: {
        AWS_RUNTIME_INPUT: fundingRuntimeInput(),
      },
      run: async (input, dependencies) => {
        runCalls.push(input);
        assert.equal(
          typeof dependencies.readSecret,
          "function",
        );
        const keystoreBytes = await readFile(
          input.keystorePath,
        );
        const metadata = JSON.parse(
          await readFile(
            input.keystorePath.replace(
              /\.json$/,
              ".public.json",
            ),
            "utf8",
          ),
        );
        assert.equal(
          (await lstat(dirname(input.keystorePath)))
            .mode & 0o777,
          0o700,
        );
        assert.equal(
          (await lstat(input.keystorePath)).mode &
            0o777,
          0o600,
        );
        assert.equal(
          (await lstat(input.rpcUrlFile)).mode &
            0o777,
          0o600,
        );
        assert.equal(
          (
            await lstat(
              input.keystorePath.replace(
                /\.json$/,
                ".public.json",
              ),
            )
          ).mode & 0o777,
          0o600,
        );
        assert.deepEqual(metadata, {
          schemaVersion: 1,
          chainId: 11155111,
          fundingAddress: TREASURY_ADDRESS,
          keystoreSha256: createHash("sha256")
            .update(keystoreBytes)
            .digest("hex"),
          createdAt: "2026-07-31T00:00:00.000Z",
        });
        assert.equal(
          await readFile(input.rpcUrlFile, "utf8"),
          "https://ethereum-rpc.publicnode.com/path\n",
        );
        return {
          paymentMoved: false,
          status: "FUNDED",
        };
      },
    });
  }

  assert.deepEqual(secretReads, [
    {
      SecretId:
        "arn:aws:secretsmanager:us-west-2:123456789012:secret:treasury-keystore",
    },
    {
      SecretId:
        "arn:aws:secretsmanager:us-west-2:123456789012:secret:rpc-url",
    },
    {
      SecretId:
        "arn:aws:secretsmanager:us-west-2:123456789012:secret:treasury-keystore",
    },
    {
      SecretId:
        "arn:aws:secretsmanager:us-west-2:123456789012:secret:rpc-url",
    },
  ]);
  assert.equal(runCalls.length, 2);
  assert.notEqual(
    dirname(runCalls[0].keystorePath),
    dirname(runCalls[1].keystorePath),
  );
  for (const runCall of runCalls) {
    assert.deepEqual(runCall, {
      actionAtMs: 2_000_000_000_000,
      actionId:
        "22222222-2222-4222-8222-222222222222",
      expectedTreasuryAddress: TREASURY_ADDRESS,
      fundingRecordPath: "/operator/funding-record.json",
      journalDirectory: "/operator/funding-journal",
      keystorePath: runCall.keystorePath,
      releaseId: OPERATOR_RELEASE_ID,
      repositorySha:
        "abcdef0123456789abcdef0123456789abcdef01",
      resultPath:
        `/var/lib/clockchain/funding-result/releases/${OPERATOR_RELEASE_ID}/actions/22222222-2222-4222-8222-222222222222/funding-result.json`,
      rpcUrlFile: runCall.rpcUrlFile,
      secretId:
        "arn:aws:secretsmanager:us-west-2:123456789012:secret:treasury-password",
      sessionId: OPERATOR_SESSION_ID,
    });
    assert.notEqual(
      runCall.keystorePath,
      "/secrets/treasury-keystore.json",
    );
    assert.notEqual(
      runCall.rpcUrlFile,
      "/secrets/sepolia-rpc",
    );
    await assert.rejects(
      lstat(runCall.keystorePath),
      { code: "ENOENT" },
    );
    await assert.rejects(
      lstat(
        runCall.keystorePath.replace(
          /\.json$/,
          ".public.json",
        ),
      ),
      { code: "ENOENT" },
    );
    await assert.rejects(
      lstat(runCall.rpcUrlFile),
      { code: "ENOENT" },
    );
  }
});

test("funding entrypoint rejects caller-supplied secret paths before reading secrets", async () => {
  const cases = [
    { keystorePath: "/secrets/treasury-keystore.json" },
    { rpcUrlFile: "/secrets/sepolia-rpc" },
    {
      secretId:
        "arn:aws:secretsmanager:us-west-2:123456789012:secret:treasury-password",
    },
    {
      keystoreSecretArn: "not-an-arn",
    },
    {
      passwordSecretArn: "not-an-arn",
    },
    {
      rpcSecretArn:
        "arn:aws:secretsmanager:us-west-2:123456789012:secret:rpc-url",
      z: "unknown",
    },
  ];
  for (const overrides of cases) {
    let secretReads = 0;
    await assert.rejects(
      fundingEntrypoint({
        client: {
          async send() {
            secretReads += 1;
            return { SecretString: "secret" };
          },
        },
        env: {
          AWS_RUNTIME_INPUT:
            fundingRuntimeInput(overrides),
        },
        run: async () => {
          assert.fail("run must not start");
        },
      }),
      /AWS funding entrypoint failed safely|AWS runtime input failed safely/,
    );
    assert.equal(secretReads, 0);
  }
});

test("funding entrypoint rejects invalid keystore and RPC secrets before scratch or run", async () => {
  const cases = [
    {
      name: "address mismatch",
      secrets: {
        "treasury-keystore": fundingKeystore(
          "0x257a377e4181f3f87c7f6efed5ddc340ccc00dce",
        ),
        "rpc-url":
          "https://ethereum-rpc.publicnode.com/path",
      },
    },
    {
      name: "noncanonical keystore",
      secrets: {
        "treasury-keystore": `${fundingKeystore()}\n`,
        "rpc-url":
          "https://ethereum-rpc.publicnode.com/path",
      },
    },
    {
      name: "unsafe rpc",
      secrets: {
        "treasury-keystore": fundingKeystore(),
        "rpc-url":
          "http://ethereum-rpc.publicnode.com/path?api_key=provider",
      },
    },
    {
      name: "rpc with query",
      secrets: {
        "treasury-keystore": fundingKeystore(),
        "rpc-url":
          "https://ethereum-rpc.publicnode.com/path?api_key=provider",
      },
    },
    {
      name: "extra keystore key",
      secrets: {
        "treasury-keystore": mutateFundingKeystore(
          (value) => {
            value.extra = true;
          },
        ),
        "rpc-url":
          "https://ethereum-rpc.publicnode.com/path",
      },
    },
    {
      name: "wrong cipher",
      secrets: {
        "treasury-keystore": mutateFundingKeystore(
          (value) => {
            value.crypto.cipher = "aes-256-ctr";
          },
        ),
        "rpc-url":
          "https://ethereum-rpc.publicnode.com/path",
      },
    },
    {
      name: "wrong kdf",
      secrets: {
        "treasury-keystore": mutateFundingKeystore(
          (value) => {
            value.crypto.kdf = "pbkdf2";
          },
        ),
        "rpc-url":
          "https://ethereum-rpc.publicnode.com/path",
      },
    },
    {
      name: "non power-of-two scrypt n",
      secrets: {
        "treasury-keystore": mutateFundingKeystore(
          (value) => {
            value.crypto.kdfparams.n = 3;
          },
        ),
        "rpc-url":
          "https://ethereum-rpc.publicnode.com/path",
      },
    },
    {
      name: "zero address",
      input: fundingRuntimeInput({
        expectedTreasuryAddress:
          "0x0000000000000000000000000000000000000000",
      }),
      secrets: {
        "treasury-keystore": fundingKeystore(
          "0x0000000000000000000000000000000000000000",
        ),
        "rpc-url":
          "https://ethereum-rpc.publicnode.com/path",
      },
    },
  ];
  for (const { input, name, secrets } of cases) {
    const calls = [];
    await assert.rejects(
      fundingEntrypoint({
        client: {
          async send(command) {
            calls.push(["secret", command.input]);
            const key = command.input.SecretId.endsWith(
              "treasury-keystore",
            )
              ? "treasury-keystore"
              : "rpc-url";
            return { SecretString: secrets[key] };
          },
        },
        createTempDir: async () => {
          calls.push(["createTempDir"]);
          throw new Error("scratch must not start");
        },
        env: {
          AWS_RUNTIME_INPUT:
            input ?? fundingRuntimeInput(),
        },
        run: async () => {
          calls.push(["run"]);
          assert.fail("run must not start");
        },
      }),
      /AWS funding entrypoint failed safely|AWS runtime input failed safely/,
      name,
    );
    assert.equal(
      calls.some(([call]) => call === "createTempDir"),
      false,
      name,
    );
    assert.equal(
      calls.some(([call]) => call === "run"),
      false,
      name,
    );
  }
});

test("funding entrypoint fails closed when scratch cleanup fails after run", async () => {
  const root = await mkdtemp(
    join(tmpdir(), "clockchain-funding-entrypoint-"),
  );
  const scratch = join(root, "clockchain-funding-");
  const calls = [];
  try {
    await assert.rejects(
      fundingEntrypoint({
        client: {
          async send(command) {
            return {
              SecretString:
                command.input.SecretId.endsWith(
                  "treasury-keystore",
                )
                  ? fundingKeystore()
                  : "https://ethereum-rpc.publicnode.com/path",
            };
          },
        },
        createTempDir: async (prefix) => {
          const path = await mkdtemp(`${scratch}-`);
          calls.push(["createTempDir", prefix, path]);
          return path;
        },
        env: {
          AWS_RUNTIME_INPUT: fundingRuntimeInput(),
        },
        removeDir: async (path) => {
          calls.push(["removeDir", path]);
          throw new Error("cleanup canary");
        },
        removeFile: async (path) => {
          calls.push(["removeFile", path]);
          throw new Error("cleanup canary");
        },
        run: async () => {
          calls.push(["run"]);
          return {
            paymentMoved: false,
            status: "FUNDED",
          };
        },
      }),
      (error) => {
        assert.equal(
          error.message,
          "AWS funding entrypoint failed safely.",
        );
        assert.doesNotMatch(
          String(error),
          /cleanup canary|treasury|ethereum-rpc/,
        );
        return true;
      },
    );
  } finally {
    await rm(root, {
      force: true,
      recursive: true,
    });
  }
  const scratchDir = calls[0][2];
  assert.deepEqual(calls, [
    [
      "createTempDir",
      join(tmpdir(), "clockchain-funding-"),
      scratchDir,
    ],
    ["run"],
    [
      "removeFile",
      join(scratchDir, "treasury-keystore.json"),
    ],
    [
      "removeFile",
      join(
        scratchDir,
        "treasury-keystore.public.json",
      ),
    ],
    [
      "removeFile",
      join(scratchDir, "sepolia-rpc-url"),
    ],
    ["removeDir", scratchDir],
  ]);
});

test("verifier entrypoint resolves metadata and secrets before running the canonical verifier task", async () => {
  const calls = [];
  const results = [];
  for (let index = 0; index < 2; index += 1) {
    results.push(
      await verifierEntrypoint({
        client: {
          async send(command) {
            calls.push(["secret", command.input]);
            return {
              SecretString:
                command.input.SecretId.endsWith("rpc-url")
                  ? "https://ethereum-rpc.publicnode.com/path?api_key=provider"
                  : `clockchain-token-canary-${index}`,
            };
          },
        },
        env: {
          AWS_RUNTIME_INPUT:
            verifierRuntimeInput(),
          ECS_CONTAINER_METADATA_URI_V4:
            "http://169.254.170.2/v4/metadata/container",
        },
        fetch: async (url) => {
          calls.push(["fetch", url]);
          return {
            ok: true,
            async json() {
              return {
                TaskARN: VERIFIER_TASK_ARN,
              };
            },
          };
        },
        run: async (input) => {
          const tokenMode =
            (await lstat(
              input.clockchainTokenFile,
            )).mode & 0o777;
          const tokenDir =
            dirname(input.clockchainTokenFile);
          const tokenDirMode =
            (await lstat(tokenDir)).mode & 0o777;
          calls.push([
            "run",
            {
              ...input,
              clockchainTokenFileMode: tokenMode,
              clockchainTokenDir: tokenDir,
              clockchainTokenDirMode:
                tokenDirMode,
              clockchainTokenValue: await readFile(
                input.clockchainTokenFile,
                "utf8",
              ),
            },
          ]);
          return {
            paymentMoved: false,
            verifier: { status: "VERIFIED" },
          };
        },
      }),
    );
  }
  assert.deepEqual(results, [
    {
      paymentMoved: false,
      verifier: { status: "VERIFIED" },
    },
    {
      paymentMoved: false,
      verifier: { status: "VERIFIED" },
    },
  ]);
  assert.deepEqual(calls.slice(0, 3), [
    [
      "fetch",
      "http://169.254.170.2/v4/metadata/container/task",
    ],
    [
      "secret",
      {
        SecretId:
          "arn:aws:secretsmanager:us-west-2:123456789012:secret:clockchain-token",
      },
    ],
    [
      "secret",
      {
        SecretId:
          "arn:aws:secretsmanager:us-west-2:123456789012:secret:rpc-url",
      },
    ],
  ]);
  const runInputs = calls
    .filter(([name]) => name === "run")
    .map(([, input]) => input);
  assert.equal(runInputs.length, 2);
  assert.notEqual(
    runInputs[0].clockchainTokenFile,
    runInputs[1].clockchainTokenFile,
  );
  assert.notEqual(
    runInputs[0].clockchainTokenDir,
    runInputs[1].clockchainTokenDir,
  );
  for (const [index, runInput] of runInputs.entries()) {
    assert.deepEqual(runInput, {
      actionAtMs: 2_000_000_000_000,
      attemptId: VERIFIER_ATTEMPT_ID,
      attemptRoot: `/verdict/${VERIFIER_ATTEMPT_ID}`,
      clockchainTokenFile:
        runInput.clockchainTokenFile,
      clockchainTokenDir:
        runInput.clockchainTokenDir,
      clockchainTokenDirMode: 0o700,
      clockchainTokenFileMode: 0o600,
      clockchainTokenValue:
        `clockchain-token-canary-${index}`,
      descriptorPath: "/evidence/descriptor.json",
      evidenceDigest: "d".repeat(64),
      expectedRevision: 5,
      mandateDigest: "e".repeat(64),
      payerMandatePath:
        "/evidence/payer-mandate.json",
      payeeResultsPath: "/evidence/payee-results",
      payerResultsPath: "/evidence/payer-results",
      paymentRequestPath:
        "/evidence/payment-request.json",
      publicationPath:
        "/verdict/task-publication.json",
      repositorySha:
        "abcdef0123456789abcdef0123456789abcdef01",
      requestDigest: "f".repeat(64),
      rpcUrl:
        "https://ethereum-rpc.publicnode.com/path?api_key=provider",
      sessionDigest: "a".repeat(64),
      taskArn: VERIFIER_TASK_ARN,
    });
    await assert.rejects(
      lstat(runInput.clockchainTokenFile),
      { code: "ENOENT" },
    );
    await assert.rejects(
      lstat(runInput.clockchainTokenDir),
      { code: "ENOENT" },
    );
  }
});

test("verifier entrypoint rejects cleanup failure after run and attempts token and scratch removal", async () => {
  const root = await mkdtemp(
    join(tmpdir(), "clockchain-verifier-entrypoint-"),
  );
  const scratch = join(root, "clockchain-verifier-");
  const calls = [];
  try {
    await assert.rejects(
      verifierEntrypoint({
        client: {
          async send(command) {
            return {
              SecretString:
                command.input.SecretId.endsWith("rpc-url")
                  ? "https://ethereum-rpc.publicnode.com/path?api_key=provider"
                  : "clockchain-token-canary",
            };
          },
        },
        createTempDir: async (prefix) => {
          const path = await mkdtemp(
            `${scratch}-`,
          );
          calls.push([
            "createTempDir",
            prefix,
            path,
          ]);
          return path;
        },
        env: {
          AWS_RUNTIME_INPUT:
            verifierRuntimeInput(),
          ECS_CONTAINER_METADATA_URI_V4:
            "http://169.254.170.2/v4/metadata/container",
        },
        fetch: async () => ({
          ok: true,
          async json() {
            return {
              TaskARN: VERIFIER_TASK_ARN,
            };
          },
        }),
        removeDir: async (path) => {
          calls.push(["removeDir", path]);
          throw new Error("dir cleanup canary");
        },
        removeFile: async (path) => {
          calls.push(["removeFile", path]);
          throw new Error("file cleanup canary");
        },
        run: async () => {
          calls.push(["run"]);
          return {
            paymentMoved: false,
            verifier: { status: "VERIFIED" },
          };
        },
      }),
      (error) => {
        assert.equal(
          error.message,
          "AWS verifier entrypoint failed safely.",
        );
        assert.doesNotMatch(
          String(error),
          /cleanup canary|clockchain-token-canary|ethereum-rpc/,
        );
        return true;
      },
    );
  } finally {
    await rm(root, {
      force: true,
      recursive: true,
    });
  }
  const scratchDir = calls[0][2];
  assert.deepEqual(calls, [
    [
      "createTempDir",
      join(tmpdir(), "clockchain-verifier-"),
      scratchDir,
    ],
    ["run"],
    [
      "removeFile",
      join(scratchDir, "clockchain-token"),
    ],
    ["removeDir", scratchDir],
  ]);
});

test("verifier entrypoint rejects invalid token secrets before creating scratch space", async () => {
  const calls = [];
  await assert.rejects(
    verifierEntrypoint({
      client: {
        async send(command) {
          calls.push(command.input.SecretId);
          return {
            SecretString: "token\u0000value",
          };
        },
      },
      createTempDir: async () => {
        calls.push("createTempDir");
        throw new Error(
          "scratch should not be created",
        );
      },
      env: {
        AWS_RUNTIME_INPUT:
          verifierRuntimeInput(),
        ECS_CONTAINER_METADATA_URI_V4:
          "http://169.254.170.2/v4/metadata/container",
      },
      fetch: async () => ({
        ok: true,
        async json() {
          return {
            TaskARN: VERIFIER_TASK_ARN,
          };
        },
      }),
      run: async () => {
        calls.push("run");
      },
    }),
    /AWS verifier entrypoint failed safely|AWS runtime input failed safely/,
  );
  assert.deepEqual(calls, [
    "arn:aws:secretsmanager:us-west-2:123456789012:secret:clockchain-token",
  ]);
});

test("verifier entrypoint fails closed before secret reads for unsafe runtime input and metadata", async () => {
  const safeEnv = () => ({
    AWS_RUNTIME_INPUT: verifierRuntimeInput(),
    ECS_CONTAINER_METADATA_URI_V4:
      "http://169.254.170.2/v4/metadata/container",
  });
  const cases = [
    {
      env: {
        ...safeEnv(),
        AWS_RUNTIME_INPUT: JSON.stringify({
          paymentMoved: false,
          schema:
            "clockchain.aws-runtime-input/v1",
          verifier: JSON.parse(
            verifierRuntimeInput(),
          ).verifier,
          z: "unknown",
        }),
      },
    },
    {
      env: {
        ...safeEnv(),
        AWS_RUNTIME_INPUT:
          verifierRuntimeInput({
            taskArn: VERIFIER_TASK_ARN,
          }),
      },
    },
    {
      env: {
        ...safeEnv(),
        AWS_RUNTIME_INPUT:
          verifierRuntimeInput({
            clockchainTokenFile: "/tmp/token",
          }),
      },
    },
    {
      env: {
        ...safeEnv(),
        AWS_RUNTIME_INPUT:
          verifierRuntimeInput({
            rpcUrl:
              "https://sepolia.example.invalid",
          }),
      },
    },
    {
      env: {
        ...safeEnv(),
        AWS_RUNTIME_INPUT:
          verifierRuntimeInput({
            descriptorPath: "relative.json",
          }),
      },
    },
    {
      env: {
        ...safeEnv(),
        AWS_RUNTIME_INPUT:
          verifierRuntimeInput({
            repositorySha: "a".repeat(39),
          }),
      },
    },
    {
      env: {
        ...safeEnv(),
        ECS_CONTAINER_METADATA_URI_V4:
          "http://example.invalid/v4/metadata/container",
      },
    },
    {
      env: {
        ...safeEnv(),
        ECS_CONTAINER_METADATA_URI_V4:
          "http://169.254.170.2/v4/metadata/container?x=1",
      },
    },
    {
      env: safeEnv(),
      fetch: async () => ({
        ok: true,
        async json() {
          return {
            TaskARN:
              "arn:aws:ecs:us-west-2:123456789012:task/clockchain/not-a-task-id",
          };
        },
      }),
    },
  ];
  for (const options of cases) {
    let secretReads = 0;
    await assert.rejects(
      verifierEntrypoint({
        client: {
          async send() {
            secretReads += 1;
            return { SecretString: "secret" };
          },
        },
        env: options.env,
        fetch:
          options.fetch ??
          (async () => ({
            ok: true,
            async json() {
              return {
                TaskARN: VERIFIER_TASK_ARN,
              };
            },
          })),
        run: async () => {},
        tempDir: tmpdir(),
      }),
      /AWS verifier entrypoint failed safely|AWS runtime input failed safely/,
    );
    assert.equal(secretReads, 0);
  }
});

test("verifier entrypoint rejects invalid Clockchain token secrets before RPC lookup or run", async () => {
  const root = await mkdtemp(
    join(tmpdir(), "clockchain-verifier-entrypoint-"),
  );
  const calls = [];
  await assert.rejects(
    verifierEntrypoint({
      client: {
        async send(command) {
          calls.push(command.input.SecretId);
          return {
            SecretString: "token\u0000value",
          };
        },
      },
      env: {
        AWS_RUNTIME_INPUT:
          verifierRuntimeInput(),
        ECS_CONTAINER_METADATA_URI_V4:
          "http://169.254.170.2/v4/metadata/container",
      },
      fetch: async () => ({
        ok: true,
        async json() {
          return {
            TaskARN: VERIFIER_TASK_ARN,
          };
        },
      }),
      run: async () => {
        calls.push("run");
      },
      tempDir: root,
    }),
    (error) => {
      assert.match(
        error.message,
        /AWS verifier entrypoint failed safely|AWS runtime input failed safely/,
      );
      assert.doesNotMatch(
        String(error),
        /token\u0000value/,
      );
      return true;
    },
  );
  assert.deepEqual(calls, [
    "arn:aws:secretsmanager:us-west-2:123456789012:secret:clockchain-token",
  ]);
});

test("verifier entrypoint rejects noncanonical, reserved, or private RPC URLs before installing the token or running", async () => {
  const invalidRpcUrls = [
    "http://ethereum-rpc.publicnode.com",
    "https://user@ethereum-rpc.publicnode.com",
    "https://ethereum-rpc.publicnode.com/#fragment",
    "https://ETHEREUM-RPC.publicnode.com/path",
    "https://sepolia.invalid/",
    "https://sepolia.test/",
    "https://sepolia.example/",
    "https://sepolia.localhost/",
    "https://sepolia.local/",
    "https://localhost/",
    "https://127.0.0.1/",
    "https://10.0.0.1/",
    "https://172.16.0.1/",
    "https://192.168.0.1/",
    "https://169.254.1.1/",
    "https://0.0.0.0/",
    "https://[::1]/",
    "https://[fc00::1]/",
    "https://[fe80::1]/",
    "https://[::]/",
  ];
  for (const rpcUrl of invalidRpcUrls) {
    const root = await mkdtemp(
      join(
        tmpdir(),
        "clockchain-verifier-entrypoint-",
      ),
    );
    const calls = [];
    await assert.rejects(
      verifierEntrypoint({
        client: {
          async send(command) {
            calls.push(command.input.SecretId);
            return {
              SecretString:
                command.input.SecretId.endsWith("rpc-url")
                  ? rpcUrl
                  : "clockchain-token-canary",
            };
          },
        },
        env: {
          AWS_RUNTIME_INPUT:
            verifierRuntimeInput(),
          ECS_CONTAINER_METADATA_URI_V4:
            "http://169.254.170.2/v4/metadata/container",
        },
        fetch: async () => ({
          ok: true,
          async json() {
            return {
              TaskARN: VERIFIER_TASK_ARN,
            };
          },
        }),
        run: async () => {
          calls.push("run");
        },
        tempDir: root,
      }),
      (error) => {
        assert.match(
          error.message,
          /AWS verifier entrypoint failed safely|AWS runtime input failed safely/,
        );
        assert.doesNotMatch(
          String(error),
          /clockchain-token-canary|ethereum-rpc|sepolia|127\.0\.0\.1/,
        );
        return true;
      },
    );
    assert.deepEqual(calls, [
      "arn:aws:secretsmanager:us-west-2:123456789012:secret:clockchain-token",
      "arn:aws:secretsmanager:us-west-2:123456789012:secret:rpc-url",
    ]);
    await assert.rejects(
      lstat(join(root, "clockchain-token")),
      { code: "ENOENT" },
    );
  }
});

test("verifier entrypoint rejects a preexisting token path after validated secrets and before run", async () => {
  const root = await mkdtemp(
    join(tmpdir(), "clockchain-verifier-entrypoint-"),
  );
  const scratch = await mkdtemp(
    join(root, "clockchain-verifier-"),
  );
  await writeFile(
    join(scratch, "clockchain-token"),
    "preexisting",
    { mode: 0o600 },
  );
  const calls = [];
  await assert.rejects(
    verifierEntrypoint({
      client: {
        async send(command) {
          calls.push(command.input.SecretId);
          return {
            SecretString:
              command.input.SecretId.endsWith("rpc-url")
                ? "https://ethereum-rpc.publicnode.com/path?api_key=provider"
                : "clockchain-token-canary",
          };
        },
      },
      createTempDir: async () => scratch,
      env: {
        AWS_RUNTIME_INPUT:
          verifierRuntimeInput(),
        ECS_CONTAINER_METADATA_URI_V4:
          "http://169.254.170.2/v4/metadata/container",
      },
      fetch: async () => ({
        ok: true,
        async json() {
          return {
            TaskARN: VERIFIER_TASK_ARN,
          };
        },
      }),
      run: async () => {
        calls.push("run");
      },
    }),
    (error) => {
      assert.match(
        error.message,
        /AWS verifier entrypoint failed safely|AWS runtime input failed safely/,
      );
      assert.doesNotMatch(
        String(error),
        /clockchain-token-canary|ethereum-rpc/,
      );
      return true;
    },
  );
  assert.deepEqual(calls, [
    "arn:aws:secretsmanager:us-west-2:123456789012:secret:clockchain-token",
    "arn:aws:secretsmanager:us-west-2:123456789012:secret:rpc-url",
  ]);
  assert.equal(
    await readFile(
      join(scratch, "clockchain-token"),
      "utf8",
    ),
    "preexisting",
  );
});
