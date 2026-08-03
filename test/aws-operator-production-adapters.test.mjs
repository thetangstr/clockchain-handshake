import assert from "node:assert/strict";
import {
  createHash,
  generateKeyPairSync,
  X509Certificate,
} from "node:crypto";
import { execFileSync } from "node:child_process";
import {
  mkdtemp,
  readFile,
  rm,
  writeFile,
} from "node:fs/promises";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { test } from "node:test";

import {
  createAwsOperatorAbortAdapter,
} from "../infra/aws/runtime/operator-abort-adapter.mjs";
import {
  createAwsOperatorBootstrapFingerprintReader,
} from "../infra/aws/runtime/operator-bootstrap-fingerprint-reader.mjs";
import {
  createDynamoOperatorLaunchRecordStore,
} from "../infra/aws/runtime/operator-dynamodb-launch-record-store.mjs";
import {
  createBootstrapState,
  submitPayerBootstrapClaim,
} from "../src/bilateral/aws/bootstrap-state.mjs";
import {
  consumePayerClaim,
  createTunnelGrant,
  validateTunnelGrantRecord,
} from "../src/bilateral/aws/tunnel-grant.mjs";
import {
  createPayerBootstrapKey,
  payerBootstrapClaimFingerprint,
  sshEd25519Fingerprint,
} from "../src/bilateral/local-mcp/payer-bootstrap-envelope.mjs";

const RELEASE_ID = "release-bd7662a5eeb41614";
const REPOSITORY_SHA =
  "abcdef0123456789abcdef0123456789abcdef01";
const SESSION_ID =
  "11111111-1111-4111-8111-111111111111";
const ACTION_ID =
  "22222222-2222-4222-8222-222222222222";
const NOW = 2_000_000_000_000;

function certificatePem() {
  const root = mkdtempSync(
    join(tmpdir(), "aws-operator-abort-"),
  );
  try {
    const certificatePath = join(root, "payer.crt");
    const privateKeyPath = join(root, "payer.key");
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
      "/CN=payer.clockchain.network",
      "-addext",
      "subjectAltName=DNS:payer.clockchain.network",
    ], { stdio: "ignore" });
    return readFileSync(certificatePath, "utf8");
  } finally {
    rmSync(root, {
      force: true,
      recursive: true,
    });
  }
}

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

function activeGrant() {
  const bootstrap = createPayerBootstrapKey();
  const ssh = generateKeyPairSync("ed25519");
  const sshPublicKey = openSshPublicKey(ssh);
  const certificate = certificatePem();
  const claim = {
    claimNonce: ACTION_ID,
    mcpTlsCertificatePem: certificate,
    mcpTlsFingerprint: createHash("sha256")
      .update(new X509Certificate(certificate).raw)
      .digest("hex"),
    paymentMoved: false,
    releaseId: RELEASE_ID,
    repositorySha: REPOSITORY_SHA,
    role: "payer",
    schema: "clockchain.payer-bootstrap-claim/v1",
    sessionId: SESSION_ID,
    sshPublicKey,
    sshPublicKeyFingerprint:
      sshEd25519Fingerprint(sshPublicKey),
    x25519PublicKey: bootstrap.publicKey,
  };
  return createTunnelGrant({
    approved: consumePayerClaim({
      claim,
      consumeClaimFingerprint: () => true,
      expectedClaimFingerprint:
        payerBootstrapClaimFingerprint(claim),
      expectedReleaseId: RELEASE_ID,
      expectedRepositorySha: REPOSITORY_SHA,
      expectedSessionId: SESSION_ID,
      nowMs: NOW,
      publicMcpHostname:
        "payer.clockchain.network",
      publicMcpPort: 9443,
      tunnelPort: 443,
    }),
    expiresAtMs: String(NOW + 60_000),
  });
}

test("ABORT adapter tombstones an active tunnel grant before reporting ABORTED", async () => {
  const root = await mkdtemp(
    join(tmpdir(), "clockchain-operator-abort-"),
  );
  try {
    const path = join(root, "tunnel-grant.json");
    const abortMarkerPath = join(
      root,
      "abort-marker.json",
    );
    await writeFile(
      path,
      JSON.stringify(activeGrant()),
      { mode: 0o600 },
    );
    const adapter = createAwsOperatorAbortAdapter({
      abortMarkerPath,
      nowMs: () => NOW + 1,
      paymentMoved: false,
      releaseId: RELEASE_ID,
      repositorySha: REPOSITORY_SHA,
      sessionId: SESSION_ID,
      tunnelGrantPath: path,
    });

    assert.deepEqual(
      await adapter.abort({
        actionId: ACTION_ID,
        expectedRevision: 2,
        paymentMoved: false,
        releaseId: RELEASE_ID,
        repositorySha: REPOSITORY_SHA,
        sessionId: SESSION_ID,
      }),
      {
        paymentMoved: false,
        status: "ABORTED",
      },
    );
    const tombstone = validateTunnelGrantRecord(
      JSON.parse(await readFile(path, "utf8")),
    );
    assert.equal(tombstone.status, "TOMBSTONED");
    assert.equal(tombstone.terminalReason, "ABORT");
    assert.equal(tombstone.releaseId, RELEASE_ID);
    assert.equal(tombstone.sessionId, SESSION_ID);
    assert.equal(tombstone.paymentMoved, false);
    const marker = JSON.parse(
      await readFile(abortMarkerPath, "utf8"),
    );
    assert.deepEqual(marker, {
      actionId: ACTION_ID,
      expectedRevision: 2,
      paymentMoved: false,
      releaseId: RELEASE_ID,
      repositorySha: REPOSITORY_SHA,
      schema:
        "clockchain.aws-operator-abort-marker/v1",
      sessionId: SESSION_ID,
      status: "ABORTED",
      terminalAtMs: NOW + 1,
      tunnelGrantPath: path,
    });
  } finally {
    await rm(root, {
      force: true,
      recursive: true,
    });
  }
});

test("ABORT adapter expires an already-expired active tunnel grant while reporting ABORTED", async () => {
  const root = await mkdtemp(
    join(tmpdir(), "clockchain-operator-abort-"),
  );
  try {
    const path = join(root, "tunnel-grant.json");
    const abortMarkerPath = join(
      root,
      "abort-marker.json",
    );
    await writeFile(
      path,
      JSON.stringify(activeGrant()),
      { mode: 0o600 },
    );
    const terminalAtMs = NOW + 60_000;
    const adapter = createAwsOperatorAbortAdapter({
      abortMarkerPath,
      nowMs: () => terminalAtMs,
      paymentMoved: false,
      releaseId: RELEASE_ID,
      repositorySha: REPOSITORY_SHA,
      sessionId: SESSION_ID,
      tunnelGrantPath: path,
    });
    const input = {
      actionId: ACTION_ID,
      expectedRevision: 2,
      paymentMoved: false,
      releaseId: RELEASE_ID,
      repositorySha: REPOSITORY_SHA,
      sessionId: SESSION_ID,
    };

    assert.deepEqual(await adapter.abort(input), {
      paymentMoved: false,
      status: "ABORTED",
    });
    assert.deepEqual(await adapter.abort(input), {
      paymentMoved: false,
      status: "ABORTED",
    });

    const tombstone = validateTunnelGrantRecord(
      JSON.parse(await readFile(path, "utf8")),
    );
    assert.equal(tombstone.status, "TOMBSTONED");
    assert.equal(
      tombstone.terminalReason,
      "EXPIRED",
    );
    assert.equal(
      tombstone.terminalAtMs,
      String(terminalAtMs),
    );
    assert.equal(tombstone.releaseId, RELEASE_ID);
    assert.equal(tombstone.repositorySha, REPOSITORY_SHA);
    assert.equal(tombstone.sessionId, SESSION_ID);
    assert.equal(tombstone.paymentMoved, false);
    assert.deepEqual(
      JSON.parse(await readFile(abortMarkerPath, "utf8")),
      {
        actionId: ACTION_ID,
        expectedRevision: 2,
        paymentMoved: false,
        releaseId: RELEASE_ID,
        repositorySha: REPOSITORY_SHA,
        schema:
          "clockchain.aws-operator-abort-marker/v1",
        sessionId: SESSION_ID,
        status: "ABORTED",
        terminalAtMs,
        tunnelGrantPath: path,
      },
    );
  } finally {
    await rm(root, {
      force: true,
      recursive: true,
    });
  }
});

test("DynamoDB launch record store reads null and writes exact durable records under the action table", async () => {
  const calls = [];
  const store = createDynamoOperatorLaunchRecordStore({
    documentClient: {
      async send(command) {
        calls.push([
          command.constructor,
          command.input,
        ]);
        if (
          command.constructor.name ===
          "GetCommand"
        ) {
          return {};
        }
        return {};
      },
    },
    tableName: "ClockchainHandshakeControl",
  });
  assert.equal(
    await store.readRecord(
      "operator-launch#release#action#funding",
    ),
    null,
  );
  const record = {
    actionAtMs: NOW,
    attemptId: ACTION_ID,
    clientToken: {
      action: "fund",
      childTask: "funding",
      fingerprint: "a".repeat(16),
    },
    identity: {
      actionId: ACTION_ID,
      expectedRevision: 2,
      kind: "funding",
      releaseId: RELEASE_ID,
      repositorySha: REPOSITORY_SHA,
      sessionId: SESSION_ID,
    },
    intentDigest: "b".repeat(64),
    paymentMoved: false,
    runtimeInputDigest: "c".repeat(64),
    schema:
      "clockchain.aws-operator-launch-record/v1",
    status: "INTENT",
    taskArn: null,
  };
  await store.writeRecord(
    "operator-launch#release#action#funding",
    record,
  );
  assert.equal(calls[0][0].name, "GetCommand");
  assert.deepEqual(calls[0][1], {
    ConsistentRead: true,
    Key: {
      actionId:
        "operator-launch#release#action#funding",
    },
    TableName: "ClockchainHandshakeControl",
  });
  assert.equal(calls[1][0].name, "PutCommand");
  assert.deepEqual(calls[1][1], {
    ConditionExpression:
      "attribute_not_exists(actionId) OR (launchRecord.intentDigest = :intentDigest AND launchRecord.runtimeInputDigest = :runtimeInputDigest AND launchRecord.identity = :identity AND (attribute_not_exists(launchRecord.taskArn) OR launchRecord.taskArn = :nullTaskArn OR launchRecord.taskArn = :taskArn))",
    ExpressionAttributeValues: {
      ":identity": record.identity,
      ":intentDigest": record.intentDigest,
      ":nullTaskArn": null,
      ":runtimeInputDigest":
        record.runtimeInputDigest,
      ":taskArn": null,
    },
    Item: {
      actionId:
        "operator-launch#release#action#funding",
      launchRecord: record,
      paymentMoved: false,
      recordType:
        "OPERATOR_LAUNCH_RECORD",
    },
    TableName: "ClockchainHandshakeControl",
  });
});

test("bootstrap fingerprint reader performs projection-only reads and returns only the live expected fingerprint", async () => {
  const claim = activeGrant().claim;
  let state = createBootstrapState({
    paymentMoved: false,
    releaseId: RELEASE_ID,
    repositorySha: REPOSITORY_SHA,
    schema: "clockchain.aws-bootstrap-state/v1",
    sessionId: SESSION_ID,
  });
  state = submitPayerBootstrapClaim({
    authCapabilityDigest: "d".repeat(64),
    claim,
    expectedRevision: state.revision,
    expiresAtMs: String(NOW + 60_000),
    nowMs: NOW,
    state,
  });
  const calls = [];
  const reader =
    createAwsOperatorBootstrapFingerprintReader(
      {
        bootstrapStatePath:
          "/var/lib/clockchain/bootstrap/releases/release-bd7662a5eeb41614/bootstrap-state.json",
        nowMs: () => NOW + 1,
        paymentMoved: false,
        releaseId: RELEASE_ID,
        repositorySha: REPOSITORY_SHA,
        sessionId: SESSION_ID,
      },
      {
        readStableJson: async (path) => {
          calls.push(["read", path]);
          return state;
        },
      },
    );
  const fingerprint =
    await reader.readExpectedClaimFingerprint({
      releaseId: RELEASE_ID,
      sessionId: SESSION_ID,
      state: {
        status: "RUN_STARTED",
      },
    });
  assert.equal(
    fingerprint,
    payerBootstrapClaimFingerprint(claim),
  );
  assert.deepEqual(calls, [
    [
      "read",
      "/var/lib/clockchain/bootstrap/releases/release-bd7662a5eeb41614/bootstrap-state.json",
    ],
  ]);
  assert.equal(
    await reader.readExpectedClaimFingerprint({
      releaseId: RELEASE_ID,
      sessionId: SESSION_ID,
      state: {
        status: "REQUESTOR_APPROVED",
      },
    }),
    null,
  );
});

test("bootstrap fingerprint reader reports no expected fingerprint before the payer joins", async () => {
  const state = createBootstrapState({
    paymentMoved: false,
    releaseId: RELEASE_ID,
    repositorySha: REPOSITORY_SHA,
    schema: "clockchain.aws-bootstrap-state/v1",
    sessionId: SESSION_ID,
  });
  const reader =
    createAwsOperatorBootstrapFingerprintReader(
      {
        bootstrapStatePath:
          "/var/lib/clockchain/bootstrap/releases/release-bd7662a5eeb41614/bootstrap-state.json",
        nowMs: () => NOW,
        paymentMoved: false,
        releaseId: RELEASE_ID,
        repositorySha: REPOSITORY_SHA,
        sessionId: SESSION_ID,
      },
      {
        readStableJson: async () => state,
      },
    );

  assert.equal(
    await reader.readExpectedClaimFingerprint({
      releaseId: RELEASE_ID,
      sessionId: SESSION_ID,
      state: {
        status: "RUN_STARTED",
      },
    }),
    null,
  );
});
