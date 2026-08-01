import assert from "node:assert/strict";
import { test } from "node:test";

import {
  runAwsPublisherLoop,
  runAwsPublisherOnce,
} from "../infra/aws/runtime/publisher-runtime.mjs";

const INPUT = Object.freeze({
  bucketName: "clockchain-public-monitor",
  paymentMoved: false,
  publicBaseUrl:
    "https://monitor.example.com",
  publicationInputPath:
    "/var/lib/clockchain/public/publisher-input.json",
  schema:
    "clockchain.aws-publisher-runtime/v1",
  stagedPaths: Object.freeze({
    certificate:
      "/var/lib/clockchain/public/payer-mcp.crt",
    payerDiscovery:
      "/var/lib/clockchain/public/payer.json",
    publicationGate:
      "/var/lib/clockchain/public/publication-gate.json",
    requestorDiscovery:
      "/var/lib/clockchain/public/requestor.json",
  }),
});

function publicationInput() {
  return {
    certificateFingerprint: "a".repeat(64),
    completedAtMs: null,
    imageDigest:
      `123456789012.dkr.ecr.us-west-2.amazonaws.com/clockchain@sha256:${"b".repeat(64)}`,
    releaseId: "release-0123456789abcdef",
    repositorySha:
      "abcdef0123456789abcdef0123456789abcdef01",
    secretCanaries: [],
    sessionId:
      "11111111-1111-4111-8111-111111111111",
    snapshot: {
      anchors: [],
      currentStep:
        "Waiting for the Payer to begin.",
      funding: { status: "NOT_STARTED" },
      mcp: { status: "NOT_STARTED" },
      paymentMoved: false,
      payer: { status: "WAITING" },
      publishedAtMs: "2000000000000",
      relay: { status: "READY" },
      requestor: { status: "WAITING" },
      runId: "run-0123456789abcdef",
      runStatus: "WAITING_FOR_PARTICIPANTS",
      schema:
        "clockchain.bilateral-public-monitor/v3",
      staleAfterMs: 10_000,
      verifier: { status: "NOT_STARTED" },
    },
    verifierPublicationValidated: false,
  };
}

test("publisher loop waits safely while staged public input is absent", async () => {
  const controller = new AbortController();
  let reads = 0;
  await runAwsPublisherLoop(INPUT, {
    intervalMs: 250,
    readFile: async () => {
      reads += 1;
      controller.abort();
      const error = new Error("missing");
      error.code = "ENOENT";
      throw error;
    },
    signal: controller.signal,
  });
  assert.equal(reads, 1);
});

test("publishes one sanitized projection to the exact private S3 bucket", async () => {
  const calls = [];
  const result = await runAwsPublisherOnce(
    INPUT,
    {
      publish: async (input, dependencies) => {
        const gate =
          await dependencies.readPublicationGate();
        assert.deepEqual(gate, {
          payerClaimApproved: false,
          payerDiscoveryReady: false,
          payerMcpReady: false,
          requestorDiscoveryReady: false,
          runStarted: true,
          tunnelTlsHealthy: false,
        });
        assert.equal(
          dependencies.publicObjectUrl(
            "runs/index.json",
          ),
          "https://monitor.example.com/runs/index.json",
        );
        await dependencies.putObject({
          body: "{}\n",
          cacheControl: "no-store,max-age=0",
          contentType: "application/json",
          key: "latest.json",
        });
        await dependencies.writePublicationRecord({
          objects: [],
          paymentMoved: false,
          publishedAtMs: "2000000000000",
          runId: "run-0123456789abcdef",
          schema:
            "clockchain.aws-publication-record/v1",
        });
        return {
          objectCount: 1,
          paymentMoved: false,
          runId: input.snapshot.runId,
          status: "PUBLISHED",
        };
      },
      readFile: async (path) => {
        calls.push(["read", path]);
        if (
          path === INPUT.publicationInputPath
        ) {
          return Buffer.from(
            `${JSON.stringify(publicationInput())}\n`,
          );
        }
        return Buffer.from(
          '{"payerClaimApproved":false,"payerDiscoveryReady":false,"payerMcpReady":false,"requestorDiscoveryReady":false,"runStarted":true,"tunnelTlsHealthy":false}\n',
        );
      },
      s3: {
        async send(command) {
          calls.push([
            "s3",
            command.constructor.name,
            command.input,
          ]);
          return { ETag: '"etag"' };
        },
      },
      writeRecord: async (record) => {
        calls.push(["record", record]);
      },
    },
  );
  assert.deepEqual(result, {
    objectCount: 1,
    paymentMoved: false,
    runId: "run-0123456789abcdef",
    status: "PUBLISHED",
  });
  const put = calls.find(
    ([kind, name]) =>
      kind === "s3" &&
      name === "PutObjectCommand",
  );
  assert.equal(
    put[2].Bucket,
    INPUT.bucketName,
  );
  assert.equal(put[2].Key, "latest.json");
  assert.equal(
    calls.some(
      ([kind]) => kind === "record",
    ),
    true,
  );
});

test("rejects traversal, public bucket URLs, and non-false runtime state", async () => {
  for (const value of [
    {
      ...INPUT,
      publicBaseUrl:
        "http://monitor.example.com",
    },
    {
      ...INPUT,
      paymentMoved: true,
    },
    {
      ...INPUT,
      stagedPaths: {
        ...INPUT.stagedPaths,
        certificate: "/tmp/../secret",
      },
    },
  ]) {
    await assert.rejects(
      runAwsPublisherOnce(value, {}),
      /AWS publisher runtime failed safely/,
    );
  }
});
