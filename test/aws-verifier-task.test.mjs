import assert from "node:assert/strict";
import { test } from "node:test";

import {
  runAwsVerifierTask,
} from "../scripts/run-aws-verifier-task.mjs";

const REPOSITORY_SHA =
  "abcdef0123456789abcdef0123456789abcdef01";
const ATTEMPT_ID =
  "11111111-1111-4111-8111-111111111111";
const TASK_ARN =
  "arn:aws:ecs:us-west-2:123456789012:task/clockchain/11111111111111111111111111111111";
const PUBLICATION_DIGEST = "c".repeat(64);

function input(overrides = {}) {
  return {
    actionAtMs: 2_000_000_000_000,
    attemptId: ATTEMPT_ID,
    attemptRoot: `/verdict/${ATTEMPT_ID}`,
    clockchainTokenFile: "/secrets/clockchain-token",
    descriptorPath: "/evidence/descriptor.json",
    evidenceDigest: "d".repeat(64),
    expectedRevision: 5,
    mandateDigest: "e".repeat(64),
    payerMandatePath: "/evidence/payer-mandate.json",
    payeeResultsPath: "/evidence/payee-results",
    payerResultsPath: "/evidence/payer-results",
    paymentRequestPath: "/evidence/payment-request.json",
    publicationPath: "/verdict/task-publication.json",
    repositorySha: REPOSITORY_SHA,
    requestDigest: "f".repeat(64),
    rpcUrl: "https://sepolia.example.invalid",
    sessionDigest: "a".repeat(64),
    taskArn: TASK_ARN,
    ...overrides,
  };
}

function verdict(overrides = {}) {
  return {
    paymentMoved: false,
    repositorySha: REPOSITORY_SHA,
    transitions: [
      { kind: "PROPOSED" },
      { kind: "ACCEPTED" },
      { kind: "ACKNOWLEDGED" },
    ],
    ...overrides,
  };
}

function fixture({
  files = [
    ".bilateral-verdict.complete.json",
    "BILATERAL-VERDICT.md",
    "bilateral-verdict.json",
  ],
  mainExit = 0,
  publishedVerdict = verdict(),
  validation = {
    publicationDigest: PUBLICATION_DIGEST,
    status: "VERIFICATION_PASSED",
  },
} = {}) {
  const calls = [];
  let stdout = "";
  return {
    calls,
    dependencies: {
      listOutputFiles: async () => files,
      nowMs: () => 2_000_000_000_100,
      readVerdict: async () => publishedVerdict,
      validatePublication: async () => validation,
      verifierMain: async (arguments_, dependencies) => {
        calls.push(["main", arguments_]);
        if (mainExit === 0) {
          await dependencies
            .beforeAuthorizationOutput({
              output: `/verdict/${ATTEMPT_ID}`,
              verdict: publishedVerdict,
            });
          dependencies.stdout.write("AUTHORIZED\n");
        }
        return mainExit;
      },
      verifierStderr: { write: () => {} },
      verifierStdout: {
        write(value) {
          stdout += value;
        },
      },
      writePublication: async (publication) => {
        calls.push(["publication", publication]);
      },
    },
    stdout: () => stdout,
  };
}

test("runs one fresh aggregate verifier and publishes only its validated three-anchor result", async () => {
  const fx = fixture();
  const result = await runAwsVerifierTask(
    input(),
    fx.dependencies,
  );
  assert.equal(fx.stdout(), "AUTHORIZED\n");
  assert.equal(result.paymentMoved, false);
  assert.equal(result.verifier.status, "VERIFIED");
  assert.deepEqual(
    result.anchors,
    ["PROPOSED", "ACCEPTED", "ACKNOWLEDGED"],
  );
  const publication = fx.calls.find(
    ([name]) => name === "publication",
  )[1];
  assert.deepEqual(publication, {
    attemptId: ATTEMPT_ID,
    evidenceDigest: "d".repeat(64),
    paymentMoved: false,
    publicationDigest: PUBLICATION_DIGEST,
    repositorySha: REPOSITORY_SHA,
    revision: 5,
    schema:
      "clockchain.aws-verifier-task-publication/v1",
    status: "VERIFICATION_PASSED",
    taskArn: TASK_ARN,
    writtenAtMs: "2000000000100",
  });
});

test("fails closed for missing, duplicate, reordered, malformed, mismatched, non-fresh, extra, stale, or payment-moved evidence", async () => {
  const cases = [
    { publishedVerdict: verdict({ transitions: [] }) },
    {
      publishedVerdict: verdict({
        transitions: [
          { kind: "PROPOSED" },
          { kind: "ACCEPTED" },
          { kind: "ACCEPTED" },
        ],
      }),
    },
    {
      publishedVerdict: verdict({
        transitions: [
          { kind: "ACCEPTED" },
          { kind: "PROPOSED" },
          { kind: "ACKNOWLEDGED" },
        ],
      }),
    },
    { publishedVerdict: null },
    {
      publishedVerdict: verdict({
        repositorySha: "f".repeat(40),
      }),
    },
    { mainExit: 1 },
    {
      files: [
        ".bilateral-verdict.complete.json",
        "BILATERAL-VERDICT.md",
        "bilateral-verdict.json",
        "extra.json",
      ],
    },
    { publishedVerdict: verdict({ paymentMoved: true }) },
  ];
  for (const options of cases) {
    await assert.rejects(
      runAwsVerifierTask(
        input(),
        fixture(options).dependencies,
      ),
      /AWS verifier task failed safely/,
    );
  }
  await assert.rejects(
    runAwsVerifierTask(
      input({
        attemptRoot:
          "/verdict/22222222-2222-4222-8222-222222222222",
      }),
      fixture().dependencies,
    ),
    /AWS verifier task failed safely/,
  );
});

test("keeps the authorization literal out of every production surface except the aggregate authority and its CLI", async () => {
  const { execFile } = await import(
    "node:child_process"
  );
  const { readFile } = await import(
    "node:fs/promises"
  );
  const { promisify } = await import("node:util");
  const { stdout } = await promisify(execFile)(
    "rg",
    [
      "--files",
      "--glob",
      "*.mjs",
      "--glob",
      "!test/**",
      "--glob",
      "!docs/**",
      "src",
      "scripts",
      "bin",
      "infra",
    ],
    { encoding: "utf8" },
  );
  const files = stdout.trim().split("\n");
  const authorizingString =
    /["']AUTHORIZED(?:\\n)?["']/;
  const matched = [];
  for (const file of files) {
    if (
      authorizingString.test(
        await readFile(file, "utf8"),
      )
    ) {
      matched.push(file);
    }
  }
  assert.deepEqual(
    matched.sort(),
    [
      "scripts/verify-bilateral-results.mjs",
      "src/bilateral/verdict.mjs",
    ],
  );
});
