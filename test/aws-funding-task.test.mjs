import assert from "node:assert/strict";
import { test } from "node:test";

import {
  runAwsFundingTask,
} from "../scripts/run-aws-funding-task.mjs";

const REPOSITORY_SHA =
  "abcdef0123456789abcdef0123456789abcdef01";
const TREASURY =
  "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const RELEASE_ID = "release-bd7662a5eeb41614";
const SESSION_ID =
  "11111111-1111-4111-8111-111111111111";
const ACTION_ID =
  "22222222-2222-4222-8222-222222222222";
const ACTION_AT_MS = 2_000_000_000_000;
const RECIPIENTS = Object.freeze([
  "0x1111111111111111111111111111111111111111",
  "0x2222222222222222222222222222222222222222",
  "0x3333333333333333333333333333333333333333",
  "0x4444444444444444444444444444444444444444",
]);
const TARGET_WEI = "10000000000000000";

function input(overrides = {}) {
  return {
    actionAtMs: ACTION_AT_MS,
    actionId: ACTION_ID,
    expectedTreasuryAddress: TREASURY,
    fundingRecordPath: "/private/funding-addresses.json",
    journalDirectory: "/private/funding-journal",
    keystorePath: "/private/funding-wallet.json",
    releaseId: RELEASE_ID,
    repositorySha: REPOSITORY_SHA,
    resultPath:
      `/var/lib/clockchain/funding-result/releases/${RELEASE_ID}/actions/${ACTION_ID}/funding-result.json`,
    rpcUrlFile: "/private/sepolia-rpc",
    secretId: "clockchain/demo/funding-password",
    sessionId: SESSION_ID,
    ...overrides,
  };
}

function summary(overrides = {}) {
  return {
    adopted: [],
    batchId: "b".repeat(64),
    fundingAddress: TREASURY,
    journalPath:
      "/private/funding-journal/funding-journal.json",
    paymentMoved: false,
    repositorySha: REPOSITORY_SHA,
    rpcEndpointSha256: "c".repeat(64),
    schema: "clockchain.bilateral-funding-summary/v1",
    transfers: RECIPIENTS.map((address, index) => ({
      address,
      fundingNonce: String(7 + index),
      transactionHash: `0x${String(index + 1).repeat(64)}`,
      valueWei: TARGET_WEI,
    })),
    ...overrides,
  };
}

function fixture(result = summary()) {
  const calls = [];
  return {
    calls,
    dependencies: {
      fundingMain: async (arguments_, dependencies) => {
        calls.push(["main", arguments_]);
        await dependencies.openFundingWallet({
          keystorePath: "/private/funding-wallet.json",
          metadataPath:
            "/private/funding-wallet.public.json",
        });
        return result instanceof Error
          ? Promise.reject(result)
          : result;
      },
      openFundingWallet: async (options) => {
        const password =
          await options.dependencies
            .readKeychainPassword();
        calls.push(["password", password]);
        return { account: {}, metadata: {} };
      },
      readSecret: async (secretId) => {
        calls.push(["secret", secretId]);
        return "treasury-password-canary";
      },
      readFundingResult: async (path, resultInput) => {
        calls.push([
          "read-result",
          path,
          resultInput,
        ]);
        return {
          batchId: result.batchId,
          paymentMoved: false,
          status: "FUNDED",
          transactionHashes:
            result.transfers.map(
              ({ transactionHash }) =>
                transactionHash,
            ),
        };
      },
      writeFundingResult: async (
        path,
        value,
        resultInput,
      ) => {
        calls.push([
          "write-result",
          path,
          value,
          resultInput,
        ]);
      },
    },
  };
}

function coercibleString(value, calls) {
  return {
    get toString() {
      calls.count += 1;
      return () => value;
    },
    valueOf() {
      calls.count += 1;
      return value;
    },
  };
}

test("runs one four-address Sepolia batch with a Secrets Manager password and confirmed exact receipts", async () => {
  const fx = fixture();
  const result = await runAwsFundingTask(
    input(),
    fx.dependencies,
  );
  assert.deepEqual(result, {
    batchId: "b".repeat(64),
    paymentMoved: false,
    status: "FUNDED",
    transactionHashes: summary().transfers.map(
      ({ transactionHash }) => transactionHash,
    ),
  });
  const durable = fx.calls.find(
    ([name]) => name === "write-result",
  )[2];
  assert.deepEqual(durable, {
    actionAtMs: ACTION_AT_MS,
    actionId: ACTION_ID,
    batchId: "b".repeat(64),
    fundingRecordPath:
      "/private/funding-addresses.json",
    paymentMoved: false,
    releaseId: RELEASE_ID,
    repositorySha: REPOSITORY_SHA,
    schema:
      "clockchain.aws-funding-task-result/v1",
    sessionId: SESSION_ID,
    status: "FUNDED",
    transactionHashes: summary().transfers.map(
      ({ transactionHash }) => transactionHash,
    ),
  });
  assert.deepEqual(fx.calls[0], [
    "secret",
    "clockchain/demo/funding-password",
  ]);
  assert.equal(
    fx.calls.some(
      ([name, value]) =>
        name === "password" &&
        value === "treasury-password-canary",
    ),
    true,
  );
  const mainArguments = fx.calls.find(
    ([name]) => name === "main",
  )[1];
  assert.deepEqual(mainArguments, [
    "--funding-record",
    "/private/funding-addresses.json",
    "--journal-directory",
    "/private/funding-journal",
    "--keystore",
    "/private/funding-wallet.json",
    "--rpc-url-file",
    "/private/sepolia-rpc",
  ]);
  assert.equal(
    JSON.stringify(result).includes("password-canary"),
    false,
  );
});

test("rejects object-valued summary regex fields without invoking string coercion hooks", async () => {
  const cases = [
    (value) => summary({ batchId: value }),
    (value) =>
      summary({
        transfers: summary().transfers.map(
          (transfer, index) =>
            index === 0
              ? { ...transfer, address: value }
              : transfer,
        ),
      }),
    (value) =>
      summary({
        transfers: summary().transfers.map(
          (transfer, index) =>
            index === 0
              ? {
                  ...transfer,
                  fundingNonce: value,
                }
              : transfer,
        ),
      }),
    (value) =>
      summary({
        transfers: summary().transfers.map(
          (transfer, index) =>
            index === 0
              ? {
                  ...transfer,
                  transactionHash: value,
                }
              : transfer,
        ),
      }),
    (value) =>
      summary({
        adopted: [
          value,
          RECIPIENTS[1],
          RECIPIENTS[2],
          RECIPIENTS[3],
        ],
      }),
  ];
  const values = [
    "b".repeat(64),
    RECIPIENTS[0],
    "7",
    `0x${"1".repeat(64)}`,
    RECIPIENTS[0],
  ];
  for (const [index, makeSummary] of cases.entries()) {
    const calls = { count: 0 };
    await assert.rejects(
      runAwsFundingTask(
        input(),
        fixture(
          makeSummary(
            coercibleString(values[index], calls),
          ),
        ).dependencies,
      ),
      /AWS funding task failed safely/,
    );
    assert.equal(calls.count, 0);
  }
});

test("accepts completed journal-backed funding replay without changing the FUNDED result", async () => {
  const first = await runAwsFundingTask(
    input(),
    fixture(summary()).dependencies,
  );
  const replay = await runAwsFundingTask(
    input(),
    fixture(
      summary({
        adopted: RECIPIENTS,
      }),
    ).dependencies,
  );
  assert.deepEqual(replay, first);
  assert.deepEqual(replay, {
    batchId: "b".repeat(64),
    paymentMoved: false,
    status: "FUNDED",
    transactionHashes: summary().transfers.map(
      ({ transactionHash }) => transactionHash,
    ),
  });
});

test("rejects partial, unsafe adopted, duplicate, wrong-value, wrong-treasury, malformed hash, and non-false summaries", async () => {
  const hostile = [
    summary({ transfers: summary().transfers.slice(0, 3) }),
    summary({ adopted: [RECIPIENTS[0]] }),
    summary({
      adopted: RECIPIENTS,
      transfers: [],
    }),
    summary({
      adopted: RECIPIENTS,
      transfers: summary().transfers.slice(0, 3),
    }),
    summary({
      adopted: [
        RECIPIENTS[0],
        RECIPIENTS[0],
        RECIPIENTS[1],
        RECIPIENTS[2],
      ],
    }),
    summary({
      adopted: [
        RECIPIENTS[0],
        RECIPIENTS[1],
        RECIPIENTS[2],
        "0x5555555555555555555555555555555555555555",
      ],
    }),
    summary({
      transfers: summary().transfers.map(
        (transfer, index) =>
          index === 1
            ? {
                ...transfer,
                address: RECIPIENTS[0],
              }
            : transfer,
      ),
    }),
    summary({
      transfers: summary().transfers.map(
        (transfer, index) =>
          index === 2
            ? { ...transfer, valueWei: "1" }
            : transfer,
      ),
    }),
    summary({
      transfers: summary().transfers.map(
        (transfer, index) =>
          index === 3
            ? {
                ...transfer,
                transactionHash: `0x${"g".repeat(64)}`,
              }
            : transfer,
      ),
    }),
    summary({
      fundingAddress:
        "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    }),
    summary({ paymentMoved: true }),
  ];
  for (const value of hostile) {
    await assert.rejects(
      runAwsFundingTask(input(), fixture(value).dependencies),
      /AWS funding task failed safely/,
    );
  }
});

test("never automatically retries an attempted or ambiguous funding journal", async () => {
  let attempts = 0;
  const fx = fixture(
    new Error("ambiguous funding journal"),
  );
  fx.dependencies.fundingMain =
    async (...arguments_) => {
      attempts += 1;
      return fixture(
        new Error("ambiguous funding journal"),
      ).dependencies.fundingMain(...arguments_);
    };
  await assert.rejects(
    runAwsFundingTask(input(), fx.dependencies),
    /AWS funding task failed safely/,
  );
  assert.equal(attempts, 1);
});
