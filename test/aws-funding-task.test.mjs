import assert from "node:assert/strict";
import { test } from "node:test";

import {
  runAwsFundingTask,
} from "../scripts/run-aws-funding-task.mjs";

const REPOSITORY_SHA =
  "abcdef0123456789abcdef0123456789abcdef01";
const TREASURY =
  "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const RECIPIENTS = Object.freeze([
  "0x1111111111111111111111111111111111111111",
  "0x2222222222222222222222222222222222222222",
  "0x3333333333333333333333333333333333333333",
  "0x4444444444444444444444444444444444444444",
]);
const TARGET_WEI = "10000000000000000";

function input(overrides = {}) {
  return {
    expectedTreasuryAddress: TREASURY,
    fundingRecordPath: "/private/funding-addresses.json",
    journalDirectory: "/private/funding-journal",
    keystorePath: "/private/funding-wallet.json",
    repositorySha: REPOSITORY_SHA,
    rpcUrlFile: "/private/sepolia-rpc",
    secretId: "clockchain/demo/funding-password",
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

test("rejects partial, adopted, duplicate, wrong-value, wrong-treasury, and non-false summaries", async () => {
  const hostile = [
    summary({ transfers: summary().transfers.slice(0, 3) }),
    summary({ adopted: [RECIPIENTS[0]] }),
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
