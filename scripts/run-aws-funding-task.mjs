#!/usr/bin/env node

import { join } from "node:path";
import { types } from "node:util";

import {
  main as fundingMain,
} from "./fund-bilateral-addresses.mjs";
import {
  openFundingWallet,
} from "../src/bilateral/funding/keystore.mjs";

const INPUT_KEYS = Object.freeze([
  "expectedTreasuryAddress",
  "fundingRecordPath",
  "journalDirectory",
  "keystorePath",
  "repositorySha",
  "rpcUrlFile",
  "secretId",
]);
const SUMMARY_KEYS = Object.freeze([
  "adopted",
  "batchId",
  "fundingAddress",
  "journalPath",
  "paymentMoved",
  "repositorySha",
  "rpcEndpointSha256",
  "schema",
  "transfers",
]);
const TRANSFER_KEYS = Object.freeze([
  "address",
  "fundingNonce",
  "transactionHash",
  "valueWei",
]);
const ADDRESS = /^0x[0-9a-f]{40}$/;
const SHA40 = /^[0-9a-f]{40}$/;
const SHA64 = /^[0-9a-f]{64}$/;
const HASH = /^0x[0-9a-f]{64}$/;
const DECIMAL = /^(?:0|[1-9][0-9]*)$/;
const TARGET_WEI = "10000000000000000";

export class AwsFundingTaskError extends Error {
  constructor() {
    super("AWS funding task failed safely.");
    this.name = "AwsFundingTaskError";
    this.code = "AWS_FUNDING_TASK_FAILED";
    this.category = "verification";
  }
}

function fail() {
  throw new AwsFundingTaskError();
}

function plain(value) {
  return (
    value !== null &&
    typeof value === "object" &&
    !Array.isArray(value) &&
    !types.isProxy(value) &&
    Object.getPrototypeOf(value) ===
      Object.prototype
  );
}

function exact(value, keys) {
  if (!plain(value)) fail();
  const ownKeys = Reflect.ownKeys(value);
  if (
    ownKeys.length !== keys.length ||
    keys.some((key, index) =>
      ownKeys[index] !== key)
  ) {
    fail();
  }
  for (const key of keys) {
    const descriptor =
      Object.getOwnPropertyDescriptor(value, key);
    if (
      descriptor?.enumerable !== true ||
      !Object.hasOwn(descriptor, "value")
    ) {
      fail();
    }
  }
  return value;
}

function absolutePath(value) {
  if (
    typeof value !== "string" ||
    !value.startsWith("/") ||
    value.includes("\0") ||
    value.includes("\n") ||
    value.includes("\r")
  ) {
    fail();
  }
  return value;
}

function stringMatching(value, pattern) {
  if (
    typeof value !== "string" ||
    !pattern.test(value)
  ) {
    fail();
  }
  return value;
}

function validateInput(value) {
  const input = exact(value, INPUT_KEYS);
  if (
    stringMatching(
      input.expectedTreasuryAddress,
      ADDRESS,
    ) !== input.expectedTreasuryAddress ||
    stringMatching(input.repositorySha, SHA40) !==
      input.repositorySha ||
    typeof input.secretId !== "string" ||
    input.secretId.length === 0 ||
    input.secretId.length > 256
  ) {
    fail();
  }
  for (const key of [
    "fundingRecordPath",
    "journalDirectory",
    "keystorePath",
    "rpcUrlFile",
  ]) {
    absolutePath(input[key]);
  }
  return input;
}

function validateSummary(value, input) {
  const summary = exact(value, SUMMARY_KEYS);
  if (
    summary.schema !==
      "clockchain.bilateral-funding-summary/v1" ||
    summary.paymentMoved !== false ||
    summary.repositorySha !==
      input.repositorySha ||
    summary.fundingAddress !==
      input.expectedTreasuryAddress ||
    summary.journalPath !==
      join(
        input.journalDirectory,
        "funding-journal.json",
      ) ||
    stringMatching(summary.batchId, SHA64) !==
      summary.batchId ||
    stringMatching(
      summary.rpcEndpointSha256,
      SHA64,
    ) !== summary.rpcEndpointSha256 ||
    !Array.isArray(summary.adopted) ||
    !Array.isArray(summary.transfers) ||
    summary.transfers.length !== 4
  ) {
    fail();
  }
  const addresses = new Set();
  const hashes = new Set();
  let firstNonce = null;
  const transactionHashes = [];
  for (
    let index = 0;
    index < summary.transfers.length;
    index += 1
  ) {
    const transfer = exact(
      summary.transfers[index],
      TRANSFER_KEYS,
    );
    if (
      stringMatching(
        transfer.address,
        ADDRESS,
      ) !== transfer.address ||
      addresses.has(transfer.address) ||
      stringMatching(
        transfer.fundingNonce,
        DECIMAL,
      ) !== transfer.fundingNonce ||
      stringMatching(
        transfer.transactionHash,
        HASH,
      ) !== transfer.transactionHash ||
      hashes.has(transfer.transactionHash) ||
      transfer.valueWei !== TARGET_WEI
    ) {
      fail();
    }
    const nonce = BigInt(
      transfer.fundingNonce,
    );
    firstNonce ??= nonce;
    if (
      nonce !== firstNonce + BigInt(index)
    ) {
      fail();
    }
    addresses.add(transfer.address);
    hashes.add(transfer.transactionHash);
    transactionHashes.push(
      transfer.transactionHash,
    );
  }
  if (
    !(
      summary.adopted.length === 0 ||
      summary.adopted.length === 4
    )
  ) {
    fail();
  }
  const adopted = new Set();
  for (const address of summary.adopted) {
    if (
      stringMatching(address, ADDRESS) !== address ||
      adopted.has(address) ||
      !addresses.has(address)
    ) {
      fail();
    }
    adopted.add(address);
  }
  if (
    adopted.size !== 0 &&
    adopted.size !== addresses.size
  ) {
    fail();
  }
  return Object.freeze({
    batchId: summary.batchId,
    paymentMoved: false,
    status: "FUNDED",
    transactionHashes:
      Object.freeze(transactionHashes),
  });
}

export async function runAwsFundingTask(
  value,
  dependencies = {},
) {
  try {
    const input = validateInput(value);
    const readSecret =
      dependencies.readSecret;
    const run =
      dependencies.fundingMain ??
      fundingMain;
    const walletOpener =
      dependencies.openFundingWallet ??
      openFundingWallet;
    if (
      typeof readSecret !== "function" ||
      typeof run !== "function" ||
      typeof walletOpener !== "function"
    ) {
      fail();
    }
    const password = await readSecret(
      input.secretId,
    );
    if (
      typeof password !== "string" ||
      password.trim().length === 0 ||
      Buffer.byteLength(password, "utf8") >
        4096 ||
      password.includes("\0")
    ) {
      fail();
    }
    const summary = await run(
      [
        "--funding-record",
        input.fundingRecordPath,
        "--journal-directory",
        input.journalDirectory,
        "--keystore",
        input.keystorePath,
        "--rpc-url-file",
        input.rpcUrlFile,
      ],
      {
        getRepositorySha: async () =>
          input.repositorySha,
        openFundingWallet: async (options) =>
          walletOpener({
            ...options,
            dependencies: {
              ...(options.dependencies ?? {}),
              readKeychainPassword:
                async () => password,
            },
          }),
        stdout: () => {},
      },
    );
    return validateSummary(summary, input);
  } catch (error) {
    if (error instanceof AwsFundingTaskError) {
      throw error;
    }
    fail();
  }
}
