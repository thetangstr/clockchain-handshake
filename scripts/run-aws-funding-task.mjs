#!/usr/bin/env node

import {
  constants as fsConstants,
} from "node:fs";
import {
  mkdir,
  open,
  link,
  readFile,
  rm,
  unlink,
} from "node:fs/promises";
import { dirname, join } from "node:path";
import { types } from "node:util";

import {
  main as fundingMain,
} from "./fund-bilateral-addresses.mjs";
import {
  openFundingWallet,
} from "../src/bilateral/funding/keystore.mjs";

const INPUT_KEYS = Object.freeze([
  "actionAtMs",
  "actionId",
  "expectedTreasuryAddress",
  "fundingRecordPath",
  "journalDirectory",
  "keystorePath",
  "releaseId",
  "repositorySha",
  "resultPath",
  "rpcUrlFile",
  "secretId",
  "sessionId",
]);
const RESULT_KEYS = Object.freeze([
  "actionAtMs",
  "actionId",
  "batchId",
  "fundingRecordPath",
  "paymentMoved",
  "releaseId",
  "repositorySha",
  "schema",
  "sessionId",
  "status",
  "transactionHashes",
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
const RELEASE = /^release-[0-9a-f]{16}$/;
const SESSION =
  /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const UUID = SESSION;
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
    !Number.isSafeInteger(input.actionAtMs) ||
    input.actionAtMs < 0 ||
    stringMatching(input.actionId, UUID) !==
      input.actionId ||
    stringMatching(
      input.expectedTreasuryAddress,
      ADDRESS,
    ) !== input.expectedTreasuryAddress ||
    stringMatching(input.repositorySha, SHA40) !==
      input.repositorySha ||
    stringMatching(input.releaseId, RELEASE) !==
      input.releaseId ||
    stringMatching(input.sessionId, SESSION) !==
      input.sessionId ||
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
    "resultPath",
    "rpcUrlFile",
  ]) {
    absolutePath(input[key]);
  }
  if (
    input.resultPath !==
    `/var/lib/clockchain/funding-result/releases/${input.releaseId}/actions/${input.actionId}/funding-result.json`
  ) {
    fail();
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

function canonical(value) {
  if (Array.isArray(value)) {
    return value.map(canonical);
  }
  if (plain(value)) {
    return Object.fromEntries(
      Object.keys(value)
        .sort()
        .map((key) => [key, canonical(value[key])]),
    );
  }
  return value;
}

function validateFundingResult(value, input) {
  const result = exact(value, RESULT_KEYS);
  if (
    result.schema !==
      "clockchain.aws-funding-task-result/v1" ||
    result.actionAtMs !== input.actionAtMs ||
    result.actionId !== input.actionId ||
    result.paymentMoved !== false ||
    result.status !== "FUNDED" ||
    result.releaseId !== input.releaseId ||
    result.repositorySha !== input.repositorySha ||
    result.sessionId !== input.sessionId ||
    result.fundingRecordPath !==
      input.fundingRecordPath ||
    stringMatching(result.batchId, SHA64) !==
      result.batchId ||
    !Array.isArray(result.transactionHashes) ||
    result.transactionHashes.length !== 4
  ) {
    fail();
  }
  const seen = new Set();
  for (const hash of result.transactionHashes) {
    if (
      stringMatching(hash, HASH) !== hash ||
      seen.has(hash)
    ) {
      fail();
    }
    seen.add(hash);
  }
  return Object.freeze({
    batchId: result.batchId,
    paymentMoved: false,
    status: "FUNDED",
    transactionHashes: Object.freeze([
      ...result.transactionHashes,
    ]),
  });
}

async function atomicWrite(path, value, input) {
  const body = `${JSON.stringify(canonical(value))}\n`;
  const temporary = `${path}.${process.pid}.${Date.now()}.next`;
  let handle;
  try {
    try {
      const existingBytes = await readFile(
        path,
        "utf8",
      );
      const existing = validateFundingResult(
        JSON.parse(existingBytes),
        input,
      );
      if (
        existingBytes === body &&
        JSON.stringify(canonical(value)) ===
        JSON.stringify(
          canonical({
            ...value,
            transactionHashes:
              existing.transactionHashes,
          }),
        )
      ) {
        return;
      }
      fail();
    } catch (error) {
      if (error?.code !== "ENOENT") {
        if (error instanceof AwsFundingTaskError) {
          throw error;
        }
        throw error;
      }
    }
    await mkdir(dirname(path), {
      recursive: true,
      mode: 0o700,
    });
    handle = await open(
      temporary,
      fsConstants.O_WRONLY |
        fsConstants.O_CREAT |
        fsConstants.O_EXCL |
        (fsConstants.O_NOFOLLOW ?? 0),
      0o600,
    );
    await handle.writeFile(body, "utf8");
    await handle.sync();
    await handle.close();
    handle = undefined;
    await link(temporary, path);
    await unlink(temporary);
  } catch (error) {
    await handle?.close().catch(() => {});
    await rm(temporary, { force: true }).catch(() => {});
    throw error;
  }
}

export async function readAwsFundingResult(path, input) {
  try {
    const bytes = await readFile(path, "utf8");
    if (Buffer.byteLength(bytes, "utf8") > 16_384) {
      fail();
    }
    const parsed = JSON.parse(bytes);
    if (JSON.stringify(canonical(parsed)) + "\n" !== bytes) {
      fail();
    }
    return validateFundingResult(parsed, input);
  } catch (error) {
    if (error instanceof AwsFundingTaskError) {
      throw error;
    }
    fail();
  }
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
    const writeFundingResult =
      dependencies.writeFundingResult ??
      atomicWrite;
    const readFundingResult =
      dependencies.readFundingResult ??
      readAwsFundingResult;
    const walletOpener =
      dependencies.openFundingWallet ??
      openFundingWallet;
    if (
      typeof readSecret !== "function" ||
      typeof run !== "function" ||
      typeof writeFundingResult !==
        "function" ||
      typeof readFundingResult !== "function" ||
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
    const result = validateSummary(summary, input);
    const durable = {
      actionAtMs: input.actionAtMs,
      actionId: input.actionId,
      batchId: result.batchId,
      fundingRecordPath: input.fundingRecordPath,
      paymentMoved: false,
      releaseId: input.releaseId,
      repositorySha: input.repositorySha,
      schema: "clockchain.aws-funding-task-result/v1",
      sessionId: input.sessionId,
      status: "FUNDED",
      transactionHashes: result.transactionHashes,
    };
    await writeFundingResult(
      input.resultPath,
      durable,
      input,
    );
    return await readFundingResult(
      input.resultPath,
      input,
    );
  } catch (error) {
    if (error instanceof AwsFundingTaskError) {
      throw error;
    }
    fail();
  }
}
