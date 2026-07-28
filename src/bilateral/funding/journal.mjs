import { createHash } from "node:crypto";
import { constants as fsConstants } from "node:fs";
import {
  lstat,
  open,
  readdir,
  readFile,
  rename,
  unlink,
} from "node:fs/promises";
import { dirname, join } from "node:path";

import { BilateralFundingError } from "./record.mjs";

export const FUNDING_JOURNAL_SCHEMA =
  "clockchain.bilateral-funding-journal/v1";
export const FUNDING_STATES = Object.freeze([
  "PLANNED",
  "BROADCAST_INTENT",
  "TRANSACTION_OBSERVED",
  "FUNDED",
]);

const JOURNAL_FILE = "funding-journal.json";
const TEMP_PREFIX = ".funding-journal.tmp-";
const ADDRESS_PATTERN = /^0x[0-9a-f]{40}$/;
const HASH_PATTERN = /^0x[0-9a-f]{64}$/;
const SHA256_PATTERN = /^[0-9a-f]{64}$/;
const GIT_SHA_PATTERN = /^[0-9a-f]{40}$/;
const WEI_PATTERN = /^(?:0|[1-9][0-9]*)$/;
const BINDING_KEYS = Object.freeze([
  "batchId",
  "chainId",
  "fundingAddress",
  "paymentMoved",
  "recipients",
  "repositorySha",
  "rpcEndpointSha256",
  "targetBalanceWei",
]);
const PUBLIC_BINDING_KEYS = Object.freeze(
  BINDING_KEYS.filter((key) => key !== "batchId"),
);
const JOURNAL_KEYS = Object.freeze([
  "binding",
  "schema",
  "state",
  "transfers",
]);
const TRANSFER_KEYS = Object.freeze([
  "address",
  "feeWei",
  "fundingNonce",
  "state",
  "transactionDigest",
  "transactionHash",
  "valueWei",
]);
const OBSERVED_INPUT_KEYS = Object.freeze([
  "address",
  "fundingNonce",
  "transactionHash",
]);
const FUNDED_INPUT_KEYS = Object.freeze(["address", "fundingNonce"]);
const RECOVERY_INPUT_KEYS = Object.freeze([
  "binding",
  "journalTransfer",
  "nonceTransaction",
  "receipt",
  "recipientFact",
]);

const defaultDependencies = Object.freeze({
  fileSystem: Object.freeze({
    lstat,
    open,
    readdir,
    readFile,
    rename,
    unlink,
  }),
});

function fail(code = "BILATERAL_FUNDING_INVALID_JOURNAL") {
  throw new BilateralFundingError(code);
}

function guarded(code, operation) {
  try {
    return operation();
  } catch (error) {
    if (error instanceof BilateralFundingError) throw error;
    fail(code);
  }
}

function canonicalJson(value) {
  if (Array.isArray(value)) {
    return `[${value.map((entry) => canonicalJson(entry)).join(",")}]`;
  }
  if (value !== null && typeof value === "object") {
    return `{${Object.keys(value)
      .sort()
      .map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`)
      .join(",")}}`;
  }
  return JSON.stringify(value);
}

function snapshotExactDataObject(value, keys, code) {
  if (value === null || typeof value !== "object") fail(code);
  const prototype = guarded(code, () => Object.getPrototypeOf(value));
  if (prototype !== Object.prototype && prototype !== null) fail(code);
  const ownKeys = guarded(code, () => Reflect.ownKeys(value));
  if (
    ownKeys.length !== keys.length ||
    !keys.every((key) => ownKeys.includes(key))
  ) {
    fail(code);
  }

  const snapshot = {};
  for (const key of keys) {
    const descriptor = guarded(code, () =>
      Object.getOwnPropertyDescriptor(value, key),
    );
    if (
      !descriptor ||
      !descriptor.enumerable ||
      !Object.hasOwn(descriptor, "value")
    ) {
      fail(code);
    }
    snapshot[key] = descriptor.value;
  }
  return Object.freeze(snapshot);
}

function snapshotDenseDataArray(value, code) {
  if (
    !guarded(code, () => Array.isArray(value)) ||
    guarded(code, () => Object.getPrototypeOf(value)) !== Array.prototype
  ) {
    fail(code);
  }
  const lengthDescriptor = guarded(code, () =>
    Object.getOwnPropertyDescriptor(value, "length"),
  );
  if (
    !lengthDescriptor ||
    !Object.hasOwn(lengthDescriptor, "value") ||
    !Number.isSafeInteger(lengthDescriptor.value)
  ) {
    fail(code);
  }
  const expectedKeys = new Set(
    Array.from({ length: lengthDescriptor.value }, (_, index) => String(index)),
  );
  const ownKeys = guarded(code, () => Reflect.ownKeys(value));
  if (
    ownKeys.length !== expectedKeys.size + 1 ||
    ownKeys.some(
      (key) =>
        key !== "length" &&
        (typeof key !== "string" || !expectedKeys.has(key)),
    )
  ) {
    fail(code);
  }

  const copy = [];
  for (let index = 0; index < lengthDescriptor.value; index += 1) {
    const descriptor = guarded(code, () =>
      Object.getOwnPropertyDescriptor(value, String(index)),
    );
    if (
      !descriptor ||
      !descriptor.enumerable ||
      !Object.hasOwn(descriptor, "value")
    ) {
      fail(code);
    }
    copy.push(descriptor.value);
  }
  return Object.freeze(copy);
}

function validateAddress(value, code) {
  if (typeof value !== "string" || !ADDRESS_PATTERN.test(value)) fail(code);
  return value;
}

function validateWeiString(value, code) {
  if (typeof value !== "string" || !WEI_PATTERN.test(value)) fail(code);
  return value;
}

function validateDecimalIntegerString(value, code) {
  return validateWeiString(value, code);
}

function validateBinding(value) {
  const binding = snapshotExactDataObject(
    value,
    BINDING_KEYS,
    "BILATERAL_FUNDING_INVALID_BINDING",
  );
  if (
    binding.chainId !== 11155111 ||
    binding.paymentMoved !== false ||
    !GIT_SHA_PATTERN.test(binding.repositorySha) ||
    !SHA256_PATTERN.test(binding.rpcEndpointSha256) ||
    binding.targetBalanceWei !== "10000000000000000"
  ) {
    fail("BILATERAL_FUNDING_INVALID_BINDING");
  }
  validateAddress(binding.fundingAddress, "BILATERAL_FUNDING_INVALID_BINDING");
  const recipients = snapshotDenseDataArray(
    binding.recipients,
    "BILATERAL_FUNDING_INVALID_BINDING",
  );
  if (recipients.length !== 4) fail("BILATERAL_FUNDING_INVALID_BINDING");
  const seen = new Set();
  const copiedRecipients = [];
  for (const recipient of recipients) {
    const address = validateAddress(
      recipient,
      "BILATERAL_FUNDING_INVALID_BINDING",
    );
    if (seen.has(address) || address === binding.fundingAddress) {
      fail("BILATERAL_FUNDING_INVALID_BINDING");
    }
    seen.add(address);
    copiedRecipients.push(address);
  }

  const copy = Object.freeze({
    batchId: binding.batchId,
    chainId: 11155111,
    fundingAddress: binding.fundingAddress,
    paymentMoved: false,
    recipients: Object.freeze(copiedRecipients),
    repositorySha: binding.repositorySha,
    rpcEndpointSha256: binding.rpcEndpointSha256,
    targetBalanceWei: binding.targetBalanceWei,
  });
  if (copy.batchId !== deriveFundingBatchId(copy)) {
    fail("BILATERAL_FUNDING_INVALID_BINDING");
  }
  return copy;
}

function validateTransfer(value) {
  const transfer = snapshotExactDataObject(
    value,
    TRANSFER_KEYS,
    "BILATERAL_FUNDING_INVALID_TRANSFER",
  );
  validateAddress(transfer.address, "BILATERAL_FUNDING_INVALID_TRANSFER");
  validateWeiString(transfer.feeWei, "BILATERAL_FUNDING_INVALID_TRANSFER");
  validateDecimalIntegerString(
    transfer.fundingNonce,
    "BILATERAL_FUNDING_INVALID_TRANSFER",
  );
  validateWeiString(transfer.valueWei, "BILATERAL_FUNDING_INVALID_TRANSFER");
  if (
    !FUNDING_STATES.includes(transfer.state) ||
    transfer.state === "PLANNED" ||
    !SHA256_PATTERN.test(transfer.transactionDigest) ||
    (transfer.transactionHash !== null &&
      !HASH_PATTERN.test(transfer.transactionHash))
  ) {
    fail("BILATERAL_FUNDING_INVALID_TRANSFER");
  }
  return Object.freeze({
    address: transfer.address,
    feeWei: transfer.feeWei,
    fundingNonce: transfer.fundingNonce,
    state: transfer.state,
    transactionDigest: transfer.transactionDigest,
    transactionHash: transfer.transactionHash,
    valueWei: transfer.valueWei,
  });
}

function validateJournalDocument(value) {
  const document = snapshotExactDataObject(
    value,
    JOURNAL_KEYS,
    "BILATERAL_FUNDING_INVALID_JOURNAL",
  );
  if (
    document.schema !== FUNDING_JOURNAL_SCHEMA ||
    !FUNDING_STATES.includes(document.state)
  ) {
    fail("BILATERAL_FUNDING_INVALID_JOURNAL");
  }
  const binding = validateBinding(document.binding);
  const transferData = snapshotDenseDataArray(
    document.transfers,
    "BILATERAL_FUNDING_INVALID_JOURNAL",
  );
  const transfers = transferData.map(validateTransfer);
  const seenTransfers = new Set();
  for (const transfer of transfers) {
    if (!binding.recipients.includes(transfer.address)) {
      fail("BILATERAL_FUNDING_INVALID_JOURNAL");
    }
    const transferKey = `${transfer.address}:${transfer.fundingNonce}`;
    if (seenTransfers.has(transferKey)) {
      fail("BILATERAL_FUNDING_INVALID_JOURNAL");
    }
    seenTransfers.add(transferKey);
  }
  const maxStateIndex = transfers.reduce(
    (max, transfer) => Math.max(max, FUNDING_STATES.indexOf(transfer.state)),
    0,
  );
  if (FUNDING_STATES.indexOf(document.state) !== maxStateIndex) {
    fail("BILATERAL_FUNDING_INVALID_JOURNAL");
  }
  return Object.freeze({
    binding,
    schema: FUNDING_JOURNAL_SCHEMA,
    state: document.state,
    transfers: Object.freeze(transfers),
  });
}

function validateDirectoryStats(stats) {
  if (
    !stats.isDirectory() ||
    stats.isSymbolicLink() ||
    (stats.mode & 0o777) !== 0o700
  ) {
    fail("BILATERAL_FUNDING_UNSAFE_JOURNAL_DIRECTORY");
  }
}

function validateFileStats(stats) {
  if (
    !stats.isFile() ||
    stats.isSymbolicLink() ||
    stats.nlink !== 1 ||
    (stats.mode & 0o777) !== 0o600
  ) {
    fail("BILATERAL_FUNDING_UNSAFE_JOURNAL");
  }
}

function sameFile(left, right) {
  return left.dev === right.dev && left.ino === right.ino;
}

async function fsyncDirectory(fileSystem, directory) {
  let handle;
  try {
    handle = await fileSystem.open(
      directory,
      fsConstants.O_RDONLY |
        fsConstants.O_DIRECTORY |
        (fsConstants.O_NOFOLLOW ?? 0),
    );
    await handle.sync();
  } finally {
    await handle?.close();
  }
}

async function assertNoTemporaryFiles(fileSystem, directory) {
  let entries;
  try {
    entries = await fileSystem.readdir(directory);
  } catch {
    fail("BILATERAL_FUNDING_INVALID_JOURNAL");
  }
  if (entries.some((entry) => entry.startsWith(TEMP_PREFIX))) {
    fail("BILATERAL_FUNDING_STALE_TEMP");
  }
}

async function readCanonicalJournal(fileSystem, path) {
  const before = await fileSystem.lstat(path);
  validateFileStats(before);
  let handle;
  try {
    handle = await fileSystem.open(
      path,
      fsConstants.O_RDONLY | (fsConstants.O_NOFOLLOW ?? 0),
    );
    const afterOpen = await handle.stat();
    if (!sameFile(before, afterOpen)) fail("BILATERAL_FUNDING_REPLACED");
    const bytes = await handle.readFile("utf8");
    const parsed = guarded("BILATERAL_FUNDING_INVALID_JOURNAL", () =>
      JSON.parse(bytes),
    );
    const document = validateJournalDocument(parsed);
    if (bytes !== canonicalJson(document)) {
      fail("BILATERAL_FUNDING_NONCANONICAL_JOURNAL");
    }
    return { bytes, document, identity: afterOpen };
  } finally {
    await handle?.close();
  }
}

function freezeJournal(document, path, identity, fileSystem) {
  async function update(nextDocument) {
    const current = await readCanonicalJournal(fileSystem, path);
    if (!sameFile(current.identity, identity)) {
      fail("BILATERAL_FUNDING_REPLACED");
    }
    if (current.bytes !== canonicalJson(document)) {
      fail("BILATERAL_FUNDING_TAMPERED");
    }
    const validated = validateJournalDocument(nextDocument);
    const bytes = canonicalJson(validated);
    const directory = dirname(path);
    const temporary = join(
      directory,
      `${TEMP_PREFIX}${process.pid}-${Date.now()}-${Math.random()
        .toString(16)
        .slice(2)}`,
    );
    let handle;
    try {
      handle = await fileSystem.open(
        temporary,
        fsConstants.O_WRONLY |
          fsConstants.O_CREAT |
          fsConstants.O_EXCL |
          (fsConstants.O_NOFOLLOW ?? 0),
        0o600,
      );
      await handle.writeFile(bytes);
      await handle.chmod(0o600);
      await handle.sync();
      const beforeRename = await fileSystem.lstat(path);
      validateFileStats(beforeRename);
      if (!sameFile(beforeRename, identity)) {
        fail("BILATERAL_FUNDING_REPLACED");
      }
      await handle.close();
      handle = null;
      await fileSystem.rename(temporary, path);
      await fsyncDirectory(fileSystem, directory);
      const replaced = await readCanonicalJournal(fileSystem, path);
      if (replaced.bytes !== bytes) fail("BILATERAL_FUNDING_TAMPERED");
      return freezeJournal(replaced.document, path, replaced.identity, fileSystem);
    } catch (error) {
      await handle?.close().catch(() => {});
      await fileSystem.unlink(temporary).catch(() => {});
      if (error instanceof BilateralFundingError) throw error;
      fail("BILATERAL_FUNDING_WRITE_FAILED");
    }
  }

  return Object.freeze({
    document,
    path,
    async recordBroadcastIntent(input) {
      const transfer = validateTransfer(input);
      if (transfer.state !== "BROADCAST_INTENT" || transfer.transactionHash !== null) {
        fail("BILATERAL_FUNDING_INVALID_TRANSFER");
      }
      const existing = document.transfers.find(
        (candidate) =>
          candidate.address === transfer.address &&
          candidate.fundingNonce === transfer.fundingNonce,
      );
      if (existing) {
        if (canonicalJson(existing) !== canonicalJson(transfer)) {
          fail("BILATERAL_FUNDING_REPLACED_TRANSFER");
        }
        return this;
      }
      if (!document.binding.recipients.includes(transfer.address)) {
        fail("BILATERAL_FUNDING_INVALID_TRANSFER");
      }
      return update({
        ...document,
        state: "BROADCAST_INTENT",
        transfers: [...document.transfers, transfer],
      });
    },
    async recordTransactionObserved(input) {
      const observed = snapshotExactDataObject(
        input,
        OBSERVED_INPUT_KEYS,
        "BILATERAL_FUNDING_INVALID_TRANSFER",
      );
      validateAddress(observed.address, "BILATERAL_FUNDING_INVALID_TRANSFER");
      validateDecimalIntegerString(
        observed.fundingNonce,
        "BILATERAL_FUNDING_INVALID_TRANSFER",
      );
      if (!HASH_PATTERN.test(observed.transactionHash)) {
        fail("BILATERAL_FUNDING_INVALID_TRANSFER");
      }
      let matched = false;
      const transfers = document.transfers.map((transfer) => {
        if (
          transfer.address !== observed.address ||
          transfer.fundingNonce !== observed.fundingNonce
        ) {
          return transfer;
        }
        matched = true;
        if (
          transfer.state === "FUNDED" ||
          (transfer.transactionHash !== null &&
            transfer.transactionHash !== observed.transactionHash)
        ) {
          fail("BILATERAL_FUNDING_REPLACED_TRANSFER");
        }
        return Object.freeze({
          ...transfer,
          state: "TRANSACTION_OBSERVED",
          transactionHash: observed.transactionHash,
        });
      });
      if (!matched) fail("BILATERAL_FUNDING_INVALID_TRANSFER");
      return update({
        ...document,
        state: maxJournalState(transfers),
        transfers,
      });
    },
    async recordFunded(input) {
      const funded = snapshotExactDataObject(
        input,
        FUNDED_INPUT_KEYS,
        "BILATERAL_FUNDING_INVALID_TRANSFER",
      );
      validateAddress(funded.address, "BILATERAL_FUNDING_INVALID_TRANSFER");
      validateDecimalIntegerString(
        funded.fundingNonce,
        "BILATERAL_FUNDING_INVALID_TRANSFER",
      );
      let matched = false;
      const transfers = document.transfers.map((transfer) => {
        if (
          transfer.address !== funded.address ||
          transfer.fundingNonce !== funded.fundingNonce
        ) {
          return transfer;
        }
        matched = true;
        if (transfer.state === "BROADCAST_INTENT") {
          fail("BILATERAL_FUNDING_AMBIGUOUS_RECEIPT");
        }
        return Object.freeze({ ...transfer, state: "FUNDED" });
      });
      if (!matched) fail("BILATERAL_FUNDING_INVALID_TRANSFER");
      return update({
        ...document,
        state: maxJournalState(transfers),
        transfers,
      });
    },
  });
}

function maxJournalState(transfers) {
  return FUNDING_STATES[
    transfers.reduce(
      (max, transfer) => Math.max(max, FUNDING_STATES.indexOf(transfer.state)),
      0,
    )
  ];
}

export function deriveFundingBatchId(binding) {
  if (binding === null || typeof binding !== "object") {
    fail("BILATERAL_FUNDING_INVALID_BINDING");
  }
  const copy = {};
  for (const key of PUBLIC_BINDING_KEYS) {
    const descriptor = guarded("BILATERAL_FUNDING_INVALID_BINDING", () =>
      Object.getOwnPropertyDescriptor(binding, key),
    );
    if (
      !descriptor ||
      !descriptor.enumerable ||
      !Object.hasOwn(descriptor, "value")
    ) {
      fail("BILATERAL_FUNDING_INVALID_BINDING");
    }
    copy[key] = descriptor.value;
  }
  if (copy.recipients) {
    copy.recipients = [...snapshotDenseDataArray(
      copy.recipients,
      "BILATERAL_FUNDING_INVALID_BINDING",
    )];
  }
  return createHash("sha256").update(canonicalJson(copy)).digest("hex");
}

export async function openFundingJournal({
  binding,
  journalDirectory,
  dependencies = {},
}) {
  if (typeof journalDirectory !== "string" || journalDirectory.length === 0) {
    fail("BILATERAL_FUNDING_INVALID_JOURNAL");
  }
  const fileSystem = Object.freeze({
    ...defaultDependencies.fileSystem,
    ...(dependencies.fileSystem ?? {}),
  });
  const validatedBinding = validateBinding(binding);
  const directoryStats = await fileSystem.lstat(journalDirectory);
  validateDirectoryStats(directoryStats);
  await assertNoTemporaryFiles(fileSystem, journalDirectory);

  const path = join(journalDirectory, JOURNAL_FILE);
  let existing;
  try {
    existing = await readCanonicalJournal(fileSystem, path);
  } catch (error) {
    if (!(error && error.code === "ENOENT")) throw error;
  }
  if (existing) {
    if (canonicalJson(existing.document.binding) !== canonicalJson(validatedBinding)) {
      fail("BILATERAL_FUNDING_BINDING_MISMATCH");
    }
    return freezeJournal(existing.document, path, existing.identity, fileSystem);
  }

  const document = validateJournalDocument({
    binding: validatedBinding,
    schema: FUNDING_JOURNAL_SCHEMA,
    state: "PLANNED",
    transfers: [],
  });
  const bytes = canonicalJson(document);
  let handle;
  try {
    handle = await fileSystem.open(
      path,
      fsConstants.O_WRONLY |
        fsConstants.O_CREAT |
        fsConstants.O_EXCL |
        (fsConstants.O_NOFOLLOW ?? 0),
      0o600,
    );
    await handle.writeFile(bytes);
    await handle.chmod(0o600);
    await handle.sync();
    await handle.close();
    handle = null;
    await fsyncDirectory(fileSystem, journalDirectory);
    const created = await readCanonicalJournal(fileSystem, path);
    if (created.bytes !== bytes) fail("BILATERAL_FUNDING_TAMPERED");
    return freezeJournal(created.document, path, created.identity, fileSystem);
  } catch (error) {
    await handle?.close().catch(() => {});
    if (error instanceof BilateralFundingError) throw error;
    fail("BILATERAL_FUNDING_WRITE_FAILED");
  }
}

function normalizeInteger(value) {
  if (typeof value === "bigint") return value.toString();
  if (typeof value === "number" && Number.isSafeInteger(value) && value >= 0) {
    return String(value);
  }
  if (typeof value === "string" && WEI_PATTERN.test(value)) return value;
  fail("BILATERAL_FUNDING_AMBIGUOUS_RECOVERY");
}

function validateRecipientFact(value, transfer) {
  const fact = snapshotExactDataObject(
    value,
    ["address", "balanceWei", "nonce"],
    "BILATERAL_FUNDING_AMBIGUOUS_RECOVERY",
  );
  if (fact.address !== transfer.address) {
    fail("BILATERAL_FUNDING_AMBIGUOUS_RECOVERY");
  }
  const balanceWei = normalizeInteger(fact.balanceWei);
  const nonce = normalizeInteger(fact.nonce);
  return { balanceWei, nonce };
}

function validateTransaction(value, transfer, binding) {
  if (value === null || value === undefined) return null;
  const transaction = snapshotExactDataObject(
    value,
    ["chainId", "from", "hash", "nonce", "to", "valueWei"],
    "BILATERAL_FUNDING_AMBIGUOUS_RECOVERY",
  );
  if (
    transaction.hash === null ||
    !HASH_PATTERN.test(transaction.hash) ||
    transaction.to !== transfer.address ||
    transaction.from !== binding.fundingAddress ||
    transaction.chainId !== binding.chainId ||
    normalizeInteger(transaction.nonce) !== transfer.fundingNonce ||
    normalizeInteger(transaction.valueWei) !== transfer.valueWei
  ) {
    fail("BILATERAL_FUNDING_AMBIGUOUS_RECOVERY");
  }
  if (
    transfer.transactionHash !== null &&
    transaction.hash !== transfer.transactionHash
  ) {
    fail("BILATERAL_FUNDING_REPLACED_TRANSACTION");
  }
  return transaction;
}

function validateReceipt(value, transfer, transaction, binding) {
  if (value === null || value === undefined) return null;
  const receipt = snapshotExactDataObject(
    value,
    ["chainId", "from", "nonce", "status", "to", "transactionHash", "valueWei"],
    "BILATERAL_FUNDING_AMBIGUOUS_RECOVERY",
  );
  if (receipt.status !== "success") {
    fail("BILATERAL_FUNDING_REVERTED_TRANSACTION");
  }
  if (
    !HASH_PATTERN.test(receipt.transactionHash) ||
    receipt.to !== transfer.address ||
    receipt.from !== binding.fundingAddress ||
    receipt.chainId !== binding.chainId ||
    normalizeInteger(receipt.nonce) !== transfer.fundingNonce ||
    normalizeInteger(receipt.valueWei) !== transfer.valueWei
  ) {
    fail("BILATERAL_FUNDING_AMBIGUOUS_RECOVERY");
  }
  if (transaction !== null && receipt.transactionHash !== transaction.hash) {
    fail("BILATERAL_FUNDING_REPLACED_TRANSACTION");
  }
  if (
    transfer.transactionHash !== null &&
    receipt.transactionHash !== transfer.transactionHash
  ) {
    fail("BILATERAL_FUNDING_REPLACED_TRANSACTION");
  }
  return receipt;
}

export function classifyFundingRecovery(value) {
  const input = snapshotExactDataObject(
    value,
    RECOVERY_INPUT_KEYS,
    "BILATERAL_FUNDING_AMBIGUOUS_RECOVERY",
  );
  const recoveryBinding = validateBinding(input.binding);
  const transfer = validateRecoveryTransfer(input.journalTransfer);
  if (!recoveryBinding.recipients.includes(transfer.address)) {
    fail("BILATERAL_FUNDING_AMBIGUOUS_RECOVERY");
  }
  const recipient = validateRecipientFact(input.recipientFact, transfer);
  if (BigInt(recipient.balanceWei) >= BigInt(recoveryBinding.targetBalanceWei)) {
    if (recipient.nonce !== "0") {
      fail("BILATERAL_FUNDING_RECIPIENT_NONCE_USED");
    }
    return "FUNDED";
  }
  if (transfer.state === "PLANNED") return "WAIT";

  const transaction = validateTransaction(
    input.nonceTransaction,
    transfer,
    recoveryBinding,
  );
  const foundReceipt = validateReceipt(
    input.receipt,
    transfer,
    transaction,
    recoveryBinding,
  );
  if (foundReceipt) return "FUNDED";
  if (transaction) {
    return transfer.state === "TRANSACTION_OBSERVED" ? "WAIT" : "OBSERVED";
  }
  fail("BILATERAL_FUNDING_DROPPED_TRANSACTION");
}

function validateRecoveryTransfer(value) {
  const transfer = snapshotExactDataObject(
    value,
    TRANSFER_KEYS,
    "BILATERAL_FUNDING_INVALID_TRANSFER",
  );
  if (transfer.state === "PLANNED") {
    validateAddress(transfer.address, "BILATERAL_FUNDING_INVALID_TRANSFER");
    validateWeiString(transfer.feeWei, "BILATERAL_FUNDING_INVALID_TRANSFER");
    validateDecimalIntegerString(
      transfer.fundingNonce,
      "BILATERAL_FUNDING_INVALID_TRANSFER",
    );
    validateWeiString(transfer.valueWei, "BILATERAL_FUNDING_INVALID_TRANSFER");
    if (
      !SHA256_PATTERN.test(transfer.transactionDigest) ||
      transfer.transactionHash !== null
    ) {
      fail("BILATERAL_FUNDING_INVALID_TRANSFER");
    }
    return Object.freeze({
      address: transfer.address,
      feeWei: transfer.feeWei,
      fundingNonce: transfer.fundingNonce,
      state: "PLANNED",
      transactionDigest: transfer.transactionDigest,
      transactionHash: null,
      valueWei: transfer.valueWei,
    });
  }
  return validateTransfer(transfer);
}
