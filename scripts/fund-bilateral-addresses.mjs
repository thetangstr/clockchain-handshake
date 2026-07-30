#!/usr/bin/env node

import { createHash } from "node:crypto";
import { constants as fsConstants } from "node:fs";
import { lstat, open, rename, unlink } from "node:fs/promises";
import { dirname, isAbsolute, join } from "node:path";
import { execFile } from "node:child_process";
import { promisify } from "node:util";

import {
  createPublicClient,
  createWalletClient,
  http,
} from "viem";
import { sepolia } from "viem/chains";

import {
  BilateralFundingError,
  PARTICIPANT_MAXIMUM_WEI,
  PARTICIPANT_MINIMUM_WEI,
  PARTICIPANT_TARGET_WEI,
  planFundingTransfers,
  validateFundingRecord,
} from "../src/bilateral/funding/record.mjs";
import { openFundingWallet } from "../src/bilateral/funding/keystore.mjs";
import {
  classifyFundingRecovery,
  deriveFundingBatchId,
  openFundingJournal,
} from "../src/bilateral/funding/journal.mjs";

export const FUNDING_CLI_FLAGS = Object.freeze([
  "--funding-record",
  "--journal-directory",
  "--keystore",
  "--rpc-url-file",
]);

const execFileAsync = promisify(execFile);
const SUMMARY_SCHEMA = "clockchain.bilateral-funding-summary/v1";
const HASH_PATTERN = /^0x[0-9a-f]{64}$/u;
const SHA_PATTERN = /^[0-9a-f]{40}$/u;
const ADDRESS_PATTERN = /^0x[0-9a-f]{40}$/u;
const PRIVATE_KEY_PATTERN = /^0x[0-9a-f]{64}$/u;
const MAX_RPC_FILE_BYTES = 2048;
const MAX_RECORD_FILE_BYTES = 4096;
const MAX_GAS = 100_000n;
const MAX_FEE_PER_GAS_WEI = 100_000_000_000n;
const MAX_PRIORITY_FEE_PER_GAS_WEI = 10_000_000_000n;
const READ_FLAGS =
  fsConstants.O_RDONLY |
  (fsConstants.O_NOFOLLOW ?? 0) |
  (fsConstants.O_NONBLOCK ?? 0);

function fail(code = "BILATERAL_FUNDING_INVALID_CLI") {
  throw new BilateralFundingError(code);
}

async function safely(operation) {
  try {
    return await operation();
  } catch (error) {
    if (error instanceof BilateralFundingError) throw error;
    fail("BILATERAL_FUNDING_RPC_FAILED");
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

function normalizeAddress(value, code = "BILATERAL_FUNDING_INVALID_CLIENT") {
  if (typeof value !== "string" || !/^0x[0-9a-fA-F]{40}$/u.test(value)) {
    fail(code);
  }
  const normalized = value.toLowerCase();
  if (normalized === "0x0000000000000000000000000000000000000000") {
    fail(code);
  }
  return normalized;
}

function normalizeQuantity(value, code = "BILATERAL_FUNDING_INVALID_CLIENT") {
  if (typeof value === "bigint" && value >= 0n) return value;
  if (typeof value === "number" && Number.isSafeInteger(value) && value >= 0) {
    return BigInt(value);
  }
  if (typeof value === "string" && /^(?:0|[1-9][0-9]*)$/u.test(value)) {
    return BigInt(value);
  }
  fail(code);
}

function metadataPathFor(keystorePath) {
  if (!keystorePath.endsWith(".json")) fail();
  return `${keystorePath.slice(0, -5)}.public.json`;
}

function rejectSecretLikePath(value) {
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    value.startsWith("--") ||
    !isAbsolute(value) ||
    ADDRESS_PATTERN.test(value) ||
    PRIVATE_KEY_PATTERN.test(value) ||
    /^[a-z][a-z0-9+.-]*:\/\//iu.test(value)
  ) {
    fail();
  }
}

function parseArguments(arguments_) {
  if (
    !Array.isArray(arguments_) ||
    arguments_.length !== FUNDING_CLI_FLAGS.length * 2
  ) {
    fail();
  }
  const parsed = {};
  for (let index = 0; index < FUNDING_CLI_FLAGS.length; index += 1) {
    const flag = arguments_[index * 2];
    const value = arguments_[index * 2 + 1];
    if (flag !== FUNDING_CLI_FLAGS[index] || Object.hasOwn(parsed, flag)) {
      fail();
    }
    rejectSecretLikePath(value);
    parsed[flag] = value;
  }
  return Object.freeze({
    fundingRecordPath: parsed["--funding-record"],
    journalDirectory: parsed["--journal-directory"],
    keystorePath: parsed["--keystore"],
    rpcUrlFile: parsed["--rpc-url-file"],
  });
}

function sameFile(left, right) {
  return left.dev === right.dev && left.ino === right.ino;
}

function validatePrivateFile(stats, maximum, code) {
  if (
    !stats.isFile() ||
    stats.isSymbolicLink() ||
    stats.nlink !== 1 ||
    (stats.mode & 0o777) !== 0o600 ||
    !Number.isSafeInteger(stats.size) ||
    stats.size < 0 ||
    stats.size > maximum
  ) {
    fail(code);
  }
}

async function readPrivateFile(path, maximum, code) {
  const before = await lstat(path).catch(() => fail(code));
  validatePrivateFile(before, maximum, code);
  let handle;
  try {
    handle = await open(path, READ_FLAGS);
    const opened = await handle.stat();
    validatePrivateFile(opened, maximum, code);
    if (!sameFile(before, opened)) fail(code);
    const bytes = await handle.readFile("utf8");
    const after = await lstat(path);
    validatePrivateFile(after, maximum, code);
    if (!sameFile(before, after)) fail(code);
    return bytes;
  } catch (error) {
    if (error instanceof BilateralFundingError) throw error;
    fail(code);
  } finally {
    await handle?.close().catch(() => {});
  }
}

function parseRpcUrl(bytes) {
  if (typeof bytes !== "string" || !bytes.endsWith("\n")) {
    fail("BILATERAL_FUNDING_INVALID_RPC");
  }
  const trimmed = bytes.slice(0, -1);
  if (trimmed.length === 0 || trimmed.includes("\n") || trimmed.includes("\r")) {
    fail("BILATERAL_FUNDING_INVALID_RPC");
  }
  let url;
  try {
    url = new URL(trimmed);
  } catch {
    fail("BILATERAL_FUNDING_INVALID_RPC");
  }
  if (
    url.protocol !== "https:" ||
    url.username !== "" ||
    url.password !== "" ||
    url.search !== "" ||
    url.hash !== "" ||
    url.hostname.length === 0
  ) {
    fail("BILATERAL_FUNDING_INVALID_RPC");
  }
  return trimmed;
}

async function defaultRepositorySha() {
  const [head, status] = await Promise.all([
    execFileAsync("git", ["rev-parse", "HEAD"], {
      encoding: "utf8",
      maxBuffer: 4096,
    }),
    execFileAsync("git", ["status", "--porcelain=v1"], {
      encoding: "utf8",
      maxBuffer: 1024 * 1024,
    }),
  ]).catch(() => fail("BILATERAL_FUNDING_DIRTY_REPOSITORY"));
  if (status.stdout !== "") fail("BILATERAL_FUNDING_DIRTY_REPOSITORY");
  const sha = head.stdout.trim();
  if (!SHA_PATTERN.test(sha)) fail("BILATERAL_FUNDING_DIRTY_REPOSITORY");
  return sha;
}

function createProductionClients({ account, rpcUrl }) {
  return Object.freeze({
    publicClient: createPublicClient({
      chain: sepolia,
      transport: http(rpcUrl, { retryCount: 0, timeout: 15_000 }),
    }),
    walletClient: createWalletClient({
      account,
      chain: sepolia,
      transport: http(rpcUrl, { retryCount: 0, timeout: 15_000 }),
    }),
  });
}

async function participantFacts(publicClient, addresses) {
  const facts = [];
  for (const address of addresses) {
    const [balanceWei, nonce] = await Promise.all([
      safely(() => publicClient.getBalance({ address })),
      safely(() => publicClient.getTransactionCount({ address, blockTag: "latest" })),
    ]);
    facts.push(Object.freeze({
      address,
      balanceWei: normalizeQuantity(balanceWei),
      nonce: normalizeQuantity(nonce),
    }));
  }
  return Object.freeze(facts);
}

async function fundingFacts(publicClient, fundingAddress) {
  const [fundingBalanceWei, fundingNonce] = await Promise.all([
    safely(() => publicClient.getBalance({ address: fundingAddress })),
    safely(() =>
      publicClient.getTransactionCount({
        address: fundingAddress,
        blockTag: "pending",
      }),
    ),
  ]);
  return Object.freeze({
    fundingBalanceWei: normalizeQuantity(fundingBalanceWei),
    fundingNonce: normalizeQuantity(fundingNonce),
  });
}

async function feeEnvelope(publicClient, account, firstTransfer) {
  if (!firstTransfer) return null;
  const [gasResult, fees] = await Promise.all([
    safely(() =>
      publicClient.estimateGas({
        account,
        to: firstTransfer.address,
        value: firstTransfer.valueWei,
      }),
    ),
    safely(() => publicClient.estimateFeesPerGas()),
  ]);
  const gas = normalizeQuantity(gasResult, "BILATERAL_FUNDING_UNBOUNDED_FEE");
  const maxFeePerGas = normalizeQuantity(
    fees?.maxFeePerGas,
    "BILATERAL_FUNDING_UNBOUNDED_FEE",
  );
  const maxPriorityFeePerGas = normalizeQuantity(
    fees?.maxPriorityFeePerGas,
    "BILATERAL_FUNDING_UNBOUNDED_FEE",
  );
  if (
    gas <= 0n ||
    gas > MAX_GAS ||
    maxFeePerGas <= 0n ||
    maxFeePerGas > MAX_FEE_PER_GAS_WEI ||
    maxPriorityFeePerGas > MAX_PRIORITY_FEE_PER_GAS_WEI ||
    maxPriorityFeePerGas > maxFeePerGas
  ) {
    fail("BILATERAL_FUNDING_UNBOUNDED_FEE");
  }
  return Object.freeze({
    feePerTransferWei: gas * maxFeePerGas,
    gas,
    maxFeePerGas,
    maxPriorityFeePerGas,
  });
}

function transactionDigest(transaction) {
  return createHash("sha256")
    .update(canonicalJson({
      chainId: 11155111,
      from: transaction.from,
      gas: transaction.gas.toString(),
      maxFeePerGas: transaction.maxFeePerGas.toString(),
      maxPriorityFeePerGas: transaction.maxPriorityFeePerGas.toString(),
      nonce: transaction.nonce.toString(),
      to: transaction.to,
      valueWei: transaction.value.toString(),
    }))
    .digest("hex");
}

function bindingFor({ fundingAddress, record, repositorySha, rpcEndpointSha256 }) {
  const publicBinding = {
    chainId: 11155111,
    fundingAddress,
    paymentMoved: false,
    recipients: [...record.addresses],
    repositorySha,
    rpcEndpointSha256,
    targetBalanceWei: PARTICIPANT_TARGET_WEI.toString(),
  };
  return Object.freeze({
    batchId: deriveFundingBatchId(publicBinding),
    ...publicBinding,
  });
}

async function findNonceTransaction(publicClient, transfer, fundingAddress) {
  if (transfer.transactionHash !== null) {
    return normalizeTransaction(
      await safely(() => publicClient.getTransaction({ hash: transfer.transactionHash })),
      fundingAddress,
    );
  }
  if (typeof publicClient.getTransactionBySenderNonce === "function") {
    return normalizeTransaction(
      await safely(() =>
        publicClient.getTransactionBySenderNonce({
          from: fundingAddress,
          nonce: Number(transfer.fundingNonce),
          to: transfer.address,
        }),
      ),
      fundingAddress,
    );
  }
  return null;
}

async function readReceipt(publicClient, transfer) {
  if (transfer.transactionHash === null) return null;
  if (typeof publicClient.getTransactionReceipt === "function") {
    const receipt = await safely(() =>
      publicClient.getTransactionReceipt({
        hash: transfer.transactionHash,
      }),
    );
    if (receipt === null || receipt === undefined) return null;
    return {
      chainId: 11155111,
      from: normalizeAddress(receipt.from),
      nonce: transfer.fundingNonce,
      status: receipt.status,
      to: normalizeAddress(receipt.to),
      transactionHash: receipt.transactionHash,
      valueWei: transfer.valueWei,
    };
  }
  return null;
}

function normalizeTransaction(value) {
  if (value === null || value === undefined) return null;
  if (value === null || typeof value !== "object") {
    fail("BILATERAL_FUNDING_INVALID_CLIENT");
  }
  return Object.freeze({
    chainId: value.chainId,
    from: normalizeAddress(value.from),
    hash: value.hash,
    nonce: normalizeQuantity(value.nonce).toString(),
    to: normalizeAddress(value.to),
    valueWei: normalizeQuantity(value.valueWei ?? value.value).toString(),
  });
}

function normalizeReceipt(value) {
  if (value === null || typeof value !== "object") {
    fail("BILATERAL_FUNDING_INVALID_CLIENT");
  }
  return Object.freeze({
    from: normalizeAddress(value.from),
    status: value.status,
    to: normalizeAddress(value.to),
    transactionHash: value.transactionHash,
  });
}

async function recoverJournal({
  binding,
  journal,
  publicClient,
}) {
  let current = journal;
  for (const transfer of current.document.transfers) {
    if (transfer.state === "FUNDED") continue;
    const [recipientFact, nonceTransaction, receipt] = await Promise.all([
      participantFacts(publicClient, [transfer.address]).then(([fact]) => fact),
      findNonceTransaction(publicClient, transfer, binding.fundingAddress),
      readReceipt(publicClient, transfer),
    ]);
    const classification = classifyFundingRecovery({
      binding,
      journalTransfer: transfer,
      nonceTransaction,
      receipt,
      recipientFact,
    });
    if (classification === "OBSERVED") {
      current = await current.recordTransactionObserved({
        address: transfer.address,
        fundingNonce: transfer.fundingNonce,
        transactionHash: nonceTransaction.hash,
      });
      continue;
    }
    if (classification === "FUNDED") {
      const hash = receipt?.transactionHash ?? nonceTransaction?.hash ?? transfer.transactionHash;
      let observed = current;
      if (hash && transfer.transactionHash === null) {
        observed = await current.recordTransactionObserved({
          address: transfer.address,
          fundingNonce: transfer.fundingNonce,
          transactionHash: hash,
        });
      }
      current = await observed.recordFunded({
        address: transfer.address,
        fundingNonce: transfer.fundingNonce,
      });
    }
  }
  return current;
}

function transferKey(transfer) {
  return `${transfer.address}:${transfer.fundingNonce}`;
}

function validateFundingNonceAgainstJournal(journal, fundingNonce) {
  const maximumRecordedNonce = journal.document.transfers.reduce(
    (maximum, transfer) =>
      BigInt(transfer.fundingNonce) > maximum
        ? BigInt(transfer.fundingNonce)
        : maximum,
    -1n,
  );
  if (maximumRecordedNonce >= 0n && fundingNonce <= maximumRecordedNonce) {
    fail("BILATERAL_FUNDING_NONCE_CONFLICT");
  }
}

function assertNoUnresolvedJournalTransfers(journal) {
  if (journal.document.transfers.some((transfer) => transfer.state !== "FUNDED")) {
    fail("BILATERAL_FUNDING_AMBIGUOUS_RECOVERY");
  }
}

function validatedReceipt(receipt, transaction) {
  const normalizedReceipt = normalizeReceipt(receipt);
  const normalizedTransaction = normalizeTransaction(transaction, transaction.from);
  if (
    normalizedReceipt.status !== "success" ||
    normalizedReceipt.transactionHash !== normalizedTransaction.hash ||
    normalizedReceipt.from !== normalizedTransaction.from ||
    normalizedReceipt.to !== normalizedTransaction.to ||
    normalizedTransaction.chainId !== 11155111
  ) {
    fail("BILATERAL_FUNDING_REVERTED_TRANSACTION");
  }
  return normalizedTransaction;
}

async function persistJournalDocument(path, document) {
  const directory = dirname(path);
  const temporary = join(
    directory,
    `.funding-journal.tmp-${process.pid}-${Date.now()}-${Math.random()
      .toString(16)
      .slice(2)}`,
  );
  let handle;
  try {
    handle = await open(
      temporary,
      fsConstants.O_WRONLY |
        fsConstants.O_CREAT |
        fsConstants.O_EXCL |
        (fsConstants.O_NOFOLLOW ?? 0),
      0o600,
    );
    await handle.writeFile(canonicalJson(document));
    await handle.chmod(0o600);
    await handle.sync();
    await handle.close();
    handle = null;
    await rename(temporary, path);
    const directoryHandle = await open(
      directory,
      fsConstants.O_RDONLY |
        fsConstants.O_DIRECTORY |
        (fsConstants.O_NOFOLLOW ?? 0),
    );
    try {
      await directoryHandle.sync();
    } finally {
      await directoryHandle.close();
    }
  } catch (error) {
    await handle?.close().catch(() => {});
    await unlink(temporary).catch(() => {});
    if (error instanceof BilateralFundingError) throw error;
    fail("BILATERAL_FUNDING_WRITE_FAILED");
  }
  return document;
}

async function appendBroadcastIntent(journal, transfer) {
  const state = journal.document.transfers.some(
    (candidate) => candidate.state === "FUNDED",
  )
    ? "FUNDED"
    : "BROADCAST_INTENT";
  const document = {
    ...journal.document,
    state,
    transfers: [...journal.document.transfers, transfer],
  };
  await persistJournalDocument(journal.path, document);
  return openFundingJournal({
    binding: journal.document.binding,
    journalDirectory: dirname(journal.path),
  });
}

async function sendPlannedTransfers({
  account,
  binding,
  journal,
  plan,
  publicClient,
  walletClient,
  envelope,
}) {
  let current = journal;
  for (const planned of plan.transfers) {
    const key = transferKey({
      address: planned.address,
      fundingNonce: planned.fundingNonce.toString(),
    });
    const existing = current.document.transfers.find(
      (transfer) => transferKey(transfer) === key,
    );
    if (existing?.state === "FUNDED") continue;
    if (existing && existing.state !== "BROADCAST_INTENT") continue;
    const transaction = {
      account,
      chain: sepolia,
      from: binding.fundingAddress,
      gas: envelope.gas,
      maxFeePerGas: envelope.maxFeePerGas,
      maxPriorityFeePerGas: envelope.maxPriorityFeePerGas,
      nonce: Number(planned.fundingNonce),
      to: planned.address,
      value: planned.valueWei,
    };
    const intent = {
      address: planned.address,
      feeWei: envelope.feePerTransferWei.toString(),
      fundingNonce: planned.fundingNonce.toString(),
      state: "BROADCAST_INTENT",
      transactionDigest: transactionDigest(transaction),
      transactionHash: null,
      valueWei: planned.valueWei.toString(),
    };
    current = existing
      ? current
      : await appendBroadcastIntent(current, intent);
    const hash = await safely(() => walletClient.sendTransaction(transaction));
    if (!HASH_PATTERN.test(hash)) fail("BILATERAL_FUNDING_INVALID_CLIENT");
    current = await current.recordTransactionObserved({
      address: planned.address,
      fundingNonce: planned.fundingNonce.toString(),
      transactionHash: hash,
    });
    const receipt = await safely(() => publicClient.waitForTransactionReceipt({ hash }));
    const observedTransaction = await safely(() => publicClient.getTransaction({ hash }));
    const transactionFacts = validatedReceipt(receipt, {
      chainId: 11155111,
      from: binding.fundingAddress,
      hash,
      nonce: planned.fundingNonce.toString(),
      to: planned.address,
      valueWei: planned.valueWei.toString(),
    });
    if (
      transactionFacts.nonce !== planned.fundingNonce.toString() ||
      transactionFacts.valueWei !== planned.valueWei.toString()
    ) {
      fail("BILATERAL_FUNDING_REVERTED_TRANSACTION");
    }
    validatedReceipt(receipt, observedTransaction);
    const [recipient] = await participantFacts(publicClient, [planned.address]);
    if (
      recipient.balanceWei < PARTICIPANT_MINIMUM_WEI ||
      recipient.balanceWei > PARTICIPANT_MAXIMUM_WEI ||
      recipient.nonce !== 0n
    ) {
      fail("BILATERAL_FUNDING_FINAL_VALIDATION_FAILED");
    }
    current = await current.recordFunded({
      address: planned.address,
      fundingNonce: planned.fundingNonce.toString(),
    });
  }
  return current;
}

async function finalSummary({ binding, journal, plan, publicClient }) {
  const facts = await participantFacts(publicClient, binding.recipients);
  for (const fact of facts) {
    if (
      fact.balanceWei < PARTICIPANT_MINIMUM_WEI ||
      fact.balanceWei > PARTICIPANT_MAXIMUM_WEI ||
      fact.nonce !== 0n
    ) {
      fail("BILATERAL_FUNDING_FINAL_VALIDATION_FAILED");
    }
  }
  return Object.freeze({
    adopted: Object.freeze([...plan.adopted]),
    batchId: binding.batchId,
    fundingAddress: binding.fundingAddress,
    journalPath: journal.path,
    paymentMoved: false,
    repositorySha: binding.repositorySha,
    rpcEndpointSha256: binding.rpcEndpointSha256,
    schema: SUMMARY_SCHEMA,
    transfers: Object.freeze(journal.document.transfers.map((transfer) =>
      Object.freeze({
        address: transfer.address,
        fundingNonce: transfer.fundingNonce,
        transactionHash: transfer.transactionHash,
        valueWei: transfer.valueWei,
      }),
    )),
  });
}

async function runMain(arguments_ = process.argv.slice(2), dependencies = {}) {
  const parsed = parseArguments(arguments_);
  const getRepositorySha = dependencies.getRepositorySha ?? defaultRepositorySha;
  const repositorySha = await getRepositorySha();
  if (!SHA_PATTERN.test(repositorySha)) {
    fail("BILATERAL_FUNDING_DIRTY_REPOSITORY");
  }

  const [recordBytes, rpcBytes] = await Promise.all([
    readPrivateFile(
      parsed.fundingRecordPath,
      MAX_RECORD_FILE_BYTES,
      "BILATERAL_FUNDING_INVALID_RECORD",
    ),
    readPrivateFile(
      parsed.rpcUrlFile,
      MAX_RPC_FILE_BYTES,
      "BILATERAL_FUNDING_INVALID_RPC",
    ),
  ]);
  const record = validateFundingRecord(JSON.parse(recordBytes));
  const rpcUrl = parseRpcUrl(rpcBytes);
  const rpcEndpointSha256 = createHash("sha256").update(rpcUrl).digest("hex");

  const walletOpener = dependencies.openFundingWallet ?? openFundingWallet;
  const wallet = await walletOpener({
    keystorePath: parsed.keystorePath,
    metadataPath: metadataPathFor(parsed.keystorePath),
  });
  const fundingAddress = normalizeAddress(wallet.metadata?.fundingAddress);
  if (
    wallet.metadata?.chainId !== 11155111 ||
    normalizeAddress(wallet.account?.address) !== fundingAddress
  ) {
    fail("BILATERAL_FUNDING_INVALID_WALLET");
  }
  const createClients = dependencies.createClients ?? createProductionClients;
  const { publicClient, walletClient } = await createClients({
    account: wallet.account,
    rpcUrl,
  });
  if ((await publicClient.getChainId()) !== 11155111) {
    fail("BILATERAL_FUNDING_WRONG_CHAIN");
  }

  const binding = bindingFor({
    fundingAddress,
    record,
    repositorySha,
    rpcEndpointSha256,
  });
  let journal = await openFundingJournal({
    binding,
    journalDirectory: parsed.journalDirectory,
  });
  journal = await recoverJournal({ binding, journal, publicClient });
  assertNoUnresolvedJournalTransfers(journal);

  const [participants, funding] = await Promise.all([
    participantFacts(publicClient, record.addresses),
    fundingFacts(publicClient, fundingAddress),
  ]);
  validateFundingNonceAgainstJournal(journal, funding.fundingNonce);
  const initialPlan = planFundingTransfers({
    feePerTransferWei: 0n,
    fundingBalanceWei: funding.fundingBalanceWei,
    fundingNonce: funding.fundingNonce,
    participantFacts: participants,
    record,
  });
  const envelope = await feeEnvelope(
    publicClient,
    wallet.account,
    initialPlan.transfers[0],
  );
  const plan = envelope
    ? planFundingTransfers({
        feePerTransferWei: envelope.feePerTransferWei,
        fundingBalanceWei: funding.fundingBalanceWei,
        fundingNonce: funding.fundingNonce,
        participantFacts: participants,
        record,
      })
    : initialPlan;

  journal = await sendPlannedTransfers({
    account: wallet.account,
    binding,
    journal,
    plan,
    publicClient,
    walletClient,
    envelope,
  });
  const summary = await finalSummary({ binding, journal, plan, publicClient });
  (dependencies.stdout ?? ((line) => process.stdout.write(line)))(
    `${canonicalJson(summary)}\n`,
  );
  return summary;
}

export async function main(arguments_ = process.argv.slice(2), dependencies = {}) {
  try {
    return await runMain(arguments_, dependencies);
  } catch (error) {
    if (error instanceof BilateralFundingError) throw error;
    fail("BILATERAL_FUNDING_RPC_FAILED");
  }
}

if (import.meta.url === `file://${process.argv[1]}`) {
  main().catch((error) => {
    const message = error instanceof BilateralFundingError
      ? error.message
      : "Bilateral funding failed safely.";
    process.stderr.write(`${message}\n`);
    process.exitCode = 1;
  });
}
