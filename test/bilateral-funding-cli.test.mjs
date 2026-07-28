import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { chmod, mkdtemp, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { isAbsolute, join } from "node:path";
import test from "node:test";
import { promisify } from "node:util";

import { BilateralFundingError } from "../src/bilateral/funding/record.mjs";
import {
  FUNDING_CLI_FLAGS,
  main,
} from "../scripts/fund-bilateral-addresses.mjs";

const FUNDING_ADDRESS = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const RECIPIENTS = Object.freeze([
  "0x1111111111111111111111111111111111111111",
  "0x2222222222222222222222222222222222222222",
  "0x3333333333333333333333333333333333333333",
  "0x4444444444444444444444444444444444444444",
]);
const REPOSITORY_SHA = "abcdef0123456789abcdef0123456789abcdef01";
const RPC_URL = "https://sepolia.example.invalid/rpc";
const RPC_DIGEST =
  "1d308186f1aab99d82ee000a298dabe1f21555d26fef32d6514f1e89fff7d4c7";
const execFileAsync = promisify(execFile);

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

async function privatePath(name, bytes) {
  const root = await mkdtemp(join(tmpdir(), "funding-cli-"));
  await chmod(root, 0o700);
  const path = join(root, name);
  await writeFile(path, bytes, { mode: 0o600 });
  return { path, root };
}

async function fixture(overrides = {}) {
  const record = overrides.record ?? {
    addresses: [...RECIPIENTS],
    paymentMoved: false,
    schema: "clockchain.bilateral-funding-addresses/v1",
  };
  const recordFile = await privatePath("funding-addresses.json", `${JSON.stringify(record)}\n`);
  const rpcFile = await privatePath("rpc-url", `${overrides.rpcUrl ?? RPC_URL}\n`);
  const keystoreFile = await privatePath("funding-wallet.json", "{}");
  await writeFile(`${keystoreFile.path.slice(0, -5)}.public.json`, "{}", {
    mode: 0o600,
  });
  const journalDirectory = await mkdtemp(join(tmpdir(), "funding-cli-journal-"));
  await chmod(journalDirectory, 0o700);
  return {
    arguments_: [
      "--funding-record",
      recordFile.path,
      "--journal-directory",
      journalDirectory,
      "--keystore",
      keystoreFile.path,
      "--rpc-url-file",
      rpcFile.path,
    ],
    journalDirectory,
    keystorePath: keystoreFile.path,
    recordPath: recordFile.path,
    rpcUrlFile: rpcFile.path,
  };
}

function fundingWallet() {
  return {
    account: {
      address: FUNDING_ADDRESS,
    },
    metadata: {
      chainId: 11155111,
      fundingAddress: FUNDING_ADDRESS,
    },
  };
}

function makeClients({
  balances = RECIPIENTS.map(() => 0n),
  fundingBalance = 100_000_000_000_000_000n,
  fundingNonce = 7,
  receiptStatus = "success",
  viemReceipt = false,
} = {}) {
  const calls = [];
  const mutableBalances = [...balances];
  let mutableFundingBalance = fundingBalance;
  let mutableFundingNonce = fundingNonce;
  const transactions = new Map();
  const publicClient = {
    async getBalance({ address }) {
      calls.push(["getBalance", address]);
      if (address === FUNDING_ADDRESS) return mutableFundingBalance;
      return mutableBalances[RECIPIENTS.indexOf(address)];
    },
    async getTransactionCount({ address }) {
      calls.push(["getTransactionCount", address]);
      if (address === FUNDING_ADDRESS) return mutableFundingNonce;
      return 0;
    },
    async getChainId() {
      calls.push(["getChainId"]);
      return 11155111;
    },
    async estimateGas(transaction) {
      calls.push(["estimateGas", transaction.to, transaction.value]);
      return 21_000n;
    },
    async estimateFeesPerGas() {
      calls.push(["estimateFeesPerGas"]);
      return {
        maxFeePerGas: 1_000_000_000n,
        maxPriorityFeePerGas: 100_000_000n,
      };
    },
    async getTransactionBySenderNonce({ from, nonce }) {
      calls.push(["getTransactionBySenderNonce", from, nonce]);
      return [...transactions.values()].find(
        (transaction) => transaction.from === from && transaction.nonce === nonce,
      ) ?? null;
    },
    async getTransaction({ hash }) {
      calls.push(["getTransaction", hash]);
      const transaction = transactions.get(hash);
      if (!transaction) return null;
      return viemReceipt
        ? {
            chainId: transaction.chainId,
            from: transaction.from,
            hash: transaction.hash,
            nonce: transaction.nonce,
            to: transaction.to,
            value: transaction.valueWei,
          }
        : transaction;
    },
    async waitForTransactionReceipt({ hash }) {
      calls.push(["waitForTransactionReceipt", hash]);
      const transaction = transactions.get(hash);
      if (receiptStatus === "success") {
        const recipientIndex = RECIPIENTS.indexOf(transaction.to);
        mutableBalances[recipientIndex] += transaction.valueWei;
        mutableFundingBalance -= transaction.valueWei;
        mutableFundingNonce = Math.max(mutableFundingNonce, transaction.nonce + 1);
      }
      if (viemReceipt) {
        return {
          from: FUNDING_ADDRESS,
          status: receiptStatus,
          to: transaction.to,
          transactionHash: hash,
        };
      }
      return {
        chainId: 11155111,
        from: FUNDING_ADDRESS,
        nonce: transaction.nonce,
        status: receiptStatus,
        to: transaction.to,
        transactionHash: hash,
        valueWei: transaction.valueWei,
      };
    },
  };
  const walletClient = {
    async sendTransaction(transaction) {
      calls.push(["sendTransaction", transaction.to, transaction.nonce]);
      const hash = `0x${String(transactions.size + 1).repeat(64)}`;
      transactions.set(hash, {
        chainId: 11155111,
        from: FUNDING_ADDRESS,
        hash,
        nonce: transaction.nonce,
        to: transaction.to,
        valueWei: transaction.value,
      });
      return hash;
    },
  };
  return { calls, publicClient, walletClient };
}

function sendCrashClients() {
  const clients = makeClients();
  return {
    calls: clients.calls,
    publicClient: clients.publicClient,
    walletClient: {
      async sendTransaction() {
        clients.calls.push(["sendTransaction", RECIPIENTS[0], 7]);
        throw new Error("crash after first intent");
      },
    },
  };
}

async function runFixture(fixture_, clients, overrides = {}) {
  const output = [];
  return main(fixture_.arguments_, {
    createClients: async () => ({
      publicClient: clients.publicClient,
      walletClient: clients.walletClient,
    }),
    getRepositorySha: async () => REPOSITORY_SHA,
    now: () => "2026-07-28T10:00:00.000Z",
    openFundingWallet: async (options) => {
      assert.equal(options.keystorePath, fixture_.keystorePath);
      assert.equal(options.metadataPath, `${fixture_.keystorePath.slice(0, -5)}.public.json`);
      return fundingWallet();
    },
    stdout: (line) => output.push(line),
    ...overrides,
  }).then((summary) => ({ output, summary }));
}

test("exports the exact path-only funding CLI flags", () => {
  assert.deepEqual(FUNDING_CLI_FLAGS, [
    "--funding-record",
    "--journal-directory",
    "--keystore",
    "--rpc-url-file",
  ]);
  assert.ok(Object.isFrozen(FUNDING_CLI_FLAGS));
});

test("rejects non-exact startup arguments before opening secrets or RPC clients", async () => {
  const fixture_ = await fixture();
  const invalidArguments = [
    [],
    fixture_.arguments_.slice(0, -1),
    [...fixture_.arguments_, "--extra", fixture_.recordPath],
    ["--journal-directory", fixture_.journalDirectory, "--funding-record", fixture_.recordPath, "--keystore", fixture_.keystorePath, "--rpc-url-file", fixture_.rpcUrlFile],
    ["--funding-record", fixture_.recordPath, "--funding-record", fixture_.recordPath, "--keystore", fixture_.keystorePath, "--rpc-url-file", fixture_.rpcUrlFile],
    ["--funding-record", "", "--journal-directory", fixture_.journalDirectory, "--keystore", fixture_.keystorePath, "--rpc-url-file", fixture_.rpcUrlFile],
    ["--funding-record", "--journal-directory", "--journal-directory", fixture_.journalDirectory, "--keystore", fixture_.keystorePath, "--rpc-url-file", fixture_.rpcUrlFile],
    ["--funding-record", "relative.json", "--journal-directory", fixture_.journalDirectory, "--keystore", fixture_.keystorePath, "--rpc-url-file", fixture_.rpcUrlFile],
    ["--funding-record", RECIPIENTS[0], "--journal-directory", fixture_.journalDirectory, "--keystore", fixture_.keystorePath, "--rpc-url-file", fixture_.rpcUrlFile],
    ["--funding-record", `0x${"1".repeat(64)}`, "--journal-directory", fixture_.journalDirectory, "--keystore", fixture_.keystorePath, "--rpc-url-file", fixture_.rpcUrlFile],
    ["--funding-record", "https://sepolia.example.invalid/rpc", "--journal-directory", fixture_.journalDirectory, "--keystore", fixture_.keystorePath, "--rpc-url-file", fixture_.rpcUrlFile],
  ];

  for (const arguments_ of invalidArguments) {
    await assert.rejects(
      main(arguments_, {
        createClients: async () => assert.fail("must not create clients"),
        getRepositorySha: async () => assert.fail("must not read git"),
        openFundingWallet: async () => assert.fail("must not open wallet"),
      }),
      BilateralFundingError,
    );
  }
});

test("requires a clean repository SHA and a strict private HTTPS RPC URL file", async () => {
  const fixture_ = await fixture();
  const clients = makeClients();

  await assert.rejects(
    runFixture(fixture_, clients, { getRepositorySha: async () => "dirty" }),
    BilateralFundingError,
  );

  const rawUrlFixture = await fixture({ rpcUrl: "https://user:pass@sepolia.example.invalid/rpc" });
  await assert.rejects(runFixture(rawUrlFixture, clients), BilateralFundingError);

  const queryFixture = await fixture({ rpcUrl: "https://sepolia.example.invalid/rpc?key=secret" });
  await assert.rejects(runFixture(queryFixture, clients), BilateralFundingError);

  const httpFixture = await fixture({ rpcUrl: "http://sepolia.example.invalid/rpc" });
  await assert.rejects(runFixture(httpFixture, clients), BilateralFundingError);

  assert.ok(isAbsolute(fixture_.rpcUrlFile));
});

test("sends no transactions when all four recipients are already inside the admission band", async () => {
  const fixture_ = await fixture();
  const clients = makeClients({
    balances: RECIPIENTS.map(() => 5_000_000_000_000_000n),
  });
  const { output, summary } = await runFixture(fixture_, clients);

  assert.equal(clients.calls.some(([method]) => method === "sendTransaction"), false);
  assert.equal(output.length, 1);
  assert.equal(output[0], `${canonicalJson(summary)}\n`);
  assert.deepEqual(summary, {
    adopted: [...RECIPIENTS],
    batchId: summary.batchId,
    fundingAddress: FUNDING_ADDRESS,
    journalPath: join(fixture_.journalDirectory, "funding-journal.json"),
    paymentMoved: false,
    repositorySha: REPOSITORY_SHA,
    rpcEndpointSha256: RPC_DIGEST,
    schema: "clockchain.bilateral-funding-summary/v1",
    transfers: [],
  });
});

test("tops up below-floor recipients sequentially with durable intent before each send", async () => {
  const fixture_ = await fixture();
  const clients = makeClients({
    balances: [
      0n,
      6_000_000_000_000_000n,
      4_000_000_000_000_000n,
      20_000_000_000_000_000n,
    ],
  });
  const { summary } = await runFixture(fixture_, clients);
  const journal = JSON.parse(await readFile(join(fixture_.journalDirectory, "funding-journal.json"), "utf8"));

  assert.deepEqual(
    clients.calls.filter(([method]) => ["sendTransaction", "waitForTransactionReceipt", "getTransaction"].includes(method)),
    [
      ["sendTransaction", RECIPIENTS[0], 7],
      ["waitForTransactionReceipt", `0x${"1".repeat(64)}`],
      ["getTransaction", `0x${"1".repeat(64)}`],
      ["sendTransaction", RECIPIENTS[2], 8],
      ["waitForTransactionReceipt", `0x${"2".repeat(64)}`],
      ["getTransaction", `0x${"2".repeat(64)}`],
    ],
  );
  assert.deepEqual(journal.transfers.map(({ address, fundingNonce, state, transactionHash, valueWei }) => ({
    address,
    fundingNonce,
    state,
    transactionHash,
    valueWei,
  })), [
    {
      address: RECIPIENTS[0],
      fundingNonce: "7",
      state: "FUNDED",
      transactionHash: `0x${"1".repeat(64)}`,
      valueWei: "10000000000000000",
    },
    {
      address: RECIPIENTS[2],
      fundingNonce: "8",
      state: "FUNDED",
      transactionHash: `0x${"2".repeat(64)}`,
      valueWei: "6000000000000000",
    },
  ]);
  assert.deepEqual(summary.transfers, [
    {
      address: RECIPIENTS[0],
      fundingNonce: "7",
      transactionHash: `0x${"1".repeat(64)}`,
      valueWei: "10000000000000000",
    },
    {
      address: RECIPIENTS[2],
      fundingNonce: "8",
      transactionHash: `0x${"2".repeat(64)}`,
      valueWei: "6000000000000000",
    },
  ]);

  assert.equal(journal.state, "FUNDED");
});

test("uses viem-shaped receipts plus fetched transactions for exact nonce value and chain validation", async () => {
  const fixture_ = await fixture();
  const clients = makeClients({
    balances: [
      0n,
      6_000_000_000_000_000n,
      4_000_000_000_000_000n,
      20_000_000_000_000_000n,
    ],
    viemReceipt: true,
  });

  await runFixture(fixture_, clients);

  assert.deepEqual(
    clients.calls.filter(([method]) => ["waitForTransactionReceipt", "getTransaction"].includes(method)),
    [
      ["waitForTransactionReceipt", `0x${"1".repeat(64)}`],
      ["getTransaction", `0x${"1".repeat(64)}`],
      ["waitForTransactionReceipt", `0x${"2".repeat(64)}`],
      ["getTransaction", `0x${"2".repeat(64)}`],
    ],
  );
});

test("persists only the active recipient intent when the first send fails", async () => {
  const fixture_ = await fixture();
  const clients = sendCrashClients();

  await assert.rejects(
    runFixture(fixture_, clients),
    BilateralFundingError,
  );

  const journal = JSON.parse(await readFile(join(fixture_.journalDirectory, "funding-journal.json"), "utf8"));
  assert.deepEqual(journal.transfers.map(({ address, fundingNonce, state, transactionHash }) => ({
    address,
    fundingNonce,
    state,
    transactionHash,
  })), [
    {
      address: RECIPIENTS[0],
      fundingNonce: "7",
      state: "BROADCAST_INTENT",
      transactionHash: null,
    },
  ]);
});

test("discovers durable journal state before recovery and never broadcasts twice for one intent", async () => {
  const fixture_ = await fixture();
  const firstClients = makeClients();
  await assert.rejects(
    runFixture(fixture_, firstClients, {
      createClients: async () => ({
        publicClient: firstClients.publicClient,
        walletClient: {
          async sendTransaction() {
            throw new Error("crash after durable intent");
          },
        },
      }),
    }),
    BilateralFundingError,
  );

  const secondClients = makeClients();
  await assert.rejects(runFixture(fixture_, secondClients), BilateralFundingError);
  assert.equal(secondClients.calls.some(([method]) => method === "sendTransaction"), false);
  assert.equal(
    secondClients.calls.some(([method]) => method === "getTransactionBySenderNonce"),
    true,
  );
});

test("top-level CLI output never includes arbitrary thrown RPC or client messages", async () => {
  const { stderr } = await execFileAsync(
    process.execPath,
    ["scripts/fund-bilateral-addresses.mjs", "--funding-record", "/tmp/not-present"],
    { encoding: "utf8" },
  ).catch((error) => error);

  assert.equal(stderr, "Bilateral funding failed safely.\n");
});

test("aborts on wrong chain, insufficient balance, funding nonce conflicts, changed RPC binding, and failed receipts", async () => {
  const wrongChainFixture = await fixture();
  const wrongChainClients = makeClients();
  wrongChainClients.publicClient.getChainId = async () => 1;
  await assert.rejects(runFixture(wrongChainFixture, wrongChainClients), BilateralFundingError);

  const insufficientFixture = await fixture();
  await assert.rejects(
    runFixture(insufficientFixture, makeClients({ fundingBalance: 1n })),
    BilateralFundingError,
  );

  const failedReceiptFixture = await fixture();
  await assert.rejects(
    runFixture(failedReceiptFixture, makeClients({ receiptStatus: "reverted" })),
    BilateralFundingError,
  );

  const conflictFixture = await fixture();
  const conflictClients = makeClients({ fundingNonce: 8 });
  await runFixture(conflictFixture, makeClients());
  await assert.rejects(runFixture(conflictFixture, conflictClients), BilateralFundingError);

  const changedRpcFixture = await fixture();
  await runFixture(changedRpcFixture, makeClients());
  await writeFile(changedRpcFixture.rpcUrlFile, "https://sepolia2.example.invalid/rpc\n", { mode: 0o600 });
  await assert.rejects(runFixture(changedRpcFixture, makeClients()), BilateralFundingError);
});
