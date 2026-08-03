import assert from "node:assert/strict";
import {
  chmod,
  lstat,
  mkdtemp,
  readFile,
  rename as nodeRename,
  rm,
  symlink,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { BilateralFundingError } from "../src/core/funding/record.mjs";
import {
  FUNDING_JOURNAL_SCHEMA,
  FUNDING_STATES,
  classifyFundingRecovery,
  deriveFundingBatchId,
  openFundingJournal,
} from "../src/core/funding/journal.mjs";

const FUNDING_ADDRESS = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const RECIPIENTS = Object.freeze([
  "0x1111111111111111111111111111111111111111",
  "0x2222222222222222222222222222222222222222",
  "0x3333333333333333333333333333333333333333",
  "0x4444444444444444444444444444444444444444",
]);
const RPC_ENDPOINT_SHA256 =
  "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const REPOSITORY_SHA = "abcdef0123456789abcdef0123456789abcdef01";

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

function binding(overrides = {}) {
  const facts = {
    chainId: 11155111,
    fundingAddress: FUNDING_ADDRESS,
    paymentMoved: false,
    recipients: [...RECIPIENTS],
    repositorySha: REPOSITORY_SHA,
    rpcEndpointSha256: RPC_ENDPOINT_SHA256,
    targetBalanceWei: "10000000000000000",
    ...overrides,
  };
  return {
    batchId: deriveFundingBatchId(facts),
    ...facts,
  };
}

async function privateDirectory(prefix = "funding-journal-") {
  const directory = await mkdtemp(join(tmpdir(), prefix));
  await chmod(directory, 0o700);
  return directory;
}

async function readJournal(directory) {
  const path = join(directory, "funding-journal.json");
  const bytes = await readFile(path, "utf8");
  return { bytes, path, value: JSON.parse(bytes) };
}

function broadcastIntent(overrides = {}) {
  return {
    address: RECIPIENTS[0],
    feeWei: "1000",
    fundingNonce: "7",
    state: "BROADCAST_INTENT",
    transactionDigest:
      "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    transactionHash: null,
    valueWei: "10000000000000000",
    ...overrides,
  };
}

test("journal exports the exact schema and state vocabulary", () => {
  assert.equal(
    FUNDING_JOURNAL_SCHEMA,
    "clockchain.bilateral-funding-journal/v1",
  );
  assert.deepEqual(FUNDING_STATES, [
    "PLANNED",
    "BROADCAST_INTENT",
    "TRANSACTION_OBSERVED",
    "FUNDED",
  ]);
  assert.ok(Object.isFrozen(FUNDING_STATES));
});

test("deriveFundingBatchId hashes only canonical public binding facts", () => {
  const publicFacts = binding();
  const first = deriveFundingBatchId(publicFacts);
  const second = deriveFundingBatchId({
    targetBalanceWei: publicFacts.targetBalanceWei,
    rpcEndpointSha256: publicFacts.rpcEndpointSha256,
    repositorySha: publicFacts.repositorySha,
    recipients: [...publicFacts.recipients],
    paymentMoved: false,
    fundingAddress: publicFacts.fundingAddress,
    chainId: 11155111,
    ignoredSecret: "not part of the public binding",
  });

  assert.match(first, /^[0-9a-f]{64}$/);
  assert.equal(first, second);
  assert.notEqual(first, deriveFundingBatchId(binding({ chainId: 1 })));
});

test("openFundingJournal creates one private canonical PLANNED journal and reopens exact bytes", async () => {
  const directory = await privateDirectory();
  const journal = await openFundingJournal({
    binding: binding(),
    journalDirectory: directory,
  });

  assert.equal(journal.path, join(directory, "funding-journal.json"));
  assert.deepEqual(journal.document, {
    binding: binding(),
    schema: FUNDING_JOURNAL_SCHEMA,
    state: "PLANNED",
    transfers: [],
  });
  assert.ok(Object.isFrozen(journal.document));

  const fileInfo = await lstat(journal.path);
  assert.equal(fileInfo.isFile(), true);
  assert.equal(fileInfo.isSymbolicLink(), false);
  assert.equal(fileInfo.nlink, 1);
  assert.equal(fileInfo.mode & 0o777, 0o600);

  const { bytes } = await readJournal(directory);
  assert.equal(bytes, canonicalJson(journal.document));

  const reopened = await openFundingJournal({
    binding: binding(),
    journalDirectory: directory,
  });
  assert.deepEqual(reopened.document, journal.document);
  assert.equal((await readJournal(directory)).bytes, bytes);
});

test("openFundingJournal rejects unsafe directories and ambiguous existing journals", async () => {
  const unsafeDirectory = await privateDirectory("funding-journal-public-");
  await chmod(unsafeDirectory, 0o755);
  await assert.rejects(
    openFundingJournal({ binding: binding(), journalDirectory: unsafeDirectory }),
    BilateralFundingError,
  );

  const staleTempDirectory = await privateDirectory("funding-journal-temp-");
  await writeFile(join(staleTempDirectory, ".funding-journal.tmp-stale"), "");
  await assert.rejects(
    openFundingJournal({ binding: binding(), journalDirectory: staleTempDirectory }),
    BilateralFundingError,
  );

  const symlinkDirectory = await privateDirectory("funding-journal-link-");
  await symlink("/dev/null", join(symlinkDirectory, "funding-journal.json"));
  await assert.rejects(
    openFundingJournal({ binding: binding(), journalDirectory: symlinkDirectory }),
    BilateralFundingError,
  );

  const malformedDirectory = await privateDirectory("funding-journal-bad-");
  await writeFile(
    join(malformedDirectory, "funding-journal.json"),
    `${JSON.stringify({
      schema: FUNDING_JOURNAL_SCHEMA,
      state: "PLANNED",
      binding: binding(),
      transfers: [],
    }, null, 2)}\n`,
    { mode: 0o600 },
  );
  await assert.rejects(
    openFundingJournal({ binding: binding(), journalDirectory: malformedDirectory }),
    BilateralFundingError,
  );

  const truncatedDirectory = await privateDirectory("funding-journal-truncated-");
  await writeFile(join(truncatedDirectory, "funding-journal.json"), "{", {
    mode: 0o600,
  });
  await assert.rejects(
    openFundingJournal({ binding: binding(), journalDirectory: truncatedDirectory }),
    BilateralFundingError,
  );

  const changedBindingDirectory = await privateDirectory("funding-journal-binding-");
  const first = await openFundingJournal({
    binding: binding(),
    journalDirectory: changedBindingDirectory,
  });
  await assert.rejects(
    openFundingJournal({
      binding: binding({ repositorySha: "1111111111111111111111111111111111111111" }),
      journalDirectory: changedBindingDirectory,
    }),
    BilateralFundingError,
  );
  assert.equal((await readJournal(changedBindingDirectory)).bytes, canonicalJson(first.document));
});

test("journal updates durable intent, observed hash, and funded state without mutating immutable transfer facts", async () => {
  const directory = await privateDirectory();
  const journal = await openFundingJournal({
    binding: binding(),
    journalDirectory: directory,
  });
  const intent = broadcastIntent();

  const afterIntent = await journal.recordBroadcastIntent(intent);
  assert.deepEqual(afterIntent.document.transfers, [intent]);
  assert.equal(afterIntent.document.state, "BROADCAST_INTENT");
  assert.equal((await lstat(journal.path)).mode & 0o777, 0o600);

  await assert.rejects(
    afterIntent.recordBroadcastIntent({
      ...intent,
      transactionDigest:
        "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
    }),
    BilateralFundingError,
  );

  const afterObserved = await afterIntent.recordTransactionObserved({
    address: intent.address,
    fundingNonce: intent.fundingNonce,
    transactionHash:
      "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  });
  assert.deepEqual(afterObserved.document.transfers[0], {
    ...intent,
    state: "TRANSACTION_OBSERVED",
    transactionHash:
      "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  });
  assert.equal(afterObserved.document.state, "TRANSACTION_OBSERVED");

  const afterFunded = await afterObserved.recordFunded({
    address: intent.address,
    fundingNonce: intent.fundingNonce,
  });
  assert.deepEqual(afterFunded.document.transfers[0], {
    ...intent,
    state: "FUNDED",
    transactionHash:
      "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  });
  assert.equal(afterFunded.document.state, "FUNDED");
  assert.equal(
    (await readJournal(directory)).bytes,
    canonicalJson(afterFunded.document),
  );
});

test("journal updates reject replacement and tampered persisted bytes fail-closed", async () => {
  const directory = await privateDirectory();
  const journal = await openFundingJournal({
    binding: binding(),
    journalDirectory: directory,
  });
  await rm(journal.path);
  await writeFile(journal.path, canonicalJson(journal.document), { mode: 0o600 });

  await assert.rejects(
    journal.recordBroadcastIntent(broadcastIntent()),
    BilateralFundingError,
  );

  const cleanDirectory = await privateDirectory("funding-journal-tamper-");
  const clean = await openFundingJournal({
    binding: binding(),
    journalDirectory: cleanDirectory,
  });
  await writeFile(clean.path, `${canonicalJson(clean.document)}\n`, {
    mode: 0o600,
  });
  await assert.rejects(
    clean.recordBroadcastIntent(broadcastIntent()),
    BilateralFundingError,
  );
});

test("classifyFundingRecovery returns WAIT before durable intent and never requests resend after intent", () => {
  assert.equal(
    classifyFundingRecovery({
      binding: binding(),
      journalTransfer: { ...broadcastIntent(), state: "PLANNED" },
      nonceTransaction: null,
      receipt: null,
      recipientFact: { address: RECIPIENTS[0], balanceWei: 0n, nonce: 0n },
    }),
    "WAIT",
  );
  assert.throws(
    () =>
      classifyFundingRecovery({
        binding: binding(),
        journalTransfer: broadcastIntent(),
        nonceTransaction: null,
        receipt: null,
        recipientFact: { address: RECIPIENTS[0], balanceWei: 0n, nonce: 0n },
      }),
    BilateralFundingError,
  );
});

test("classifyFundingRecovery advances observed transactions and funded recipients", () => {
  const transfer = broadcastIntent();
  const nonceTransaction = {
    chainId: 11155111,
    from: FUNDING_ADDRESS,
    hash: "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    nonce: "7",
    to: RECIPIENTS[0],
    valueWei: "10000000000000000",
  };

  assert.equal(
    classifyFundingRecovery({
      binding: binding(),
      journalTransfer: transfer,
      nonceTransaction,
      receipt: null,
      recipientFact: { address: RECIPIENTS[0], balanceWei: 0n, nonce: 0n },
    }),
    "OBSERVED",
  );

  assert.equal(
    classifyFundingRecovery({
      binding: binding(),
      journalTransfer: transfer,
      nonceTransaction,
      receipt: {
        chainId: 11155111,
        from: FUNDING_ADDRESS,
        nonce: "7",
        status: "success",
        to: RECIPIENTS[0],
        transactionHash:
          "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        valueWei: "10000000000000000",
      },
      recipientFact: {
        address: RECIPIENTS[0],
        balanceWei: 10_000_000_000_000_000n,
        nonce: 0n,
      },
    }),
    "FUNDED",
  );

  assert.equal(
    classifyFundingRecovery({
      binding: binding(),
      journalTransfer: broadcastIntent(),
      nonceTransaction: null,
      receipt: null,
      recipientFact: {
        address: RECIPIENTS[0],
        balanceWei: 10_000_000_000_000_000n,
        nonce: 0n,
      },
    }),
    "FUNDED",
  );
});

test("classifyFundingRecovery fails closed for replaced, reverted, mismatched, dropped, or ambiguous outcomes", () => {
  const transfer = broadcastIntent({
    transactionHash:
      "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  });
  const validNonceTransaction = {
    chainId: 11155111,
    from: FUNDING_ADDRESS,
    hash: transfer.transactionHash,
    nonce: "7",
    to: RECIPIENTS[0],
    valueWei: "10000000000000000",
  };
  const validReceipt = {
    chainId: 11155111,
    from: FUNDING_ADDRESS,
    nonce: "7",
    status: "success",
    to: RECIPIENTS[0],
    transactionHash: transfer.transactionHash,
    valueWei: "10000000000000000",
  };

  const invalidCases = [
    { nonceTransaction: { ...validNonceTransaction, to: RECIPIENTS[1] }, receipt: null },
    { nonceTransaction: { ...validNonceTransaction, hash: null }, receipt: null },
    { nonceTransaction: { ...validNonceTransaction, nonce: "8" }, receipt: null },
    { nonceTransaction: { ...validNonceTransaction, from: RECIPIENTS[1] }, receipt: null },
    { nonceTransaction: { ...validNonceTransaction, chainId: 1 }, receipt: null },
    {
      nonceTransaction: validNonceTransaction,
      receipt: { ...validReceipt, status: "reverted" },
    },
    {
      nonceTransaction: validNonceTransaction,
      receipt: { ...validReceipt, transactionHash: "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" },
    },
    {
      nonceTransaction: validNonceTransaction,
      receipt: { ...validReceipt, to: RECIPIENTS[1] },
    },
    {
      nonceTransaction: null,
      receipt: null,
      recipientFact: {
        address: RECIPIENTS[0],
        balanceWei: 10_000_000_000_000_000n,
        nonce: 1n,
      },
    },
  ];

  for (const invalid of invalidCases) {
    assert.throws(
      () =>
        classifyFundingRecovery({
          binding: binding(),
          journalTransfer: transfer,
          nonceTransaction: invalid.nonceTransaction,
          receipt: invalid.receipt,
          recipientFact: invalid.recipientFact ?? {
            address: RECIPIENTS[0],
            balanceWei: 0n,
            nonce: 0n,
          },
        }),
      BilateralFundingError,
    );
  }
});

test("classifyFundingRecovery requires exact binding context before trusting sender chain or target", () => {
  const transfer = broadcastIntent();
  const nonceTransaction = {
    chainId: 11155111,
    from: FUNDING_ADDRESS,
    hash: "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    nonce: "7",
    to: RECIPIENTS[0],
    valueWei: "10000000000000000",
  };
  const recipientFact = { address: RECIPIENTS[0], balanceWei: 0n, nonce: 0n };

  assert.throws(
    () =>
      classifyFundingRecovery({
        journalTransfer: transfer,
        nonceTransaction,
        receipt: null,
        recipientFact,
      }),
    BilateralFundingError,
  );
  assert.throws(
    () =>
      classifyFundingRecovery({
        binding: binding({ chainId: 1 }),
        journalTransfer: transfer,
        nonceTransaction,
        receipt: null,
        recipientFact,
      }),
    BilateralFundingError,
  );
  assert.throws(
    () =>
      classifyFundingRecovery({
        binding: binding({ fundingAddress: RECIPIENTS[1] }),
        journalTransfer: transfer,
        nonceTransaction,
        receipt: null,
        recipientFact,
      }),
    BilateralFundingError,
  );
});

test("classifyFundingRecovery uses only binding target balance and never falls back to transfer value", () => {
  assert.throws(
    () =>
      classifyFundingRecovery({
        binding: binding(),
        journalTransfer: broadcastIntent({ valueWei: "1" }),
        nonceTransaction: null,
        receipt: null,
        recipientFact: { address: RECIPIENTS[0], balanceWei: 1n, nonce: 0n },
      }),
    BilateralFundingError,
  );
});

test("classifyFundingRecovery treats post-intent missing nonce evidence as terminal while observed tx waits for receipt", () => {
  assert.throws(
    () =>
      classifyFundingRecovery({
        binding: binding(),
        journalTransfer: broadcastIntent(),
        nonceTransaction: null,
        receipt: null,
        recipientFact: { address: RECIPIENTS[0], balanceWei: 0n, nonce: 0n },
      }),
    BilateralFundingError,
  );

  assert.equal(
    classifyFundingRecovery({
      binding: binding(),
      journalTransfer: broadcastIntent({
        state: "TRANSACTION_OBSERVED",
        transactionHash:
          "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      }),
      nonceTransaction: {
        chainId: 11155111,
        from: FUNDING_ADDRESS,
        hash: "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        nonce: "7",
        to: RECIPIENTS[0],
        valueWei: "10000000000000000",
      },
      receipt: null,
      recipientFact: { address: RECIPIENTS[0], balanceWei: 0n, nonce: 0n },
    }),
    "WAIT",
  );
});

test("openFundingJournal rejects persisted transfers outside the bound recipients or duplicate address nonce pair", async () => {
  const alienDirectory = await privateDirectory("funding-journal-alien-transfer-");
  const bound = binding();
  await writeFile(
    join(alienDirectory, "funding-journal.json"),
    canonicalJson({
      binding: bound,
      schema: FUNDING_JOURNAL_SCHEMA,
      state: "BROADCAST_INTENT",
      transfers: [
        broadcastIntent({
          address: "0x9999999999999999999999999999999999999999",
        }),
      ],
    }),
    { mode: 0o600 },
  );
  await assert.rejects(
    openFundingJournal({ binding: bound, journalDirectory: alienDirectory }),
    BilateralFundingError,
  );

  const duplicateDirectory = await privateDirectory(
    "funding-journal-duplicate-transfer-",
  );
  const transfer = broadcastIntent();
  await writeFile(
    join(duplicateDirectory, "funding-journal.json"),
    canonicalJson({
      binding: bound,
      schema: FUNDING_JOURNAL_SCHEMA,
      state: "BROADCAST_INTENT",
      transfers: [transfer, transfer],
    }),
    { mode: 0o600 },
  );
  await assert.rejects(
    openFundingJournal({ binding: bound, journalDirectory: duplicateDirectory }),
    BilateralFundingError,
  );
});

test("classifyFundingRecovery snapshots planned and recovery descriptors without invoking getters or proxy gets", () => {
  let reads = 0;
  const hostileTransfer = new Proxy(
    { ...broadcastIntent(), state: "PLANNED" },
    {
      get(target, property, receiver) {
        if (property === "address") reads += 1;
        return Reflect.get(target, property, receiver);
      },
    },
  );

  assert.equal(
    classifyFundingRecovery({
      binding: binding(),
      journalTransfer: hostileTransfer,
      nonceTransaction: null,
      receipt: null,
      recipientFact: { address: RECIPIENTS[0], balanceWei: 0n, nonce: 0n },
    }),
    "WAIT",
  );
  assert.equal(reads, 0);

  let accessorReads = 0;
  assert.throws(
    () =>
      classifyFundingRecovery({
        binding: binding(),
        journalTransfer: Object.defineProperty(
          { ...broadcastIntent(), state: "PLANNED" },
          "address",
          {
            enumerable: true,
            get() {
              accessorReads += 1;
              return RECIPIENTS[0];
            },
          },
        ),
        nonceTransaction: null,
        receipt: null,
        recipientFact: { address: RECIPIENTS[0], balanceWei: 0n, nonce: 0n },
      }),
    BilateralFundingError,
  );
  assert.equal(accessorReads, 0);

  assert.throws(
    () =>
      classifyFundingRecovery({
        binding: binding(),
        journalTransfer: broadcastIntent(),
        nonceTransaction: Object.defineProperty(
          {
            chainId: 11155111,
            from: FUNDING_ADDRESS,
            hash: "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            nonce: "7",
            to: RECIPIENTS[0],
            valueWei: "10000000000000000",
          },
          "from",
          {
            enumerable: true,
            get() {
              return FUNDING_ADDRESS;
            },
          },
        ),
        receipt: null,
        recipientFact: { address: RECIPIENTS[0], balanceWei: 0n, nonce: 0n },
      }),
    BilateralFundingError,
  );
});

test("journal update checks target identity immediately before rename", async () => {
  const directory = await privateDirectory("funding-journal-rename-race-");
  let journalPath;
  let renameCalled = false;
  const fileSystem = {
    async open(path, flags, mode) {
      const handle = await import("node:fs/promises").then(({ open }) =>
        open(path, flags, mode),
      );
      if (!path.includes(".funding-journal.tmp-")) return handle;
      return {
        ...handle,
        chmod: handle.chmod.bind(handle),
        close: handle.close.bind(handle),
        stat: handle.stat.bind(handle),
        writeFile: handle.writeFile.bind(handle),
        async sync() {
          await handle.sync();
          await rm(journalPath);
          await writeFile(journalPath, canonicalJson({}), { mode: 0o600 });
        },
      };
    },
    async rename(from, to) {
      renameCalled = true;
      await nodeRename(from, to);
    },
  };
  const journal = await openFundingJournal({
    binding: binding(),
    journalDirectory: directory,
    dependencies: { fileSystem },
  });
  journalPath = journal.path;

  await assert.rejects(
    journal.recordBroadcastIntent(broadcastIntent()),
    BilateralFundingError,
  );
  assert.equal(renameCalled, false);
});
