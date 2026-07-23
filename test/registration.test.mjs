import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

import {
  encodeAbiParameters,
  encodeEventTopics,
} from "viem";

import {
  ERC8004_ABI,
  buildRegistrationDocument,
  identityReference,
  parseRegisteredAgentId,
  registerIdentity,
  registrationDataUri,
  registryNamespace,
} from "../src/registration.mjs";

const REGISTRY_ADDRESS =
  "0x8004A818BFB912233c491871b3d84c89A494BD9e";
const REGISTRY_NAMESPACE = `eip155:11155111:${REGISTRY_ADDRESS}`;
const REGISTERED_TOPIC =
  "0xca52e62c367d81bb2e328eb795f7c7ba24afb478408a26c0e201d155c449bc4a";
const EXPECTED_OWNER = "0x1111111111111111111111111111111111111111";
const FOREIGN_ADDRESS = "0x2222222222222222222222222222222222222222";
const FIXTURE_URI = "data:application/json;base64,e30=";
const PRIVATE_KEY = `0x${"11".repeat(32)}`;
const DERIVED_ADDRESS = "0x19E7E376E7C213B7E7e7e46cc70A5dD086DAff2A";
const REGISTER_HASH = `0x${"33".repeat(32)}`;
const METADATA_HASH = `0x${"44".repeat(32)}`;
const DESCRIPTION =
  "Ephemeral Clockchain Handshake testnet identity; registration does not establish capability or trust.";

function loadReceipt() {
  return JSON.parse(
    readFileSync(
      new URL("./fixtures/registered-receipt.json", import.meta.url),
      "utf8",
    ),
  );
}

function registeredLog(receipt) {
  return receipt.logs.find((log) => log.topics[0] === REGISTERED_TOPIC);
}

function option(options, name, fallback) {
  return Object.hasOwn(options, name) ? options[name] : fallback;
}

function createRegisteredLog({
  address = REGISTRY_ADDRESS,
  agentId = 42n,
  agentURI,
  owner = DERIVED_ADDRESS,
}) {
  return {
    address,
    data: encodeAbiParameters(
      [{ name: "agentURI", type: "string" }],
      [agentURI],
    ),
    topics: encodeEventTopics({
      abi: ERC8004_ABI,
      eventName: "Registered",
      args: { agentId, owner },
    }),
  };
}

function createFakeClients(options = {}) {
  const state = {
    calls: [],
    finalURI: null,
    initialURI: null,
  };
  const registerHash = option(options, "registerHash", REGISTER_HASH);
  const metadataHash = option(options, "metadataHash", METADATA_HASH);

  function record(name, parameters) {
    state.calls.push({ name, parameters });
  }

  function createRegisterReceipt(hash) {
    const eventMode = option(options, "eventMode", "valid");
    const event = createRegisteredLog({
      address:
        eventMode === "foreign" ? FOREIGN_ADDRESS : REGISTRY_ADDRESS,
      agentURI:
        eventMode === "wrongURI"
          ? `${state.initialURI}-wrong`
          : state.initialURI,
      owner:
        eventMode === "wrongOwner"
          ? FOREIGN_ADDRESS
          : DERIVED_ADDRESS,
    });

    if (eventMode === "malformed") {
      event.data = "0x1234";
    }

    const logs = eventMode === "missing" ? [] : [event];
    if (eventMode === "duplicate") {
      logs.push(structuredClone(event));
    }

    return {
      status: option(options, "registerStatus", "success"),
      transactionHash: option(
        options,
        "registerReceiptHash",
        hash,
      ),
      blockNumber: option(
        options,
        "registerBlockNumber",
        123_456n,
      ),
      logs,
    };
  }

  function createMetadataReceipt(hash) {
    return {
      status: option(options, "metadataStatus", "success"),
      transactionHash: option(
        options,
        "metadataReceiptHash",
        hash,
      ),
      blockNumber: option(
        options,
        "metadataBlockNumber",
        123_457n,
      ),
      logs: [],
    };
  }

  const publicClient = {
    async getChainId() {
      record("getChainId");
      return option(options, "chainId", 11_155_111);
    },

    async getCode(parameters) {
      record("getCode", parameters);
      return option(options, "code", "0x60006000");
    },

    async readContract(parameters) {
      record(`read:${parameters.functionName}`, parameters);

      switch (parameters.functionName) {
        case "getVersion":
          return option(options, "version", "2.0.0");
        case "ownerOf":
          return option(options, "finalOwner", DERIVED_ADDRESS);
        case "getAgentWallet":
          return option(options, "finalWallet", DERIVED_ADDRESS);
        case "tokenURI":
          return option(options, "finalTokenURI", state.finalURI);
        default:
          throw new Error("Unexpected readContract call.");
      }
    },

    async getTransactionCount(parameters) {
      record("getTransactionCount", parameters);
      return option(options, "nonce", 0);
    },

    async getBalance(parameters) {
      record("getBalance", parameters);
      return option(options, "balance", 1_000_000_000_000_000n);
    },

    async estimateContractGas(parameters) {
      record(`estimate:${parameters.functionName}`, parameters);
      if (parameters.functionName === "register") {
        return option(options, "registerGas", 180_000n);
      }
      if (parameters.functionName === "setAgentURI") {
        return option(options, "metadataGas", 90_000n);
      }
      throw new Error("Unexpected estimateContractGas call.");
    },

    async waitForTransactionReceipt(parameters) {
      const stage =
        parameters.hash === registerHash ? "register" : "metadata";
      record(`wait:${stage}`, parameters);
      return stage === "register"
        ? createRegisterReceipt(parameters.hash)
        : createMetadataReceipt(parameters.hash);
    },
  };

  const walletClient = {
    async writeContract(parameters) {
      record(`write:${parameters.functionName}`, parameters);

      if (parameters.functionName === "register") {
        state.initialURI = parameters.args[0];
        return registerHash;
      }
      if (parameters.functionName === "setAgentURI") {
        state.finalURI = parameters.args[1];
        return metadataHash;
      }
      throw new Error("Unexpected writeContract call.");
    },
  };

  return { publicClient, state, walletClient };
}

async function captureRejection(operation) {
  let rejection;

  try {
    await operation();
  } catch (error) {
    rejection = error;
  }

  assert.ok(rejection instanceof Error, "expected operation to reject");
  return rejection;
}

function assertErrorOmits(error, ...values) {
  const diagnostic = `${error.message}\n${error.stack ?? ""}`;

  for (const value of values) {
    assert.equal(
      diagnostic.includes(value),
      false,
      "error diagnostic must not echo secret input",
    );
  }
}

function decodeRegistrationDataURI(uri) {
  const prefix = "data:application/json;base64,";
  assert.ok(uri.startsWith(prefix));
  return JSON.parse(
    Buffer.from(uri.slice(prefix.length), "base64").toString("utf8"),
  );
}

async function runWithFakeClients(fake, overrides = {}) {
  return registerIdentity({
    privateKey: PRIVATE_KEY,
    expectedAddress: DERIVED_ADDRESS,
    displayName: "Billy",
    publicClient: fake.publicClient,
    walletClient: fake.walletClient,
    ...overrides,
  });
}

test("builds exact official identity references", () => {
  assert.equal(registryNamespace(), REGISTRY_NAMESPACE);
  assert.equal(
    identityReference(42n),
    `${REGISTRY_NAMESPACE}:42`,
  );

  for (const invalidAgentId of [
    -1n,
    -1,
    1.5,
    Number.NaN,
    Number.POSITIVE_INFINITY,
    Number.MAX_SAFE_INTEGER + 1,
    1n << 256n,
    "42",
    null,
    undefined,
    {},
  ]) {
    assert.throws(
      () => identityReference(invalidAgentId),
      /agent id/i,
    );
  }
});

test("builds the exact initial registration document without capability claims", () => {
  const document = buildRegistrationDocument({
    displayName: "Billy",
    agentId: null,
  });

  assert.deepEqual(document, {
    type: "https://eips.ethereum.org/EIPS/eip-8004#registration-v1",
    name: "Billy",
    description: DESCRIPTION,
    services: [],
    x402Support: false,
    active: true,
    registrations: [],
  });
});

test("builds the exact final registration document with a canonical registration", () => {
  const document = buildRegistrationDocument({
    displayName: "Billy",
    agentId: 42n,
  });

  assert.deepEqual(document, {
    type: "https://eips.ethereum.org/EIPS/eip-8004#registration-v1",
    name: "Billy",
    description: DESCRIPTION,
    services: [],
    x402Support: false,
    active: true,
    registrations: [
      {
        agentRegistry: REGISTRY_NAMESPACE,
        agentId: 42,
      },
    ],
  });
  assert.equal(Object.hasOwn(document, "address"), false);
  assert.equal(Object.hasOwn(document, "wallet"), false);
  assert.equal(Object.hasOwn(document, "supportedTrust"), false);
  assert.equal(Object.hasOwn(document, "payment"), false);
  assert.equal(Object.hasOwn(document, "mcp"), false);
  assert.equal(Object.hasOwn(document, "a2a"), false);
});

test("validates registration names and JSON-safe agent IDs", () => {
  for (const displayName of ["", "   ", "x".repeat(129), null, undefined]) {
    assert.throws(
      () => buildRegistrationDocument({ displayName, agentId: null }),
      /display name/i,
    );
  }

  for (const agentId of [
    -1n,
    BigInt(Number.MAX_SAFE_INTEGER) + 1n,
    Number.MAX_SAFE_INTEGER + 1,
    1.5,
    "42",
  ]) {
    assert.throws(
      () => buildRegistrationDocument({ displayName: "Billy", agentId }),
      /agent id/i,
    );
  }
});

test("encodes the exact UTF-8 JSON bytes as a base64 data URI", () => {
  const document = buildRegistrationDocument({
    displayName: "Billy 🚲",
    agentId: 42n,
  });
  const json = JSON.stringify(document);
  const expected =
    `data:application/json;base64,${Buffer.from(json, "utf8").toString("base64")}`;
  const uri = registrationDataUri(document);

  assert.equal(uri, expected);
  assert.deepEqual(
    Buffer.from(uri.slice("data:application/json;base64,".length), "base64"),
    Buffer.from(json, "utf8"),
  );
});

test("strictly extracts the Registered agent ID from a four-log receipt", () => {
  const receipt = loadReceipt();

  assert.equal(receipt.logs.length, 4);
  assert.equal(registeredLog(receipt).topics[0], REGISTERED_TOPIC);
  assert.equal(
    parseRegisteredAgentId(receipt, {
      expectedOwner: EXPECTED_OWNER,
      expectedAgentURI: FIXTURE_URI,
    }),
    42n,
  );
});

test("rejects reverted, foreign-only, and duplicate Registered receipts", () => {
  const reverted = loadReceipt();
  reverted.status = "reverted";

  assert.throws(
    () =>
      parseRegisteredAgentId(reverted, {
        expectedOwner: EXPECTED_OWNER,
        expectedAgentURI: FIXTURE_URI,
      }),
    /receipt/i,
  );

  const foreignOnly = loadReceipt();
  registeredLog(foreignOnly).address = FOREIGN_ADDRESS;
  assert.throws(
    () =>
      parseRegisteredAgentId(foreignOnly, {
        expectedOwner: EXPECTED_OWNER,
        expectedAgentURI: FIXTURE_URI,
      }),
    /registered event/i,
  );

  const duplicate = loadReceipt();
  duplicate.logs.push(structuredClone(registeredLog(duplicate)));
  assert.throws(
    () =>
      parseRegisteredAgentId(duplicate, {
        expectedOwner: EXPECTED_OWNER,
        expectedAgentURI: FIXTURE_URI,
      }),
    /registered event/i,
  );
});

test("rejects wrong-owner, wrong-URI, and malformed Registered events", () => {
  const wrongOwner = loadReceipt();
  assert.throws(
    () =>
      parseRegisteredAgentId(wrongOwner, {
        expectedOwner: FOREIGN_ADDRESS,
        expectedAgentURI: FIXTURE_URI,
      }),
    /owner/i,
  );

  const wrongUri = loadReceipt();
  assert.throws(
    () =>
      parseRegisteredAgentId(wrongUri, {
        expectedOwner: EXPECTED_OWNER,
        expectedAgentURI: `${FIXTURE_URI}-wrong`,
      }),
    /uri/i,
  );

  const malformed = loadReceipt();
  registeredLog(malformed).data = "0x1234";
  assert.throws(
    () =>
      parseRegisteredAgentId(malformed, {
        expectedOwner: EXPECTED_OWNER,
        expectedAgentURI: FIXTURE_URI,
      }),
    /registered event/i,
  );
});

test("registers then finalizes metadata in strict order and returns public JSON evidence", async () => {
  const fake = createFakeClients();
  const evidence = await runWithFakeClients(fake);

  assert.deepEqual(
    fake.state.calls.map(({ name }) => name),
    [
      "getChainId",
      "getCode",
      "read:getVersion",
      "getTransactionCount",
      "getBalance",
      "estimate:register",
      "write:register",
      "wait:register",
      "estimate:setAgentURI",
      "write:setAgentURI",
      "wait:metadata",
      "read:ownerOf",
      "read:getAgentWallet",
      "read:tokenURI",
    ],
  );

  const initialDocument = decodeRegistrationDataURI(fake.state.initialURI);
  const finalDocument = decodeRegistrationDataURI(fake.state.finalURI);
  assert.deepEqual(
    initialDocument,
    buildRegistrationDocument({ displayName: "Billy", agentId: null }),
  );
  assert.deepEqual(
    finalDocument,
    buildRegistrationDocument({ displayName: "Billy", agentId: 42n }),
  );

  const registerEstimate = fake.state.calls.find(
    ({ name }) => name === "estimate:register",
  ).parameters;
  const registerWrite = fake.state.calls.find(
    ({ name }) => name === "write:register",
  ).parameters;
  const metadataEstimate = fake.state.calls.find(
    ({ name }) => name === "estimate:setAgentURI",
  ).parameters;
  const metadataWrite = fake.state.calls.find(
    ({ name }) => name === "write:setAgentURI",
  ).parameters;
  assert.equal(registerEstimate.address, REGISTRY_ADDRESS);
  assert.equal(registerEstimate.account.address, DERIVED_ADDRESS);
  assert.deepEqual(registerEstimate.args, [fake.state.initialURI]);
  assert.equal(registerWrite.gas, 180_000n);
  assert.equal(registerWrite.account.address, DERIVED_ADDRESS);
  assert.deepEqual(registerWrite.args, registerEstimate.args);
  assert.equal(metadataEstimate.address, REGISTRY_ADDRESS);
  assert.equal(metadataEstimate.account.address, DERIVED_ADDRESS);
  assert.deepEqual(metadataEstimate.args, [42n, fake.state.finalURI]);
  assert.equal(metadataWrite.gas, 90_000n);
  assert.equal(metadataWrite.account.address, DERIVED_ADDRESS);
  assert.deepEqual(metadataWrite.args, metadataEstimate.args);

  const waits = fake.state.calls.filter(({ name }) => name.startsWith("wait:"));
  assert.deepEqual(
    waits.map(({ parameters }) => parameters),
    [
      {
        hash: REGISTER_HASH,
        confirmations: 1,
        timeout: 120_000,
      },
      {
        hash: METADATA_HASH,
        confirmations: 1,
        timeout: 120_000,
      },
    ],
  );

  assert.deepEqual(evidence, {
    chainId: 11_155_111,
    registryAddress: REGISTRY_ADDRESS,
    registryNamespace: REGISTRY_NAMESPACE,
    identityReference: `${REGISTRY_NAMESPACE}:42`,
    agentId: "42",
    address: DERIVED_ADDRESS,
    displayName: "Billy",
    registerTx: REGISTER_HASH,
    registerBlock: "123456",
    metadataTx: METADATA_HASH,
    metadataBlock: "123457",
    document: finalDocument,
  });
  assert.doesNotThrow(() => JSON.stringify(evidence));
  assert.equal(JSON.stringify(evidence).includes(PRIVATE_KEY), false);
});

test("rejects malformed keys and derived-address mismatches without key leakage", async () => {
  const malformedKey = "malformed-private-key-do-not-echo";
  const malformedFake = createFakeClients();
  const malformedError = await captureRejection(() =>
    registerIdentity({
      privateKey: malformedKey,
      expectedAddress: DERIVED_ADDRESS,
      displayName: "Billy",
      publicClient: malformedFake.publicClient,
      walletClient: malformedFake.walletClient,
    }),
  );
  assert.match(malformedError.message, /private key/i);
  assertErrorOmits(malformedError, malformedKey);
  assert.deepEqual(malformedFake.state.calls, []);

  const mismatchFake = createFakeClients();
  const mismatchError = await captureRejection(() =>
    runWithFakeClients(mismatchFake, { expectedAddress: FOREIGN_ADDRESS }),
  );
  assert.match(mismatchError.message, /address/i);
  assertErrorOmits(mismatchError, PRIVATE_KEY);
  assert.deepEqual(mismatchFake.state.calls, []);
});

test("rejects a wrong chain before any contract write", async () => {
  const fake = createFakeClients({ chainId: 1 });
  const error = await captureRejection(() => runWithFakeClients(fake));

  assert.match(error.message, /chain/i);
  assert.deepEqual(
    fake.state.calls.map(({ name }) => name),
    ["getChainId"],
  );
});

test("rejects missing registry bytecode before contract reads or writes", async () => {
  for (const code of [undefined, "", "0x"]) {
    const fake = createFakeClients({ code });
    const error = await captureRejection(() => runWithFakeClients(fake));

    assert.match(error.message, /registry contract/i);
    assert.deepEqual(
      fake.state.calls.map(({ name }) => name),
      ["getChainId", "getCode"],
    );
  }
});

test("rejects an unsupported registry version before any write", async () => {
  const fake = createFakeClients({ version: "2.0.1" });
  const error = await captureRejection(() => runWithFakeClients(fake));

  assert.match(error.message, /version/i);
  assert.deepEqual(
    fake.state.calls.map(({ name }) => name),
    ["getChainId", "getCode", "read:getVersion"],
  );
});

test("rejects a nonzero pending nonce before balance and writes", async () => {
  const fake = createFakeClients({ nonce: 1 });
  const error = await captureRejection(() => runWithFakeClients(fake));

  assert.match(error.message, /nonce/i);
  assert.deepEqual(
    fake.state.calls.map(({ name }) => name),
    [
      "getChainId",
      "getCode",
      "read:getVersion",
      "getTransactionCount",
    ],
  );
  assert.deepEqual(fake.state.calls.at(-1).parameters, {
    address: DERIVED_ADDRESS,
    blockTag: "pending",
  });
});

test("rejects a zero balance before gas estimation or writes", async () => {
  const fake = createFakeClients({ balance: 0n });
  const error = await captureRejection(() => runWithFakeClients(fake));

  assert.match(error.message, /balance/i);
  assert.deepEqual(
    fake.state.calls.map(({ name }) => name),
    [
      "getChainId",
      "getCode",
      "read:getVersion",
      "getTransactionCount",
      "getBalance",
    ],
  );
});

test("rejects reverted first and second transaction receipts", async () => {
  const firstFake = createFakeClients({ registerStatus: "reverted" });
  const firstError = await captureRejection(() =>
    runWithFakeClients(firstFake),
  );
  assert.match(firstError.message, /registration receipt/i);
  assert.deepEqual(
    firstFake.state.calls.slice(-3).map(({ name }) => name),
    ["estimate:register", "write:register", "wait:register"],
  );
  assert.equal(
    firstFake.state.calls.some(({ name }) => name === "write:setAgentURI"),
    false,
  );

  const secondFake = createFakeClients({ metadataStatus: "reverted" });
  const secondError = await captureRejection(() =>
    runWithFakeClients(secondFake),
  );
  assert.match(secondError.message, /metadata receipt/i);
  assert.deepEqual(
    secondFake.state.calls.slice(-3).map(({ name }) => name),
    [
      "estimate:setAgentURI",
      "write:setAgentURI",
      "wait:metadata",
    ],
  );
  assert.equal(
    secondFake.state.calls.some(({ name }) => name === "read:ownerOf"),
    false,
  );
});

test("rejects foreign, duplicate, wrong-owner, wrong-URI, and malformed registration events", async () => {
  for (const eventMode of [
    "foreign",
    "duplicate",
    "wrongOwner",
    "wrongURI",
    "malformed",
  ]) {
    const fake = createFakeClients({ eventMode });
    const error = await captureRejection(() => runWithFakeClients(fake));

    assert.match(error.message, /registration event/i);
    assert.equal(
      fake.state.calls.some(({ name }) => name === "write:setAgentURI"),
      false,
    );
  }
});

test("rejects final owner, agent wallet, and token URI mismatches", async () => {
  for (const [options, pattern] of [
    [{ finalOwner: FOREIGN_ADDRESS }, /owner/i],
    [{ finalWallet: FOREIGN_ADDRESS }, /agent wallet/i],
    [{ finalTokenURI: `${FIXTURE_URI}-wrong` }, /token uri/i],
  ]) {
    const fake = createFakeClients(options);
    const error = await captureRejection(() => runWithFakeClients(fake));

    assert.match(error.message, pattern);
  }
});

test("rejects missing transaction hashes and receipt evidence fields", async () => {
  for (const options of [
    { registerHash: undefined },
    { metadataHash: undefined },
    { registerReceiptHash: undefined },
    { metadataReceiptHash: undefined },
    { registerBlockNumber: undefined },
    { metadataBlockNumber: undefined },
  ]) {
    const fake = createFakeClients(options);
    const error = await captureRejection(() => runWithFakeClients(fake));

    assert.match(error.message, /transaction|receipt/i);
  }
});
