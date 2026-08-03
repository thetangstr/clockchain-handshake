import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

import {
  createWalletClient,
  custom,
  decodeFunctionData,
  encodeAbiParameters,
  encodeEventTopics,
  encodeFunctionData,
  keccak256,
  parseTransaction,
} from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { sepolia } from "viem/chains";

import {
  ERC8004_ABI,
  PartialRegistrationError,
  RegistrationConfigurationError,
  RegistrationNetworkError,
  buildRegistrationDocument,
  finalizeIdentityRegistration,
  identityReference,
  parseRegisteredAgentId,
  registerIdentity,
  registrationDataUri,
  registryNamespace,
} from "../src/core/registration.mjs";

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
const RETRY_METADATA_HASH = `0x${"55".repeat(32)}`;
const UNRELATED_HASH = `0x${"66".repeat(32)}`;
const RECOVERY_SCHEMA =
  "clockchain.handshake-registration-recovery/v1";
const INTENT_SCHEMA =
  "clockchain.handshake-registration-intent/v1";
const PILOT_MINIMUM_BALANCE_WEI = 5_000_000_000_000_000n;
const PILOT_MAXIMUM_BALANCE_WEI = 20_000_000_000_000_000n;
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

function initialRegistrationURI(displayName = "Billy") {
  return registrationDataUri(
    buildRegistrationDocument({ displayName, agentId: null }),
  );
}

function finalRegistrationURI(agentId = 42n, displayName = "Billy") {
  return registrationDataUri(
    buildRegistrationDocument({ displayName, agentId }),
  );
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
    balanceReads: 0,
    calls: [],
    feeReads: 0,
    finalURI: null,
    initialURI: null,
    nonceReads: 0,
    metadataReceipts: 0,
  };
  const registerHash = option(options, "registerHash", REGISTER_HASH);
  const recoveryRegisterHash = option(
    options,
    "recoveryRegisterHash",
    REGISTER_HASH,
  );
  const metadataHash = option(options, "metadataHash", METADATA_HASH);
  state.registrationHashes = new Set(
    [registerHash, recoveryRegisterHash].filter(
      (hash) => typeof hash === "string",
    ),
  );

  function record(name, parameters) {
    state.calls.push({ name, parameters });
  }

  function createRegisterReceipt(hash) {
    const eventMode = option(options, "eventMode", "valid");
    const initialURI = state.initialURI ?? initialRegistrationURI();
    const event = createRegisteredLog({
      address:
        eventMode === "foreign" ? FOREIGN_ADDRESS : REGISTRY_ADDRESS,
      agentId: option(options, "registerEventAgentId", 42n),
      agentURI: option(
        options,
        "registerEventURI",
        eventMode === "wrongURI"
          ? `${initialURI}-wrong`
          : initialURI,
      ),
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

    const receipt = {
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

    return option(options, "registerReceipt", receipt);
  }

  function createMetadataReceipt(hash) {
    const metadataStatuses = option(
      options,
      "metadataStatuses",
      [option(options, "metadataStatus", "success")],
    );
    const status =
      metadataStatuses[
        Math.min(
          state.metadataReceipts,
          metadataStatuses.length - 1,
        )
      ];
    state.metadataReceipts += 1;
    return {
      status,
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
      if (options.readError === parameters.functionName) {
        throw new Error(`Sensitive RPC failure ${PRIVATE_KEY}`);
      }

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

    async getTransaction(parameters) {
      const isRegistration = state.registrationHashes.has(
        parameters.hash,
      );
      const stage = isRegistration ? "register" : "metadata";
      record(`getTransaction:${stage}`, parameters);

      if (
        (isRegistration && options.registerTransactionError) ||
        (!isRegistration && options.metadataTransactionError)
      ) {
        throw new Error(`Sensitive transaction failure ${PRIVATE_KEY}`);
      }

      if (isRegistration) {
        const transaction = {
          hash: parameters.hash,
          chainId: 11_155_111,
          from: DERIVED_ADDRESS,
          to: REGISTRY_ADDRESS,
          nonce: 0,
          value: 0n,
          blockNumber: 123_456n,
          input: encodeFunctionData({
            abi: ERC8004_ABI,
            functionName: "register",
            args: [state.initialURI ?? initialRegistrationURI()],
          }),
          ...option(options, "registerTransactionOverrides", {}),
        };
        return option(options, "registerTransaction", transaction);
      }

      const defaultNonce =
        parameters.hash === RETRY_METADATA_HASH ? 2 : 1;
      const transactionOverrides =
        typeof options.metadataTransactionOverrides === "function"
          ? options.metadataTransactionOverrides(parameters.hash)
          : option(options, "metadataTransactionOverrides", {});
      const transaction = {
        hash: parameters.hash,
        chainId: 11_155_111,
        from: DERIVED_ADDRESS,
        to: REGISTRY_ADDRESS,
        nonce: defaultNonce,
        value: 0n,
        blockNumber: 123_457n,
        input: encodeFunctionData({
          abi: ERC8004_ABI,
          functionName: "setAgentURI",
          args: [42n, state.finalURI ?? finalRegistrationURI()],
        }),
        ...transactionOverrides,
      };
      return option(options, "metadataTransaction", transaction);
    },

    async getTransactionCount(parameters) {
      record("getTransactionCount", parameters);
      if (Object.hasOwn(options, "nonce")) {
        return options.nonce;
      }

      const nonces = option(options, "nonces", [0, 1]);
      const nonce = nonces[Math.min(state.nonceReads, nonces.length - 1)];
      state.nonceReads += 1;
      return nonce;
    },

    async getBalance(parameters) {
      record("getBalance", parameters);
      if (Object.hasOwn(options, "balance")) {
        return options.balance;
      }

      const balances = option(
        options,
        "balances",
        [
          10_000_000_000_000_000n,
          10_000_000_000_000_000n,
        ],
      );
      const balance =
        balances[Math.min(state.balanceReads, balances.length - 1)];
      state.balanceReads += 1;
      return balance;
    },

    async estimateFeesPerGas(parameters) {
      record("estimateFeesPerGas", parameters);
      if (
        options.feeErrorAt === "registration" &&
        state.feeReads === 0
      ) {
        throw new Error(`Sensitive fee failure ${PRIVATE_KEY}`);
      }
      if (
        options.feeErrorAt === "metadata" &&
        state.feeReads > 0
      ) {
        throw new Error(`Sensitive fee failure ${PRIVATE_KEY}`);
      }
      const feeQuotes = option(options, "feeQuotes", [
        { maxFeePerGas: 2n, maxPriorityFeePerGas: 1n },
        { maxFeePerGas: 2n, maxPriorityFeePerGas: 1n },
      ]);
      const fees =
        feeQuotes[Math.min(state.feeReads, feeQuotes.length - 1)];
      state.feeReads += 1;
      return fees;
    },

    async estimateContractGas(parameters) {
      record(`estimate:${parameters.functionName}`, parameters);
      if (parameters.functionName === "register") {
        if (options.registerEstimateError) {
          throw new Error(`Sensitive estimate failure ${PRIVATE_KEY}`);
        }
        return option(options, "registerGas", 180_000n);
      }
      if (parameters.functionName === "setAgentURI") {
        if (options.metadataEstimateError) {
          throw new Error(`Sensitive estimate failure ${PRIVATE_KEY}`);
        }
        return option(options, "metadataGas", 90_000n);
      }
      throw new Error("Unexpected estimateContractGas call.");
    },

    async waitForTransactionReceipt(parameters) {
      const stage =
        state.registrationHashes.has(parameters.hash)
          ? "register"
          : "metadata";
      record(`wait:${stage}`, parameters);
      if (
        (stage === "register" && options.registerWaitError) ||
        (stage === "metadata" && options.metadataWaitError)
      ) {
        throw new Error(`Sensitive receipt failure ${PRIVATE_KEY}`);
      }
      return stage === "register"
        ? createRegisterReceipt(parameters.hash)
        : createMetadataReceipt(parameters.hash);
    },
  };

  const walletClient = {
    async writeContract(parameters) {
      record(`write:${parameters.functionName}`, parameters);

      if (parameters.functionName === "register") {
        if (options.registerWriteError) {
          throw new Error(`Sensitive write failure ${PRIVATE_KEY}`);
        }
        state.initialURI = parameters.args[0];
        return registerHash;
      }
      if (parameters.functionName === "setAgentURI") {
        if (options.metadataWriteError) {
          throw new Error(`Sensitive write failure ${PRIVATE_KEY}`);
        }
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

function expectedRecovery(overrides = {}) {
  const recovery = {
    schema: "clockchain.handshake-registration-recovery/v1",
    chainId: 11_155_111,
    registryAddress: REGISTRY_ADDRESS,
    registryNamespace: REGISTRY_NAMESPACE,
    identityReference: `${REGISTRY_NAMESPACE}:42`,
    agentId: "42",
    address: DERIVED_ADDRESS,
    displayName: "Billy",
    registerTx: REGISTER_HASH,
    registerBlock: "123456",
    ...overrides,
  };

  if (
    Object.hasOwn(recovery, "metadataTx") &&
    !Object.hasOwn(recovery, "metadataNonce")
  ) {
    recovery.metadataNonce =
      recovery.metadataTx === RETRY_METADATA_HASH ? 2 : 1;
  }

  return recovery;
}

function expectedIntent(overrides = {}) {
  return {
    schema: "clockchain.handshake-registration-intent/v1",
    chainId: 11_155_111,
    registryAddress: REGISTRY_ADDRESS,
    registryNamespace: REGISTRY_NAMESPACE,
    address: DERIVED_ADDRESS,
    displayName: "Billy",
    registerNonce: 0,
    registerCalldata: encodeFunctionData({
      abi: ERC8004_ABI,
      functionName: "register",
      args: [initialRegistrationURI()],
    }),
    registerGas: "226000",
    maxFeePerGas: "2",
    maxPriorityFeePerGas: "1",
    ...overrides,
  };
}

function legacyIntent(overrides = {}) {
  const {
    maxFeePerGas: _maxFeePerGas,
    maxPriorityFeePerGas: _maxPriorityFeePerGas,
    ...intent
  } = expectedIntent();

  return { ...intent, gasPrice: "3000000000", ...overrides };
}

function withoutIntentKey(key) {
  const intent = expectedIntent();
  delete intent[key];
  return intent;
}

async function broadcastRegistrationIntent(options = {}) {
  const persisted = [];
  const fake = createFakeClients({
    registerWaitError: true,
    ...options,
  });
  const { rawTransactions, walletClient } = createRealSigningWallet(fake);
  const failure = await captureRejection(() =>
    registerIdentity({
      privateKey: PRIVATE_KEY,
      expectedAddress: DERIVED_ADDRESS,
      displayName: "Billy",
      publicClient: fake.publicClient,
      walletClient,
      onCheckpoint: async (record) => {
        persisted.push(structuredClone(record));
      },
    }),
  );

  assert.equal(rawTransactions.length, 1);
  assert.equal(persisted.length, 1);

  return {
    broadcastHash: keccak256(rawTransactions[0]),
    fake,
    failure,
    intent: structuredClone(persisted[0]),
  };
}

function checkpointStage(checkpoint) {
  if (checkpoint.schema.endsWith("-intent/v1")) {
    return "intent";
  }

  return checkpoint.metadataTx ? "metadata" : "registration";
}

function assertPublicPartialError(error, expected) {
  assert.ok(error instanceof PartialRegistrationError);
  assert.equal(error.code, "ERC8004_PARTIAL_REGISTRATION");
  assert.deepEqual(error.recovery, expected);
  assert.doesNotThrow(() => JSON.stringify(error.recovery));
  assert.equal(JSON.stringify(error.recovery).includes(PRIVATE_KEY), false);
  assert.equal(`${error.message}\n${error.stack ?? ""}`.includes(PRIVATE_KEY), false);
  assert.equal(Object.hasOwn(error, "cause"), false);
}

function assertNoMetadataActivity(fake) {
  const forbiddenCalls = new Set([
    "getTransaction:metadata",
    "getTransactionCount",
    "getBalance",
    "estimateFeesPerGas",
    "estimate:setAgentURI",
    "write:setAgentURI",
    "wait:metadata",
    "read:ownerOf",
    "read:getAgentWallet",
    "read:tokenURI",
  ]);

  assert.deepEqual(
    fake.state.calls
      .map(({ name }) => name)
      .filter((name) => forbiddenCalls.has(name)),
    [],
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

async function finalizeWithFakeClients(
  fake,
  recovery,
  overrides = {},
) {
  return finalizeIdentityRegistration({
    privateKey: PRIVATE_KEY,
    expectedAddress: DERIVED_ADDRESS,
    displayName: "Billy",
    recovery,
    publicClient: fake.publicClient,
    walletClient: fake.walletClient,
    ...overrides,
  });
}

function createRealSigningWallet(fake) {
  const rawTransactions = [];
  const walletClient = createWalletClient({
    account: privateKeyToAccount(PRIVATE_KEY),
    chain: sepolia,
    transport: custom({
      async request({ method, params }) {
        if (method !== "eth_sendRawTransaction") {
          throw new Error(`Unexpected wallet RPC method: ${method}`);
        }

        const rawTransaction = params[0];
        const transactionHash = keccak256(rawTransaction);
        const transaction = parseTransaction(rawTransaction);
        const decoded = decodeFunctionData({
          abi: ERC8004_ABI,
          data: transaction.data,
        });
        rawTransactions.push(rawTransaction);

        if (decoded.functionName === "register") {
          fake.state.initialURI = decoded.args[0];
          fake.state.registrationHashes.add(transactionHash);
        } else if (decoded.functionName === "setAgentURI") {
          fake.state.finalURI = decoded.args[1];
        }

        return transactionHash;
      },
    }),
  });

  return { rawTransactions, walletClient };
}

test("exports stable secret-safe registration error types", () => {
  assert.equal(typeof RegistrationNetworkError, "function");
  assert.equal(typeof RegistrationConfigurationError, "function");

  const networkError = new RegistrationNetworkError("Safe network failure.");
  assert.equal(networkError.name, "RegistrationNetworkError");
  assert.equal(networkError.code, "HANDSHAKE_REGISTRATION_NETWORK");
  assert.equal(networkError.category, "network");
  assert.equal(Object.hasOwn(networkError, "cause"), false);

  const configurationError = new RegistrationConfigurationError(
    "Safe configuration failure.",
  );
  assert.equal(configurationError.name, "RegistrationConfigurationError");
  assert.equal(
    configurationError.code,
    "HANDSHAKE_REGISTRATION_CONFIGURATION",
  );
  assert.equal(configurationError.category, "configuration");
  assert.equal(Object.hasOwn(configurationError, "cause"), false);
});

test("classifies caught RPC failures without retaining raw network details", async () => {
  const fake = createFakeClients({ feeErrorAt: "registration" });
  const error = await captureRejection(() => runWithFakeClients(fake));

  assert.ok(error instanceof RegistrationNetworkError);
  assert.equal(error.name, "RegistrationNetworkError");
  assert.equal(error.code, "HANDSHAKE_REGISTRATION_NETWORK");
  assert.equal(error.category, "network");
  assert.equal(error.message, "Registration fee estimation failed.");
  assert.equal(Object.hasOwn(error, "cause"), false);
  assertErrorOmits(error, PRIVATE_KEY, "Sensitive fee failure");
  assert.equal(JSON.stringify(error).includes(PRIVATE_KEY), false);
});

test("classifies pre-write wallet and funding failures as configuration errors", async (t) => {
  const pilotFeePerGas = 20_000_000_000n;
  const requiredBalance =
    (226_000n + 250_000n) * pilotFeePerGas;
  const malformedKey = "malformed-private-key-do-not-echo";
  const scenarios = [
    {
      name: "invalid private key",
      run: () => {
        const fake = createFakeClients();
        return registerIdentity({
          privateKey: malformedKey,
          expectedAddress: DERIVED_ADDRESS,
          displayName: "Billy",
          publicClient: fake.publicClient,
          walletClient: fake.walletClient,
        });
      },
      canaries: [malformedKey],
    },
    {
      name: "derived address mismatch",
      run: () =>
        runWithFakeClients(createFakeClients(), {
          expectedAddress: FOREIGN_ADDRESS,
        }),
      canaries: [PRIVATE_KEY],
    },
    {
      name: "nonzero initial nonce",
      run: () => runWithFakeClients(createFakeClients({ nonce: 1 })),
      canaries: [PRIVATE_KEY],
    },
    {
      name: "zero balance",
      run: () => runWithFakeClients(createFakeClients({ balance: 0n })),
      canaries: [PRIVATE_KEY],
    },
    {
      name: "insufficient fee envelope",
      run: () =>
        runWithFakeClients(
          createFakeClients({
            balance: requiredBalance - 1n,
            feeQuotes: [
              {
                maxFeePerGas: pilotFeePerGas,
                maxPriorityFeePerGas: 1n,
              },
            ],
          }),
        ),
      canaries: [PRIVATE_KEY],
    },
    {
      name: "invalid initial metadata",
      run: () =>
        runWithFakeClients(createFakeClients(), { displayName: "" }),
      canaries: [PRIVATE_KEY],
    },
  ];

  for (const scenario of scenarios) {
    await t.test(scenario.name, async () => {
      const error = await captureRejection(scenario.run);

      assert.ok(error instanceof RegistrationConfigurationError);
      assert.equal(error.name, "RegistrationConfigurationError");
      assert.equal(error.code, "HANDSHAKE_REGISTRATION_CONFIGURATION");
      assert.equal(error.category, "configuration");
      assert.equal(Object.hasOwn(error, "cause"), false);
      assertErrorOmits(error, ...scenario.canaries);
    });
  }
});

test("carries stable safe categories through partial registration errors", async (t) => {
  const scenarios = [
    {
      name: "network failure after registration",
      options: { metadataWaitError: true },
      category: "network",
      expected: expectedRecovery({ metadataTx: METADATA_HASH }),
    },
    {
      name: "configuration failure after registration",
      options: {
        balances: [10_000_000_000_000_000n, 0n],
      },
      category: "configuration",
      expected: expectedRecovery(),
    },
    {
      name: "protocol failure after registration",
      options: { finalOwner: FOREIGN_ADDRESS },
      category: "protocol",
      expected: expectedRecovery({ metadataTx: METADATA_HASH }),
    },
  ];

  for (const scenario of scenarios) {
    await t.test(scenario.name, async () => {
      const error = await captureRejection(() =>
        runWithFakeClients(createFakeClients(scenario.options)),
      );

      assertPublicPartialError(error, scenario.expected);
      assert.equal(error.code, "ERC8004_PARTIAL_REGISTRATION");
      assert.equal(error.category, scenario.category);
      assert.equal(Object.hasOwn(error, "cause"), false);
      assert.equal(Object.hasOwn(error, "originalError"), false);
      assertErrorOmits(
        error,
        PRIVATE_KEY,
        "Sensitive receipt failure",
      );
      assert.equal(JSON.stringify(error).includes(PRIVATE_KEY), false);
    });
  }
});

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
      "estimateFeesPerGas",
      "estimate:register",
      "getBalance",
      "write:register",
      "wait:register",
      "getChainId",
      "getCode",
      "read:getVersion",
      "getTransaction:register",
      "wait:register",
      "getTransactionCount",
      "getBalance",
      "estimateFeesPerGas",
      "estimate:setAgentURI",
      "write:setAgentURI",
      "getTransaction:metadata",
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
  assert.equal(registerWrite.gas, 226_000n);
  assert.equal(registerWrite.account.address, DERIVED_ADDRESS);
  assert.equal(registerWrite.nonce, 0);
  assert.equal(registerWrite.maxFeePerGas, 2n);
  assert.equal(registerWrite.maxPriorityFeePerGas, 1n);
  assert.deepEqual(registerWrite.args, registerEstimate.args);
  assert.equal(metadataEstimate.address, REGISTRY_ADDRESS);
  assert.equal(metadataEstimate.account.address, DERIVED_ADDRESS);
  assert.deepEqual(metadataEstimate.args, [42n, fake.state.finalURI]);
  assert.equal(metadataWrite.gas, 118_000n);
  assert.equal(metadataWrite.account.address, DERIVED_ADDRESS);
  assert.equal(metadataWrite.nonce, 1);
  assert.equal(metadataWrite.maxFeePerGas, 2n);
  assert.equal(metadataWrite.maxPriorityFeePerGas, 1n);
  assert.deepEqual(metadataWrite.args, metadataEstimate.args);

  const waits = fake.state.calls.filter(({ name }) => name.startsWith("wait:"));
  assert.deepEqual(
    waits.map(({ parameters }) => parameters),
    [
      {
        hash: REGISTER_HASH,
        confirmations: 2,
        timeout: 120_000,
      },
      {
        hash: REGISTER_HASH,
        confirmations: 2,
        timeout: 120_000,
      },
      {
        hash: METADATA_HASH,
        confirmations: 2,
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

test("rejects a positive balance that cannot fund the conservative two-transaction envelope", async () => {
  const bufferedRegisterGas = 226_000n;
  const conservativeMetadataReserve = 250_000n;
  const maxFeePerGas = 20_000_000_000n;
  const requiredBalance =
    (bufferedRegisterGas + conservativeMetadataReserve) * maxFeePerGas;
  const fake = createFakeClients({
    balance: requiredBalance - 1n,
    feeQuotes: [
      {
        maxFeePerGas,
        maxPriorityFeePerGas: 1n,
      },
    ],
  });
  const error = await captureRejection(() => runWithFakeClients(fake));

  assert.match(error.message, /balance|fee/i);
  assert.equal(
    fake.state.calls.some(({ name }) => name === "write:register"),
    false,
  );
});

test("enforces the inclusive pilot balance range immediately before the first write", async (t) => {
  for (const { label, balance } of [
    {
      label: "below minimum",
      balance: PILOT_MINIMUM_BALANCE_WEI - 1n,
    },
    {
      label: "above maximum",
      balance: PILOT_MAXIMUM_BALANCE_WEI + 1n,
    },
  ]) {
    await t.test(label, async () => {
      const fake = createFakeClients({ balance });
      const error = await captureRejection(() =>
        runWithFakeClients(fake),
      );

      assert.ok(
        error instanceof RegistrationConfigurationError,
      );
      assert.match(error.message, /0\.005.*0\.02|pilot balance/i);
      assert.equal(
        fake.state.calls.some(
          ({ name }) => name === "write:register",
        ),
        false,
      );
    });
  }

  for (const { label, balance } of [
    {
      label: "minimum",
      balance: PILOT_MINIMUM_BALANCE_WEI,
    },
    {
      label: "maximum",
      balance: PILOT_MAXIMUM_BALANCE_WEI,
    },
  ]) {
    await t.test(label, async () => {
      const fake = createFakeClients({ balance });
      await runWithFakeClients(fake);
      const callNames = fake.state.calls.map(
        ({ name }) => name,
      );

      assert.equal(
        callNames[callNames.indexOf("write:register") - 1],
        "getBalance",
      );
    });
  }
});

test("does not apply the initial pilot balance floor to recovery finalization", async () => {
  const fake = createFakeClients({
    balance: 1_000_000_000_000_000n,
    nonce: 1,
  });

  await finalizeWithFakeClients(fake, expectedRecovery());

  assert.equal(
    fake.state.calls.some(
      ({ name }) => name === "write:setAgentURI",
    ),
    true,
  );
});

test("adds deterministic gas headroom and explicit fee and nonce fields to both writes", async () => {
  const fake = createFakeClients();
  await runWithFakeClients(fake);

  const registerWrite = fake.state.calls.find(
    ({ name }) => name === "write:register",
  ).parameters;
  const metadataWrite = fake.state.calls.find(
    ({ name }) => name === "write:setAgentURI",
  ).parameters;
  assert.deepEqual(
    {
      chainId: registerWrite.chainId,
      gas: registerWrite.gas,
      maxFeePerGas: registerWrite.maxFeePerGas,
      maxPriorityFeePerGas: registerWrite.maxPriorityFeePerGas,
      nonce: registerWrite.nonce,
    },
    {
      chainId: 11_155_111,
      gas: 226_000n,
      maxFeePerGas: 2n,
      maxPriorityFeePerGas: 1n,
      nonce: 0,
    },
  );
  assert.deepEqual(
    {
      chainId: metadataWrite.chainId,
      gas: metadataWrite.gas,
      maxFeePerGas: metadataWrite.maxFeePerGas,
      maxPriorityFeePerGas: metadataWrite.maxPriorityFeePerGas,
      nonce: metadataWrite.nonce,
    },
    {
      chainId: 11_155_111,
      gas: 118_000n,
      maxFeePerGas: 2n,
      maxPriorityFeePerGas: 1n,
      nonce: 1,
    },
  );
});

test("uses validated legacy gas prices for both explicitly signed writes", async () => {
  const fake = createFakeClients({
    feeQuotes: [{ gasPrice: 3n }, { gasPrice: 4n }],
  });
  await runWithFakeClients(fake);

  const registerWrite = fake.state.calls.find(
    ({ name }) => name === "write:register",
  ).parameters;
  const metadataWrite = fake.state.calls.find(
    ({ name }) => name === "write:setAgentURI",
  ).parameters;
  assert.deepEqual(
    {
      gasPrice: registerWrite.gasPrice,
      maxFeePerGas: registerWrite.maxFeePerGas,
      maxPriorityFeePerGas: registerWrite.maxPriorityFeePerGas,
    },
    {
      gasPrice: 3n,
      maxFeePerGas: undefined,
      maxPriorityFeePerGas: undefined,
    },
  );
  assert.deepEqual(
    {
      gasPrice: metadataWrite.gasPrice,
      maxFeePerGas: metadataWrite.maxFeePerGas,
      maxPriorityFeePerGas: metadataWrite.maxPriorityFeePerGas,
    },
    {
      gasPrice: 4n,
      maxFeePerGas: undefined,
      maxPriorityFeePerGas: undefined,
    },
  );
});

test("rejects malformed fee quotes before their corresponding write", async () => {
  const invalidRegistration = createFakeClients({
    feeQuotes: [
      { maxFeePerGas: 2n, maxPriorityFeePerGas: 3n },
    ],
  });
  const registrationError = await captureRejection(() =>
    runWithFakeClients(invalidRegistration),
  );
  assert.match(registrationError.message, /fee quote/i);
  assert.equal(
    invalidRegistration.state.calls.some(
      ({ name }) => name === "write:register",
    ),
    false,
  );

  const invalidMetadata = createFakeClients({
    feeQuotes: [
      { maxFeePerGas: 2n, maxPriorityFeePerGas: 1n },
      {
        gasPrice: 2n,
        maxFeePerGas: 2n,
        maxPriorityFeePerGas: 1n,
      },
    ],
  });
  const metadataError = await captureRejection(() =>
    runWithFakeClients(invalidMetadata),
  );
  assertPublicPartialError(metadataError, expectedRecovery());
  assert.equal(
    invalidMetadata.state.calls.some(
      ({ name }) => name === "write:setAgentURI",
    ),
    false,
  );
});

test("signs and decodes both contract writes through a real viem wallet transport", async () => {
  const fake = createFakeClients();
  const { rawTransactions, walletClient } = createRealSigningWallet(fake);

  await registerIdentity({
    privateKey: PRIVATE_KEY,
    expectedAddress: DERIVED_ADDRESS,
    displayName: "Billy",
    publicClient: fake.publicClient,
    walletClient,
  });

  assert.equal(rawTransactions.length, 2);
  const transactions = rawTransactions.map((rawTransaction) =>
    parseTransaction(rawTransaction),
  );
  const calls = transactions.map((transaction) =>
    decodeFunctionData({
      abi: ERC8004_ABI,
      data: transaction.data,
    }),
  );

  assert.deepEqual(
    transactions.map(
      ({
        chainId,
        gas,
        maxFeePerGas,
        maxPriorityFeePerGas,
        nonce,
        to,
      }) => ({
        chainId,
        gas,
        maxFeePerGas,
        maxPriorityFeePerGas,
        nonce,
        to: to.toLowerCase(),
      }),
    ),
    [
      {
        chainId: 11_155_111,
        gas: 226_000n,
        maxFeePerGas: 2n,
        maxPriorityFeePerGas: 1n,
        nonce: 0,
        to: REGISTRY_ADDRESS.toLowerCase(),
      },
      {
        chainId: 11_155_111,
        gas: 118_000n,
        maxFeePerGas: 2n,
        maxPriorityFeePerGas: 1n,
        nonce: 1,
        to: REGISTRY_ADDRESS.toLowerCase(),
      },
    ],
  );
  assert.deepEqual(calls, [
    {
      functionName: "register",
      args: [fake.state.initialURI],
    },
    {
      functionName: "setAgentURI",
      args: [42n, fake.state.finalURI],
    },
  ]);
  assert.deepEqual(
    decodeRegistrationDataURI(fake.state.initialURI).registrations,
    [],
  );
  assert.deepEqual(
    decodeRegistrationDataURI(fake.state.finalURI).registrations,
    [{ agentRegistry: REGISTRY_NAMESPACE, agentId: 42 }],
  );
});

test("returns a secret-free public partial checkpoint for every post-registration failure stage", async () => {
  const scenarios = [
    {
      name: "registration checkpoint callback",
      options: {},
      onCheckpoint: async (checkpoint) => {
        if (checkpointStage(checkpoint) === "registration") {
          throw new Error(`Sensitive checkpoint failure ${PRIVATE_KEY}`);
        }
      },
      expected: expectedRecovery(),
    },
    {
      name: "metadata balance",
      options: {
        balances: [10_000_000_000_000_000n, 0n],
      },
      expected: expectedRecovery(),
    },
    {
      name: "metadata fee quote",
      options: { feeErrorAt: "metadata" },
      expected: expectedRecovery(),
    },
    {
      name: "metadata estimate",
      options: { metadataEstimateError: true },
      expected: expectedRecovery(),
    },
    {
      name: "metadata write",
      options: { metadataWriteError: true },
      expected: expectedRecovery(),
    },
    {
      name: "metadata checkpoint callback",
      options: {},
      onCheckpoint: async (checkpoint) => {
        if (checkpoint.metadataTx) {
          throw new Error(`Sensitive checkpoint failure ${PRIVATE_KEY}`);
        }
      },
      expected: expectedRecovery({ metadataTx: METADATA_HASH }),
    },
    {
      name: "metadata transaction lookup",
      options: { metadataTransactionError: true },
      expected: expectedRecovery({ metadataTx: METADATA_HASH }),
    },
    {
      name: "metadata wait",
      options: { metadataWaitError: true },
      expected: expectedRecovery({ metadataTx: METADATA_HASH }),
    },
    {
      name: "final readback",
      options: { finalOwner: FOREIGN_ADDRESS },
      expected: expectedRecovery({ metadataTx: METADATA_HASH }),
    },
  ];

  for (const scenario of scenarios) {
    const fake = createFakeClients(scenario.options);
    const error = await captureRejection(() =>
      runWithFakeClients(fake, {
        onCheckpoint: scenario.onCheckpoint,
      }),
    );

    assertPublicPartialError(error, scenario.expected);
  }
});

test("checkpoints before the register broadcast, after registration, and after metadata submission", async () => {
  const fake = createFakeClients();
  const checkpoints = [];

  await runWithFakeClients(fake, {
    onCheckpoint: async (checkpoint) => {
      fake.state.calls.push({
        name: `checkpoint:${checkpointStage(checkpoint)}`,
      });
      checkpoints.push(structuredClone(checkpoint));
    },
  });

  assert.deepEqual(checkpoints, [
    expectedIntent(),
    expectedRecovery(),
    expectedRecovery({ metadataTx: METADATA_HASH }),
  ]);
  const names = fake.state.calls.map(({ name }) => name);
  assert.ok(
    names.indexOf("checkpoint:intent") < names.indexOf("write:register"),
    "the intent record must be written before the register broadcast",
  );
  assert.ok(
    names.indexOf("estimate:register") <
      names.indexOf("checkpoint:intent"),
  );
  assert.ok(
    names.indexOf("wait:register") <
      names.indexOf("checkpoint:registration"),
  );
  assert.ok(
    names.indexOf("checkpoint:registration") <
      names.lastIndexOf("getTransactionCount"),
  );
  assert.ok(
    names.indexOf("write:setAgentURI") <
      names.indexOf("checkpoint:metadata"),
  );
  assert.ok(
    names.indexOf("checkpoint:metadata") <
      names.indexOf("wait:metadata"),
  );
});

test("rejects a mutated agent identity that the registration event does not prove", async () => {
  const recovery = expectedRecovery({
    agentId: "43",
    identityReference: `${REGISTRY_NAMESPACE}:43`,
  });
  const fake = createFakeClients({ nonces: [1] });
  const error = await captureRejection(() =>
    finalizeWithFakeClients(fake, recovery),
  );

  assertPublicPartialError(error, recovery);
  assert.deepEqual(
    fake.state.calls.map(({ name }) => name),
    [
      "getChainId",
      "getCode",
      "read:getVersion",
      "getTransaction:register",
      "wait:register",
    ],
  );
  assertNoMetadataActivity(fake);
});

test("rejects registration checkpoints whose transaction fields do not bind to the recovery", async (t) => {
  const wrongInitialURI = `${initialRegistrationURI()}-wrong`;
  const scenarios = [
    {
      name: "mutated recovery block",
      recovery: expectedRecovery({ registerBlock: "123457" }),
    },
    {
      name: "transaction hash",
      options: {
        registerTransactionOverrides: { hash: UNRELATED_HASH },
      },
    },
    {
      name: "transaction chain",
      options: {
        registerTransactionOverrides: { chainId: 1 },
      },
    },
    {
      name: "transaction sender",
      options: {
        registerTransactionOverrides: { from: FOREIGN_ADDRESS },
      },
    },
    {
      name: "transaction destination",
      options: {
        registerTransactionOverrides: { to: FOREIGN_ADDRESS },
      },
    },
    {
      name: "transaction nonce",
      options: {
        registerTransactionOverrides: { nonce: 1 },
      },
    },
    {
      name: "transaction value",
      options: {
        registerTransactionOverrides: { value: 1n },
      },
    },
    {
      name: "transaction block",
      options: {
        registerTransactionOverrides: { blockNumber: 123_457n },
      },
    },
    {
      name: "unrelated calldata",
      options: {
        registerTransactionOverrides: {
          input: encodeFunctionData({
            abi: ERC8004_ABI,
            functionName: "setAgentURI",
            args: [42n, finalRegistrationURI()],
          }),
        },
      },
    },
    {
      name: "mutated hash pointing to unrelated calldata",
      recovery: expectedRecovery({ registerTx: UNRELATED_HASH }),
      options: {
        recoveryRegisterHash: UNRELATED_HASH,
        registerTransactionOverrides: {
          input: encodeFunctionData({
            abi: ERC8004_ABI,
            functionName: "setAgentURI",
            args: [42n, finalRegistrationURI()],
          }),
        },
      },
    },
    {
      name: "wrong initial URI",
      options: {
        registerTransactionOverrides: {
          input: encodeFunctionData({
            abi: ERC8004_ABI,
            functionName: "register",
            args: [wrongInitialURI],
          }),
        },
      },
    },
    {
      name: "missing transaction",
      options: { registerTransactionError: true },
    },
  ];

  for (const scenario of scenarios) {
    await t.test(scenario.name, async () => {
      const recovery = scenario.recovery ?? expectedRecovery();
      const fake = createFakeClients({
        nonces: [1],
        ...scenario.options,
      });
      const error = await captureRejection(() =>
        finalizeWithFakeClients(fake, recovery),
      );

      assertPublicPartialError(error, recovery);
      assertNoMetadataActivity(fake);
    });
  }
});

test("rejects missing, reverted, or mismatched registration receipts before metadata work", async (t) => {
  const scenarios = [
    {
      name: "missing receipt",
      options: { registerReceipt: undefined },
    },
    {
      name: "receipt wait failure",
      options: { registerWaitError: true },
    },
    {
      name: "reverted receipt",
      options: { registerStatus: "reverted" },
    },
    {
      name: "receipt hash",
      options: { registerReceiptHash: UNRELATED_HASH },
    },
    {
      name: "receipt block",
      options: { registerBlockNumber: 123_457n },
    },
    {
      name: "event agent ID",
      options: { registerEventAgentId: 43n },
    },
    {
      name: "event URI",
      options: { registerEventURI: `${initialRegistrationURI()}-wrong` },
    },
    {
      name: "event owner",
      options: { eventMode: "wrongOwner" },
    },
    {
      name: "ambiguous event",
      options: { eventMode: "duplicate" },
    },
  ];

  for (const scenario of scenarios) {
    await t.test(scenario.name, async () => {
      const recovery = expectedRecovery();
      const fake = createFakeClients({
        nonces: [1],
        ...scenario.options,
      });
      const error = await captureRejection(() =>
        finalizeWithFakeClients(fake, recovery),
      );

      assertPublicPartialError(error, recovery);
      assertNoMetadataActivity(fake);
    });
  }
});

test("rejects checkpointed metadata transactions that do not encode the proven finalization", async (t) => {
  const wrongURI = `${finalRegistrationURI()}-wrong`;
  const scenarios = [
    {
      name: "transaction hash",
      overrides: { hash: UNRELATED_HASH },
    },
    {
      name: "transaction chain",
      overrides: { chainId: 1 },
    },
    {
      name: "transaction sender",
      overrides: { from: FOREIGN_ADDRESS },
    },
    {
      name: "transaction destination",
      overrides: { to: FOREIGN_ADDRESS },
    },
    {
      name: "transaction value",
      overrides: { value: 1n },
    },
    {
      name: "transaction nonce",
      overrides: { nonce: 2 },
    },
    {
      name: "unrelated calldata",
      overrides: {
        input: encodeFunctionData({
          abi: ERC8004_ABI,
          functionName: "register",
          args: [initialRegistrationURI()],
        }),
      },
    },
    {
      name: "wrong agent ID",
      overrides: {
        input: encodeFunctionData({
          abi: ERC8004_ABI,
          functionName: "setAgentURI",
          args: [43n, finalRegistrationURI(43n)],
        }),
      },
    },
    {
      name: "wrong final URI",
      overrides: {
        input: encodeFunctionData({
          abi: ERC8004_ABI,
          functionName: "setAgentURI",
          args: [42n, wrongURI],
        }),
      },
    },
  ];

  for (const scenario of scenarios) {
    await t.test(scenario.name, async () => {
      const recovery = expectedRecovery({
        metadataTx: METADATA_HASH,
        metadataNonce: 1,
      });
      const fake = createFakeClients({
        finalTokenURI: finalRegistrationURI(),
        metadataTransactionOverrides: scenario.overrides,
      });
      const error = await captureRejection(() =>
        finalizeWithFakeClients(fake, recovery),
      );

      assertPublicPartialError(error, recovery);
      assert.equal(
        fake.state.calls.some(({ name }) => name === "wait:metadata"),
        false,
      );
      assert.equal(
        fake.state.calls.some(({ name }) => name.startsWith("read:owner")),
        false,
      );
      assert.equal(
        fake.state.calls.some(({ name }) => name.startsWith("write:")),
        false,
      );
    });
  }
});

test("binds a valid resumed recovery to exact registration and metadata evidence", async () => {
  const recovery = expectedRecovery({
    metadataTx: METADATA_HASH,
    metadataNonce: 1,
  });
  const fake = createFakeClients({
    finalTokenURI: finalRegistrationURI(),
  });
  const evidence = await finalizeWithFakeClients(fake, recovery);

  assert.equal(evidence.metadataTx, METADATA_HASH);
  assert.deepEqual(
    fake.state.calls.map(({ name }) => name),
    [
      "getChainId",
      "getCode",
      "read:getVersion",
      "getTransaction:register",
      "wait:register",
      "getTransaction:metadata",
      "wait:metadata",
      "read:ownerOf",
      "read:getAgentWallet",
      "read:tokenURI",
    ],
  );
  assert.deepEqual(
    fake.state.calls
      .filter(({ name }) => name.startsWith("getTransaction:"))
      .map(({ parameters }) => parameters),
    [{ hash: REGISTER_HASH }, { hash: METADATA_HASH }],
  );
  assert.deepEqual(
    fake.state.calls
      .filter(({ name }) => name.startsWith("wait:"))
      .map(({ parameters }) => parameters),
    [
      {
        hash: REGISTER_HASH,
        confirmations: 2,
        timeout: 120_000,
      },
      {
        hash: METADATA_HASH,
        confirmations: 2,
        timeout: 120_000,
      },
    ],
  );
});

test("resumes a clean public checkpoint without registering again", async () => {
  const firstFake = createFakeClients({
    balances: [10_000_000_000_000_000n, 0n],
  });
  const partial = await captureRejection(() =>
    runWithFakeClients(firstFake),
  );
  assertPublicPartialError(partial, expectedRecovery());

  const resumedFake = createFakeClients({
    nonces: [1],
  });
  const evidence = await finalizeIdentityRegistration({
    privateKey: PRIVATE_KEY,
    expectedAddress: DERIVED_ADDRESS,
    displayName: "Billy",
    recovery: partial.recovery,
    publicClient: resumedFake.publicClient,
    walletClient: resumedFake.walletClient,
  });

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
    document: buildRegistrationDocument({
      displayName: "Billy",
      agentId: 42n,
    }),
  });
  assert.equal(
    resumedFake.state.calls.some(({ name }) => name === "write:register"),
    false,
  );
  assert.equal(
    resumedFake.state.calls.filter(
      ({ name }) => name === "write:setAgentURI",
    ).length,
    1,
  );
});

test("waits and verifies an existing metadata transaction before any resubmission", async () => {
  const finalURI = registrationDataUri(
    buildRegistrationDocument({ displayName: "Billy", agentId: 42n }),
  );
  const fake = createFakeClients({
    finalTokenURI: finalURI,
  });
  const evidence = await finalizeIdentityRegistration({
    privateKey: PRIVATE_KEY,
    expectedAddress: DERIVED_ADDRESS,
    displayName: "Billy",
    recovery: expectedRecovery({ metadataTx: METADATA_HASH }),
    publicClient: fake.publicClient,
    walletClient: fake.walletClient,
  });

  assert.equal(evidence.metadataTx, METADATA_HASH);
  assert.equal(evidence.metadataBlock, "123457");
  assert.equal(
    fake.state.calls.some(({ name }) => name.startsWith("write:")),
    false,
  );
  assert.equal(
    fake.state.calls.some(({ name }) => name.startsWith("estimate:")),
    false,
  );
  assert.ok(
    fake.state.calls.some(({ name }) => name === "wait:metadata"),
  );
});

test("never resubmits checkpointed metadata on lookup, wait, or unknown-status failures", async (t) => {
  const scenarios = [
    {
      name: "transaction lookup failure",
      options: { metadataTransactionError: true },
    },
    {
      name: "receipt wait failure",
      options: { metadataWaitError: true },
    },
    {
      name: "unknown receipt status",
      options: { metadataStatus: "pending" },
    },
  ];

  for (const scenario of scenarios) {
    await t.test(scenario.name, async () => {
      const recovery = expectedRecovery({
        metadataTx: METADATA_HASH,
        metadataNonce: 1,
      });
      const fake = createFakeClients({
        finalTokenURI: finalRegistrationURI(),
        ...scenario.options,
      });
      const error = await captureRejection(() =>
        finalizeWithFakeClients(fake, recovery),
      );

      assertPublicPartialError(error, recovery);
      assert.equal(
        fake.state.calls.some(({ name }) => name.startsWith("write:")),
        false,
      );
    });
  }
});

test("resubmits metadata only after the checkpoint transaction is confirmed reverted", async () => {
  const fake = createFakeClients({
    metadataHash: RETRY_METADATA_HASH,
    metadataStatuses: ["reverted", "success"],
    nonces: [2],
  });
  const checkpoints = [];
  const evidence = await finalizeIdentityRegistration({
    privateKey: PRIVATE_KEY,
    expectedAddress: DERIVED_ADDRESS,
    displayName: "Billy",
    recovery: expectedRecovery({ metadataTx: METADATA_HASH }),
    publicClient: fake.publicClient,
    walletClient: fake.walletClient,
    onCheckpoint: async (checkpoint) => {
      checkpoints.push(structuredClone(checkpoint));
    },
  });

  const names = fake.state.calls.map(({ name }) => name);
  assert.ok(
    names.indexOf("wait:metadata") <
      names.indexOf("write:setAgentURI"),
  );
  assert.equal(
    fake.state.calls.find(
      ({ name }) => name === "write:setAgentURI",
    ).parameters.nonce,
    2,
  );
  assert.deepEqual(checkpoints, [
    expectedRecovery({ metadataTx: RETRY_METADATA_HASH }),
  ]);
  assert.deepEqual(
    fake.state.calls
      .filter(({ name }) => name.startsWith("getTransaction:"))
      .map(({ parameters }) => parameters.hash),
    [REGISTER_HASH, METADATA_HASH, RETRY_METADATA_HASH],
  );
  assert.equal(evidence.metadataTx, RETRY_METADATA_HASH);
});

test("rejects an ambiguous nonce gap after a confirmed metadata revert", async () => {
  const recovery = expectedRecovery({
    metadataTx: METADATA_HASH,
    metadataNonce: 1,
  });
  const fake = createFakeClients({
    metadataHash: RETRY_METADATA_HASH,
    metadataStatuses: ["reverted", "success"],
    metadataTransactionOverrides: (hash) =>
      hash === RETRY_METADATA_HASH ? { nonce: 3 } : {},
    nonces: [3],
  });
  const error = await captureRejection(() =>
    finalizeWithFakeClients(fake, recovery),
  );

  assertPublicPartialError(error, recovery);
  assert.equal(
    fake.state.calls.some(({ name }) => name === "write:setAgentURI"),
    false,
  );
});

test("does not reuse the nonce of a confirmed reverted metadata transaction", async () => {
  const recovery = expectedRecovery({
    metadataTx: METADATA_HASH,
    metadataNonce: 2,
  });
  const fake = createFakeClients({
    metadataHash: RETRY_METADATA_HASH,
    metadataStatuses: ["reverted", "success"],
    metadataTransactionOverrides: (hash) =>
      hash === METADATA_HASH ? { nonce: 2 } : {},
    nonces: [2],
  });
  const error = await captureRejection(() =>
    finalizeWithFakeClients(fake, recovery),
  );

  assertPublicPartialError(error, recovery);
  assert.equal(
    fake.state.calls.some(({ name }) => name === "write:setAgentURI"),
    false,
  );
});

test("retains a confirmed reverted hash until a replacement hash exists", async () => {
  const fake = createFakeClients({
    metadataStatuses: ["reverted"],
    metadataWriteError: true,
    nonces: [2],
  });
  const checkpoints = [];
  const recovery = expectedRecovery({ metadataTx: METADATA_HASH });
  const error = await captureRejection(() =>
    finalizeIdentityRegistration({
      privateKey: PRIVATE_KEY,
      expectedAddress: DERIVED_ADDRESS,
      displayName: "Billy",
      recovery,
      publicClient: fake.publicClient,
      walletClient: fake.walletClient,
      onCheckpoint: async (checkpoint) => {
        checkpoints.push(structuredClone(checkpoint));
      },
    }),
  );

  assertPublicPartialError(error, recovery);
  assert.deepEqual(checkpoints, []);
  assert.ok(
    fake.state.calls.indexOf(
      fake.state.calls.find(({ name }) => name === "wait:metadata"),
    ) <
      fake.state.calls.indexOf(
        fake.state.calls.find(
          ({ name }) => name === "write:setAgentURI",
        ),
      ),
  );
});

test("does not guess when a clean checkpoint has an unknown pending nonce", async () => {
  const fake = createFakeClients({
    nonces: [2],
  });
  const error = await captureRejection(() =>
    finalizeIdentityRegistration({
      privateKey: PRIVATE_KEY,
      expectedAddress: DERIVED_ADDRESS,
      displayName: "Billy",
      recovery: expectedRecovery(),
      publicClient: fake.publicClient,
      walletClient: fake.walletClient,
    }),
  );

  assertPublicPartialError(error, expectedRecovery());
  assert.equal(
    fake.state.calls.some(({ name }) => name.startsWith("write:")),
    false,
  );
});

test("strictly validates recovery schema and caller identity before RPC calls", async () => {
  const invalidRecoveries = [
    { ...expectedRecovery(), extra: true },
    { ...expectedRecovery(), chainId: 1 },
    { ...expectedRecovery(), registryAddress: FOREIGN_ADDRESS },
    { ...expectedRecovery(), registryNamespace: "eip155:1:wrong" },
    { ...expectedRecovery(), identityReference: `${REGISTRY_NAMESPACE}:41` },
    { ...expectedRecovery(), agentId: "042" },
    { ...expectedRecovery(), address: FOREIGN_ADDRESS },
    { ...expectedRecovery(), displayName: "Iris" },
    { ...expectedRecovery(), registerTx: "0x1234" },
    { ...expectedRecovery(), registerBlock: "0x123456" },
    { ...expectedRecovery(), metadataTx: "0x1234" },
    { ...expectedRecovery(), metadataTx: METADATA_HASH },
    { ...expectedRecovery(), metadataNonce: 1 },
    expectedRecovery({
      metadataTx: METADATA_HASH,
      metadataNonce: -1,
    }),
    expectedRecovery({
      metadataTx: METADATA_HASH,
      metadataNonce: 1n,
    }),
  ];

  for (const recovery of invalidRecoveries) {
    const fake = createFakeClients();
    const error = await captureRejection(() =>
      finalizeIdentityRegistration({
        privateKey: PRIVATE_KEY,
        expectedAddress: DERIVED_ADDRESS,
        displayName: "Billy",
        recovery,
        publicClient: fake.publicClient,
        walletClient: fake.walletClient,
      }),
    );

    assert.equal(error instanceof PartialRegistrationError, false);
    assert.match(error.message, /recovery/i);
    assert.deepEqual(fake.state.calls, []);
  }
});

test("rejects an invalid checkpoint callback before the registration write", async () => {
  const fake = createFakeClients();
  const error = await captureRejection(() =>
    runWithFakeClients(fake, { onCheckpoint: null }),
  );

  assert.equal(error instanceof PartialRegistrationError, false);
  assert.ok(error instanceof RegistrationConfigurationError);
  assert.equal(error.code, "HANDSHAKE_REGISTRATION_CONFIGURATION");
  assert.equal(error.category, "configuration");
  assert.match(error.message, /checkpoint callback/i);
  assert.deepEqual(fake.state.calls, []);
});

test("rejects an invalid checkpoint callback before a resumed metadata write", async () => {
  const fake = createFakeClients({ nonces: [1] });
  const error = await captureRejection(() =>
    finalizeWithFakeClients(fake, expectedRecovery(), {
      onCheckpoint: null,
    }),
  );

  assert.equal(error instanceof PartialRegistrationError, false);
  assert.ok(error instanceof RegistrationConfigurationError);
  assert.equal(error.code, "HANDSHAKE_REGISTRATION_CONFIGURATION");
  assert.equal(error.category, "configuration");
  assert.match(error.message, /checkpoint callback/i);
  assert.deepEqual(fake.state.calls, []);
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

test("rejects a zero balance immediately before the first write", async () => {
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
      "estimateFeesPerGas",
      "estimate:register",
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
    ["getBalance", "write:register", "wait:register"],
  );
  assert.equal(
    firstFake.state.calls.some(({ name }) => name === "write:setAgentURI"),
    false,
  );

  const secondFake = createFakeClients({ metadataStatus: "reverted" });
  const secondError = await captureRejection(() =>
    runWithFakeClients(secondFake),
  );
  assertPublicPartialError(
    secondError,
    expectedRecovery({ metadataTx: METADATA_HASH }),
  );
  assert.deepEqual(
    secondFake.state.calls.slice(-4).map(({ name }) => name),
    [
      "estimate:setAgentURI",
      "write:setAgentURI",
      "getTransaction:metadata",
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

test("returns partial recovery for final owner, agent wallet, and token URI mismatches", async () => {
  for (const options of [
    { finalOwner: FOREIGN_ADDRESS },
    { finalWallet: FOREIGN_ADDRESS },
    { finalTokenURI: `${FIXTURE_URI}-wrong` },
  ]) {
    const fake = createFakeClients(options);
    const error = await captureRejection(() => runWithFakeClients(fake));

    assertPublicPartialError(
      error,
      expectedRecovery({ metadataTx: METADATA_HASH }),
    );
  }
});

test("rejects missing transaction hashes and receipt evidence fields", async () => {
  for (const options of [
    { registerHash: undefined },
    { registerReceiptHash: undefined },
    { registerBlockNumber: undefined },
  ]) {
    const fake = createFakeClients(options);
    const error = await captureRejection(() => runWithFakeClients(fake));

    assert.match(error.message, /transaction|receipt/i);
  }

  for (const [options, expected] of [
    [{ metadataHash: undefined }, expectedRecovery()],
    [
      { metadataReceiptHash: undefined },
      expectedRecovery({ metadataTx: METADATA_HASH }),
    ],
    [
      { metadataBlockNumber: undefined },
      expectedRecovery({ metadataTx: METADATA_HASH }),
    ],
  ]) {
    const fake = createFakeClients(options);
    const error = await captureRejection(() => runWithFakeClients(fake));

    assertPublicPartialError(error, expected);
  }
});

test("recovers a fresh registration whose receipt wait failed after broadcast", async () => {
  const persisted = [];
  const checkpointWriter = async (record) => {
    persisted.push(structuredClone(record));
  };
  const firstFake = createFakeClients({ registerWaitError: true });
  const { rawTransactions, walletClient } =
    createRealSigningWallet(firstFake);
  const failure = await captureRejection(() =>
    registerIdentity({
      privateKey: PRIVATE_KEY,
      expectedAddress: DERIVED_ADDRESS,
      displayName: "Billy",
      publicClient: firstFake.publicClient,
      walletClient,
      onCheckpoint: checkpointWriter,
    }),
  );

  assert.equal(rawTransactions.length, 1);
  const broadcastHash = keccak256(rawTransactions[0]);
  assert.ok(failure instanceof RegistrationNetworkError);
  assertErrorOmits(failure, PRIVATE_KEY, "Sensitive receipt failure");
  assert.equal(
    failure.registerTx,
    broadcastHash,
    "the broadcast register hash must be surfaced for hand recovery",
  );
  assert.equal(
    persisted.length,
    1,
    "a pre-broadcast intent record must survive a failed receipt wait",
  );

  const intent = structuredClone(persisted.at(-1));
  const secondFake = createFakeClients({
    registerHash: broadcastHash,
    nonces: [1],
  });
  const evidence = await registerIdentity({
    privateKey: PRIVATE_KEY,
    expectedAddress: DERIVED_ADDRESS,
    displayName: "Billy",
    intent,
    publicClient: secondFake.publicClient,
    walletClient: secondFake.walletClient,
    onCheckpoint: checkpointWriter,
  });

  assert.equal(evidence.registerTx, broadcastHash);
  assert.equal(evidence.agentId, "42");
  assert.equal(
    secondFake.state.calls.some(({ name }) => name === "write:register"),
    false,
    "resuming from an intent record must never re-broadcast register",
  );
  assert.deepEqual(persisted.slice(1), [
    expectedRecovery({ registerTx: broadcastHash }),
    expectedRecovery({
      metadataTx: METADATA_HASH,
      registerTx: broadcastHash,
    }),
  ]);
});

test("surfaces the broadcast hash as failure evidence when the register receipt wait fails", async () => {
  const checkpoints = [];
  const fake = createFakeClients({ registerWaitError: true });
  const error = await captureRejection(() =>
    runWithFakeClients(fake, {
      onCheckpoint: async (checkpoint) => {
        checkpoints.push(structuredClone(checkpoint));
      },
    }),
  );

  assert.ok(error instanceof RegistrationNetworkError);
  assert.equal(error.message, "Registration receipt wait failed.");
  assert.equal(error.category, "network");
  assert.equal(error instanceof PartialRegistrationError, false);
  assert.equal(error.registerTx, REGISTER_HASH);
  assert.equal(Object.hasOwn(error, "recovery"), false);
  assert.equal(Object.hasOwn(error, "agentId"), false);
  assert.equal(Object.hasOwn(error, "cause"), false);
  assert.equal(
    JSON.parse(JSON.stringify(error)).registerTx,
    REGISTER_HASH,
  );
  assertErrorOmits(error, PRIVATE_KEY, "Sensitive receipt failure");
  assert.deepEqual(checkpoints, [expectedIntent()]);
  assert.deepEqual(
    fake.state.calls.slice(-2).map(({ name }) => name),
    ["write:register", "wait:register"],
  );
  assert.equal(
    fake.state.calls.some(({ name }) => name === "write:setAgentURI"),
    false,
  );
});

test("refuses to broadcast when the pre-broadcast intent record cannot be recorded", async () => {
  const fake = createFakeClients();
  const error = await captureRejection(() =>
    runWithFakeClients(fake, {
      onCheckpoint: async () => {
        throw new Error(`Sensitive checkpoint failure ${PRIVATE_KEY}`);
      },
    }),
  );

  assert.equal(error instanceof PartialRegistrationError, false);
  assert.ok(error instanceof RegistrationConfigurationError);
  assert.equal(error.category, "configuration");
  assert.match(error.message, /intent record/i);
  assert.equal(Object.hasOwn(error, "registerTx"), false);
  assertErrorOmits(
    error,
    PRIVATE_KEY,
    "Sensitive checkpoint failure",
  );
  assert.equal(
    fake.state.calls.some(({ name }) => name.startsWith("write:")),
    false,
  );
  assert.deepEqual(fake.state.calls.at(-1).name, "getBalance");
});

test("wraps a typed checkpoint failure before the pre-broadcast intent record", async () => {
  for (const failure of [
    () =>
      new RegistrationConfigurationError(
        `Sensitive checkpoint failure ${PRIVATE_KEY}`,
      ),
    () =>
      new RegistrationNetworkError(
        `Sensitive checkpoint failure ${PRIVATE_KEY}`,
      ),
  ]) {
    const fake = createFakeClients();
    const error = await captureRejection(() =>
      runWithFakeClients(fake, {
        onCheckpoint: async () => {
          throw failure();
        },
      }),
    );

    assert.equal(error instanceof PartialRegistrationError, false);
    assert.ok(error instanceof RegistrationConfigurationError);
    assert.equal(error.category, "configuration");
    assert.match(
      error.message,
      /intent record could not be recorded/i,
    );
    assertErrorOmits(
      error,
      PRIVATE_KEY,
      "Sensitive checkpoint failure",
    );
    assert.equal(
      fake.state.calls.some(({ name }) => name.startsWith("write:")),
      false,
    );
  }
});

test("keeps the pre-broadcast intent record failure typed for a degenerate fee quote", async () => {
  let reads = 0;
  const poisonedQuote = {
    get maxFeePerGas() {
      reads += 1;
      return reads > 4 ? 0n : 2n;
    },
    maxPriorityFeePerGas: 1n,
  };
  const fake = createFakeClients({ feeQuotes: [poisonedQuote] });
  const error = await captureRejection(() =>
    runWithFakeClients(fake),
  );

  assert.equal(error instanceof PartialRegistrationError, false);
  assert.ok(error instanceof RegistrationConfigurationError);
  assert.equal(error.category, "configuration");
  assert.equal(error.code, "HANDSHAKE_REGISTRATION_CONFIGURATION");
  assert.match(error.message, /intent record is invalid/i);
  assert.equal(
    fake.state.calls.some(({ name }) => name.startsWith("write:")),
    false,
  );
});

test("preserves the typed registration failure when the error cannot carry the transaction", async () => {
  const sealedFailure = Object.preventExtensions(
    new Error("Registration receipt status read failed."),
  );
  const fake = createFakeClients({
    registerReceipt: {
      get status() {
        throw sealedFailure;
      },
      transactionHash: REGISTER_HASH,
      blockNumber: 123_456n,
      logs: [],
    },
  });
  const error = await captureRejection(() =>
    runWithFakeClients(fake),
  );

  assert.equal(error instanceof TypeError, false);
  assert.equal(error, sealedFailure);
  assert.equal(
    error.message,
    "Registration receipt status read failed.",
  );
  assert.equal(Object.hasOwn(error, "registerTx"), false);
  assert.equal(
    fake.state.calls.some(
      ({ name }) => name === "write:setAgentURI",
    ),
    false,
  );
});

test("resumes an intent record through a real wallet without signing a second register", async () => {
  const { broadcastHash, intent } = await broadcastRegistrationIntent();
  const fake = createFakeClients({
    registerHash: broadcastHash,
    nonces: [1],
  });
  const { rawTransactions, walletClient } = createRealSigningWallet(fake);
  const evidence = await registerIdentity({
    privateKey: PRIVATE_KEY,
    expectedAddress: DERIVED_ADDRESS,
    displayName: "Billy",
    intent,
    publicClient: fake.publicClient,
    walletClient,
  });

  assert.equal(evidence.registerTx, broadcastHash);
  assert.equal(rawTransactions.length, 1);
  assert.deepEqual(
    decodeFunctionData({
      abi: ERC8004_ABI,
      data: parseTransaction(rawTransactions[0]).data,
    }).functionName,
    "setAgentURI",
  );
  assert.equal(parseTransaction(rawTransactions[0]).nonce, 1);
});

test("recovers a legacy-priced registration intent without re-broadcasting", async () => {
  const legacyFees = [{ gasPrice: 3_000_000_000n }];
  const { broadcastHash, intent } = await broadcastRegistrationIntent({
    feeQuotes: legacyFees,
  });

  assert.equal(intent.gasPrice, "3000000000");
  assert.equal(Object.hasOwn(intent, "maxFeePerGas"), false);
  assert.equal(Object.hasOwn(intent, "maxPriorityFeePerGas"), false);

  const fake = createFakeClients({
    feeQuotes: legacyFees,
    registerHash: broadcastHash,
    nonces: [1],
  });
  const evidence = await registerIdentity({
    privateKey: PRIVATE_KEY,
    expectedAddress: DERIVED_ADDRESS,
    displayName: "Billy",
    intent,
    publicClient: fake.publicClient,
    walletClient: fake.walletClient,
  });

  assert.equal(evidence.registerTx, broadcastHash);
  assert.equal(
    fake.state.calls.some(({ name }) => name === "write:register"),
    false,
  );
});

test("never re-broadcasts register when intent recovery cannot prove the transaction", async (t) => {
  const { broadcastHash, intent } = await broadcastRegistrationIntent();
  const scenarios = [
    {
      name: "transaction lookup failure",
      options: { registerTransactionError: true },
    },
    {
      name: "transaction sender mismatch",
      options: {
        registerTransactionOverrides: { from: FOREIGN_ADDRESS },
      },
    },
    {
      name: "transaction nonce mismatch",
      options: { registerTransactionOverrides: { nonce: 1 } },
    },
    {
      name: "unrelated calldata",
      options: {
        registerTransactionOverrides: {
          input: encodeFunctionData({
            abi: ERC8004_ABI,
            functionName: "setAgentURI",
            args: [42n, finalRegistrationURI()],
          }),
        },
      },
    },
    {
      name: "receipt wait failure",
      options: { registerWaitError: true },
    },
    {
      name: "reverted receipt",
      options: { registerStatus: "reverted" },
    },
    {
      name: "foreign registration event",
      options: { eventMode: "foreign" },
    },
  ];

  for (const scenario of scenarios) {
    await t.test(scenario.name, async () => {
      const checkpoints = [];
      const fake = createFakeClients({
        registerHash: broadcastHash,
        nonces: [1],
        ...scenario.options,
      });
      const error = await captureRejection(() =>
        registerIdentity({
          privateKey: PRIVATE_KEY,
          expectedAddress: DERIVED_ADDRESS,
          displayName: "Billy",
          intent,
          publicClient: fake.publicClient,
          walletClient: fake.walletClient,
          onCheckpoint: async (checkpoint) => {
            checkpoints.push(structuredClone(checkpoint));
          },
        }),
      );

      assert.equal(error instanceof PartialRegistrationError, false);
      assert.equal(error.registerTx, broadcastHash);
      assert.deepEqual(checkpoints, []);
      assertErrorOmits(error, PRIVATE_KEY);
      assert.equal(
        fake.state.calls.some(({ name }) => name.startsWith("write:")),
        false,
      );
    });
  }
});

test("rejects an intent record whose calldata does not encode the invitation identity", async () => {
  const fake = createFakeClients({ nonces: [1] });
  const error = await captureRejection(() =>
    registerIdentity({
      privateKey: PRIVATE_KEY,
      expectedAddress: DERIVED_ADDRESS,
      displayName: "Billy",
      intent: expectedIntent({
        registerCalldata: encodeFunctionData({
          abi: ERC8004_ABI,
          functionName: "register",
          args: [`${initialRegistrationURI()}-wrong`],
        }),
      }),
      publicClient: fake.publicClient,
      walletClient: fake.walletClient,
    }),
  );

  assert.ok(error instanceof RegistrationConfigurationError);
  assert.match(error.message, /intent calldata/i);
  assert.equal(
    fake.state.calls.some(({ name }) => name.startsWith("write:")),
    false,
  );
  assert.equal(
    fake.state.calls.some(({ name }) =>
      name.startsWith("getTransaction:"),
    ),
    false,
  );
});

test("re-records a fresh intent before broadcasting when the pending nonce is still zero", async () => {
  const { intent } = await broadcastRegistrationIntent({
    feeQuotes: [{ maxFeePerGas: 9n, maxPriorityFeePerGas: 4n }],
  });
  assert.equal(intent.maxFeePerGas, "9");

  const checkpoints = [];
  const fake = createFakeClients();
  const evidence = await registerIdentity({
    privateKey: PRIVATE_KEY,
    expectedAddress: DERIVED_ADDRESS,
    displayName: "Billy",
    intent,
    publicClient: fake.publicClient,
    walletClient: fake.walletClient,
    onCheckpoint: async (checkpoint) => {
      checkpoints.push(structuredClone(checkpoint));
    },
  });

  assert.equal(evidence.registerTx, REGISTER_HASH);
  assert.deepEqual(checkpoints[0], expectedIntent());
  assert.deepEqual(
    checkpoints.map((checkpoint) => checkpointStage(checkpoint)),
    ["intent", "registration", "metadata"],
  );
  assert.equal(
    fake.state.calls.filter(({ name }) => name === "write:register")
      .length,
    1,
  );
});

test("keeps the nonce gate absolute when no intent record is available", async () => {
  for (const intent of [undefined, null]) {
    const fake = createFakeClients({ nonce: 1 });
    const error = await captureRejection(() =>
      registerIdentity({
        privateKey: PRIVATE_KEY,
        expectedAddress: DERIVED_ADDRESS,
        displayName: "Billy",
        intent,
        publicClient: fake.publicClient,
        walletClient: fake.walletClient,
      }),
    );

    assert.ok(error instanceof RegistrationConfigurationError);
    assert.match(error.message, /nonce must be zero/i);
    assert.deepEqual(
      fake.state.calls.map(({ name }) => name),
      [
        "getChainId",
        "getCode",
        "read:getVersion",
        "getTransactionCount",
      ],
    );
  }
});

test("strictly validates the intent record schema before any RPC call", async () => {
  const invalidIntents = [
    { ...expectedIntent(), extra: true },
    withoutIntentKey("registerGas"),
    withoutIntentKey("registerCalldata"),
    withoutIntentKey("maxPriorityFeePerGas"),
    expectedIntent({ schema: RECOVERY_SCHEMA }),
    expectedIntent({ chainId: 1 }),
    expectedIntent({ registryAddress: FOREIGN_ADDRESS }),
    expectedIntent({ registryNamespace: "eip155:1:wrong" }),
    expectedIntent({ address: FOREIGN_ADDRESS }),
    expectedIntent({ address: "not-an-address" }),
    expectedIntent({ displayName: "Iris" }),
    expectedIntent({ displayName: "" }),
    expectedIntent({ registerNonce: 1 }),
    expectedIntent({ registerNonce: "0" }),
    expectedIntent({ registerNonce: 0n }),
    expectedIntent({ registerCalldata: "0x1" }),
    expectedIntent({ registerCalldata: "0x" }),
    expectedIntent({ registerCalldata: "not-hex" }),
    expectedIntent({ registerGas: "0" }),
    expectedIntent({ registerGas: "0226000" }),
    expectedIntent({ registerGas: 226_000 }),
    expectedIntent({ registerGas: 226_000n }),
    expectedIntent({ maxFeePerGas: "0" }),
    expectedIntent({ maxFeePerGas: "0x2" }),
    expectedIntent({ maxPriorityFeePerGas: "-1" }),
    expectedIntent({ maxPriorityFeePerGas: "3" }),
    expectedIntent({ gasPrice: "2" }),
    { ...legacyIntent(), maxFeePerGas: "2" },
    legacyIntent({ gasPrice: "0" }),
    legacyIntent({ gasPrice: "02" }),
    expectedRecovery(),
    "intent",
    42,
    [],
  ];

  for (const intent of invalidIntents) {
    const fake = createFakeClients();
    const error = await captureRejection(() =>
      registerIdentity({
        privateKey: PRIVATE_KEY,
        expectedAddress: DERIVED_ADDRESS,
        displayName: "Billy",
        intent,
        publicClient: fake.publicClient,
        walletClient: fake.walletClient,
      }),
    );

    assert.equal(error instanceof PartialRegistrationError, false);
    assert.match(error.message, /intent record is invalid/i);
    assert.deepEqual(fake.state.calls, []);
  }
});

test("keeps the full recovery checkpoint schema closed to intent records", async () => {
  for (const recovery of [
    expectedIntent(),
    legacyIntent(),
    { ...expectedRecovery(), schema: INTENT_SCHEMA },
  ]) {
    const fake = createFakeClients();
    const error = await captureRejection(() =>
      finalizeIdentityRegistration({
        privateKey: PRIVATE_KEY,
        expectedAddress: DERIVED_ADDRESS,
        displayName: "Billy",
        recovery,
        publicClient: fake.publicClient,
        walletClient: fake.walletClient,
      }),
    );

    assert.equal(error instanceof PartialRegistrationError, false);
    assert.match(error.message, /recovery checkpoint is invalid/i);
    assert.deepEqual(fake.state.calls, []);
  }
});
