import {
  decodeFunctionData,
  encodeFunctionData,
  keccak256,
  parseEventLogs,
} from "viem";
import { privateKeyToAccount } from "viem/accounts";

import {
  CHAIN_ID,
  REGISTRY_ADDRESS,
  RPC_URL,
} from "./constants.mjs";
import {
  CONSERVATIVE_METADATA_GAS_RESERVE,
  RECEIPT_CONFIRMATIONS,
  RECEIPT_TIMEOUT_MILLISECONDS,
  REGISTER_NONCE,
  RegistrationConfigurationError,
  RegistrationNetworkError,
  addGasHeadroom,
  addressesEqual,
  createRecovery,
  createRegistrationClients,
  createRegistrationIntent,
  estimateFeeQuote,
  identityReferenceValue,
  intentTransactionFields,
  intentTransactionType,
  invokeCheckpoint,
  isRevertedReceipt,
  isSuccessfulReceipt,
  isTransactionHash,
  normalizeAgentId,
  normalizePendingNonce,
  registryNamespaceValue,
  runStage,
  validateCheckpointCallback,
  validateDisplayName,
  validateReceipt,
  validateReceiptEvidence,
  validateRecovery,
  validateRegistrationIntent,
  validateTransactionHash,
  withMetadataTransaction,
  withoutMetadataTransaction,
} from "./registration-internal.mjs";

export {
  RegistrationConfigurationError,
  RegistrationNetworkError,
};

const REGISTRATION_TYPE =
  "https://eips.ethereum.org/EIPS/eip-8004#registration-v1";
const REGISTRATION_DESCRIPTION =
  "Ephemeral Clockchain Handshake testnet identity; registration does not establish capability or trust.";
const REGISTRY_VERSION = "2.0.0";
const PILOT_MINIMUM_BALANCE_WEI =
  5_000_000_000_000_000n;
const PILOT_MAXIMUM_BALANCE_WEI =
  20_000_000_000_000_000n;

export const ERC8004_ABI = [
  {
    type: "function",
    name: "getVersion",
    stateMutability: "view",
    inputs: [],
    outputs: [{ name: "", type: "string" }],
  },
  {
    type: "function",
    name: "register",
    stateMutability: "nonpayable",
    inputs: [{ name: "agentURI", type: "string" }],
    outputs: [{ name: "agentId", type: "uint256" }],
  },
  {
    type: "function",
    name: "setAgentURI",
    stateMutability: "nonpayable",
    inputs: [
      { name: "agentId", type: "uint256" },
      { name: "newURI", type: "string" },
    ],
    outputs: [],
  },
  {
    type: "function",
    name: "ownerOf",
    stateMutability: "view",
    inputs: [{ name: "tokenId", type: "uint256" }],
    outputs: [{ name: "", type: "address" }],
  },
  {
    type: "function",
    name: "tokenURI",
    stateMutability: "view",
    inputs: [{ name: "tokenId", type: "uint256" }],
    outputs: [{ name: "", type: "string" }],
  },
  {
    type: "function",
    name: "getAgentWallet",
    stateMutability: "view",
    inputs: [{ name: "agentId", type: "uint256" }],
    outputs: [{ name: "", type: "address" }],
  },
  {
    type: "event",
    name: "Registered",
    anonymous: false,
    inputs: [
      {
        name: "agentId",
        type: "uint256",
        indexed: true,
      },
      {
        name: "agentURI",
        type: "string",
        indexed: false,
      },
      {
        name: "owner",
        type: "address",
        indexed: true,
      },
    ],
  },
];

const RECOVERY_TRANSACTION_ABI = [
  {
    type: "function",
    name: "register",
    stateMutability: "nonpayable",
    inputs: [{ name: "agentURI", type: "string" }],
    outputs: [{ name: "agentId", type: "uint256" }],
  },
  {
    type: "function",
    name: "setAgentURI",
    stateMutability: "nonpayable",
    inputs: [
      { name: "agentId", type: "uint256" },
      { name: "newURI", type: "string" },
    ],
    outputs: [],
  },
];

function isOfficialRegistryLog(log) {
  return addressesEqual(log?.address, REGISTRY_ADDRESS);
}

async function verifyOfficialRegistry(publicClient) {
  const chainId = await runStage(
    () => publicClient.getChainId(),
    "Ethereum Sepolia chain verification failed.",
  );
  if (chainId !== CHAIN_ID) {
    throw new Error("Ethereum Sepolia chain verification failed.");
  }

  const bytecode = await runStage(
    () => publicClient.getCode({ address: REGISTRY_ADDRESS }),
    "Official registry contract verification failed.",
  );
  if (
    typeof bytecode !== "string" ||
    !/^0x(?:[0-9a-fA-F]{2})+$/.test(bytecode)
  ) {
    throw new Error("Official registry contract is not deployed.");
  }

  const version = await runStage(
    () =>
      publicClient.readContract({
        address: REGISTRY_ADDRESS,
        abi: ERC8004_ABI,
        functionName: "getVersion",
      }),
    "Official registry version verification failed.",
  );
  if (version !== REGISTRY_VERSION) {
    throw new Error("Official registry version is unsupported.");
  }

  return chainId;
}

export function registryNamespace() {
  return registryNamespaceValue();
}

export function identityReference(agentId) {
  return identityReferenceValue(agentId);
}

export function buildRegistrationDocument({
  displayName,
  agentId = null,
}) {
  validateDisplayName(displayName);
  const registrations =
    agentId === null
      ? []
      : [
          {
            agentRegistry: registryNamespace(),
            agentId: Number(normalizeAgentId(agentId, { jsonSafe: true })),
          },
        ];

  return {
    type: REGISTRATION_TYPE,
    name: displayName,
    description: REGISTRATION_DESCRIPTION,
    services: [],
    x402Support: false,
    active: true,
    registrations,
  };
}

export function registrationDataUri(document) {
  const json = JSON.stringify(document);
  return `data:application/json;base64,${Buffer.from(json, "utf8").toString("base64")}`;
}

export function parseRegisteredAgentId(
  receipt,
  { expectedOwner, expectedAgentURI },
) {
  if (!isSuccessfulReceipt(receipt)) {
    throw new Error("Registration receipt was not successful.");
  }

  const officialLogs = Array.isArray(receipt.logs)
    ? receipt.logs.filter(isOfficialRegistryLog)
    : [];
  let events;

  try {
    events = parseEventLogs({
      abi: ERC8004_ABI,
      eventName: "Registered",
      logs: officialLogs,
      strict: true,
    });
  } catch {
    throw new Error(
      "Registration receipt must contain exactly one official Registered event.",
    );
  }

  if (events.length !== 1) {
    throw new Error(
      "Registration receipt must contain exactly one official Registered event.",
    );
  }

  const { agentId, agentURI, owner } = events[0].args;
  let ownerMatches = false;

  try {
    ownerMatches = addressesEqual(owner, expectedOwner);
  } catch {
    ownerMatches = false;
  }

  if (!ownerMatches) {
    throw new Error(
      "Registered event owner does not match the stakeholder address.",
    );
  }

  if (agentURI !== expectedAgentURI) {
    throw new Error(
      "Registered event URI does not match the submitted registration document.",
    );
  }

  return normalizeAgentId(agentId);
}

function validateTransactionEnvelope(
  transaction,
  {
    expectedBlockNumber,
    expectedFrom,
    expectedHash,
    expectedNonce,
    stage,
  },
) {
  try {
    validateTransactionHash(transaction?.hash, stage);
    if (
      transaction.hash.toLowerCase() !== expectedHash.toLowerCase() ||
      transaction.chainId !== CHAIN_ID ||
      !addressesEqual(transaction.from, expectedFrom) ||
      !addressesEqual(transaction.to, REGISTRY_ADDRESS) ||
      transaction.nonce !== expectedNonce ||
      transaction.value !== 0n ||
      typeof transaction.input !== "string" ||
      !/^0x(?:[0-9a-fA-F]{2})+$/.test(transaction.input) ||
      (expectedBlockNumber !== undefined &&
        (typeof transaction.blockNumber !== "bigint" ||
          transaction.blockNumber !== expectedBlockNumber))
    ) {
      throw new Error();
    }
  } catch {
    throw new Error(`${stage} transaction evidence is invalid.`);
  }

  return transaction.input;
}

function validateExactTransactionCall({
  args,
  functionName,
  input,
  stage,
}) {
  try {
    const decoded = decodeFunctionData({
      abi: RECOVERY_TRANSACTION_ABI,
      data: input,
    });
    const canonicalInput = encodeFunctionData({
      abi: RECOVERY_TRANSACTION_ABI,
      functionName,
      args,
    });

    if (
      decoded.functionName !== functionName ||
      decoded.args.length !== args.length ||
      decoded.args.some((argument, index) => argument !== args[index]) ||
      input.toLowerCase() !== canonicalInput.toLowerCase()
    ) {
      throw new Error();
    }
  } catch {
    throw new Error(`${stage} transaction calldata is invalid.`);
  }
}

async function verifyRegistrationRecoveryEvidence({
  account,
  agentId,
  initialURI,
  publicClient,
  recovery,
}) {
  const transaction = await runStage(
    () => publicClient.getTransaction({ hash: recovery.registerTx }),
    "Registration transaction lookup failed.",
  );
  const expectedBlockNumber = BigInt(recovery.registerBlock);
  const input = validateTransactionEnvelope(transaction, {
    expectedBlockNumber,
    expectedFrom: account.address,
    expectedHash: recovery.registerTx,
    expectedNonce: 0,
    stage: "Registration",
  });
  validateExactTransactionCall({
    args: [initialURI],
    functionName: "register",
    input,
    stage: "Registration",
  });

  const receipt = await runStage(
    () =>
      publicClient.waitForTransactionReceipt({
        hash: recovery.registerTx,
        confirmations: RECEIPT_CONFIRMATIONS,
        timeout: RECEIPT_TIMEOUT_MILLISECONDS,
      }),
    "Registration receipt wait failed.",
  );
  const receiptBlock = validateReceipt(
    receipt,
    recovery.registerTx,
    "Registration",
  );
  if (receiptBlock !== expectedBlockNumber) {
    throw new Error("Registration receipt block is invalid.");
  }

  let receiptAgentId;
  try {
    receiptAgentId = parseRegisteredAgentId(receipt, {
      expectedOwner: account.address,
      expectedAgentURI: initialURI,
    });
  } catch {
    throw new Error("Registration event evidence is invalid.");
  }
  if (receiptAgentId !== agentId) {
    throw new Error("Registration agent identity is invalid.");
  }
}

async function verifyMetadataTransactionEvidence({
  account,
  agentId,
  finalURI,
  publicClient,
  recovery,
}) {
  const transaction = await runStage(
    () => publicClient.getTransaction({ hash: recovery.metadataTx }),
    "Metadata transaction lookup failed.",
  );
  const input = validateTransactionEnvelope(transaction, {
    expectedFrom: account.address,
    expectedHash: recovery.metadataTx,
    expectedNonce: recovery.metadataNonce,
    stage: "Metadata",
  });
  validateExactTransactionCall({
    args: [agentId, finalURI],
    functionName: "setAgentURI",
    input,
    stage: "Metadata",
  });
}

export class PartialRegistrationError extends Error {
  constructor(recovery, underlyingError) {
    super("ERC-8004 identity registration is incomplete.");
    this.name = "PartialRegistrationError";
    this.code = "ERC8004_PARTIAL_REGISTRATION";
    this.category =
      underlyingError instanceof RegistrationNetworkError
        ? "network"
        : underlyingError instanceof RegistrationConfigurationError
          ? "configuration"
          : "protocol";
    this.recovery = Object.freeze(validateRecovery(recovery));
  }
}

function attachRegisterTransaction(error, registerTx) {
  if (
    !(error instanceof Error) ||
    !isTransactionHash(registerTx) ||
    Object.hasOwn(error, "registerTx") ||
    !Object.isExtensible(error)
  ) {
    return error;
  }

  try {
    Object.defineProperty(error, "registerTx", {
      value: registerTx,
      enumerable: true,
      writable: false,
      configurable: false,
    });
  } catch {
    // The typed failure matters more than the transaction annotation.
  }

  return error;
}

function encodeRegisterCalldata(initialURI) {
  return encodeFunctionData({
    abi: ERC8004_ABI,
    functionName: "register",
    args: [initialURI],
  });
}

async function recoverIntendedRegisterHash(account, intent) {
  let serialized;

  try {
    serialized = await account.signTransaction({
      chainId: CHAIN_ID,
      data: intent.registerCalldata,
      gas: BigInt(intent.registerGas),
      nonce: intent.registerNonce,
      to: REGISTRY_ADDRESS,
      type: intentTransactionType(intent),
      value: 0n,
      ...intentTransactionFields(intent),
    });
  } catch {
    throw new RegistrationConfigurationError(
      "Registration intent transaction could not be reconstructed.",
    );
  }

  let hash;

  try {
    hash = keccak256(serialized);
  } catch {
    throw new RegistrationConfigurationError(
      "Registration intent transaction could not be reconstructed.",
    );
  }

  validateTransactionHash(hash, "Registration");
  return hash;
}

function createVerifiedAccount(privateKey, expectedAddress) {
  let account;

  try {
    account = privateKeyToAccount(privateKey);
  } catch {
    throw new RegistrationConfigurationError("Private key is invalid.");
  }

  if (!addressesEqual(account.address, expectedAddress)) {
    throw new RegistrationConfigurationError(
      "Derived wallet address does not match the expected address.",
    );
  }

  return account;
}

async function verifyFinalReadback({
  account,
  agentId,
  finalURI,
  publicClient,
}) {
  const owner = await runStage(
    () =>
      publicClient.readContract({
        address: REGISTRY_ADDRESS,
        abi: ERC8004_ABI,
        functionName: "ownerOf",
        args: [agentId],
      }),
    "Final owner read failed.",
  );
  if (!addressesEqual(owner, account.address)) {
    throw new Error("Final owner verification failed.");
  }

  const agentWallet = await runStage(
    () =>
      publicClient.readContract({
        address: REGISTRY_ADDRESS,
        abi: ERC8004_ABI,
        functionName: "getAgentWallet",
        args: [agentId],
      }),
    "Final agent wallet read failed.",
  );
  if (!addressesEqual(agentWallet, account.address)) {
    throw new Error("Final agent wallet verification failed.");
  }

  const tokenURI = await runStage(
    () =>
      publicClient.readContract({
        address: REGISTRY_ADDRESS,
        abi: ERC8004_ABI,
        functionName: "tokenURI",
        args: [agentId],
      }),
    "Final token URI read failed.",
  );
  if (tokenURI !== finalURI) {
    throw new Error("Final token URI verification failed.");
  }
}

function createCompletedEvidence({
  document,
  metadataBlock,
  metadataTx,
  recovery,
}) {
  return {
    chainId: recovery.chainId,
    registryAddress: recovery.registryAddress,
    registryNamespace: recovery.registryNamespace,
    identityReference: recovery.identityReference,
    agentId: recovery.agentId,
    address: recovery.address,
    displayName: recovery.displayName,
    registerTx: recovery.registerTx,
    registerBlock: recovery.registerBlock,
    metadataTx,
    metadataBlock: metadataBlock.toString(10),
    document,
  };
}

export async function finalizeIdentityRegistration({
  privateKey,
  expectedAddress,
  displayName,
  recovery,
  rpcUrl = RPC_URL,
  publicClient,
  walletClient,
  onCheckpoint = async () => {},
}) {
  validateCheckpointCallback(onCheckpoint);
  const account = createVerifiedAccount(privateKey, expectedAddress);
  let checkpoint = validateRecovery(recovery, {
    expectedAddress: account.address,
    displayName,
  });

  try {
    const {
      activePublicClient,
      activeWalletClient,
    } = createRegistrationClients({
      account,
      publicClient,
      rpcUrl,
      walletClient,
    });
    await verifyOfficialRegistry(activePublicClient);

    const agentId = normalizeAgentId(BigInt(checkpoint.agentId));
    const initialDocument = buildRegistrationDocument({
      displayName,
      agentId: null,
    });
    const initialURI = registrationDataUri(initialDocument);
    await verifyRegistrationRecoveryEvidence({
      account,
      agentId,
      initialURI,
      publicClient: activePublicClient,
      recovery: checkpoint,
    });

    const document = buildRegistrationDocument({ displayName, agentId });
    const finalURI = registrationDataUri(document);
    let recoveredFromRevert = false;
    let submissionRecovery = checkpoint;

    if (checkpoint.metadataTx) {
      await verifyMetadataTransactionEvidence({
        account,
        agentId,
        finalURI,
        publicClient: activePublicClient,
        recovery: checkpoint,
      });
      const existingMetadataReceipt = await runStage(
        () =>
          activePublicClient.waitForTransactionReceipt({
            hash: checkpoint.metadataTx,
            confirmations: RECEIPT_CONFIRMATIONS,
            timeout: RECEIPT_TIMEOUT_MILLISECONDS,
          }),
        "Metadata receipt wait failed.",
      );
      const existingMetadataBlock = validateReceiptEvidence(
        existingMetadataReceipt,
        checkpoint.metadataTx,
        "Metadata",
      );

      if (isSuccessfulReceipt(existingMetadataReceipt)) {
        await verifyFinalReadback({
          account,
          agentId,
          finalURI,
          publicClient: activePublicClient,
        });
        return createCompletedEvidence({
          document,
          metadataBlock: existingMetadataBlock,
          metadataTx: checkpoint.metadataTx,
          recovery: checkpoint,
        });
      }

      if (!isRevertedReceipt(existingMetadataReceipt)) {
        throw new Error("Metadata receipt status is invalid.");
      }

      recoveredFromRevert = true;
      submissionRecovery = withoutMetadataTransaction(checkpoint);
    }

    const pendingNonceValue = await runStage(
      () =>
        activePublicClient.getTransactionCount({
          address: account.address,
          blockTag: "pending",
        }),
      "Metadata wallet nonce verification failed.",
    );
    const pendingNonce = normalizePendingNonce(pendingNonceValue);
    if (
      (!recoveredFromRevert && pendingNonce !== 1) ||
      (recoveredFromRevert &&
        pendingNonce !== checkpoint.metadataNonce + 1)
    ) {
      throw new Error("Metadata wallet nonce is unsafe.");
    }

    const metadataBalance = await runStage(
      () => activePublicClient.getBalance({ address: account.address }),
      "Metadata wallet balance verification failed.",
    );
    if (
      typeof metadataBalance !== "bigint" ||
      metadataBalance <= 0n
    ) {
      throw new RegistrationConfigurationError(
        "Metadata wallet balance must be greater than zero.",
      );
    }

    const metadataFees = await estimateFeeQuote(
      activePublicClient,
      "Metadata",
    );
    const metadataGasEstimate = await runStage(
      () =>
        activePublicClient.estimateContractGas({
          address: REGISTRY_ADDRESS,
          abi: ERC8004_ABI,
          functionName: "setAgentURI",
          args: [agentId, finalURI],
          account,
        }),
      "Metadata gas estimation failed.",
    );
    let metadataGas;

    try {
      metadataGas = addGasHeadroom(metadataGasEstimate);
    } catch {
      throw new Error("Metadata gas estimate is invalid.");
    }

    if (metadataBalance < metadataGas * metadataFees.unitPrice) {
      throw new RegistrationConfigurationError(
        "Wallet balance cannot fund metadata finalization at current fees.",
      );
    }

    const metadataTx = await runStage(
      () =>
        activeWalletClient.writeContract({
          address: REGISTRY_ADDRESS,
          abi: ERC8004_ABI,
          functionName: "setAgentURI",
          args: [agentId, finalURI],
          account,
          chainId: CHAIN_ID,
          gas: metadataGas,
          nonce: pendingNonce,
          ...metadataFees.transactionFields,
        }),
      "Metadata transaction submission failed.",
    );
    validateTransactionHash(metadataTx, "Metadata");
    checkpoint = withMetadataTransaction(
      submissionRecovery,
      metadataTx,
      pendingNonce,
    );
    await invokeCheckpoint(onCheckpoint, checkpoint);
    await verifyMetadataTransactionEvidence({
      account,
      agentId,
      finalURI,
      publicClient: activePublicClient,
      recovery: checkpoint,
    });

    const metadataReceipt = await runStage(
      () =>
        activePublicClient.waitForTransactionReceipt({
          hash: metadataTx,
          confirmations: RECEIPT_CONFIRMATIONS,
          timeout: RECEIPT_TIMEOUT_MILLISECONDS,
        }),
      "Metadata receipt wait failed.",
    );
    const metadataBlock = validateReceipt(
      metadataReceipt,
      metadataTx,
      "Metadata",
    );
    await verifyFinalReadback({
      account,
      agentId,
      finalURI,
      publicClient: activePublicClient,
    });

    return createCompletedEvidence({
      document,
      metadataBlock,
      metadataTx,
      recovery: checkpoint,
    });
  } catch (error) {
    if (error instanceof PartialRegistrationError) {
      throw error;
    }

    throw new PartialRegistrationError(checkpoint, error);
  }
}

async function completeRegistrationFromIntent({
  account,
  displayName,
  expectedAddress,
  initialURI,
  intent,
  onCheckpoint,
  privateKey,
  publicClient,
  rpcUrl,
  walletClient,
}) {
  if (
    intent.registerCalldata.toLowerCase() !==
    encodeRegisterCalldata(initialURI).toLowerCase()
  ) {
    throw new RegistrationConfigurationError(
      "Registration intent calldata does not match the registration document.",
    );
  }

  const registerTx = await recoverIntendedRegisterHash(account, intent);
  let recovery;

  try {
    const transaction = await runStage(
      () => publicClient.getTransaction({ hash: registerTx }),
      "Registration transaction lookup failed.",
    );
    const input = validateTransactionEnvelope(transaction, {
      expectedFrom: account.address,
      expectedHash: registerTx,
      expectedNonce: REGISTER_NONCE,
      stage: "Registration",
    });
    validateExactTransactionCall({
      args: [initialURI],
      functionName: "register",
      input,
      stage: "Registration",
    });

    const registerReceipt = await runStage(
      () =>
        publicClient.waitForTransactionReceipt({
          hash: registerTx,
          confirmations: RECEIPT_CONFIRMATIONS,
          timeout: RECEIPT_TIMEOUT_MILLISECONDS,
        }),
      "Registration receipt wait failed.",
    );
    const registerBlock = validateReceipt(
      registerReceipt,
      registerTx,
      "Registration",
    );

    let agentId;

    try {
      agentId = parseRegisteredAgentId(registerReceipt, {
        expectedOwner: account.address,
        expectedAgentURI: initialURI,
      });
    } catch {
      throw new Error("Registration event verification failed.");
    }

    recovery = createRecovery({
      address: account.address,
      agentId,
      displayName,
      registerBlock,
      registerTx,
    });
  } catch (error) {
    throw attachRegisterTransaction(error, registerTx);
  }

  try {
    await invokeCheckpoint(onCheckpoint, recovery);
    return await finalizeIdentityRegistration({
      privateKey,
      expectedAddress,
      displayName,
      recovery,
      rpcUrl,
      publicClient,
      walletClient,
      onCheckpoint,
    });
  } catch (error) {
    if (error instanceof PartialRegistrationError) {
      throw error;
    }

    throw new PartialRegistrationError(recovery, error);
  }
}

export async function registerIdentity({
  privateKey,
  expectedAddress,
  displayName,
  intent,
  rpcUrl = RPC_URL,
  publicClient,
  walletClient,
  onCheckpoint = async () => {},
}) {
  validateCheckpointCallback(onCheckpoint);
  const account = createVerifiedAccount(privateKey, expectedAddress);
  const priorIntent =
    intent === undefined || intent === null
      ? null
      : validateRegistrationIntent(intent, {
          expectedAddress: account.address,
          displayName,
        });
  let activePublicClient;
  let activeWalletClient;

  try {
    ({
      activePublicClient,
      activeWalletClient,
    } = createRegistrationClients({
      account,
      publicClient,
      rpcUrl,
      walletClient,
    }));
  } catch {
    throw new RegistrationConfigurationError(
      "Registration clients could not be created.",
    );
  }

  await verifyOfficialRegistry(activePublicClient);

  let initialDocument;
  let initialURI;

  try {
    initialDocument = buildRegistrationDocument({
      displayName,
      agentId: null,
    });
    initialURI = registrationDataUri(initialDocument);
  } catch {
    throw new RegistrationConfigurationError(
      "Initial registration metadata is invalid.",
    );
  }

  const nonce = await runStage(
    () =>
      activePublicClient.getTransactionCount({
        address: account.address,
        blockTag: "pending",
      }),
    "Pending wallet nonce verification failed.",
  );
  if (nonce !== 0 && nonce !== 0n) {
    if (priorIntent === null) {
      throw new RegistrationConfigurationError(
        "Pending wallet nonce must be zero.",
      );
    }

    return await completeRegistrationFromIntent({
      account,
      displayName,
      expectedAddress,
      initialURI,
      intent: priorIntent,
      onCheckpoint,
      privateKey,
      publicClient: activePublicClient,
      rpcUrl,
      walletClient: activeWalletClient,
    });
  }

  const registerFees = await estimateFeeQuote(
    activePublicClient,
    "Registration",
  );
  const registerGasEstimate = await runStage(
    () =>
      activePublicClient.estimateContractGas({
        address: REGISTRY_ADDRESS,
        abi: ERC8004_ABI,
        functionName: "register",
        args: [initialURI],
        account,
      }),
    "Registration gas estimation failed.",
  );
  let registerGas;

  try {
    registerGas = addGasHeadroom(registerGasEstimate);
  } catch {
    throw new Error("Registration gas estimate is invalid.");
  }

  const balance = await runStage(
    () => activePublicClient.getBalance({ address: account.address }),
    "Wallet balance verification failed.",
  );
  if (
    typeof balance !== "bigint" ||
    balance < PILOT_MINIMUM_BALANCE_WEI ||
    balance > PILOT_MAXIMUM_BALANCE_WEI
  ) {
    throw new RegistrationConfigurationError(
      "Wallet pilot balance must be within 0.005 through 0.02 Sepolia ETH, inclusive.",
    );
  }

  const requiredRegisterBalance =
    (registerGas + CONSERVATIVE_METADATA_GAS_RESERVE) *
    registerFees.unitPrice;
  if (balance < requiredRegisterBalance) {
    throw new RegistrationConfigurationError(
      "Wallet balance cannot fund the registration and metadata fee envelope.",
    );
  }

  let registerIntent;

  try {
    registerIntent = createRegistrationIntent({
      address: account.address,
      displayName,
      registerCalldata: encodeRegisterCalldata(initialURI),
      registerGas,
      transactionFields: registerFees.transactionFields,
    });
  } catch {
    throw new RegistrationConfigurationError(
      "Registration intent record is invalid.",
    );
  }

  try {
    await invokeCheckpoint(onCheckpoint, registerIntent);
  } catch {
    throw new RegistrationConfigurationError(
      "Registration intent record could not be recorded before broadcast.",
    );
  }

  const registerTx = await runStage(
    () =>
      activeWalletClient.writeContract({
        address: REGISTRY_ADDRESS,
        abi: ERC8004_ABI,
        functionName: "register",
        args: [initialURI],
        account,
        chainId: CHAIN_ID,
        gas: registerGas,
        nonce: REGISTER_NONCE,
        ...registerFees.transactionFields,
      }),
    "Registration transaction submission failed.",
  );
  validateTransactionHash(registerTx, "Registration");

  let recovery;

  try {
    const registerReceipt = await runStage(
      () =>
        activePublicClient.waitForTransactionReceipt({
          hash: registerTx,
          confirmations: RECEIPT_CONFIRMATIONS,
          timeout: RECEIPT_TIMEOUT_MILLISECONDS,
        }),
      "Registration receipt wait failed.",
    );
    const registerBlock = validateReceipt(
      registerReceipt,
      registerTx,
      "Registration",
    );

    let agentId;

    try {
      agentId = parseRegisteredAgentId(registerReceipt, {
        expectedOwner: account.address,
        expectedAgentURI: initialURI,
      });
    } catch {
      throw new Error("Registration event verification failed.");
    }

    recovery = createRecovery({
      address: account.address,
      agentId,
      displayName,
      registerBlock,
      registerTx,
    });
  } catch (error) {
    throw attachRegisterTransaction(error, registerTx);
  }

  try {
    await invokeCheckpoint(onCheckpoint, recovery);
    return await finalizeIdentityRegistration({
      privateKey,
      expectedAddress,
      displayName,
      recovery,
      rpcUrl,
      publicClient: activePublicClient,
      walletClient: activeWalletClient,
      onCheckpoint,
    });
  } catch (error) {
    if (error instanceof PartialRegistrationError) {
      throw error;
    }

    throw new PartialRegistrationError(recovery, error);
  }
}
