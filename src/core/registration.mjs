import {
  createPublicClient,
  createWalletClient,
  decodeFunctionData,
  encodeFunctionData,
  http,
  isAddressEqual,
  keccak256,
  parseEventLogs,
} from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { sepolia } from "viem/chains";

import {
  CHAIN_ID,
  REGISTRY_ADDRESS,
  RPC_URL,
} from "./constants.mjs";

export const RECOVERY_SCHEMA =
  "clockchain.handshake-registration-recovery/v1";
export const INTENT_SCHEMA =
  "clockchain.handshake-registration-intent/v1";
export const REGISTER_NONCE = 0;
export const RECEIPT_TIMEOUT_MILLISECONDS = 120_000;
export const RECEIPT_CONFIRMATIONS = 2;
export const CONSERVATIVE_METADATA_GAS_RESERVE = 250_000n;

export class RegistrationNetworkError extends Error {
  constructor(message) {
    super(message);
    this.name = "RegistrationNetworkError";
    this.code = "HANDSHAKE_REGISTRATION_NETWORK";
    this.category = "network";
  }
}

export class RegistrationConfigurationError extends Error {
  constructor(message) {
    super(message);
    this.name = "RegistrationConfigurationError";
    this.code = "HANDSHAKE_REGISTRATION_CONFIGURATION";
    this.category = "configuration";
  }
}

const MAX_DISPLAY_NAME_LENGTH = 128;
const MAX_UINT256 = (1n << 256n) - 1n;
const RPC_TIMEOUT_MILLISECONDS = 10_000;
const RPC_RETRY_COUNT = 1;
const GAS_HEADROOM_NUMERATOR = 120n;
const GAS_HEADROOM_DENOMINATOR = 100n;
const GAS_HEADROOM_FIXED = 10_000n;
const BASE_RECOVERY_KEYS = [
  "schema",
  "chainId",
  "registryAddress",
  "registryNamespace",
  "identityReference",
  "agentId",
  "address",
  "displayName",
  "registerTx",
  "registerBlock",
];
const METADATA_RECOVERY_KEYS = [
  ...BASE_RECOVERY_KEYS,
  "metadataTx",
  "metadataNonce",
];
const BASE_INTENT_KEYS = [
  "schema",
  "chainId",
  "registryAddress",
  "registryNamespace",
  "address",
  "displayName",
  "registerNonce",
  "registerCalldata",
  "registerGas",
];
const DYNAMIC_FEE_INTENT_KEYS = [
  ...BASE_INTENT_KEYS,
  "maxFeePerGas",
  "maxPriorityFeePerGas",
];
const LEGACY_FEE_INTENT_KEYS = [...BASE_INTENT_KEYS, "gasPrice"];

export function normalizeAgentId(
  agentId,
  { jsonSafe = false } = {},
) {
  let normalized;

  if (typeof agentId === "bigint") {
    normalized = agentId;
  } else if (
    typeof agentId === "number" &&
    Number.isSafeInteger(agentId)
  ) {
    normalized = BigInt(agentId);
  } else {
    throw new TypeError("Agent ID must be a nonnegative integer.");
  }

  if (normalized < 0n || normalized > MAX_UINT256) {
    throw new RangeError("Agent ID is outside the uint256 range.");
  }

  if (
    jsonSafe &&
    normalized > BigInt(Number.MAX_SAFE_INTEGER)
  ) {
    throw new RangeError(
      "Agent ID is too large for exact JSON numeric encoding.",
    );
  }

  return normalized;
}

export function validateDisplayName(displayName) {
  if (
    typeof displayName !== "string" ||
    displayName.trim().length === 0 ||
    displayName.length > MAX_DISPLAY_NAME_LENGTH
  ) {
    throw new TypeError(
      `Display name must contain 1-${MAX_DISPLAY_NAME_LENGTH} characters.`,
    );
  }
}

export function registryNamespaceValue() {
  return `eip155:${CHAIN_ID}:${REGISTRY_ADDRESS}`;
}

export function identityReferenceValue(agentId) {
  return `${registryNamespaceValue()}:${normalizeAgentId(agentId)}`;
}

export function addressesEqual(left, right) {
  try {
    return isAddressEqual(left, right);
  } catch {
    return false;
  }
}

export function isSuccessfulReceipt(receipt) {
  return (
    receipt?.status === "success" ||
    receipt?.status === 1 ||
    receipt?.status === 1n ||
    receipt?.status === "0x1"
  );
}

export function isRevertedReceipt(receipt) {
  return (
    receipt?.status === "reverted" ||
    receipt?.status === 0 ||
    receipt?.status === 0n ||
    receipt?.status === "0x0"
  );
}

export function isTransactionHash(value) {
  return (
    typeof value === "string" &&
    /^0x[0-9a-fA-F]{64}$/.test(value)
  );
}

function parseBlockNumber(value) {
  try {
    if (typeof value === "bigint" && value >= 0n) {
      return value;
    }

    if (
      typeof value === "number" &&
      Number.isSafeInteger(value) &&
      value >= 0
    ) {
      return BigInt(value);
    }

    if (
      typeof value === "string" &&
      (/^[0-9]+$/.test(value) ||
        /^0x[0-9a-fA-F]+$/.test(value))
    ) {
      const blockNumber = BigInt(value);
      if (blockNumber >= 0n) {
        return blockNumber;
      }
    }
  } catch {
    // Fall through to the generic receipt error.
  }

  return null;
}

export function validateTransactionHash(hash, stage) {
  if (!isTransactionHash(hash)) {
    throw new Error(`${stage} transaction hash is invalid.`);
  }
}

export function validateReceiptEvidence(
  receipt,
  expectedHash,
  stage,
) {
  if (
    !isTransactionHash(receipt?.transactionHash) ||
    receipt.transactionHash.toLowerCase() !==
      expectedHash.toLowerCase()
  ) {
    throw new Error(
      `${stage} receipt transaction hash is missing or mismatched.`,
    );
  }

  const blockNumber = parseBlockNumber(receipt.blockNumber);
  if (blockNumber === null) {
    throw new Error(
      `${stage} receipt block number is missing or invalid.`,
    );
  }

  return blockNumber;
}

export function validateReceipt(receipt, expectedHash, stage) {
  if (!isSuccessfulReceipt(receipt)) {
    throw new Error(`${stage} receipt was not successful.`);
  }

  return validateReceiptEvidence(receipt, expectedHash, stage);
}

export function addGasHeadroom(estimate) {
  if (typeof estimate !== "bigint" || estimate <= 0n) {
    throw new Error("Gas estimate is invalid.");
  }

  return (
    (estimate * GAS_HEADROOM_NUMERATOR +
      GAS_HEADROOM_DENOMINATOR -
      1n) /
      GAS_HEADROOM_DENOMINATOR +
    GAS_HEADROOM_FIXED
  );
}

function normalizeFeeQuote(quote) {
  if (
    typeof quote?.maxFeePerGas === "bigint" &&
    quote.maxFeePerGas > 0n &&
    typeof quote.maxPriorityFeePerGas === "bigint" &&
    quote.maxPriorityFeePerGas >= 0n &&
    quote.maxPriorityFeePerGas <= quote.maxFeePerGas &&
    quote.gasPrice === undefined
  ) {
    return {
      unitPrice: quote.maxFeePerGas,
      transactionFields: {
        maxFeePerGas: quote.maxFeePerGas,
        maxPriorityFeePerGas: quote.maxPriorityFeePerGas,
      },
    };
  }

  if (
    typeof quote?.gasPrice === "bigint" &&
    quote.gasPrice > 0n &&
    quote.maxFeePerGas === undefined &&
    quote.maxPriorityFeePerGas === undefined
  ) {
    return {
      unitPrice: quote.gasPrice,
      transactionFields: { gasPrice: quote.gasPrice },
    };
  }

  throw new Error("Fee quote is invalid.");
}

export async function runStage(operation, errorMessage) {
  try {
    return await operation();
  } catch {
    throw new RegistrationNetworkError(errorMessage);
  }
}

export async function estimateFeeQuote(publicClient, stage) {
  const quote = await runStage(
    () => publicClient.estimateFeesPerGas(),
    `${stage} fee estimation failed.`,
  );

  try {
    return normalizeFeeQuote(quote);
  } catch {
    throw new Error(`${stage} fee quote is invalid.`);
  }
}

function isPlainObject(value) {
  if (value === null || typeof value !== "object") {
    return false;
  }

  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function hasExactKeys(value, expectedKeys) {
  if (!isPlainObject(value)) {
    return false;
  }

  const keys = Reflect.ownKeys(value);
  return (
    keys.length === expectedKeys.length &&
    expectedKeys.every((key) => keys.includes(key))
  );
}

function isCanonicalDecimal(value) {
  return (
    typeof value === "string" &&
    /^(?:0|[1-9][0-9]*)$/.test(value)
  );
}

function copyRecovery(recovery) {
  return { ...recovery };
}

export function validateRecovery(
  recovery,
  { expectedAddress, displayName } = {},
) {
  const hasMetadataTransaction =
    isPlainObject(recovery) &&
    Object.hasOwn(recovery, "metadataTx");
  const hasMetadataNonce =
    isPlainObject(recovery) &&
    Object.hasOwn(recovery, "metadataNonce");
  const expectedKeys =
    hasMetadataTransaction && hasMetadataNonce
      ? METADATA_RECOVERY_KEYS
      : BASE_RECOVERY_KEYS;

  try {
    if (
      hasMetadataTransaction !== hasMetadataNonce ||
      !hasExactKeys(recovery, expectedKeys) ||
      recovery.schema !== RECOVERY_SCHEMA ||
      recovery.chainId !== CHAIN_ID ||
      recovery.registryAddress !== REGISTRY_ADDRESS ||
      recovery.registryNamespace !== registryNamespaceValue() ||
      !isCanonicalDecimal(recovery.agentId) ||
      !isCanonicalDecimal(recovery.registerBlock) ||
      !isTransactionHash(recovery.registerTx) ||
      !addressesEqual(recovery.address, recovery.address)
    ) {
      throw new Error();
    }

    validateDisplayName(recovery.displayName);
    const agentId = normalizeAgentId(BigInt(recovery.agentId));
    if (
      recovery.identityReference !==
      identityReferenceValue(agentId)
    ) {
      throw new Error();
    }

    if (
      hasMetadataTransaction &&
      (!isTransactionHash(recovery.metadataTx) ||
        typeof recovery.metadataNonce !== "number" ||
        !Number.isSafeInteger(recovery.metadataNonce) ||
        recovery.metadataNonce < 0)
    ) {
      throw new Error();
    }

    if (
      expectedAddress !== undefined &&
      !addressesEqual(recovery.address, expectedAddress)
    ) {
      throw new Error();
    }

    if (
      displayName !== undefined &&
      recovery.displayName !== displayName
    ) {
      throw new Error();
    }

    return copyRecovery(recovery);
  } catch {
    throw new Error("Registration recovery checkpoint is invalid.");
  }
}

export function createRecovery({
  address,
  agentId,
  displayName,
  registerBlock,
  registerTx,
}) {
  return validateRecovery({
    schema: RECOVERY_SCHEMA,
    chainId: CHAIN_ID,
    registryAddress: REGISTRY_ADDRESS,
    registryNamespace: registryNamespaceValue(),
    identityReference: identityReferenceValue(agentId),
    agentId: normalizeAgentId(agentId).toString(10),
    address,
    displayName,
    registerTx,
    registerBlock: registerBlock.toString(10),
  });
}

export function withMetadataTransaction(
  recovery,
  metadataTx,
  metadataNonce,
) {
  return validateRecovery({
    ...recovery,
    metadataTx,
    metadataNonce,
  });
}

export function withoutMetadataTransaction(recovery) {
  const {
    metadataTx: _metadataTx,
    metadataNonce: _metadataNonce,
    ...registrationRecovery
  } = recovery;
  return validateRecovery(registrationRecovery);
}

function isCalldata(value) {
  return (
    typeof value === "string" &&
    /^0x(?:[0-9a-fA-F]{2})+$/.test(value)
  );
}

function isPositiveCanonicalDecimal(value) {
  return isCanonicalDecimal(value) && value !== "0";
}

export function validateRegistrationIntent(
  intent,
  { expectedAddress, displayName } = {},
) {
  const hasLegacyFee =
    isPlainObject(intent) && Object.hasOwn(intent, "gasPrice");
  const expectedKeys = hasLegacyFee
    ? LEGACY_FEE_INTENT_KEYS
    : DYNAMIC_FEE_INTENT_KEYS;

  try {
    if (
      !hasExactKeys(intent, expectedKeys) ||
      intent.schema !== INTENT_SCHEMA ||
      intent.chainId !== CHAIN_ID ||
      intent.registryAddress !== REGISTRY_ADDRESS ||
      intent.registryNamespace !== registryNamespaceValue() ||
      intent.registerNonce !== REGISTER_NONCE ||
      !isCalldata(intent.registerCalldata) ||
      !isPositiveCanonicalDecimal(intent.registerGas) ||
      !addressesEqual(intent.address, intent.address)
    ) {
      throw new Error();
    }

    validateDisplayName(intent.displayName);

    if (hasLegacyFee) {
      if (!isPositiveCanonicalDecimal(intent.gasPrice)) {
        throw new Error();
      }
    } else if (
      !isPositiveCanonicalDecimal(intent.maxFeePerGas) ||
      !isCanonicalDecimal(intent.maxPriorityFeePerGas) ||
      BigInt(intent.maxPriorityFeePerGas) >
        BigInt(intent.maxFeePerGas)
    ) {
      throw new Error();
    }

    if (
      expectedAddress !== undefined &&
      !addressesEqual(intent.address, expectedAddress)
    ) {
      throw new Error();
    }

    if (
      displayName !== undefined &&
      intent.displayName !== displayName
    ) {
      throw new Error();
    }

    return { ...intent };
  } catch {
    throw new Error("Registration intent record is invalid.");
  }
}

export function createRegistrationIntent({
  address,
  displayName,
  registerCalldata,
  registerGas,
  transactionFields,
}) {
  const feeFields =
    typeof transactionFields?.gasPrice === "bigint"
      ? { gasPrice: transactionFields.gasPrice.toString(10) }
      : {
          maxFeePerGas:
            transactionFields?.maxFeePerGas?.toString(10),
          maxPriorityFeePerGas:
            transactionFields?.maxPriorityFeePerGas?.toString(10),
        };

  return validateRegistrationIntent({
    schema: INTENT_SCHEMA,
    chainId: CHAIN_ID,
    registryAddress: REGISTRY_ADDRESS,
    registryNamespace: registryNamespaceValue(),
    address,
    displayName,
    registerNonce: REGISTER_NONCE,
    registerCalldata,
    registerGas: registerGas.toString(10),
    ...feeFields,
  });
}

export function intentTransactionFields(intent) {
  return Object.hasOwn(intent, "gasPrice")
    ? { gasPrice: BigInt(intent.gasPrice) }
    : {
        maxFeePerGas: BigInt(intent.maxFeePerGas),
        maxPriorityFeePerGas: BigInt(intent.maxPriorityFeePerGas),
      };
}

export function intentTransactionType(intent) {
  return Object.hasOwn(intent, "gasPrice") ? "legacy" : "eip1559";
}

export function validateCheckpointCallback(onCheckpoint) {
  if (typeof onCheckpoint !== "function") {
    throw new RegistrationConfigurationError(
      "Registration checkpoint callback is invalid.",
    );
  }
}

export async function invokeCheckpoint(onCheckpoint, recovery) {
  validateCheckpointCallback(onCheckpoint);
  await onCheckpoint(copyRecovery(recovery));
}

export function normalizePendingNonce(value) {
  if (
    typeof value === "number" &&
    Number.isSafeInteger(value) &&
    value >= 0
  ) {
    return value;
  }

  if (
    typeof value === "bigint" &&
    value >= 0n &&
    value <= BigInt(Number.MAX_SAFE_INTEGER)
  ) {
    return Number(value);
  }

  throw new Error("Pending wallet nonce is invalid.");
}

export function createRegistrationClients({
  account,
  publicClient,
  rpcUrl,
  walletClient,
}) {
  let activePublicClient = publicClient;
  let activeWalletClient = walletClient;

  activePublicClient ??= createPublicClient({
    chain: sepolia,
    transport: http(rpcUrl, {
      retryCount: RPC_RETRY_COUNT,
      timeout: RPC_TIMEOUT_MILLISECONDS,
    }),
  });
  activeWalletClient ??= createWalletClient({
    account,
    chain: sepolia,
    transport: http(rpcUrl, {
      retryCount: RPC_RETRY_COUNT,
      timeout: RPC_TIMEOUT_MILLISECONDS,
    }),
  });

  return { activePublicClient, activeWalletClient };
}

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
