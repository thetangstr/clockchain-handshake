import {
  createPublicClient,
  createWalletClient,
  http,
  isAddressEqual,
} from "viem";
import { sepolia } from "viem/chains";

import {
  CHAIN_ID,
  REGISTRY_ADDRESS,
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
