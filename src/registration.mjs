import {
  createPublicClient,
  createWalletClient,
  http,
  isAddressEqual,
  parseEventLogs,
} from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { sepolia } from "viem/chains";

import {
  CHAIN_ID,
  REGISTRY_ADDRESS,
  RPC_URL,
} from "./constants.mjs";

const REGISTRATION_TYPE =
  "https://eips.ethereum.org/EIPS/eip-8004#registration-v1";
const REGISTRATION_DESCRIPTION =
  "Ephemeral Clockchain Handshake testnet identity; registration does not establish capability or trust.";
const MAX_DISPLAY_NAME_LENGTH = 128;
const MAX_UINT256 = (1n << 256n) - 1n;
const REGISTRY_VERSION = "2.0.0";
const RECEIPT_TIMEOUT_MILLISECONDS = 120_000;
const RPC_TIMEOUT_MILLISECONDS = 10_000;
const RPC_RETRY_COUNT = 1;

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

function normalizeAgentId(agentId, { jsonSafe = false } = {}) {
  let normalized;

  if (typeof agentId === "bigint") {
    normalized = agentId;
  } else if (typeof agentId === "number" && Number.isSafeInteger(agentId)) {
    normalized = BigInt(agentId);
  } else {
    throw new TypeError("Agent ID must be a nonnegative integer.");
  }

  if (normalized < 0n || normalized > MAX_UINT256) {
    throw new RangeError("Agent ID is outside the uint256 range.");
  }

  if (jsonSafe && normalized > BigInt(Number.MAX_SAFE_INTEGER)) {
    throw new RangeError("Agent ID is too large for exact JSON numeric encoding.");
  }

  return normalized;
}

function validateDisplayName(displayName) {
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

function isSuccessfulReceipt(receipt) {
  return (
    receipt?.status === "success" ||
    receipt?.status === 1 ||
    receipt?.status === 1n ||
    receipt?.status === "0x1"
  );
}

function isOfficialRegistryLog(log) {
  try {
    return isAddressEqual(log.address, REGISTRY_ADDRESS);
  } catch {
    return false;
  }
}

function addressesEqual(left, right) {
  try {
    return isAddressEqual(left, right);
  } catch {
    return false;
  }
}

function isTransactionHash(value) {
  return typeof value === "string" && /^0x[0-9a-fA-F]{64}$/.test(value);
}

function parseBlockNumber(value) {
  try {
    if (
      typeof value === "bigint" &&
      value >= 0n
    ) {
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
      (/^[0-9]+$/.test(value) || /^0x[0-9a-fA-F]+$/.test(value))
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

function validateTransactionHash(hash, stage) {
  if (!isTransactionHash(hash)) {
    throw new Error(`${stage} transaction hash is invalid.`);
  }
}

function validateReceipt(receipt, expectedHash, stage) {
  if (!isSuccessfulReceipt(receipt)) {
    throw new Error(`${stage} receipt was not successful.`);
  }

  if (
    !isTransactionHash(receipt?.transactionHash) ||
    receipt.transactionHash.toLowerCase() !== expectedHash.toLowerCase()
  ) {
    throw new Error(
      `${stage} receipt transaction hash is missing or mismatched.`,
    );
  }

  const blockNumber = parseBlockNumber(receipt.blockNumber);
  if (blockNumber === null) {
    throw new Error(`${stage} receipt block number is missing or invalid.`);
  }

  return blockNumber;
}

async function runStage(operation, errorMessage) {
  try {
    return await operation();
  } catch {
    throw new Error(errorMessage);
  }
}

export function registryNamespace() {
  return `eip155:${CHAIN_ID}:${REGISTRY_ADDRESS}`;
}

export function identityReference(agentId) {
  return `${registryNamespace()}:${normalizeAgentId(agentId)}`;
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
    ownerMatches = isAddressEqual(owner, expectedOwner);
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

export async function registerIdentity({
  privateKey,
  expectedAddress,
  displayName,
  rpcUrl = RPC_URL,
  publicClient,
  walletClient,
}) {
  let account;

  try {
    account = privateKeyToAccount(privateKey);
  } catch {
    throw new Error("Private key is invalid.");
  }

  if (!addressesEqual(account.address, expectedAddress)) {
    throw new Error(
      "Derived wallet address does not match the expected address.",
    );
  }

  let activePublicClient = publicClient;
  let activeWalletClient = walletClient;

  try {
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
  } catch {
    throw new Error("Registration clients could not be created.");
  }

  const chainId = await runStage(
    () => activePublicClient.getChainId(),
    "Ethereum Sepolia chain verification failed.",
  );
  if (chainId !== CHAIN_ID) {
    throw new Error("Ethereum Sepolia chain verification failed.");
  }

  const bytecode = await runStage(
    () => activePublicClient.getCode({ address: REGISTRY_ADDRESS }),
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
      activePublicClient.readContract({
        address: REGISTRY_ADDRESS,
        abi: ERC8004_ABI,
        functionName: "getVersion",
      }),
    "Official registry version verification failed.",
  );
  if (version !== REGISTRY_VERSION) {
    throw new Error("Official registry version is unsupported.");
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
    throw new Error("Pending wallet nonce must be zero.");
  }

  const balance = await runStage(
    () => activePublicClient.getBalance({ address: account.address }),
    "Wallet balance verification failed.",
  );
  if (typeof balance !== "bigint" || balance <= 0n) {
    throw new Error("Wallet balance must be greater than zero.");
  }

  let initialDocument;
  let initialURI;

  try {
    initialDocument = buildRegistrationDocument({
      displayName,
      agentId: null,
    });
    initialURI = registrationDataUri(initialDocument);
  } catch {
    throw new Error("Initial registration metadata is invalid.");
  }

  const registerGas = await runStage(
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
  if (typeof registerGas !== "bigint" || registerGas <= 0n) {
    throw new Error("Registration gas estimate is invalid.");
  }

  const registerTx = await runStage(
    () =>
      activeWalletClient.writeContract({
        address: REGISTRY_ADDRESS,
        abi: ERC8004_ABI,
        functionName: "register",
        args: [initialURI],
        account,
        gas: registerGas,
      }),
    "Registration transaction submission failed.",
  );
  validateTransactionHash(registerTx, "Registration");

  const registerReceipt = await runStage(
    () =>
      activePublicClient.waitForTransactionReceipt({
        hash: registerTx,
        confirmations: 1,
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

  let document;
  let finalURI;

  try {
    document = buildRegistrationDocument({ displayName, agentId });
    finalURI = registrationDataUri(document);
  } catch {
    throw new Error("Final registration metadata is invalid.");
  }

  const metadataGas = await runStage(
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
  if (typeof metadataGas !== "bigint" || metadataGas <= 0n) {
    throw new Error("Metadata gas estimate is invalid.");
  }

  const metadataTx = await runStage(
    () =>
      activeWalletClient.writeContract({
        address: REGISTRY_ADDRESS,
        abi: ERC8004_ABI,
        functionName: "setAgentURI",
        args: [agentId, finalURI],
        account,
        gas: metadataGas,
      }),
    "Metadata transaction submission failed.",
  );
  validateTransactionHash(metadataTx, "Metadata");

  const metadataReceipt = await runStage(
    () =>
      activePublicClient.waitForTransactionReceipt({
        hash: metadataTx,
        confirmations: 1,
        timeout: RECEIPT_TIMEOUT_MILLISECONDS,
      }),
    "Metadata receipt wait failed.",
  );
  const metadataBlock = validateReceipt(
    metadataReceipt,
    metadataTx,
    "Metadata",
  );

  const owner = await runStage(
    () =>
      activePublicClient.readContract({
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
      activePublicClient.readContract({
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
      activePublicClient.readContract({
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

  return {
    chainId,
    registryAddress: REGISTRY_ADDRESS,
    registryNamespace: registryNamespace(),
    identityReference: identityReference(agentId),
    agentId: agentId.toString(10),
    address: account.address,
    displayName,
    registerTx,
    registerBlock: registerBlock.toString(10),
    metadataTx,
    metadataBlock: metadataBlock.toString(10),
    document,
  };
}
