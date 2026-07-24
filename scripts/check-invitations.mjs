import { constants as fsConstants } from "node:fs";
import {
  lstat,
  open,
  readdir,
} from "node:fs/promises";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import {
  createPublicClient,
  formatEther,
  http,
  isAddress,
  parseEther,
} from "viem";
import { sepolia } from "viem/chains";

import {
  CHAIN_ID,
  INVITATION_SCHEMA,
  REGISTRY_ADDRESS,
  RPC_URL,
} from "../src/constants.mjs";

const PILOT_MINIMUM_WEI = parseEther("0.005");
const PILOT_MAXIMUM_WEI = parseEther("0.02");
const MAX_BUNDLE_BYTES = 16_384;
const ID_PATTERN =
  /^(?=.{1,32}$)[a-z][a-z0-9]*(?:-[a-z0-9]+)*$/u;
const MAX_DISPLAY_NAME_LENGTH = 128;
const CONTROL_CHARACTER_PATTERN = /[\u0000-\u001f\u007f-\u009f]/u;
const READ_FLAGS =
  fsConstants.O_RDONLY |
  (fsConstants.O_NOFOLLOW ?? 0) |
  (fsConstants.O_NONBLOCK ?? 0);
const BUNDLE_KEYS = Object.freeze([
  "schema",
  "version",
  "address",
  "displayName",
  "crypto",
]);
const CRYPTO_KEYS = Object.freeze([
  "kdf",
  "cipher",
  "encoding",
  "salt",
  "iv",
  "ciphertext",
  "tag",
]);
const KDF_KEYS = Object.freeze(["name", "N", "r", "p", "keyLength"]);
const CIPHER_KEYS = Object.freeze([
  "name",
  "ivLength",
  "tagLength",
]);

function isUnsafeAdjacentArtifact(name) {
  return (
    name.endsWith(".secret.json") ||
    name.endsWith(".tmp") ||
    name.endsWith(".bak") ||
    name.endsWith(".lock")
  );
}

class InvitationCheckError extends Error {
  constructor() {
    super("Invitation readiness check failed safely.");
    this.name = "InvitationCheckError";
  }
}

function fail() {
  throw new InvitationCheckError();
}

function isPlainObject(value) {
  if (value === null || typeof value !== "object") {
    return false;
  }
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function hasExactKeys(value, keys) {
  if (!isPlainObject(value)) {
    return false;
  }
  const actualKeys = Reflect.ownKeys(value);
  return (
    actualKeys.length === keys.length &&
    keys.every((key) => actualKeys.includes(key))
  );
}

function isCanonicalHex(value, byteLength) {
  return (
    typeof value === "string" &&
    value.length === byteLength * 2 &&
    /^[0-9a-f]+$/.test(value)
  );
}

function isCiphertext(value) {
  return (
    typeof value === "string" &&
    value.length > 0 &&
    value.length <= 8_192 &&
    value.length % 2 === 0 &&
    /^[0-9a-f]+$/.test(value)
  );
}

function validateBundle(bundle) {
  const crypto = bundle?.crypto;
  if (
    !hasExactKeys(bundle, BUNDLE_KEYS) ||
    bundle.schema !== INVITATION_SCHEMA ||
    bundle.version !== 1 ||
    !isAddress(bundle.address) ||
    typeof bundle.displayName !== "string" ||
    bundle.displayName.length === 0 ||
    bundle.displayName.length > MAX_DISPLAY_NAME_LENGTH ||
    bundle.displayName !== bundle.displayName.trim() ||
    CONTROL_CHARACTER_PATTERN.test(bundle.displayName) ||
    !hasExactKeys(crypto, CRYPTO_KEYS) ||
    !hasExactKeys(crypto.kdf, KDF_KEYS) ||
    crypto.kdf.name !== "scrypt" ||
    crypto.kdf.N !== 16_384 ||
    crypto.kdf.r !== 8 ||
    crypto.kdf.p !== 1 ||
    crypto.kdf.keyLength !== 32 ||
    !hasExactKeys(crypto.cipher, CIPHER_KEYS) ||
    crypto.cipher.name !== "aes-256-gcm" ||
    crypto.cipher.ivLength !== 12 ||
    crypto.cipher.tagLength !== 16 ||
    crypto.encoding !== "hex" ||
    !isCanonicalHex(crypto.salt, 32) ||
    !isCanonicalHex(crypto.iv, 12) ||
    !isCiphertext(crypto.ciphertext) ||
    !isCanonicalHex(crypto.tag, 16)
  ) {
    fail();
  }
  return bundle;
}

function sameFile(left, right) {
  return (
    left.dev === right.dev &&
    left.ino === right.ino &&
    left.size === right.size &&
    left.mtimeMs === right.mtimeMs &&
    left.mode === right.mode
  );
}

function parseArguments(arguments_) {
  const values = new Map();
  for (let index = 0; index < arguments_.length; index += 1) {
    const argument = arguments_[index];
    if (
      argument !== "--input-public" &&
      argument !== "--rpc-url"
    ) {
      fail();
    }
    if (values.has(argument) || index + 1 >= arguments_.length) {
      fail();
    }
    const value = arguments_[index + 1];
    if (
      typeof value !== "string" ||
      value.length === 0 ||
      value.startsWith("--")
    ) {
      fail();
    }
    values.set(argument, value);
    index += 1;
  }

  const rpcUrl = values.get("--rpc-url") ?? RPC_URL;
  let parsedRpcUrl;
  try {
    parsedRpcUrl = new URL(rpcUrl);
  } catch {
    fail();
  }
  if (
    parsedRpcUrl.protocol !== "http:" &&
    parsedRpcUrl.protocol !== "https:"
  ) {
    fail();
  }

  return {
    inputDirectory: resolve(values.get("--input-public") ?? "invites"),
    rpcUrl,
  };
}

async function validateInputDirectory(path) {
  try {
    const metadata = await lstat(path);
    if (!metadata.isDirectory() || metadata.isSymbolicLink()) {
      fail();
    }
  } catch (error) {
    if (error instanceof InvitationCheckError) {
      throw error;
    }
    fail();
  }
}

async function readBundle(path) {
  let fileHandle;
  try {
    fileHandle = await open(path, READ_FLAGS);
    const metadata = await fileHandle.stat();
    if (
      !metadata.isFile() ||
      metadata.size <= 0 ||
      metadata.size > MAX_BUNDLE_BYTES
    ) {
      fail();
    }
    const serialized = await fileHandle.readFile("utf8");
    const finalMetadata = await fileHandle.stat();
    if (
      !finalMetadata.isFile() ||
      !sameFile(metadata, finalMetadata) ||
      Buffer.byteLength(serialized, "utf8") > MAX_BUNDLE_BYTES
    ) {
      fail();
    }

    let parsed;
    try {
      parsed = JSON.parse(serialized);
    } catch {
      fail();
    }
    return validateBundle(parsed);
  } catch (error) {
    if (error instanceof InvitationCheckError) {
      throw error;
    }
    fail();
  } finally {
    if (fileHandle !== undefined) {
      try {
        await fileHandle.close();
      } catch {
        fail();
      }
    }
  }
}

async function loadInvitations(inputDirectory) {
  await validateInputDirectory(inputDirectory);
  let entries;
  try {
    entries = await readdir(inputDirectory, { withFileTypes: true });
  } catch {
    fail();
  }
  if (entries.some(({ name }) => isUnsafeAdjacentArtifact(name))) {
    fail();
  }

  const matching = entries
    .filter(({ name }) => name.endsWith(".enc.json"))
    .sort(({ name: left }, { name: right }) =>
      left.localeCompare(right, "en"),
    );
  if (
    matching.length === 0 ||
    matching.some((entry) => !entry.isFile() || entry.isSymbolicLink())
  ) {
    fail();
  }

  const invitations = [];
  const addresses = new Set();
  for (const entry of matching) {
    const id = entry.name.slice(0, -".enc.json".length);
    if (!ID_PATTERN.test(id)) {
      fail();
    }
    const bundle = await readBundle(join(inputDirectory, entry.name));
    const normalizedAddress = bundle.address.toLowerCase();
    if (addresses.has(normalizedAddress)) {
      fail();
    }
    addresses.add(normalizedAddress);
    invitations.push({
      id,
      address: bundle.address,
    });
  }

  return invitations;
}

function registryCodeIsPresent(bytecode) {
  return (
    typeof bytecode === "string" &&
    /^0x(?:[0-9a-fA-F]{2})+$/.test(bytecode)
  );
}

function readinessReasons({ balance, nonce }) {
  const reasons = [];
  if (nonce !== 0) {
    reasons.push("wallet-used");
  }
  if (balance < PILOT_MINIMUM_WEI) {
    reasons.push("below-pilot-minimum");
  }
  if (balance > PILOT_MAXIMUM_WEI) {
    reasons.push("above-pilot-maximum");
  }
  return reasons;
}

async function inspectNetwork(invitations, rpcUrl) {
  const client = createPublicClient({
    chain: sepolia,
    transport: http(rpcUrl, {
      retryCount: 0,
      timeout: 15_000,
    }),
  });
  let chainId;
  let bytecode;

  try {
    chainId = await client.getChainId();
    if (chainId !== CHAIN_ID) {
      fail();
    }
    bytecode = await client.getCode({ address: REGISTRY_ADDRESS });
    if (!registryCodeIsPresent(bytecode)) {
      fail();
    }
  } catch (error) {
    if (error instanceof InvitationCheckError) {
      throw error;
    }
    fail();
  }

  let invitationReports;
  try {
    invitationReports = await Promise.all(
      invitations.map(async (invitation) => {
        const [balance, nonce] = await Promise.all([
          client.getBalance({ address: invitation.address }),
          client.getTransactionCount({
            address: invitation.address,
            blockTag: "pending",
          }),
        ]);
        if (
          typeof balance !== "bigint" ||
          balance < 0n ||
          !Number.isSafeInteger(nonce) ||
          nonce < 0
        ) {
          fail();
        }
        const reasons = readinessReasons({ balance, nonce });
        return {
          ...invitation,
          balanceWei: balance.toString(),
          balanceEth: formatEther(balance),
          nonce,
          ready: reasons.length === 0,
          reasons,
        };
      }),
    );
  } catch (error) {
    if (error instanceof InvitationCheckError) {
      throw error;
    }
    fail();
  }

  return {
    chainId,
    registryAddress: REGISTRY_ADDRESS,
    registryBytecodePresent: true,
    pilotBalanceWei: {
      minimum: PILOT_MINIMUM_WEI.toString(),
      maximum: PILOT_MAXIMUM_WEI.toString(),
    },
    invitations: invitationReports,
    ready: invitationReports.every(({ ready }) => ready),
  };
}

export async function main(arguments_ = process.argv.slice(2)) {
  const { inputDirectory, rpcUrl } = parseArguments(arguments_);
  const invitations = await loadInvitations(inputDirectory);
  return inspectNetwork(invitations, rpcUrl);
}

const isEntryPoint =
  process.argv[1] !== undefined &&
  resolve(process.argv[1]) === fileURLToPath(import.meta.url);

if (isEntryPoint) {
  try {
    const report = await main();
    process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
    if (!report.ready) {
      process.exitCode = 1;
    }
  } catch {
    process.stderr.write("Invitation readiness check failed safely.\n");
    process.exitCode = 1;
  }
}
