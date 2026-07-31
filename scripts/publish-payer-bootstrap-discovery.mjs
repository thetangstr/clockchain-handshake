#!/usr/bin/env node
import {
  createHash,
  createPrivateKey,
  createPublicKey,
  sign,
  verify,
} from "node:crypto";
import { readFile } from "node:fs/promises";
import { pathToFileURL } from "node:url";
import { types } from "node:util";

import {
  sshEd25519Fingerprint,
} from "../src/bilateral/local-mcp/payer-bootstrap-envelope.mjs";

export {
  sshEd25519Fingerprint,
};

export const PAYER_BOOTSTRAP_DISCOVERY_SCHEMA =
  "clockchain.payer-bootstrap-discovery/v1";

const DISCOVERY_KEYS = Object.freeze([
  "expiresAtMs",
  "imageDigest",
  "operatorKeyId",
  "paymentMoved",
  "payerClaimUrl",
  "publicMcpHostname",
  "publicMcpPort",
  "releaseId",
  "repositorySha",
  "schema",
  "sessionId",
  "signature",
  "tunnelHost",
  "tunnelHostPublicKey",
  "tunnelHostKeyFingerprint",
  "tunnelPort",
]);
const UNSIGNED_KEYS = Object.freeze(
  DISCOVERY_KEYS.filter((key) => key !== "signature"),
);
const SIGNATURE_KEYS = Object.freeze([
  "algorithm",
  "keyId",
  "value",
]);
const SHA40_PATTERN = /^[0-9a-f]{40}$/;
const UUID_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const KEY_ID_PATTERN = /^[a-z0-9][a-z0-9-]{0,63}$/;
const BASE64_PATTERN =
  /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;
const IMAGE_DIGEST_PATTERN =
  /^[0-9]{12}\.dkr\.ecr\.[a-z]{2}-[a-z]+-[1-9]\.amazonaws\.com\/[a-z0-9][a-z0-9._/-]{0,254}@sha256:[0-9a-f]{64}$/;
const HOSTNAME_PATTERN =
  /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?$/;
const ED25519_SPKI_PREFIX = Buffer.from(
  "302a300506032b6570032100",
  "hex",
);
const MAX_DISCOVERY_BYTES = 65_536;

class PayerBootstrapDiscoveryError extends Error {
  constructor() {
    super("Payer bootstrap discovery failed safely.");
    this.name = "PayerBootstrapDiscoveryError";
  }
}

function fail() {
  throw new PayerBootstrapDiscoveryError();
}

function exactObject(value, keys) {
  if (
    value === null ||
    typeof value !== "object" ||
    Array.isArray(value) ||
    types.isProxy(value) ||
    ![Object.prototype, null].includes(
      Object.getPrototypeOf(value),
    )
  ) {
    fail();
  }
  const ownKeys = Reflect.ownKeys(value);
  if (
    ownKeys.length !== keys.length ||
    keys.some((key, index) => ownKeys[index] !== key)
  ) {
    fail();
  }
  for (const key of keys) {
    const descriptor =
      Object.getOwnPropertyDescriptor(value, key);
    if (
      descriptor?.enumerable !== true ||
      !Object.hasOwn(descriptor, "value")
    ) {
      fail();
    }
  }
  return value;
}

function timestamp(value) {
  if (
    typeof value !== "string" ||
    !/^(?:0|[1-9][0-9]*)$/.test(value) ||
    BigInt(value) > BigInt(Number.MAX_SAFE_INTEGER)
  ) {
    fail();
  }
}

function hostname(value) {
  if (
    typeof value !== "string" ||
    !HOSTNAME_PATTERN.test(value)
  ) {
    fail();
  }
  return value;
}

function claimUrl(value) {
  if (typeof value !== "string") fail();
  let url;
  try {
    url = new URL(value);
  } catch {
    fail();
  }
  if (
    url.protocol !== "https:" ||
    url.username !== "" ||
    url.password !== "" ||
    url.port !== "" ||
    url.pathname !== "/v1/payer-claims" ||
    url.search !== "" ||
    url.hash !== "" ||
    url.hostname !== url.hostname.toLowerCase()
  ) {
    fail();
  }
  hostname(url.hostname);
  return value;
}

function unsignedSnapshot(value) {
  const data = exactObject(value, UNSIGNED_KEYS);
  timestamp(data.expiresAtMs);
  if (
    !IMAGE_DIGEST_PATTERN.test(data.imageDigest) ||
    !KEY_ID_PATTERN.test(data.operatorKeyId) ||
    data.paymentMoved !== false ||
    data.publicMcpPort !== 9443 ||
    typeof data.releaseId !== "string" ||
    data.releaseId.length === 0 ||
    data.releaseId.length > 128 ||
    data.releaseId.trim() !== data.releaseId ||
    !SHA40_PATTERN.test(data.repositorySha) ||
    data.schema !== PAYER_BOOTSTRAP_DISCOVERY_SCHEMA ||
    !UUID_PATTERN.test(data.sessionId) ||
    data.tunnelPort !== 443
  ) {
    fail();
  }
  claimUrl(data.payerClaimUrl);
  hostname(data.publicMcpHostname);
  hostname(data.tunnelHost);
  if (
    sshEd25519Fingerprint(
      data.tunnelHostPublicKey,
    ) !== data.tunnelHostKeyFingerprint
  ) {
    fail();
  }
  return Object.freeze({ ...data });
}

function signatureSnapshot(value, keyId) {
  const signature = exactObject(value, SIGNATURE_KEYS);
  if (
    signature.algorithm !== "ed25519" ||
    signature.keyId !== keyId ||
    typeof signature.value !== "string" ||
    !BASE64_PATTERN.test(signature.value) ||
    Buffer.from(signature.value, "base64").length !== 64 ||
    Buffer.from(signature.value, "base64").toString("base64") !==
      signature.value
  ) {
    fail();
  }
  return Object.freeze({ ...signature });
}

function signingBytes(value) {
  return Buffer.from(JSON.stringify(value), "utf8");
}

function rawEd25519PublicKey(value) {
  if (
    typeof value !== "string" ||
    !BASE64_PATTERN.test(value)
  ) {
    fail();
  }
  const raw = Buffer.from(value, "base64");
  if (
    raw.length !== 32 ||
    raw.toString("base64") !== value
  ) {
    fail();
  }
  return createPublicKey({
    key: Buffer.concat([ED25519_SPKI_PREFIX, raw]),
    format: "der",
    type: "spki",
  });
}

export function createSignedPayerBootstrapDiscovery(input) {
  try {
    const { signer, ...unsignedInput } = input ?? {};
    const unsigned = unsignedSnapshot(unsignedInput);
    if (typeof signer !== "function") fail();
    const signatureValue = signer(signingBytes(unsigned));
    const signature = signatureSnapshot({
      algorithm: "ed25519",
      keyId: unsigned.operatorKeyId,
      value: signatureValue,
    }, unsigned.operatorKeyId);
    const entries = [];
    for (const key of DISCOVERY_KEYS) {
      entries.push([
        key,
        key === "signature" ? signature : unsigned[key],
      ]);
    }
    return Object.freeze(Object.fromEntries(entries));
  } catch (error) {
    if (error instanceof PayerBootstrapDiscoveryError) {
      throw error;
    }
    fail();
  }
}

export function verifySignedPayerBootstrapDiscovery({
  discovery,
  expectedImageDigest,
  expectedPublicMcpHostname,
  nowMs = Date.now(),
  operatorPublicKey,
  repositorySha,
} = {}) {
  try {
    const data = exactObject(discovery, DISCOVERY_KEYS);
    const unsignedInput = Object.fromEntries(
      UNSIGNED_KEYS.map((key) => [key, data[key]]),
    );
    const unsigned = unsignedSnapshot(unsignedInput);
    const signature = signatureSnapshot(
      data.signature,
      unsigned.operatorKeyId,
    );
    if (
      unsigned.repositorySha !== repositorySha ||
      unsigned.imageDigest !== expectedImageDigest ||
      unsigned.publicMcpHostname !==
        expectedPublicMcpHostname ||
      Number(unsigned.expiresAtMs) <= nowMs
    ) {
      fail();
    }
    const publicKey =
      typeof operatorPublicKey === "string"
        ? rawEd25519PublicKey(operatorPublicKey)
        : operatorPublicKey;
    if (
      publicKey?.asymmetricKeyType !== "ed25519" ||
      !verify(
        null,
        signingBytes(unsigned),
        publicKey,
        Buffer.from(signature.value, "base64"),
      )
    ) {
      fail();
    }
    return Object.freeze({
      ...unsigned,
      signature,
    });
  } catch (error) {
    if (error instanceof PayerBootstrapDiscoveryError) {
      throw error;
    }
    fail();
  }
}

function rejectDuplicateJsonKeys(text) {
  if (
    typeof text !== "string" ||
    text.length === 0 ||
    Buffer.byteLength(text, "utf8") >
      MAX_DISCOVERY_BYTES
  ) {
    fail();
  }
  let index = 0;
  const skip = () => {
    while (/[\t\n\r ]/.test(text[index] ?? "")) index += 1;
  };
  const string = () => {
    if (text[index] !== "\"") fail();
    const start = index;
    index += 1;
    while (index < text.length) {
      if (text[index] === "\\") {
        index += 2;
        continue;
      }
      if (text[index] === "\"") {
        index += 1;
        try {
          return JSON.parse(text.slice(start, index));
        } catch {
          fail();
        }
      }
      if (text.charCodeAt(index) < 0x20) fail();
      index += 1;
    }
    fail();
  };
  const value = () => {
    skip();
    if (text[index] === "{") return object();
    if (text[index] === "[") return array();
    if (text[index] === "\"") return string();
    const match = text
      .slice(index)
      .match(/^(?:true|false|null|-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?)/);
    if (!match) fail();
    index += match[0].length;
  };
  const array = () => {
    index += 1;
    skip();
    if (text[index] === "]") {
      index += 1;
      return;
    }
    for (;;) {
      value();
      skip();
      if (text[index] === "]") {
        index += 1;
        return;
      }
      if (text[index] !== ",") fail();
      index += 1;
    }
  };
  const object = () => {
    index += 1;
    const keys = new Set();
    skip();
    if (text[index] === "}") {
      index += 1;
      return;
    }
    for (;;) {
      skip();
      const key = string();
      if (keys.has(key)) fail();
      keys.add(key);
      skip();
      if (text[index] !== ":") fail();
      index += 1;
      value();
      skip();
      if (text[index] === "}") {
        index += 1;
        return;
      }
      if (text[index] !== ",") fail();
      index += 1;
    }
  };
  value();
  skip();
  if (index !== text.length) fail();
}

export function parsePayerBootstrapDiscoveryWire(text) {
  try {
    if (
      typeof text !== "string" ||
      !text.endsWith("\n") ||
      text.slice(0, -1).includes("\n")
    ) {
      fail();
    }
    const body = text.slice(0, -1);
    rejectDuplicateJsonKeys(body);
    const parsed = JSON.parse(body);
    if (`${JSON.stringify(parsed)}\n` !== text) fail();
    return exactObject(parsed, DISCOVERY_KEYS);
  } catch (error) {
    if (error instanceof PayerBootstrapDiscoveryError) {
      throw error;
    }
    fail();
  }
}

function safeBucket(value) {
  if (
    typeof value !== "string" ||
    !/^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$/.test(value) ||
    value.includes("..") ||
    /^\d+\.\d+\.\d+\.\d+$/.test(value)
  ) {
    fail();
  }
  return value;
}

function safeRegion(value) {
  if (
    typeof value !== "string" ||
    !/^[a-z]{2}-[a-z]+-[1-9]$/.test(value)
  ) {
    fail();
  }
  return value;
}

function safeObjectKey(value) {
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    value.length > 1024 ||
    value.startsWith("/") ||
    /[\x00-\x1f\x7f]/.test(value) ||
    value.split("/").some((part) =>
      ["", ".", ".."].includes(part))
  ) {
    fail();
  }
  return value;
}

export async function publishPayerBootstrapDiscovery({
  bucket,
  discoveryKey,
  putObject,
  region,
  signer,
  ...publicValues
} = {}) {
  try {
    const discovery =
      createSignedPayerBootstrapDiscovery({
        ...publicValues,
        signer,
      });
    let discoveryUrl = null;
    if (
      bucket !== undefined ||
      discoveryKey !== undefined ||
      putObject !== undefined ||
      region !== undefined
    ) {
      if (typeof putObject !== "function") fail();
      const safeBucketName = safeBucket(bucket);
      const safeKey = safeObjectKey(discoveryKey);
      const safeRegionName = safeRegion(region);
      await putObject({
        body: `${JSON.stringify(discovery)}\n`,
        bucket: safeBucketName,
        cacheControl: "no-store,max-age=0",
        contentType: "application/json",
        key: safeKey,
      });
      discoveryUrl =
        `https://${safeBucketName}.s3.${safeRegionName}.amazonaws.com/` +
        safeKey
          .split("/")
          .map((part) => encodeURIComponent(part))
          .join("/");
    }
    return Object.freeze({
      discovery,
      discoveryUrl,
      paymentMoved: false,
    });
  } catch (error) {
    if (error instanceof PayerBootstrapDiscoveryError) {
      throw error;
    }
    fail();
  }
}

async function main() {
  const values = Object.fromEntries(
    process.argv.slice(2).map((entry) => {
      const separator = entry.indexOf("=");
      if (separator < 3 || !entry.startsWith("--")) fail();
      return [
        entry.slice(2, separator),
        entry.slice(separator + 1),
      ];
    }),
  );
  const operatorPrivateKey = createPrivateKey(
    await readFile(values.operatorPrivateKey, "utf8"),
  );
  const result = await publishPayerBootstrapDiscovery({
    bucket: values.bucket,
    discoveryKey: values.discoveryKey,
    expiresAtMs: values.expiresAtMs,
    imageDigest: values.imageDigest,
    operatorKeyId: values.operatorKeyId,
    paymentMoved: false,
    payerClaimUrl: values.payerClaimUrl,
    publicMcpHostname: values.publicMcpHostname,
    publicMcpPort: 9443,
    putObject: async ({ body, bucket, cacheControl, contentType, key }) => {
      const { spawn } = await import("node:child_process");
      await new Promise((resolvePromise, rejectPromise) => {
        const child = spawn("aws", [
          "s3", "cp", "-", `s3://${bucket}/${key}`,
          "--region", values.region,
          "--content-type", contentType,
          "--cache-control", cacheControl,
          "--only-show-errors",
        ], { stdio: ["pipe", "ignore", "ignore"] });
        child.on("error", rejectPromise);
        child.on("exit", (code) =>
          code === 0 ? resolvePromise() : rejectPromise(fail()));
        child.stdin.end(body);
      });
    },
    region: values.region,
    releaseId: values.releaseId,
    repositorySha: values.repositorySha,
    schema: PAYER_BOOTSTRAP_DISCOVERY_SCHEMA,
    sessionId: values.sessionId,
    signer: (bytes) =>
      sign(null, bytes, operatorPrivateKey).toString("base64"),
    tunnelHost: values.tunnelHost,
    tunnelHostKeyFingerprint: values.tunnelHostKeyFingerprint,
    tunnelHostPublicKey: values.tunnelHostPublicKey,
    tunnelPort: 443,
  });
  process.stdout.write(`${JSON.stringify({
    discoveryUrl: result.discoveryUrl,
    paymentMoved: false,
    status: "PAYER_BOOTSTRAP_DISCOVERY_PUBLISHED",
  })}\n`);
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? "").href) {
  main().catch(() => {
    process.stderr.write("PAYER_BOOTSTRAP_DISCOVERY_FAILED\n");
    process.exitCode = 1;
  });
}
