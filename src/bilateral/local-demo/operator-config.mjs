import { constants as fsConstants } from "node:fs";
import { lstat, open } from "node:fs/promises";
import { homedir } from "node:os";
import { dirname, isAbsolute, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";

export const HYBRID_OPERATOR_CONFIG_SCHEMA =
  "clockchain.hybrid-local-operator-config/v1";

const REPOSITORY_ROOT = resolve(
  fileURLToPath(new URL("../../../", import.meta.url)),
);
const MAX_CONFIG_BYTES = 65_536;
const SHA40 = /^[0-9a-f]{40}$/;
const SHA64 = /^[0-9a-f]{64}$/;
const KEY_ID = /^[a-z0-9][a-z0-9-]{0,63}$/;
const BUCKET = /^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$/;
const REGION = /^[a-z]{2}-[a-z]+-[1-9]$/;
const IMAGE_DIGEST =
  /^[0-9]{12}\.dkr\.ecr\.[a-z]{2}-[a-z]+-[1-9]\.amazonaws\.com\/[a-z0-9][a-z0-9._/-]{0,254}@sha256:[0-9a-f]{64}$/;
const HOST = /^[A-Za-z0-9][A-Za-z0-9.-]{0,252}[A-Za-z0-9]$/;
const LOOPBACKS = new Set(["127.0.0.1", "::1", "localhost"]);
const PRIVATE_FILE_KEYS = Object.freeze([
  ["operator", "clockchainTokenFile"],
  ["publicEdge", "hostKeyFile"],
  ["publicEdge", "identityFile"],
  ["funding", "keystoreFile"],
  ["operator", "privateKeyFile"],
  ["payerMcp", "tlsCertificateFile"],
  ["payerMcp", "tlsPrivateKeyFile"],
  ["relay", "tlsCertificateFile"],
  ["relay", "tlsPrivateKeyFile"],
  ["operator", "rpcUrlFile"],
]);
const READ_FLAGS =
  fsConstants.O_RDONLY |
  (fsConstants.O_NOFOLLOW ?? 0) |
  (fsConstants.O_NONBLOCK ?? 0);

const KEYS = Object.freeze({
  console: Object.freeze(["host", "port"]),
  funding: Object.freeze(["journalDirectory", "keystoreFile", "mode"]),
  operator: Object.freeze([
    "clockchainTokenFile",
    "keyId",
    "privateKeyFile",
    "rpcUrlFile",
  ]),
  payerMcp: Object.freeze([
    "host",
    "port",
    "publicUrl",
    "tlsCertificateFile",
    "tlsPrivateKeyFile",
  ]),
  publicEdge: Object.freeze([
    "coordinationPublicUrl",
    "host",
    "hostKeyFile",
    "identityFile",
    "payerMcpRemotePort",
    "port",
    "relayRemotePort",
    "user",
  ]),
  publishing: Object.freeze([
    "bucket",
    "imageDigest",
    "receiptEmailUrl",
    "region",
    "requestorDiscoveryUrl",
  ]),
  relay: Object.freeze([
    "advertisedHost",
    "host",
    "port",
    "tlsCertificateFile",
    "tlsFingerprint",
    "tlsPrivateKeyFile",
  ]),
  root: Object.freeze([
    "console",
    "funding",
    "operator",
    "payerMcp",
    "paymentMoved",
    "publicEdge",
    "publishing",
    "relay",
    "repositorySha",
    "schema",
  ]),
});

export class HybridOperatorConfigError extends Error {
  constructor() {
    super("Hybrid local operator configuration failed safely.");
    this.name = "HybridOperatorConfigError";
    this.code = "HYBRID_OPERATOR_CONFIG_INVALID";
    this.category = "configuration";
  }
}

function fail() {
  throw new HybridOperatorConfigError();
}

function plain(value) {
  return (
    value !== null &&
    typeof value === "object" &&
    !Array.isArray(value) &&
    Object.getPrototypeOf(value) === Object.prototype
  );
}

function exact(value, keys) {
  if (!plain(value)) fail();
  const actual = Reflect.ownKeys(value);
  if (
    actual.length !== keys.length ||
    keys.some((key, index) => actual[index] !== key)
  ) {
    fail();
  }
  return value;
}

function port(value) {
  if (!Number.isSafeInteger(value) || value < 1 || value > 65_535) fail();
  return value;
}

function absolutePath(value) {
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    value.includes("\0") ||
    !isAbsolute(value) ||
    resolve(value) !== value ||
    value === "/" ||
    value.startsWith("--") ||
    /^[a-z][a-z0-9+.-]*:\/\//i.test(value) ||
    /^0x[0-9a-f]{64}$/i.test(value) ||
    /^Bearer\s/i.test(value)
  ) {
    fail();
  }
  return value;
}

function publicHttps(value, expectedPath = null) {
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
    url.search !== "" ||
    url.hash !== "" ||
    LOOPBACKS.has(url.hostname) ||
    (expectedPath !== null && url.pathname !== expectedPath)
  ) {
    fail();
  }
  return url;
}

function privateStats(stats, maximum = 1_048_576) {
  const uid = typeof process.getuid === "function" ? process.getuid() : null;
  if (
    !stats.isFile() ||
    stats.isSymbolicLink() ||
    stats.nlink !== 1 ||
    (stats.mode & 0o777) !== 0o600 ||
    (uid !== null && stats.uid !== uid) ||
    !Number.isSafeInteger(stats.size) ||
    stats.size < 1 ||
    stats.size > maximum
  ) {
    fail();
  }
}

function sameStats(left, right) {
  return (
    left.dev === right.dev &&
    left.ino === right.ino &&
    left.mode === right.mode &&
    left.nlink === right.nlink &&
    left.uid === right.uid &&
    left.gid === right.gid &&
    left.size === right.size &&
    left.mtimeMs === right.mtimeMs &&
    left.ctimeMs === right.ctimeMs
  );
}

async function readConfigFile(path) {
  absolutePath(path);
  const before = await lstat(path);
  privateStats(before, MAX_CONFIG_BYTES);
  let handle;
  let opened;
  let bytes;
  try {
    handle = await open(path, READ_FLAGS);
    opened = await handle.stat();
    privateStats(opened, MAX_CONFIG_BYTES);
    if (!sameStats(before, opened)) fail();
    bytes = await handle.readFile("utf8");
  } finally {
    await handle?.close();
  }
  const after = await lstat(path);
  privateStats(after, MAX_CONFIG_BYTES);
  if (!sameStats(before, after) || !sameStats(opened, after)) fail();
  if (
    typeof bytes !== "string" ||
    !bytes.endsWith("\n") ||
    bytes.slice(0, -1).includes("\n") ||
    bytes.includes("\r")
  ) {
    fail();
  }
  const body = bytes.slice(0, -1);
  let parsed;
  try {
    parsed = JSON.parse(body);
  } catch {
    fail();
  }
  if (JSON.stringify(parsed) !== body) fail();
  return parsed;
}

function outsideRepository(path) {
  const fromRoot = relative(REPOSITORY_ROOT, path);
  if (fromRoot === "" || (!fromRoot.startsWith("..") && !isAbsolute(fromRoot))) {
    fail();
  }
}

async function validateNewStateRoot(path, configPath) {
  absolutePath(path);
  outsideRepository(path);
  if (path === homedir() || path === dirname(configPath)) fail();
  try {
    await lstat(path);
    fail();
  } catch (error) {
    if (error instanceof HybridOperatorConfigError) throw error;
    if (error?.code !== "ENOENT") fail();
  }
  const parent = await lstat(dirname(path));
  const uid = typeof process.getuid === "function" ? process.getuid() : null;
  if (
    !parent.isDirectory() ||
    parent.isSymbolicLink() ||
    (parent.mode & 0o077) !== 0 ||
    (uid !== null && parent.uid !== uid)
  ) {
    fail();
  }
}

async function validatePrivatePath(path, onPrivatePath) {
  absolutePath(path);
  const before = await lstat(path);
  privateStats(before);
  await onPrivatePath?.(path);
  const after = await lstat(path);
  privateStats(after);
  if (!sameStats(before, after)) fail();
}

function validateDirectoryPath(path) {
  absolutePath(path);
  outsideRepository(path);
}

function validateShape(value) {
  const root = exact(value, KEYS.root);
  const consoleConfig = exact(root.console, KEYS.console);
  const funding = exact(root.funding, KEYS.funding);
  const operator = exact(root.operator, KEYS.operator);
  const payerMcp = exact(root.payerMcp, KEYS.payerMcp);
  const publicEdge = exact(root.publicEdge, KEYS.publicEdge);
  const publishing = exact(root.publishing, KEYS.publishing);
  const relay = exact(root.relay, KEYS.relay);

  if (
    root.schema !== HYBRID_OPERATOR_CONFIG_SCHEMA ||
    root.paymentMoved !== false ||
    typeof root.repositorySha !== "string" ||
    !SHA40.test(root.repositorySha) ||
    !LOOPBACKS.has(consoleConfig.host) ||
    port(consoleConfig.port) !== 8787 ||
    funding.mode !== "fund-on-ready" ||
    typeof operator.keyId !== "string" ||
    !KEY_ID.test(operator.keyId) ||
    !LOOPBACKS.has(payerMcp.host) ||
    !LOOPBACKS.has(relay.host) ||
    typeof relay.tlsFingerprint !== "string" ||
    !SHA64.test(relay.tlsFingerprint) ||
    typeof publicEdge.host !== "string" ||
    !HOST.test(publicEdge.host) ||
    LOOPBACKS.has(publicEdge.host) ||
    publicEdge.user !== "clockchain-tunnel" ||
    typeof publishing.bucket !== "string" ||
    !BUCKET.test(publishing.bucket) ||
    typeof publishing.imageDigest !== "string" ||
    !IMAGE_DIGEST.test(publishing.imageDigest) ||
    typeof publishing.region !== "string" ||
    !REGION.test(publishing.region)
  ) {
    fail();
  }

  port(payerMcp.port);
  port(relay.port);
  port(publicEdge.port);
  port(publicEdge.payerMcpRemotePort);
  port(publicEdge.relayRemotePort);
  const payerUrl = publicHttps(payerMcp.publicUrl, "/mcp");
  const relayUrl = publicHttps(publicEdge.coordinationPublicUrl, "/");
  publicHttps(publishing.requestorDiscoveryUrl);
  publicHttps(publishing.receiptEmailUrl, "/v1/receipt-email");
  if (
    payerUrl.hostname !== publicEdge.host ||
    Number(payerUrl.port) !== payerMcp.port ||
    payerMcp.port !== publicEdge.payerMcpRemotePort ||
    relayUrl.hostname !== publicEdge.host ||
    Number(relayUrl.port) !== relay.port ||
    relay.port !== publicEdge.relayRemotePort ||
    relay.advertisedHost !== publicEdge.host
  ) {
    fail();
  }

  validateDirectoryPath(funding.journalDirectory);
  return root;
}

function freezeDeep(value) {
  for (const child of Object.values(value)) {
    if (child !== null && typeof child === "object") freezeDeep(child);
  }
  return Object.freeze(value);
}

export async function readHybridOperatorConfig(
  configPath,
  stateRoot,
  dependencies = {},
) {
  try {
    if (
      dependencies === null ||
      typeof dependencies !== "object" ||
      Array.isArray(dependencies) ||
      Reflect.ownKeys(dependencies).some((key) => key !== "onPrivatePath") ||
      (dependencies.onPrivatePath !== undefined &&
        typeof dependencies.onPrivatePath !== "function")
    ) {
      fail();
    }
    await validateNewStateRoot(stateRoot, configPath);
    const value = validateShape(await readConfigFile(configPath));
    for (const [section, key] of PRIVATE_FILE_KEYS) {
      await validatePrivatePath(value[section][key], dependencies.onPrivatePath);
    }
    return freezeDeep(value);
  } catch (error) {
    if (error instanceof HybridOperatorConfigError) throw error;
    fail();
  }
}
