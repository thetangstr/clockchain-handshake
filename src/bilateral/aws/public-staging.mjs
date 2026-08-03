import {
  createHash,
  randomUUID,
  sign,
  X509Certificate,
} from "node:crypto";
import { constants } from "node:fs";
import {
  chmod,
  lstat,
  open,
  readFile,
  rename,
  rm,
} from "node:fs/promises";
import {
  basename,
  dirname,
  resolve,
} from "node:path";
import { types } from "node:util";

import {
  createSignedPayerBootstrapDiscovery,
  sshEd25519Fingerprint,
} from "../../../scripts/publish-payer-bootstrap-discovery.mjs";
import {
  createSignedRequestorDiscovery,
  REQUESTOR_DISCOVERY_SCHEMA,
} from "../../../scripts/publish-requestor-discovery.mjs";
import {
  observePublicMonitorSnapshot,
} from "../coordination/public-monitor.mjs";

const CONFIG_KEYS = Object.freeze([
  "imageDigest",
  "operatorKeyId",
  "operatorPrivateKey",
  "paths",
  "payerClaimUrl",
  "publicBaseUrl",
  "publicMcpHostname",
  "publicMcpUrl",
  "releaseId",
  "repositorySha",
  "sessionId",
  "tunnelHost",
  "tunnelHostPublicKey",
  "tunnelHostKeyFingerprint",
]);
const PATH_KEYS = Object.freeze([
  "certificate",
  "gate",
  "input",
  "payer",
  "requestor",
]);
const APPROVED_KEYS = Object.freeze([
  "certificateFingerprint",
  "certificatePem",
  "claimFingerprint",
  "expiresAtMs",
  "paymentMoved",
  "releaseId",
  "repositorySha",
  "schema",
  "sessionId",
  "status",
]);
const HEALTH_KEYS = Object.freeze([
  "schema",
  "releaseId",
  "repositorySha",
  "sessionId",
  "claimFingerprint",
  "mcpTlsFingerprint",
  "observedAtMs",
  "expiresAtMs",
  "paymentMoved",
  "status",
]);
const GATE_KEYS = Object.freeze([
  "payerClaimApproved",
  "payerDiscoveryReady",
  "payerMcpReady",
  "requestorDiscoveryReady",
  "runStarted",
  "tunnelTlsHealthy",
]);
const INPUT_KEYS = Object.freeze([
  "certificateFingerprint",
  "completedAtMs",
  "imageDigest",
  "releaseId",
  "repositorySha",
  "secretCanaries",
  "sessionId",
  "snapshot",
  "verifierPublicationValidated",
]);
const IMAGE =
  /^[0-9]{12}\.dkr\.ecr\.[a-z]{2}-[a-z]+-[1-9]\.amazonaws\.com\/[a-z0-9][a-z0-9._/-]{0,254}@sha256:[0-9a-f]{64}$/;
const HOST =
  /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?$/;
const KEY_ID = /^[a-z0-9][a-z0-9-]{0,63}$/;
const RELEASE = /^release-[0-9a-f]{16}$/;
const SHA40 = /^[0-9a-f]{40}$/;
const SHA64 = /^[0-9a-f]{64}$/;
const SESSION =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const TIMESTAMP = /^(?:0|[1-9][0-9]*)$/;
const MAX_BYTES = 262_144;

export class AwsPublicStagingError extends Error {
  constructor() {
    super("AWS public staging failed safely.");
    this.name = "AwsPublicStagingError";
    this.code = "AWS_PUBLIC_STAGING_INVALID";
    this.category = "verification";
  }
}

function fail() {
  throw new AwsPublicStagingError();
}

function plain(value) {
  return (
    value !== null &&
    typeof value === "object" &&
    !Array.isArray(value) &&
    !types.isProxy(value) &&
    Object.getPrototypeOf(value) === Object.prototype
  );
}

function exact(value, keys) {
  if (!plain(value)) fail();
  const ownKeys = Reflect.ownKeys(value);
  if (
    ownKeys.length !== keys.length ||
    keys.some((key, index) => ownKeys[index] !== key)
  ) {
    fail();
  }
  for (const key of keys) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (
      descriptor?.enumerable !== true ||
      !Object.hasOwn(descriptor, "value")
    ) {
      fail();
    }
  }
  return value;
}

function safeTimestamp(value) {
  if (
    typeof value !== "string" ||
    !TIMESTAMP.test(value) ||
    BigInt(value) > BigInt(Number.MAX_SAFE_INTEGER)
  ) {
    fail();
  }
  return Number(value);
}

function now(value) {
  if (!Number.isSafeInteger(value) || value < 0) fail();
  return value;
}

function publicUrl(value, expectedPath = null) {
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
    (expectedPath !== null && url.pathname !== expectedPath) ||
    !HOST.test(url.hostname)
  ) {
    fail();
  }
  return url;
}

function validFilePath(value) {
  if (
    typeof value !== "string" ||
    !value.startsWith("/") ||
    resolve(value) !== value ||
    value.includes("\0") ||
    !/^[A-Za-z0-9._-]+$/.test(basename(value))
  ) {
    fail();
  }
  return value;
}

function validateConfig(value) {
  const input = exact(value, CONFIG_KEYS);
  const paths = exact(input.paths, PATH_KEYS);
  const roots = new Set();
  const distinct = new Set();
  for (const key of PATH_KEYS) {
    validFilePath(paths[key]);
    roots.add(dirname(paths[key]));
    distinct.add(paths[key]);
  }
  if (
    roots.size !== 1 ||
    distinct.size !== PATH_KEYS.length ||
    !IMAGE.test(input.imageDigest) ||
    !KEY_ID.test(input.operatorKeyId) ||
    input.operatorPrivateKey?.asymmetricKeyType !== "ed25519" ||
    !HOST.test(input.publicMcpHostname) ||
    !RELEASE.test(input.releaseId) ||
    !SHA40.test(input.repositorySha) ||
    !SESSION.test(input.sessionId) ||
    !HOST.test(input.tunnelHost) ||
    sshEd25519Fingerprint(input.tunnelHostPublicKey) !==
    input.tunnelHostKeyFingerprint ||
    input.releaseId !== `release-${createHash("sha256").update(input.sessionId, "utf8").digest("hex").slice(0, 16)}`
  ) {
    fail();
  }
  const payerClaim = publicUrl(input.payerClaimUrl, "/v1/payer-claims");
  const publicBase = publicUrl(input.publicBaseUrl, "/");
  const publicMcp = publicUrl(input.publicMcpUrl, "/mcp");
  if (
    payerClaim.port !== "" ||
    publicMcp.hostname !== input.publicMcpHostname ||
    publicMcp.port !== "9443"
  ) {
    fail();
  }
  return Object.freeze({
    ...input,
    paths: Object.freeze({ ...paths }),
    publicBaseUrl: publicBase.href,
    root: [...roots][0],
  });
}

function storedWaitingSnapshot(snapshot) {
  const publishedAtMs = safeTimestamp(snapshot?.publishedAtMs);
  const checked = validateSnapshot(snapshot, publishedAtMs);
  if (
    checked.runStatus !== "WAITING" ||
    checked.verifier.status !== "NOT_STARTED" ||
    checked.mcp.status !== "WAITING" ||
    checked.payer.status !== "WAITING"
  ) {
    fail();
  }
  return checked;
}

function payerReadySnapshot(snapshot, nowMs) {
  const checked = storedWaitingSnapshot(snapshot);
  return validateSnapshot({
    ...checked,
    currentStep:
      "Payer MCP is ready. Requestor may connect to the published MCP endpoint.",
    mcp: { status: "READY" },
    payer: { status: "READY" },
    publishedAtMs: String(nowMs),
    runStatus: "WAITING",
    verifier: { status: "NOT_STARTED" },
  }, nowMs);
}

function failedSnapshot(snapshot, nowMs) {
  const checked = validateSnapshot(snapshot, nowMs);
  return validateSnapshot({
    ...checked,
    currentStep:
      "The run stopped safely before completion because required evidence did not validate.",
    paymentMoved: false,
    publishedAtMs: String(nowMs),
    runStatus: "FAILED",
    verifier: { status: "FAILED" },
  }, nowMs);
}

function sameIdentity(left, right) {
  return (
    left.dev === right.dev &&
    left.ino === right.ino &&
    left.mode === right.mode
  );
}

function sameFileIdentity(left, right) {
  return sameIdentity(left, right) && left.nlink === right.nlink;
}

function sameStableFileIdentity(left, right) {
  return (
    left.isFile() &&
    right.isFile() &&
    !left.isSymbolicLink() &&
    !right.isSymbolicLink() &&
    left.dev === right.dev &&
    left.ino === right.ino &&
    left.mode === right.mode &&
    left.nlink === right.nlink &&
    left.size === right.size &&
    left.ctimeMs === right.ctimeMs &&
    left.mtimeMs === right.mtimeMs
  );
}

function privateRoot(value) {
  return (
    value.isDirectory() &&
    !value.isSymbolicLink() &&
    (value.mode & 0o777) === 0o700
  );
}

function privateFile(value) {
  return (
    value.isFile() &&
    !value.isSymbolicLink() &&
    value.nlink === 1 &&
    (value.mode & 0o777) === 0o600 &&
    value.size > 0 &&
    value.size <= MAX_BYTES
  );
}

async function pinRoot(path) {
  const before = await lstat(path);
  if (!privateRoot(before)) fail();
  const handle = await open(
    path,
    constants.O_RDONLY |
      (constants.O_DIRECTORY ?? 0) |
      (constants.O_NOFOLLOW ?? 0),
  );
  const opened = await handle.stat();
  if (!privateRoot(opened) || !sameIdentity(before, opened)) {
    await handle.close();
    fail();
  }
  return Object.freeze({ before, handle, path });
}

async function assertRoot(root) {
  const current = await lstat(root.path);
  const opened = await root.handle.stat();
  if (
    !privateRoot(current) ||
    !privateRoot(opened) ||
    !sameIdentity(root.before, current) ||
    !sameIdentity(root.before, opened)
  ) {
    fail();
  }
}

function canonicalJson(value) {
  const text = `${JSON.stringify(value)}\n`;
  const bytes = Buffer.from(text, "utf8");
  if (bytes.length === 0 || bytes.length > MAX_BYTES) fail();
  return bytes;
}

async function stableRead(path, maximum = MAX_BYTES) {
  const before = await lstat(path);
  if (!privateFile(before) || before.size > maximum) fail();
  const handle = await open(
    path,
    constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0),
  );
  try {
    const opened = await handle.stat();
    if (
      !privateFile(opened) ||
      !sameStableFileIdentity(before, opened)
    ) {
      fail();
    }
    const bytes = await handle.readFile();
    const after = await lstat(path);
    const final = await handle.stat();
    if (
      bytes.length !== before.size ||
      !privateFile(after) ||
      !privateFile(final) ||
      !sameStableFileIdentity(before, after) ||
      !sameStableFileIdentity(before, final)
    ) {
      fail();
    }
    return bytes;
  } finally {
    await handle.close();
  }
}

async function readCanonical(path, keys) {
  const bytes = await stableRead(path);
  const text = bytes.toString("utf8");
  let value;
  try {
    value = JSON.parse(text.endsWith("\n") ? text.slice(0, -1) : "");
  } catch {
    fail();
  }
  if (!canonicalJson(value).equals(bytes)) fail();
  return exact(value, keys);
}

async function atomicWrite(root, path, bytes) {
  await assertRoot(root);
  const temporary = `${path}.${randomUUID()}.next`;
  let handle;
  try {
    handle = await open(
      temporary,
      constants.O_WRONLY |
        constants.O_CREAT |
        constants.O_EXCL |
        (constants.O_NOFOLLOW ?? 0),
      0o600,
    );
    await handle.writeFile(bytes);
    await handle.sync();
    await handle.close();
    handle = undefined;
    let existing = null;
    try {
      existing = await lstat(path);
    } catch (error) {
      if (error?.code !== "ENOENT") throw error;
    }
    if (existing !== null && !privateFile(existing)) fail();
    await assertRoot(root);
    if (existing !== null) {
      const current = await lstat(path);
      if (!privateFile(current) || !sameFileIdentity(existing, current)) fail();
    }
    await rename(temporary, path);
    await chmod(path, 0o600);
    await root.handle.sync();
    await assertRoot(root);
    const stored = await stableRead(path, bytes.length);
    if (!stored.equals(bytes)) fail();
  } catch (error) {
    await handle?.close().catch(() => {});
    await rm(temporary, { force: true }).catch(() => {});
    if (error instanceof AwsPublicStagingError) throw error;
    fail();
  }
}

function secretFree(value, canaries) {
  const text = Buffer.isBuffer(value) ? value.toString("utf8") : JSON.stringify(value);
  if (
    /AUTH(?:OR)?IZED/i.test(text) ||
    canaries.some((canary) => text.includes(canary))
  ) {
    fail();
  }
}

function validateSnapshot(snapshot, nowMs) {
  let checked;
  try {
    checked = observePublicMonitorSnapshot(snapshot, { nowMs });
  } catch {
    fail();
  }
  return checked;
}

function validateInput(value, active) {
  const input = exact(value, INPUT_KEYS);
  if (
    !(input.certificateFingerprint === null || SHA64.test(input.certificateFingerprint)) ||
    !(input.completedAtMs === null || (Number.isSafeInteger(input.completedAtMs) && input.completedAtMs >= 0)) ||
    input.imageDigest !== active.imageDigest ||
    input.releaseId !== active.releaseId ||
    input.repositorySha !== active.repositorySha ||
    !Array.isArray(input.secretCanaries) ||
    input.secretCanaries.length !== 0 ||
    input.sessionId !== active.sessionId ||
    typeof input.verifierPublicationValidated !== "boolean"
  ) {
    fail();
  }
  return input;
}

function publicationInput(active, {
  certificateFingerprint,
  completedAtMs,
  snapshot,
  verifierPublicationValidated,
}) {
  return Object.freeze({
    certificateFingerprint,
    completedAtMs,
    imageDigest: active.imageDigest,
    releaseId: active.releaseId,
    repositorySha: active.repositorySha,
    secretCanaries: Object.freeze([]),
    sessionId: active.sessionId,
    snapshot,
    verifierPublicationValidated,
  });
}

function gate(value) {
  const checked = exact(value, GATE_KEYS);
  if (GATE_KEYS.some((key) => typeof checked[key] !== "boolean")) fail();
  return checked;
}

function sameScope(value, active) {
  return (
    value.paymentMoved === false &&
    value.releaseId === active.releaseId &&
    value.repositorySha === active.repositorySha &&
    value.sessionId === active.sessionId
  );
}

function approvedPayer(value, active, nowMs) {
  const approved = exact(value, APPROVED_KEYS);
  let certificate;
  try {
    certificate = new X509Certificate(approved.certificatePem);
  } catch {
    fail();
  }
  if (
    !sameScope(approved, active) ||
    approved.schema !== "clockchain.aws-approved-payer-public/v1" ||
    approved.status !== "APPROVED" ||
    !SHA64.test(approved.claimFingerprint) ||
    !SHA64.test(approved.certificateFingerprint) ||
    createHash("sha256").update(certificate.raw).digest("hex") !== approved.certificateFingerprint ||
    certificate.checkHost(active.publicMcpHostname, { subject: "never" }) === undefined ||
    safeTimestamp(approved.expiresAtMs) <= nowMs
  ) {
    fail();
  }
  return approved;
}

function readyHealth(value, active, approved, nowMs) {
  const health = exact(value, HEALTH_KEYS);
  const observedAtMs = safeTimestamp(health.observedAtMs);
  if (
    !sameScope(health, active) ||
    health.schema !== "clockchain.payer-tunnel-health/v1" ||
    health.status !== "READY" ||
    health.claimFingerprint !== approved.claimFingerprint ||
    health.mcpTlsFingerprint !== approved.certificateFingerprint ||
    health.expiresAtMs !== approved.expiresAtMs ||
    observedAtMs > nowMs ||
    safeTimestamp(health.expiresAtMs) <= nowMs
  ) {
    fail();
  }
  return health;
}

export function createAwsPublicStager(value, dependencies = {}) {
  try {
    const active = validateConfig(value);
    const canaries = dependencies.secretCanaries ?? [];
    if (
      !plain(dependencies) ||
      !Array.isArray(canaries) ||
      canaries.some((entry) => typeof entry !== "string" || entry.length === 0)
    ) {
      fail();
    }
    let pinned;
    const root = async () => {
      pinned ??= await pinRoot(active.root);
      return pinned;
    };
    const writeJson = async (path, object) => {
      const bytes = canonicalJson(object);
      secretFree(bytes, canaries);
      await atomicWrite(await root(), path, bytes);
    };
    return Object.freeze({
      async close() {
        await pinned?.handle.close();
        pinned = undefined;
      },
      async stagePayerReady({ approvedPayer: approvedValue, nowMs, tunnelHealth }) {
        const currentNow = now(nowMs);
        const approved = approvedPayer(approvedValue, active, currentNow);
        readyHealth(tunnelHealth, active, approved, currentNow);
        const certificateUrl = new URL(
          `certificates/${approved.certificateFingerprint}.crt`,
          active.publicBaseUrl,
        ).href;
        const requestor = createSignedRequestorDiscovery({
          schema: REQUESTOR_DISCOVERY_SCHEMA,
          paymentMoved: false,
          imageDigest: active.imageDigest,
          releaseId: active.releaseId,
          sessionId: active.sessionId,
          repositorySha: active.repositorySha,
          publicUrl: active.publicMcpUrl,
          certificateUrl,
          certificateFingerprint: approved.certificateFingerprint,
          operatorKeyId: active.operatorKeyId,
          runMode: "aws-stakeholder-only",
          expiresAtMs: approved.expiresAtMs,
          operatorPrivateKey: active.operatorPrivateKey,
        });
        secretFree(approved.certificatePem, canaries);
        secretFree(requestor, canaries);
        await atomicWrite(
          await root(),
          active.paths.certificate,
          Buffer.from(approved.certificatePem, "utf8"),
        );
        await writeJson(active.paths.requestor, requestor);
        await writeJson(active.paths.gate, gate({
          payerClaimApproved: true,
          payerDiscoveryReady: true,
          payerMcpReady: true,
          requestorDiscoveryReady: true,
          runStarted: true,
          tunnelTlsHealthy: true,
        }));
        const input = validateInput(
          await readCanonical(active.paths.input, INPUT_KEYS),
          active,
        );
        if (
          input.completedAtMs !== null ||
          input.verifierPublicationValidated !== false
        ) {
          fail();
        }
        const snapshot = payerReadySnapshot(input.snapshot, currentNow);
        await writeJson(active.paths.input, publicationInput(active, {
          certificateFingerprint: approved.certificateFingerprint,
          completedAtMs: input.completedAtMs,
          snapshot,
          verifierPublicationValidated: input.verifierPublicationValidated,
        }));
      },
      async stageSnapshot({ completedAtMs, nowMs, snapshot, verifierPublicationValidated }) {
        const currentNow = now(nowMs);
        const checked = validateSnapshot(snapshot, currentNow);
        if (
          typeof verifierPublicationValidated !== "boolean" ||
          !(
            completedAtMs === null ||
            (Number.isSafeInteger(completedAtMs) && completedAtMs >= 0)
          ) ||
          ((checked.runStatus === "VERIFIED") !== verifierPublicationValidated) ||
          ((completedAtMs !== null) !== ["VERIFIED", "FAILED", "EXPIRED"].includes(checked.runStatus))
        ) {
          fail();
        }
        const previous = validateInput(
          await readCanonical(active.paths.input, INPUT_KEYS),
          active,
        );
        await writeJson(active.paths.input, publicationInput(active, {
          certificateFingerprint: previous.certificateFingerprint,
          completedAtMs,
          snapshot: checked,
          verifierPublicationValidated,
        }));
      },
      async stageStart({ expiresAtMs, nowMs, snapshot }) {
        const currentNow = now(nowMs);
        if (safeTimestamp(expiresAtMs) <= currentNow) fail();
        const checked = validateSnapshot(snapshot, currentNow);
        if (
          checked.runId !== `run-${active.releaseId.slice("release-".length)}` ||
          checked.runStatus !== "WAITING"
        ) {
          fail();
        }
        const payer = createSignedPayerBootstrapDiscovery({
          expiresAtMs,
          imageDigest: active.imageDigest,
          operatorKeyId: active.operatorKeyId,
          paymentMoved: false,
          payerClaimUrl: active.payerClaimUrl,
          publicMcpHostname: active.publicMcpHostname,
          publicMcpPort: 9443,
          releaseId: active.releaseId,
          repositorySha: active.repositorySha,
          schema: "clockchain.payer-bootstrap-discovery/v1",
          sessionId: active.sessionId,
          tunnelHost: active.tunnelHost,
          tunnelHostPublicKey: active.tunnelHostPublicKey,
          tunnelHostKeyFingerprint: active.tunnelHostKeyFingerprint,
          tunnelPort: 443,
          signer: (bytes) => sign(null, bytes, active.operatorPrivateKey).toString("base64"),
        });
        await writeJson(active.paths.payer, payer);
        await writeJson(active.paths.gate, gate({
          payerClaimApproved: false,
          payerDiscoveryReady: true,
          payerMcpReady: false,
          requestorDiscoveryReady: false,
          runStarted: true,
          tunnelTlsHealthy: false,
        }));
        await writeJson(active.paths.input, publicationInput(active, {
          certificateFingerprint: null,
          completedAtMs: null,
          snapshot: checked,
          verifierPublicationValidated: false,
        }));
      },
      async stageTerminalFailure({ nowMs }) {
        const currentNow = now(nowMs);
        const previous = validateInput(
          await readCanonical(active.paths.input, INPUT_KEYS),
          active,
        );
        const snapshot = failedSnapshot(previous.snapshot, currentNow);
        secretFree(snapshot, canaries);
        await writeJson(active.paths.input, publicationInput(active, {
          certificateFingerprint: previous.certificateFingerprint,
          completedAtMs: currentNow,
          snapshot,
          verifierPublicationValidated: false,
        }));
      },
    });
  } catch (error) {
    if (error instanceof AwsPublicStagingError) throw error;
    fail();
  }
}
