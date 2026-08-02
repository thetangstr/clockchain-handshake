import { spawn } from "node:child_process";
import { X509Certificate, randomBytes, createHash } from "node:crypto";
import { constants } from "node:fs";
import { lstat, mkdir, open, readFile } from "node:fs/promises";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { readCoordinatorState } from "../coordination/coordinator-runtime.mjs";
import { approveBootstrapClaim } from "../local-mcp/bootstrap-broker.mjs";
import {
  HybridPublicEdgeError,
  buildPublicEdgeArguments,
  probePinnedTlsEndpoint,
  waitForPublicEdge as waitForPinnedPublicEdge,
} from "./public-edge.mjs";

const ROOT = resolve(fileURLToPath(new URL("../../../", import.meta.url)));
const SHA40 = /^[0-9a-f]{40}$/;
const SHA64 = /^[0-9a-f]{64}$/;
const RELEASE_ID = /^release-[0-9a-f]{16}$/;
const SESSION_ID =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const MAX_LINE_BYTES = 16 * 1024;
const DEFAULT_WAIT_MS = 120_000;
const BROKER_PORT = 9555;

class HybridOperatorProductionError extends Error {
  constructor() {
    super("Hybrid local operator production dependencies failed safely.");
    this.name = "HybridOperatorProductionError";
    this.code = "HYBRID_OPERATOR_PRODUCTION_FAILED";
  }
}

function fail() {
  throw new HybridOperatorProductionError();
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
  const own = Reflect.ownKeys(value);
  if (own.length !== keys.length || keys.some((key) => !own.includes(key))) {
    fail();
  }
  return value;
}

function safeAbsolute(path) {
  if (
    typeof path !== "string" ||
    path.length === 0 ||
    path.includes("\0") ||
    !path.startsWith("/") ||
    resolve(path) !== path ||
    path === "/"
  ) {
    fail();
  }
  return path;
}

function safePort(value) {
  if (!Number.isSafeInteger(value) || value < 1 || value > 65_535) fail();
  return String(value);
}

function safeSha40(value) {
  if (typeof value !== "string" || !SHA40.test(value)) fail();
  return value;
}

function roleManifest(release, role) {
  const manifest = release.manifests?.find((entry) => entry.role === role);
  if (!plain(manifest) || typeof manifest.path !== "string") fail();
  return safeAbsolute(manifest.path);
}

function validateRelease(value, repositorySha) {
  if (
    !plain(value) ||
    value.paymentMoved !== false ||
    value.repositorySha !== repositorySha ||
    !RELEASE_ID.test(value.releaseId) ||
    !SESSION_ID.test(value.sessionId) ||
    !Array.isArray(value.manifests) ||
    value.manifests.length !== 2
  ) {
    fail();
  }
  roleManifest(value, "payer");
  roleManifest(value, "payee");
  return Object.freeze(value);
}

function parseJsonLine(line) {
  if (
    typeof line !== "string" ||
    line.length === 0 ||
    Buffer.byteLength(line, "utf8") > MAX_LINE_BYTES ||
    line.includes("\r")
  ) {
    fail();
  }
  const text = line.endsWith("\n") ? line.slice(0, -1) : line;
  if (text.includes("\n")) fail();
  try {
    return JSON.parse(text);
  } catch {
    fail();
  }
}

function parsedLineResult(value) {
  return typeof value === "string" ? parseJsonLine(value) : value;
}

function waitForLineFromStream(stream, predicate, deadlineMs = DEFAULT_WAIT_MS) {
  if (typeof predicate !== "function") fail();
  return new Promise((resolvePromise, reject) => {
    let buffer = "";
    let settled = false;
    const done = (operation, value) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      stream.off("data", onData);
      stream.off("error", onError);
      operation(value);
    };
    const onError = () => done(reject, new HybridOperatorProductionError());
    const onData = (chunk) => {
      buffer += chunk.toString("utf8");
      if (Buffer.byteLength(buffer, "utf8") > MAX_LINE_BYTES * 8) {
        done(reject, new HybridOperatorProductionError());
        return;
      }
      for (;;) {
        const index = buffer.indexOf("\n");
        if (index === -1) return;
        const line = buffer.slice(0, index + 1);
        buffer = buffer.slice(index + 1);
        const value = predicate(line);
        if (value !== null && value !== undefined) {
          done(resolvePromise, value);
          return;
        }
      }
    };
    const timer = setTimeout(
      () => done(reject, new HybridOperatorProductionError()),
      deadlineMs,
    );
    stream.on("data", onData);
    stream.once("error", onError);
  });
}

function createSpawnedService({ args, command }) {
  if (typeof command !== "string" || !Array.isArray(args)) fail();
  const child = spawn(command, args, {
    cwd: ROOT,
    env: process.env,
    stdio: ["ignore", "pipe", "pipe"],
  });
  let stderrBytes = 0;
  child.stderr.on("data", (chunk) => {
    stderrBytes += chunk.length;
    if (stderrBytes > MAX_LINE_BYTES * 8) child.kill("SIGTERM");
  });
  child.once("error", () => {});
  return Object.freeze({
    async stop() {
      if (child.exitCode !== null || child.signalCode !== null) return;
      child.kill("SIGTERM");
      await Promise.race([
        new Promise((resolvePromise) => child.once("close", resolvePromise)),
        new Promise((resolvePromise) => setTimeout(resolvePromise, 2_000)),
      ]);
      if (child.exitCode === null && child.signalCode === null) {
        child.kill("SIGKILL");
      }
    },
    waitForExit() {
      if (child.exitCode !== null) return Promise.resolve(child.exitCode);
      return new Promise((resolvePromise) =>
        child.once("close", (code) => resolvePromise(code)),
      );
    },
    waitForLine(predicate, deadlineMs) {
      return waitForLineFromStream(child.stdout, predicate, deadlineMs);
    },
  });
}

async function writePrivateFile(path, bytes) {
  const handle = await open(path, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL, 0o600);
  try {
    await handle.writeFile(bytes);
    await handle.sync();
  } finally {
    await handle.close();
  }
}

async function createStateRoot({ config, stateRoot }) {
  safeAbsolute(stateRoot);
  await mkdir(stateRoot, { mode: 0o700, recursive: false });
  const paths = Object.freeze({
    bootstrapBrokerCapabilityFile: join(stateRoot, "bootstrap-broker.capability"),
    bootstrapBrokerStateRoot: join(stateRoot, "bootstrap-broker"),
    payerStateRoot: join(stateRoot, "payer"),
    relayStateRoot: join(stateRoot, "relay"),
    releaseRoot: join(stateRoot, "release"),
  });
  for (const directory of [
    paths.bootstrapBrokerStateRoot,
    paths.payerStateRoot,
    paths.relayStateRoot,
    paths.releaseRoot,
  ]) {
    await mkdir(directory, { mode: 0o700, recursive: false });
  }
  await writePrivateFile(
    paths.bootstrapBrokerCapabilityFile,
    `${randomBytes(32).toString("hex")}\n`,
  );
  if (config.paymentMoved !== false) fail();
  return paths;
}

function relayArgs(config, paths) {
  return Object.freeze([
    join(ROOT, "bin/handshake-relay.mjs"),
    "--advertised-host", config.relay.advertisedHost,
    "--host", config.relay.host,
    "--port", safePort(config.relay.port),
    "--repository-sha", safeSha40(config.repositorySha),
    "--state", paths.relayStateRoot,
    "--tls-certificate", config.relay.tlsCertificateFile,
    "--tls-private-key", config.relay.tlsPrivateKeyFile,
  ]);
}

async function startRelay({ config, paths }, { spawnService = createSpawnedService } = {}) {
  const service = await spawnService({
    args: relayArgs(config, paths),
    command: process.execPath,
  });
  const ready = parsedLineResult(await service.waitForLine((line) => {
    const value = parseJsonLine(line);
    return value.schema === "clockchain.bilateral-relay-ready/v1" ? value : null;
  }));
  if (
    ready.paymentMoved !== false ||
    ready.host !== config.relay.host ||
    ready.port !== config.relay.port
  ) {
    fail();
  }
  return service;
}

async function startPublicEdge({ config }, { spawnService = createSpawnedService } = {}) {
  return spawnService({
    args: buildPublicEdgeArguments(config.publicEdge, {
      payerMcp: config.payerMcp.port,
      relay: config.relay.port,
    }),
    command: "ssh",
  });
}

const COORDINATION_PROBE_ATTEMPTS = 40;
const COORDINATION_PROBE_DELAY_MS = 250;

async function probeCoordinationEdge(
  { config },
  {
    probePinnedTlsEndpoint: probe = probePinnedTlsEndpoint,
    sleep = (delayMs) => new Promise((resolve_) => setTimeout(resolve_, delayMs)),
  } = {},
) {
  if (typeof sleep !== "function") fail();
  const input = Object.freeze({
    expectedFingerprint: config.relay.tlsFingerprint,
    host: config.publicEdge.host,
    path: "/",
    port: config.publicEdge.relayRemotePort,
  });
  let lastError = null;
  for (let attempt = 0; attempt < COORDINATION_PROBE_ATTEMPTS; attempt += 1) {
    try {
      return await probe(input);
    } catch (error) {
      if (
        error instanceof HybridPublicEdgeError &&
        error.code === "HYBRID_PUBLIC_EDGE_IDENTITY_MISMATCH"
      ) {
        throw error;
      }
      lastError = error;
      if (attempt + 1 < COORDINATION_PROBE_ATTEMPTS) {
        await sleep(COORDINATION_PROBE_DELAY_MS);
      }
    }
  }
  throw lastError ?? new HybridPublicEdgeError("HYBRID_PUBLIC_EDGE_UNAVAILABLE");
}

async function readStateFromRoot(releaseRoot) {
  const handle = await open(releaseRoot, constants.O_RDONLY | constants.O_DIRECTORY);
  try {
    return await readCoordinatorState({
      before: await lstat(releaseRoot),
      handle,
      path: releaseRoot,
    });
  } finally {
    await handle.close();
  }
}

async function waitForCoordinatorRelease({ releaseRoot, repositorySha }) {
  const deadline = Date.now() + DEFAULT_WAIT_MS;
  for (;;) {
    try {
      const state = await readStateFromRoot(releaseRoot);
      if (state !== null && state.repositorySha === repositorySha) {
        return validateRelease({
          ...state,
          manifests: [
            { path: join(releaseRoot, "payee.launch.json"), role: "payee" },
            { path: join(releaseRoot, "payer.launch.json"), role: "payer" },
          ],
        }, repositorySha);
      }
    } catch {
      // Keep polling until the coordinator has created the release files.
    }
    if (Date.now() >= deadline) fail();
    await new Promise((resolvePromise) => setTimeout(resolvePromise, 100));
  }
}

async function startCoordinator(
  { config, paths },
  {
    spawnService = createSpawnedService,
    waitForCoordinatorRelease: waitRelease = waitForCoordinatorRelease,
    useProductionCoordinatorState = true,
  } = {},
) {
  const service = await spawnService({
    args: [
      join(ROOT, "bin/handshake-coordinator.mjs"),
      "--clockchain-token-file", config.operator.clockchainTokenFile,
      "--operator-key-id", config.operator.keyId,
      "--operator-private-key", config.operator.privateKeyFile,
      "--release-root", paths.releaseRoot,
      "--relay-url", config.publicEdge.coordinationPublicUrl,
      "--repository-sha", config.repositorySha,
      "--rpc-url-file", config.operator.rpcUrlFile,
      "--tls-certificate", config.relay.tlsCertificateFile,
      "--tls-fingerprint", config.relay.tlsFingerprint,
    ],
    command: process.execPath,
  });
  const release = validateRelease(
    await waitRelease({
      releaseRoot: paths.releaseRoot,
      repositorySha: config.repositorySha,
    }),
    config.repositorySha,
  );
  return Object.freeze({
    ...service,
    release,
    async waitForTerminal() {
      const code = await service.waitForExit();
      if (code !== 0) fail();
      if (useProductionCoordinatorState) {
        const state = await readStateFromRoot(paths.releaseRoot);
        if (
          state?.paymentMoved !== false ||
          state.repositorySha !== config.repositorySha ||
          state.state !== "COMPLETE"
        ) {
          fail();
        }
      }
      return Object.freeze({ paymentMoved: false, status: "VERIFICATION_PASSED" });
    },
  });
}

async function startConsole({ config, paths }, { spawnService = createSpawnedService } = {}) {
  const service = await spawnService({
    args: [
      join(ROOT, "bin/handshake-console.mjs"),
      "--host", config.console.host,
      "--port", safePort(config.console.port),
      "--state-root", paths.releaseRoot,
    ],
    command: process.execPath,
  });
  await service.waitForLine((line) =>
    line === "Handshake console listening.\n" ? Object.freeze({ ready: true }) : null,
  );
  return service;
}

async function startBootstrapBroker(
  { config, paths, release },
  {
    approveBootstrapClaim: approveClaim = approveBootstrapClaim,
    spawnService = createSpawnedService,
    waitForPendingBootstrapClaim: waitClaim = waitForPendingBootstrapClaim,
  } = {},
) {
  const service = await spawnService({
    args: [
      join(ROOT, "bin/handshake-bootstrap-broker.mjs"),
      "serve",
      "--capability-file", paths.bootstrapBrokerCapabilityFile,
      "--host", "127.0.0.1",
      "--manifest", roleManifest(release, "payee"),
      "--operator-key-id", config.operator.keyId,
      "--operator-private-key", config.operator.privateKeyFile,
      "--port", String(BROKER_PORT),
      "--repository-sha", config.repositorySha,
      "--state", paths.bootstrapBrokerStateRoot,
    ],
    command: process.execPath,
  });
  const ready = parsedLineResult(await service.waitForLine((line) => {
    const value = parseJsonLine(line);
    return value.status === "BOOTSTRAP_BROKER_READY" ? value : null;
  }));
  if (ready.paymentMoved !== false || typeof ready.url !== "string") fail();
  return Object.freeze({
    ...service,
    capabilityFile: paths.bootstrapBrokerCapabilityFile,
    url: ready.url,
    async approveRequestor() {
      const claimFingerprint = await waitClaim({
        release,
        repositorySha: config.repositorySha,
        stateRoot: paths.bootstrapBrokerStateRoot,
      });
      if (typeof claimFingerprint !== "string" || !SHA64.test(claimFingerprint)) fail();
      const approval = await approveClaim({
        claimFingerprint,
        stateRoot: paths.bootstrapBrokerStateRoot,
      });
      if (
        approval?.paymentMoved !== false ||
        approval.status !== "APPROVED"
      ) {
        fail();
      }
      return Object.freeze({ paymentMoved: false, status: "APPROVED" });
    },
  });
}

async function waitForPendingBootstrapClaim({ stateRoot }) {
  const deadline = Date.now() + DEFAULT_WAIT_MS;
  for (;;) {
    try {
      const journal = JSON.parse(await readFile(join(stateRoot, "bootstrap-broker-journal.json"), "utf8"));
      const pending = Object.values(journal.claims ?? {}).filter(
        (claim) => claim?.status === "PENDING_APPROVAL",
      );
      if (pending.length === 1 && SHA64.test(pending[0].claimFingerprint)) {
        return pending[0].claimFingerprint;
      }
      if (pending.length > 1) fail();
    } catch (error) {
      if (error instanceof HybridOperatorProductionError) throw error;
      // Keep polling until the Requestor submits its exact bootstrap claim.
    }
    if (Date.now() >= deadline) fail();
    await new Promise((resolvePromise) => setTimeout(resolvePromise, 100));
  }
}

async function startPayer({ broker, config, paths, release }, { spawnService = createSpawnedService } = {}) {
  return spawnService({
    args: [
      join(ROOT, "bin/handshake-supervisor.mjs"),
      "--launch-manifest", roleManifest(release, "payer"),
      "--state", paths.payerStateRoot,
      "--run-mode", "local-two-run",
      "--payer-mcp-host", config.payerMcp.host,
      "--payer-mcp-port", safePort(config.payerMcp.port),
      "--payer-mcp-public-url", config.payerMcp.publicUrl,
      "--payer-mcp-bootstrap-broker-url", broker.url,
      "--payer-mcp-bootstrap-broker-capability-file", broker.capabilityFile,
      "--payer-mcp-tls-certificate", config.payerMcp.tlsCertificateFile,
      "--payer-mcp-tls-private-key", config.payerMcp.tlsPrivateKeyFile,
    ],
    command: process.execPath,
  });
}

async function waitForPayerMcpReady({ config, payer }) {
  const ready = parsedLineResult(await payer.waitForLine((line) => {
    const value = parseJsonLine(line);
    return value.status === "PAYER_MCP_READY" ? value : null;
  }));
  if (
    ready.paymentMoved !== false ||
    ready.role !== "payer" ||
    ready.url !== config.payerMcp.publicUrl
  ) {
    fail();
  }
  return Object.freeze({
    paymentMoved: false,
    status: "PAYER_MCP_READY",
    url: ready.url,
  });
}

async function certificateFingerprint(path) {
  const pem = await readFile(path, "utf8");
  return createHash("sha256").update(new X509Certificate(pem).raw).digest("hex");
}

async function waitForStableFile(path) {
  const deadline = Date.now() + DEFAULT_WAIT_MS;
  for (;;) {
    try {
      const before = await lstat(path);
      if (
        before.isFile() &&
        !before.isSymbolicLink() &&
        before.uid === process.getuid() &&
        (before.mode & 0o777) === 0o600 &&
        before.size > 0
      ) {
        const handle = await open(path, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
        try {
          const opened = await handle.stat();
          const after = await lstat(path);
          if (
            opened.isFile() &&
            opened.dev === before.dev &&
            opened.ino === before.ino &&
            after.dev === before.dev &&
            after.ino === before.ino &&
            opened.size === before.size &&
            after.size === before.size &&
            opened.mtimeMs === before.mtimeMs &&
            after.mtimeMs === before.mtimeMs
          ) {
            return;
          }
        } finally {
          await handle.close();
        }
      }
    } catch (error) {
      if (error instanceof HybridOperatorProductionError) throw error;
    }
    if (Date.now() >= deadline) fail();
    await new Promise((resolvePromise) => setTimeout(resolvePromise, 100));
  }
}

async function waitForPublicEdge(
  { config, release },
  {
    useProductionPublicEdge = true,
    waitForPublicEdge: waitEdge = waitForPinnedPublicEdge,
  } = {},
) {
  return waitEdge({
    coordination: {
      expectedFingerprint: config.relay.tlsFingerprint,
      host: config.publicEdge.host,
      path: `/v1/sessions/${release.sessionId}/enrollment-readiness?waitMs=0`,
      port: config.publicEdge.relayRemotePort,
    },
    deadlineMs: DEFAULT_WAIT_MS,
    payerMcp: {
      expectedFingerprint: useProductionPublicEdge
        ? await certificateFingerprint(config.payerMcp.tlsCertificateFile)
        : "0".repeat(64),
      host: config.publicEdge.host,
      path: "/mcp",
      port: config.publicEdge.payerMcpRemotePort,
    },
  });
}

async function publishRequestorDiscovery({ config, release }, { spawnService = createSpawnedService, now = Date.now } = {}) {
  const service = await spawnService({
    args: [
      join(ROOT, "scripts/publish-requestor-discovery.mjs"),
      "--bucket", config.publishing.bucket,
      "--certificate-key", "payer-mcp.crt",
      "--certificate-path", config.payerMcp.tlsCertificateFile,
      "--discovery-key", "requestor-discovery.json",
      "--expires-at-ms", String(now() + 30 * 60_000),
      "--image-digest", config.publishing.imageDigest,
      "--operator-key-id", config.operator.keyId,
      "--operator-private-key", config.operator.privateKeyFile,
      "--public-url", config.payerMcp.publicUrl,
      "--region", config.publishing.region,
      "--release-id", release.releaseId,
      "--repository-sha", config.repositorySha,
      "--session-id", release.sessionId,
      "--run-mode", "hybrid-local",
    ],
    command: process.execPath,
  });
  const result = parsedLineResult(await service.waitForLine((line) => {
    const value = parseJsonLine(line);
    return value.status === "REQUESTOR_DISCOVERY_PUBLISHED" ? value : null;
  }));
  if (
    result.paymentMoved !== false ||
    result.discoveryUrl !== config.publishing.requestorDiscoveryUrl
  ) {
    fail();
  }
  return Object.freeze({
    discoveryUrl: result.discoveryUrl,
    paymentMoved: false,
  });
}

async function runFunding(
  { config, paths },
  {
    spawnService = createSpawnedService,
    useProductionFundingRecord = true,
    waitForStableFundingRecord = waitForStableFile,
  } = {},
) {
  const fundingRecord = join(paths.releaseRoot, "funding-addresses.json");
  if (useProductionFundingRecord) await waitForStableFundingRecord(fundingRecord);
  const service = await spawnService({
    args: [
      join(ROOT, "scripts/fund-bilateral-addresses.mjs"),
      "--funding-record", fundingRecord,
      "--journal-directory", config.funding.journalDirectory,
      "--keystore", config.funding.keystoreFile,
      "--rpc-url-file", config.operator.rpcUrlFile,
    ],
    command: process.execPath,
  });
  const code = await service.waitForExit();
  if (code !== 0) fail();
  return Object.freeze({
    paymentMoved: false,
    status: "FUNDING_CONFIRMED",
  });
}

function writeStatus(value, { stdout = process.stdout } = {}) {
  stdout.write(`${JSON.stringify(value)}\n`);
}

export function createProductionHybridOperatorDependencies(overrides = {}) {
  if (!plain(overrides)) fail();
  const deps = Object.freeze({
    approveBootstrapClaim: overrides.approveBootstrapClaim ?? approveBootstrapClaim,
    now: overrides.now ?? Date.now,
    sleep: overrides.sleep ?? ((delayMs) => new Promise((resolve_) => setTimeout(resolve_, delayMs))),
    probePinnedTlsEndpoint: overrides.probePinnedTlsEndpoint ?? probePinnedTlsEndpoint,
    spawnService: overrides.spawnService ?? createSpawnedService,
    stdout: overrides.stdout ?? process.stdout,
    waitForCoordinatorRelease: overrides.waitForCoordinatorRelease ?? waitForCoordinatorRelease,
    waitForStableFundingRecord: overrides.waitForStableFundingRecord ?? waitForStableFile,
    waitForPendingBootstrapClaim: overrides.waitForPendingBootstrapClaim ?? waitForPendingBootstrapClaim,
    waitForPublicEdge: overrides.waitForPublicEdge ?? waitForPinnedPublicEdge,
    useProductionCoordinatorState: overrides.waitForCoordinatorRelease === undefined,
    useProductionFundingRecord:
      overrides.spawnService === undefined ||
      overrides.waitForStableFundingRecord !== undefined,
    useProductionPublicEdge: overrides.waitForPublicEdge === undefined,
  });
  return Object.freeze({
    createStateRoot,
    probeCoordinationEdge(input) {
      return probeCoordinationEdge(input, deps);
    },
    publishRequestorDiscovery(input) {
      return publishRequestorDiscovery(input, deps);
    },
    runFunding(input) {
      return runFunding(input, deps);
    },
    startBootstrapBroker(input) {
      return startBootstrapBroker(input, deps);
    },
    startConsole(input) {
      return startConsole(input, deps);
    },
    startCoordinator(input) {
      return startCoordinator(input, deps);
    },
    startPayer(input) {
      return startPayer(input, deps);
    },
    startPublicEdge(input) {
      return startPublicEdge(input, deps);
    },
    startRelay(input) {
      return startRelay(input, deps);
    },
    waitForPayerMcpReady,
    waitForPublicEdge(input) {
      return waitForPublicEdge(input, deps);
    },
    writeStatus(value) {
      return writeStatus(value, deps);
    },
  });
}
