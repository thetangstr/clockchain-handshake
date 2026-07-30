#!/usr/bin/env node
// Test-only process driver. It imports production parsers/builders while
// injecting the localhost fake only through explicit test configuration.
import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { constants } from "node:fs";
import { lstat, mkdir, open, readFile, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { Agent, request as httpsRequest } from "node:https";
import process from "node:process";
import { toHex } from "viem";
import { privateKeyToAccount } from "viem/accounts";

import { canonicalBytes } from "../../src/bilateral/canonical.mjs";
import { buildDefaultRoleInput, runPayerRole, runPayeeRole } from "../../src/bilateral/roles.mjs";
import { CHAIN_ID, REGISTRY_ADDRESS } from "../../src/constants.mjs";
import { createRecovery, createRegistrationIntent, withMetadataTransaction } from "../../src/registration-internal.mjs";
import { createRoleSupervisor } from "../../src/bilateral/coordination/supervisor.mjs";
import { createGitInspector, createProductionSupervisorDependencies } from "../../src/bilateral/coordination/supervisor-runtime.mjs";
import { createCoordinatorRuntimeDependencies, loadOrCreateCoordinatorRelease, parseCoordinatorArguments, readCoordinatorRuntimeConfig } from "../../src/bilateral/coordination/coordinator-runtime.mjs";
import { runCoordinator as runProductionCoordinator } from "../../src/bilateral/coordination/coordinator.mjs";
import { validateRelayArtifactWithFacts } from "../../src/bilateral/coordination/artifact.mjs";
import { requestPaymentThroughPayerMcp } from "../../src/bilateral/local-mcp/client.mjs";
import { main as proposeMain } from "../../bin/handshake-propose.mjs";
import { main as acceptMain } from "../../bin/handshake-accept.mjs";
import { main as requestPaymentMain } from "../../bin/handshake-request-payment.mjs";
import { main as preflightMain } from "../../scripts/probe-bilateral-rendezvous.mjs";
import { runCli as registrationRunCli } from "../../scripts/register-bilateral-identity.mjs";
import { buildDefaultVerifierInput, main as verifierMain } from "../../scripts/verify-bilateral-results.mjs";
import { renderBilateralVerdictMarkdown } from "../../src/bilateral/verdict.mjs";
import { createFakeBilateralClockchainHttpClient } from "./fake-bilateral-clockchain-service.mjs";

const SCHEMA = "clockchain.bilateral-coordination-process-child/v1";
const MODES = new Set(["coordinator", "payer", "payee", "verifier"]);
const CHILD_DEADLINE_MS = 60_000;
const STOP_GRACE_MS = 1_000;
const BARRIER_DEADLINE_MS = 90_000;
const ROLE_SCHEMA = "clockchain.bilateral-coordination-process-supervisor/v1";
const COORDINATOR_SCHEMA = "clockchain.bilateral-coordination-process-coordinator/v1";
const PROCESS_SCENARIOS = new Set([
  "success",
  "missing-mandate",
  "forged-iris-signature",
  "wrong-billie-signer",
  "invoice-prefix-mismatch",
  "request-replay-changed-bytes",
  "expired-mandate",
  "expired-request",
  "descriptor-swap",
  "fourth-write",
  "relay-restart-after-mandate",
  "relay-restart-after-request",
  "coordinator-restart-before-descriptor",
  "stale-verifier-publication",
  "mismatched-verifier-publication",
]);
let failurePhase = "dispatch";

function fail() {
  throw new Error("process child rejected its configuration");
}

function exact(value, keys) {
  return value !== null
    && typeof value === "object"
    && !Array.isArray(value)
    && Object.getPrototypeOf(value) === Object.prototype
    && Object.keys(value).length === keys.length
    && keys.every((key) => Object.hasOwn(value, key));
}

function canonicalJson(value) {
  if (value === null || ["string", "boolean", "number"].includes(typeof value)) {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (value !== null && typeof value === "object" && Object.getPrototypeOf(value) === Object.prototype) {
    return `{${Object.keys(value).sort().map(
      (key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`,
    ).join(",")}}`;
  }
  fail();
}

function identity(owners) {
  return Object.freeze({
    async getChainId() {
      return 11155111;
    },
    async readContract({ args }) {
      const owner = owners[String(args[0])];
      if (typeof owner !== "string") throw new Error("unknown agent");
      return owner;
    },
  });
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function absolute(path) {
  return typeof path === "string" && path.startsWith("/") && path.length < 4096;
}

function parse(argv) {
  if (!Array.isArray(argv) || argv.length !== 3 || !MODES.has(argv[0]) || argv[1] !== "--configuration" || !absolute(argv[2])) fail();
  return { mode: argv[0], path: argv[2] };
}

async function config(path) {
  const info = await lstat(path);
  if (!info.isFile() || info.isSymbolicLink() || info.nlink !== 1 || (info.mode & 0o777) !== 0o600 || info.size < 2 || info.size > 65536) fail();
  const handle = await open(path, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
  try {
    const opened = await handle.stat();
    if (opened.dev !== info.dev || opened.ino !== info.ino) fail();
    const bytes = Buffer.alloc(info.size);
    const { bytesRead } = await handle.read(bytes, 0, bytes.length, 0);
    if (bytesRead !== bytes.length) fail();
    const value = JSON.parse(bytes.toString("utf8"));
    if (canonicalJson(value) !== bytes.toString("utf8")) fail();
    return value;
  } finally { await handle.close(); }
}

function validFake(value) {
  return exact(value, ["host", "paymentMoved", "pid", "port", "schema"])
    && value.schema === "clockchain.fake-bilateral-clockchain-listen/v1"
    && value.host === "127.0.0.1"
    && value.paymentMoved === false
    && Number.isInteger(value.pid)
    && Number.isInteger(value.port);
}

function validPayerMcpServer(value) {
  return value === null || exact(value, ["host", "port", "tlsCertificatePath", "tlsPrivateKeyPath"])
    && value.host === "127.0.0.1"
    && Number.isInteger(value.port)
    && value.port >= 0
    && value.port <= 65_535
    && absolute(value.tlsCertificatePath)
    && absolute(value.tlsPrivateKeyPath);
}

function validRequestPayment(value) {
  return value === null || exact(value, ["intakeRequestId", "mcpUrl", "tlsCertificatePath", "tlsFingerprint"])
    && /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(value.intakeRequestId)
    && typeof value.mcpUrl === "string"
    && value.mcpUrl.startsWith("https://127.0.0.1:")
    && value.mcpUrl.endsWith("/mcp")
    && absolute(value.tlsCertificatePath)
    && /^[0-9a-f]{64}$/.test(value.tlsFingerprint);
}

function validRoleConfiguration(value, role) {
  if (!exact(value, ["agentIds", "clockMs", "controlBarrier", "fake", "launchManifestPath", "payerMcpServer", "preflightFake", "repositoryRoot", "requestPayment", "role", "scenario", "schema", "sepoliaRpc", "startBarrier", "stateRoot", "token"])
    || value.schema !== ROLE_SCHEMA
    || value.role !== role
    || !validFake(value.fake)
    || !validFake(value.preflightFake)
    || !absolute(value.launchManifestPath)
    || !absolute(value.repositoryRoot)
    || !absolute(value.stateRoot)
    || !exact(value.startBarrier, ["ready", "release"])
    || !absolute(value.startBarrier.ready)
    || !absolute(value.startBarrier.release)
    || typeof value.token !== "string"
    || !/^[!-~]{1,4096}$/.test(value.token)
    || typeof value.sepoliaRpc !== "string"
    || !/^https?:\/\/[!-~]{1,2048}$/.test(value.sepoliaRpc)
    || !exact(value.agentIds, ["rehearsal", "stakeholder"])
    || !/^[1-9][0-9]*$/.test(value.agentIds.rehearsal)
    || !/^[1-9][0-9]*$/.test(value.agentIds.stakeholder)
    || value.agentIds.rehearsal === value.agentIds.stakeholder || !Number.isSafeInteger(value.clockMs) || value.clockMs < 0
    || !PROCESS_SCENARIOS.has(value.scenario)
    || !validPayerMcpServer(value.payerMcpServer)
    || !validRequestPayment(value.requestPayment)) fail();
  if (value.controlBarrier !== null && (!exact(value.controlBarrier, ["ready", "release"]) || !absolute(value.controlBarrier.ready) || !absolute(value.controlBarrier.release))) fail();
  if ((role === "payer") !== (value.payerMcpServer !== null)) fail();
  if ((role === "payee") !== (value.requestPayment !== null)) fail();
  return value;
}

async function ensureRoleToken({ stateRoot, token }) {
  try {
    await mkdir(stateRoot, { mode: 0o700 });
  } catch (error) {
    if (error?.code !== "EEXIST") throw error;
  }
  const root = await lstat(stateRoot);
  if (!root.isDirectory() || root.isSymbolicLink() || root.nlink < 2 || root.uid !== process.getuid?.() || (root.mode & 0o777) !== 0o700) fail();
  const tokenPath = join(stateRoot, "clockchain.token");
  try {
    await writeFile(tokenPath, token, { encoding: "utf8", flag: "wx", mode: 0o600 });
  } catch (error) {
    if (error?.code !== "EEXIST") throw error;
    const existing = await readFile(tokenPath, "utf8");
    if (existing !== token) fail();
  }
  const info = await lstat(tokenPath);
  if (!info.isFile() || info.isSymbolicLink() || info.nlink !== 1 || (info.mode & 0o777) !== 0o600 || (await readFile(tokenPath, "utf8")) !== token) fail();
  return tokenPath;
}

function boundedRoleRunner(value, role, owners) {
  const sharedIdentity = Object.freeze({
    async getChainId() { return 11155111; },
    async readContract({ args }) {
      const agentId = String(args?.[0]);
      if (!/^[1-9][0-9]*$/.test(agentId)) throw new Error("unknown agent");
      if (typeof owners[agentId] === "string") return owners[agentId];
      const resolved = await createFakeBilateralClockchainHttpClient(value.fake).resolveAgent(agentId);
      if (!exact(resolved, ["agentId", "owner", "status"])
        || resolved.agentId !== agentId
        || resolved.status !== "active"
        || !/^0x[0-9a-f]{40}$/.test(resolved.owner)) throw new Error("unknown agent");
      owners[agentId] = resolved.owner;
      return resolved.owner;
    },
  });
  const buildRoleInput = (values, requestedRole) => buildDefaultRoleInput(values, requestedRole, {
    createClockchainClient: () => createFakeBilateralClockchainHttpClient(value.fake),
    createIdentityClient: () => sharedIdentity,
  });
  const runner = role === "payer" ? runPayerRole : runPayeeRole;
  let elapsed = 0;
  return async (arguments_, notifyReady) => {
    if (typeof notifyReady !== "function") fail();
    const runRole = (input) => runner({
      ...input,
      jitter: () => 0,
      monotonicNow: () => elapsed,
      notifyReady,
      now: () => value.clockMs,
      sleeper: async () => {
        elapsed += 1;
        await new Promise((resolve) => setImmediate(resolve));
      },
    });
    const code = role === "payer"
      ? await proposeMain(arguments_, { buildRoleInput, runRole })
      : await acceptMain(arguments_, { buildRoleInput, runRole });
    return code === 0 ? Object.freeze({ ambiguous: false, exitCode: 0 }) : Object.freeze({ ambiguous: false, exitCode: 1 });
  };
}

function supervisorLauncher(value, role, owners, inspector) {
  const roleRunner = boundedRoleRunner(value, role, owners);
  const registration = async (args) => {
    const run = args[args.indexOf("--output") + 1].endsWith("/rehearsal/identity") ? "rehearsal" : "stakeholder";
    const displayName = role === "payer" ? "Payer" : "Requestor";
    const agentId = value.agentIds[run];
    const stableHash = (label) => `0x${createHash("sha256").update(`${role}:${run}:${label}`).digest("hex")}`;
    const dependencies = {
      repositoryStateResolver: async () => ({ headSha: args[args.indexOf("--repository-sha") + 1], worktreeStatus: "" }),
      output: () => {},
      writeError: () => {},
      register: async ({ expectedAddress, onCheckpoint, privateKey }) => {
        if (typeof privateKey !== "string" || !/^0x[0-9a-f]{40}$/i.test(expectedAddress) || Object.hasOwn(owners, agentId)) fail();
        const registerTx = stableHash("register");
        const metadataTx = stableHash("metadata");
        const intent = createRegistrationIntent({ address: expectedAddress, displayName, registerCalldata: "0x01020304", registerGas: 150_000n, transactionFields: { gasPrice: 2n } });
        const recovery = createRecovery({ address: expectedAddress, agentId: BigInt(agentId), displayName, registerBlock: 4_000n, registerTx });
        await onCheckpoint(intent);
        await onCheckpoint(recovery);
        await onCheckpoint(withMetadataTransaction(recovery, metadataTx, 1));
        const owner = expectedAddress.toLowerCase();
        await createFakeBilateralClockchainHttpClient(value.fake).registerAgent({ agentId, owner, status: "active" });
        owners[agentId] = owner;
        return { address: expectedAddress, agentId, chainId: CHAIN_ID, displayName, identityReference: recovery.identityReference, metadataBlock: "4001", metadataTx, registerBlock: recovery.registerBlock, registerTx, registryAddress: REGISTRY_ADDRESS, registryNamespace: recovery.registryNamespace };
      },
    };
    return registrationRunCli(args, dependencies);
  };
  return async ({ args, command }) => {
    if (!Array.isArray(args) || !["scripts/probe-bilateral-rendezvous.mjs", "scripts/register-bilateral-identity.mjs", "bin/handshake-propose.mjs", "bin/handshake-accept.mjs"].includes(command)) fail();
    try {
      if (command === "bin/handshake-propose.mjs" || command === "bin/handshake-accept.mjs") {
        let readinessState = "pending";
        let resolveReadiness;
        let rejectReadiness;
        const readiness = new Promise((resolve, reject) => {
          resolveReadiness = resolve;
          rejectReadiness = reject;
        });
        const completion = Promise.resolve().then(() => roleRunner(args, () => {
          if (readinessState !== "pending") fail();
          readinessState = "ready";
          resolveReadiness();
        }));
        void completion.then(
          () => {
            if (readinessState === "pending") {
              readinessState = "rejected";
              rejectReadiness(new Error("role exited before authenticated readiness"));
            }
          },
          () => {
            if (readinessState === "pending") {
              readinessState = "rejected";
              rejectReadiness(new Error("role failed before authenticated readiness"));
            }
          },
        );
        let readinessTimer;
        try {
          await Promise.race([
            readiness,
            new Promise((_resolve, reject) => {
              readinessTimer = setTimeout(() => {
                if (readinessState === "pending") {
                  readinessState = "rejected";
                  reject(new Error("role readiness deadline expired"));
                }
              }, BARRIER_DEADLINE_MS);
            }),
          ]);
        } finally {
          clearTimeout(readinessTimer);
        }
        return Object.freeze({ ambiguous: false, started: true, completion });
      }
      if (command === "scripts/probe-bilateral-rendezvous.mjs") {
        const barrierRoot = dirname(value.stateRoot);
        const readyPath = join(barrierRoot, `.preflight-${role}-ready.json`);
        const peerPath = join(barrierRoot, `.preflight-${role === "payer" ? "payee" : "payer"}-ready.json`);
        const payerWrite = preflightWriteMarker(barrierRoot, "payer");
        const payeeWrite = preflightWriteMarker(barrierRoot, "payee");
        await writeOrReuseExact(readyPath, { role, schema: ROLE_SCHEMA, stage: "preflight-client-ready" });
        const peerDeadline = Date.now() + BARRIER_DEADLINE_MS;
        let peerReady = false;
        while (Date.now() < peerDeadline) {
          try {
            const peer = JSON.parse(await readFile(peerPath, "utf8"));
            if (!exact(peer, ["role", "schema", "stage"]) || peer.role === role || peer.schema !== ROLE_SCHEMA || peer.stage !== "preflight-client-ready") fail();
            peerReady = true;
            break;
          } catch (error) {
            if (error?.code !== "ENOENT") throw error;
          }
          await sleep(5);
        }
        if (!peerReady) fail();
        let now = value.clockMs;
        let firstPeerRead = true;
        const rawPreflightClient = createFakeBilateralClockchainHttpClient(value.preflightFake);
        const preflightClient = Object.freeze({
          ...rawPreflightClient,
          logAction: async (input) => {
            if (role === "payee") await waitForExactPrivateMarker(payerWrite.path, payerWrite.value);
            const result = await rawPreflightClient.logAction(input);
            const marker = role === "payer" ? payerWrite : payeeWrite;
            await writeOrReuseExact(marker.path, marker.value);
            return result;
          },
          searchActions: async (input) => {
            if (role === "payer" && firstPeerRead) {
              firstPeerRead = false;
              await waitForExactPrivateMarker(payeeWrite.path, payeeWrite.value);
            }
            return rawPreflightClient.searchActions(input);
          },
        });
        await preflightMain(args, {
          createClient: () => preflightClient,
          now: () => ++now,
          repositoryPublicKeyResolver: async ({ repositoryPath, repositorySha }) => {
            const key = /^docs\/operator-keys\/([a-z0-9][a-z0-9-]{0,63})\.pub$/.exec(repositoryPath);
            if (key === null) fail();
            return inspector.operatorKey(repositorySha, key[1]);
          },
          repositoryStateResolver: async ({ repositorySha }) => {
            const state = await inspector.probe();
            if (state.head !== repositorySha || state.clean !== true) fail();
            return { commitSha: repositorySha, headSha: repositorySha, worktreeStatus: "" };
          },
          sleeper: async (delay) => {
            now += delay;
            await sleep(20);
          },
          windowMs: 120_000,
        });
        return Object.freeze({ ambiguous: false, exitCode: 0 });
      }
      const code = await registration(args);
      return Object.freeze({ ambiguous: false, exitCode: code === 0 ? 0 : 1 });
    } catch {
      return Object.freeze({ ambiguous: false, exitCode: 1 });
    }
  };
}

async function runSupervisorRole(value, role) {
  const configuration = validRoleConfiguration(value, role);
  const tokenPath = await ensureRoleToken(configuration);
  const production = await createProductionSupervisorDependencies({
    launchManifestPath: configuration.launchManifestPath,
    ...(configuration.payerMcpServer === null ? {} : { payerMcpServerOptions: configuration.payerMcpServer }),
    repositoryRoot: configuration.repositoryRoot,
    sepoliaRpc: async () => "0x0",
    stateRoot: configuration.stateRoot,
  });
  const owners = Object.create(null);
  let replayRequestBytes = null;
  const inspector = createGitInspector(configuration.repositoryRoot);
  const immediateEvents = (client) => {
    if (!client || typeof client.readEvents !== "function") fail();
    return Object.freeze({
      ...client,
      readEvents: ({ after, waitMs }) => {
        if (after !== null || !Number.isSafeInteger(waitMs) || waitMs < 0 || waitMs > 30_000) fail();
        return client.readEvents({ after: null, waitMs: 0 });
      },
    });
  };
  const scenarioClient = (client) => {
    const immediate = immediateEvents(client);
    const checkpoint = async (stage) => {
      if (configuration.controlBarrier === null) fail();
      await writeOrReuseExact(configuration.controlBarrier.ready, { schema: COORDINATOR_SCHEMA, stage });
      await waitForRelease(configuration.controlBarrier.release);
    };
    if (configuration.scenario === "relay-restart-after-mandate" && role === "payer") {
      return Object.freeze({
        ...immediate,
        publishPayerMandate: async (input) => {
          const receipt = await immediate.publishPayerMandate(input);
          await checkpoint("mandate-ready");
          return receipt;
        },
      });
    }
    if (configuration.scenario === "relay-restart-after-request" && role === "payee") {
      return Object.freeze({
        ...immediate,
        submitPaymentRequest: async (input) => {
          const receipt = await immediate.submitPaymentRequest(input);
          await checkpoint("request-ready");
          return receipt;
        },
      });
    }
    if (configuration.scenario === "missing-mandate" && role === "payer") {
      return Object.freeze({
        ...immediate,
        publishPayerMandate: async ({ bytes }) => Object.freeze({
          digest: createHash("sha256").update(bytes).digest("hex"),
        }),
      });
    }
    if (configuration.scenario === "request-replay-changed-bytes" && role === "payee") {
      return Object.freeze({
        ...immediate,
        submitPaymentRequest: async ({ bytes }) => {
          const receipt = await immediate.submitPaymentRequest({ bytes });
          if (!Buffer.isBuffer(replayRequestBytes) || replayRequestBytes.equals(bytes)) fail();
          let replayRejected = false;
          try {
            await immediate.submitPaymentRequest({ bytes: replayRequestBytes });
          } catch {
            replayRejected = true;
          }
          if (!replayRejected || receipt?.paymentMoved !== false) fail();
          throw new Error("conflicting request replay rejected");
        },
      });
    }
    return immediate;
  };
  // Production dependencies are frozen.  Copying the surface makes every test
  // substitution explicit and keeps the TLS/enrollment/replay implementation.
  const dependencies = {
    ...production,
    createCoordinationClient: (input) => scenarioClient(production.createCoordinationClient(input)),
    createResumedCoordinationClient: async (input) => scenarioClient(await production.createResumedCoordinationClient(input)),
    async ensureToken({ role: requestedRole }) {
      if (requestedRole !== role) fail();
      return Object.freeze({ tokenPath });
    },
    nowMs: () => configuration.clockMs,
    async verifyFundingInputs() { return Object.freeze({ paymentMoved: false }); },
    launcher: supervisorLauncher(configuration, role, owners, inspector),
  };
  if (["forged-iris-signature", "expired-mandate"].includes(configuration.scenario) && role === "payer") {
    dependencies.signPayerMandate = async (input) => {
      const changed = structuredClone(input);
      if (configuration.scenario === "expired-mandate") {
        changed.mandate = structuredClone(input.mandate);
        changed.mandate.expiresAtMs = String(
          Number(changed.mandate.issuedAtMs) + 1,
        );
        if (
          !/^(?:0|[1-9][0-9]*)$/.test(changed.mandate.issuedAtMs) ||
          !/^(?:0|[1-9][0-9]*)$/.test(changed.mandate.expiresAtMs) ||
          !(
            Number(changed.mandate.issuedAtMs) <
              Number(changed.mandate.expiresAtMs) &&
            Number(changed.mandate.expiresAtMs) <=
              configuration.clockMs
          )
        ) {
          fail();
        }
        return production.signPayerMandate(changed);
      }
      const envelope = structuredClone(await production.signPayerMandate(changed));
      const last = envelope.signature.value.at(-1);
      envelope.signature.value = `${envelope.signature.value.slice(0, -1)}${last === "0" ? "1" : "0"}`;
      return envelope;
    };
  }
  if (["wrong-billie-signer", "invoice-prefix-mismatch", "expired-request", "request-replay-changed-bytes"].includes(configuration.scenario) && role === "payee") {
    dependencies.signPaymentRequest = async (input) => {
      if (configuration.scenario === "wrong-billie-signer") {
        const other = privateKeyToAccount(`0x${"42".repeat(32)}`);
        const request = structuredClone(input.request);
        return Object.freeze({
          request: Object.freeze(request),
          schema: "clockchain.bilateral-payment-request-envelope/v1",
          signature: Object.freeze({
            address: other.address,
            algorithm: "eip191",
            value: await other.signMessage({ message: { raw: toHex(canonicalBytes(request)) } }),
          }),
        });
      }
      const changed = structuredClone(input);
      changed.request = structuredClone(input.request);
      if (configuration.scenario === "invoice-prefix-mismatch") {
        changed.request.invoiceReference = `WRONG-${changed.request.invoiceReference}`;
      } else if (configuration.scenario === "expired-request") {
        changed.request.expiresAtMs = String(Number(changed.request.createdAtMs) + 1);
      } else {
        const replay = structuredClone(input);
        replay.request = structuredClone(input.request);
        replay.request.invoiceReference = `${replay.request.invoiceReference}-REPLAY`;
        replayRequestBytes = canonicalBytes(await production.signPaymentRequest(replay));
      }
      return production.signPaymentRequest(changed);
    };
  }
  if (role === "payee" && configuration.requestPayment !== null) {
    const requestArguments = [
      "--launch-manifest", configuration.launchManifestPath,
      "--intake-request-id", configuration.requestPayment.intakeRequestId,
      "--mcp-url", configuration.requestPayment.mcpUrl,
      "--state", configuration.stateRoot,
      "--tls-certificate", configuration.requestPayment.tlsCertificatePath,
      "--tls-fingerprint", configuration.requestPayment.tlsFingerprint,
    ];
    await requestPaymentMain(requestArguments, {
      runSupervisor: async ({ launchManifestPath, stateRoot }) => {
        if (launchManifestPath !== configuration.launchManifestPath || stateRoot !== configuration.stateRoot) fail();
        const manifest = await production.readLaunchManifest(configuration.launchManifestPath);
        const retry = await requestPaymentThroughPayerMcp({
          capability: manifest.payerMcpIntakeCapability,
          intakeRequestId: configuration.requestPayment.intakeRequestId,
          mcpUrl: configuration.requestPayment.mcpUrl,
          repositorySha: manifest.repositorySha,
          stateRoot: configuration.stateRoot,
          tlsCertificatePem: await readFile(configuration.requestPayment.tlsCertificatePath, "utf8"),
          tlsFingerprint: configuration.requestPayment.tlsFingerprint,
        });
        if (retry?.paymentMoved !== false || retry.status !== "HANDSHAKE_REQUIRED") fail();
        process.stdout.write(`${canonicalJson({ paymentMoved: false, status: "REQUESTOR_SUPERVISOR_START" })}\n`);
        const supervisor = await createRoleSupervisor({
          dependencies,
          launchManifestPath: configuration.launchManifestPath,
          stateRoot: configuration.stateRoot,
        });
        await supervisor.bootstrap();
        await writeExclusive(configuration.startBarrier.ready, {
          role,
          schema: ROLE_SCHEMA,
          stage: "bootstrap-complete",
        });
        return supervisor.run();
      },
    });
    return;
  }
  const supervisor = await createRoleSupervisor({
    dependencies,
    launchManifestPath: configuration.launchManifestPath,
    stateRoot: configuration.stateRoot,
  });
  await supervisor.bootstrap();
  await writeExclusive(configuration.startBarrier.ready, {
    role,
    schema: ROLE_SCHEMA,
    stage: "bootstrap-complete",
  });
  await waitForRelease(configuration.startBarrier.release);
  await supervisor.run();
}

function roleDependencies(value, role) {
  if (!exact(value, ["arguments", "fake", "owners", "schema"])
    || value.schema !== SCHEMA
    || !Array.isArray(value.arguments)
    || !validFake(value.fake)
    || !exact(value.owners, ["8677", "8678"])) fail();
  const buildRoleInput = (values, requestedRole) => buildDefaultRoleInput(
    values,
    requestedRole,
    {
      createClockchainClient: () => createFakeBilateralClockchainHttpClient(value.fake),
      createIdentityClient: () => identity(value.owners),
    },
  );
  const runner = role === "payer" ? runPayerRole : runPayeeRole;
  let elapsed = 0;
  return {
    buildRoleInput,
    runRole: async (input) => runner({
      ...input,
      jitter: () => 0,
      monotonicNow: () => elapsed,
      now: () => value.clockMs,
      sleeper: async () => {
        elapsed += 1;
        await sleep(20);
      },
    }),
  };
}
async function runRole(value, role) {
  const dependencies = roleDependencies(value, role);
  const result = role === "payer"
    ? await proposeMain(value.arguments, dependencies)
    : await acceptMain(value.arguments, dependencies);
  if (result !== 0) fail();
}

async function runVerifier(value) {
  if (!exact(value, ["arguments", "fake", "owners", "scenario", "schema"])
    || value.schema !== SCHEMA
    || !Array.isArray(value.arguments)
    || !validFake(value.fake)
    || !validOwners(value.owners)
    || !PROCESS_SCENARIOS.has(value.scenario)) fail();
  const result = await verifierMain(value.arguments, {
    buildVerifierInput: (values) => buildDefaultVerifierInput(values, {
      createClockchainClient: () => createFakeBilateralClockchainHttpClient(value.fake),
      createIdentityClient: () => identity(value.owners),
    }),
    ...(["stale-verifier-publication", "mismatched-verifier-publication"].includes(value.scenario)
      ? { stdout: { write() {} } }
      : {}),
  });
  if (result !== 0) fail();
}

async function tlsProbe(relay) {
  const ca = await readFile(relay.ca);
  const agent = new Agent({ ca, keepAlive: false, maxCachedSessions: 0 });
  try {
    await new Promise((resolve, reject) => {
      const request = httpsRequest({ agent, ca, host: "127.0.0.1", method: "GET", path: "/v1/bootstrap", port: relay.port, rejectUnauthorized: true, servername: "localhost", headers: { host: `127.0.0.1:${relay.port}` } }, (response) => {
        const certificate = response.socket.getPeerCertificate(true);
        const fingerprint = certificate.raw && createHash("sha256").update(certificate.raw).digest("hex");
        response.resume();
        response.once("end", () => response.statusCode === 400 && fingerprint === relay.fingerprint ? resolve() : reject(new Error("relay probe failed")));
      });
      request.once("error", reject);
      request.end();
    });
  } finally { agent.destroy(); }
}

function childExited(child) {
  return child.exitCode !== null || child.signalCode !== null;
}

async function terminate(child) {
  if (childExited(child)) return;
  child.kill("SIGTERM");
  await Promise.race([
    new Promise((resolve) => child.once("close", resolve)),
    sleep(STOP_GRACE_MS),
  ]);
  if (!childExited(child)) {
    child.kill("SIGKILL");
    await new Promise((resolve) => child.once("close", resolve));
  }
}

async function waitForChild(child) {
  if (childExited(child)) return { code: child.exitCode, signal: child.signalCode };
  return new Promise((resolve, reject) => {
    const timer = setTimeout(async () => {
      try { await terminate(child); reject(new Error("child deadline expired")); } catch (error) { reject(error); }
    }, CHILD_DEADLINE_MS);
    child.once("error", (error) => { clearTimeout(timer); reject(error); });
    child.once("close", (code, signal) => { clearTimeout(timer); resolve({ code, signal }); });
  });
}
async function start(configuration, { resume = false } = {}) {
  const stdout = await open(configuration.logs.stdout, resume ? "a" : "wx", 0o600);
  const stderr = await open(configuration.logs.stderr, resume ? "a" : "wx", 0o600);
  try {
    return spawn(process.execPath, [
      process.argv[1],
      configuration.mode,
      "--configuration",
      configuration.path,
    ], { stdio: ["ignore", stdout, stderr] });
  } finally {
    await stdout.close();
    await stderr.close();
  }
}

async function writeExclusive(path, value) {
  await writeFile(path, canonicalJson(value), {
    encoding: "utf8",
    flag: "wx",
    mode: 0o600,
  });
}

async function writeOrReuseExact(path, value) {
  const bytes = canonicalJson(value);
  try {
    await writeFile(path, bytes, {
      encoding: "utf8",
      flag: "wx",
      mode: 0o600,
    });
  } catch (error) {
    if (error?.code !== "EEXIST") throw error;
    const info = await lstat(path);
    if (!info.isFile() || info.isSymbolicLink() || info.nlink !== 1 || (info.mode & 0o777) !== 0o600 || await readFile(path, "utf8") !== bytes) fail();
  }
}

async function readRelease(path) {
  const info = await lstat(path);
  if (!info.isFile()
    || info.isSymbolicLink()
    || info.nlink !== 1
    || (info.mode & 0o777) !== 0o600
    || info.size > 256) fail();
  const text = await readFile(path, "utf8");
  const value = JSON.parse(text);
  if (!exact(value, ["release"]) || value.release !== true || canonicalJson(value) !== text) fail();
}

async function waitForRelease(path) {
  const deadline = Date.now() + BARRIER_DEADLINE_MS;
  while (Date.now() < deadline) {
    try {
      await readRelease(path);
      return;
    } catch (error) {
      if (error?.code !== "ENOENT") throw error;
    }
    await sleep(20);
  }
  fail();
}

async function waitForExactPrivateMarker(path, expected) {
  const bytes = canonicalJson(expected);
  const deadline = Date.now() + BARRIER_DEADLINE_MS;
  while (Date.now() < deadline) {
    try {
      const info = await lstat(path);
      if (!info.isFile() || info.isSymbolicLink() || info.nlink !== 1 || (info.mode & 0o777) !== 0o600) fail();
      if (await readFile(path, "utf8") !== bytes) fail();
      return;
    } catch (error) {
      if (error?.code !== "ENOENT") throw error;
    }
    await sleep(20);
  }
  fail();
}

function preflightWriteMarker(root, role) {
  return Object.freeze({
    path: join(root, `.preflight-${role}-write-complete.json`),
    value: Object.freeze({ role, schema: ROLE_SCHEMA, stage: "preflight-write-complete" }),
  });
}

function validLogs(value) {
  return exact(value, ["stderr", "stdout"]) && absolute(value.stdout) && absolute(value.stderr);
}

function validOwners(value) {
  if (value === null || typeof value !== "object" || Array.isArray(value) || Object.getPrototypeOf(value) !== Object.prototype) return false;
  const agentIds = Object.keys(value);
  return agentIds.length === 2
    && agentIds.every((agentId) => /^[1-9][0-9]*$/.test(agentId) && /^0x[0-9a-f]{40}$/.test(value[agentId]))
    && new Set(Object.values(value)).size === 2;
}

function validCoordinatorRole(value) {
  return exact(value, ["agentIds", "configPath", "logs", "stateRoot", "token"])
    && exact(value.agentIds, ["rehearsal", "stakeholder"])
    && /^[1-9][0-9]*$/.test(value.agentIds.rehearsal)
    && /^[1-9][0-9]*$/.test(value.agentIds.stakeholder)
    && value.agentIds.rehearsal !== value.agentIds.stakeholder
    && absolute(value.configPath)
    && absolute(value.stateRoot)
    && typeof value.token === "string"
    && /^[!-~]{1,4096}$/.test(value.token)
    && validLogs(value.logs);
}

function validCoordinatorConfiguration(value) {
  if (!exact(value, ["arguments", "barrier", "children", "clockMs", "coordinatorFirst", "fake", "payerMcp", "preflightFake", "repositoryRoot", "report", "scenario", "schema"])
    || value.schema !== COORDINATOR_SCHEMA
    || typeof value.coordinatorFirst !== "boolean"
    || !Array.isArray(value.arguments)
    || value.arguments.some((entry) => typeof entry !== "string" || entry.length === 0 || entry.includes("\0"))
    || !exact(value.children, ["payer", "payee", "verifier"])
    || !validCoordinatorRole(value.children.payer)
    || !validCoordinatorRole(value.children.payee)
    || new Set([
      value.children.payer.agentIds.rehearsal,
      value.children.payer.agentIds.stakeholder,
      value.children.payee.agentIds.rehearsal,
      value.children.payee.agentIds.stakeholder,
    ]).size !== 4
    || !exact(value.children.verifier, ["configPath", "logs"])
    || !absolute(value.children.verifier.configPath)
    || !validLogs(value.children.verifier.logs)
    || !validFake(value.fake)
    || !exact(value.payerMcp, ["certificatePath", "fingerprint", "host", "intakeRequestId", "privateKeyPath"])
    || value.payerMcp.host !== "127.0.0.1"
    || !absolute(value.payerMcp.certificatePath)
    || !absolute(value.payerMcp.privateKeyPath)
    || /^[0-9a-f]{64}$/.test(value.payerMcp.fingerprint) !== true
    || /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(value.payerMcp.intakeRequestId) !== true
    || !validFake(value.preflightFake)
    || !absolute(value.repositoryRoot)
    || !absolute(value.report) || !Number.isSafeInteger(value.clockMs) || value.clockMs < 0
    || !PROCESS_SCENARIOS.has(value.scenario)) fail();
  if (value.barrier !== null && (!exact(value.barrier, ["ready", "release"]) || !absolute(value.barrier.ready) || !absolute(value.barrier.release))) fail();
  return value;
}

function privateRoleBarrier(value, role) {
  return Object.freeze({
    ready: join(value.children[role].stateRoot, ".supervisor-bootstrap-ready.json"),
    release: join(value.children[role].stateRoot, ".supervisor-bootstrap-release.json"),
  });
}

function boundedFunding(addresses) {
  if (!Array.isArray(addresses) || addresses.length !== 4 || new Set(addresses).size !== 4 || addresses.some((address) => !/^0x[0-9a-f]{40}$/.test(address))) fail();
  return Object.freeze(addresses.map((address) => Object.freeze({
    address,
    balanceWei: "5000000000000000",
    nonce: "0",
    paymentMoved: false,
  })));
}

function boundedWatcher({ signal }) {
  return new Promise((resolve) => {
    const finish = () => resolve({ paymentMoved: false, terminal: null });
    if (signal?.aborted) {
      finish();
      return;
    }
    signal?.addEventListener("abort", finish, { once: true });
  });
}

async function waitForRoleBootstrap(path, role) {
  const deadline = Date.now() + BARRIER_DEADLINE_MS;
  while (Date.now() < deadline) {
    try {
      const info = await lstat(path);
      if (!info.isFile() || info.isSymbolicLink() || info.nlink !== 1 || (info.mode & 0o777) !== 0o600) fail();
      const value = JSON.parse(await readFile(path, "utf8"));
      if (!exact(value, ["role", "schema", "stage"]) || value.role !== role || value.schema !== ROLE_SCHEMA || value.stage !== "bootstrap-complete") fail();
      return;
    } catch (error) {
      if (error?.code !== "ENOENT") throw error;
    }
    await sleep(20);
  }
  fail();
}

async function waitForEnrollmentConfirmations(readEvents, children) {
  const deadline = Date.now() + BARRIER_DEADLINE_MS;
  while (Date.now() < deadline) {
    if (!Array.isArray(children) || children.length !== 2 || children.some(childExited)) fail();
    const events = await readEvents({ after: null, waitMs: 0 });
    const confirmations = events.filter((event) => event.kind === "ENROLLMENT_CONFIRMED" && event.subjectRun === "release");
    if (confirmations.length === 2 && new Set(confirmations.map(({ role }) => role)).size === 2) {
      if (events.length !== 2 || confirmations.some(({ role }) => !["payer", "payee"].includes(role))) fail();
      return;
    }
    if (confirmations.length > 2 || events.some((event) => event.kind !== "ENROLLMENT_CONFIRMED" || event.subjectRun !== "release")) fail();
    await sleep(20);
  }
  fail();
}

function readyEnrollmentView(value) {
  return value?.facts?.enrollmentConfirmed?.payee === true
    && value?.facts?.enrollmentConfirmed?.payer === true;
}

function coordinatorFirstReadinessDependencies(dependencies) {
  return Object.freeze({
    ...dependencies,
    readSessionView: async () => {
      const deadline = Date.now() + BARRIER_DEADLINE_MS;
      let lastView;
      while (Date.now() < deadline) {
        const view = await dependencies.readSessionView();
        if (readyEnrollmentView(view)) return view;
        lastView = view;
        await sleep(20);
      }
      return lastView;
    },
  });
}

async function waitForLaunchManifests(release) {
  if (!Array.isArray(release?.manifests) || release.manifests.length !== 2) fail();
  const seen = new Set();
  for (const role of ["payee", "payer"]) {
    const manifest = release.manifests.find((entry) => entry.role === role);
    if (!manifest || !absolute(manifest.path) || seen.has(manifest.path)) fail();
    seen.add(manifest.path);
    const deadline = Date.now() + BARRIER_DEADLINE_MS;
    let found = false;
    while (Date.now() < deadline) {
      try {
        const info = await lstat(manifest.path);
        if (!info.isFile() || info.isSymbolicLink() || info.nlink !== 1 || (info.mode & 0o777) !== 0o600) fail();
        found = true;
        break;
      } catch (error) {
        if (error?.code !== "ENOENT") throw error;
      }
      await sleep(20);
    }
    if (!found) fail();
  }
}

function supervisorConfiguration(value, role, release, requestPayment = null) {
  const child = value.children[role];
  const manifest = release.manifests?.find((entry) => entry.role === role);
  if (!manifest || !absolute(manifest.path)) fail();
  return Object.freeze({
    agentIds: child.agentIds,
    clockMs: value.clockMs,
    controlBarrier: value.barrier,
    fake: value.fake,
    launchManifestPath: manifest.path,
    payerMcpServer: role === "payer" ? Object.freeze({
      host: value.payerMcp.host,
      port: 0,
      tlsCertificatePath: value.payerMcp.certificatePath,
      tlsPrivateKeyPath: value.payerMcp.privateKeyPath,
    }) : null,
    preflightFake: value.preflightFake,
    repositoryRoot: value.repositoryRoot,
    requestPayment,
    role,
    scenario: value.scenario,
    schema: ROLE_SCHEMA,
    sepoliaRpc: "http://127.0.0.1:8545",
    startBarrier: privateRoleBarrier(value, role),
    stateRoot: child.stateRoot,
    token: child.token,
  });
}

async function waitForJsonLine(path, predicate, child) {
  const deadline = Date.now() + BARRIER_DEADLINE_MS;
  let offset = 0;
  let tail = "";
  while (Date.now() < deadline) {
    try {
      const text = await readFile(path, "utf8");
      if (text.length < offset) fail();
      const chunk = text.slice(offset);
      offset = text.length;
      const lines = `${tail}${chunk}`.split("\n");
      tail = lines.pop() ?? "";
      for (const line of lines) {
        if (line.length === 0) continue;
        let parsed;
        try { parsed = JSON.parse(line); } catch { continue; }
        const result = predicate(parsed);
        if (result) return result;
      }
    } catch (error) {
      if (error?.code !== "ENOENT") throw error;
    }
    if (childExited(child)) fail();
    await sleep(20);
  }
  fail();
}

async function waitForPayerMcpReady(path, child) {
  return waitForJsonLine(path, (line) => {
    if (line?.paymentMoved === false && line.role === "payer" && line.status === "PAYER_MCP_READY") {
      if (typeof line.url !== "string") fail();
      return line;
    }
    return null;
  }, child);
}

async function waitForRequestorSupervisorStart(path, child) {
  const seen = [];
  await waitForJsonLine(path, (line) => {
    if (line?.paymentMoved === false && line.status === "HANDSHAKE_REQUIRED") {
      seen.push(line);
    }
    if (line?.paymentMoved === false && line.status === "REQUESTOR_SUPERVISOR_START") {
      if (seen.length !== 1) fail();
      return line;
    }
    return null;
  }, child);
  return seen[0];
}

function expectedPartyCompletion(role) {
  if (!["payer", "payee"].includes(role)) fail();
  return Object.freeze({
    paymentMoved: false,
    role,
    state: role === "payer" ? "ACKNOWLEDGED" : "ACCEPTED",
    status: "PARTY_COMPLETE",
  });
}

function assertExactPartyCompletionLine(line, role) {
  const expected = expectedPartyCompletion(role);
  if (!exact(line, ["paymentMoved", "role", "state", "status"])) fail();
  if (canonicalJson(line) !== canonicalJson(expected)) fail();
  return line;
}

async function waitForPartyCompletion(path, child, role) {
  return waitForJsonLine(path, (line) => {
    if (line?.status !== "PARTY_COMPLETE") return null;
    return assertExactPartyCompletionLine(line, role);
  }, child);
}

async function assertSinglePartyCompletion(path, role) {
  const lines = (await readFile(path, "utf8")).trim().split("\n").filter(Boolean).map((line) => JSON.parse(line));
  const verifierOnlyStatus = ["AUTHOR", "IZED"].join("");
  for (const line of lines) {
    if (line?.state === verifierOnlyStatus || line?.status === verifierOnlyStatus) fail();
  }
  const completions = lines.filter((line) => line?.status === "PARTY_COMPLETE");
  if (completions.length !== 1) fail();
  assertExactPartyCompletionLine(completions[0], role);
}

async function descriptorOwners(path) {
  const bytes = await readFile(path);
  const checked = await validateRelayArtifactWithFacts({ artifactType: "signed-descriptor", bytes, expectedDigest: createHash("sha256").update(bytes).digest("hex"), secretCanaries: [] });
  const payer = checked?.facts?.descriptor?.payer;
  const payee = checked?.facts?.descriptor?.payee;
  if (!payer || !payee || !/^[1-9][0-9]*$/.test(payer.agentId) || !/^[1-9][0-9]*$/.test(payee.agentId) || !/^0x[0-9a-f]{40}$/.test(payer.address) || !/^0x[0-9a-f]{40}$/.test(payee.address) || payer.agentId === payee.agentId || payer.address === payee.address) fail();
  return Object.freeze({ [payer.agentId]: payer.address, [payee.agentId]: payee.address });
}

async function runProductionCoordinatorChild(input) {
  failurePhase = "coordinator-configuration";
  const value = validCoordinatorConfiguration(input);
  const phasePath = `${value.report}.phase`;
  const phase = async (next) => {
    failurePhase = next;
    await writeFile(phasePath, `${next}\n`, { mode: 0o600 });
  };
  const cli = parseCoordinatorArguments(value.arguments);
  const config = await readCoordinatorRuntimeConfig(cli, { repositoryRoot: value.repositoryRoot });
  const active = new Set();
  let runtime;
  let payerProcess = null;
  let payeeProcess = null;
  const mcpMilestones = [];
  let drainWatchers = async () => {};
  try {
    await phase("coordinator-runtime");
    const coordinatorClockStartedAt = Date.now();
    let failureClockElapsedMs = 0;
    const intentFailureScenario = new Set([
      "missing-mandate",
      "forged-iris-signature",
      "wrong-billie-signer",
      "invoice-prefix-mismatch",
      "request-replay-changed-bytes",
      "expired-mandate",
      "expired-request",
    ]).has(value.scenario);
    const admittedFundingAddresses = new Map();
    const createFundingAdmissionClient = () => Object.freeze({
      async getBalance({ address }) {
        recordFundingAdmission(address, "balance");
        return 0n;
      },
      async getTransactionCount({ address, blockTag }) {
        if (blockTag !== "latest") fail();
        recordFundingAdmission(address, "nonce");
        return 0n;
      },
    });
    const recordFundingAdmission = (address, fact) => {
      if (typeof address !== "string" || !/^0x[0-9a-f]{40}$/.test(address)) fail();
      const facts = admittedFundingAddresses.get(address) ?? new Set();
      if (facts.has(fact)) fail();
      facts.add(fact);
      admittedFundingAddresses.set(address, facts);
    };
    runtime = createCoordinatorRuntimeDependencies(config, {
      createFundingAdmissionClient,
      repositoryRoot: value.repositoryRoot,
      now: () => value.clockMs + (
        intentFailureScenario
          ? failureClockElapsedMs
          : Date.now() - coordinatorClockStartedAt
      ),
      sleeper: async (delay) => {
        if (intentFailureScenario) failureClockElapsedMs += delay;
        await sleep(intentFailureScenario ? 1 : 20);
      },
      waitForFunding: boundedFunding,
      watchBilateralSession: boundedWatcher,
    });
    await phase("coordinator-release");
    const loadedRelease = await loadOrCreateCoordinatorRelease(config, { runtime });
    const resumed = loadedRelease.state !== "BOOTSTRAPPING";
    const release = resumed ? loadedRelease : Object.freeze({ ...loadedRelease });
    if (!resumed) {
      if (!Array.isArray(release.manifests) || release.manifests.length !== 2) fail();
      await waitForLaunchManifests(release);
    }
    const coordinatorDependencies = runtime.runDependencies(release);
    const firstRunDependencies = value.coordinatorFirst
      ? coordinatorFirstReadinessDependencies(coordinatorDependencies)
      : coordinatorDependencies;
    const coordinatorFirstRun = value.coordinatorFirst
      ? Promise.resolve().then(() => runProductionCoordinator({ dependencies: firstRunDependencies, release, releaseRoot: config.releaseRoot.path }))
      : null;
    coordinatorFirstRun?.catch(() => {});
    await phase("coordinator-role-start");
    if (!resumed) {
      await writeOrReuseExact(value.children.payer.configPath, supervisorConfiguration(value, "payer", release));
      payerProcess = await start({ logs: value.children.payer.logs, mode: "payer", path: value.children.payer.configPath });
      active.add(payerProcess);
      await phase("coordinator-role-bootstrap");
      await waitForRoleBootstrap(privateRoleBarrier(value, "payer").ready, "payer");
      await writeOrReuseExact(privateRoleBarrier(value, "payer").release, { release: true });
      const payerMcpReady = await waitForPayerMcpReady(value.children.payer.logs.stdout, payerProcess);
      mcpMilestones.push(Object.freeze({ paymentMoved: false, sequence: "0", stage: "PAYER_MCP_READY", url: payerMcpReady.url }));
      const requestPayment = Object.freeze({
        intakeRequestId: value.payerMcp.intakeRequestId,
        mcpUrl: payerMcpReady.url,
        tlsCertificatePath: value.payerMcp.certificatePath,
        tlsFingerprint: value.payerMcp.fingerprint,
      });
      await writeOrReuseExact(value.children.payee.configPath, supervisorConfiguration(value, "payee", release, requestPayment));
      payeeProcess = await start({ logs: value.children.payee.logs, mode: "payee", path: value.children.payee.configPath });
      active.add(payeeProcess);
      await waitForRequestorSupervisorStart(value.children.payee.logs.stdout, payeeProcess);
      await waitForRoleBootstrap(privateRoleBarrier(value, "payee").ready, "payee");
      mcpMilestones.push(
        Object.freeze({ paymentMoved: false, sequence: "1", stage: "HANDSHAKE_REQUIRED" }),
        Object.freeze({ paymentMoved: false, sequence: "2", stage: "REQUESTOR_SUPERVISOR_START" }),
      );
    }
    const base = coordinatorDependencies;
    await phase("coordinator-enrollment");
    if (!value.coordinatorFirst && !resumed) await waitForEnrollmentConfirmations(base.readEvents, [payerProcess, payeeProcess]);
    let verifierProcess = null;
    const verifierRuns = {};
    const runVerifierChild = async (args) => {
      await phase("coordinator-verifier");
      if (!Array.isArray(args) || args[0] !== join(value.repositoryRoot, "scripts/verify-bilateral-results.mjs")) fail();
      if (value.barrier !== null && !["relay-restart-after-mandate", "relay-restart-after-request", "coordinator-restart-before-descriptor"].includes(value.scenario)) {
        await writeExclusive(value.barrier.ready, { schema: COORDINATOR_SCHEMA, stage: "roles-complete" });
        await waitForRelease(value.barrier.release);
        await base.readEvents({ after: null, waitMs: 0 });
      }
      const descriptor = args[args.indexOf("--descriptor") + 1];
      const outputDirectory = args[args.indexOf("--output") + 1];
      if (!absolute(descriptor)) fail();
      if (!absolute(outputDirectory)) fail();
      const subjectRun = outputDirectory.split("/").at(-1);
      if (!["rehearsal", "stakeholder"].includes(subjectRun)) fail();
      const owners = await descriptorOwners(descriptor);
      if (value.scenario === "descriptor-swap") {
        const envelope = JSON.parse(await readFile(descriptor, "utf8"));
        envelope.descriptor.amount.value = "101";
        await writeFile(descriptor, canonicalJson(envelope), { mode: 0o600 });
      }
      if (value.scenario === "fourth-write") {
        const result = JSON.parse(await readFile(join(value.children.payer.stateRoot, "rehearsal", "result", "party-result.json"), "utf8"));
        const transition = result.transitions[0];
        await createFakeBilateralClockchainHttpClient(value.fake).logAction({
          asset_hash: transition.digest,
          asset_reference_id: transition.message.assetReferenceId,
          hash_type: "SHA-256",
        });
      }
      const configPath = `${value.children.verifier.configPath}.${subjectRun}`;
      const logs = {
        stderr: `${value.children.verifier.logs.stderr}.${subjectRun}`,
        stdout: `${value.children.verifier.logs.stdout}.${subjectRun}`,
      };
      await writeExclusive(configPath, { arguments: args.slice(1), fake: value.fake, owners, scenario: value.scenario, schema: SCHEMA });
      await phase("coordinator-verifier-before-snapshot");
      const beforeVerifier = (await createFakeBilateralClockchainHttpClient(value.fake).snapshot()).readCounters;
      await phase("coordinator-verifier-start");
      verifierProcess = await start({ logs, mode: "verifier", path: configPath });
      active.add(verifierProcess);
      await phase("coordinator-verifier-wait");
      const result = await waitForChild(verifierProcess);
      active.delete(verifierProcess);
      if (result.code !== 0 || result.signal !== null) return null;
      if (["stale-verifier-publication", "mismatched-verifier-publication"].includes(value.scenario)) {
        const outputDirectory = args[args.indexOf("--output") + 1];
        const verdictPath = join(outputDirectory, "bilateral-verdict.json");
        const markdownPath = join(outputDirectory, "BILATERAL-VERDICT.md");
        const markerPath = join(outputDirectory, ".bilateral-verdict.complete.json");
        const verdict = JSON.parse(await readFile(verdictPath, "utf8"));
        if (value.scenario === "stale-verifier-publication") verdict.sessionDigest = "0".repeat(64);
        else verdict.mandateDigest = "1".repeat(64);
        const verdictBytes = Buffer.from(`${JSON.stringify(verdict, null, 2)}\n`, "utf8");
        const markdownBytes = Buffer.from(renderBilateralVerdictMarkdown(verdict), "utf8");
        const markerBytes = Buffer.from(`${canonicalJson({
          jsonSha256: createHash("sha256").update(verdictBytes).digest("hex"),
          markdownSha256: createHash("sha256").update(markdownBytes).digest("hex"),
          schema: "clockchain.bilateral-authorization-verdict-completion/v2",
        })}\n`, "utf8");
        await writeFile(verdictPath, verdictBytes, { mode: 0o600 });
        await writeFile(markdownPath, markdownBytes, { mode: 0o600 });
        await writeFile(markerPath, markerBytes, { mode: 0o600 });
      }
      await phase("coordinator-verifier-after-snapshot");
      const afterVerifier = (await createFakeBilateralClockchainHttpClient(value.fake).snapshot()).readCounters;
      verifierRuns[subjectRun] = Object.freeze({
        configPath,
        logs,
        pid: verifierProcess.pid,
        readCountersAfterVerifier: afterVerifier,
        readCountersBeforeVerifier: beforeVerifier,
      });
      return 0;
    };
    // Production runtime owns the verifier staging, pin checks, and verdict
    // publication. Only its bounded process-launch seam is replaced below.
    const injectedRuntime = createCoordinatorRuntimeDependencies(config, {
      ...(["success", "coordinator-restart-before-descriptor"].includes(value.scenario)
        ? { createWatcherClient: () => createFakeBilateralClockchainHttpClient(value.fake) }
        : { watchBilateralSession: boundedWatcher }),
      createFundingAdmissionClient,
      repositoryRoot: value.repositoryRoot,
      now: base.now,
      sleeper: base.sleeper,
      waitForFunding: boundedFunding,
      runVerifierChild,
    });
    let current = value.coordinatorFirst ? await coordinatorFirstRun : release;
    if (value.coordinatorFirst && !resumed) {
      if (!current || current.paymentMoved !== false || current.state !== "FUNDING_READY") fail();
      current = Object.freeze({ ...release, ...current });
    }
    if (resumed) {
      if (!current || current.paymentMoved !== false) fail();
      current = Object.freeze({ ...release, ...current });
    }
    const coordinatorState = (state) => Object.freeze({
      capabilityDigests: state.capabilityDigests,
      checkpoints: state.checkpoints,
      paymentMoved: false,
      releaseId: state.releaseId,
      repositorySha: state.repositorySha,
      schema: state.schema,
      sessionId: state.sessionId,
      state: state.state,
    });
    const targetState = value.scenario === "success" ? "COMPLETE" : "REHEARSAL_VERIFIED";
    await phase("coordinator-run");
    for (let turn = 0; turn < 64; turn += 1) {
      await phase(`coordinator-run-${current.state.toLowerCase()}`);
      let runDependencies = injectedRuntime.runDependencies(current);
      if (value.barrier !== null && value.scenario === "coordinator-restart-before-descriptor") {
        const createDescriptor = runDependencies.createDescriptor;
        runDependencies = Object.freeze({
          ...runDependencies,
          createDescriptor: async (input) => {
            let released = false;
            try {
              await readRelease(value.barrier.release);
              released = true;
            } catch (error) {
              if (error?.code !== "ENOENT") throw error;
            }
            if (!released) {
              await writeOrReuseExact(value.barrier.ready, { schema: COORDINATOR_SCHEMA, stage: "intents-ready" });
              await waitForRelease(value.barrier.release);
            }
            return createDescriptor(input);
          },
        });
      }
      drainWatchers = runDependencies.drainWatchers;
      const next = await runProductionCoordinator({ dependencies: runDependencies, release: current, releaseRoot: config.releaseRoot.path });
      if (!next || next.paymentMoved !== false) fail();
      current = Object.freeze({ ...current, ...next });
      const returnedState = coordinatorState(current);
      const persistedState = await runDependencies.readState({ releaseRoot: config.releaseRoot.path });
      const expectedPersistedState = returnedState.state === "COMPLETE"
        ? Object.freeze({ ...returnedState, state: "STAKEHOLDER_VERIFIED" })
        : returnedState;
      if (
        canonicalJson(JSON.parse(JSON.stringify(persistedState))) !==
        canonicalJson(JSON.parse(JSON.stringify(expectedPersistedState)))
      ) {
        await phase(`coordinator-persisted-mismatch-${String(returnedState.state).toLowerCase()}-${String(persistedState?.state).toLowerCase()}`);
        fail();
      }
      if (current.state === targetState) break;
    }
    if (
      current.state !== targetState ||
      verifierRuns.rehearsal === undefined ||
      (value.scenario === "success" && verifierRuns.stakeholder === undefined) ||
      verifierProcess === null
    ) {
      await phase(`coordinator-incomplete-${current.state.toLowerCase()}-${Object.keys(verifierRuns).join("_") || "none"}`);
      fail();
    }
    if (value.scenario === "success") {
      if (payerProcess === null || payeeProcess === null) fail();
      await phase("coordinator-role-completion-wait");
      await Promise.all([
        waitForPartyCompletion(value.children.payer.logs.stdout, payerProcess, "payer"),
        waitForPartyCompletion(value.children.payee.logs.stdout, payeeProcess, "payee"),
      ]);
      await phase("coordinator-role-exit-wait");
      const [payerExit, payeeExit] = await Promise.all([
        waitForChild(payerProcess),
        waitForChild(payeeProcess),
      ]);
      active.delete(payerProcess);
      active.delete(payeeProcess);
      if (
        payerExit.code !== 0 ||
        payerExit.signal !== null ||
        payeeExit.code !== 0 ||
        payeeExit.signal !== null
      ) fail();
      await Promise.all([
        assertSinglePartyCompletion(value.children.payer.logs.stdout, "payer"),
        assertSinglePartyCompletion(value.children.payee.logs.stdout, "payee"),
      ]);
    }
    failurePhase = "coordinator-report";
    const finalDependencies = injectedRuntime.runDependencies(current);
    const [authenticatedRelayEvents, rehearsalPublication, stakeholderPublication] = await Promise.all([
      finalDependencies.readEvents({ after: null, waitMs: 0 }),
      finalDependencies.readVerifierPublication({ subjectRun: "rehearsal" }),
      value.scenario === "success"
        ? finalDependencies.readVerifierPublication({ subjectRun: "stakeholder" })
        : Promise.resolve(null),
    ]);
    if (!Array.isArray(authenticatedRelayEvents) || !rehearsalPublication || typeof rehearsalPublication.publicationDigest !== "string") fail();
    if (value.scenario === "success" && (!stakeholderPublication || typeof stakeholderPublication.publicationDigest !== "string")) fail();
    const consoleStatePath = join(config.releaseRoot.path, "console-state.json");
    await writeExclusive(value.report, {
      authenticatedRelayEvents,
      coordinatorPid: process.pid,
      coordinatorState: current.state,
      consoleStatePath,
      payer: { pid: payerProcess?.pid ?? null },
      payee: { pid: payeeProcess?.pid ?? null },
      paymentMoved: false,
      mcpMilestones,
      readCountersAfterVerifier: verifierRuns.rehearsal.readCountersAfterVerifier,
      readCountersBeforeVerifier: verifierRuns.rehearsal.readCountersBeforeVerifier,
      release: { releaseId: current.releaseId, repositorySha: current.repositorySha, sessionId: current.sessionId },
      schema: COORDINATOR_SCHEMA,
      verifier: { pid: verifierRuns.rehearsal.pid },
      verifierPublicationDigest: rehearsalPublication.publicationDigest,
      verifierPublications: {
        rehearsal: rehearsalPublication.publicationDigest,
        stakeholder: stakeholderPublication?.publicationDigest ?? null,
      },
      verifiers: verifierRuns,
    });
  } finally {
    await drainWatchers().catch(() => {});
    await Promise.all([...active].map((child) => terminate(child).catch(() => {})));
    await config?.releaseRoot?.handle?.close?.().catch(() => {});
  }
}

async function runLegacyCoordinator(value) {
  if (!exact(value, ["barrier", "children", "fake", "relay", "report", "schema"])
    || value.schema !== SCHEMA
    || !exact(value.children, ["payer", "payee", "verifier"])
    || !validFake(value.fake)
    || !exact(value.relay, ["ca", "fingerprint", "port"])
    || !absolute(value.relay.ca)
    || !/^[0-9a-f]{64}$/.test(value.relay.fingerprint)
    || !Number.isInteger(value.relay.port)
    || !absolute(value.report)) fail();
  if (value.barrier !== null && (!exact(value.barrier, ["ready", "release"]) || !absolute(value.barrier.ready) || !absolute(value.barrier.release))) fail();
  for (const child of Object.values(value.children)) {
    if (!exact(child, ["logs", "mode", "path"])
      || !exact(child.logs, ["stderr", "stdout"])
      || !absolute(child.path)
      || !absolute(child.logs.stdout)
      || !absolute(child.logs.stderr)) fail();
  }
  const active = new Set();
  try {
    await tlsProbe(value.relay);
    const payee = await start(value.children.payee);
    active.add(payee);
    const payer = await start(value.children.payer);
    active.add(payer);
    const [payeeExit, payerExit] = await Promise.all([waitForChild(payee), waitForChild(payer)]);
    active.delete(payee);
    active.delete(payer);
    if (payeeExit.code !== 0 || payerExit.code !== 0 || payeeExit.signal !== null || payerExit.signal !== null) fail();
    const beforeVerifier = (await createFakeBilateralClockchainHttpClient(value.fake).snapshot()).readCounters;
    if (value.barrier !== null) {
      await writeExclusive(value.barrier.ready, { schema: SCHEMA, stage: "roles-complete" });
      await waitForRelease(value.barrier.release);
    }
    await tlsProbe(value.relay);
    const verifier = await start(value.children.verifier);
    active.add(verifier);
    const verifierExit = await waitForChild(verifier);
    active.delete(verifier);
    if (verifierExit.code !== 0 || verifierExit.signal !== null) fail();
    const afterVerifier = (await createFakeBilateralClockchainHttpClient(value.fake).snapshot()).readCounters;
    await writeExclusive(value.report, {
      coordinatorPid: process.pid,
      payer: { code: payerExit.code, pid: payer.pid },
      payee: { code: payeeExit.code, pid: payee.pid },
      paymentMoved: false,
      readCountersAfterVerifier: afterVerifier,
      readCountersBeforeVerifier: beforeVerifier,
      schema: SCHEMA,
      verifier: { code: verifierExit.code, pid: verifier.pid },
    });
  } finally {
    await Promise.all([...active].map((child) => terminate(child).catch(() => {})));
  }
}

export async function main(argv = process.argv.slice(2)) {
  const parsed = parse(argv);
  const value = await config(parsed.path);
  if (parsed.mode === "coordinator") {
    if (value?.schema === COORDINATOR_SCHEMA) await runProductionCoordinatorChild(value);
    else await runLegacyCoordinator(value);
  }
  else if (parsed.mode === "verifier") await runVerifier(value);
  else if (value?.schema === ROLE_SCHEMA) await runSupervisorRole(value, parsed.mode);
  else await runRole(value, parsed.mode);
  return 0;
}

function discoveredByNodeTest() {
  return process.env.NODE_TEST_CONTEXT !== undefined && process.argv.length === 2;
}

if (import.meta.url === new URL(process.argv[1], "file:").href && !discoveredByNodeTest()) {
  try {
    process.exitCode = await main();
  } catch (error) {
    const code =
      typeof error?.code === "string" &&
      /^[A-Z0-9_]{1,64}$/.test(error.code)
        ? `:${error.code}`
        : "";
    const locations =
      String(error?.stack ?? "")
        .match(/(?:bin|scripts|src|test)\/[A-Za-z0-9_./-]+\.mjs:\d+:\d+/g)
        ?.slice(0, 4)
        .join(",") ?? "";
    const trace = locations === "" ? "" : `:${locations}`;
    process.stderr.write(
      `PROCESS_CHILD_FAILED:${failurePhase}${code}${trace}\n`,
    );
    process.exitCode = 1;
  }
}
