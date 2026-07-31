#!/usr/bin/env node

import {
  createHash,
  timingSafeEqual,
} from "node:crypto";
import {
  constants,
} from "node:fs";
import {
  chmod,
  mkdir,
  open,
  readFile,
  rename,
  rm,
} from "node:fs/promises";
import { createServer } from "node:http";
import { isAbsolute, join } from "node:path";
import { spawn } from "node:child_process";
import { connect } from "node:tls";
import { pathToFileURL } from "node:url";

import {
  renderRestrictedAuthorizedKey,
  tombstoneTunnelGrant,
  validateTunnelGrantRecord,
} from "../src/bilateral/aws/tunnel-grant.mjs";

const ACTIVE_SCHEMA =
  "clockchain.payer-tunnel-grant/v1";
const TOMBSTONE_SCHEMA =
  "clockchain.payer-tunnel-tombstone/v1";
const HEALTHY = Object.freeze({
  paymentMoved: false,
  status: "READY",
});
const UNHEALTHY = Object.freeze({
  paymentMoved: false,
  status: "UNHEALTHY",
});
const SHA256 = /^[0-9a-f]{64}$/;
const ABORT_MARKER_SCHEMA =
  "clockchain.aws-operator-abort-marker/v1";

export class AwsTunnelServiceError extends Error {
  constructor() {
    super("AWS tunnel service failed safely.");
    this.name = "AwsTunnelServiceError";
    this.code = "AWS_TUNNEL_SERVICE_FAILED";
    this.category = "verification";
  }
}

function fail() {
  throw new AwsTunnelServiceError();
}

function fixedLog(logger, status) {
  try {
    logger.info({
      paymentMoved: false,
      status,
    });
  } catch {
    fail();
  }
}

async function atomicWrite(path, body) {
  const temporary = `${path}.next`;
  let handle;
  try {
    handle = await open(
      temporary,
      constants.O_WRONLY |
        constants.O_CREAT |
        constants.O_EXCL,
      0o600,
    );
    await handle.writeFile(body, "utf8");
    await handle.sync();
    await handle.close();
    handle = undefined;
    await rename(temporary, path);
    await chmod(path, 0o600);
  } catch {
    await handle?.close().catch(() => {});
    await rm(temporary, { force: true }).catch(
      () => {},
    );
    fail();
  }
}

function defaultProcessController({
  configPath =
    "/etc/ssh/clockchain_sshd_config",
} = {}) {
  let child;
  return {
    async reload() {
      if (
        child === undefined ||
        child.exitCode !== null
      ) {
        fail();
      }
      child.kill("SIGHUP");
    },
    async start({ authorizedKeysPath, port }) {
      if (
        child !== undefined ||
        port !== 2222 ||
        typeof authorizedKeysPath !== "string"
      ) {
        fail();
      }
      child = spawn(
        "/usr/sbin/sshd",
        [
          "-D",
          "-e",
          "-f",
          configPath,
          "-o",
          `AuthorizedKeysFile=${authorizedKeysPath}`,
          "-p",
          "2222",
        ],
        {
          stdio: "ignore",
        },
      );
      child.once("error", () => {});
    },
    async stop() {
      if (
        child !== undefined &&
        child.exitCode === null
      ) {
        child.kill("SIGTERM");
      }
      child = undefined;
    },
  };
}

export async function probeTunnelTls({
  expectedFingerprint,
  host,
  port,
  timeoutMs = 5_000,
}) {
  if (
    !SHA256.test(expectedFingerprint) ||
    host !== "127.0.0.1" ||
    port !== 9443 ||
    !Number.isSafeInteger(timeoutMs) ||
    timeoutMs < 100 ||
    timeoutMs > 30_000
  ) {
    fail();
  }
  return new Promise((resolve) => {
    let settled = false;
    const finish = (result, socket) => {
      if (settled) return;
      settled = true;
      socket?.destroy();
      resolve(result);
    };
    const socket = connect({
      host,
      port,
      rejectUnauthorized: false,
      servername: undefined,
    });
    socket.setTimeout(timeoutMs);
    socket.once("secureConnect", () => {
      try {
        const raw =
          socket.getPeerCertificate(true)?.raw;
        if (!Buffer.isBuffer(raw)) {
          finish(false, socket);
          return;
        }
        const actual = createHash("sha256")
          .update(raw)
          .digest();
        const expected = Buffer.from(
          expectedFingerprint,
          "hex",
        );
        finish(
          actual.length === expected.length &&
            timingSafeEqual(actual, expected),
          socket,
        );
      } catch {
        finish(false, socket);
      }
    });
    socket.once("timeout", () =>
      finish(false, socket));
    socket.once("error", () =>
      finish(false, socket));
    socket.once("close", () =>
      finish(false, socket));
  });
}

function healthServer({ host, port, readHealth }) {
  const server = createServer((request, response) => {
    if (
      request.method !== "GET" ||
      request.url !== "/"
    ) {
      response.writeHead(404, {
        "cache-control": "no-store",
        "content-type": "application/json",
      });
      response.end(
        '{"paymentMoved":false,"status":"NOT_FOUND"}\n',
      );
      return;
    }
    const health = readHealth();
    response.writeHead(
      health.status === "READY" ? 200 : 503,
      {
        "cache-control": "no-store",
        "content-type": "application/json",
      },
    );
    response.end(`${JSON.stringify(health)}\n`);
  });
  return {
    get url() {
      const address = server.address();
      if (
        address === null ||
        typeof address === "string"
      ) {
        fail();
      }
      return `http://${host}:${address.port}/`;
    },
    async start() {
      await new Promise((resolve, reject) => {
        server.once("error", reject);
        server.listen(port, host, resolve);
      });
    },
    async stop() {
      if (!server.listening) return;
      await new Promise((resolve, reject) =>
        server.close((error) =>
          error === undefined
            ? resolve()
            : reject(error)));
    },
  };
}

export function createAwsTunnelService({
  healthHost = "0.0.0.0",
  healthPort = 8080,
  logger = console,
  nowMs = Date.now,
  probePinnedTls = probeTunnelTls,
  processController =
    defaultProcessController(),
  readGrant,
  readAbortMarker = async () => null,
  stateRoot,
  tombstoneGrant = tombstoneTunnelGrant,
  validateGrant = validateTunnelGrantRecord,
  writeTombstone,
} = {}) {
  if (
    typeof stateRoot !== "string" ||
    !isAbsolute(stateRoot) ||
    stateRoot.includes("\0") ||
    typeof healthHost !== "string" ||
    !Number.isSafeInteger(healthPort) ||
    healthPort < 0 ||
    healthPort > 65_535 ||
    typeof logger?.info !== "function" ||
    typeof nowMs !== "function" ||
    typeof probePinnedTls !== "function" ||
    typeof processController?.start !==
      "function" ||
    typeof processController?.reload !==
      "function" ||
    typeof processController?.stop !==
      "function" ||
    typeof readGrant !== "function" ||
    typeof readAbortMarker !== "function" ||
    typeof tombstoneGrant !== "function" ||
    typeof validateGrant !== "function" ||
    typeof writeTombstone !== "function"
  ) {
    fail();
  }
  const authorizedKeysPath = join(
    stateRoot,
    "authorized_keys",
  );
  let currentHealth = UNHEALTHY;
  let activeGrant = null;
  let processStarted = false;
  let stopped = false;
  const listener = healthServer({
    host: healthHost,
    port: healthPort,
    readHealth: () => currentHealth,
  });

  async function stopProcess() {
    currentHealth = UNHEALTHY;
    if (processStarted) {
      await processController.stop();
      processStarted = false;
    }
    await rm(authorizedKeysPath, {
      force: true,
    });
    activeGrant = null;
  }

  async function install(grant) {
    const line = renderRestrictedAuthorizedKey({
      sshPublicKey: grant.claim.sshPublicKey,
    });
    await atomicWrite(
      authorizedKeysPath,
      `${line}\n`,
    );
  }

  async function reconcile() {
    try {
      currentHealth = UNHEALTHY;
      const abortMarker = await readAbortMarker();
      if (abortMarker !== null) {
        if (
          abortMarker === null ||
          typeof abortMarker !== "object" ||
          Array.isArray(abortMarker) ||
          abortMarker.schema !==
            ABORT_MARKER_SCHEMA ||
          abortMarker.paymentMoved !== false ||
          abortMarker.status !== "ABORTED"
        ) {
          fail();
        }
        await stopProcess();
        fixedLog(logger, "ABORTED");
        return UNHEALTHY;
      }
      const grant = validateGrant(
        await readGrant(),
      );
      if (grant.schema === TOMBSTONE_SCHEMA) {
        await stopProcess();
        fixedLog(logger, "TOMBSTONED");
        return UNHEALTHY;
      }
      if (
        grant.schema !== ACTIVE_SCHEMA ||
        grant.paymentMoved !== false
      ) {
        fail();
      }
      const currentNow = nowMs();
      if (
        !Number.isSafeInteger(currentNow) ||
        currentNow < 0
      ) {
        fail();
      }
      if (
        currentNow >= Number(grant.expiresAtMs)
      ) {
        const tombstone = tombstoneGrant({
          activeGrant: grant,
          nowMs: currentNow,
          reason: "EXPIRED",
        });
        await writeTombstone(tombstone);
        await stopProcess();
        fixedLog(logger, "EXPIRED");
        return UNHEALTHY;
      }

      const reconnect =
        activeGrant !== null &&
        grant.claimFingerprint ===
          activeGrant.claimFingerprint &&
        grant.claim.sshPublicKey ===
          activeGrant.claim.sshPublicKey &&
        grant.connectionSequence !==
          activeGrant.connectionSequence;
      const changed =
        activeGrant === null ||
        grant.claimFingerprint !==
          activeGrant.claimFingerprint ||
        grant.claim.sshPublicKey !==
          activeGrant.claim.sshPublicKey;
      if (
        activeGrant !== null &&
        changed
      ) {
        fail();
      }
      if (changed) {
        await install(grant);
      }
      if (!processStarted) {
        await processController.start({
          authorizedKeysPath,
          port: 2222,
        });
        processStarted = true;
      } else if (reconnect) {
        await install(grant);
        await processController.reload();
      }
      activeGrant = grant;
      if (
        grant.connectionStatus !==
        "CONNECTED"
      ) {
        fixedLog(logger, "WAITING");
        return UNHEALTHY;
      }
      const ready = await probePinnedTls({
        expectedFingerprint:
          grant.claim.mcpTlsFingerprint,
        host: "127.0.0.1",
        port: 9443,
      });
      if (ready !== true) {
        fixedLog(logger, "UNHEALTHY");
        return UNHEALTHY;
      }
      currentHealth = HEALTHY;
      fixedLog(logger, "READY");
      return HEALTHY;
    } catch (error) {
      currentHealth = UNHEALTHY;
      if (
        error instanceof AwsTunnelServiceError
      ) {
        throw error;
      }
      fail();
    }
  }

  return Object.freeze({
    get healthUrl() {
      return listener.url;
    },
    health() {
      return currentHealth;
    },
    reconcile,
    async start() {
      if (stopped) fail();
      await mkdir(stateRoot, {
        mode: 0o700,
        recursive: true,
      });
      await listener.start();
      try {
        await reconcile();
      } catch (error) {
        await listener.stop().catch(() => {});
        throw error;
      }
      return Object.freeze({
        paymentMoved: false,
        status: "RUNNING",
      });
    },
    async stop() {
      if (stopped) return;
      stopped = true;
      await stopProcess();
      await listener.stop();
      fixedLog(logger, "STOPPED");
    },
    async terminate(reason) {
      if (
        !["ABORT", "FAILURE", "SUCCESS"].includes(
          reason,
        ) ||
        activeGrant === null
      ) {
        fail();
      }
      const tombstone = tombstoneGrant({
        activeGrant,
        nowMs: nowMs(),
        reason,
      });
      await writeTombstone(tombstone);
      await stopProcess();
      fixedLog(logger, "TOMBSTONED");
      return tombstone;
    },
  });
}

async function readJson(path) {
  const bytes = await readFile(path);
  if (bytes.length > 1024 * 1024) fail();
  return JSON.parse(bytes.toString("utf8"));
}

async function readOptionalJson(path) {
  try {
    return await readJson(path);
  } catch (error) {
    if (error?.code === "ENOENT") {
      return null;
    }
    throw error;
  }
}

function required(env, key) {
  const value = env[key];
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    value.trim() !== value
  ) {
    fail();
  }
  return value;
}

export async function main(env = process.env) {
  const grantPath = required(
    env,
    "AWS_TUNNEL_GRANT_PATH",
  );
  const abortMarkerPath = required(
    env,
    "AWS_TUNNEL_ABORT_MARKER_PATH",
  );
  const service = createAwsTunnelService({
    readAbortMarker: () =>
      readOptionalJson(abortMarkerPath),
    readGrant: () => readJson(grantPath),
    stateRoot: required(
      env,
      "AWS_TUNNEL_STATE_ROOT",
    ),
    writeTombstone: (value) =>
      atomicWrite(
        grantPath,
        `${JSON.stringify(value)}\n`,
      ),
  });
  await service.start();
  const interval = setInterval(() => {
    void service.reconcile().catch(() => {});
  }, 1_000);
  const stop = async () => {
    clearInterval(interval);
    await service.stop();
  };
  process.once("SIGINT", () => {
    void stop();
  });
  process.once("SIGTERM", () => {
    void stop();
  });
}

if (
  process.argv[1] !== undefined &&
  import.meta.url ===
    pathToFileURL(process.argv[1]).href
) {
  main().catch(() => {
    process.stderr.write(
      "AWS_TUNNEL_SERVICE_FAILED\n",
    );
    process.exitCode = 1;
  });
}
