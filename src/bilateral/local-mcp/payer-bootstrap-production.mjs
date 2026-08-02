import {
  execFile as execFileCallback,
  spawn,
} from "node:child_process";
import {
  constants as fsConstants,
  closeSync,
  fsyncSync,
  openSync,
  unlinkSync,
  writeSync,
} from "node:fs";
import {
  chmod,
  lstat,
  readFile,
} from "node:fs/promises";
import {
  createHash,
  createPublicKey,
  randomBytes,
  randomUUID,
  X509Certificate,
} from "node:crypto";
import https from "node:https";
import { createInterface } from "node:readline";
import {
  dirname,
  join,
  resolve,
} from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";

import {
  createResolvedLookup,
  resolvePublicEndpoint,
  validatePublicEndpoint,
} from "../network-endpoint.mjs";
import {
  preparePrivateDirectory,
  writePrivateFile,
} from "../private-path.mjs";
import {
  inspectParticipantPrerequisites,
} from "../platform-tools.mjs";
import {
  parsePayerBootstrapDiscoveryWire,
  verifySignedPayerBootstrapDiscovery,
} from "../../../scripts/publish-payer-bootstrap-discovery.mjs";
import {
  createPayerBootstrapKey,
  openSignedPayerBootstrapPackage,
  payerBootstrapClaimFingerprint,
  sshEd25519Fingerprint,
} from "./payer-bootstrap-envelope.mjs";
import {
  runPayerBootstrap,
} from "./payer-bootstrap.mjs";

export {
  runPayerBootstrap,
};

const execFileAsync = promisify(execFileCallback);
const REPOSITORY_ROOT = resolve(
  fileURLToPath(new URL("../../../", import.meta.url)),
);
const GIT_PREFIX = Object.freeze([
  "--no-pager",
  "--no-replace-objects",
  "-c",
  "core.attributesFile=/dev/null",
  "-c",
  "core.excludesFile=/dev/null",
  "-c",
  "core.fsmonitor=false",
  "-c",
  "core.hooksPath=/dev/null",
  "-c",
  "core.untrackedCache=false",
  "-C",
]);
const MAX_HTTP_BYTES = 262_144;
const POLL_INTERVAL_MS = 2_000;
const MAX_POLL_MS = 1_800_000;
const MCP_CERTIFICATE_COMMON_NAME =
  "clockchain-payer-mcp";
const ED25519_SPKI_PREFIX = Buffer.from(
  "302a300506032b6570032100",
  "hex",
);

function fail() {
  throw failure();
}

function failure() {
  return new Error(
    "Payer production bootstrap failed safely.",
  );
}

function gitEnvironment() {
  const nullDevice =
    process.platform === "win32" ? "NUL" : "/dev/null";
  const environment = Object.assign(
    Object.create(null),
    {
      GIT_ATTR_NOSYSTEM: "1",
      GIT_CONFIG_GLOBAL: nullDevice,
      GIT_CONFIG_NOSYSTEM: "1",
      GIT_CONFIG_SYSTEM: nullDevice,
      GIT_NO_REPLACE_OBJECTS: "1",
      GIT_OPTIONAL_LOCKS: "0",
      GIT_TERMINAL_PROMPT: "0",
      LANG: "C",
      LC_ALL: "C",
    },
  );
  for (const name of [
    "COMSPEC",
    "HOMEDRIVE",
    "HOMEPATH",
    "PATH",
    "PATHEXT",
    "SystemRoot",
    "SYSTEMROOT",
    "TEMP",
    "TMP",
    "USERPROFILE",
  ]) {
    if (typeof process.env[name] === "string") {
      environment[name] = process.env[name];
    }
  }
  return environment;
}

function childEnvironment() {
  const environment = Object.assign(
    Object.create(null),
    {
      LANG: "C",
      LC_ALL: "C",
      OPENSSL_CONF:
        process.platform === "win32"
          ? "NUL"
          : "/dev/null",
    },
  );
  for (const name of [
    "COMSPEC",
    "PATH",
    "PATHEXT",
    "SystemRoot",
    "SYSTEMROOT",
    "TEMP",
    "TMP",
  ]) {
    if (typeof process.env[name] === "string") {
      environment[name] = process.env[name];
    }
  }
  return environment;
}

async function inspectRepository(gitCommand) {
  const run = (arguments_) =>
    execFileAsync(
      gitCommand,
      [...GIT_PREFIX, REPOSITORY_ROOT, ...arguments_],
      {
        cwd: REPOSITORY_ROOT,
        encoding: "utf8",
        env: gitEnvironment(),
        maxBuffer: 8192,
        windowsHide: true,
      },
    );
  const { stdout: head } = await run([
    "rev-parse",
    "--verify",
    "HEAD^{commit}",
  ]);
  const { stdout: status } = await run([
    "status",
    "--porcelain=v1",
    "--untracked-files=all",
    "--ignore-submodules=none",
  ]);
  let detached = false;
  try {
    await run(["symbolic-ref", "-q", "HEAD"]);
  } catch (error) {
    detached = error?.code === 1;
  }
  const repositorySha = head.trim();
  if (!/^[0-9a-f]{40}$/.test(repositorySha)) fail();
  return Object.freeze({
    clean: status === "",
    detached,
    repositorySha,
  });
}

async function reviewedOperatorPublicKey(
  gitCommand,
  repositorySha,
  keyId,
) {
  if (
    !/^[0-9a-f]{40}$/.test(repositorySha) ||
    !/^[a-z0-9][a-z0-9-]{0,63}$/.test(keyId)
  ) {
    fail();
  }
  const { stdout } = await execFileAsync(
    gitCommand,
    [
      ...GIT_PREFIX,
      REPOSITORY_ROOT,
      "show",
      `${repositorySha}:docs/operator-keys/${keyId}.pub`,
    ],
    {
      cwd: REPOSITORY_ROOT,
      encoding: "utf8",
      env: gitEnvironment(),
      maxBuffer: 8192,
      windowsHide: true,
    },
  );
  const value = stdout.trim();
  const raw = Buffer.from(value, "base64");
  if (
    raw.length !== 32 ||
    raw.toString("base64") !== value
  ) {
    fail();
  }
  return Object.freeze({
    key: createPublicKey({
      key: Buffer.concat([
        ED25519_SPKI_PREFIX,
        raw,
      ]),
      format: "der",
      type: "spki",
    }),
    raw: value,
  });
}

async function endpointFor(url, allowedPath, port = 443) {
  const endpoint = validatePublicEndpoint(url, {
    allowedPaths: [allowedPath],
    defaultPort: port,
    protocols: ["https:"],
  });
  return resolvePublicEndpoint(endpoint);
}

async function httpsRequest({
  authorization,
  body,
  method,
  url,
}) {
  const parsed = new URL(url);
  const resolved = await endpointFor(
    parsed.href,
    parsed.pathname,
    parsed.port === "" ? 443 : Number(parsed.port),
  );
  const encoded =
    body === undefined
      ? null
      : Buffer.from(JSON.stringify(body), "utf8");
  return new Promise((resolvePromise, rejectPromise) => {
    const request = https.request({
      agent: false,
      headers: {
        accept: "application/json",
        ...(authorization === undefined
          ? {}
          : { authorization }),
        ...(encoded === null
          ? {}
          : {
            "content-length": String(encoded.length),
            "content-type": "application/json",
          }),
      },
      host: resolved.hostname,
      lookup: createResolvedLookup(resolved),
      method,
      path: resolved.path,
      port: resolved.port,
      rejectUnauthorized: true,
      servername: resolved.hostname,
      timeout: 10_000,
    }, (response) => {
      if (
        response.statusCode !== 200 ||
        response.headers.location !== undefined ||
        String(
          response.headers["content-type"] ?? "",
        ).split(";")[0].trim().toLowerCase() !==
          "application/json"
      ) {
        response.resume();
        rejectPromise(failure());
        return;
      }
      const chunks = [];
      let size = 0;
      response.on("data", (chunk) => {
        size += chunk.length;
        if (size > MAX_HTTP_BYTES) {
          response.destroy(failure());
        } else {
          chunks.push(chunk);
        }
      });
      response.on("end", () => {
        const text = Buffer.concat(chunks).toString("utf8");
        const bodyText = text.endsWith("\n")
          ? text.slice(0, -1)
          : text;
        let parsedBody;
        try {
          parsedBody = JSON.parse(bodyText);
        } catch {
          rejectPromise(fail());
          return;
        }
        if (JSON.stringify(parsedBody) !== bodyText) {
          rejectPromise(fail());
          return;
        }
        resolvePromise(parsedBody);
      });
    });
    request.once("timeout", () =>
      request.destroy(failure()));
    request.once("error", rejectPromise);
    request.end(encoded);
  });
}

async function fetchDiscovery(url) {
  const parsed = new URL(url);
  const resolved = await endpointFor(
    parsed.href,
    parsed.pathname,
  );
  return new Promise((resolvePromise, rejectPromise) => {
    const request = https.request({
      agent: false,
      headers: { accept: "application/json" },
      host: resolved.hostname,
      lookup: createResolvedLookup(resolved),
      method: "GET",
      path: resolved.path,
      port: resolved.port,
      rejectUnauthorized: true,
      servername: resolved.hostname,
      timeout: 10_000,
    }, (response) => {
      if (
        response.statusCode !== 200 ||
        response.headers.location !== undefined ||
        String(
          response.headers["content-type"] ?? "",
        ).split(";")[0].trim().toLowerCase() !==
          "application/json"
      ) {
        response.resume();
        rejectPromise(failure());
        return;
      }
      const chunks = [];
      let size = 0;
      response.on("data", (chunk) => {
        size += chunk.length;
        if (size > MAX_HTTP_BYTES) {
          response.destroy(failure());
        } else {
          chunks.push(chunk);
        }
      });
      response.on("end", () => {
        try {
          resolvePromise(
            parsePayerBootstrapDiscoveryWire(
              Buffer.concat(chunks).toString("utf8"),
            ),
          );
        } catch {
          rejectPromise(fail());
        }
      });
    });
    request.once("timeout", () =>
      request.destroy(failure()));
    request.once("error", rejectPromise);
    request.end();
  });
}

async function exactPrivateFile(path) {
  const stats = await lstat(path);
  if (
    !stats.isFile() ||
    stats.isSymbolicLink() ||
    stats.nlink !== 1 ||
    (process.platform !== "win32" &&
      (stats.mode & 0o777) !== 0o600)
  ) {
    fail();
  }
  return path;
}

function childReady(command, arguments_, options = {}) {
  return new Promise((resolvePromise, rejectPromise) => {
    const child = spawn(command, arguments_, {
      ...options,
      stdio: options.stdio ?? [
        "ignore",
        "pipe",
        "ignore",
      ],
      windowsHide: true,
    });
    child.once("error", rejectPromise);
    child.once("spawn", () => resolvePromise(child));
  });
}

function stopChild(child) {
  if (
    child === null ||
    child.exitCode !== null ||
    child.signalCode !== null
  ) {
    return Promise.resolve();
  }
  return new Promise((resolvePromise) => {
    const timer = setTimeout(() => {
      if (
        child.exitCode === null &&
        child.signalCode === null
      ) {
        child.kill("SIGKILL");
      }
    }, 2_000);
    timer.unref?.();
    child.once("close", () => {
      clearTimeout(timer);
      resolvePromise();
    });
    child.kill("SIGTERM");
  });
}

export function buildRestrictedTunnelArguments({
  discovery,
  paths,
  sshIdentity,
} = {}) {
  if (
    discovery?.tunnelPort !== 443 ||
    typeof discovery.tunnelHost !== "string" ||
    typeof paths?.knownHostsPath !== "string" ||
    typeof sshIdentity?.privateKeyPath !== "string"
  ) {
    fail();
  }
  return Object.freeze([
    "-N",
    "-T",
    "-o",
    "BatchMode=yes",
    "-o",
    "ExitOnForwardFailure=yes",
    "-o",
    "IdentitiesOnly=yes",
    "-o",
    "StrictHostKeyChecking=yes",
    "-o",
    `UserKnownHostsFile=${paths.knownHostsPath}`,
    "-o",
    "PasswordAuthentication=no",
    "-o",
    "KbdInteractiveAuthentication=no",
    "-o",
    "PreferredAuthentications=publickey",
    "-i",
    sshIdentity.privateKeyPath,
    "-p",
    "443",
    "-R",
    "0.0.0.0:9443:127.0.0.1:9443",
    `clockchain-payer@${discovery.tunnelHost}`,
  ]);
}

export function buildMcpCertificateArguments({
  certificatePath,
  hostname,
  privateKeyPath,
} = {}) {
  if (
    typeof certificatePath !== "string" ||
    resolve(certificatePath) !== certificatePath ||
    typeof privateKeyPath !== "string" ||
    resolve(privateKeyPath) !== privateKeyPath ||
    typeof hostname !== "string" ||
    hostname.length === 0 ||
    hostname.length > 253 ||
    !/^[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?$/.test(
      hostname,
    )
  ) {
    fail();
  }
  return Object.freeze([
    "req",
    "-x509",
    "-newkey",
    "ed25519",
    "-keyout",
    privateKeyPath,
    "-out",
    certificatePath,
    "-nodes",
    "-days",
    "1",
    "-subj",
    `/CN=${MCP_CERTIFICATE_COMMON_NAME}`,
    "-addext",
    `subjectAltName=DNS:${hostname}`,
  ]);
}

export function buildPayerSupervisorArguments({
  discovery,
  paths,
  stateRoot,
  tlsIdentity,
} = {}) {
  if (
    discovery?.publicMcpPort !== 9443 ||
    typeof discovery.publicMcpHostname !== "string" ||
    typeof paths?.bootstrapBrokerCapabilityPath !==
      "string" ||
    typeof paths.bootstrapBrokerUrl !== "string" ||
    typeof paths.launchManifestPath !== "string" ||
    typeof stateRoot !== "string" ||
    typeof tlsIdentity?.certificatePath !== "string" ||
    typeof tlsIdentity.privateKeyPath !== "string"
  ) {
    fail();
  }
  return Object.freeze([
    join(
      REPOSITORY_ROOT,
      "bin/handshake-supervisor.mjs",
    ),
    "--launch-manifest",
    paths.launchManifestPath,
    "--state",
    stateRoot,
    "--run-mode",
    "aws-stakeholder-only",
    "--payer-mcp-host",
    "127.0.0.1",
    "--payer-mcp-port",
    "9443",
    "--payer-mcp-tls-certificate",
    tlsIdentity.certificatePath,
    "--payer-mcp-tls-private-key",
    tlsIdentity.privateKeyPath,
    "--payer-mcp-public-url",
    `https://${discovery.publicMcpHostname}:9443/mcp`,
    "--payer-mcp-bootstrap-broker-url",
    paths.bootstrapBrokerUrl,
    "--payer-mcp-bootstrap-broker-capability-file",
    paths.bootstrapBrokerCapabilityPath,
  ]);
}

export async function createProductionPayerBootstrapDependencies(
  input,
) {
  const requestJson =
    typeof input?.httpsRequest === "function"
      ? input.httpsRequest
      : httpsRequest;
  const submitHttpRequest =
    typeof input?.submitHttpRequest === "function"
      ? input.submitHttpRequest
      : requestJson;
  let prerequisites;
  let operatorPublicKey;
  let privateState;
  let activeClaim;
  let activeTunnel = null;
  let activeSupervisor = null;
  let signalHandler = null;
  let privateStateIdentity = null;
  const assertPrivateStatePinned = async () => {
    if (
      privateState === undefined ||
      privateStateIdentity === null
    ) {
      fail();
    }
    const stats = await lstat(privateState.stateRoot);
    if (
      !stats.isDirectory() ||
      stats.isSymbolicLink() ||
      stats.dev !== privateStateIdentity.dev ||
      stats.ino !== privateStateIdentity.ino ||
      (process.platform !== "win32" &&
        (stats.mode & 0o777) !== 0o700)
    ) {
      fail();
    }
  };
  const platformOptions = {
    platform: process.platform,
  };

  return {
    async createMcpTlsIdentity({ hostname }) {
      await assertPrivateStatePinned();
      const certificatePath = join(
        privateState.stateRoot,
        "payer-mcp.crt",
      );
      const privateKeyPath = join(
        privateState.stateRoot,
        "payer-mcp.key",
      );
      await execFileAsync(
        prerequisites.openssl.command,
        buildMcpCertificateArguments({
          certificatePath,
          hostname,
          privateKeyPath,
        }),
        {
          encoding: "utf8",
          env: childEnvironment(),
          maxBuffer: 8192,
          windowsHide: true,
        },
      );
      if (process.platform !== "win32") {
        await chmod(privateKeyPath, 0o600);
        await chmod(certificatePath, 0o600);
      }
      await exactPrivateFile(privateKeyPath);
      await exactPrivateFile(certificatePath);
      await assertPrivateStatePinned();
      const certificatePem = await readFile(
        certificatePath,
        "utf8",
      );
      return Object.freeze({
        certificatePath,
        certificatePem,
        fingerprint: createHash("sha256")
          .update(
            new X509Certificate(certificatePem).raw,
          )
          .digest("hex"),
        privateKeyPath,
      });
    },

    async createSshIdentity() {
      await assertPrivateStatePinned();
      const privateKeyPath = join(
        privateState.stateRoot,
        "payer-tunnel.ed25519",
      );
      await execFileAsync(
        prerequisites.sshKeygen.command,
        [
          "-q",
          "-t",
          "ed25519",
          "-N",
          "",
          "-C",
          "",
          "-f",
          privateKeyPath,
        ],
        {
          encoding: "utf8",
          env: childEnvironment(),
          maxBuffer: 8192,
          windowsHide: true,
        },
      );
      const publicKeyPath = `${privateKeyPath}.pub`;
      if (process.platform !== "win32") {
        await chmod(privateKeyPath, 0o600);
        await chmod(publicKeyPath, 0o600);
      }
      await exactPrivateFile(privateKeyPath);
      await exactPrivateFile(publicKeyPath);
      await assertPrivateStatePinned();
      const publicKey = (
        await readFile(publicKeyPath, "utf8")
      ).trim();
      return Object.freeze({
        fingerprint:
          sshEd25519Fingerprint(publicKey),
        privateKeyPath,
        publicKey,
        publicKeyPath,
      });
    },

    async createX25519Key() {
      await assertPrivateStatePinned();
      const key = createPayerBootstrapKey();
      await writePrivateFile({
        bytes: Buffer.from(
          `${JSON.stringify(key)}\n`,
          "utf8",
        ),
        path: join(
          privateState.stateRoot,
          "payer-bootstrap-x25519.json",
        ),
        ...platformOptions,
      });
      await assertPrivateStatePinned();
      return key;
    },

    installSignalHandlers(onSignal) {
      if (
        signalHandler !== null ||
        typeof onSignal !== "function"
      ) {
        fail();
      }
      signalHandler = () => {
        onSignal();
        if (activeSupervisor !== null) {
          void stopChild(activeSupervisor.child);
        }
        if (activeTunnel !== null) {
          void activeTunnel.stop();
        }
      };
      process.once("SIGINT", signalHandler);
      process.once("SIGTERM", signalHandler);
      return () => {
        if (signalHandler !== null) {
          process.removeListener(
            "SIGINT",
            signalHandler,
          );
          process.removeListener(
            "SIGTERM",
            signalHandler,
          );
          signalHandler = null;
        }
      };
    },

    async inspectPrerequisites() {
      prerequisites =
        await inspectParticipantPrerequisites({
          role: "payer",
        });
      return prerequisites;
    },

    async pollApprovedPackage({
      claimFingerprint,
      expiresAtMs,
      payerClaimUrl,
      pollCapability,
    }) {
      const deadline = Math.min(
        Number(expiresAtMs),
        Date.now() + MAX_POLL_MS,
      );
      const pollUrl =
        `${payerClaimUrl}/${claimFingerprint}`;
      const waitForNextPoll = async () => {
        if (Date.now() + POLL_INTERVAL_MS > deadline) {
          fail();
        }
        await new Promise((resolvePromise) =>
          setTimeout(resolvePromise, POLL_INTERVAL_MS));
      };
      for (;;) {
        let response;
        try {
          response = await requestJson({
            authorization: `Bearer ${pollCapability}`,
            method: "GET",
            url: pollUrl,
          });
        } catch {
          await waitForNextPoll();
          continue;
        }
        if (response?.paymentMoved !== false) {
          fail();
        }
        if (response.status === "SEALED") {
          if (response.packageResponse === undefined) fail();
          return response;
        }
        if (!["PENDING", "APPROVED"].includes(response.status)) {
          fail();
        }
        await waitForNextPoll();
      }
    },

    async preparePrivateState({ stateRoot }) {
      const created = await preparePrivateDirectory({
        path: stateRoot,
        ...platformOptions,
      });
      if (created.created !== true) fail();
      privateState = Object.freeze({
        stateRoot: created.path,
      });
      privateStateIdentity = await lstat(
        privateState.stateRoot,
      );
      return privateState;
    },

    randomUUID,

    async revokeTunnelGrant() {
      // Task 7's durable bootstrap service owns revocation.
      // A failed local wrapper closes its SSH connection below.
    },

    async startPayerSupervisor({
      discovery,
      paths,
      stateRoot,
      tlsIdentity,
    }) {
      const child = await childReady(
        process.execPath,
        buildPayerSupervisorArguments({
          discovery,
          paths,
          stateRoot,
          tlsIdentity,
        }),
        {
          cwd: REPOSITORY_ROOT,
          env: childEnvironment(),
        },
      );
      const lines = createInterface({
        crlfDelay: Infinity,
        input: child.stdout,
      });
      activeSupervisor = Object.freeze({
        child,
        lines,
      });
      return activeSupervisor;
    },

    async startRestrictedTunnel({
      discovery,
      paths,
      sshIdentity,
    }) {
      let stopped = false;
      let child = null;
      let attempts = 0;
      let rejectFatal;
      const fatal = new Promise(
        (_resolvePromise, rejectPromise) => {
          rejectFatal = rejectPromise;
        },
      );
      fatal.catch(() => {});
      const arguments_ =
        buildRestrictedTunnelArguments({
          discovery,
          paths,
          sshIdentity,
        });
      const launch = async () => {
        child = await childReady(
          prerequisites.openssh.command,
          arguments_,
          {
            env: childEnvironment(),
            stdio: ["ignore", "ignore", "ignore"],
          },
        );
        attempts += 1;
        child.once("close", () => {
          if (
            !stopped &&
            attempts < 4 &&
            Date.now() <
              Number(discovery.expiresAtMs)
          ) {
            setTimeout(() => {
              void launch().catch(rejectFatal);
            }, Math.min(1_000 * attempts, 3_000));
          } else if (!stopped) {
            rejectFatal(failure());
          }
        });
      };
      await launch();
      activeTunnel = {
        fatal,
        get child() {
          return child;
        },
        async stop() {
          stopped = true;
          await stopChild(child);
        },
      };
      return activeTunnel;
    },

    async stopPayerSupervisor(handle) {
      handle.lines.close();
      await stopChild(handle.child);
      if (activeSupervisor === handle) {
        activeSupervisor = null;
      }
    },

    async stopRestrictedTunnel(handle) {
      await handle.stop();
      if (activeTunnel === handle) {
        activeTunnel = null;
      }
    },

    async submitPayerClaim({
      claim,
      payerClaimUrl,
    }) {
      activeClaim = claim;
      const pollCapability =
        randomBytes(32).toString("hex");
      const body = {
        claim,
        paymentMoved: false,
        pollCapability,
      };
      const request = () => submitHttpRequest({
        body,
        method: "POST",
        url: payerClaimUrl,
      });
      let response;
      try {
        response = await request();
      } catch {
        try {
          response = await request();
        } catch {
          fail();
        }
      }
      const claimFingerprint =
        payerBootstrapClaimFingerprint(claim);
      if (
        response?.claimFingerprint !==
          claimFingerprint ||
        response.paymentMoved !== false ||
        response.status !== "PENDING"
      ) {
        fail();
      }
      return Object.freeze({
        claimFingerprint,
        pollCapability,
      });
    },

    async verifyAndOpenPackage({
      approved,
      claim,
      discovery,
      payerPrivateKey,
    }) {
      if (
        approved?.claimFingerprint !==
          payerBootstrapClaimFingerprint(claim) ||
        approved.packageResponse === undefined
      ) {
        fail();
      }
      const markerPath = join(
        privateState.stateRoot,
        `consumed-${claim.claimNonce}`,
      );
      return openSignedPayerBootstrapPackage({
        claim,
        consumeClaimNonce() {
          if (activeClaim !== claim) return false;
          let descriptor;
          try {
            descriptor = openSync(
              markerPath,
              fsConstants.O_WRONLY |
                fsConstants.O_CREAT |
                fsConstants.O_EXCL |
                (fsConstants.O_NOFOLLOW ?? 0),
              0o600,
            );
            writeSync(
              descriptor,
              `${claim.claimNonce}\n`,
              null,
              "utf8",
            );
            fsyncSync(descriptor);
            closeSync(descriptor);
            descriptor = undefined;
            return true;
          } catch {
            if (descriptor !== undefined) {
              try {
                closeSync(descriptor);
              } catch {
                // The fixed replay rejection remains authoritative.
              }
              try {
                unlinkSync(markerPath);
              } catch {
                // A failed marker is never treated as reusable.
              }
            }
            return false;
          }
        },
        expectedReleaseId: discovery.releaseId,
        expectedRepositorySha:
          discovery.repositorySha,
        expectedSessionId: discovery.sessionId,
        nowMs: Date.now(),
        operatorPublicKey: operatorPublicKey.key,
        payerPrivateKey,
        response: approved.packageResponse,
      });
    },

    async verifyCleanDetachedRelease() {
      return inspectRepository(prerequisites.git.command);
    },

    async verifySignedDiscovery({
      discoveryUrl,
      repositorySha,
    }) {
      const candidate = await fetchDiscovery(discoveryUrl);
      operatorPublicKey =
        await reviewedOperatorPublicKey(
          prerequisites.git.command,
          repositorySha,
          candidate.operatorKeyId,
        );
      return verifySignedPayerBootstrapDiscovery({
        discovery: candidate,
        expectedImageDigest:
          candidate.imageDigest,
        expectedPublicMcpHostname:
          candidate.publicMcpHostname,
        nowMs: Date.now(),
        operatorPublicKey:
          operatorPublicKey.raw,
        repositorySha,
      });
    },

    async waitForTerminalLocalStatus({
      supervisor,
      tunnel,
      writeStatus,
    }) {
      const consumeSupervisor = async () => {
        let acknowledged = false;
        for await (const line of supervisor.lines) {
          let status;
          try {
            status = JSON.parse(line);
          } catch {
            fail();
          }
          if (
            status?.paymentMoved !== false ||
            status.role !== "payer"
          ) {
            fail();
          }
          if (status.status === "PAYER_MCP_READY") {
            writeStatus({
              paymentMoved: false,
              status: "PAYER_MCP_READY",
            });
          } else if (
            status.status === "PARTY_PROGRESS" &&
            status.state === "PROPOSED"
          ) {
            writeStatus({
              paymentMoved: false,
              status: "PROPOSED",
            });
          } else if (
            status.status === "PARTY_COMPLETE" &&
            status.state === "ACKNOWLEDGED"
          ) {
            writeStatus({
              paymentMoved: false,
              status: "ACKNOWLEDGED",
            });
            acknowledged = true;
          } else if (
            ![
              "WAITING_FOR_PEER",
              "PEER_READY",
            ].includes(status.status)
          ) {
            fail();
          }
        }
        if (
          !acknowledged ||
          supervisor.child.exitCode !== 0
        ) {
          fail();
        }
        return Object.freeze({
          paymentMoved: false,
          status: "COMPLETED",
        });
      };
      return Promise.race([
        consumeSupervisor(),
        tunnel.fatal,
      ]);
    },

    async writePrivateLaunchMaterial({
      discovery,
      openedPackage,
    }) {
      await assertPrivateStatePinned();
      const launchManifestPath = join(
        privateState.stateRoot,
        "payer.launch.json",
      );
      const bootstrapBrokerCapabilityPath = join(
        privateState.stateRoot,
        "bootstrap-broker.capability",
      );
      const tunnelGrantPath = join(
        privateState.stateRoot,
        "tunnel-grant.json",
      );
      const knownHostsPath = join(
        privateState.stateRoot,
        "known_hosts",
      );
      await writePrivateFile({
        bytes: openedPackage.launchManifestBytes,
        path: launchManifestPath,
        ...platformOptions,
      });
      await writePrivateFile({
        bytes: Buffer.from(
          `${openedPackage.bootstrapBrokerCapability}\n`,
          "utf8",
        ),
        path: bootstrapBrokerCapabilityPath,
        ...platformOptions,
      });
      await writePrivateFile({
        bytes: openedPackage.tunnelGrantBytes,
        path: tunnelGrantPath,
        ...platformOptions,
      });
      await writePrivateFile({
        bytes: Buffer.from(
          `[${discovery.tunnelHost}]:${discovery.tunnelPort} ${discovery.tunnelHostPublicKey}\n`,
          "utf8",
        ),
        path: knownHostsPath,
        ...platformOptions,
      });
      await assertPrivateStatePinned();
      return Object.freeze({
        bootstrapBrokerCapabilityPath,
        bootstrapBrokerUrl:
          openedPackage.bootstrapBrokerUrl,
        knownHostsPath,
        launchManifestPath,
        tunnelGrantPath,
      });
    },

    writeStatus(value) {
      process.stdout.write(
        `${JSON.stringify(value)}\n`,
      );
    },

    async zeroizeBootstrapSecrets(value) {
      const visit = (entry) => {
        if (Buffer.isBuffer(entry)) {
          entry.fill(0);
        } else if (
          entry !== null &&
          typeof entry === "object"
        ) {
          for (const child of Object.values(entry)) {
            visit(child);
          }
        }
      };
      visit(value);
      activeClaim = null;
    },
  };
}
