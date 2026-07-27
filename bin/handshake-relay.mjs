#!/usr/bin/env node

import {
  constants as fsConstants,
} from "node:fs";
import {
  lstat,
  open,
} from "node:fs/promises";
import {
  execFile as execFileCallback,
} from "node:child_process";
import {
  X509Certificate,
  constants as cryptoConstants,
  createHash,
  createPrivateKey,
  sign,
  verify,
} from "node:crypto";
import https from "node:https";
import { isIP } from "node:net";
import { resolve } from "node:path";
import {
  fileURLToPath,
} from "node:url";
import { promisify } from "node:util";

import {
  canonicalizeReceiptEventValue,
} from "../src/canonical.mjs";
import {
  operatorPublicKeyPath,
} from "../src/bilateral/descriptor.mjs";
import {
  ARTIFACT_POLICIES,
} from "../src/bilateral/coordination/artifact.mjs";
import {
  createRelayService,
} from "../src/bilateral/coordination/relay.mjs";
import {
  openCoordinationStore,
} from "../src/bilateral/coordination/storage.mjs";

export const RELAY_HEADER_TIMEOUT_MS = 5_000;
export const RELAY_BODY_TIMEOUT_MS = 5_000;
export const RELAY_TOTAL_TIMEOUT_MS = 40_000;
export const RELAY_REPOSITORY_ROOT = resolve(
  fileURLToPath(new URL("../", import.meta.url)),
);

const MAX_TLS_CERTIFICATE_BYTES = 65_536;
const MAX_TLS_PRIVATE_KEY_BYTES = 16_384;
const MAX_GIT_OUTPUT_BYTES = 8_192;
const GIT_SUBPROCESS_ENVIRONMENT = Object.freeze(
  Object.assign(Object.create(null), {
    GIT_ATTR_NOSYSTEM: "1",
    GIT_CONFIG_GLOBAL: "/dev/null",
    GIT_CONFIG_NOSYSTEM: "1",
    GIT_CONFIG_SYSTEM: "/dev/null",
    GIT_NO_REPLACE_OBJECTS: "1",
    GIT_OPTIONAL_LOCKS: "0",
    GIT_TERMINAL_PROMPT: "0",
    LANG: "C",
    LC_ALL: "C",
    PATH: "/usr/bin:/bin",
  }),
);
const GIT_REPOSITORY_ARGUMENTS = Object.freeze([
  "--no-pager",
  "--no-replace-objects",
  "-C",
  RELAY_REPOSITORY_ROOT,
  "--work-tree",
  RELAY_REPOSITORY_ROOT,
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
]);
const FLAGS = Object.freeze([
  "--host",
  "--port",
  "--repository-sha",
  "--state",
  "--tls-certificate",
  "--tls-private-key",
]);
const MAIN_DEPENDENCY_KEYS = Object.freeze([
  "checkoutProbe",
]);
const CHECKOUT_RESULT_KEYS = Object.freeze([
  "clean",
  "repositorySha",
]);
const SHA256_PATTERN = /^[0-9a-f]{64}$/;
const REPOSITORY_SHA_PATTERN = /^[0-9a-f]{40}$/;
const UUID_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const PORT_PATTERN = /^(?:[1-9][0-9]{0,4})$/;
const REQUEST_ERROR = Object.freeze({
  code: "COORDINATION_RELAY_REQUEST_INVALID",
  paymentMoved: false,
});
const execFile = promisify(execFileCallback);

export class CoordinationRelayStartupError extends Error {
  constructor() {
    super("Handshake relay startup failed safely.");
    this.name = new.target.name;
    this.category = "configuration";
    this.code = "COORDINATION_RELAY_STARTUP_INVALID";
  }
}

function invalid() {
  throw new CoordinationRelayStartupError();
}

function repositoryGit(arguments_) {
  return execFile(
    "git",
    [...GIT_REPOSITORY_ARGUMENTS, ...arguments_],
    {
      cwd: RELAY_REPOSITORY_ROOT,
      encoding: "utf8",
      env: GIT_SUBPROCESS_ENVIRONMENT,
      maxBuffer: MAX_GIT_OUTPUT_BYTES,
    },
  );
}

function isPlainObject(value) {
  if (value === null || typeof value !== "object") {
    return false;
  }
  try {
    const prototype = Object.getPrototypeOf(value);
    return (
      prototype === Object.prototype || prototype === null
    );
  } catch {
    return false;
  }
}

function readExactData(value, keys) {
  if (!isPlainObject(value)) {
    invalid();
  }
  let ownKeys;
  try {
    ownKeys = Reflect.ownKeys(value);
  } catch {
    invalid();
  }
  if (
    ownKeys.length !== keys.length ||
    ownKeys.some(
      (key) =>
        typeof key !== "string" || !keys.includes(key),
    )
  ) {
    invalid();
  }
  const result = Object.create(null);
  for (const key of keys) {
    let descriptor;
    try {
      descriptor = Object.getOwnPropertyDescriptor(value, key);
    } catch {
      invalid();
    }
    if (
      descriptor?.enumerable !== true ||
      !Object.hasOwn(descriptor, "value")
    ) {
      invalid();
    }
    Object.defineProperty(result, key, {
      enumerable: true,
      value: descriptor.value,
    });
  }
  return result;
}

function stableBytes(value) {
  try {
    return Buffer.from(
      JSON.stringify(
        canonicalizeReceiptEventValue(value),
      ),
      "utf8",
    );
  } catch {
    invalid();
  }
}

function isCanonicalIpText(value) {
  const version = isIP(value);
  if (version === 0) {
    return false;
  }
  try {
    const authority =
      version === 6 ? `[${value}]` : value;
    const normalized = new URL(
      `https://${authority}:8443`,
    ).hostname;
    return (
      version === 6
        ? normalized.slice(1, -1)
        : normalized
    ) === value;
  } catch {
    return false;
  }
}

function parseArguments(arguments_) {
  if (
    !Array.isArray(arguments_) ||
    arguments_.length !== FLAGS.length * 2
  ) {
    invalid();
  }
  const values = Object.create(null);
  for (
    let index = 0;
    index < arguments_.length;
    index += 2
  ) {
    const flag = arguments_[index];
    const value = arguments_[index + 1];
    if (
      !FLAGS.includes(flag) ||
      Object.hasOwn(values, flag) ||
      typeof value !== "string" ||
      value.length === 0 ||
      value.startsWith("--")
    ) {
      invalid();
    }
    values[flag] = value;
  }
  if (!FLAGS.every((flag) => Object.hasOwn(values, flag))) {
    invalid();
  }
  const host = values["--host"];
  const portText = values["--port"];
  const repositorySha = values["--repository-sha"];
  if (
    !isCanonicalIpText(host) ||
    host === "0.0.0.0" ||
    host === "::" ||
    !PORT_PATTERN.test(portText) ||
    Number(portText) > 65_535 ||
    !REPOSITORY_SHA_PATTERN.test(repositorySha)
  ) {
    invalid();
  }
  return Object.freeze({
    certificatePath: resolve(
      values["--tls-certificate"],
    ),
    host,
    port: Number(portText),
    privateKeyPath: resolve(
      values["--tls-private-key"],
    ),
    repositorySha,
    statePath: resolve(values["--state"]),
  });
}

function sameIdentity(left, right) {
  return (
    left.dev === right.dev &&
    left.ino === right.ino &&
    left.mode === right.mode &&
    left.nlink === right.nlink &&
    left.uid === right.uid &&
    left.gid === right.gid &&
    left.rdev === right.rdev &&
    left.size === right.size &&
    left.mtimeMs === right.mtimeMs &&
    left.ctimeMs === right.ctimeMs
  );
}

async function boundedRegularFile(
  path,
  maximum,
  { privateMode = false } = {},
) {
  let pathname;
  let handle;
  try {
    pathname = await lstat(path);
    if (
      !pathname.isFile() ||
      pathname.isSymbolicLink() ||
      pathname.nlink !== 1 ||
      pathname.uid !== process.getuid() ||
      (privateMode
        ? (pathname.mode & 0o777) !== 0o600
        : (pathname.mode & 0o022) !== 0) ||
      pathname.size <= 0 ||
      pathname.size > maximum
    ) {
      invalid();
    }
    handle = await open(
      path,
      fsConstants.O_RDONLY |
        (fsConstants.O_NOFOLLOW ?? 0) |
        fsConstants.O_NONBLOCK,
    );
    const opened = await handle.stat();
    if (
      !opened.isFile() ||
      !sameIdentity(pathname, opened)
    ) {
      invalid();
    }
    const output = Buffer.alloc(maximum + 1);
    let offset = 0;
    for (;;) {
      const { bytesRead } = await handle.read(
        output,
        offset,
        output.length - offset,
        offset,
      );
      offset += bytesRead;
      if (bytesRead === 0 || offset === output.length) {
        break;
      }
    }
    const after = await handle.stat();
    const pathnameAfter = await lstat(path);
    if (
      offset === 0 ||
      offset > maximum ||
      offset !== pathname.size ||
      !sameIdentity(pathname, after) ||
      !pathnameAfter.isFile() ||
      pathnameAfter.isSymbolicLink() ||
      !sameIdentity(pathname, pathnameAfter)
    ) {
      invalid();
    }
    return Buffer.from(output.subarray(0, offset));
  } catch (error) {
    if (error instanceof CoordinationRelayStartupError) {
      throw error;
    }
    invalid();
  } finally {
    if (handle !== undefined) {
      try {
        await handle.close();
      } catch {
        invalid();
      }
    }
  }
}

async function assertPrivateStateRoot(path) {
  try {
    const metadata = await lstat(path);
    if (
      !metadata.isDirectory() ||
      metadata.isSymbolicLink() ||
      metadata.uid !== process.getuid() ||
      (metadata.mode & 0o777) !== 0o700
    ) {
      invalid();
    }
  } catch (error) {
    if (error instanceof CoordinationRelayStartupError) {
      throw error;
    }
    invalid();
  }
}

async function productionCheckoutProbe() {
  try {
    const [head, status] = await Promise.all([
      repositoryGit([
        "rev-parse",
        "--verify",
        "HEAD",
      ]),
      repositoryGit(
        [
          "status",
          "--porcelain=v1",
          "--untracked-files=normal",
        ],
      ),
    ]);
    return {
      clean: status.stdout.length === 0,
      repositorySha: head.stdout.trim(),
    };
  } catch {
    invalid();
  }
}

function readCheckoutResult(value, expectedSha) {
  const data = readExactData(
    value,
    CHECKOUT_RESULT_KEYS,
  );
  if (
    data.clean !== true ||
    data.repositorySha !== expectedSha
  ) {
    invalid();
  }
}

function createReceiptSigner(
  certificate,
  privateKey,
) {
  const publicKey = certificate.publicKey;
  const certificateSha256 = createHash("sha256")
    .update(certificate.raw)
    .digest("hex");
  let signatureAlgorithm;
  let algorithm;
  let keyOptions;
  if (privateKey.asymmetricKeyType === "ed25519") {
    signatureAlgorithm = "ed25519";
    algorithm = null;
    keyOptions = privateKey;
  } else if (privateKey.asymmetricKeyType === "ec") {
    signatureAlgorithm = "ecdsa-sha256";
    algorithm = "sha256";
    keyOptions = privateKey;
  } else if (
    privateKey.asymmetricKeyType === "rsa" ||
    privateKey.asymmetricKeyType === "rsa-pss"
  ) {
    signatureAlgorithm = "rsa-pss-sha256";
    algorithm = "sha256";
    keyOptions = {
      key: privateKey,
      padding: cryptoConstants.RSA_PKCS1_PSS_PADDING,
      saltLength: cryptoConstants.RSA_PSS_SALTLEN_DIGEST,
    };
  } else {
    invalid();
  }
  const verifyOptions =
    signatureAlgorithm === "rsa-pss-sha256"
      ? {
          key: publicKey,
          padding:
            cryptoConstants.RSA_PKCS1_PSS_PADDING,
          saltLength:
            cryptoConstants.RSA_PSS_SALTLEN_DIGEST,
        }
      : publicKey;
  return Object.freeze({
    certificateSha256,
    sign(preimage) {
      return sign(algorithm, preimage, keyOptions);
    },
    signatureAlgorithm,
    verify(preimage, signature) {
      return verify(
        algorithm,
        preimage,
        verifyOptions,
        signature,
      );
    },
  });
}

async function gitShowPublicKey(context) {
  try {
    const expectedPath = operatorPublicKeyPath(
      context.keyId,
    );
    if (
      context.repositoryPath !== expectedPath ||
      !REPOSITORY_SHA_PATTERN.test(
        context.repositorySha,
      )
    ) {
      invalid();
    }
    const result = await repositoryGit(
      [
        "show",
        `${context.repositorySha}:${expectedPath}`,
      ],
    );
    if (
      result.stdout.length === 0 ||
      Buffer.byteLength(result.stdout, "utf8") >
        MAX_GIT_OUTPUT_BYTES
    ) {
      invalid();
    }
    return result.stdout;
  } catch (error) {
    if (error instanceof CoordinationRelayStartupError) {
      throw error;
    }
    invalid();
  }
}

function rawHeaderValues(request, name) {
  const values = [];
  for (
    let index = 0;
    index < request.rawHeaders.length;
    index += 2
  ) {
    if (
      request.rawHeaders[index].toLowerCase() === name
    ) {
      values.push(request.rawHeaders[index + 1]);
    }
  }
  return values;
}

function assertNoDangerousHeaders(request) {
  for (const name of [
    "authorization",
    "cookie",
    "expect",
    "forwarded",
    "proxy-authorization",
    "upgrade",
    "x-forwarded-for",
    "x-forwarded-host",
    "x-forwarded-proto",
  ]) {
    if (request.headers[name] !== undefined) {
      throw new Error();
    }
  }
  if (
    rawHeaderValues(request, "content-length").length > 1 ||
    rawHeaderValues(request, "transfer-encoding").length > 1 ||
    (
      request.headers["content-length"] !== undefined &&
      request.headers["transfer-encoding"] !== undefined
    )
  ) {
    throw new Error();
  }
}

function requireContentType(request, expected) {
  const values = rawHeaderValues(
    request,
    "content-type",
  );
  if (
    values.length !== 1 ||
    values[0] !== expected
  ) {
    throw new Error();
  }
}

function requireOneHeader(request, name) {
  const values = rawHeaderValues(request, name);
  if (
    values.length !== 1 ||
    values[0].length === 0
  ) {
    throw new Error();
  }
  return values[0];
}

function requireEmptyGetBody(request) {
  if (
    request.headers["content-type"] !== undefined ||
    request.headers["transfer-encoding"] !== undefined ||
    (
      request.headers["content-length"] !== undefined &&
      request.headers["content-length"] !== "0"
    )
  ) {
    throw new Error();
  }
}

function readBody(request, maximum) {
  return new Promise((resolveBody, rejectBody) => {
    const chunks = [];
    let length = 0;
    let complete = false;
    const finish = (action, value) => {
      if (complete) {
        return;
      }
      complete = true;
      clearTimeout(timer);
      action(value);
    };
    const timer = setTimeout(
      () => finish(rejectBody, new Error()),
      RELAY_BODY_TIMEOUT_MS,
    );
    request.on("data", (chunk) => {
      length += chunk.length;
      if (length > maximum) {
        request.resume();
        finish(rejectBody, new Error());
        return;
      }
      chunks.push(Buffer.from(chunk));
    });
    request.once("end", () => {
      finish(resolveBody, Buffer.concat(chunks));
    });
    request.once("aborted", () => {
      finish(rejectBody, new Error());
    });
    request.once("error", () => {
      finish(rejectBody, new Error());
    });
  });
}

function sendJson(response, statusCode, value) {
  if (response.headersSent || response.destroyed) {
    return;
  }
  const body = stableBytes(value);
  response.writeHead(statusCode, {
    "cache-control": "no-store",
    "content-length": String(body.length),
    "content-type": "application/json",
    "x-content-type-options": "nosniff",
  });
  response.end(body);
}

function sendBytes(response, bytes) {
  if (response.headersSent || response.destroyed) {
    return;
  }
  response.writeHead(200, {
    "cache-control": "no-store",
    "content-length": String(bytes.length),
    "content-type": "application/octet-stream",
    "x-content-type-options": "nosniff",
  });
  response.end(bytes);
}

function parseRequestTarget(value) {
  if (
    typeof value !== "string" ||
    !value.startsWith("/") ||
    value.startsWith("//") ||
    value.includes("#")
  ) {
    throw new Error();
  }
  const queryIndex = value.indexOf("?");
  const path =
    queryIndex === -1
      ? value
      : value.slice(0, queryIndex);
  const query =
    queryIndex === -1
      ? null
      : value.slice(queryIndex + 1);
  if (
    path.length === 0 ||
    path.includes("%") ||
    query === "" ||
    query?.includes("?")
  ) {
    throw new Error();
  }
  return { path, query };
}

function parseRawQuery(query, allowed) {
  const result = new Map();
  if (query === null) {
    return result;
  }
  if (
    query.includes("%") ||
    query.includes("+")
  ) {
    throw new Error();
  }
  for (const field of query.split("&")) {
    const separator = field.indexOf("=");
    if (
      separator <= 0 ||
      separator !== field.lastIndexOf("=")
    ) {
      throw new Error();
    }
    const key = field.slice(0, separator);
    const value = field.slice(separator + 1);
    if (
      !allowed.includes(key) ||
      result.has(key)
    ) {
      throw new Error();
    }
    result.set(key, value);
  }
  return result;
}

function requestHandler(service, host, port) {
  const expectedHost =
    isIP(host) === 6
      ? `[${host}]:${port}`
      : `${host}:${port}`;
  return async (request, response) => {
    const requestController = new AbortController();
    const abortRequest = () => {
      requestController.abort();
    };
    request.once("aborted", abortRequest);
    response.once("close", abortRequest);
    const totalTimer = setTimeout(() => {
      abortRequest();
      sendJson(response, 408, REQUEST_ERROR);
      request.destroy();
    }, RELAY_TOTAL_TIMEOUT_MS);
    try {
      assertNoDangerousHeaders(request);
      const hostValues = rawHeaderValues(
        request,
        "host",
      );
      if (
        hostValues.length !== 1 ||
        hostValues[0] !== expectedHost
      ) {
        throw new Error();
      }
      const { path, query } = parseRequestTarget(
        request.url,
      );
      if (request.method === "GET") {
        requireEmptyGetBody(request);
      }

      if (
        request.method === "POST" &&
        (path === "/v1/bootstrap" ||
          path === "/v1/events")
      ) {
        if (query !== null) {
          throw new Error();
        }
        requireContentType(request, "application/json");
        const body = await readBody(
          request,
          65_536,
        );
        const result =
          path === "/v1/bootstrap"
            ? await service.bootstrap({ body })
            : await service.appendEvent({ body });
        sendJson(response, 200, result);
        return;
      }

      const artifactMatch = path.match(
        /^\/v1\/artifacts\/([0-9a-f]{64})$/,
      );
      if (
        request.method === "PUT" &&
        artifactMatch !== null
      ) {
        if (query !== null) {
          throw new Error();
        }
        requireContentType(
          request,
          "application/octet-stream",
        );
        const artifactType = requireOneHeader(
          request,
          "x-clockchain-artifact-type",
        );
        const policy = ARTIFACT_POLICIES[artifactType];
        if (policy === undefined) {
          throw new Error();
        }
        const body = await readBody(
          request,
          policy.maximum,
        );
        const result = await service.putArtifact({
          artifactType,
          body,
          expectedDigest: artifactMatch[1],
        });
        sendJson(response, 200, result);
        return;
      }
      if (
        request.method === "GET" &&
        artifactMatch !== null
      ) {
        if (query !== null) {
          throw new Error();
        }
        sendBytes(
          response,
          await service.getArtifact({
            digest: artifactMatch[1],
          }),
        );
        return;
      }

      const eventsMatch = path.match(
        /^\/v1\/sessions\/([0-9a-f-]{36})\/events$/,
      );
      const enrollmentsMatch = path.match(
        /^\/v1\/sessions\/([0-9a-f-]{36})\/enrollments$/,
      );
      if (
        request.method === "GET" &&
        enrollmentsMatch !== null
      ) {
        if (
          query !== null ||
          !UUID_PATTERN.test(enrollmentsMatch[1])
        ) {
          throw new Error();
        }
        sendJson(
          response,
          200,
          await service.readEnrollmentSet({
            sessionId: enrollmentsMatch[1],
          }),
        );
        return;
      }
      if (
        request.method === "GET" &&
        eventsMatch !== null
      ) {
        const queryValues = parseRawQuery(
          query,
          ["after", "waitMs"],
        );
        const after = queryValues.has("after")
          ? queryValues.get("after")
          : null;
        const waitText = queryValues.has("waitMs")
          ? queryValues.get("waitMs")
          : "0";
        if (
          !/^(?:0|[1-9][0-9]*)$/.test(waitText) ||
          !UUID_PATTERN.test(eventsMatch[1])
        ) {
          throw new Error();
        }
        const result = await service.readEvents({
          after,
          sessionId: eventsMatch[1],
          signal: requestController.signal,
          waitMs: Number(waitText),
        });
        sendJson(response, 200, result);
        return;
      }

      const viewMatch = path.match(
        /^\/v1\/sessions\/([0-9a-f-]{36})\/view$/,
      );
      if (
        request.method === "GET" &&
        viewMatch !== null
      ) {
        if (
          query !== null ||
          !UUID_PATTERN.test(viewMatch[1])
        ) {
          throw new Error();
        }
        sendJson(
          response,
          200,
          await service.readSessionView({
            sessionId: viewMatch[1],
          }),
        );
        return;
      }
      throw new Error();
    } catch {
      sendJson(response, 400, REQUEST_ERROR);
    } finally {
      clearTimeout(totalTimer);
      request.off("aborted", abortRequest);
      response.off("close", abortRequest);
    }
  };
}

function listen(server, port, host) {
  return new Promise((resolveListen, rejectListen) => {
    const failed = (error) => {
      server.off("listening", listening);
      rejectListen(error);
    };
    const listening = () => {
      server.off("error", failed);
      resolveListen();
    };
    server.once("error", failed);
    server.once("listening", listening);
    server.listen(port, host);
  });
}

export async function main(arguments_, dependencies = {}) {
  let store;
  let server;
  try {
    const dependencyData = readExactData(
      dependencies,
      Object.keys(dependencies).length === 0
        ? []
        : MAIN_DEPENDENCY_KEYS,
    );
    const checkoutProbe =
      dependencyData.checkoutProbe ??
      productionCheckoutProbe;
    if (typeof checkoutProbe !== "function") {
      invalid();
    }
    const options = parseArguments(arguments_);
    readCheckoutResult(
      await checkoutProbe(),
      options.repositorySha,
    );
    await assertPrivateStateRoot(options.statePath);
    const [certificateBytes, privateKeyBytes] =
      await Promise.all([
        boundedRegularFile(
          options.certificatePath,
          MAX_TLS_CERTIFICATE_BYTES,
        ),
        boundedRegularFile(
          options.privateKeyPath,
          MAX_TLS_PRIVATE_KEY_BYTES,
          { privateMode: true },
        ),
      ]);
    let certificate;
    let privateKey;
    try {
      certificate = new X509Certificate(
        certificateBytes,
      );
      privateKey = createPrivateKey(privateKeyBytes);
      if (!certificate.checkPrivateKey(privateKey)) {
        invalid();
      }
    } catch (error) {
      if (error instanceof CoordinationRelayStartupError) {
        throw error;
      }
      invalid();
    }
    const receiptSigner = createReceiptSigner(
      certificate,
      privateKey,
    );
    store = await openCoordinationStore({
      repositorySha: options.repositorySha,
      root: options.statePath,
    });
    const service = createRelayService({
      frozenRepositorySha: options.repositorySha,
      receiptSigner,
      repositoryPublicKeyResolver: gitShowPublicKey,
      store,
    });
    server = https.createServer(
      {
        cert: certificateBytes,
        key: privateKeyBytes,
      },
      requestHandler(
        service,
        options.host,
        options.port,
      ),
    );
    server.headersTimeout = RELAY_HEADER_TIMEOUT_MS;
    server.requestTimeout = RELAY_TOTAL_TIMEOUT_MS;
    server.timeout = RELAY_TOTAL_TIMEOUT_MS;
    server.keepAliveTimeout = 1_000;
    server.maxHeadersCount = 32;
    server.on("clientError", (_error, socket) => {
      if (!socket.writable) {
        return;
      }
      const body = stableBytes(REQUEST_ERROR);
      socket.end(
        "HTTP/1.1 400 Bad Request\r\n" +
          "Connection: close\r\n" +
          `Content-Length: ${body.length}\r\n` +
          "Content-Type: application/json\r\n" +
          "\r\n" +
          body.toString("utf8"),
      );
    });
    await listen(server, options.port, options.host);
    let closePromise;
    const running = Object.freeze({
      address: Object.freeze({
        host: options.host,
        port: options.port,
      }),
      close() {
        if (closePromise !== undefined) {
          return closePromise;
        }
        closePromise = (async () => {
          server.closeIdleConnections();
          server.closeAllConnections();
          await new Promise((resolveClose, rejectClose) => {
            server.close((error) =>
              error === undefined
                ? resolveClose()
                : rejectClose(error),
            );
          });
          await store.close();
        })();
        return closePromise;
      },
    });
    return running;
  } catch (error) {
    if (server !== undefined) {
      server.closeAllConnections();
      await new Promise((resolveClose) => {
        server.close(() => resolveClose());
      }).catch(() => {});
    }
    await store?.close().catch(() => {});
    if (error instanceof CoordinationRelayStartupError) {
      throw error;
    }
    invalid();
  }
}

const isDirect =
  process.argv[1] !== undefined &&
  resolve(process.argv[1]) ===
    resolve(fileURLToPath(import.meta.url));

if (isDirect) {
  main(process.argv.slice(2)).catch(() => {
    process.stderr.write(
      "COORDINATION_RELAY_STARTUP_INVALID\n",
    );
    process.exitCode = 1;
  });
}
