import {
  GetObjectCommand,
  PutObjectCommand,
} from "@aws-sdk/client-s3";
import {
  createHash,
} from "node:crypto";
import {
  readFile as nodeReadFile,
} from "node:fs/promises";
import {
  dirname,
  resolve,
} from "node:path";

import {
  publishAwsPublicMonitor,
} from "../../../scripts/publish-aws-public-monitor.mjs";

const CONFIG_KEYS = Object.freeze([
  "bucketName",
  "paymentMoved",
  "publicBaseUrl",
  "publicationInputPath",
  "schema",
  "stagedPaths",
]);
const STAGED_KEYS = Object.freeze([
  "certificate",
  "payerDiscovery",
  "publicationGate",
  "requestorDiscovery",
]);
const BUCKET =
  /^(?!xn--)(?!.*\.\.)(?!.*\.$)[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$/;
const MAX_FILE_BYTES = 262_144;

export class AwsPublisherRuntimeError extends Error {
  constructor() {
    super("AWS publisher runtime failed safely.");
    this.name = "AwsPublisherRuntimeError";
    this.code = "AWS_PUBLISHER_RUNTIME_INVALID";
    this.category = "verification";
  }
}

function fail() {
  throw new AwsPublisherRuntimeError();
}

function exact(value, keys) {
  if (
    value === null ||
    typeof value !== "object" ||
    Array.isArray(value) ||
    Object.getPrototypeOf(value) !==
      Object.prototype ||
    Reflect.ownKeys(value).length !==
      keys.length ||
    keys.some(
      (key, index) =>
        Reflect.ownKeys(value)[index] !== key,
    )
  ) {
    fail();
  }
  return value;
}

function safePath(value, root = null) {
  if (
    typeof value !== "string" ||
    !value.startsWith("/") ||
    resolve(value) !== value ||
    value.includes("\0") ||
    (
      root !== null &&
      value !== root &&
      !value.startsWith(`${root}/`)
    )
  ) {
    fail();
  }
  return value;
}

function config(value) {
  const input = exact(value, CONFIG_KEYS);
  if (
    !BUCKET.test(input.bucketName) ||
    input.paymentMoved !== false ||
    input.schema !==
      "clockchain.aws-publisher-runtime/v1"
  ) {
    fail();
  }
  let url;
  try {
    url = new URL(input.publicBaseUrl);
  } catch {
    fail();
  }
  if (
    url.protocol !== "https:" ||
    url.username !== "" ||
    url.password !== "" ||
    url.pathname !== "/" ||
    url.search !== "" ||
    url.hash !== ""
  ) {
    fail();
  }
  const publicationInputPath = safePath(
    input.publicationInputPath,
  );
  const root = dirname(
    publicationInputPath,
  );
  const staged = exact(
    input.stagedPaths,
    STAGED_KEYS,
  );
  for (const key of STAGED_KEYS) {
    safePath(staged[key], root);
  }
  return input;
}

async function readCanonicalJson(
  readFile,
  path,
) {
  const bytes = await readFile(path);
  if (
    !Buffer.isBuffer(bytes) ||
    bytes.length === 0 ||
    bytes.length > MAX_FILE_BYTES
  ) {
    fail();
  }
  const text = bytes.toString("utf8");
  let value;
  try {
    value = JSON.parse(
      text.endsWith("\n")
        ? text.slice(0, -1)
        : "",
    );
  } catch {
    fail();
  }
  if (
    `${JSON.stringify(value)}\n` !== text
  ) {
    fail();
  }
  return value;
}

async function bodyText(body) {
  if (
    body === undefined ||
    typeof body.transformToString !==
      "function"
  ) {
    fail();
  }
  const text =
    await body.transformToString("utf-8");
  if (
    typeof text !== "string" ||
    Buffer.byteLength(text, "utf8") >
      MAX_FILE_BYTES
  ) {
    fail();
  }
  return text;
}

export async function runAwsPublisherOnce(
  value,
  dependencies = {},
) {
  try {
    const input = config(value);
    const publish =
      dependencies.publish ??
      publishAwsPublicMonitor;
    const readFile =
      dependencies.readFile ?? nodeReadFile;
    const s3 = dependencies.s3;
    const writeRecord =
      dependencies.writeRecord;
    if (
      typeof publish !== "function" ||
      typeof readFile !== "function" ||
      s3 === null ||
      typeof s3 !== "object" ||
      typeof s3.send !== "function" ||
      typeof writeRecord !== "function"
    ) {
      fail();
    }
    const publication =
      await readCanonicalJson(
        readFile,
        input.publicationInputPath,
      );
    return await publish(publication, {
      publicObjectUrl: (key) =>
        new URL(
          key,
          input.publicBaseUrl,
        ).href,
      async putObject({
        body,
        cacheControl,
        contentType,
        ifMatch,
        ifNoneMatch,
        key,
      }) {
        let result;
        try {
          result = await s3.send(
            new PutObjectCommand({
              Body: body,
              Bucket: input.bucketName,
              CacheControl: cacheControl,
              ContentType: contentType,
              ...(ifMatch === undefined
                ? {}
                : { IfMatch: ifMatch }),
              ...(ifNoneMatch === undefined
                ? {}
                : {
                    IfNoneMatch:
                      ifNoneMatch,
                  }),
              Key: key,
            }),
          );
        } catch (error) {
          const preconditionFailed =
            ifNoneMatch === "*" &&
            (
              error?.name ===
                "PreconditionFailed" ||
              error?.code ===
                "PreconditionFailed" ||
              error?.$metadata
                ?.httpStatusCode === 412
            );
          if (!preconditionFailed) throw error;
          const existing = await s3.send(
            new GetObjectCommand({
              Bucket: input.bucketName,
              Key: key,
            }),
          );
          if (
            await bodyText(existing.Body) !== body ||
            existing.CacheControl !==
              cacheControl ||
            existing.ContentType !==
              contentType ||
            typeof existing.ETag !== "string"
          ) {
            fail();
          }
          result = existing;
        }
        return {
          etag: result.ETag,
          ...(result.VersionId === undefined
            ? {}
            : {
                versionId:
                  result.VersionId,
              }),
        };
      },
      async readIndex() {
        try {
          const result = await s3.send(
            new GetObjectCommand({
              Bucket: input.bucketName,
              Key: "runs/index.json",
            }),
          );
          return {
            body: await bodyText(
              result.Body,
            ),
            etag: result.ETag,
          };
        } catch (error) {
          if (
            error?.name ===
              "NoSuchKey" ||
            error?.$metadata
              ?.httpStatusCode === 404
          ) {
            return null;
          }
          throw error;
        }
      },
      readPublicationGate: () =>
        readCanonicalJson(
          readFile,
          input.stagedPaths
            .publicationGate,
        ),
      async readStagedPublicObject(name) {
        if (
          ![
            "certificate",
            "payerDiscovery",
            "requestorDiscovery",
          ].includes(name)
        ) {
          fail();
        }
        const bytes = await readFile(
          input.stagedPaths[name],
        );
        if (
          !Buffer.isBuffer(bytes) ||
          bytes.length === 0 ||
          bytes.length > MAX_FILE_BYTES
        ) {
          fail();
        }
        return {
          body: bytes.toString("utf8"),
          contentType:
            name === "certificate"
              ? "application/x-pem-file"
              : "application/json",
        };
      },
      writePublicationRecord: writeRecord,
    });
  } catch (error) {
    if (
      error instanceof
      AwsPublisherRuntimeError
    ) {
      throw error;
    }
    fail();
  }
}

export async function runAwsPublisherLoop(
  value,
  {
    intervalMs = 2_000,
    readFile = nodeReadFile,
    signal,
    ...dependencies
  } = {},
) {
  if (
    !Number.isSafeInteger(intervalMs) ||
    intervalMs < 250 ||
    intervalMs > 60_000 ||
    typeof readFile !== "function"
  ) {
    fail();
  }
  const input = config(value);
  let priorDigest = null;
  while (signal?.aborted !== true) {
    let bytes;
    try {
      bytes = await readFile(
        input.publicationInputPath,
      );
    } catch (error) {
      if (error?.code !== "ENOENT") {
        fail();
      }
      await waitForNext(intervalMs, signal);
      continue;
    }
    if (
      !Buffer.isBuffer(bytes) ||
      bytes.length === 0 ||
      bytes.length > MAX_FILE_BYTES
    ) {
      fail();
    }
    const digest = createHash("sha256")
      .update(bytes)
      .digest("hex");
    if (digest !== priorDigest) {
      await runAwsPublisherOnce(input, {
        ...dependencies,
        readFile,
      });
      priorDigest = digest;
    }
    await waitForNext(intervalMs, signal);
  }
}

function waitForNext(intervalMs, signal) {
  return new Promise((resolvePromise) => {
    if (signal?.aborted === true) {
      resolvePromise();
      return;
    }
    let settled = false;
    const finish = () => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      signal?.removeEventListener(
        "abort",
        finish,
      );
      resolvePromise();
    };
    const timer = setTimeout(finish, intervalMs);
    signal?.addEventListener(
      "abort",
      finish,
      { once: true },
    );
  });
}
