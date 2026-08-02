import {
  constants as fsConstants,
} from "node:fs";
import {
  lstat,
  open,
} from "node:fs/promises";
import { resolve } from "node:path";

import {
  validateBootstrapState,
} from "../../../src/bilateral/aws/bootstrap-state.mjs";

const CONFIG_KEYS = Object.freeze([
  "bootstrapStatePath",
  "nowMs",
  "paymentMoved",
  "releaseId",
  "repositorySha",
  "sessionId",
]);
const INPUT_KEYS = Object.freeze([
  "releaseId",
  "sessionId",
  "state",
]);
const SHA40 = /^[0-9a-f]{40}$/;
const SHA64 = /^[0-9a-f]{64}$/;
const RELEASE = /^release-[0-9a-f]{16}$/;
const SESSION =
  /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const MAX_BYTES = 262_144;

export class AwsOperatorBootstrapFingerprintReaderError extends Error {
  constructor() {
    super(
      "AWS operator bootstrap fingerprint reader failed safely.",
    );
    this.name =
      "AwsOperatorBootstrapFingerprintReaderError";
    this.code =
      "AWS_OPERATOR_BOOTSTRAP_FINGERPRINT_READER_INVALID";
    this.category = "verification";
  }
}

function fail() {
  throw new AwsOperatorBootstrapFingerprintReaderError();
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

function config(value) {
  const input = exact(value, CONFIG_KEYS);
  if (
    typeof input.bootstrapStatePath !==
      "string" ||
    resolve(input.bootstrapStatePath) !==
      input.bootstrapStatePath ||
    typeof input.nowMs !== "function" ||
    input.paymentMoved !== false ||
    !RELEASE.test(input.releaseId) ||
    !SHA40.test(input.repositorySha) ||
    !SESSION.test(input.sessionId)
  ) {
    fail();
  }
  return Object.freeze({ ...input });
}

function expectedRole(input) {
  if (input.state.status === "RUN_STARTED") {
    return "payer";
  }
  if (input.state.status === "PAYER_APPROVED") {
    return "requestor";
  }
  return null;
}

async function readStableJson(path) {
  const before = await lstat(path);
  if (
    !before.isFile() ||
    before.isSymbolicLink() ||
    before.nlink !== 1 ||
    before.size <= 0 ||
    before.size > MAX_BYTES
  ) {
    fail();
  }
  let handle;
  try {
    handle = await open(
      path,
      fsConstants.O_RDONLY |
        (fsConstants.O_NOFOLLOW ?? 0) |
        fsConstants.O_NONBLOCK,
    );
    const opened = await handle.stat();
    if (
      opened.dev !== before.dev ||
      opened.ino !== before.ino ||
      opened.size !== before.size
    ) {
      fail();
    }
    return JSON.parse(
      (await handle.readFile()).toString("utf8"),
    );
  } finally {
    await handle?.close();
  }
}

export function createAwsOperatorBootstrapFingerprintReader(
  value,
  dependencies = {},
) {
  try {
    const active = config(value);
    const readJson =
      dependencies.readStableJson ?? readStableJson;
    if (typeof readJson !== "function") fail();
    return Object.freeze({
      async readExpectedClaimFingerprint(input) {
        try {
          const data = exact(input, INPUT_KEYS);
          if (
            data.releaseId !== active.releaseId ||
            data.sessionId !== active.sessionId ||
            data.state === null ||
            typeof data.state !== "object" ||
            Array.isArray(data.state)
          ) {
            fail();
          }
          const role = expectedRole(data);
          if (role === null) return null;
          const nowMs = active.nowMs();
          if (
            !Number.isSafeInteger(nowMs) ||
            nowMs < 0
          ) {
            fail();
          }
          const state = validateBootstrapState(
            await readJson(
              active.bootstrapStatePath,
            ),
          );
          if (
            state.releaseId !== active.releaseId ||
            state.repositorySha !==
              active.repositorySha ||
            state.sessionId !== active.sessionId ||
            state.paymentMoved !== false
          ) {
            fail();
          }
          const matches = Object.values(state.claims)
            .filter(
              (entry) =>
                entry.role === role &&
                ["PENDING", "APPROVED"].includes(
                  entry.status,
                ) &&
                Number(entry.expiresAtMs) > nowMs,
            );
          if (matches.length === 0) return null;
          if (matches.length !== 1) fail();
          const fingerprint =
            matches[0].claimFingerprint;
          if (!SHA64.test(fingerprint)) fail();
          return fingerprint;
        } catch (error) {
          if (
            error instanceof
            AwsOperatorBootstrapFingerprintReaderError
          ) {
            throw error;
          }
          fail();
        }
      },
    });
  } catch (error) {
    if (
      error instanceof
      AwsOperatorBootstrapFingerprintReaderError
    ) {
      throw error;
    }
    fail();
  }
}
