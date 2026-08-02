import {
  constants as fsConstants,
} from "node:fs";
import {
  open,
  readFile,
  mkdir,
  rename,
  rm,
} from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { types } from "node:util";

import {
  tombstoneTunnelGrant,
  validateTunnelGrantRecord,
} from "../../../src/bilateral/aws/tunnel-grant.mjs";
import {
  canonicalizeReceiptEventValue,
} from "../../../src/canonical.mjs";

const CONFIG_KEYS = Object.freeze([
  "abortMarkerPath",
  "nowMs",
  "paymentMoved",
  "releaseId",
  "repositorySha",
  "sessionId",
  "tunnelGrantPath",
]);
const INPUT_KEYS = Object.freeze([
  "actionId",
  "expectedRevision",
  "paymentMoved",
  "releaseId",
  "repositorySha",
  "sessionId",
]);
const ABORT_MARKER_KEYS = Object.freeze([
  "actionId",
  "expectedRevision",
  "paymentMoved",
  "releaseId",
  "repositorySha",
  "schema",
  "sessionId",
  "status",
  "terminalAtMs",
  "tunnelGrantPath",
]);
const RELEASE = /^release-[0-9a-f]{16}$/;
const SESSION =
  /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const SHA40 = /^[0-9a-f]{40}$/;
const UUID = SESSION;
const IDEMPOTENT_ABORT_TERMINAL_REASONS =
  new Set(["ABORT", "EXPIRED"]);

export class AwsOperatorAbortAdapterError extends Error {
  constructor() {
    super(
      "AWS operator abort adapter failed safely.",
    );
    this.name =
      "AwsOperatorAbortAdapterError";
    this.code =
      "AWS_OPERATOR_ABORT_ADAPTER_INVALID";
    this.category = "verification";
  }
}

function fail() {
  throw new AwsOperatorAbortAdapterError();
}

function exact(value, keys) {
  if (
    value === null ||
    typeof value !== "object" ||
    Array.isArray(value) ||
    types.isProxy(value) ||
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

function canonicalBytes(value) {
  return Buffer.from(
    JSON.stringify(
      canonicalizeReceiptEventValue(value),
    ),
    "utf8",
  );
}

function validateConfig(value) {
  const input = exact(value, CONFIG_KEYS);
  if (
    typeof input.nowMs !== "function" ||
    input.paymentMoved !== false ||
    !RELEASE.test(input.releaseId) ||
    !SHA40.test(input.repositorySha) ||
    !SESSION.test(input.sessionId) ||
    typeof input.abortMarkerPath !== "string" ||
    resolve(input.abortMarkerPath) !==
      input.abortMarkerPath ||
    typeof input.tunnelGrantPath !== "string" ||
    resolve(input.tunnelGrantPath) !==
      input.tunnelGrantPath
  ) {
    fail();
  }
  return Object.freeze({ ...input });
}

function validateInput(value, active) {
  const input = exact(value, INPUT_KEYS);
  if (
    !UUID.test(input.actionId) ||
    !Number.isSafeInteger(
      input.expectedRevision,
    ) ||
    input.expectedRevision < 0 ||
    input.paymentMoved !== false ||
    input.releaseId !== active.releaseId ||
    input.repositorySha !==
      active.repositorySha ||
    input.sessionId !== active.sessionId
  ) {
    fail();
  }
}

async function writeReplacement(path, bytes) {
  const temporary = `${path}.abort.next`;
  let handle;
  try {
    await mkdir(dirname(path), {
      recursive: true,
      mode: 0o700,
    });
    handle = await open(
      temporary,
      fsConstants.O_WRONLY |
        fsConstants.O_CREAT |
        fsConstants.O_EXCL |
        (fsConstants.O_NOFOLLOW ?? 0),
      0o600,
    );
    await handle.write(bytes, 0, bytes.length, 0);
    await handle.sync();
    await handle.close();
    handle = undefined;
    await rename(temporary, path);
    const dir = await open(
      dirname(path),
      fsConstants.O_RDONLY,
    );
    try {
      await dir.sync();
    } finally {
      await dir.close();
    }
  } catch (error) {
    await handle?.close().catch(() => {});
    await rm(temporary, {
      force: true,
    }).catch(() => {});
    throw error;
  }
}

function abortMarker(active, input, terminalAtMs) {
  return Object.freeze({
    actionId: input.actionId,
    expectedRevision: input.expectedRevision,
    paymentMoved: false,
    releaseId: active.releaseId,
    repositorySha: active.repositorySha,
    schema:
      "clockchain.aws-operator-abort-marker/v1",
    sessionId: active.sessionId,
    status: "ABORTED",
    terminalAtMs,
    tunnelGrantPath: active.tunnelGrantPath,
  });
}

function validateAbortMarker(value, active, input) {
  const marker = exact(value, ABORT_MARKER_KEYS);
  if (
    marker.actionId !== input.actionId ||
    marker.expectedRevision !==
      input.expectedRevision ||
    marker.paymentMoved !== false ||
    marker.releaseId !== active.releaseId ||
    marker.repositorySha !==
      active.repositorySha ||
    marker.schema !==
      "clockchain.aws-operator-abort-marker/v1" ||
    marker.sessionId !== active.sessionId ||
    marker.status !== "ABORTED" ||
    !Number.isSafeInteger(marker.terminalAtMs) ||
    marker.terminalAtMs < 0 ||
    marker.tunnelGrantPath !==
      active.tunnelGrantPath
  ) {
    fail();
  }
  return marker;
}

function isActiveGrantExpired(grant, nowMs) {
  return nowMs >= Number(grant.expiresAtMs);
}

function isSameActiveContext(record, active) {
  return (
    record.releaseId === active.releaseId &&
    record.repositorySha === active.repositorySha &&
    record.sessionId === active.sessionId
  );
}

async function writeAbortMarker(active, input, terminalAtMs) {
  const marker = abortMarker(active, input, terminalAtMs);
  try {
    const existing = validateAbortMarker(
      JSON.parse(
        await readFile(
          active.abortMarkerPath,
          "utf8",
        ),
      ),
      active,
      input,
    );
    if (
      JSON.stringify(
        canonicalizeReceiptEventValue(existing),
      ) !==
      JSON.stringify(
        canonicalizeReceiptEventValue(marker),
      )
    ) {
      fail();
    }
    return;
  } catch (error) {
    if (error?.code !== "ENOENT") {
      throw error;
    }
  }
  await writeReplacement(
    active.abortMarkerPath,
    canonicalBytes(marker),
  );
}

export function createAwsOperatorAbortAdapter(
  value,
) {
  try {
    const active = validateConfig(value);
    return Object.freeze({
      async abort(input) {
        try {
          validateInput(input, active);
          const nowMs = active.nowMs();
          if (
            !Number.isSafeInteger(nowMs) ||
            nowMs < 0
          ) {
            fail();
          }
          let existing;
          try {
            existing = validateTunnelGrantRecord(
              JSON.parse(
                await readFile(
                  active.tunnelGrantPath,
                  "utf8",
                ),
              ),
            );
          } catch (error) {
            if (error?.code === "ENOENT") {
              await writeAbortMarker(
                active,
                input,
                nowMs,
              );
              return Object.freeze({
                paymentMoved: false,
                status: "ABORTED",
              });
            }
            throw error;
          }
          if (
            existing.status === "TOMBSTONED" &&
            IDEMPOTENT_ABORT_TERMINAL_REASONS.has(
              existing.terminalReason,
            ) &&
            isSameActiveContext(existing, active)
          ) {
            await writeAbortMarker(
              active,
              input,
              nowMs,
            );
            return Object.freeze({
              paymentMoved: false,
              status: "ABORTED",
            });
          }
          if (existing.status === "TOMBSTONED") {
            fail();
          }
          const tombstone =
            tombstoneTunnelGrant({
              activeGrant: existing,
              nowMs,
              reason: isActiveGrantExpired(
                existing,
                nowMs,
              )
                ? "EXPIRED"
                : "ABORT",
            });
          if (
            tombstone.releaseId !== active.releaseId ||
            tombstone.repositorySha !==
              active.repositorySha ||
            tombstone.sessionId !== active.sessionId
          ) {
            fail();
          }
          await writeReplacement(
            active.tunnelGrantPath,
            canonicalBytes(tombstone),
          );
          await writeAbortMarker(
            active,
            input,
            nowMs,
          );
          return Object.freeze({
            paymentMoved: false,
            status: "ABORTED",
          });
        } catch (error) {
          if (
            error instanceof
            AwsOperatorAbortAdapterError
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
      AwsOperatorAbortAdapterError
    ) {
      throw error;
    }
    fail();
  }
}
