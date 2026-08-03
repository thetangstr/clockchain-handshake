import {
  constants as fsConstants,
} from "node:fs";
import {
  open,
  readFile,
} from "node:fs/promises";
import { types } from "node:util";

import { createPublicClient, http } from "viem";
import { privateKeyToAccount } from "viem/accounts";

import {
  createMcpClient,
  mintDemoToken,
} from "../core/clockchain.mjs";
import {
  RPC_URL,
} from "../core/constants.mjs";
import {
  ERC8004_ABI,
} from "../core/registration.mjs";

// Shared plumbing for the role shells. Private keys come from 0600
// files only — never from the environment, never from an OS-specific
// secret store. All cross-process waits are unbounded with heartbeat
// (human-paced) or bounded by a caller-computed in-window deadline.

export const RELAY_POLL_WAIT_MS = 25_000;
export const HEARTBEAT_INTERVAL_MS = 15_000;

const MAX_PRIVATE_KEY_FILE_BYTES = 256;
const PRIVATE_KEY_PATTERN = /^(0x)?[0-9a-f]{64}$/;

export class RoleShellError extends Error {
  constructor(code) {
    super(`Role shell failure: ${code}`);
    this.name = "RoleShellError";
    this.code = code;
  }
}

function shellFailure(code) {
  throw new RoleShellError(code);
}

export async function loadPrivateKeyHex(path) {
  if (typeof path !== "string" || path.length === 0) {
    shellFailure("KEY_PATH");
  }
  let handle;
  try {
    handle = await open(
      path,
      fsConstants.O_RDONLY |
        (fsConstants.O_NOFOLLOW ?? 0),
    );
    const stat = await handle.stat();
    if (
      !stat.isFile() ||
      (stat.mode & 0o777) !== 0o600 ||
      stat.size === 0 ||
      stat.size > MAX_PRIVATE_KEY_FILE_BYTES
    ) {
      shellFailure("KEY_FILE_SECURITY");
    }
    const raw = await handle.readFile("utf8");
    const trimmed = raw.trim();
    if (!PRIVATE_KEY_PATTERN.test(trimmed)) {
      shellFailure("KEY_FILE_SHAPE");
    }
    return trimmed.startsWith("0x")
      ? trimmed
      : `0x${trimmed}`;
  } catch (error) {
    if (error instanceof RoleShellError) throw error;
    shellFailure("KEY_FILE_UNREADABLE");
  } finally {
    if (handle !== undefined) {
      await handle.close().catch(() => {});
    }
  }
}

export function accountFromPrivateKeyHex(privateKeyHex) {
  try {
    return privateKeyToAccount(privateKeyHex);
  } catch {
    shellFailure("KEY_INVALID");
  }
}

export function signerFromAccount(account) {
  return (bytes) =>
    account.signMessage({ message: { raw: bytes } });
}

export async function connectClockchain(options = {}) {
  const { fetchImpl, subject } = options;
  const token = await mintDemoToken({
    ...(fetchImpl === undefined ? {} : { fetchImpl }),
    ...(subject === undefined ? {} : { subject }),
  });
  return createMcpClient({
    token,
    ...(fetchImpl === undefined ? {} : { fetchImpl }),
  });
}

export function createOwnerOf(options = {}) {
  const { rpcUrl = RPC_URL, publicClient } = options;
  const client =
    publicClient ??
    createPublicClient({ transport: http(rpcUrl) });
  return async ({ agentId, registry }) => {
    let owner;
    try {
      owner = await client.readContract({
        address: registry,
        abi: ERC8004_ABI,
        functionName: "ownerOf",
        args: [BigInt(agentId)],
      });
    } catch {
      shellFailure("OWNER_LOOKUP_FAILED");
    }
    if (typeof owner !== "string") {
      shellFailure("OWNER_LOOKUP_FAILED");
    }
    return owner.toLowerCase();
  };
}

// Long-poll loop over relay messages. Unbounded by default: the
// human-paced phases rely on the heartbeat, and in-window callers pass
// deadlineMs computed through assertInWindowPollBound.
export async function waitForRelayMessage({
  relay,
  sessionId,
  kinds,
  startAfter = 0,
  deadlineMs,
  onPoll,
}) {
  if (
    !Array.isArray(kinds) ||
    kinds.length === 0 ||
    kinds.some((kind) => typeof kind !== "string")
  ) {
    shellFailure("WAIT_INPUT");
  }
  let cursor = startAfter;
  for (;;) {
    if (
      deadlineMs !== undefined &&
      Date.now() >= deadlineMs
    ) {
      shellFailure("WAIT_DEADLINE");
    }
    const page = await relay.pollMessages({
      sessionId,
      after: cursor,
      waitMs: RELAY_POLL_WAIT_MS,
    });
    if (
      !isPlainObject(page) ||
      !Array.isArray(page.messages) ||
      typeof page.next !== "number"
    ) {
      shellFailure("WAIT_RELAY_RESPONSE");
    }
    cursor = page.next;
    const match = page.messages.find(
      (message) =>
        isPlainObject(message) &&
        kinds.includes(message.kind),
    );
    if (onPoll !== undefined) {
      await onPoll({
        cursor,
        polledAtMs: Date.now(),
      });
    }
    if (match !== undefined) {
      return Object.freeze({
        cursor,
        message: match,
      });
    }
  }
}

function isPlainObject(value) {
  return (
    value !== null &&
    typeof value === "object" &&
    !Array.isArray(value) &&
    !types.isProxy(value)
  );
}

export function createStatusReporter({
  relay,
  sessionId,
  role,
}) {
  return {
    async report(phase, detail = {}) {
      await relay.putStatus(sessionId, role, {
        phase,
        paymentMoved: false,
        updatedAtMs: String(Date.now()),
        ...detail,
      });
    },
  };
}

// Periodic status heartbeat for human-paced waits. The returned handle
// must be stopped with clearInterval semantics via .stop().
export function startHeartbeat(reporter, phase, detail = {}) {
  const timer = setInterval(() => {
    reporter.report(phase, detail).catch(() => {});
  }, HEARTBEAT_INTERVAL_MS);
  timer.unref();
  return {
    stop() {
      clearInterval(timer);
    },
  };
}

export function emitStatus(stdout, code, fields = {}) {
  stdout.write(
    `STATUS ${code} ${JSON.stringify({
      paymentMoved: false,
      ...fields,
    })}\n`,
  );
}

export async function readJsonFile(path, maxBytes) {
  let raw;
  try {
    raw = await readFile(path, "utf8");
  } catch {
    shellFailure("FILE_UNREADABLE");
  }
  if (Buffer.byteLength(raw, "utf8") > maxBytes) {
    shellFailure("FILE_TOO_LARGE");
  }
  try {
    return JSON.parse(raw);
  } catch {
    shellFailure("FILE_BAD_JSON");
  }
}
