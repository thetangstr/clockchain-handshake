import assert from "node:assert/strict";
import test from "node:test";

import {
  SENSITIVE_KEY,
  assertSecretFree,
  redact,
} from "../src/redact.mjs";

const REDACTED = "[REDACTED]";

function captureThrow(operation) {
  let thrown;

  try {
    operation();
  } catch (error) {
    thrown = error;
  }

  assert.ok(thrown instanceof Error, "expected operation to throw");
  return thrown;
}

test("recursively redacts sensitive keys while preserving structure", () => {
  const input = {
    nested: {
      privateKey: "wallet-material",
      token: "clockchain-token",
      inviteCode: "invitation-code",
      safe: "public",
    },
    entries: [{ ciphertext: "encrypted-but-sensitive-in-output" }],
  };
  const snapshot = structuredClone(input);

  assert.equal(
    SENSITIVE_KEY.source,
    "private.?key|secret|token|authorization|invite.?code|ciphertext",
  );
  assert.equal(SENSITIVE_KEY.flags, "i");
  assert.deepEqual(redact(input), {
    nested: {
      privateKey: REDACTED,
      token: REDACTED,
      inviteCode: REDACTED,
      safe: "public",
    },
    entries: [{ ciphertext: REDACTED }],
  });
  assert.deepEqual(input, snapshot);
});

test("redacts exact canaries inside longer strings and detects unsanitized canaries", () => {
  const canary = "CANARY.exact+$";
  const input = {
    message: `prefix-${canary}-middle-${canary}-suffix`,
  };
  const error = captureThrow(() => assertSecretFree(input, [canary]));

  assert.match(error.message, /secret material detected/i);
  assert.equal(error.message.includes(canary), false);

  const clean = redact(input, [canary]);
  assert.equal(
    clean.message,
    `prefix-${REDACTED}-middle-${REDACTED}-suffix`,
  );
  assert.doesNotThrow(() => assertSecretFree(clean, [canary]));
  assert.throws(() => redact(input, [""]), /nonempty/i);
  assert.throws(() => assertSecretFree(input, [""]), /nonempty/i);
});

test("handles arrays, Errors, bigint, and non-plain scalars without mutation", () => {
  const canary = "ERROR_SECRET_CANARY";
  const diagnostic = new Error(`request failed: ${canary}`);
  diagnostic.name = "ClockchainTransportError";
  diagnostic.stack = `ClockchainTransportError: ${canary}\n    at test`;
  diagnostic.details = {
    authorization: "Bearer clockchain_live_abcdefghijklmnop",
    retryable: false,
  };
  const timestamp = new Date("2026-07-22T00:00:00.000Z");
  const input = {
    values: [1n, diagnostic, timestamp, null, true, 42],
    total: 2n,
  };

  const clean = redact(input, [canary]);

  assert.notEqual(clean, input);
  assert.notEqual(clean.values, input.values);
  assert.equal(clean.values[0], 1n);
  assert.equal(clean.total, 2n);
  assert.equal(clean.values[2], timestamp);
  assert.deepEqual(clean.values[1], {
    name: "ClockchainTransportError",
    message: `request failed: ${REDACTED}`,
    stack: `ClockchainTransportError: ${REDACTED}\n    at test`,
    details: {
      authorization: REDACTED,
      retryable: false,
    },
  });
  assert.doesNotThrow(() => JSON.stringify(clean.values[1]));
  assert.equal(diagnostic.message, `request failed: ${canary}`);
  assert.equal(diagnostic.details.authorization.includes("clockchain_live_"), true);
  assert.doesNotThrow(() => assertSecretFree(clean, [canary]));
});

test("detects labeled private keys and bearer tokens without treating transaction hashes as secrets", () => {
  const privateKey = `0x${"ab".repeat(32)}`;
  const bearerToken = "clockchain_live_abcdefghijklmnopqrstuv";
  const transactionHash = `0x${"cd".repeat(32)}`;
  const input = {
    keyDiagnostic: `private key: ${privateKey}`,
    transport: `Authorization: Bearer ${bearerToken}`,
    transactionHash,
  };
  const error = captureThrow(() => assertSecretFree(input));

  assert.match(error.message, /secret material detected/i);
  assert.equal(error.message.includes(privateKey), false);
  assert.equal(error.message.includes(bearerToken), false);

  const clean = redact(input);
  assert.equal(clean.keyDiagnostic, `private key: ${REDACTED}`);
  assert.equal(clean.transport, `Authorization: Bearer ${REDACTED}`);
  assert.equal(clean.transactionHash, transactionHash);
  assert.doesNotThrow(() => assertSecretFree(clean));
});

test("accepts a sanitized object without false positives", () => {
  const publicTransactionHash = `0x${"ef".repeat(32)}`;
  const value = {
    privateKey: REDACTED,
    nested: [
      {
        authorization: REDACTED,
        transactionHash: publicTransactionHash,
      },
    ],
    message: "public Clockchain evidence",
  };

  assert.doesNotThrow(() => assertSecretFree(value));
});
