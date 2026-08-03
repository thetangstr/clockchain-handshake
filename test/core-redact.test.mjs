import assert from "node:assert/strict";
import test from "node:test";

import {
  SENSITIVE_KEY,
  SecretMaterialDetectedError,
  assertSecretFree,
  broadSecretAssignmentPattern,
  highEntropySecretAssignmentPattern,
  redact,
} from "../src/core/redact.mjs";

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

  assert.ok(error instanceof SecretMaterialDetectedError);
  assert.equal(error.code, "SECRET_MATERIAL_DETECTED");
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

  assert.ok(error instanceof SecretMaterialDetectedError);
  assert.equal(error.code, "SECRET_MATERIAL_DETECTED");
  assert.equal(error.message.includes(privateKey), false);
  assert.equal(error.message.includes(bearerToken), false);

  const clean = redact(input);
  assert.equal(clean.keyDiagnostic, `private key: ${REDACTED}`);
  assert.equal(clean.transport, `Authorization: Bearer ${REDACTED}`);
  assert.equal(clean.transactionHash, transactionHash);
  assert.doesNotThrow(() => assertSecretFree(clean));
});

test("detects standalone Clockchain cc_ tokens in whole and embedded strings", () => {
  const token = `cc_${"A".repeat(88)}.${"b".repeat(89)}`;
  const transactionHash = `0x${"12".repeat(32)}`;
  assert.equal(token.length, 181);
  const input = {
    standalone: token,
    embedded: `Clockchain transport rejected ${token} during setup`,
    publicText: "cc_demo",
    transactionHash,
  };
  const error = captureThrow(() => assertSecretFree(input));

  assert.ok(error instanceof SecretMaterialDetectedError);
  assert.equal(error.code, "SECRET_MATERIAL_DETECTED");
  assert.equal(error.message.includes(token), false);

  const clean = redact(input);
  assert.equal(clean.standalone, REDACTED);
  assert.equal(
    clean.embedded,
    `Clockchain transport rejected ${REDACTED} during setup`,
  );
  assert.equal(clean.publicText, input.publicText);
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

test("throws a typed error consumers can match without parsing the message", () => {
  const error = captureThrow(() =>
    assertSecretFree({ privateKey: "wallet-material" }));

  // Deliberately no assertion on the wording: the typed error exists so that
  // consumers stop matching on the message. Only the type, the code, and the
  // absence of the offending value are contractual.
  assert.ok(error instanceof SecretMaterialDetectedError);
  assert.equal(error.name, "SecretMaterialDetectedError");
  assert.equal(error.code, "SECRET_MATERIAL_DETECTED");
  assert.equal(error.message.includes("wallet-material"), false);
});

test("owns the shared high-entropy secret-assignment pattern", () => {
  for (const prose of [
    "Minted a Clockchain token: mcp.clockchain.network",
    "Clockchain token = minted successfully",
    "Result: no secret: material was printed",
    "- Authorization: 100 USD",
    "invite code: none",
    "token: see docs.handshake.example for details",
  ]) {
    assert.equal(
      highEntropySecretAssignmentPattern().test(prose),
      false,
      prose,
    );
  }
  for (const leak of [
    'invitation_code: "aGlnaEVudHJvcHlDbGllbnRUb2tlblZhbHVl"',
    `private_key=0x${"a".repeat(64)}`,
    "ciphertext: 3f9a2b7c1d4e5f60718293a4b5c6d7e8",
    '{"token":"aGlnaEVudHJvcHlDbGllbnRUb2tlblZhbHVl"}',
  ]) {
    assert.equal(
      highEntropySecretAssignmentPattern().test(leak),
      true,
      leak,
    );
  }
});

test("owns a broad secret-assignment pattern for schema-generated documents", () => {
  // Short values the high-entropy floor cannot see. These are exactly the
  // assignments HEAD caught and the entropy floor stopped catching, and they
  // are illegitimate in an exact-key allowlist document at any length.
  for (const leak of [
    "token: abc123",
    "secret: hunter2xy",
    "token=9f8e7d6c5b4a",
    '"invitation_code": "x1"',
    "ciphertext: q",
  ]) {
    assert.equal(
      highEntropySecretAssignmentPattern().test(leak),
      false,
      leak,
    );
    assert.equal(
      broadSecretAssignmentPattern().test(leak),
      true,
      leak,
    );
  }
  // An already-sanitized document still passes, so redaction is not itself
  // grounds for refusing a run.
  for (const sanitized of [
    'private_key: "[REDACTED]"',
    '{"token":"[REDACTED]"}',
    "secret: [REDACTED]",
  ]) {
    assert.equal(
      broadSecretAssignmentPattern().test(sanitized),
      false,
      sanitized,
    );
  }
  // Benign prose DOES trip the broad rule. That is why it is confined to the
  // canonical schema artifacts and never applied to free-form logs.
  assert.equal(
    broadSecretAssignmentPattern().test(
      "Result: no secret: material was printed",
    ),
    true,
  );
});

test("redacts every segment of a JWT-shaped credential", () => {
  const jwt =
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" +
    ".eyJzdWIiOiJoYW5kc2hha2UtZGVtbyIsImlhdCI6MTcwMDAwMDB9" +
    ".c2lnbmF0dXJlU2VnbWVudFRoYXRNdXN0Tm90U3Vydml2ZQ";
  const [header, payload, signature] = jwt.split(".");

  const cleaned = `token: ${jwt}`.replace(
    highEntropySecretAssignmentPattern("gi"),
    "$1[REDACTED]",
  );

  assert.equal(cleaned, `token: ${REDACTED}`);
  for (const segment of [header, payload, signature]) {
    assert.equal(cleaned.includes(segment), false, segment);
  }
});

test("redacts email addresses in strings and inside structures", () => {
  const input = {
    clientId: "codex.agent@handshake.example",
    note: "peer record for Claude.Agent+demo@handshake.example arrived",
    nested: ["contact: operator@sub.handshake.example"],
    publicText: "no address here",
  };

  const clean = redact(input);

  assert.equal(clean.clientId, REDACTED);
  assert.equal(
    clean.note,
    `peer record for ${REDACTED} arrived`,
  );
  assert.equal(clean.nested[0], `contact: ${REDACTED}`);
  assert.equal(clean.publicText, input.publicText);
  assert.doesNotThrow(() => assertSecretFree(clean));
});

test("detects an email address as secret material", () => {
  const error = captureThrow(() =>
    assertSecretFree({
      record: "walletId codex.agent@handshake.example",
    }));

  assert.ok(error instanceof SecretMaterialDetectedError);
  assert.equal(
    error.message.includes("codex.agent@handshake.example"),
    false,
  );
});

test("keeps non-email at-signs and versioned specifiers readable", () => {
  const value = {
    dependency: "@anthropic-ai/sdk@1.2.3",
    handle: "ping @operator about the run",
    path: "/tmp/handshake@demo/result.json",
  };

  assert.deepEqual(redact(value), value);
  assert.doesNotThrow(() => assertSecretFree(value));
});
