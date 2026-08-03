#!/usr/bin/env node

// Fresh verifier CLI (G1a). The operator spawns this process only
// after both party evidence triples are present on the relay. It
// re-reads every signed artifact from the relay, performs the
// slot-order pre-check (this file is the declared REORDERED emission
// site), runs the proven core verifier against a fresh chain
// connection, signs the resulting verdict with the operator Ed25519
// key, and publishes it back to the relay.
//
// The gated outcome word never appears in this file: the verdict
// object arrives fully formed from src/core/verdict.mjs and is passed
// through unchanged. Process freshness is the security argument — no
// operator or party state is shared with this process beyond the
// relay contents and the public chain.

import {
  createPrivateKey,
  createPublicKey,
  sign,
} from "node:crypto";
import {
  mkdir,
  readFile,
  writeFile,
} from "node:fs/promises";
import {
  dirname,
  join,
  resolve,
  sep,
} from "node:path";
import { fileURLToPath } from "node:url";
import {
  parseArgs,
  types,
} from "node:util";

import { canonicalBytes } from "../core/canonical.mjs";
import { McpRateLimitedError } from "../core/clockchain.mjs";
import {
  dSession,
  KEY_ID_PATTERN,
} from "../core/descriptor.mjs";
import {
  SESSION_SLOTS,
  sessionKey,
} from "../core/refid.mjs";
import {
  BilateralVerdictError,
  renderBilateralVerdictMarkdown,
  VERDICT_SCHEMA,
  verifyBilateralAuthorization,
  verifyRehearsal,
} from "../core/verdict.mjs";
import {
  createRelayClient,
  RelayClientError,
} from "../relay/client.mjs";
import {
  CatalogError,
  exactlyOneFrom,
  RELAY_KINDS,
} from "../roles/catalog.mjs";
import {
  connectClockchain,
  createOwnerOf,
} from "../roles/common.mjs";

export const VERDICT_DOCUMENT_SCHEMA = "handshake-verdict/v2";
export const SUBJECT_RUNS = Object.freeze([
  "stakeholder",
  "rehearsal",
]);

const REPO_ROOT = resolve(
  dirname(fileURLToPath(import.meta.url)),
  "..",
  "..",
);
const OPERATOR_KEY_DIRECTORY = join(
  "docs",
  "operator-keys",
);

export class VerifierRunError extends Error {
  constructor(code) {
    super(`Verifier run failure: ${code}`);
    this.name = "VerifierRunError";
    this.code = code;
  }
}

function failure(code = "FAILED") {
  throw new VerifierRunError(code);
}

function verdictFailure(code = "FAILED") {
  throw new BilateralVerdictError(code);
}

function isPlainObject(value) {
  return (
    value !== null &&
    typeof value === "object" &&
    !Array.isArray(value) &&
    !types.isProxy(value)
  );
}

// Pull every message for the session. The operator only invokes this
// process once the session is complete, so non-blocking pages are
// sufficient; the loop stops at the first short page.
async function collectMessages(relay, sessionId) {
  const messages = [];
  let cursor = 0;
  for (;;) {
    const page = await relay.pollMessages({
      after: cursor,
      sessionId,
      waitMs: 0,
    });
    if (
      !isPlainObject(page) ||
      !Array.isArray(page.messages) ||
      typeof page.next !== "number"
    ) {
      verdictFailure("FAILED");
    }
    messages.push(...page.messages);
    if (page.messages.length === 0 || page.next <= cursor) {
      break;
    }
    cursor = page.next;
  }
  return messages;
}

// Exactly one copy of the signed artifact from the expected role; a
// divergent second copy or an absent artifact fails closed with the
// same public code the on-chain verifier would have emitted.
function extractEnvelope(messages, kind, role) {
  let message;
  try {
    message = exactlyOneFrom(messages, kind, role);
  } catch (error) {
    if (error instanceof CatalogError) {
      verdictFailure(
        error.code === "DUPLICATE" ? "DUPLICATE" : "MALFORMED",
      );
    }
    throw error;
  }
  if (message === null) {
    verdictFailure("MISSING");
  }
  const envelope = isPlainObject(message.body)
    ? message.body.envelope
    : undefined;
  if (!isPlainObject(envelope)) {
    verdictFailure("MALFORMED");
  }
  return envelope;
}

// Slot-order pre-check. The core verifier authenticates each anchor
// but reports a later-slot-without-earlier-slot chain as MISSING;
// the honest public code for that condition is emitted here.
async function assertSlotOrder(clockchain, descriptorEnvelope) {
  let sessionDigest;
  try {
    sessionDigest = dSession(
      isPlainObject(descriptorEnvelope)
        ? descriptorEnvelope.descriptor
        : undefined,
    );
  } catch {
    // Descriptor shape failures are reported by the core verifier.
    return;
  }
  const populated = [];
  for (const slot of SESSION_SLOTS) {
    let records;
    try {
      records = await clockchain.searchActions({
        asset_reference_id: sessionKey(sessionDigest, slot),
      });
    } catch (error) {
      if (error instanceof McpRateLimitedError) {
        verdictFailure("RATE_BLOCKED");
      }
      verdictFailure("FAILED");
    }
    if (!Array.isArray(records)) {
      verdictFailure("FAILED");
    }
    populated.push(records.length > 0);
  }
  if (
    (populated[1] === true && populated[0] === false) ||
    (
      populated[2] === true &&
      (populated[0] === false || populated[1] === false)
    )
  ) {
    verdictFailure("REORDERED");
  }
}

async function fetchEvidence(relay, sessionId, role) {
  try {
    return await relay.getEvidence(sessionId, role);
  } catch (error) {
    if (
      error instanceof RelayClientError &&
      (
        error.code === "NO_EVIDENCE" ||
        error.code === "UNKNOWN_SESSION"
      )
    ) {
      verdictFailure("MISSING");
    }
    throw error;
  }
}

export function signVerdictDocument({
  keyId,
  privateKeyPem,
  sessionId,
  verdict,
}) {
  if (typeof keyId !== "string" || !KEY_ID_PATTERN.test(keyId)) {
    failure("VERIFIER_KEY");
  }
  let privateKey;
  let publicKeyBase64;
  try {
    privateKey = createPrivateKey({
      key: privateKeyPem,
      format: "pem",
    });
    if (privateKey.asymmetricKeyType !== "ed25519") {
      failure("VERIFIER_KEY");
    }
    const der = createPublicKey(privateKey).export({
      format: "der",
      type: "spki",
    });
    publicKeyBase64 = Buffer.from(der)
      .subarray(der.length - 32)
      .toString("base64");
  } catch (error) {
    if (error instanceof VerifierRunError) throw error;
    failure("VERIFIER_KEY");
  }
  const value = sign(
    null,
    canonicalBytes(verdict),
    privateKey,
  ).toString("base64");
  return Object.freeze({
    schema: VERDICT_DOCUMENT_SCHEMA,
    sessionId,
    signature: Object.freeze({
      algorithm: "ed25519",
      keyId,
      publicKey: publicKeyBase64,
      value,
    }),
    verdict,
  });
}

export async function runVerification({
  clockchain,
  operatorKeyId,
  operatorPrivateKeyPem,
  ownerOf,
  relay,
  repositoryPublicKeyResolver,
  sessionId,
  subjectRun,
  verify,
}) {
  if (
    !isPlainObject(relay) ||
    typeof relay.pollMessages !== "function" ||
    typeof relay.getEvidence !== "function" ||
    typeof relay.putVerdict !== "function" ||
    typeof sessionId !== "string" ||
    sessionId.length === 0 ||
    !SUBJECT_RUNS.includes(subjectRun) ||
    !isPlainObject(clockchain) ||
    typeof clockchain.searchActions !== "function" ||
    typeof ownerOf !== "function" ||
    typeof repositoryPublicKeyResolver !== "function" ||
    typeof operatorPrivateKeyPem !== "string" ||
    typeof operatorKeyId !== "string" ||
    !KEY_ID_PATTERN.test(operatorKeyId) ||
    (verify !== undefined && typeof verify !== "function")
  ) {
    failure("VERIFIER_INPUT");
  }

  const messages = await collectMessages(relay, sessionId);
  const mandateEnvelope = extractEnvelope(
    messages,
    RELAY_KINDS.MANDATE_PUBLISHED,
    "payer",
  );
  const requestEnvelope = extractEnvelope(
    messages,
    RELAY_KINDS.PAYMENT_REQUEST_SIGNED,
    "payee",
  );
  const descriptorEnvelope = extractEnvelope(
    messages,
    RELAY_KINDS.DESCRIPTOR_PUBLISHED,
    "operator",
  );

  await assertSlotOrder(clockchain, descriptorEnvelope);

  const payerPackage = await fetchEvidence(
    relay,
    sessionId,
    "payer",
  );
  const payeePackage = await fetchEvidence(
    relay,
    sessionId,
    "payee",
  );

  const verifyImpl =
    verify ??
    (
      subjectRun === "stakeholder"
        ? verifyBilateralAuthorization
        : verifyRehearsal
    );
  const verdict = await verifyImpl({
    canaries: [],
    clockchain,
    descriptorEnvelope,
    mandateEnvelope,
    ownerOf,
    payeePackage,
    payerPackage,
    repositoryPublicKeyResolver,
    requestEnvelope,
  });

  const document = signVerdictDocument({
    keyId: operatorKeyId,
    privateKeyPem: operatorPrivateKeyPem,
    sessionId,
    verdict,
  });
  let stored;
  try {
    stored = await relay.putVerdict(sessionId, document);
  } catch (error) {
    if (
      error instanceof RelayClientError &&
      error.code === "VERDICT_CONFLICT"
    ) {
      failure("VERDICT_CONFLICT");
    }
    throw error;
  }
  return Object.freeze({
    document,
    republished:
      isPlainObject(stored) && stored.stored === false,
    verdict,
  });
}

function createRepositoryPublicKeyResolver(repoRoot) {
  const allowedRoot = join(repoRoot, OPERATOR_KEY_DIRECTORY);
  return async ({ keyId, repositoryPath }) => {
    if (
      typeof keyId !== "string" ||
      !KEY_ID_PATTERN.test(keyId) ||
      typeof repositoryPath !== "string"
    ) {
      failure("VERIFIER_KEY");
    }
    const resolved = resolve(repoRoot, repositoryPath);
    if (
      resolved !== join(allowedRoot, `${keyId}.pub`)
    ) {
      failure("VERIFIER_KEY");
    }
    const contents = await readFile(resolved, "utf8");
    return contents.trim();
  };
}

const USAGE =
  "usage: run.mjs --session <id> --relay <url> --state <dir>" +
  " --key-id <operator-key-id>" +
  " --subject-run <stakeholder|rehearsal>";

export async function main(
  argv = process.argv.slice(2),
  seams = {},
) {
  const stdout = seams.stdout ?? process.stdout;
  let values;
  try {
    ({ values } = parseArgs({
      args: argv,
      options: {
        "key-id": { type: "string" },
        "relay": { type: "string" },
        "session": { type: "string" },
        "state": { type: "string" },
        "subject-run": { type: "string" },
      },
      strict: true,
    }));
  } catch {
    stdout.write(`${USAGE}\n`);
    return 2;
  }
  const sessionId = values.session;
  const keyId = values["key-id"];
  const subjectRun = values["subject-run"];
  if (
    typeof sessionId !== "string" ||
    sessionId.length === 0 ||
    typeof values.relay !== "string" ||
    typeof values.state !== "string" ||
    typeof keyId !== "string" ||
    !KEY_ID_PATTERN.test(keyId) ||
    !SUBJECT_RUNS.includes(subjectRun)
  ) {
    stdout.write(`${USAGE}\n`);
    return 2;
  }

  const repoRoot = seams.repoRoot ?? REPO_ROOT;
  try {
    const relay =
      seams.relay ??
      createRelayClient({ relayUrl: values.relay });
    const clockchain =
      seams.clockchain ?? (await connectClockchain());
    const ownerOf = seams.ownerOf ?? createOwnerOf();
    const operatorPrivateKeyPem =
      seams.operatorPrivateKeyPem ??
      (await readFile(
        join(
          repoRoot,
          ".context",
          "operator-keys",
          `${keyId}.ed25519.pem`,
        ),
        "utf8",
      ));
    const repositoryPublicKeyResolver =
      seams.repositoryPublicKeyResolver ??
      createRepositoryPublicKeyResolver(repoRoot);

    const { document, verdict } = await runVerification({
      clockchain,
      operatorKeyId: keyId,
      operatorPrivateKeyPem,
      ownerOf,
      relay,
      repositoryPublicKeyResolver,
      sessionId,
      subjectRun,
      ...(seams.verify === undefined
        ? {}
        : { verify: seams.verify }),
    });

    await mkdir(values.state, { recursive: true });
    await writeFile(
      join(values.state, "verdict.json"),
      `${JSON.stringify(document, null, 2)}\n`,
      { encoding: "utf8", mode: 0o600 },
    );
    if (verdict.schema === VERDICT_SCHEMA) {
      await writeFile(
        join(values.state, "verdict.md"),
        renderBilateralVerdictMarkdown(verdict),
        { encoding: "utf8", mode: 0o600 },
      );
    }
    stdout.write(
      `VERDICT_PUBLISHED ${verdict.outcome} session=${sessionId}\n`,
    );
    return 0;
  } catch (error) {
    if (error instanceof BilateralVerdictError) {
      stdout.write(
        `VERIFICATION_FAILED ${error.terminalCode} session=${sessionId}\n`,
      );
      return 1;
    }
    if (
      error instanceof RelayClientError ||
      error instanceof VerifierRunError
    ) {
      stdout.write(
        `VERIFIER_FAILED ${error.code} session=${sessionId}\n`,
      );
      return 1;
    }
    throw error;
  }
}

const invokedAsScript =
  process.argv[1] !== undefined &&
  fileURLToPath(import.meta.url) === resolve(process.argv[1]);

if (invokedAsScript) {
  main().then(
    (code) => {
      process.exitCode = code;
    },
    (error) => {
      process.stderr.write(
        `verifier crashed: ${
          error instanceof Error ? error.message : "unknown"
        }\n`,
      );
      process.exitCode = 1;
    },
  );
}
