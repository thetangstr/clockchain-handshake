#!/usr/bin/env node

import { pathToFileURL } from "node:url";

import {
  EvidenceError,
  validatePassResult,
} from "../src/evidence.mjs";
import {
  HANDSHAKE_FAILURE_CATEGORIES,
  HandshakeStageError,
  runHandshake,
} from "../src/run.mjs";

const PROGRESS_LINES = Object.freeze({
  "invitation-read": "Reading the secret invitation",
  "invitation-decrypted": "Decrypting the invitation locally",
  "registration-started": "Registering ERC-8004 identity",
  "registration-resumed":
    "Resuming ERC-8004 identity registration",
  "registration-recovery-loaded":
    "Loaded public registration recovery checkpoint",
  "registration-complete": "Registering ERC-8004 identity: confirmed",
  "token-minted": "Minting an ephemeral Clockchain demo token",
  "identity-resolved":
    "Resolving the ERC-8004 identity through Clockchain",
  "timestamp-received": "Reading Clockchain consensus time",
  "receipt-created": "Submitting the trust_handshake receipt",
  "receipt-anchored": "Confirming the Clockchain receipt anchor",
  "receipt-verified": "Verifying the receipt commitment",
  "cross-party-verified":
    "Verifying the immutable block cross-party",
  "evidence-writing": "Writing sanitized evidence",
  "evidence-written": "Validating sanitized evidence",
});
const EXIT_CODES = Object.freeze({
  configuration: 2,
  network: 3,
  protocol: 4,
  verification: 4,
  redaction: 5,
});
const DEFAULT_EXIT_CODE = 4;
const UNEXPECTED_FAILURE_CODE = "HANDSHAKE_UNEXPECTED_FAILURE";
const DIRECTORY_FAILURE_CODE =
  "HANDSHAKE_OUTPUT_DIRECTORY_IN_USE";
const UNPRINTABLE_PATTERN =
  /[\u0000-\u001f\u007f-\u009f\u2028\u2029]/;
export const FAILURE_HINTS = Object.freeze({
  HANDSHAKE_CONFIGURATION:
    "The command line, HANDSHAKE_INVITE_FILE, or output path is invalid; correct the invocation and start the demo again.",
  HANDSHAKE_INVITATION_READ_FAILED:
    "The invitation file could not be read safely; ask the operator to confirm its path and permissions without opening it.",
  HANDSHAKE_INVITATION_DECRYPTION_FAILED:
    "The invitation could not be authenticated; ask the operator for a fresh invitation instead of retrying this one.",
  [DIRECTORY_FAILURE_CODE]:
    "This directory already holds result.json or RESULT.md from an earlier run; start the demo in a new empty directory instead of rerunning here.",
  HANDSHAKE_REGISTRATION_RECOVERY_FAILED:
    "The public registration checkpoint could not be written or read back; keep this directory and ask the operator to inspect it.",
  HANDSHAKE_REGISTRATION_FAILED:
    "Ethereum identity registration did not complete; keep this directory, wait 30 seconds, and start the demo once more here with the same invitation.",
  HANDSHAKE_TOKEN_MINT_FAILED:
    "The ephemeral Clockchain demo token could not be minted; keep this directory, wait 30 seconds, and start the demo once more here.",
  HANDSHAKE_MCP_CLIENT_FAILED:
    "The Clockchain client could not be prepared; confirm outbound HTTPS access, then start the demo once more in this directory.",
  HANDSHAKE_IDENTITY_RESOLUTION_FAILED:
    "Clockchain did not resolve the registered identity as expected; stop and ask the operator to inspect live state.",
  HANDSHAKE_TIMESTAMP_FAILED:
    "Clockchain consensus time was unavailable; keep this directory, wait 30 seconds, and start the demo once more here.",
  HANDSHAKE_ATTESTATION_FAILED:
    "The single-shot receipt write failed or had already started in this directory, so a receipt may exist; stop and ask the operator to inspect live state before any further write.",
  HANDSHAKE_RECEIPT_COMPLETION_FAILED:
    "The receipt did not reach a confirmed block anchor; stop and ask the operator to inspect the receipt before any further write.",
  HANDSHAKE_RECEIPT_VERIFICATION_FAILED:
    "The receipt commitment did not verify against the recorded block; stop and ask the operator to inspect the receipt, and do not start the demo again here.",
  HANDSHAKE_CROSS_PARTY_VERIFICATION_FAILED:
    "Cross-party verification against the immutable block failed; stop and ask the operator to inspect the block, and do not start the demo again here.",
  HANDSHAKE_EVIDENCE_FAILED:
    "Sanitized evidence failed validation or could not be written; keep this directory, report the code, and do not call the run successful.",
  HANDSHAKE_STAGE_FAILED:
    "The runner reported an unknown stage; treat it as a defect and report the terminal output to the operator.",
  [UNEXPECTED_FAILURE_CODE]:
    "The runner raised an untyped error; treat it as a defect and report the terminal output to the operator.",
});
export const FAILURE_EXIT_CODES = Object.freeze(
  Object.fromEntries(
    Object.entries({
      ...HANDSHAKE_FAILURE_CATEGORIES,
      [UNEXPECTED_FAILURE_CODE]: "protocol",
    }).map(([code, category]) => [
      code,
      EXIT_CODES[category] ?? DEFAULT_EXIT_CODE,
    ]),
  ),
);

function directoryLabel(value) {
  return typeof value === "string" &&
    value.length > 0 &&
    value.length <= 4_096 &&
    !UNPRINTABLE_PATTERN.test(value)
    ? value
    : null;
}

function failureHint(code, outputDirectory) {
  const hint = Object.hasOwn(FAILURE_HINTS, code)
    ? FAILURE_HINTS[code]
    : FAILURE_HINTS[UNEXPECTED_FAILURE_CODE];
  if (code !== DIRECTORY_FAILURE_CODE) {
    return hint;
  }
  const label = directoryLabel(outputDirectory);
  return label === null
    ? hint
    : `${hint} Directory: ${label}`;
}

function configurationError() {
  return new HandshakeStageError({
    stage: "configuration",
    category: "configuration",
    code: "HANDSHAKE_CONFIGURATION",
  });
}

function parseArguments(argv, env, cwd) {
  if (
    !Array.isArray(argv) ||
    argv.some((value) => typeof value !== "string") ||
    typeof cwd !== "string" ||
    cwd.length === 0
  ) {
    throw configurationError();
  }

  let invitationFile;
  let outputDirectory = cwd;
  let inviteSeen = false;
  let outputSeen = false;

  for (let index = 0; index < argv.length; index += 1) {
    const option = argv[index];
    if (
      option !== "--invite-file" &&
      option !== "--output"
    ) {
      throw configurationError();
    }

    const value = argv[index + 1];
    if (
      typeof value !== "string" ||
      value.length === 0 ||
      value.startsWith("--")
    ) {
      throw configurationError();
    }
    index += 1;

    if (option === "--invite-file") {
      if (inviteSeen) {
        throw configurationError();
      }
      invitationFile = value;
      inviteSeen = true;
    } else {
      if (outputSeen) {
        throw configurationError();
      }
      outputDirectory = value;
      outputSeen = true;
    }
  }

  if (invitationFile === undefined) {
    const environmentValue = env?.HANDSHAKE_INVITE_FILE;
    if (
      typeof environmentValue !== "string" ||
      environmentValue.length === 0
    ) {
      throw configurationError();
    }
    invitationFile = environmentValue;
  }

  return { invitationFile, outputDirectory };
}

function writeLine(stream, value) {
  if (!stream || typeof stream.write !== "function") {
    throw configurationError();
  }
  stream.write(`${value}\n`);
}

function cliError(error) {
  if (error instanceof HandshakeStageError) {
    return error;
  }
  if (error instanceof EvidenceError) {
    return new HandshakeStageError({
      stage: "evidence",
      category: error.category,
      code: "HANDSHAKE_EVIDENCE_FAILED",
    });
  }
  return new HandshakeStageError({
    stage: "configuration",
    category: "protocol",
    code: "HANDSHAKE_UNEXPECTED_FAILURE",
  });
}

function reportPublicResult(stdout, result) {
  writeLine(stdout, `Agent ID: ${result.identity.agentId}`);
  writeLine(
    stdout,
    `Registration transaction: ${result.identity.registerTx}`,
  );
  writeLine(
    stdout,
    `Metadata transaction: ${result.identity.metadataTx}`,
  );
  writeLine(
    stdout,
    `Clockchain ledger: ${result.clockchain.ledgerId}`,
  );
  writeLine(
    stdout,
    `Clockchain block: ${result.clockchain.blockHeight}`,
  );
  writeLine(stdout, "Evidence: result.json and RESULT.md");
  writeLine(stdout, "PASS");
}

export async function main({
  argv = process.argv.slice(2),
  env = process.env,
  cwd = process.cwd(),
  stdout = process.stdout,
  stderr = process.stderr,
  run = runHandshake,
} = {}) {
  let reportedDirectory;
  try {
    if (typeof run !== "function") {
      throw configurationError();
    }
    const { invitationFile, outputDirectory } =
      parseArguments(argv, env, cwd);
    reportedDirectory = outputDirectory;
    const result = await run({
      invitationFile,
      outputDirectory,
      adapters: {
        reportProgress(event) {
          const line = PROGRESS_LINES[event?.stage];
          if (line !== undefined) {
            writeLine(stdout, line);
          }
        },
      },
    });
    validatePassResult(result);
    reportPublicResult(stdout, result);
    return 0;
  } catch (error) {
    const safe = cliError(error);
    try {
      writeLine(stderr, `FAILED [${safe.code}]`);
      writeLine(
        stderr,
        `Hint: ${failureHint(safe.code, reportedDirectory)}`,
      );
    } catch {
      // There is no safe fallback when the caller's error stream is unusable.
    }
    return EXIT_CODES[safe.category] ?? DEFAULT_EXIT_CODE;
  }
}

const invokedPath = process.argv[1];
if (
  typeof invokedPath === "string" &&
  import.meta.url === pathToFileURL(invokedPath).href
) {
  process.exitCode = await main();
}
