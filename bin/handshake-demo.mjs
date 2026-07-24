#!/usr/bin/env node

import { pathToFileURL } from "node:url";

import {
  EvidenceError,
  validatePassResult,
} from "../src/evidence.mjs";
import {
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
  try {
    if (typeof run !== "function") {
      throw configurationError();
    }
    const { invitationFile, outputDirectory } =
      parseArguments(argv, env, cwd);
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
    } catch {
      // There is no safe fallback when the caller's error stream is unusable.
    }
    return EXIT_CODES[safe.category] ?? 4;
  }
}

const invokedPath = process.argv[1];
if (
  typeof invokedPath === "string" &&
  import.meta.url === pathToFileURL(invokedPath).href
) {
  process.exitCode = await main();
}
