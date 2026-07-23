import { randomBytes } from "node:crypto";
import { constants as fsConstants } from "node:fs";
import {
  link,
  lstat,
  mkdir,
  open,
  rename,
  unlink,
} from "node:fs/promises";
import { basename, dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { generatePrivateKey, privateKeyToAccount } from "viem/accounts";

import { encryptInvitation } from "../src/invitation.mjs";

const ID_PATTERN =
  /^(?=.{1,32}$)[a-z][a-z0-9]*(?:-[a-z0-9]+)*$/u;
const MAX_DISPLAY_NAME_LENGTH = 128;
const CONTROL_CHARACTER_PATTERN = /[\u0000-\u001f\u007f-\u009f]/u;
const WRITE_FLAGS =
  fsConstants.O_WRONLY |
  fsConstants.O_CREAT |
  fsConstants.O_EXCL |
  (fsConstants.O_NOFOLLOW ?? 0);

class InvitationCreationError extends Error {
  constructor() {
    super("Invitation creation failed safely.");
    this.name = "InvitationCreationError";
  }
}

function fail() {
  throw new InvitationCreationError();
}

function parseArguments(arguments_) {
  const values = new Map();
  let force = false;

  for (let index = 0; index < arguments_.length; index += 1) {
    const argument = arguments_[index];

    if (argument === "--force") {
      if (force) {
        fail();
      }
      force = true;
      continue;
    }

    if (
      argument !== "--output-public" &&
      argument !== "--output-secret" &&
      argument !== "--ids" &&
      argument !== "--names"
    ) {
      fail();
    }

    if (values.has(argument) || index + 1 >= arguments_.length) {
      fail();
    }

    const value = arguments_[index + 1];
    if (
      typeof value !== "string" ||
      value.length === 0 ||
      value.startsWith("--")
    ) {
      fail();
    }
    values.set(argument, value);
    index += 1;
  }

  const required = [
    "--output-public",
    "--output-secret",
    "--ids",
    "--names",
  ];
  if (!required.every((key) => values.has(key))) {
    fail();
  }

  const ids = parseList(values.get("--ids"));
  const names = parseList(values.get("--names"));
  if (
    ids.length === 0 ||
    ids.length !== names.length ||
    new Set(ids).size !== ids.length ||
    !ids.every((id) => ID_PATTERN.test(id)) ||
    !names.every(isSafeDisplayName)
  ) {
    fail();
  }

  return {
    force,
    ids,
    names,
    publicDirectory: resolve(values.get("--output-public")),
    secretDirectory: resolve(values.get("--output-secret")),
  };
}

function parseList(value) {
  const parts = value.split(",");
  if (
    parts.some(
      (part) => part.length === 0 || part !== part.trim(),
    )
  ) {
    fail();
  }
  return parts;
}

function isSafeDisplayName(value) {
  return (
    value.length > 0 &&
    value.length <= MAX_DISPLAY_NAME_LENGTH &&
    value === value.trim() &&
    !CONTROL_CHARACTER_PATTERN.test(value)
  );
}

async function inspectDirectory(path) {
  try {
    const metadata = await lstat(path);
    if (!metadata.isDirectory() || metadata.isSymbolicLink()) {
      fail();
    }
    return true;
  } catch (error) {
    if (error?.code === "ENOENT") {
      return false;
    }
    if (error instanceof InvitationCreationError) {
      throw error;
    }
    fail();
  }
}

async function prepareDirectories(publicDirectory, secretDirectory) {
  const publicExists = await inspectDirectory(publicDirectory);
  const secretExists =
    secretDirectory === publicDirectory
      ? publicExists
      : await inspectDirectory(secretDirectory);

  if (!publicExists) {
    await createDirectory(publicDirectory, 0o755);
  }
  if (!secretExists && secretDirectory !== publicDirectory) {
    await createDirectory(secretDirectory, 0o700);
  }
}

async function createDirectory(path, mode) {
  try {
    await mkdir(path, { recursive: true, mode });
  } catch {
    fail();
  }
  if (!(await inspectDirectory(path))) {
    fail();
  }
}

async function inspectTarget(path, force) {
  try {
    const metadata = await lstat(path);
    if (
      !force ||
      !metadata.isFile() ||
      metadata.isSymbolicLink()
    ) {
      fail();
    }
    return true;
  } catch (error) {
    if (error?.code === "ENOENT") {
      return false;
    }
    if (error instanceof InvitationCreationError) {
      throw error;
    }
    fail();
  }
}

async function preflightTargets(targets, force) {
  for (const target of targets) {
    await inspectTarget(target, force);
  }
}

function temporaryPath(path) {
  return join(
    dirname(path),
    `.${basename(path)}.${process.pid}.${randomBytes(12).toString("hex")}.tmp`,
  );
}

async function atomicWrite(path, contents, { force, mode }) {
  const temporary = temporaryPath(path);
  let fileHandle;

  try {
    fileHandle = await open(temporary, WRITE_FLAGS, mode);
    await fileHandle.writeFile(contents, "utf8");
    await fileHandle.sync();
    await fileHandle.close();
    fileHandle = undefined;

    if (force) {
      await inspectTarget(path, true);
      await rename(temporary, path);
    } else {
      await link(temporary, path);
      await unlink(temporary);
    }
  } catch (error) {
    if (fileHandle !== undefined) {
      try {
        await fileHandle.close();
      } catch {
        // The public CLI still emits only its fixed safe failure.
      }
    }
    try {
      await unlink(temporary);
    } catch {
      // The temporary may already have been linked and removed.
    }
    if (error instanceof InvitationCreationError) {
      throw error;
    }
    fail();
  }
}

async function createDistinctInvitation({
  displayName,
  usedAddresses,
  usedCodes,
}) {
  for (let attempt = 0; attempt < 16; attempt += 1) {
    const privateKey = generatePrivateKey();
    const address = privateKeyToAccount(privateKey).address;
    const code = randomBytes(32).toString("hex");

    if (
      usedAddresses.has(address.toLowerCase()) ||
      usedCodes.has(code)
    ) {
      continue;
    }

    const bundle = await encryptInvitation(
      { privateKey, address, displayName },
      code,
    );
    usedAddresses.add(address.toLowerCase());
    usedCodes.add(code);
    return { address, bundle, code };
  }

  fail();
}

async function createInvitations(configuration) {
  const {
    force,
    ids,
    names,
    publicDirectory,
    secretDirectory,
  } = configuration;
  const targets = ids.flatMap((id) => [
    join(publicDirectory, `${id}.enc.json`),
    join(secretDirectory, `${id}.secret.json`),
  ]);

  await prepareDirectories(publicDirectory, secretDirectory);
  await preflightTargets(targets, force);

  const usedAddresses = new Set();
  const usedCodes = new Set();
  const invitations = [];
  for (let index = 0; index < ids.length; index += 1) {
    invitations.push({
      id: ids[index],
      ...(await createDistinctInvitation({
        displayName: names[index],
        usedAddresses,
        usedCodes,
      })),
    });
  }

  for (const invitation of invitations) {
    await atomicWrite(
      join(publicDirectory, `${invitation.id}.enc.json`),
      `${JSON.stringify(invitation.bundle, null, 2)}\n`,
      { force, mode: 0o644 },
    );
    await atomicWrite(
      join(secretDirectory, `${invitation.id}.secret.json`),
      `${JSON.stringify(
        {
          bundle: invitation.bundle,
          code: invitation.code,
        },
        null,
        2,
      )}\n`,
      { force, mode: 0o600 },
    );
  }

  return {
    created: invitations.map(({ id, address }) => ({ id, address })),
  };
}

export async function main(arguments_ = process.argv.slice(2)) {
  const configuration = parseArguments(arguments_);
  return createInvitations(configuration);
}

const isEntryPoint =
  process.argv[1] !== undefined &&
  resolve(process.argv[1]) === fileURLToPath(import.meta.url);

if (isEntryPoint) {
  try {
    const report = await main();
    process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
  } catch {
    process.stderr.write("Invitation creation failed safely.\n");
    process.exitCode = 1;
  }
}
