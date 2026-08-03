import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import { readFile, writeFile } from "node:fs/promises";
import { promisify } from "node:util";

import {
  BILATERAL_PROTOCOL_ID,
} from "../src/core/mandate-construction.mjs";

// The only writer of release.json. The release pin is the single source
// the operator's session start uses to generate the signed discovery
// document; the kit re-derives repositorySha and kitManifestDigest from
// its own clean checkout and refuses to run on any mismatch.

export const RELEASE_SCHEMA = "handshake-release/v1";
export const DEFAULT_CLOCKCHAIN_URL =
  "https://mcp.clockchain.network/mcp";
export const DEFAULT_REGISTRY =
  "0x8004a818bfb912233c491871b3d84c89a494bd9e";
export const DEFAULT_CHAIN_ID = "11155111";

const RELEASE_KEYS = Object.freeze([
  "chainId",
  "clockchainUrl",
  "generatedAtMs",
  "kitManifestDigest",
  "kitRepoUrl",
  "protocolVersion",
  "registry",
  "repositorySha",
  "schema",
]);

const SHA_PATTERN = /^[0-9a-f]{40}$/;
const DIGEST_PATTERN = /^[0-9a-f]{64}$/;
const DECIMAL_PATTERN = /^(0|[1-9][0-9]*)$/;
const ADDRESS_PATTERN = /^0x[0-9a-f]{40}$/;
const HTTPS_URL_PATTERN = /^https:\/\/[ -~]{1,240}$/;
const KIT_REPO_PATTERN =
  /^(https:\/\/[ -~]{1,240}|git@[-./\w]{1,240}:[-./\w]{1,240})$/;

const execFileAsync = promisify(execFile);

export class ReleasePinError extends Error {
  constructor(code) {
    super("Release pin generation failed.");
    this.name = "ReleasePinError";
    this.category = "release";
    this.code = code;
  }
}

async function git(cwd, args) {
  try {
    const { stdout } = await execFileAsync(
      "git",
      args,
      { cwd, encoding: "buffer", maxBuffer: 64 * 1024 * 1024 },
    );
    return stdout;
  } catch {
    throw new ReleasePinError("RELEASE_GIT_FAILED");
  }
}

export async function computeRepositorySha({ cwd }) {
  const out = await git(cwd, ["rev-parse", "HEAD"]);
  const sha = out.toString("utf8").trim();
  if (!SHA_PATTERN.test(sha)) {
    throw new ReleasePinError("RELEASE_GIT_FAILED");
  }
  return sha;
}

// sha256 over the raw `git ls-tree -r -z <rev>` bytes: the tracked-file
// manifest of the pinned commit. Deterministic across machines because
// it reflects the commit object, not the index or the working tree.
export async function computeKitManifestDigest({ cwd, rev }) {
  if (typeof rev !== "string" || !SHA_PATTERN.test(rev)) {
    throw new ReleasePinError("RELEASE_INPUT");
  }
  const manifest = await git(cwd, ["ls-tree", "-r", "-z", rev]);
  if (manifest.length === 0) {
    throw new ReleasePinError("RELEASE_GIT_FAILED");
  }
  return createHash("sha256").update(manifest).digest("hex");
}

export async function assertCleanWorktree({ cwd }) {
  const out = await git(cwd, ["status", "--porcelain"]);
  if (out.length !== 0) {
    throw new ReleasePinError("RELEASE_NOT_CLEAN");
  }
}

function checked(input, pattern, code) {
  if (typeof input !== "string" || !pattern.test(input)) {
    throw new ReleasePinError(code);
  }
  return input;
}

export function validateReleasePin(pin) {
  if (
    pin === null ||
    typeof pin !== "object" ||
    Array.isArray(pin)
  ) {
    throw new ReleasePinError("RELEASE_INPUT");
  }
  const keys = Object.keys(pin);
  if (
    keys.length !== RELEASE_KEYS.length ||
    !RELEASE_KEYS.every((key) => keys.includes(key))
  ) {
    throw new ReleasePinError("RELEASE_INPUT");
  }
  if (pin.schema !== RELEASE_SCHEMA) {
    throw new ReleasePinError("RELEASE_INPUT");
  }
  if (pin.protocolVersion !== BILATERAL_PROTOCOL_ID) {
    throw new ReleasePinError("RELEASE_INPUT");
  }
  checked(pin.kitRepoUrl, KIT_REPO_PATTERN, "RELEASE_INPUT");
  checked(pin.repositorySha, SHA_PATTERN, "RELEASE_INPUT");
  checked(
    pin.kitManifestDigest,
    DIGEST_PATTERN,
    "RELEASE_INPUT",
  );
  checked(
    pin.clockchainUrl,
    HTTPS_URL_PATTERN,
    "RELEASE_INPUT",
  );
  checked(pin.registry, ADDRESS_PATTERN, "RELEASE_INPUT");
  checked(pin.chainId, DECIMAL_PATTERN, "RELEASE_INPUT");
  checked(pin.generatedAtMs, DECIMAL_PATTERN, "RELEASE_INPUT");
  return pin;
}

// The single reader counterpart: delivery-shell code must not name the
// pin file directly, so the operator loads the pin through here.
export async function readReleasePin({ cwd }) {
  if (typeof cwd !== "string" || cwd.length === 0) {
    throw new ReleasePinError("RELEASE_INPUT");
  }
  let raw;
  try {
    raw = await readFile(`${cwd}/release.json`, "utf8");
  } catch {
    throw new ReleasePinError("RELEASE_UNAVAILABLE");
  }
  if (Buffer.byteLength(raw, "utf8") > 65536) {
    throw new ReleasePinError("RELEASE_INPUT");
  }
  let parsed;
  try {
    parsed = JSON.parse(raw);
  } catch {
    throw new ReleasePinError("RELEASE_INPUT");
  }
  return validateReleasePin(parsed);
}

export async function buildReleasePin({
  cwd,
  kitRepoUrl,
  clockchainUrl = DEFAULT_CLOCKCHAIN_URL,
  registry = DEFAULT_REGISTRY,
  chainId = DEFAULT_CHAIN_ID,
  nowMs = Date.now(),
}) {
  if (
    typeof cwd !== "string" ||
    cwd.length === 0 ||
    !Number.isSafeInteger(nowMs) ||
    nowMs < 0
  ) {
    throw new ReleasePinError("RELEASE_INPUT");
  }
  await assertCleanWorktree({ cwd });
  const repositorySha = await computeRepositorySha({ cwd });
  const kitManifestDigest = await computeKitManifestDigest({
    cwd,
    rev: repositorySha,
  });
  return Object.freeze(
    validateReleasePin({
      chainId,
      clockchainUrl,
      generatedAtMs: String(nowMs),
      kitManifestDigest,
      kitRepoUrl,
      protocolVersion: BILATERAL_PROTOCOL_ID,
      registry,
      repositorySha,
      schema: RELEASE_SCHEMA,
    }),
  );
}

function parseFlags(argv) {
  const flags = new Map();
  for (let index = 0; index < argv.length; index += 1) {
    const token = argv[index];
    if (!token.startsWith("--")) {
      throw new ReleasePinError("RELEASE_INPUT");
    }
    const eq = token.indexOf("=");
    if (eq === -1) {
      throw new ReleasePinError("RELEASE_INPUT");
    }
    flags.set(token.slice(2, eq), token.slice(eq + 1));
  }
  return flags;
}

async function main() {
  const flags = parseFlags(process.argv.slice(2));
  const cwd = flags.get("cwd") ?? process.cwd();
  const out = flags.get("out") ?? `${cwd}/release.json`;
  const kitRepoUrl =
    flags.get("kit-repo-url") ??
    (await git(cwd, ["remote", "get-url", "origin"])
      .then((bytes) => bytes.toString("utf8").trim())
      .catch(() => undefined));
  if (kitRepoUrl === undefined || kitRepoUrl === "") {
    throw new ReleasePinError("RELEASE_INPUT");
  }
  const pin = await buildReleasePin({
    cwd,
    kitRepoUrl,
    ...(flags.has("clockchain-url")
      ? { clockchainUrl: flags.get("clockchain-url") }
      : {}),
    ...(flags.has("registry")
      ? { registry: flags.get("registry") }
      : {}),
    ...(flags.has("chain-id")
      ? { chainId: flags.get("chain-id") }
      : {}),
  });
  await writeFile(out, `${JSON.stringify(pin, null, 2)}\n`, {
    encoding: "utf8",
    mode: 0o644,
  });
  process.stdout.write(`${JSON.stringify(pin, null, 2)}\n`);
}

const invokedAsScript =
  process.argv[1] !== undefined &&
  import.meta.url === new URL(
    `file://${process.argv[1]}`,
  ).href;
if (invokedAsScript) {
  main().catch((error) => {
    const code =
      error instanceof ReleasePinError
        ? error.code
        : "RELEASE_GIT_FAILED";
    process.stderr.write(`release-pin failed: ${code}\n`);
    process.exitCode = 1;
  });
}
