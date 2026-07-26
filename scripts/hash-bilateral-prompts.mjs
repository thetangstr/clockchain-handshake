import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import { dirname } from "node:path";
import {
  fileURLToPath,
  pathToFileURL,
} from "node:url";
import { promisify } from "node:util";

import { canonicalBytes } from "../src/bilateral/canonical.mjs";

export const PROMPT_HASH_REPOSITORY_ROOT = dirname(
  dirname(fileURLToPath(import.meta.url)),
);

const MAX_PROMPT_BYTES = 1_048_576;
const REPOSITORY_SHA_PATTERN = /^[0-9a-f]{40}$/;
const PROMPT_PATHS = Object.freeze({
  payer: "prompts/run-billy-bilateral-demo.md",
  payee: "prompts/run-iris-bilateral-demo.md",
});
const execFileAsync = promisify(execFile);

export class BilateralPromptHashError extends Error {
  constructor() {
    super("Bilateral prompt hashing failed safely.");
    this.name = "BilateralPromptHashError";
    this.code = "BILATERAL_PROMPT_HASH_FAILED";
  }
}

function fail() {
  throw new BilateralPromptHashError();
}

function parseArguments(arguments_) {
  if (
    !Array.isArray(arguments_) ||
    arguments_.length !== 2 ||
    arguments_[0] !== "--repository-sha" ||
    typeof arguments_[1] !== "string" ||
    !REPOSITORY_SHA_PATTERN.test(arguments_[1])
  ) {
    fail();
  }
  return arguments_[1];
}

export async function defaultPromptResolver(
  {
    repositoryPath,
    repositoryRoot,
    repositorySha,
  },
  runGit = execFileAsync,
) {
  if (
    typeof repositoryPath !== "string" ||
    repositoryPath.length === 0 ||
    typeof repositoryRoot !== "string" ||
    repositoryRoot.length === 0 ||
    typeof repositorySha !== "string" ||
    !REPOSITORY_SHA_PATTERN.test(repositorySha) ||
    typeof runGit !== "function"
  ) {
    fail();
  }
  try {
    await runGit(
      "git",
      ["cat-file", "-e", `${repositorySha}^{commit}`],
      {
        cwd: repositoryRoot,
        maxBuffer: 128,
      },
    );
    const result = await runGit(
      "git",
      ["show", `${repositorySha}:${repositoryPath}`],
      {
        cwd: repositoryRoot,
        encoding: "buffer",
        maxBuffer: MAX_PROMPT_BYTES + 1,
      },
    );
    if (
      result === null ||
      typeof result !== "object" ||
      !Buffer.isBuffer(result.stdout)
    ) {
      fail();
    }
    return result.stdout;
  } catch (error) {
    if (error instanceof BilateralPromptHashError) {
      throw error;
    }
    fail();
  }
}

export async function computeBilateralPromptHash({
  promptResolver = defaultPromptResolver,
  repositoryRoot = PROMPT_HASH_REPOSITORY_ROOT,
  repositorySha,
} = {}) {
  if (
    typeof promptResolver !== "function" ||
    typeof repositoryRoot !== "string" ||
    repositoryRoot.length === 0 ||
    typeof repositorySha !== "string" ||
    !REPOSITORY_SHA_PATTERN.test(repositorySha)
  ) {
    fail();
  }
  const promptDigests = {};
  for (const role of ["payer", "payee"]) {
    let bytes;
    try {
      bytes = await promptResolver({
        repositoryPath: PROMPT_PATHS[role],
        repositoryRoot,
        repositorySha,
      });
    } catch (error) {
      if (error instanceof BilateralPromptHashError) {
        throw error;
      }
      fail();
    }
    if (
      !Buffer.isBuffer(bytes) ||
      bytes.length === 0 ||
      bytes.length > MAX_PROMPT_BYTES
    ) {
      fail();
    }
    promptDigests[role] = createHash("sha256")
      .update(bytes)
      .digest("hex");
  }
  try {
    return createHash("sha256")
      .update(canonicalBytes(promptDigests))
      .digest("hex");
  } catch {
    fail();
  }
}

export async function main(
  arguments_ = process.argv.slice(2),
  dependencies = {},
) {
  const repositorySha = parseArguments(arguments_);
  if (
    dependencies === null ||
    typeof dependencies !== "object" ||
    Array.isArray(dependencies)
  ) {
    fail();
  }
  return computeBilateralPromptHash({
    promptResolver:
      dependencies.promptResolver ??
      defaultPromptResolver,
    repositorySha,
  });
}

export async function runCli(
  arguments_ = process.argv.slice(2),
  dependencies = {},
) {
  const output =
    dependencies.output ??
    ((line) => process.stdout.write(line));
  const writeError =
    dependencies.writeError ??
    ((line) => process.stderr.write(line));
  try {
    const digest = await main(arguments_, dependencies);
    output(`${digest}\n`);
    return 0;
  } catch {
    writeError("Bilateral prompt hashing failed safely.\n");
    return 1;
  }
}

if (
  process.argv[1] &&
  import.meta.url === pathToFileURL(process.argv[1]).href
) {
  process.exitCode = await runCli();
}
