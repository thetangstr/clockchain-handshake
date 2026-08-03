import { execFile as execFileCallback } from "node:child_process";
import { constants as fsConstants } from "node:fs";
import { access, lstat, realpath } from "node:fs/promises";
import { delimiter, isAbsolute, join } from "node:path";
import { promisify } from "node:util";

const execFileAsync = promisify(execFileCallback);
const SUPPORTED_PLATFORMS = Object.freeze(["darwin", "linux", "win32"]);
const SUPPORTED_ROLES = Object.freeze(["payer", "requestor"]);
const CONTROL_CHARACTER_PATTERN = /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/;
const NODE_VERSION_PATTERN = /^v([0-9]+)\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?$/;
const GIT_VERSION_PATTERN = /^git version ([0-9]+(?:\.[0-9]+){1,3})(?:\s.*)?$/;
const NPM_VERSION_PATTERN = /^([0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?)$/;
const OPENSSH_VERSION_PATTERN = /^OpenSSH_([0-9]+\.[0-9]+)(?:p[0-9]+)?(?:,|$)/;
const OPENSSL_VERSION_PATTERN = /^OpenSSL\s+([0-9]+\.[0-9]+\.[0-9]+[a-z]?)(?:\s|$)/;
const MAX_OUTPUT_BYTES = 1_024;

function fail() {
  throw new Error("Participant prerequisites failed safely.");
}

function sanitize(error) {
  if (error?.message === "Participant prerequisites failed safely.") throw error;
  fail();
}

function exactKeys(value, expected) {
  if (
    value === null ||
    typeof value !== "object" ||
    Array.isArray(value) ||
    Object.getPrototypeOf(value) !== Object.prototype
  ) {
    return false;
  }
  const keys = Object.keys(value);
  return keys.length === expected.length && expected.every((key) => keys.includes(key));
}

function cleanOutput(value) {
  if (typeof value !== "string" || Buffer.byteLength(value, "utf8") > MAX_OUTPUT_BYTES) fail();
  if (CONTROL_CHARACTER_PATTERN.test(value)) fail();
  return value.trim();
}

function version(value, pattern) {
  const match = pattern.exec(cleanOutput(value));
  if (match === null) fail();
  return match[1];
}

function executableNames(platform) {
  if (platform === "win32") {
    return Object.freeze({
      git: "git.exe",
      npm: "npm.cmd",
      openssh: "ssh.exe",
      openssl: "openssl.exe",
      sshKeygen: "ssh-keygen.exe",
    });
  }
  return Object.freeze({
    git: "git",
    npm: "npm",
    openssh: "ssh",
    openssl: "openssl",
    sshKeygen: "ssh-keygen",
  });
}

async function defaultResolveExecutable(name, {
  environment = process.env,
  platform = process.platform,
} = {}) {
  if (
    typeof name !== "string" ||
    name.length === 0 ||
    name.includes("/") ||
    name.includes("\\") ||
    CONTROL_CHARACTER_PATTERN.test(name) ||
    environment === null ||
    typeof environment !== "object"
  ) {
    fail();
  }
  const pathValue = environment.PATH ?? environment.Path ?? environment.path;
  if (typeof pathValue !== "string" || pathValue.length === 0 || CONTROL_CHARACTER_PATTERN.test(pathValue)) {
    fail();
  }
  const mode = platform === "win32" ? fsConstants.F_OK : fsConstants.X_OK;
  for (const directory of pathValue.split(delimiter)) {
    if (directory.length === 0 || !isAbsolute(directory)) continue;
    const candidate = join(directory, name);
    try {
      await access(candidate, mode);
      const canonical = await realpath(candidate);
      const stats = await lstat(canonical);
      if (stats.isFile() && !CONTROL_CHARACTER_PATTERN.test(canonical)) return canonical;
    } catch {
      // Try the next PATH entry.
    }
  }
  return null;
}

async function defaultExecute(command, arguments_, {
  platform = process.platform,
} = {}) {
  if (
    typeof command !== "string" ||
    !isAbsolute(command) ||
    !Array.isArray(arguments_) ||
    arguments_.some((argument) => typeof argument !== "string" || CONTROL_CHARACTER_PATTERN.test(argument))
  ) {
    fail();
  }
  if (platform === "win32" && command.toLowerCase().endsWith(".cmd")) {
    const commandInterpreter = process.env.ComSpec ?? process.env.COMSPEC;
    if (typeof commandInterpreter !== "string" || !isAbsolute(commandInterpreter)) fail();
    const quotedCommand = `"${command.replaceAll('"', '""')}"`;
    const quotedArguments = arguments_.map((argument) => `"${argument.replaceAll('"', '""')}"`);
    return await execFileAsync(
      commandInterpreter,
      ["/d", "/s", "/c", [quotedCommand, ...quotedArguments].join(" ")],
      {
        encoding: "utf8",
        maxBuffer: MAX_OUTPUT_BYTES,
        windowsHide: true,
      },
    );
  }
  return await execFileAsync(command, arguments_, {
    encoding: "utf8",
    maxBuffer: MAX_OUTPUT_BYTES,
    windowsHide: true,
  });
}

function validateInput(input) {
  if (
    !exactKeys(input, [
      "execute",
      "nodeVersion",
      "platform",
      "resolveExecutable",
      "role",
    ]) ||
    typeof input.execute !== "function" ||
    typeof input.resolveExecutable !== "function" ||
    !SUPPORTED_PLATFORMS.includes(input.platform) ||
    !SUPPORTED_ROLES.includes(input.role) ||
    typeof input.nodeVersion !== "string"
  ) {
    fail();
  }
  const match = NODE_VERSION_PATTERN.exec(input.nodeVersion);
  if (match === null || Number(match[1]) !== 22) fail();
  return 22;
}

export async function inspectParticipantPrerequisites(options = {}) {
  try {
    if (
      options === null ||
      typeof options !== "object" ||
      Array.isArray(options) ||
      Object.getPrototypeOf(options) !== Object.prototype ||
      Object.keys(options).some(
        (key) =>
          !["execute", "nodeVersion", "platform", "resolveExecutable", "role"].includes(key),
      ) ||
      (Object.hasOwn(options, "execute") && typeof options.execute !== "function") ||
      (Object.hasOwn(options, "resolveExecutable") &&
        typeof options.resolveExecutable !== "function")
    ) {
      fail();
    }
    const platform = options.platform ?? process.platform;
    const input = {
      execute: options.execute ?? ((command, arguments_) => defaultExecute(command, arguments_, { platform })),
      nodeVersion: options.nodeVersion ?? process.version,
      platform,
      resolveExecutable:
        options.resolveExecutable ??
        ((name) => defaultResolveExecutable(name, { platform })),
      role: options.role,
    };
    const nodeMajor = validateInput(input);
    const names = executableNames(platform);
    const gitCommand = await input.resolveExecutable(names.git);
    const npmCommand = await input.resolveExecutable(names.npm);
    if (typeof gitCommand !== "string" || typeof npmCommand !== "string") fail();
    const gitResult = await input.execute(gitCommand, ["--version"]);
    const npmResult = await input.execute(npmCommand, ["--version"]);
    if (!exactKeys(gitResult, ["stderr", "stdout"]) || !exactKeys(npmResult, ["stderr", "stdout"])) fail();
    const result = {
      git: Object.freeze({
        command: gitCommand,
        version: version(`${gitResult.stdout}${gitResult.stderr}`, GIT_VERSION_PATTERN),
      }),
      node: Object.freeze({ command: process.execPath, major: nodeMajor }),
      npm: Object.freeze({
        command: npmCommand,
        version: version(`${npmResult.stdout}${npmResult.stderr}`, NPM_VERSION_PATTERN),
      }),
    };
    if (input.role === "requestor") return Object.freeze(result);

    const sshCommand = await input.resolveExecutable(names.openssh);
    const sshKeygenCommand = await input.resolveExecutable(names.sshKeygen);
    const opensslCommand = await input.resolveExecutable(names.openssl);
    if (
      typeof sshCommand !== "string" ||
      typeof sshKeygenCommand !== "string" ||
      typeof opensslCommand !== "string"
    ) {
      fail();
    }
    const sshResult = await input.execute(sshCommand, ["-V"]);
    const opensslResult = await input.execute(opensslCommand, ["version"]);
    if (!exactKeys(sshResult, ["stderr", "stdout"]) || !exactKeys(opensslResult, ["stderr", "stdout"])) fail();
    const opensshVersion = version(`${sshResult.stdout}${sshResult.stderr}`, OPENSSH_VERSION_PATTERN);
    return Object.freeze({
      ...result,
      openssh: Object.freeze({ command: sshCommand, version: opensshVersion }),
      openssl: Object.freeze({
        command: opensslCommand,
        version: version(`${opensslResult.stdout}${opensslResult.stderr}`, OPENSSL_VERSION_PATTERN),
      }),
      sshKeygen: Object.freeze({ command: sshKeygenCommand, version: opensshVersion }),
    });
  } catch (error) {
    sanitize(error);
  }
  fail();
}
