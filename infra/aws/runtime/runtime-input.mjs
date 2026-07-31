import {
  randomUUID,
} from "node:crypto";
import {
  constants,
} from "node:fs";
import {
  chmod,
  link,
  open,
  rm,
} from "node:fs/promises";
import {
  isAbsolute,
} from "node:path";

const SECRET_ARN =
  /^arn:aws(?:-[a-z]+)?:secretsmanager:[a-z0-9-]+:[0-9]{12}:secret:[A-Za-z0-9/_+=.@-]{1,512}$/;
const MAX_INPUT_BYTES = 32_768;
const MAX_SECRET_BYTES = 3_145_728;

export class AwsRuntimeInputError extends Error {
  constructor() {
    super("AWS runtime input failed safely.");
    this.name = "AwsRuntimeInputError";
    this.code = "AWS_RUNTIME_INPUT_INVALID";
    this.category = "configuration";
  }
}

function fail() {
  throw new AwsRuntimeInputError();
}

export function parseRuntimeInput(
  env = process.env,
) {
  try {
    const text = env?.AWS_RUNTIME_INPUT;
    if (
      typeof text !== "string" ||
      text.length === 0 ||
      text.trim() !== text ||
      Buffer.byteLength(text, "utf8") >
        MAX_INPUT_BYTES
    ) {
      fail();
    }
    const value = JSON.parse(text);
    const keys =
      value !== null &&
      typeof value === "object" &&
      !Array.isArray(value)
        ? Object.keys(value)
        : [];
    if (
      value === null ||
      typeof value !== "object" ||
      Array.isArray(value) ||
      Object.getPrototypeOf(value) !==
        Object.prototype ||
      keys.some(
        (key, index) =>
          key !== [...keys].sort()[index],
      ) ||
      JSON.stringify(value) !== text ||
      value.paymentMoved !== false ||
      value.schema !==
        "clockchain.aws-runtime-input/v1"
    ) {
      fail();
    }
    return value;
  } catch (error) {
    if (error instanceof AwsRuntimeInputError) {
      throw error;
    }
    fail();
  }
}

export async function readSecretString({
  client,
  commandFactory,
  secretArn,
  validate,
} = {}) {
  try {
    if (
      client === null ||
      typeof client !== "object" ||
      typeof client.send !== "function" ||
      typeof commandFactory !== "function" ||
      !SECRET_ARN.test(secretArn) ||
      typeof validate !== "function"
    ) {
      fail();
    }
    const response = await client.send(
      commandFactory({
        SecretId: secretArn,
      }),
    );
    const secret = response?.SecretString;
    if (
      typeof secret !== "string" ||
      secret.length === 0 ||
      Buffer.byteLength(secret, "utf8") >
        MAX_SECRET_BYTES ||
      validate(secret) !== true
    ) {
      fail();
    }
    return secret;
  } catch (error) {
    if (error instanceof AwsRuntimeInputError) {
      throw error;
    }
    fail();
  }
}

export async function installPrivateFile({
  path,
  value,
} = {}) {
  let handle;
  let temporary;
  try {
    if (
      typeof path !== "string" ||
      !isAbsolute(path) ||
      path.includes("\0") ||
      typeof value !== "string" ||
      value.length === 0 ||
      Buffer.byteLength(value, "utf8") >
        MAX_SECRET_BYTES
    ) {
      fail();
    }
    temporary = `${path}.${randomUUID()}.next`;
    handle = await open(
      temporary,
      constants.O_WRONLY |
        constants.O_CREAT |
        constants.O_EXCL |
        (constants.O_NOFOLLOW ?? 0),
      0o600,
    );
    await handle.writeFile(value, "utf8");
    await handle.sync();
    await handle.close();
    handle = undefined;
    await link(temporary, path);
    await chmod(path, 0o600);
    await rm(temporary);
    temporary = undefined;
  } catch (error) {
    await handle?.close().catch(() => {});
    if (temporary !== undefined) {
      await rm(temporary, {
        force: true,
      }).catch(() => {});
    }
    if (error instanceof AwsRuntimeInputError) {
      throw error;
    }
    fail();
  }
}

export async function installSecretFile({
  client,
  commandFactory,
  path,
  secretArn,
  validate,
} = {}) {
  try {
    if (
      client === null ||
      typeof client !== "object" ||
      typeof client.send !== "function" ||
      typeof commandFactory !== "function" ||
      typeof path !== "string" ||
      !isAbsolute(path) ||
      path.includes("\0") ||
      !SECRET_ARN.test(secretArn) ||
      typeof validate !== "function"
    ) {
      fail();
    }
    const secret = await readSecretString({
      client,
      commandFactory,
      secretArn,
      validate,
    });
    await installPrivateFile({
      path,
      value: secret,
    });
  } catch (error) {
    if (error instanceof AwsRuntimeInputError) {
      throw error;
    }
    fail();
  }
}
