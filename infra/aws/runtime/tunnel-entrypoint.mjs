#!/usr/bin/env node

import {
  GetSecretValueCommand,
  SecretsManagerClient,
} from "@aws-sdk/client-secrets-manager";
import { randomUUID } from "node:crypto";
import {
  chmod,
  open,
  rename,
  rm,
} from "node:fs/promises";
import { isAbsolute } from "node:path";
import { pathToFileURL } from "node:url";

import {
  main as tunnelMain,
} from "../../../scripts/run-aws-tunnel-service.mjs";

function required(env, key) {
  const value = env[key];
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    value.trim() !== value
  ) {
    throw new Error(
      "AWS tunnel entrypoint configuration invalid.",
    );
  }
  return value;
}

export function validateTunnelRuntimeConfiguration(
  env = process.env,
) {
  const healthPath = env.AWS_TUNNEL_HEALTH_PATH;
  if (
    typeof healthPath !== "string" ||
    healthPath.length === 0 ||
    healthPath.trim() !== healthPath ||
    healthPath.includes("\0") ||
    !isAbsolute(healthPath)
  ) {
    throw new Error(
      "AWS tunnel entrypoint configuration invalid.",
    );
  }
  return Object.freeze({
    healthPath,
    hostKeySecretArn: required(
      env,
      "TUNNEL_HOST_KEY_SECRET_ARN",
    ),
  });
}

export async function installHostKey({
  client = new SecretsManagerClient({}),
  path =
    "/run/clockchain/ssh_host_ed25519_key",
  secretArn = required(
    process.env,
    "TUNNEL_HOST_KEY_SECRET_ARN",
  ),
} = {}) {
  const result = await client.send(
    new GetSecretValueCommand({
      SecretId: secretArn,
    }),
  );
  const key = result.SecretString;
  if (
    typeof key !== "string" ||
    !key.startsWith(
      "-----BEGIN OPENSSH PRIVATE KEY-----\n",
    ) ||
    !key.endsWith(
      "-----END OPENSSH PRIVATE KEY-----",
    ) ||
    Buffer.byteLength(key, "utf8") >
      32_768
  ) {
    throw new Error(
      "AWS tunnel host key failed validation.",
    );
  }
  const temporary = `${path}.${randomUUID()}.next`;
  let handle;
  try {
    handle = await open(temporary, "wx", 0o600);
    await handle.writeFile(`${key}\n`, "utf8");
    await handle.sync();
    await handle.close();
    handle = undefined;
    await rename(temporary, path);
    await chmod(path, 0o600);
  } catch (error) {
    await handle?.close().catch(() => {});
    await rm(temporary, {
      force: true,
    }).catch(() => {});
    throw error;
  }
}

export async function main() {
  const config = validateTunnelRuntimeConfiguration();
  await installHostKey({
    secretArn: config.hostKeySecretArn,
  });
  await tunnelMain(process.env);
}

if (
  process.argv[1] !== undefined &&
  import.meta.url ===
    pathToFileURL(process.argv[1]).href
) {
  main().catch(() => {
    process.stderr.write(
      "AWS_TUNNEL_ENTRYPOINT_FAILED\n",
    );
    process.exitCode = 1;
  });
}
