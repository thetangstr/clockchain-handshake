#!/usr/bin/env node

import {
  GetSecretValueCommand,
  SecretsManagerClient,
} from "@aws-sdk/client-secrets-manager";
import {
  rm,
} from "node:fs/promises";

import {
  main as relayMain,
  relayReadinessLine,
} from "../../../bin/handshake-relay.mjs";
import {
  installPrivateFile,
  parseRuntimeInput,
  readSecretString,
} from "./runtime-input.mjs";

function exactRelaySecret(text) {
  try {
    const value = JSON.parse(text);
    return (
      value !== null &&
      typeof value === "object" &&
      !Array.isArray(value) &&
      Reflect.ownKeys(value).length === 2 &&
      typeof value.certificatePem === "string" &&
      typeof value.privateKeyPem === "string" &&
      JSON.stringify(value) === text
    );
  } catch {
    return false;
  }
}

export async function main({
  client = new SecretsManagerClient({}),
  env = process.env,
  run = relayMain,
  stdout = process.stdout,
} = {}) {
  const input = parseRuntimeInput(env);
  const relay = input.relay;
  if (
    relay === null ||
    typeof relay !== "object" ||
    Array.isArray(relay) ||
    !Array.isArray(relay.argv) ||
    typeof relay.certificatePath !==
      "string" ||
    typeof relay.privateKeyPath !==
      "string" ||
    typeof relay.tlsSecretArn !==
      "string" ||
    typeof relay.provenance !== "object" ||
    relay.provenance === null ||
    typeof run !== "function" ||
    typeof stdout?.write !== "function"
  ) {
    throw new Error(
      "AWS relay entrypoint failed safely.",
    );
  }
  const secret = await readSecretString({
    client,
    commandFactory: (value) =>
      new GetSecretValueCommand(value),
    secretArn: relay.tlsSecretArn,
    validate: exactRelaySecret,
  });
  const tls = JSON.parse(secret);
  await installPrivateFile({
    path: relay.certificatePath,
    value: tls.certificatePem,
  });
  await installPrivateFile({
    path: relay.privateKeyPath,
    value: tls.privateKeyPem,
  });
  let running;
  try {
    const provenance = Object.freeze({
      imageDigest:
        relay.provenance.imageDigest,
      operatorPublicKey:
        relay.provenance.operatorPublicKey,
      repositorySha:
        relay.provenance.repositorySha,
      sourceTreeSha256:
        relay.provenance.sourceTreeSha256,
    });
    const provider = Object.freeze({
      async assertRepository() {
        return provenance;
      },
      async verify(value) {
        if (
          value?.operatorKeyId !==
            relay.provenance.operatorKeyId
        ) {
          throw new Error();
        }
        return provenance;
      },
    });
    running = await run(relay.argv, {
      provenanceProvider: provider,
    });
    stdout.write(relayReadinessLine(running));
  } finally {
    await Promise.all([
      rm(relay.certificatePath, {
        force: true,
      }),
      rm(relay.privateKeyPath, {
        force: true,
      }),
    ]);
  }
  return running;
}

if (
  process.argv[1] !== undefined &&
  import.meta.url ===
    new URL(`file://${process.argv[1]}`).href
) {
  main().catch(() => {
    process.stderr.write(
      "AWS_RELAY_ENTRYPOINT_FAILED\n",
    );
    process.exitCode = 1;
  });
}
