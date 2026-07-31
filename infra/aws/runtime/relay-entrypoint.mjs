#!/usr/bin/env node

import {
  GetSecretValueCommand,
  SecretsManagerClient,
} from "@aws-sdk/client-secrets-manager";
import {
  createHash,
  createPrivateKey,
  X509Certificate,
} from "node:crypto";
import {
  rm,
} from "node:fs/promises";
import {
  isAbsolute,
} from "node:path";
import { types } from "node:util";

import {
  main as relayMain,
  relayReadinessLine,
} from "../../../bin/handshake-relay.mjs";
import {
  installPrivateFile,
  parseRuntimeInput,
  readSecretString,
} from "./runtime-input.mjs";

const RELAY_INPUT_KEYS = Object.freeze([
  "argv",
  "certificatePath",
  "privateKeyPath",
  "provenance",
  "tlsFingerprint",
  "tlsSecretArn",
]);
const PROVENANCE_KEYS = Object.freeze([
  "imageDigest",
  "operatorKeyId",
  "operatorPublicKey",
  "repositorySha",
  "sourceTreeSha256",
]);
const TOP_LEVEL_KEYS = Object.freeze([
  "paymentMoved",
  "relay",
  "schema",
]);
const SECRET_KEYS = Object.freeze([
  "certificatePem",
  "privateKeyPem",
]);
const CERTIFICATE_PATH =
  "/var/lib/clockchain/relay/runtime/tls.crt";
const PRIVATE_KEY_PATH =
  "/var/lib/clockchain/relay/runtime/tls.key";
const CONTROL = /[\u0000-\u001f\u007f]/;
const DNS_LABEL =
  /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;
const FINGERPRINT = /^[0-9a-f]{64}$/;
const OPERATOR_KEY_ID =
  /^[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?$/;
const REPOSITORY_SHA = /^[0-9a-f]{40}$/;
const SECRET_ARN =
  /^arn:aws(?:-[a-z]+)?:secretsmanager:[a-z0-9-]+:[0-9]{12}:secret:[A-Za-z0-9/_+=.@-]{1,512}$/;
const SHA256 = /^[0-9a-f]{64}$/;
const STATE_PATH =
  /^\/var\/lib\/clockchain\/relay\/releases\/release-[0-9a-f]{16}\/relay-state\.json$/;

class AwsRelayEntrypointError extends Error {
  constructor() {
    super("AWS relay entrypoint failed safely.");
    this.name = "AwsRelayEntrypointError";
  }
}

function fail() {
  throw new AwsRelayEntrypointError();
}

function plain(value) {
  return (
    value !== null &&
    typeof value === "object" &&
    !Array.isArray(value) &&
    !types.isProxy(value) &&
    Object.getPrototypeOf(value) ===
      Object.prototype
  );
}

function exact(value, keys) {
  if (!plain(value)) fail();
  const ownKeys = Reflect.ownKeys(value);
  if (
    ownKeys.length !== keys.length ||
    keys.some((key, index) =>
      ownKeys[index] !== key)
  ) {
    fail();
  }
  for (const key of keys) {
    const descriptor =
      Object.getOwnPropertyDescriptor(value, key);
    if (
      descriptor?.enumerable !== true ||
      !Object.hasOwn(descriptor, "value")
    ) {
      fail();
    }
  }
  return value;
}

function validAdvertisedHost(value) {
  if (
    typeof value !== "string" ||
    CONTROL.test(value) ||
    value.length > 253 ||
    value !== value.toLowerCase() ||
    value === "localhost" ||
    value.endsWith(".localhost")
  ) {
    return false;
  }
  const labels = value.split(".");
  return (
    labels.length >= 2 &&
    labels.every((label) =>
      DNS_LABEL.test(label))
  );
}

function validateArgv(relay) {
  const expected = [
    "--advertised-host",
    relay.argv[1],
    "--host",
    "0.0.0.0",
    "--port",
    "8443",
    "--repository-sha",
    relay.provenance.repositorySha,
    "--state",
    relay.argv[9],
    "--tls-certificate",
    CERTIFICATE_PATH,
    "--tls-private-key",
    PRIVATE_KEY_PATH,
  ];
  if (
    !Array.isArray(relay.argv) ||
    relay.argv.length !== expected.length ||
    !relay.argv.every(
      (value, index) =>
        typeof value === "string" &&
        value === expected[index],
    ) ||
    !validAdvertisedHost(relay.argv[1]) ||
    !STATE_PATH.test(relay.argv[9])
  ) {
    fail();
  }
  return Object.freeze([...relay.argv]);
}

function validateProvenance(value) {
  const provenance = exact(
    value,
    PROVENANCE_KEYS,
  );
  let publicKey;
  try {
    publicKey = Buffer.from(
      provenance.operatorPublicKey,
      "base64",
    );
  } catch {
    fail();
  }
  if (
    !(
      provenance.imageDigest === null ||
      /^sha256:[0-9a-f]{64}$/.test(
        provenance.imageDigest,
      )
    ) ||
    !OPERATOR_KEY_ID.test(
      provenance.operatorKeyId,
    ) ||
    typeof provenance.operatorPublicKey !==
      "string" ||
    !/^[A-Za-z0-9+/]{43}=$/.test(
      provenance.operatorPublicKey,
    ) ||
    publicKey.length !== 32 ||
    publicKey.toString("base64") !==
      provenance.operatorPublicKey ||
    !REPOSITORY_SHA.test(
      provenance.repositorySha,
    ) ||
    !SHA256.test(provenance.sourceTreeSha256)
  ) {
    fail();
  }
  return Object.freeze({
    imageDigest: provenance.imageDigest,
    operatorKeyId: provenance.operatorKeyId,
    operatorPublicKey:
      provenance.operatorPublicKey,
    repositorySha: provenance.repositorySha,
    sourceTreeSha256:
      provenance.sourceTreeSha256,
  });
}

function validateRelayInput(value) {
  const relay = exact(value, RELAY_INPUT_KEYS);
  relay.provenance = validateProvenance(
    relay.provenance,
  );
  if (
    relay.certificatePath !== CERTIFICATE_PATH ||
    relay.privateKeyPath !== PRIVATE_KEY_PATH ||
    !isAbsolute(relay.certificatePath) ||
    !isAbsolute(relay.privateKeyPath) ||
    !FINGERPRINT.test(relay.tlsFingerprint) ||
    !SECRET_ARN.test(relay.tlsSecretArn)
  ) {
    fail();
  }
  return Object.freeze({
    argv: validateArgv(relay),
    certificatePath: relay.certificatePath,
    privateKeyPath: relay.privateKeyPath,
    provenance: relay.provenance,
    tlsFingerprint: relay.tlsFingerprint,
    tlsSecretArn: relay.tlsSecretArn,
  });
}

function exactRelaySecret(text, fingerprint) {
  try {
    const value = JSON.parse(text);
    const secret = exact(value, SECRET_KEYS);
    if (
      typeof secret.certificatePem !== "string" ||
      secret.certificatePem.length === 0 ||
      Buffer.byteLength(
        secret.certificatePem,
        "utf8",
      ) > 65_536 ||
      typeof secret.privateKeyPem !== "string" ||
      secret.privateKeyPem.length === 0 ||
      Buffer.byteLength(
        secret.privateKeyPem,
        "utf8",
      ) > 16_384 ||
      JSON.stringify(secret) !== text
    ) {
      return false;
    }
    const certificate = new X509Certificate(
      secret.certificatePem,
    );
    const privateKey = createPrivateKey(
      secret.privateKeyPem,
    );
    return (
      certificate.toString() ===
        secret.certificatePem &&
      privateKey.asymmetricKeyType === "ed25519" &&
      certificate.checkPrivateKey(privateKey) &&
      createHash("sha256")
        .update(certificate.raw)
        .digest("hex") === fingerprint
    );
  } catch {
    return false;
  }
}

export async function main({
  client = new SecretsManagerClient({}),
  env = process.env,
  installFile = installPrivateFile,
  removeFile = (path) => rm(path, { force: true }),
  run = relayMain,
  stdout = process.stdout,
} = {}) {
  const input = exact(
    parseRuntimeInput(env),
    TOP_LEVEL_KEYS,
  );
  const relay = validateRelayInput(input.relay);
  if (
    typeof installFile !== "function" ||
    typeof removeFile !== "function" ||
    typeof run !== "function" ||
    typeof stdout?.write !== "function"
  ) {
    fail();
  }
  const secret = await readSecretString({
    client,
    commandFactory: (value) =>
      new GetSecretValueCommand(value),
    secretArn: relay.tlsSecretArn,
    validate: (value) =>
      exactRelaySecret(
        value,
        relay.tlsFingerprint,
      ),
  });
  const tls = JSON.parse(secret);
  let running;
  try {
    await installFile({
      path: relay.certificatePath,
      value: tls.certificatePem,
    });
    await installFile({
      path: relay.privateKeyPath,
      value: tls.privateKeyPem,
    });
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
  } catch (error) {
    if (error instanceof AwsRelayEntrypointError) {
      throw error;
    }
    fail();
  } finally {
    await Promise.all([
      removeFile(relay.certificatePath),
      removeFile(relay.privateKeyPath),
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
