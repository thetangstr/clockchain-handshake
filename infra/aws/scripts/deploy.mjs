#!/usr/bin/env node

import { execFile } from "node:child_process";
import {
  chmod,
  mkdir,
  open,
  readFile,
  rename,
  rm,
} from "node:fs/promises";
import { dirname, relative, resolve } from "node:path";
import { promisify } from "node:util";
import { pathToFileURL } from "node:url";
import {
  createHash,
  X509Certificate,
} from "node:crypto";

import {
  assertFrozenRelease,
  DEFAULT_ACCOUNT,
  DEFAULT_REGION,
} from "./build-and-push.mjs";

const execFileAsync = promisify(execFile);
const SHA40 = /^[0-9a-f]{40}$/;
const IMAGE =
  /^[0-9]{12}\.dkr\.ecr\.[a-z]{2}-[a-z]+-[1-9]\.amazonaws\.com\/[a-z0-9][a-z0-9._/-]{0,254}@sha256:[0-9a-f]{64}$/;
const SESSION =
  /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const SHA64 = /^[0-9a-f]{64}$/;
const RAW_ED25519_PUBLIC_KEY =
  /^[A-Za-z0-9+/]{43}=$/;
const SECRET_ARN =
  /^arn:aws(?:-[a-z]+)?:secretsmanager:[a-z0-9-]+:[0-9]{12}:secret:[A-Za-z0-9/_+=.@-]{1,512}$/;
const PUBLIC_HOSTNAME =
  /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?$/;
const SSH_ED25519_PUBLIC_KEY =
  /^ssh-ed25519 ([A-Za-z0-9+/]+={0,2})$/;
const SSH_SHA256_FINGERPRINT =
  /^SHA256:[A-Za-z0-9+/]{43}$/;

function required(value, pattern, label) {
  if (
    typeof value !== "string" ||
    !pattern.test(value)
  ) {
    throw new Error(`${label} is invalid.`);
  }
  return value;
}

function validOperatorPublicKey(value) {
  if (
    typeof value !== "string" ||
    !RAW_ED25519_PUBLIC_KEY.test(value)
  ) {
    return false;
  }
  const decoded = Buffer.from(value, "base64");
  return (
    decoded.length === 32 &&
    decoded.toString("base64") === value
  );
}

function validTunnelHostKey(publicKey, fingerprint) {
  if (
    typeof publicKey !== "string" ||
    typeof fingerprint !== "string" ||
    !SSH_SHA256_FINGERPRINT.test(fingerprint)
  ) {
    return false;
  }
  const match =
    SSH_ED25519_PUBLIC_KEY.exec(publicKey);
  if (match === null) return false;
  const blob = Buffer.from(match[1], "base64");
  if (blob.toString("base64") !== match[1]) {
    return false;
  }
  let offset = 0;
  const readString = () => {
    if (offset + 4 > blob.length) return null;
    const length = blob.readUInt32BE(offset);
    offset += 4;
    if (offset + length > blob.length) {
      return null;
    }
    const value = blob.subarray(
      offset,
      offset + length,
    );
    offset += length;
    return value;
  };
  const algorithm = readString();
  const key = readString();
  return (
    algorithm?.toString("ascii") ===
      "ssh-ed25519" &&
    key?.length === 32 &&
    offset === blob.length &&
    `SHA256:${createHash("sha256")
      .update(blob)
      .digest("base64")
      .replace(/=+$/u, "")}` === fingerprint
  );
}

export function createDeploymentPlan({
  account = DEFAULT_ACCOUNT,
  activateServices = false,
  bootstrapBrokerCapabilityDigest,
  controlPlaneImage,
  operatorPublicKey,
  region = DEFAULT_REGION,
  relayPublicHostname,
  repositorySha,
  relayTlsCertificatePem,
  relayTlsFingerprint,
  relayTlsSecretArn,
  sessionId,
  sourceTreeSha256,
  tunnelHostKeyFingerprint,
  tunnelHostPublicKey,
  tunnelImage,
}) {
  if (typeof activateServices !== "boolean") {
    throw new Error(
      "Service activation must be a boolean.",
    );
  }
  required(account, /^[0-9]{12}$/, "AWS account");
  required(
    region,
    /^[a-z]{2}-[a-z]+-[1-9]$/,
    "AWS region",
  );
  required(
    repositorySha,
    SHA40,
    "Repository SHA",
  );
  required(
    controlPlaneImage,
    IMAGE,
    "Control-plane image",
  );
  required(
    tunnelImage,
    IMAGE,
    "Tunnel image",
  );
  required(
    bootstrapBrokerCapabilityDigest,
    SHA64,
    "Bootstrap broker capability digest",
  );
  required(
    relayPublicHostname,
    PUBLIC_HOSTNAME,
    "Relay public hostname",
  );
  required(
    relayTlsFingerprint,
    SHA64,
    "Relay TLS fingerprint",
  );
  required(
    relayTlsSecretArn,
    SECRET_ARN,
    "Relay TLS secret ARN",
  );
  required(
    sessionId,
    SESSION,
    "Session ID",
  );
  if (!validOperatorPublicKey(operatorPublicKey)) {
    throw new Error(
      "Operator public key is invalid.",
    );
  }
  if (
    !validTunnelHostKey(
      tunnelHostPublicKey,
      tunnelHostKeyFingerprint,
    )
  ) {
    throw new Error(
      "Tunnel host public key and fingerprint must match.",
    );
  }
  required(
    sourceTreeSha256,
    SHA64,
    "Source tree SHA-256",
  );
  let relayTlsCertificate;
  try {
    relayTlsCertificate = new X509Certificate(
      relayTlsCertificatePem,
    );
  } catch {
    throw new Error(
      "Relay TLS certificate is invalid.",
    );
  }
  if (
    createHash("sha256")
      .update(relayTlsCertificate.raw)
      .digest("hex") !==
    relayTlsFingerprint
  ) {
    throw new Error(
      "Relay TLS certificate and fingerprint must match.",
    );
  }
  if (
    relayTlsCertificate.checkHost(
      relayPublicHostname,
      { subject: "never" },
    ) === undefined
  ) {
    throw new Error(
      "Relay TLS certificate must cover the public hostname.",
    );
  }
  return {
    account,
    activateServices,
    bootstrapBrokerCapabilityDigest,
    controlPlaneImage,
    legacyInfrastructure: {
      action: "preserve",
    },
    operatorPublicKey,
    region,
    relayPublicHostname,
    repositorySha,
    relayTlsCertificatePem,
    relayTlsFingerprint,
    relayTlsSecretArn,
    schema: "clockchain.aws-deployment-plan/v1",
    sessionId,
    sourceTreeSha256,
    stacks: [
      "ClockchainHandshakeImages",
      "ClockchainHandshake",
    ],
    tunnelImage,
    tunnelHostKeyFingerprint,
    tunnelHostPublicKey,
  };
}

export function createDeploymentContexts(plan) {
  const certificateBase64 = Buffer.from(
    plan.relayTlsCertificatePem,
    "utf8",
  ).toString("base64");
  return [
    "-c",
    `activateServices=${plan.activateServices}`,
    "-c",
    `repositorySha=${plan.repositorySha}`,
    "-c",
    `controlPlaneImage=${plan.controlPlaneImage}`,
    "-c",
    `tunnelImage=${plan.tunnelImage}`,
    "-c",
    `sessionId=${plan.sessionId}`,
    "-c",
    `bootstrapBrokerCapabilityDigest=${plan.bootstrapBrokerCapabilityDigest}`,
    "-c",
    `relayTlsCertificatePemBase64=${certificateBase64}`,
    "-c",
    `relayPublicHostname=${plan.relayPublicHostname}`,
    "-c",
    `relayTlsFingerprint=${plan.relayTlsFingerprint}`,
    "-c",
    `relayTlsSecretArn=${plan.relayTlsSecretArn}`,
    "-c",
    `operatorPublicKey=${plan.operatorPublicKey}`,
    "-c",
    `sourceTreeSha256=${plan.sourceTreeSha256}`,
    "-c",
    `tunnelHostKeyFingerprint=${plan.tunnelHostKeyFingerprint}`,
    "-c",
    `tunnelHostPublicKey=${plan.tunnelHostPublicKey}`,
  ];
}

function isInside(parent, candidate) {
  const path = relative(parent, candidate);
  return (
    path === "" ||
    (!path.startsWith("..") &&
      !path.startsWith(`..${process.platform === "win32" ? "\\" : "/"}`))
  );
}

export async function writePrivateDeploymentEvidence({
  evidence,
  output,
  repositoryRoot,
}) {
  const destination = resolve(output);
  const root = resolve(repositoryRoot);
  if (isInside(root, destination)) {
    throw new Error(
      "Private deployment evidence must stay outside the repository.",
    );
  }
  const serialized = `${JSON.stringify(
    evidence,
    null,
    2,
  )}\n`;
  if (
    /"(?:secretValue|privateKey|password|token)"\s*:/i.test(
      serialized,
    )
  ) {
    throw new Error(
      "Private deployment evidence contains a forbidden secret field.",
    );
  }
  await mkdir(dirname(destination), {
    mode: 0o700,
    recursive: true,
  });
  const temporary = `${destination}.next`;
  let handle;
  try {
    handle = await open(temporary, "wx", 0o600);
    await handle.writeFile(serialized, "utf8");
    await handle.sync();
    await handle.close();
    handle = undefined;
    await rename(temporary, destination);
    await chmod(destination, 0o600);
  } catch (error) {
    await handle?.close().catch(() => {});
    await rm(temporary, {
      force: true,
    }).catch(() => {});
    throw error;
  }
}

async function runCdk(args) {
  return execFileAsync("npx", ["cdk", ...args], {
    cwd: new URL("..", import.meta.url),
    encoding: "utf8",
    env: {
      ...process.env,
      CDK_DEFAULT_ACCOUNT: DEFAULT_ACCOUNT,
      CDK_DEFAULT_REGION: DEFAULT_REGION,
    },
  });
}

async function main() {
  const repositorySha =
    await assertFrozenRelease();
  const controlPlaneImage =
    process.env.CONTROL_PLANE_IMAGE;
  const tunnelImage =
    process.env.TUNNEL_IMAGE;
  const sessionId =
    process.env.CLOCKCHAIN_SESSION_ID;
  const bootstrapBrokerCapabilityDigest =
    process.env.BOOTSTRAP_BROKER_CAPABILITY_DIGEST;
  const relayTlsCertificatePem =
    process.env.RELAY_TLS_CERTIFICATE_PEM;
  const relayPublicHostname =
    process.env.RELAY_PUBLIC_HOSTNAME;
  const relayTlsFingerprint =
    process.env.RELAY_TLS_FINGERPRINT;
  const relayTlsSecretArn =
    process.env.RELAY_TLS_SECRET_ARN;
  const operatorPublicKey =
    process.env.OPERATOR_PUBLIC_KEY;
  const sourceTreeSha256 =
    process.env.SOURCE_TREE_SHA256;
  const tunnelHostKeyFingerprint =
    process.env.TUNNEL_HOST_KEY_FINGERPRINT;
  const tunnelHostPublicKey =
    process.env.TUNNEL_HOST_PUBLIC_KEY;
  const activateServicesInput =
    process.env.ACTIVATE_SERVICES;
  if (
    activateServicesInput !== undefined &&
    activateServicesInput !== "true" &&
    activateServicesInput !== "false"
  ) {
    throw new Error(
      "ACTIVATE_SERVICES must be exactly true or false.",
    );
  }
  if (
    typeof controlPlaneImage !== "string" ||
    typeof tunnelImage !== "string"
  ) {
    throw new Error(
      "CONTROL_PLANE_IMAGE and TUNNEL_IMAGE digest references are required.",
    );
  }
  const plan = createDeploymentPlan({
    activateServices:
      activateServicesInput === "true",
    controlPlaneImage,
    repositorySha,
    bootstrapBrokerCapabilityDigest,
    relayTlsCertificatePem,
    relayPublicHostname,
    relayTlsFingerprint,
    relayTlsSecretArn,
    sessionId,
    operatorPublicKey,
    sourceTreeSha256,
    tunnelHostKeyFingerprint,
    tunnelHostPublicKey,
    tunnelImage,
  });
  const contexts = createDeploymentContexts(plan);
  if (process.argv.includes("--plan")) {
    const diff = await runCdk([
      "diff",
      "ClockchainHandshake",
      ...contexts,
    ]);
    process.stderr.write(diff.stdout);
    process.stderr.write(diff.stderr);
    process.stdout.write(
      `${JSON.stringify(plan, null, 2)}\n`,
    );
    return;
  }
  const deploymentOutputs =
    process.env.DEPLOYMENT_OUTPUTS_FILE ??
    `/tmp/clockchain-aws-outputs-${repositorySha}.json`;
  await runCdk([
    "deploy",
    "ClockchainHandshake",
    ...contexts,
    "--require-approval",
    "never",
    "--outputs-file",
    deploymentOutputs,
  ]);
  const outputs = JSON.parse(
    await readFile(
      deploymentOutputs,
      "utf8",
    ),
  );
  const evidence = {
    account: plan.account,
    activateServices:
      plan.activateServices,
    controlPlaneImage:
      plan.controlPlaneImage,
    deployedAtMs: Date.now(),
    legacyInfrastructure:
      plan.legacyInfrastructure,
    outputs:
      outputs.ClockchainHandshake ?? {},
    region: plan.region,
    repositorySha:
      plan.repositorySha,
    schema:
      "clockchain.aws-deployment-evidence/v1",
    tunnelImage: plan.tunnelImage,
  };
  const evidencePath =
    process.env.DEPLOYMENT_EVIDENCE_FILE ??
    `/tmp/clockchain-aws-deployment-${repositorySha}.json`;
  await writePrivateDeploymentEvidence({
    evidence,
    output: evidencePath,
    repositoryRoot: process.cwd(),
  });
  process.stdout.write(
    `${JSON.stringify(
      {
        account: plan.account,
        activateServices:
          plan.activateServices,
        evidencePath,
        legacyInfrastructure:
          plan.legacyInfrastructure,
        outputs: evidence.outputs,
        region: plan.region,
        repositorySha:
          plan.repositorySha,
        schema:
          "clockchain.aws-deployment-complete/v1",
      },
      null,
      2,
    )}\n`,
  );
}

if (
  process.argv[1] !== undefined &&
  import.meta.url ===
    pathToFileURL(process.argv[1]).href
) {
  main().catch((error) => {
    process.stderr.write(
      `${error instanceof Error ? error.message : "AWS deployment failed."}\n`,
    );
    process.exitCode = 1;
  });
}
