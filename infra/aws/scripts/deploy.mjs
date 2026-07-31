#!/usr/bin/env node

import { execFile } from "node:child_process";
import {
  chmod,
  mkdir,
  open,
  rename,
  rm,
} from "node:fs/promises";
import { dirname, relative, resolve } from "node:path";
import { promisify } from "node:util";
import { pathToFileURL } from "node:url";

import {
  assertFrozenRelease,
  DEFAULT_ACCOUNT,
  DEFAULT_REGION,
} from "./build-and-push.mjs";

const execFileAsync = promisify(execFile);
const SHA40 = /^[0-9a-f]{40}$/;
const IMAGE =
  /^[0-9]{12}\.dkr\.ecr\.[a-z]{2}-[a-z]+-[1-9]\.amazonaws\.com\/[a-z0-9][a-z0-9._/-]{0,254}@sha256:[0-9a-f]{64}$/;

function required(value, pattern, label) {
  if (
    typeof value !== "string" ||
    !pattern.test(value)
  ) {
    throw new Error(`${label} is invalid.`);
  }
  return value;
}

export function createDeploymentPlan({
  account = DEFAULT_ACCOUNT,
  controlPlaneImage,
  region = DEFAULT_REGION,
  repositorySha,
  tunnelImage,
}) {
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
  return {
    account,
    controlPlaneImage,
    legacyInfrastructure: {
      action: "preserve",
    },
    region,
    repositorySha,
    schema: "clockchain.aws-deployment-plan/v1",
    stacks: [
      "ClockchainHandshakeImages",
      "ClockchainHandshake",
    ],
    tunnelImage,
  };
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
  await chmod(dirname(destination), 0o700);
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
  await execFileAsync("npx", ["cdk", ...args], {
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
  if (
    typeof controlPlaneImage !== "string" ||
    typeof tunnelImage !== "string"
  ) {
    throw new Error(
      "CONTROL_PLANE_IMAGE and TUNNEL_IMAGE digest references are required.",
    );
  }
  const plan = createDeploymentPlan({
    controlPlaneImage,
    repositorySha,
    tunnelImage,
  });
  const contexts = [
    "-c",
    `repositorySha=${repositorySha}`,
    "-c",
    `controlPlaneImage=${controlPlaneImage}`,
    "-c",
    `tunnelImage=${tunnelImage}`,
  ];
  if (process.argv.includes("--plan")) {
    await runCdk([
      "diff",
      "ClockchainHandshake",
      ...contexts,
      "--fail",
    ]);
    process.stdout.write(
      `${JSON.stringify(plan, null, 2)}\n`,
    );
    return;
  }
  await runCdk([
    "deploy",
    "ClockchainHandshake",
    ...contexts,
    "--require-approval",
    "never",
    "--outputs-file",
    process.env.DEPLOYMENT_OUTPUTS_FILE ??
      "/tmp/clockchain-aws-outputs.json",
  ]);
  process.stdout.write(
    `${JSON.stringify(
      {
        account: plan.account,
        legacyInfrastructure:
          plan.legacyInfrastructure,
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
