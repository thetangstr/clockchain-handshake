#!/usr/bin/env node

import {
  DescribeImagesCommand,
  DescribeRepositoriesCommand,
  ECRClient,
  GetAuthorizationTokenCommand,
} from "@aws-sdk/client-ecr";
import { execFile, spawn } from "node:child_process";
import { promisify } from "node:util";
import {
  fileURLToPath,
  pathToFileURL,
} from "node:url";

const execFileAsync = promisify(execFile);
const SHA40 = /^[0-9a-f]{40}$/;
const DIGEST = /^sha256:[0-9a-f]{64}$/;
const REPOSITORY_ROOT = fileURLToPath(
  new URL("../../../", import.meta.url),
);

export const DEFAULT_ACCOUNT = "570035913370";
export const DEFAULT_REGION = "us-west-2";
export const CONTROL_REPOSITORY =
  "clockchain-handshake-control-plane";
export const TUNNEL_REPOSITORY =
  "clockchain-handshake-tunnel";

async function defaultGit(args, { allowFailure = false } = {}) {
  try {
    const { stdout } = await execFileAsync("git", args, {
      encoding: "utf8",
    });
    return stdout;
  } catch (error) {
    if (allowFailure) {
      return "";
    }
    throw error;
  }
}

export async function assertFrozenRelease({
  git = defaultGit,
} = {}) {
  const status = await git([
    "status",
    "--short",
    "--untracked-files=all",
  ]);
  if (status.trim() !== "") {
    throw new Error(
      "Release candidate must have a clean worktree.",
    );
  }
  const attached = await git(
    ["symbolic-ref", "-q", "HEAD"],
    { allowFailure: true },
  );
  if (attached.trim() !== "") {
    throw new Error(
      "Release candidate must use a detached HEAD.",
    );
  }
  const repositorySha = (
    await git(["rev-parse", "HEAD"])
  ).trim();
  if (!SHA40.test(repositorySha)) {
    throw new Error(
      "Release candidate SHA is invalid.",
    );
  }
  return repositorySha;
}

function required(value, pattern, label) {
  if (
    typeof value !== "string" ||
    !pattern.test(value)
  ) {
    throw new Error(`${label} is invalid.`);
  }
  return value;
}

export function createBuildPlan({
  account = DEFAULT_ACCOUNT,
  controlRepository = CONTROL_REPOSITORY,
  region = DEFAULT_REGION,
  repositorySha,
  tunnelRepository = TUNNEL_REPOSITORY,
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
  const registry =
    `${account}.dkr.ecr.${region}.amazonaws.com`;
  return {
    account,
    images: [
      {
        buildArgs: {
          REPOSITORY_SHA: repositorySha,
        },
        dockerfile:
          "infra/aws/docker/control-plane.Dockerfile",
        name: "controlPlane",
        platform: "linux/amd64",
        repository: controlRepository,
        tag: repositorySha,
        uri: `${registry}/${controlRepository}:${repositorySha}`,
      },
      {
        buildArgs: {
          REPOSITORY_SHA: repositorySha,
        },
        dockerfile:
          "infra/aws/docker/tunnel.Dockerfile",
        name: "tunnel",
        platform: "linux/amd64",
        repository: tunnelRepository,
        tag: repositorySha,
        uri: `${registry}/${tunnelRepository}:${repositorySha}`,
      },
    ],
    region,
    repositorySha,
    schema: "clockchain.aws-image-plan/v1",
  };
}

export function createDockerBuildInvocation({
  image,
  repositoryRoot = REPOSITORY_ROOT,
  repositorySha,
}) {
  required(
    repositorySha,
    SHA40,
    "Repository SHA",
  );
  if (
    typeof repositoryRoot !== "string" ||
    repositoryRoot.length === 0
  ) {
    throw new Error(
      "Repository root is invalid.",
    );
  }
  return {
    args: [
      "buildx",
      "build",
      "--platform",
      image.platform,
      "--build-arg",
      `REPOSITORY_SHA=${repositorySha}`,
      "--file",
      image.dockerfile,
      "--tag",
      image.uri,
      "--push",
      ".",
    ],
    cwd: repositoryRoot,
  };
}

async function runDocker(
  args,
  { cwd = REPOSITORY_ROOT, input } = {},
) {
  await new Promise((resolve, reject) => {
    const child = spawn("docker", args, {
      cwd,
      stdio: [
        input === undefined ? "ignore" : "pipe",
        "inherit",
        "inherit",
      ],
    });
    child.once("error", reject);
    child.once("exit", (code) => {
      if (code === 0) {
        resolve();
      } else {
        reject(
          new Error(
            `Docker command failed with exit ${code}.`,
          ),
        );
      }
    });
    if (input !== undefined) {
      child.stdin.end(input);
    }
  });
}

async function assertRepositories(client, plan) {
  const response = await client.send(
    new DescribeRepositoriesCommand({
      repositoryNames: plan.images.map(
        (image) => image.repository,
      ),
    }),
  );
  const repositories =
    response.repositories ?? [];
  for (const image of plan.images) {
    const repository = repositories.find(
      (candidate) =>
        candidate.repositoryName ===
        image.repository,
    );
    if (
      repository?.imageTagMutability !==
        "IMMUTABLE" ||
      repository.imageScanningConfiguration
        ?.scanOnPush !== true
    ) {
      throw new Error(
        `ECR repository ${image.repository} is missing immutable scan-on-push policy.`,
      );
    }
  }
}

export async function buildAndPush({
  account = DEFAULT_ACCOUNT,
  client = new ECRClient({
    region: DEFAULT_REGION,
  }),
  region = DEFAULT_REGION,
  repositorySha,
  runDockerCommand = runDocker,
} = {}) {
  const plan = createBuildPlan({
    account,
    region,
    repositorySha,
  });
  await assertRepositories(client, plan);
  const authorization = await client.send(
    new GetAuthorizationTokenCommand({}),
  );
  const encoded =
    authorization.authorizationData?.[0]
      ?.authorizationToken;
  if (typeof encoded !== "string") {
    throw new Error(
      "ECR authorization token unavailable.",
    );
  }
  const [username, password] = Buffer.from(
    encoded,
    "base64",
  )
    .toString("utf8")
    .split(":", 2);
  if (
    typeof username !== "string" ||
    typeof password !== "string" ||
    password.length === 0
  ) {
    throw new Error(
      "ECR authorization token invalid.",
    );
  }
  const registry =
    `${account}.dkr.ecr.${region}.amazonaws.com`;
  await runDockerCommand(
    [
      "login",
      "--username",
      username,
      "--password-stdin",
      registry,
    ],
    { input: password },
  );

  const resolved = {};
  for (const image of plan.images) {
    const invocation =
      createDockerBuildInvocation({
        image,
        repositorySha,
      });
    await runDockerCommand(
      invocation.args,
      { cwd: invocation.cwd },
    );
    const response = await client.send(
      new DescribeImagesCommand({
        imageIds: [
          {
            imageTag: repositorySha,
          },
        ],
        repositoryName: image.repository,
      }),
    );
    const digest =
      response.imageDetails?.[0]?.imageDigest;
    required(
      digest,
      DIGEST,
      `${image.name} image digest`,
    );
    resolved[image.name] =
      `${registry}/${image.repository}@${digest}`;
  }
  return {
    ...plan,
    resolved,
  };
}

async function main() {
  const repositorySha =
    await assertFrozenRelease();
  const plan = createBuildPlan({
    repositorySha,
  });
  if (process.argv.includes("--plan")) {
    process.stdout.write(
      `${JSON.stringify(plan, null, 2)}\n`,
    );
    return;
  }
  const result = await buildAndPush({
    repositorySha,
  });
  process.stdout.write(
    `${JSON.stringify(result, null, 2)}\n`,
  );
}

if (
  process.argv[1] !== undefined &&
  import.meta.url ===
    pathToFileURL(process.argv[1]).href
) {
  main().catch((error) => {
    process.stderr.write(
      `${error instanceof Error ? error.message : "AWS image build failed."}\n`,
    );
    process.exitCode = 1;
  });
}
