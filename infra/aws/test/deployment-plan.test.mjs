import assert from "node:assert/strict";
import { chmod, mkdtemp, readFile, stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import {
  assertFrozenRelease,
  createBuildPlan,
  createDockerBuildInvocation,
} from "../scripts/build-and-push.mjs";
import {
  createDeploymentPlan,
  writePrivateDeploymentEvidence,
} from "../scripts/deploy.mjs";

const SHA = "a".repeat(40);
const DIGEST = `sha256:${"b".repeat(64)}`;

test("frozen release validation rejects dirty and attached worktrees", async () => {
  await assert.rejects(
    assertFrozenRelease({
      git: async (args) => {
        if (args.includes("status")) {
          return " M README.md\n";
        }
        return args.includes("symbolic-ref") ? "" : SHA;
      },
    }),
    /clean/i,
  );
  await assert.rejects(
    assertFrozenRelease({
      git: async (args) =>
        args.includes("symbolic-ref")
          ? "refs/heads/main\n"
          : "",
    }),
    /detached/i,
  );
});

test("build plan pins linux amd64 images to the exact repository SHA", () => {
  const plan = createBuildPlan({
    account: "570035913370",
    controlRepository:
      "clockchain-handshake-control-plane",
    region: "us-west-2",
    repositorySha: SHA,
    tunnelRepository:
      "clockchain-handshake-tunnel",
  });

  assert.equal(plan.schema, "clockchain.aws-image-plan/v1");
  assert.equal(plan.repositorySha, SHA);
  assert.equal(plan.images.length, 2);
  for (const image of plan.images) {
    assert.equal(image.platform, "linux/amd64");
    assert.equal(image.tag, SHA);
    assert.match(image.uri, new RegExp(`:${SHA}$`));
    assert.deepEqual(image.buildArgs, {
      REPOSITORY_SHA: SHA,
    });
  }
  assert.doesNotMatch(JSON.stringify(plan), /password|secretValue|privateKey/i);
});

test("docker build always runs from the reviewed repository root", () => {
  const plan = createBuildPlan({
    repositorySha: SHA,
  });
  const invocation =
    createDockerBuildInvocation({
      image: plan.images[0],
      repositoryRoot:
        "/private/reviewed-checkout",
      repositorySha: SHA,
    });
  assert.equal(
    invocation.cwd,
    "/private/reviewed-checkout",
  );
  assert.equal(
    invocation.args.at(-1),
    ".",
  );
  assert.match(
    invocation.args.join(" "),
    /infra\/aws\/docker\/control-plane\.Dockerfile/,
  );
});

test("deployment plan uses image digests and fixed account without deleting legacy infrastructure", () => {
  const plan = createDeploymentPlan({
    account: "570035913370",
    controlPlaneImage:
      `570035913370.dkr.ecr.us-west-2.amazonaws.com/clockchain-handshake-control-plane@${DIGEST}`,
    region: "us-west-2",
    repositorySha: SHA,
    tunnelImage:
      `570035913370.dkr.ecr.us-west-2.amazonaws.com/clockchain-handshake-tunnel@${DIGEST}`,
  });

  assert.equal(plan.account, "570035913370");
  assert.equal(plan.region, "us-west-2");
  assert.equal(plan.repositorySha, SHA);
  assert.deepEqual(plan.stacks, [
    "ClockchainHandshakeImages",
    "ClockchainHandshake",
  ]);
  assert.deepEqual(plan.legacyInfrastructure, {
    action: "preserve",
  });
  assert.match(plan.controlPlaneImage, /@sha256:[0-9a-f]{64}$/);
  assert.match(plan.tunnelImage, /@sha256:[0-9a-f]{64}$/);
  assert.doesNotMatch(JSON.stringify(plan), /secretValue|password|privateKey/i);
});

test("private deployment evidence is written outside the repository with strict permissions", async (t) => {
  const directory = await mkdtemp(
    join(tmpdir(), "clockchain-deployment-evidence-"),
  );
  t.after(async () => {
    await chmod(directory, 0o700).catch(() => {});
  });
  const output = join(directory, "deployment.json");
  await writePrivateDeploymentEvidence({
    evidence: {
      imageDigests: {
        controlPlane: DIGEST,
        tunnel: DIGEST,
      },
      repositorySha: SHA,
      schema: "clockchain.aws-deployment-evidence/v1",
      secretArns: [
        "arn:aws:secretsmanager:us-west-2:570035913370:secret:example",
      ],
    },
    output,
    repositoryRoot: process.cwd(),
  });
  assert.equal((await stat(output)).mode & 0o777, 0o600);
  assert.match(await readFile(output, "utf8"), /aws-deployment-evidence/);
  await assert.rejects(
    writePrivateDeploymentEvidence({
      evidence: { schema: "invalid" },
      output: join(process.cwd(), ".context", "deployment.json"),
      repositoryRoot: process.cwd(),
    }),
    /outside/i,
  );
});
