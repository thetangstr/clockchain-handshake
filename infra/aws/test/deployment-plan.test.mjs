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
  createDeploymentContexts,
  createDeploymentPlan,
  writePrivateDeploymentEvidence,
} from "../scripts/deploy.mjs";

const SHA = "a".repeat(40);
const DIGEST = `sha256:${"b".repeat(64)}`;
const RELAY_TLS_CERTIFICATE_PEM = `-----BEGIN CERTIFICATE-----
MIIBdDCCASagAwIBAgIUPrXOrIpEJb7MiFXU0DDWShb37kIwBQYDK2VwMB8xHTAb
BgNVBAMMFHJlbGF5LmNsb2NrY2hhaW4ubmV0MB4XDTI2MDczMTIyNDIyN1oXDTI2
MDgwMTIyNDIyN1owHzEdMBsGA1UEAwwUcmVsYXkuY2xvY2tjaGFpbi5uZXQwKjAF
BgMrZXADIQDwMVNUm7k6YU4Ra2V4wCNd0g55HJvSHdDe25+8kjDieaN0MHIwHQYD
VR0OBBYEFMWEqIIWZMtV/0sLBCI8b/LPLlxKMB8GA1UdIwQYMBaAFMWEqIIWZMtV
/0sLBCI8b/LPLlxKMA8GA1UdEwEB/wQFMAMBAf8wHwYDVR0RBBgwFoIUcmVsYXku
Y2xvY2tjaGFpbi5uZXQwBQYDK2VwA0EAaeNXc+Bk8jhlk7JOWlWPgajcq14EO03b
GzRaxazJRJqgomGuhMdWNo8pqbWf9+sUnkkr9ZGuAGcK3zyS6UeHDA==
-----END CERTIFICATE-----
`;

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

test("container release metadata uses the prevalidated SHA without requiring copied Git metadata", async () => {
  for (const dockerfile of [
    "control-plane.Dockerfile",
    "tunnel.Dockerfile",
  ]) {
    const source = await readFile(
      new URL(`../docker/${dockerfile}`, import.meta.url),
      "utf8",
    );
    assert.match(source, /REPOSITORY_SHA/);
    assert.match(source, /clockchain\.container-release\/v1/);
    assert.doesNotMatch(source, /git rev-parse|git diff|git status/);
  }
});

test("deployment plan uses image digests and fixed account without deleting legacy infrastructure", () => {
  const plan = createDeploymentPlan({
    account: "570035913370",
    controlPlaneImage:
      `570035913370.dkr.ecr.us-west-2.amazonaws.com/clockchain-handshake-control-plane@${DIGEST}`,
    bootstrapBrokerCapabilityDigest:
      "c".repeat(64),
    operatorPublicKey:
      "oIcoZqI/cqzG4UbXcaV+k1fxwt8EBb+9S+XNcb9pq3k=",
    region: "us-west-2",
    relayTlsCertificatePem:
      RELAY_TLS_CERTIFICATE_PEM,
    relayPublicHostname:
      "relay.clockchain.net",
    relayTlsFingerprint:
      "3dbe9d0ea7491d9d6e4586f978ddf2b67c4ac173780b3b8d5b86def84a0d73d9",
    relayTlsSecretArn:
      "arn:aws:secretsmanager:us-west-2:570035913370:secret:clockchain-relay-tls-AbCdEf",
    repositorySha: SHA,
    sessionId:
      "11111111-1111-4111-8111-111111111111",
    sourceTreeSha256: "e".repeat(64),
    tunnelImage:
      `570035913370.dkr.ecr.us-west-2.amazonaws.com/clockchain-handshake-tunnel@${DIGEST}`,
  });

  assert.equal(plan.account, "570035913370");
  assert.equal(plan.activateServices, false);
  assert.equal(plan.region, "us-west-2");
  assert.equal(plan.repositorySha, SHA);
  assert.equal(
    plan.operatorPublicKey,
    "oIcoZqI/cqzG4UbXcaV+k1fxwt8EBb+9S+XNcb9pq3k=",
  );
  assert.equal(
    plan.relayPublicHostname,
    "relay.clockchain.net",
  );
  assert.equal(
    plan.relayTlsSecretArn,
    "arn:aws:secretsmanager:us-west-2:570035913370:secret:clockchain-relay-tls-AbCdEf",
  );
  assert.equal(
    plan.sessionId,
    "11111111-1111-4111-8111-111111111111",
  );
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

test("deployment plan rejects a relay certificate hostname mismatch", () => {
  assert.throws(
    () =>
      createDeploymentPlan({
        account: "570035913370",
        bootstrapBrokerCapabilityDigest:
          "c".repeat(64),
        controlPlaneImage:
          `570035913370.dkr.ecr.us-west-2.amazonaws.com/clockchain-handshake-control-plane@${DIGEST}`,
        operatorPublicKey:
          "oIcoZqI/cqzG4UbXcaV+k1fxwt8EBb+9S+XNcb9pq3k=",
        region: "us-west-2",
        relayPublicHostname:
          "other.clockchain.net",
        relayTlsCertificatePem:
          RELAY_TLS_CERTIFICATE_PEM,
        relayTlsFingerprint:
          "3dbe9d0ea7491d9d6e4586f978ddf2b67c4ac173780b3b8d5b86def84a0d73d9",
        relayTlsSecretArn:
          "arn:aws:secretsmanager:us-west-2:570035913370:secret:clockchain-relay-tls-AbCdEf",
        repositorySha: SHA,
        sessionId:
          "11111111-1111-4111-8111-111111111111",
        sourceTreeSha256: "e".repeat(64),
        tunnelImage:
          `570035913370.dkr.ecr.us-west-2.amazonaws.com/clockchain-handshake-tunnel@${DIGEST}`,
      }),
    /hostname/i,
  );
});

test("deployment contexts encode the public TLS certificate without multiline argv", () => {
  const plan = createDeploymentPlan({
    activateServices: true,
    account: "570035913370",
    bootstrapBrokerCapabilityDigest:
      "c".repeat(64),
    controlPlaneImage:
      `570035913370.dkr.ecr.us-west-2.amazonaws.com/clockchain-handshake-control-plane@${DIGEST}`,
    operatorPublicKey:
      "oIcoZqI/cqzG4UbXcaV+k1fxwt8EBb+9S+XNcb9pq3k=",
    region: "us-west-2",
    relayPublicHostname:
      "relay.clockchain.net",
    relayTlsCertificatePem:
      RELAY_TLS_CERTIFICATE_PEM,
    relayTlsFingerprint:
      "3dbe9d0ea7491d9d6e4586f978ddf2b67c4ac173780b3b8d5b86def84a0d73d9",
    relayTlsSecretArn:
      "arn:aws:secretsmanager:us-west-2:570035913370:secret:clockchain-relay-tls-AbCdEf",
    repositorySha: SHA,
    sessionId:
      "11111111-1111-4111-8111-111111111111",
    sourceTreeSha256: "e".repeat(64),
    tunnelImage:
      `570035913370.dkr.ecr.us-west-2.amazonaws.com/clockchain-handshake-tunnel@${DIGEST}`,
  });
  const contexts = createDeploymentContexts(plan);
  assert.equal(
    contexts.includes("activateServices=true"),
    true,
  );
  assert.equal(
    contexts.includes(
      "operatorPublicKey=oIcoZqI/cqzG4UbXcaV+k1fxwt8EBb+9S+XNcb9pq3k=",
    ),
    true,
  );
  const certificate = contexts.find((value) =>
    value.startsWith(
      "relayTlsCertificatePemBase64=",
    ));
  assert.equal(typeof certificate, "string");
  assert.equal(certificate.includes("\n"), false);
  assert.equal(
    Buffer.from(
      certificate.slice(
        certificate.indexOf("=") + 1,
      ),
      "base64",
    ).toString("utf8"),
    RELAY_TLS_CERTIFICATE_PEM,
  );
  assert.equal(
    contexts.some((value) =>
      value.includes("BEGIN CERTIFICATE")),
    false,
  );
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

test("private evidence never changes permissions on an existing shared parent", async () => {
  const directory = await mkdtemp(
    join(tmpdir(), "clockchain-shared-evidence-"),
  );
  await chmod(directory, 0o755);
  const before =
    (await stat(directory)).mode & 0o777;
  const output = join(directory, "deployment.json");

  await writePrivateDeploymentEvidence({
    evidence: {
      repositorySha: SHA,
      schema: "clockchain.aws-deployment-evidence/v1",
    },
    output,
    repositoryRoot: process.cwd(),
  });

  assert.equal(
    (await stat(directory)).mode & 0o777,
    before,
  );
  assert.equal(
    (await stat(output)).mode & 0o777,
    0o600,
  );
});
