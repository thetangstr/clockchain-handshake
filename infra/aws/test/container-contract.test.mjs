import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { test } from "node:test";

const ROOT = new URL("../../..", import.meta.url)
  .pathname;

function read(path) {
  return readFileSync(join(ROOT, path), "utf8");
}

test("sshd is remote-forward-only on the fixed unprivileged container port", () => {
  const config = read("infra/aws/docker/sshd_config");
  for (const line of [
    "Port 2222",
    "PasswordAuthentication no",
    "KbdInteractiveAuthentication no",
    "PermitRootLogin no",
    "AllowTcpForwarding remote",
    "GatewayPorts clientspecified",
    "PermitTTY no",
    "X11Forwarding no",
    "PermitUserRC no",
    "MaxSessions 1",
  ]) {
    assert.equal(config.includes(`${line}\n`), true, line);
  }
  assert.match(config, /^AuthorizedKeysFile \/run\/clockchain\/authorized_keys$/m);
  assert.match(config, /^ForceCommand \/usr\/sbin\/nologin$/m);
});

test("tunnel image is Node 22, non-root, nologin, fixed-port, and read-only-root compatible", () => {
  const dockerfile = read(
    "infra/aws/docker/tunnel.Dockerfile",
  );
  const config = read(
    "infra/aws/docker/sshd_config",
  );
  assert.match(dockerfile, /^FROM node:22-/m);
  assert.match(
    dockerfile,
    /useradd[^\n]+(?:nologin|false)/,
  );
  assert.match(dockerfile, /^EXPOSE 2222 9443 8080$/m);
  assert.match(dockerfile, /^VOLUME \["\/run\/clockchain"\]$/m);
  assert.match(
    dockerfile,
    /npm ci --prefix infra\/aws --omit=dev --ignore-scripts/,
  );
  assert.match(
    dockerfile,
    /^CMD \["node", "infra\/aws\/runtime\/tunnel-entrypoint\.mjs"\]$/m,
  );
  assert.match(
    config,
    /^HostKey \/run\/clockchain\/ssh_host_ed25519_key$/m,
  );
  assert.equal(/COPY .*?(?:\.key|secret|token|keystore)/i.test(dockerfile), false);
});

test("both images generate exact immutable release provenance and reject dirty or mismatched source", () => {
  for (const path of [
    "infra/aws/docker/control-plane.Dockerfile",
    "infra/aws/docker/tunnel.Dockerfile",
  ]) {
    const dockerfile = read(path);
    assert.match(
      dockerfile,
      /^ARG REPOSITORY_SHA$/m,
      path,
    );
    assert.match(
      dockerfile,
      /git diff --quiet/,
      path,
    );
    assert.match(
      dockerfile,
      /git rev-parse HEAD/,
      path,
    );
    assert.match(
      dockerfile,
      /\/opt\/clockchain\/release\.json/,
      path,
    );
    assert.equal(
      /COPY .*?(?:\.key|secret|token|keystore)/i.test(
        dockerfile,
      ),
      false,
      path,
    );
  }
});

test("AWS SDK construction stays in infrastructure entrypoints", () => {
  for (const path of [
    "scripts/run-aws-bootstrap-service.mjs",
    "scripts/run-aws-coordinator.mjs",
    "scripts/run-aws-funding-task.mjs",
    "scripts/run-aws-operator-worker.mjs",
    "scripts/publish-aws-public-monitor.mjs",
    "scripts/run-aws-relay.mjs",
    "scripts/run-aws-tunnel-service.mjs",
    "scripts/run-aws-verifier-task.mjs",
  ]) {
    assert.equal(
      read(path).includes("@aws-sdk/"),
      false,
      path,
    );
  }
  assert.match(
    read("infra/aws/runtime/aws-clients.mjs"),
    /@aws-sdk\//,
  );
});

test("package exposes exact AWS image and task commands", () => {
  const packageJson = JSON.parse(read("package.json"));
  assert.deepEqual(
    Object.fromEntries(
      Object.entries(packageJson.scripts).filter(
        ([name]) => name.startsWith("aws:"),
      ),
    ),
    {
      "aws:bootstrap":
        "node scripts/run-aws-bootstrap-service.mjs",
      "aws:coordinator":
        "node scripts/run-aws-coordinator.mjs",
      "aws:fund":
        "node scripts/run-aws-funding-task.mjs",
      "aws:operator-worker":
        "node scripts/run-aws-operator-worker.mjs",
      "aws:public-monitor":
        "node scripts/publish-aws-public-monitor.mjs",
      "aws:relay":
        "node scripts/run-aws-relay.mjs",
      "aws:tunnel":
        "node scripts/run-aws-tunnel-service.mjs",
      "aws:verify":
        "node scripts/run-aws-verifier-task.mjs",
    },
  );
});
