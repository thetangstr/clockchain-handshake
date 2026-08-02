import assert from "node:assert/strict";
import { chmod, lstat, mkdir, mkdtemp, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import {
  HYBRID_OPERATOR_CONFIG_SCHEMA,
  HybridOperatorConfigError,
  readHybridOperatorConfig,
} from "../src/bilateral/local-demo/operator-config.mjs";

async function privateFile(path, contents = "fixture\n") {
  await writeFile(path, contents, { flag: "wx", mode: 0o600 });
  await chmod(path, 0o600);
  return path;
}

async function fixture(t) {
  const root = await mkdtemp(join(tmpdir(), "clockchain-hybrid-config-"));
  t.after(async () => {
    await rm(root, { force: true, recursive: true });
  });
  await chmod(root, 0o700);

  const paths = Object.freeze({
    clockchainTokenFile: await privateFile(join(root, "clockchain-token")),
    configFile: join(root, "operator.json"),
    edgeHostKeyFile: await privateFile(join(root, "edge-known-hosts")),
    edgeIdentityFile: await privateFile(join(root, "edge-identity")),
    keystoreFile: await privateFile(join(root, "treasury.json"), "{}\n"),
    operatorPrivateKeyFile: await privateFile(join(root, "operator-private.pem")),
    payerCertificateFile: await privateFile(join(root, "payer-mcp.crt")),
    payerPrivateKeyFile: await privateFile(join(root, "payer-mcp.key")),
    relayCertificateFile: await privateFile(join(root, "relay.crt")),
    relayPrivateKeyFile: await privateFile(join(root, "relay.key")),
    rpcUrlFile: await privateFile(join(root, "sepolia-rpc"), "https://rpc.example.invalid\n"),
    stateRoot: join(root, "new-state"),
  });
  const value = {
    console: { host: "127.0.0.1", port: 8787 },
    funding: {
      journalDirectory: join(root, "funding-journal"),
      keystoreFile: paths.keystoreFile,
      mode: "fund-on-ready",
    },
    operator: {
      clockchainTokenFile: paths.clockchainTokenFile,
      keyId: "operator-yang",
      privateKeyFile: paths.operatorPrivateKeyFile,
      rpcUrlFile: paths.rpcUrlFile,
    },
    payerMcp: {
      host: "127.0.0.1",
      port: 9443,
      publicUrl: "https://32.186.198.119:9443/mcp",
      tlsCertificateFile: paths.payerCertificateFile,
      tlsPrivateKeyFile: paths.payerPrivateKeyFile,
    },
    paymentMoved: false,
    publicEdge: {
      coordinationPublicUrl: "https://32.186.198.119:8443",
      host: "32.186.198.119",
      hostKeyFile: paths.edgeHostKeyFile,
      identityFile: paths.edgeIdentityFile,
      payerMcpRemotePort: 9443,
      port: 22,
      relayRemotePort: 8443,
      user: "clockchain-tunnel",
    },
    publishing: {
      bucket: "clockchain-handshake-monitor-570035913370-us-west-2",
      receiptEmailUrl: "https://anhgkkcm46.execute-api.us-west-2.amazonaws.com/v1/receipt-email",
      region: "us-west-2",
      requestorDiscoveryUrl: "https://clockchain-handshake-monitor-570035913370-us-west-2.s3.us-west-2.amazonaws.com/requestor-discovery.json",
    },
    relay: {
      advertisedHost: "32.186.198.119",
      host: "127.0.0.1",
      port: 8443,
      tlsCertificateFile: paths.relayCertificateFile,
      tlsFingerprint: "a".repeat(64),
      tlsPrivateKeyFile: paths.relayPrivateKeyFile,
    },
    repositorySha: "b".repeat(40),
    schema: HYBRID_OPERATOR_CONFIG_SCHEMA,
  };
  return { paths, root, value };
}

async function writeConfig(path, value, mode = 0o600) {
  await writeFile(path, `${JSON.stringify(value)}\n`, { flag: "wx", mode });
  await chmod(path, mode);
}

function fixedFailure(error) {
  assert.equal(error instanceof HybridOperatorConfigError, true);
  assert.equal(error.code, "HYBRID_OPERATOR_CONFIG_INVALID");
  assert.equal(error.category, "configuration");
  assert.equal(error.message, "Hybrid local operator configuration failed safely.");
  return true;
}

test("reads one exact path-only hybrid operator configuration without opening secret values", async (t) => {
  const { paths, value } = await fixture(t);
  await writeConfig(paths.configFile, value);

  const reads = [];
  const config = await readHybridOperatorConfig(paths.configFile, paths.stateRoot, {
    onPrivatePath(path) {
      reads.push(path);
    },
  });

  assert.deepEqual(config, value);
  assert.equal(Object.isFrozen(config), true);
  assert.equal(Object.isFrozen(config.operator), true);
  assert.deepEqual(new Set(reads), new Set([
    paths.clockchainTokenFile,
    paths.edgeHostKeyFile,
    paths.edgeIdentityFile,
    paths.keystoreFile,
    paths.operatorPrivateKeyFile,
    paths.payerCertificateFile,
    paths.payerPrivateKeyFile,
    paths.relayCertificateFile,
    paths.relayPrivateKeyFile,
    paths.rpcUrlFile,
  ]));
});

test("fails closed on unsafe config identity, state reuse, and noncanonical JSON", async (t) => {
  await t.test("permissive config", async (t) => {
    const { paths, value } = await fixture(t);
    await writeConfig(paths.configFile, value, 0o644);
    await assert.rejects(readHybridOperatorConfig(paths.configFile, paths.stateRoot), fixedFailure);
  });

  await t.test("symlinked config", async (t) => {
    const { paths, root, value } = await fixture(t);
    const target = join(root, "target.json");
    await writeConfig(target, value);
    await symlink(target, paths.configFile);
    await assert.rejects(readHybridOperatorConfig(paths.configFile, paths.stateRoot), fixedFailure);
  });

  await t.test("existing state root", async (t) => {
    const { paths, value } = await fixture(t);
    await writeConfig(paths.configFile, value);
    await mkdir(paths.stateRoot, { mode: 0o700 });
    await assert.rejects(readHybridOperatorConfig(paths.configFile, paths.stateRoot), fixedFailure);
  });

  await t.test("duplicate JSON key", async (t) => {
    const { paths, value } = await fixture(t);
    const body = JSON.stringify(value);
    await writeFile(paths.configFile, `${body.slice(0, -1)},\"paymentMoved\":false}\n`, { flag: "wx", mode: 0o600 });
    await assert.rejects(readHybridOperatorConfig(paths.configFile, paths.stateRoot), fixedFailure);
  });

  await t.test("trailing whitespace", async (t) => {
    const { paths, value } = await fixture(t);
    await writeFile(paths.configFile, `${JSON.stringify(value)} \n`, { flag: "wx", mode: 0o600 });
    await assert.rejects(readHybridOperatorConfig(paths.configFile, paths.stateRoot), fixedFailure);
  });
});

test("fails closed on changed fields, embedded values, public-port drift, and unsafe private paths", async (t) => {
  const cases = [
    ["extra top-level key", (value) => ({ ...value, extra: true })],
    ["payment moved", (value) => ({ ...value, paymentMoved: true })],
    ["relative token path", (value) => ({ ...value, operator: { ...value.operator, clockchainTokenFile: "token" } })],
    ["embedded bearer token", (value) => ({ ...value, operator: { ...value.operator, clockchainTokenFile: "Bearer secret" } })],
    ["embedded private key", (value) => ({ ...value, operator: { ...value.operator, privateKeyFile: `0x${"1".repeat(64)}` } })],
    ["non-loopback relay", (value) => ({ ...value, relay: { ...value.relay, host: "0.0.0.0" } })],
    ["non-loopback payer", (value) => ({ ...value, payerMcp: { ...value.payerMcp, host: "0.0.0.0" } })],
    ["relay port drift", (value) => ({ ...value, publicEdge: { ...value.publicEdge, relayRemotePort: 8444 } })],
    ["payer port drift", (value) => ({ ...value, publicEdge: { ...value.publicEdge, payerMcpRemotePort: 9444 } })],
    ["unsupported funding mode", (value) => ({ ...value, funding: { ...value.funding, mode: "manual" } })],
  ];

  for (const [name, change] of cases) {
    await t.test(name, async (t) => {
      const { paths, value } = await fixture(t);
      await writeConfig(paths.configFile, change(value));
      await assert.rejects(readHybridOperatorConfig(paths.configFile, paths.stateRoot), fixedFailure);
    });
  }

  await t.test("symlinked private input", async (t) => {
    const { paths, root, value } = await fixture(t);
    const target = join(root, "alternate-token");
    await privateFile(target);
    const symlinkPath = join(root, "token-link");
    await symlink(target, symlinkPath);
    await writeConfig(paths.configFile, {
      ...value,
      operator: { ...value.operator, clockchainTokenFile: symlinkPath },
    });
    await assert.rejects(readHybridOperatorConfig(paths.configFile, paths.stateRoot), fixedFailure);
  });

  await t.test("private input changed after inspection", async (t) => {
    const { paths, value } = await fixture(t);
    await writeConfig(paths.configFile, value);
    let changed = false;
    await assert.rejects(
      readHybridOperatorConfig(paths.configFile, paths.stateRoot, {
        async onPrivatePath(path) {
          if (!changed && path === paths.clockchainTokenFile) {
            changed = true;
            await writeFile(path, "changed\n");
          }
        },
      }),
      fixedFailure,
    );
    assert.equal((await lstat(paths.clockchainTokenFile)).isFile(), true);
  });
});
