import assert from "node:assert/strict";
import { createServer } from "node:http";
import {
  link,
  lstat,
  mkdir,
  mkdtemp,
  open as openFile,
  readFile,
  readdir,
  realpath,
  rename,
  stat,
  symlink,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { spawn } from "node:child_process";
import test from "node:test";

import { parseEther } from "viem";
import { privateKeyToAccount } from "viem/accounts";

import {
  CHAIN_ID,
  INVITATION_SCHEMA,
  REGISTRY_ADDRESS,
} from "../src/constants.mjs";
import {
  decryptInvitation,
  encryptInvitation,
} from "../src/invitation.mjs";
import { main as createInvitations } from "../scripts/create-invitations.mjs";

const REPOSITORY_ROOT = resolve(
  dirname(new URL(import.meta.url).pathname),
  "..",
);
const CREATE_SCRIPT = join(
  REPOSITORY_ROOT,
  "scripts",
  "create-invitations.mjs",
);
const CHECK_SCRIPT = join(
  REPOSITORY_ROOT,
  "scripts",
  "check-invitations.mjs",
);
const PILOT_MINIMUM_WEI = parseEther("0.005");
const PILOT_MAXIMUM_WEI = parseEther("0.02");
const TRANSACTION_LOCK_FILENAME = ".handshake-invitations.lock";
const PRIVATE_KEYS = [
  `0x${"0".repeat(63)}1`,
  `0x${"0".repeat(63)}2`,
  `0x${"0".repeat(63)}3`,
  `0x${"0".repeat(63)}4`,
  `0x${"0".repeat(63)}5`,
];

async function makeTemporaryDirectory(t) {
  const directory = await mkdtemp(
    join(tmpdir(), "handshake-operator-tools-"),
  );
  t.after(async () => {
    const { rm } = await import("node:fs/promises");
    await rm(directory, { recursive: true, force: true });
  });
  return directory;
}

async function runNode(script, args) {
  const child = spawn(process.execPath, [script, ...args], {
    cwd: REPOSITORY_ROOT,
    env: {
      PATH: process.env.PATH,
      NODE_NO_WARNINGS: "1",
    },
    stdio: ["ignore", "pipe", "pipe"],
  });
  let stdout = "";
  let stderr = "";

  child.stdout.setEncoding("utf8");
  child.stderr.setEncoding("utf8");
  child.stdout.on("data", (chunk) => {
    stdout += chunk;
  });
  child.stderr.on("data", (chunk) => {
    stderr += chunk;
  });

  const status = await new Promise((resolveStatus, reject) => {
    child.once("error", reject);
    child.once("close", resolveStatus);
  });

  return { status, stdout, stderr };
}

function createArguments({
  publicDirectory,
  secretDirectory,
  ids = "codex,claude",
  names = "Billy,Iris",
  force = false,
}) {
  return [
    "--output-public",
    publicDirectory,
    "--output-secret",
    secretDirectory,
    "--ids",
    ids,
    "--names",
    names,
    ...(force ? ["--force"] : []),
  ];
}

async function readJson(path) {
  return JSON.parse(await readFile(path, "utf8"));
}

async function writePublicBundle({
  directory,
  id,
  displayName,
  privateKey,
}) {
  await mkdir(directory, { recursive: true });
  const account = privateKeyToAccount(privateKey);
  const bundle = await encryptInvitation(
    {
      privateKey,
      address: account.address,
      displayName,
    },
    "test-only-invitation-code",
  );
  await writeFile(
    join(directory, `${id}.enc.json`),
    `${JSON.stringify(bundle, null, 2)}\n`,
    "utf8",
  );
  return bundle;
}

async function startRpcFixture(t, {
  chainId = CHAIN_ID,
  bytecode = "0x60006000",
  balances = new Map(),
  nonces = new Map(),
  rawFailure,
} = {}) {
  const requests = [];
  const server = createServer(async (request, response) => {
    let body = "";
    for await (const chunk of request) {
      body += chunk;
    }

    if (rawFailure !== undefined) {
      response.writeHead(500, { "content-type": "text/plain" });
      response.end(rawFailure);
      return;
    }

    const payload = JSON.parse(body);
    const calls = Array.isArray(payload) ? payload : [payload];
    const replies = calls.map((call) => {
      requests.push(call);
      let result;

      switch (call.method) {
        case "eth_chainId":
          result = `0x${chainId.toString(16)}`;
          break;
        case "eth_getCode":
          result = bytecode;
          break;
        case "eth_getBalance": {
          const address = call.params[0].toLowerCase();
          result = `0x${(balances.get(address) ?? 0n).toString(16)}`;
          break;
        }
        case "eth_getTransactionCount": {
          const address = call.params[0].toLowerCase();
          result = `0x${(nonces.get(address) ?? 0).toString(16)}`;
          break;
        }
        default:
          throw new Error(`Unexpected JSON-RPC method: ${call.method}`);
      }

      return {
        jsonrpc: "2.0",
        id: call.id,
        result,
      };
    });

    response.writeHead(200, { "content-type": "application/json" });
    response.end(JSON.stringify(Array.isArray(payload) ? replies : replies[0]));
  });
  await new Promise((resolveListen) => {
    server.listen(0, "127.0.0.1", resolveListen);
  });
  t.after(async () => {
    await new Promise((resolveClose, reject) => {
      server.close((error) => {
        if (error) {
          reject(error);
        } else {
          resolveClose();
        }
      });
    });
  });
  const address = server.address();

  return {
    requests,
    url: `http://127.0.0.1:${address.port}`,
  };
}

test("creates distinct encrypted invitations without printing their secrets", async (t) => {
  const directory = await makeTemporaryDirectory(t);
  const publicDirectory = join(directory, "public");
  const secretDirectory = join(directory, "secret");
  const result = await runNode(
    CREATE_SCRIPT,
    createArguments({ publicDirectory, secretDirectory }),
  );

  assert.equal(result.status, 0, result.stderr);
  assert.equal(result.stderr, "");
  const report = JSON.parse(result.stdout);
  assert.deepEqual(
    report.created.map(({ id }) => id),
    ["codex", "claude"],
  );

  const publicBundles = await Promise.all(
    ["codex", "claude"].map((id) =>
      readJson(join(publicDirectory, `${id}.enc.json`)),
    ),
  );
  const secrets = await Promise.all(
    ["codex", "claude"].map((id) =>
      readJson(join(secretDirectory, `${id}.secret.json`)),
    ),
  );

  assert.equal(new Set(publicBundles.map(({ address }) => address)).size, 2);
  assert.equal(new Set(secrets.map(({ code }) => code)).size, 2);
  assert.ok(secrets.every(({ code }) => /^[0-9a-f]{64}$/.test(code)));

  for (let index = 0; index < publicBundles.length; index += 1) {
    const bundle = publicBundles[index];
    const secret = secrets[index];
    const id = ["codex", "claude"][index];
    const serializedPublic = JSON.stringify(bundle);
    const publicMetadata = await stat(
      join(publicDirectory, `${id}.enc.json`),
    );
    const secretMetadata = await stat(
      join(secretDirectory, `${id}.secret.json`),
    );
    const decrypted = await decryptInvitation(secret.bundle, secret.code);

    assert.deepEqual(secret.bundle, bundle);
    assert.equal(decrypted.address, bundle.address);
    assert.equal(decrypted.displayName, ["Billy", "Iris"][index]);
    assert.equal(publicMetadata.mode & 0o777, 0o644);
    assert.equal(secretMetadata.mode & 0o777, 0o600);
    assert.doesNotMatch(serializedPublic, /privateKey|"code"/i);
    assert.equal(report.created[index].address, bundle.address);
    assert.doesNotMatch(result.stdout, new RegExp(secret.code, "u"));
    assert.doesNotMatch(result.stdout, new RegExp(decrypted.privateKey, "u"));
  }
});

test("rejects invalid ID and name lists before creating output paths", async (t) => {
  const directory = await makeTemporaryDirectory(t);
  const cases = [
    { ids: "../escape", names: "Billy" },
    { ids: "Codex", names: "Billy" },
    { ids: "bad-", names: "Billy" },
    { ids: "bad--id", names: "Billy" },
    { ids: "codex,codex", names: "Billy,Iris" },
    { ids: "codex,claude", names: "Billy" },
    { ids: "codex", names: "Billy\u001b[31m" },
  ];

  for (let index = 0; index < cases.length; index += 1) {
    const publicDirectory = join(directory, `public-${index}`);
    const secretDirectory = join(directory, `secret-${index}`);
    const result = await runNode(
      CREATE_SCRIPT,
      createArguments({
        publicDirectory,
        secretDirectory,
        ...cases[index],
      }),
    );

    assert.equal(result.status, 1);
    assert.match(result.stderr, /^Invitation creation failed safely\.\n$/);
    await assert.rejects(lstat(publicDirectory), { code: "ENOENT" });
    await assert.rejects(lstat(secretDirectory), { code: "ENOENT" });
  }
});

test("rejects equal, nested, and canonical-aliased public and secret directories", async (t) => {
  const directory = await makeTemporaryDirectory(t);
  const directDirectory = join(directory, "direct");
  const publicParent = join(directory, "public-parent");
  const secretParent = join(directory, "secret-parent");
  const canonicalDirectory = join(directory, "canonical");
  const aliasRoot = join(directory, "alias-root");
  await mkdir(canonicalDirectory);
  await symlink(directory, aliasRoot, "dir");

  const cases = [
    {
      publicDirectory: directDirectory,
      secretDirectory: directDirectory,
    },
    {
      publicDirectory: publicParent,
      secretDirectory: join(publicParent, "secret"),
    },
    {
      publicDirectory: join(secretParent, "public"),
      secretDirectory: secretParent,
    },
    {
      publicDirectory: canonicalDirectory,
      secretDirectory: join(aliasRoot, "canonical"),
    },
  ];

  for (const { publicDirectory, secretDirectory } of cases) {
    const result = await runNode(
      CREATE_SCRIPT,
      createArguments({
        publicDirectory,
        secretDirectory,
        ids: "codex",
        names: "Billy",
      }),
    );

    assert.equal(result.status, 1);
    assert.equal(result.stdout, "");
    assert.match(
      result.stderr,
      /^Invitation creation failed safely\.\n$/,
    );
    await assert.rejects(
      lstat(join(publicDirectory, "codex.enc.json")),
      { code: "ENOENT" },
    );
    await assert.rejects(
      lstat(join(secretDirectory, "codex.secret.json")),
      { code: "ENOENT" },
    );
  }
});

test("fails closed on stale transaction artifacts in either output directory", async (t) => {
  const directory = await makeTemporaryDirectory(t);
  const cases = [
    { location: "public", name: ".orphan.tmp" },
    { location: "secret", name: ".orphan.bak" },
    {
      location: "public",
      name: TRANSACTION_LOCK_FILENAME,
    },
  ];

  for (let index = 0; index < cases.length; index += 1) {
    const publicDirectory = join(directory, `public-${index}`);
    const secretDirectory = join(directory, `secret-${index}`);
    await mkdir(publicDirectory);
    await mkdir(secretDirectory);
    const artifactDirectory =
      cases[index].location === "public"
        ? publicDirectory
        : secretDirectory;
    await writeFile(
      join(artifactDirectory, cases[index].name),
      "stale\n",
      "utf8",
    );

    const result = await runNode(
      CREATE_SCRIPT,
      createArguments({
        publicDirectory,
        secretDirectory,
        ids: "codex",
        names: "Billy",
      }),
    );

    assert.equal(result.status, 1);
    assert.equal(result.stdout, "");
    assert.match(
      result.stderr,
      /^Invitation creation failed safely\.\n$/,
    );
    assert.equal(
      await readFile(
        join(artifactDirectory, cases[index].name),
        "utf8",
      ),
      "stale\n",
    );
    await assert.rejects(
      lstat(join(publicDirectory, "codex.enc.json")),
      { code: "ENOENT" },
    );
    await assert.rejects(
      lstat(join(secretDirectory, "codex.secret.json")),
      { code: "ENOENT" },
    );
  }
});

test("refuses overwrites unless force is explicit and preserves mode 0600", async (t) => {
  const directory = await makeTemporaryDirectory(t);
  const publicDirectory = join(directory, "public");
  const secretDirectory = join(directory, "secret");
  const args = createArguments({
    publicDirectory,
    secretDirectory,
    ids: "codex",
    names: "Billy",
  });
  const first = await runNode(CREATE_SCRIPT, args);
  assert.equal(first.status, 0, first.stderr);
  const originalBundle = await readFile(
    join(publicDirectory, "codex.enc.json"),
    "utf8",
  );
  const originalSecret = await readFile(
    join(secretDirectory, "codex.secret.json"),
    "utf8",
  );

  const refused = await runNode(CREATE_SCRIPT, args);
  assert.equal(refused.status, 1);
  assert.match(refused.stderr, /^Invitation creation failed safely\.\n$/);
  assert.equal(
    await readFile(join(publicDirectory, "codex.enc.json"), "utf8"),
    originalBundle,
  );
  assert.equal(
    await readFile(join(secretDirectory, "codex.secret.json"), "utf8"),
    originalSecret,
  );

  const replaced = await runNode(CREATE_SCRIPT, [...args, "--force"]);
  assert.equal(replaced.status, 0, replaced.stderr);
  assert.notEqual(
    await readFile(join(publicDirectory, "codex.enc.json"), "utf8"),
    originalBundle,
  );
  assert.notEqual(
    await readFile(join(secretDirectory, "codex.secret.json"), "utf8"),
    originalSecret,
  );
  assert.equal(
    (await stat(join(secretDirectory, "codex.secret.json"))).mode & 0o777,
    0o600,
  );
});

test("rolls back a fresh invitation pair when its second publication fails", async (t) => {
  const directory = await makeTemporaryDirectory(t);
  const publicDirectory = join(directory, "public");
  const secretDirectory = join(directory, "secret");
  let publicationCount = 0;
  const publicationTargets = [];

  await assert.rejects(
    createInvitations(
      createArguments({
        publicDirectory,
        secretDirectory,
        ids: "codex",
        names: "Billy",
      }),
      {
        fileSystem: {
          async link(source, target) {
            publicationCount += 1;
            publicationTargets.push(target);
            if (publicationCount === 2) {
              throw new Error("injected publication failure");
            }
            return link(source, target);
          },
        },
      },
    ),
    {
      name: "InvitationCreationError",
      message: "Invitation creation failed safely.",
    },
  );

  assert.equal(publicationCount, 2);
  const canonicalSecretDirectory = await realpath(secretDirectory);
  const canonicalPublicDirectory = await realpath(publicDirectory);
  assert.deepEqual(publicationTargets, [
    join(canonicalSecretDirectory, "codex.secret.json"),
    join(canonicalPublicDirectory, "codex.enc.json"),
  ]);
  assert.deepEqual(await readdir(publicDirectory), []);
  assert.deepEqual(await readdir(secretDirectory), []);
});

test("restores every old invitation pair when a forced batch publication fails", async (t) => {
  const directory = await makeTemporaryDirectory(t);
  const publicDirectory = join(directory, "public");
  const secretDirectory = join(directory, "secret");
  const arguments_ = createArguments({
    publicDirectory,
    secretDirectory,
  });

  await createInvitations(arguments_);
  const expectedFiles = {
    public: ["claude.enc.json", "codex.enc.json"],
    secret: ["claude.secret.json", "codex.secret.json"],
  };
  const originals = new Map();
  for (const [kind, filenames] of Object.entries(expectedFiles)) {
    const outputDirectory =
      kind === "public" ? publicDirectory : secretDirectory;
    for (const filename of filenames) {
      originals.set(
        join(outputDirectory, filename),
        {
          contents: await readFile(
            join(outputDirectory, filename),
            "utf8",
          ),
          mode:
            (await stat(join(outputDirectory, filename))).mode &
            0o777,
        },
      );
    }
  }

  let renameCount = 0;
  let failureInjected = false;
  await assert.rejects(
    createInvitations([...arguments_, "--force"], {
      fileSystem: {
        async rename(...arguments_) {
          renameCount += 1;
          if (!failureInjected && renameCount === 3) {
            failureInjected = true;
            throw new Error("injected forced-publication failure");
          }
          return rename(...arguments_);
        },
      },
    }),
    {
      name: "InvitationCreationError",
      message: "Invitation creation failed safely.",
    },
  );

  assert.equal(failureInjected, true);
  assert.ok(renameCount > 3);
  assert.deepEqual(
    (await readdir(publicDirectory)).sort(),
    expectedFiles.public,
  );
  assert.deepEqual(
    (await readdir(secretDirectory)).sort(),
    expectedFiles.secret,
  );
  for (const [path, original] of originals) {
    assert.equal(await readFile(path, "utf8"), original.contents);
    assert.equal((await stat(path)).mode & 0o777, original.mode);
  }
});

test("serializes concurrent forced batches and leaves one exactly matching pair", { timeout: 10_000 }, async (t) => {
  const directory = await makeTemporaryDirectory(t);
  const publicDirectory = join(directory, "public");
  const secretDirectory = join(directory, "secret");
  const arguments_ = createArguments({
    publicDirectory,
    secretDirectory,
    ids: "codex",
    names: "Billy",
  });
  await createInvitations(arguments_);

  let releaseStaging;
  const stagingRelease = new Promise((resolveRelease) => {
    releaseStaging = resolveRelease;
  });
  let reportStaging;
  const stagingReached = new Promise((resolveReached) => {
    reportStaging = resolveReached;
  });
  let paused = false;
  const first = createInvitations([...arguments_, "--force"], {
    fileSystem: {
      async open(path, ...rest) {
        const handle = await openFile(path, ...rest);
        if (!paused && path.endsWith(".tmp")) {
          paused = true;
          reportStaging();
          await stagingRelease;
        }
        return handle;
      },
    },
  });

  await Promise.race([
    stagingReached,
    first.then(
      () => {
        throw new Error("first invocation never paused");
      },
      (error) => {
        throw error;
      },
    ),
  ]);
  assert.equal(
    (
      await stat(
        join(publicDirectory, TRANSACTION_LOCK_FILENAME),
      )
    ).mode & 0o777,
    0o600,
  );
  assert.equal(
    (
      await stat(
        join(secretDirectory, TRANSACTION_LOCK_FILENAME),
      )
    ).mode & 0o777,
    0o600,
  );
  const [secondOutcome] = await Promise.allSettled([
    createInvitations([...arguments_, "--force"]),
  ]);
  releaseStaging();
  const [firstOutcome] = await Promise.allSettled([first]);

  assert.equal(firstOutcome.status, "fulfilled");
  assert.equal(secondOutcome.status, "rejected");
  assert.equal(secondOutcome.reason?.name, "InvitationCreationError");
  assert.equal(
    secondOutcome.reason?.message,
    "Invitation creation failed safely.",
  );

  const publicBundle = await readJson(
    join(publicDirectory, "codex.enc.json"),
  );
  const secret = await readJson(
    join(secretDirectory, "codex.secret.json"),
  );
  assert.deepEqual(secret.bundle, publicBundle);
  assert.equal(
    firstOutcome.value.created[0].address,
    publicBundle.address,
  );
  assert.deepEqual(
    (await readdir(publicDirectory)).sort(),
    ["codex.enc.json"],
  );
  assert.deepEqual(
    (await readdir(secretDirectory)).sort(),
    ["codex.secret.json"],
  );
});

test("never follows special output paths, including with force", async (t) => {
  const directory = await makeTemporaryDirectory(t);
  const publicDirectory = join(directory, "public");
  const secretDirectory = join(directory, "secret");
  await mkdir(publicDirectory);
  await mkdir(secretDirectory);
  const victim = join(directory, "victim.json");
  await writeFile(victim, "do-not-change\n", "utf8");
  await symlink(victim, join(publicDirectory, "codex.enc.json"));

  const symlinkResult = await runNode(
    CREATE_SCRIPT,
    createArguments({
      publicDirectory,
      secretDirectory,
      ids: "codex",
      names: "Billy",
      force: true,
    }),
  );
  assert.equal(symlinkResult.status, 1);
  assert.match(
    symlinkResult.stderr,
    /^Invitation creation failed safely\.\n$/,
  );
  assert.equal(await readFile(victim, "utf8"), "do-not-change\n");
  assert.equal((await lstat(join(publicDirectory, "codex.enc.json"))).isSymbolicLink(), true);

  await mkdir(join(secretDirectory, "claude.secret.json"));
  const nonregularResult = await runNode(
    CREATE_SCRIPT,
    createArguments({
      publicDirectory,
      secretDirectory,
      ids: "claude",
      names: "Iris",
      force: true,
    }),
  );
  assert.equal(nonregularResult.status, 1);
  assert.match(
    nonregularResult.stderr,
    /^Invitation creation failed safely\.\n$/,
  );
  assert.equal(
    (await lstat(join(secretDirectory, "claude.secret.json"))).isDirectory(),
    true,
  );
});

test("rejects symlink output directories before writing invitations", async (t) => {
  const directory = await makeTemporaryDirectory(t);
  const targetDirectory = join(directory, "target");
  const publicDirectory = join(directory, "public-link");
  const secretDirectory = join(directory, "secret");
  await mkdir(targetDirectory);
  await symlink(targetDirectory, publicDirectory);

  const result = await runNode(
    CREATE_SCRIPT,
    createArguments({
      publicDirectory,
      secretDirectory,
      ids: "codex",
      names: "Billy",
    }),
  );

  assert.equal(result.status, 1);
  assert.match(result.stderr, /^Invitation creation failed safely\.\n$/);
  assert.deepEqual(await import("node:fs/promises").then(({ readdir }) => readdir(targetDirectory)), []);
  await assert.rejects(lstat(secretDirectory), { code: "ENOENT" });
});

test("reports readiness only for unused wallets inside the bounded pilot range", async (t) => {
  const directory = await makeTemporaryDirectory(t);
  const bundles = await Promise.all([
    writePublicBundle({
      directory,
      id: "minimum",
      displayName: "Minimum",
      privateKey: PRIVATE_KEYS[0],
    }),
    writePublicBundle({
      directory,
      id: "used",
      displayName: "Used",
      privateKey: PRIVATE_KEYS[1],
    }),
    writePublicBundle({
      directory,
      id: "low",
      displayName: "Low",
      privateKey: PRIVATE_KEYS[2],
    }),
    writePublicBundle({
      directory,
      id: "high",
      displayName: "High",
      privateKey: PRIVATE_KEYS[3],
    }),
  ]);
  const balances = new Map([
    [bundles[0].address.toLowerCase(), PILOT_MINIMUM_WEI],
    [bundles[1].address.toLowerCase(), parseEther("0.008")],
    [bundles[2].address.toLowerCase(), PILOT_MINIMUM_WEI - 1n],
    [bundles[3].address.toLowerCase(), PILOT_MAXIMUM_WEI + 1n],
  ]);
  const nonces = new Map([
    [bundles[0].address.toLowerCase(), 0],
    [bundles[1].address.toLowerCase(), 1],
    [bundles[2].address.toLowerCase(), 0],
    [bundles[3].address.toLowerCase(), 0],
  ]);
  const fixture = await startRpcFixture(t, { balances, nonces });

  const result = await runNode(CHECK_SCRIPT, [
    "--input-public",
    directory,
    "--rpc-url",
    fixture.url,
  ]);

  assert.equal(result.status, 1, result.stderr);
  assert.equal(result.stderr, "");
  const report = JSON.parse(result.stdout);
  assert.equal(report.chainId, CHAIN_ID);
  assert.equal(report.registryAddress, REGISTRY_ADDRESS);
  assert.equal(report.registryBytecodePresent, true);
  assert.deepEqual(report.pilotBalanceWei, {
    minimum: PILOT_MINIMUM_WEI.toString(),
    maximum: PILOT_MAXIMUM_WEI.toString(),
  });
  assert.ok(
    report.invitations.every(
      (invitation) =>
        Object.hasOwn(invitation, "id") &&
        Object.hasOwn(invitation, "address") &&
        Object.hasOwn(invitation, "balanceWei") &&
        Object.hasOwn(invitation, "balanceEth") &&
        Object.hasOwn(invitation, "nonce") &&
        Object.hasOwn(invitation, "ready") &&
        Object.hasOwn(invitation, "reasons") &&
        !Object.hasOwn(invitation, "displayName"),
    ),
  );
  assert.deepEqual(
    Object.fromEntries(
      report.invitations.map(({ id, ready, reasons }) => [
        id,
        { ready, reasons },
      ]),
    ),
    {
      high: { ready: false, reasons: ["above-pilot-maximum"] },
      low: { ready: false, reasons: ["below-pilot-minimum"] },
      minimum: { ready: true, reasons: [] },
      used: { ready: false, reasons: ["wallet-used"] },
    },
  );
  assert.equal(report.ready, false);

  const codeRequest = fixture.requests.find(
    ({ method }) => method === "eth_getCode",
  );
  assert.equal(codeRequest.params[0].toLowerCase(), REGISTRY_ADDRESS.toLowerCase());
  assert.equal(
    fixture.requests.filter(({ method }) => method === "eth_getBalance").length,
    4,
  );
  assert.equal(
    fixture.requests.filter(
      ({ method }) => method === "eth_getTransactionCount",
    ).length,
    4,
  );
  assert.ok(
    fixture.requests
      .filter(({ method }) => method === "eth_getTransactionCount")
      .every(({ params }) => params[1] === "pending"),
  );
});

test("returns success when every invitation is unused and pilot-funded", async (t) => {
  const directory = await makeTemporaryDirectory(t);
  const bundle = await writePublicBundle({
    directory,
    id: "codex",
    displayName: "Billy",
    privateKey: PRIVATE_KEYS[0],
  });
  const fixture = await startRpcFixture(t, {
    balances: new Map([
      [bundle.address.toLowerCase(), PILOT_MAXIMUM_WEI],
    ]),
    nonces: new Map([[bundle.address.toLowerCase(), 0]]),
  });

  const result = await runNode(CHECK_SCRIPT, [
    "--input-public",
    directory,
    "--rpc-url",
    fixture.url,
  ]);

  assert.equal(result.status, 0, result.stderr);
  assert.equal(JSON.parse(result.stdout).ready, true);
});

test("fails before wallet reads when Sepolia or registry checks fail", async (t) => {
  const directory = await makeTemporaryDirectory(t);
  await writePublicBundle({
    directory,
    id: "codex",
    displayName: "Billy",
    privateKey: PRIVATE_KEYS[0],
  });

  for (const fixtureOptions of [
    { chainId: 1 },
    { bytecode: "0x" },
  ]) {
    const fixture = await startRpcFixture(t, fixtureOptions);
    const result = await runNode(CHECK_SCRIPT, [
      "--input-public",
      directory,
      "--rpc-url",
      fixture.url,
    ]);

    assert.equal(result.status, 1);
    assert.match(result.stderr, /^Invitation readiness check failed safely\.\n$/);
    assert.equal(result.stdout, "");
    assert.equal(
      fixture.requests.some(
        ({ method }) =>
          method === "eth_getBalance" ||
          method === "eth_getTransactionCount",
      ),
      false,
    );
  }
});

test("does not expose RPC URLs or upstream errors on readiness failure", async (t) => {
  const directory = await makeTemporaryDirectory(t);
  await writePublicBundle({
    directory,
    id: "codex",
    displayName: "Billy",
    privateKey: PRIVATE_KEYS[0],
  });
  const upstreamSecret = "upstream-secret-body";
  const querySecret = "rpc-query-secret";
  const fixture = await startRpcFixture(t, {
    rawFailure: upstreamSecret,
  });
  const rpcUrl = `${fixture.url}/?apiKey=${querySecret}`;

  const result = await runNode(CHECK_SCRIPT, [
    "--input-public",
    directory,
    "--rpc-url",
    rpcUrl,
  ]);

  assert.equal(result.status, 1);
  assert.match(result.stderr, /^Invitation readiness check failed safely\.\n$/);
  assert.equal(result.stdout, "");
  assert.doesNotMatch(result.stderr, new RegExp(upstreamSecret, "u"));
  assert.doesNotMatch(result.stderr, new RegExp(querySecret, "u"));
  assert.doesNotMatch(result.stderr, /127\.0\.0\.1/u);
});

test("rejects adjacent secrets and stale transaction artifacts before network access", async (t) => {
  const directory = await makeTemporaryDirectory(t);
  const fixture = await startRpcFixture(t);
  const artifacts = [
    "codex.secret.json",
    ".orphan.tmp",
    ".orphan.bak",
    TRANSACTION_LOCK_FILENAME,
  ];

  for (let index = 0; index < artifacts.length; index += 1) {
    const publicDirectory = join(directory, `public-${index}`);
    await writePublicBundle({
      directory: publicDirectory,
      id: "codex",
      displayName: "Billy",
      privateKey: PRIVATE_KEYS[0],
    });
    await writeFile(
      join(publicDirectory, artifacts[index]),
      "unsafe-adjacent-artifact\n",
      "utf8",
    );

    const result = await runNode(CHECK_SCRIPT, [
      "--input-public",
      publicDirectory,
      "--rpc-url",
      fixture.url,
    ]);

    assert.equal(result.status, 1);
    assert.equal(result.stdout, "");
    assert.match(
      result.stderr,
      /^Invitation readiness check failed safely\.\n$/,
    );
  }

  assert.equal(fixture.requests.length, 0);
});

test("rejects symlink and secret-bearing public bundles before network access", async (t) => {
  const directory = await makeTemporaryDirectory(t);
  const actualBundle = join(directory, "actual.json");
  await writeFile(
    actualBundle,
    JSON.stringify({
      schema: INVITATION_SCHEMA,
      privateKey: PRIVATE_KEYS[0],
    }),
    "utf8",
  );
  await symlink(actualBundle, join(directory, "codex.enc.json"));
  const fixture = await startRpcFixture(t);

  const result = await runNode(CHECK_SCRIPT, [
    "--input-public",
    directory,
    "--rpc-url",
    fixture.url,
  ]);

  assert.equal(result.status, 1);
  assert.match(result.stderr, /^Invitation readiness check failed safely\.\n$/);
  assert.equal(result.stdout, "");
  assert.equal(fixture.requests.length, 0);
});
