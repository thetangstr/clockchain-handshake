import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import {
  createHash,
  randomBytes,
} from "node:crypto";
import * as fileSystem from "node:fs/promises";
import {
  chmod,
  lstat,
  mkdir,
  mkdtemp,
  rename,
  readFile,
  rm,
  stat,
  symlink,
  unlink,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { promisify } from "node:util";
import test from "node:test";

import { privateKeyToAccount } from "viem/accounts";

import { canonicalBytes } from "../src/bilateral/canonical.mjs";
import {
  CHAIN_ID,
  REGISTRY_ADDRESS,
} from "../src/constants.mjs";
import { encryptInvitation } from "../src/invitation.mjs";
import {
  PartialRegistrationError,
} from "../src/registration.mjs";
import {
  createRecovery,
  createRegistrationIntent,
  withMetadataTransaction,
} from "../src/registration-internal.mjs";

const REPOSITORY_SHA =
  "0123456789abcdef0123456789abcdef01234567";
const MINT_MODULE = await import(
  "../scripts/mint-bilateral-token.mjs"
).catch(() => null);
const REGISTRATION_MODULE = await import(
  "../scripts/register-bilateral-identity.mjs"
).catch(() => null);
const PROMPT_HASH_MODULE = await import(
  "../scripts/hash-bilateral-prompts.mjs"
).catch(() => null);
const execFileAsync = promisify(execFile);

function requiredExport(module, name) {
  assert.notEqual(module, null, "expected machine-prep module to exist");
  assert.equal(
    typeof module[name],
    "function",
    `expected ${name} export`,
  );
  return module[name];
}

async function privateRoot(t, prefix) {
  const root = await mkdtemp(join(tmpdir(), prefix));
  await chmod(root, 0o700);
  t.after(() => rm(root, { force: true, recursive: true }));
  return root;
}

function cleanRepositoryState(events = []) {
  return async ({ repositoryRoot }) => {
    events.push({ repositoryRoot, type: "repository" });
    return {
      headSha: REPOSITORY_SHA,
      worktreeStatus: "",
    };
  };
}

test("token mint verifies provenance, publishes one private token, and refuses every second mint", async (t) => {
  const runCli = requiredExport(MINT_MODULE, "runCli");
  const root = await privateRoot(
    t,
    "bilateral-token-mint-",
  );
  const outputPath = join(root, "payer.token");
  const token =
    `cc_${randomBytes(24).toString("base64url")}`;
  const lines = [];
  const events = [];
  let mintCalls = 0;
  const dependencies = {
    mintToken: async (options) => {
      mintCalls += 1;
      events.push({ options, type: "mint" });
      return token;
    },
    output: (line) => lines.push(line),
    repositoryStateResolver:
      cleanRepositoryState(events),
    writeError: () => {},
  };
  const arguments_ = [
    "--role",
    "payer",
    "--output",
    outputPath,
    "--repository-sha",
    REPOSITORY_SHA,
  ];

  assert.equal(
    await runCli(arguments_, dependencies),
    0,
  );
  assert.equal(await readFile(outputPath, "utf8"), token);
  assert.equal((await stat(outputPath)).mode & 0o777, 0o600);
  assert.deepEqual(lines, ["TOKEN_READY\n"]);
  assert.equal(lines[0].includes(token), false);
  assert.equal(mintCalls, 1);
  assert.deepEqual(events.map(({ type }) => type), [
    "repository",
    "mint",
  ]);
  assert.deepEqual(events[1].options, {
    subject: `bilateral-payer-${REPOSITORY_SHA}`,
  });

  assert.equal(
    await runCli(arguments_, dependencies),
    1,
  );
  assert.equal(mintCalls, 1);
  assert.equal(await readFile(outputPath, "utf8"), token);
});

test("token mint rejects dirty, wrong-HEAD, unsafe-parent, and argv-secret cases before minting", async (t) => {
  const main = requiredExport(MINT_MODULE, "main");
  const root = await privateRoot(
    t,
    "bilateral-token-provenance-",
  );
  let mintCalls = 0;
  const mintToken = async () => {
    mintCalls += 1;
    return `cc_${randomBytes(24).toString("base64url")}`;
  };

  for (const [name, state] of [
    [
      "wrong HEAD",
      {
        headSha:
          "fedcba9876543210fedcba9876543210fedcba98",
        worktreeStatus: "",
      },
    ],
    [
      "dirty worktree",
      {
        headSha: REPOSITORY_SHA,
        worktreeStatus: " M scripts/example.mjs\n",
      },
    ],
  ]) {
    await t.test(name, async () => {
      await assert.rejects(
        () =>
          main(
            [
              "--role",
              "payee",
              "--output",
              join(root, `${name}.token`),
              "--repository-sha",
              REPOSITORY_SHA,
            ],
            {
              mintToken,
              repositoryStateResolver: async () => state,
            },
          ),
        /token/i,
      );
    });
  }

  const unsafeParent = join(root, "unsafe");
  await mkdir(unsafeParent, { mode: 0o755 });
  await assert.rejects(
    () =>
      main(
        [
          "--role",
          "operator",
          "--output",
          join(unsafeParent, "operator.token"),
          "--repository-sha",
          REPOSITORY_SHA,
        ],
        {
          mintToken,
          repositoryStateResolver:
            cleanRepositoryState(),
        },
      ),
    /token/i,
  );
  await assert.rejects(
    () =>
      main([
        "--role",
        "payer",
        "--output",
        join(root, "payer.token"),
        "--repository-sha",
        REPOSITORY_SHA,
        "--token",
        `cc_${randomBytes(24).toString("base64url")}`,
      ]),
    /token/i,
  );
  assert.equal(mintCalls, 0);
});

test("token mint enforces the shared 4096-byte contract before token publication", async (t) => {
  const main = requiredExport(MINT_MODULE, "main");
  const root = await privateRoot(
    t,
    "bilateral-token-bound-",
  );
  const outputPath = join(root, "payer.token");
  await assert.rejects(
    () =>
      main(
        [
          "--role",
          "payer",
          "--output",
          outputPath,
          "--repository-sha",
          REPOSITORY_SHA,
        ],
        {
          mintToken: async () => "x".repeat(4097),
          repositoryStateResolver:
            cleanRepositoryState(),
        },
      ),
    /token/i,
  );
  await assert.rejects(lstat(outputPath), {
    code: "ENOENT",
  });
});

test("token mint rejects symlink and FIFO outputs before minting", async (t) => {
  const main = requiredExport(MINT_MODULE, "main");
  const root = await privateRoot(
    t,
    "bilateral-token-special-",
  );
  const target = join(root, "target.token");
  const outputPath = join(root, "payer.token");
  await writeFile(target, "existing", { mode: 0o600 });
  await symlink(target, outputPath);
  let mintCalls = 0;
  const dependencies = {
    mintToken: async () => {
      mintCalls += 1;
      return "cc_unreachable";
    },
    repositoryStateResolver: cleanRepositoryState(),
  };
  await assert.rejects(
    () =>
      main(
        [
          "--role",
          "payer",
          "--output",
          outputPath,
          "--repository-sha",
          REPOSITORY_SHA,
        ],
        dependencies,
      ),
    /token/i,
  );

  if (process.platform !== "win32") {
    await unlink(outputPath);
    await execFileAsync("mkfifo", [outputPath]);
    await assert.rejects(
      () =>
        main(
          [
            "--role",
            "payer",
            "--output",
            outputPath,
            "--repository-sha",
            REPOSITORY_SHA,
          ],
          dependencies,
        ),
      /token/i,
    );
  }
  assert.equal(mintCalls, 0);
});

test("token mint pins its private output directory across intent and token publication", async (t) => {
  const main = requiredExport(MINT_MODULE, "main");
  const root = await privateRoot(
    t,
    "bilateral-token-path-swap-",
  );
  const outputDirectory = join(root, "tokens");
  const displacedDirectory = join(root, "tokens-displaced");
  const outputPath = join(outputDirectory, "payer.token");
  await mkdir(outputDirectory, { mode: 0o700 });
  let mintCalls = 0;

  await assert.rejects(
    () =>
      main(
        [
          "--role",
          "payer",
          "--output",
          outputPath,
          "--repository-sha",
          REPOSITORY_SHA,
        ],
        {
          mintToken: async () => {
            mintCalls += 1;
            await rename(
              outputDirectory,
              displacedDirectory,
            );
            await mkdir(outputDirectory, { mode: 0o700 });
            return "cc_path_swap_must_not_publish";
          },
          repositoryStateResolver:
            cleanRepositoryState(),
        },
      ),
    /token/i,
  );
  assert.equal(mintCalls, 1);
  await assert.rejects(lstat(outputPath), {
    code: "ENOENT",
  });
});

test("post-intent ambiguous mint failures are never reminted on a second run", async (t) => {
  const main = requiredExport(MINT_MODULE, "main");
  const root = await privateRoot(
    t,
    "bilateral-token-ambiguous-",
  );
  const outputPath = join(root, "payer.token");
  const arguments_ = [
    "--role",
    "payer",
    "--output",
    outputPath,
    "--repository-sha",
    REPOSITORY_SHA,
  ];
  let mintCalls = 0;
  const dependencies = {
    mintToken: async () => {
      mintCalls += 1;
      throw new Error("ambiguous mint result");
    },
    repositoryStateResolver: cleanRepositoryState(),
  };

  await assert.rejects(
    () => main(arguments_, dependencies),
    /token/i,
  );
  await assert.rejects(
    () => main(arguments_, dependencies),
    /token/i,
  );
  assert.equal(mintCalls, 1);
});

async function invitationFixture(t, prefix) {
  const root = await privateRoot(t, prefix);
  const privateKey =
    `0x${randomBytes(32).toString("hex")}`;
  const address =
    privateKeyToAccount(privateKey).address;
  const displayName = "Billy";
  const code = randomBytes(24).toString("base64url");
  const bundle = await encryptInvitation(
    { address, displayName, privateKey },
    code,
  );
  const invitationPath = join(root, "billy.secret.json");
  await writeFile(
    invitationPath,
    JSON.stringify({ bundle, code }),
    { mode: 0o600 },
  );
  return {
    address,
    code,
    displayName,
    invitationPath,
    privateKey,
    root,
  };
}

function registrationRecords(fixture) {
  const registerTx =
    `0x${randomBytes(32).toString("hex")}`;
  const metadataTx =
    `0x${randomBytes(32).toString("hex")}`;
  const intent = createRegistrationIntent({
    address: fixture.address,
    displayName: fixture.displayName,
    registerCalldata:
      `0x${randomBytes(8).toString("hex")}`,
    registerGas: 150_000n,
    transactionFields: { gasPrice: 2n },
  });
  const recovery = createRecovery({
    address: fixture.address,
    agentId: 8677n,
    displayName: fixture.displayName,
    registerBlock: 4_000n,
    registerTx,
  });
  const finalRecovery = withMetadataTransaction(
    recovery,
    metadataTx,
    1,
  );
  const registration = {
    address: fixture.address,
    agentId: "8677",
    chainId: CHAIN_ID,
    displayName: fixture.displayName,
    identityReference: recovery.identityReference,
    metadataBlock: "4001",
    metadataTx,
    registerBlock: recovery.registerBlock,
    registerTx,
    registryAddress: REGISTRY_ADDRESS,
    registryNamespace: recovery.registryNamespace,
  };
  return {
    finalRecovery,
    intent,
    recovery,
    registration,
  };
}

function registrationArguments(fixture, output) {
  return [
    "--invitation",
    fixture.invitationPath,
    "--output",
    output,
    "--repository-sha",
    REPOSITORY_SHA,
    "--i-understand-this-writes-to-sepolia",
  ];
}

test("registration publishes marker-complete secret-free identity evidence from the existing invitation key", async (t) => {
  const runCli = requiredExport(
    REGISTRATION_MODULE,
    "runCli",
  );
  const fixture = await invitationFixture(
    t,
    "bilateral-registration-",
  );
  const records = registrationRecords(fixture);
  const output = join(fixture.root, "registration");
  const lines = [];
  const events = [];
  const exitCode = await runCli(
    registrationArguments(fixture, output),
    {
      finalizeRegistration: async () => {
        assert.fail("fresh registration must not finalize directly");
      },
      output: (line) => lines.push(line),
      register: async (options) => {
        events.push("register");
        assert.equal(
          options.privateKey,
          fixture.privateKey,
        );
        assert.equal(
          options.expectedAddress,
          fixture.address,
        );
        assert.equal(options.intent, undefined);
        await options.onCheckpoint(records.intent);
        events.push("intent-durable");
        await options.onCheckpoint(records.recovery);
        events.push("recovery-durable");
        await options.onCheckpoint(records.finalRecovery);
        events.push("metadata-intent-durable");
        return records.registration;
      },
      repositoryStateResolver:
        cleanRepositoryState(events),
      writeError: () => {},
    },
  );

  assert.equal(exitCode, 0);
  assert.deepEqual(lines, ["IDENTITY_READY\n"]);
  assert.equal(
    lines.some(
      (line) =>
        line.includes(fixture.privateKey) ||
        line.includes(fixture.code),
    ),
    false,
  );
  assert.deepEqual(
    events.map((entry) =>
      typeof entry === "string" ? entry : entry.type),
    [
      "repository",
      "register",
      "intent-durable",
      "recovery-durable",
      "metadata-intent-durable",
    ],
  );
  assert.equal((await stat(output)).mode & 0o777, 0o700);
  assert.equal(
    (await stat(join(output, "identity.json"))).mode &
      0o777,
    0o600,
  );
  assert.equal(
    (
      await stat(
        join(output, ".identity.complete.json"),
      )
    ).mode & 0o777,
    0o600,
  );
  const artifactBytes = await readFile(
    join(output, "identity.json"),
  );
  const artifact = JSON.parse(artifactBytes);
  assert.deepEqual(artifact, {
    address: fixture.address.toLowerCase(),
    agentId: "8677",
    chainId: String(CHAIN_ID),
    displayName: fixture.displayName,
    identityReference: records.recovery.identityReference,
    metadata: {
      blockHeight: "4001",
      transactionHash:
        records.registration.metadataTx,
    },
    paymentMoved: false,
    register: {
      blockHeight: "4000",
      transactionHash:
        records.registration.registerTx,
    },
    registryAddress: REGISTRY_ADDRESS.toLowerCase(),
    repositorySha: REPOSITORY_SHA,
    schema:
      "clockchain.bilateral-identity-registration/v1",
  });
  const completion = JSON.parse(
    await readFile(
      join(output, ".identity.complete.json"),
      "utf8",
    ),
  );
  assert.equal(
    completion.fileSha256,
    createHash("sha256")
      .update(artifactBytes)
      .digest("hex"),
  );
  assert.equal(
    artifactBytes.includes(Buffer.from(fixture.privateKey)),
    false,
  );
  assert.equal(
    artifactBytes.includes(Buffer.from(fixture.code)),
    false,
  );
});

test("registration resumes a durable pre-broadcast intent without a blind fresh attempt", async (t) => {
  const main = requiredExport(
    REGISTRATION_MODULE,
    "main",
  );
  const fixture = await invitationFixture(
    t,
    "bilateral-registration-intent-",
  );
  const records = registrationRecords(fixture);
  const output = join(fixture.root, "registration");
  const arguments_ = registrationArguments(
    fixture,
    output,
  );
  let attempts = 0;

  await assert.rejects(
    () =>
      main(arguments_, {
        register: async ({ onCheckpoint }) => {
          attempts += 1;
          await onCheckpoint(records.intent);
          throw new Error("ambiguous post-intent failure");
        },
        repositoryStateResolver:
          cleanRepositoryState(),
      }),
    /registration/i,
  );
  assert.equal(attempts, 1);
  assert.equal(
    JSON.parse(
      await readFile(
        join(output, "registration-checkpoint.json"),
        "utf8",
      ),
    ).schema,
    "clockchain.handshake-registration-intent/v1",
  );

  const result = await main(arguments_, {
    register: async ({ intent, onCheckpoint }) => {
      attempts += 1;
      assert.deepEqual(intent, records.intent);
      await onCheckpoint(records.recovery);
      return records.registration;
    },
    repositoryStateResolver:
      cleanRepositoryState(),
  });
  assert.equal(result.agentId, "8677");
  assert.equal(attempts, 2);
});

test("registration recovery invokes finalization and never repeats registration", async (t) => {
  const main = requiredExport(
    REGISTRATION_MODULE,
    "main",
  );
  const fixture = await invitationFixture(
    t,
    "bilateral-registration-recovery-",
  );
  const records = registrationRecords(fixture);
  const output = join(fixture.root, "registration");
  const arguments_ = registrationArguments(
    fixture,
    output,
  );

  await assert.rejects(
    () =>
      main(arguments_, {
        register: async ({ onCheckpoint }) => {
          await onCheckpoint(records.intent);
          await onCheckpoint(records.recovery);
          throw new Error("crash after registration");
        },
        repositoryStateResolver:
          cleanRepositoryState(),
      }),
    /registration/i,
  );
  let registerCalls = 0;
  let finalizeCalls = 0;
  const result = await main(arguments_, {
    finalizeRegistration: async ({
      recovery,
      privateKey,
    }) => {
      finalizeCalls += 1;
      assert.deepEqual(recovery, records.recovery);
      assert.equal(privateKey, fixture.privateKey);
      return records.registration;
    },
    register: async () => {
      registerCalls += 1;
      assert.fail("recovery must not repeat registration");
    },
    repositoryStateResolver:
      cleanRepositoryState(),
  });
  assert.equal(result.agentId, "8677");
  assert.equal(registerCalls, 0);
  assert.equal(finalizeCalls, 1);
});

test("registration rejects provenance and permissive invitation modes before registration calls", async (t) => {
  const main = requiredExport(
    REGISTRATION_MODULE,
    "main",
  );
  const fixture = await invitationFixture(
    t,
    "bilateral-registration-reject-",
  );
  const output = join(fixture.root, "registration");
  let networkCalls = 0;
  const register = async () => {
    networkCalls += 1;
  };

  for (const state of [
    {
      headSha:
        "fedcba9876543210fedcba9876543210fedcba98",
      worktreeStatus: "",
    },
    {
      headSha: REPOSITORY_SHA,
      worktreeStatus: "?? unexpected\n",
    },
  ]) {
    await assert.rejects(
      () =>
        main(
          registrationArguments(fixture, output),
          {
            register,
            repositoryStateResolver: async () => state,
          },
        ),
      /registration/i,
    );
  }
  await chmod(fixture.invitationPath, 0o644);
  await assert.rejects(
    () =>
      main(
        registrationArguments(fixture, output),
        {
          register,
          repositoryStateResolver:
            cleanRepositoryState(),
        },
      ),
    /registration/i,
  );
  assert.equal(networkCalls, 0);
});

test("registration treats only an initial nofollow-open ENOENT as checkpoint absence", async () => {
  const readCheckpoint = requiredExport(
    REGISTRATION_MODULE,
    "readCheckpoint",
  );
  const invitation = {
    address:
      "0x00112233445566778899aabbccddeeff00112233",
    displayName: "Billy",
  };
  const missing = await readCheckpoint(
    "/private/output",
    invitation,
    {
      async open() {
        const error = new Error("missing");
        error.code = "ENOENT";
        throw error;
      },
    },
  );
  assert.equal(missing, null);

  let closeCalls = 0;
  await assert.rejects(
    () =>
      readCheckpoint(
        "/private/output",
        invitation,
        {
          async open() {
            return {
              async close() {
                closeCalls += 1;
              },
              async stat() {
                const error = new Error(
                  "unlinked after open",
                );
                error.code = "ENOENT";
                throw error;
              },
            };
          },
        },
      ),
    /registration/i,
  );
  assert.equal(closeCalls, 1);
});

test("registration bounded reads use maximum-plus-one reads and reject growth or metadata changes", async () => {
  const readBoundedFile = requiredExport(
    REGISTRATION_MODULE,
    "readBoundedFile",
  );
  const maximum = 16;
  const metadata = (overrides = {}) => ({
    dev: 1,
    ino: 2,
    isFile: () => true,
    mode: 0o100600,
    mtimeMs: 3,
    size: maximum,
    ...overrides,
  });
  let readCalls = 0;
  let closeCalls = 0;
  await assert.rejects(
    () =>
      readBoundedFile(
        "/private/invitation.json",
        {
          maximum,
          privateFile: true,
        },
        {
          async open() {
            return {
              async close() {
                closeCalls += 1;
              },
              async read(buffer, offset, length) {
                readCalls += 1;
                assert.equal(length, maximum + 1);
                Buffer.from("x".repeat(maximum + 1)).copy(
                  buffer,
                  offset,
                );
                return { bytesRead: maximum + 1 };
              },
              async readFile() {
                assert.fail(
                  "bounded reader must not call readFile",
                );
              },
              async stat() {
                return metadata();
              },
            };
          },
        },
      ),
    /registration/i,
  );
  assert.equal(readCalls, 1);
  assert.equal(closeCalls, 1);

  let statCalls = 0;
  let metadataReadCalls = 0;
  await assert.rejects(
    () =>
      readBoundedFile(
        "/private/invitation.json",
        {
          maximum,
          privateFile: true,
        },
        {
          async open() {
            return {
              async close() {},
              async read(buffer, offset) {
                metadataReadCalls += 1;
                if (metadataReadCalls > 1) {
                  return { bytesRead: 0 };
                }
                Buffer.from("x".repeat(maximum)).copy(
                  buffer,
                  offset,
                );
                return { bytesRead: maximum };
              },
              async stat() {
                statCalls += 1;
                return metadata({
                  ino: statCalls === 1 ? 2 : 9,
                });
              },
            };
          },
        },
      ),
    /registration/i,
  );
});

test("registration rejects invitation symlinks and FIFOs before network calls", async (t) => {
  const main = requiredExport(
    REGISTRATION_MODULE,
    "main",
  );
  const fixture = await invitationFixture(
    t,
    "bilateral-registration-special-",
  );
  const originalInvitation = await readFile(
    fixture.invitationPath,
  );
  const target = join(fixture.root, "target.secret.json");
  await writeFile(target, originalInvitation, {
    mode: 0o600,
  });
  await unlink(fixture.invitationPath);
  await symlink(target, fixture.invitationPath);
  let networkCalls = 0;
  const dependencies = {
    register: async () => {
      networkCalls += 1;
    },
    repositoryStateResolver: cleanRepositoryState(),
  };
  await assert.rejects(
    () =>
      main(
        registrationArguments(
          fixture,
          join(fixture.root, "symlink-output"),
        ),
        dependencies,
      ),
    /registration/i,
  );

  if (process.platform !== "win32") {
    await unlink(fixture.invitationPath);
    await execFileAsync("mkfifo", [
      fixture.invitationPath,
    ]);
    await chmod(fixture.invitationPath, 0o600);
    await assert.rejects(
      () =>
        main(
          registrationArguments(
            fixture,
            join(fixture.root, "fifo-output"),
          ),
          dependencies,
        ),
      /registration/i,
    );
  }
  assert.equal(networkCalls, 0);
});

test("registration enforces private checkpoint mode before recovery calls", async (t) => {
  const main = requiredExport(
    REGISTRATION_MODULE,
    "main",
  );
  const fixture = await invitationFixture(
    t,
    "bilateral-registration-checkpoint-mode-",
  );
  const records = registrationRecords(fixture);
  const output = join(fixture.root, "registration");
  await mkdir(output, { mode: 0o700 });
  await writeFile(
    join(output, "registration-checkpoint.json"),
    JSON.stringify(records.finalRecovery),
    { mode: 0o644 },
  );
  let finalizeCalls = 0;
  await assert.rejects(
    () =>
      main(registrationArguments(fixture, output), {
        finalizeRegistration: async () => {
          finalizeCalls += 1;
          return records.registration;
        },
        repositoryStateResolver:
          cleanRepositoryState(),
      }),
    /registration/i,
  );
  assert.equal(finalizeCalls, 0);
});

test("registration persists PartialRegistrationError recovery for safe finalization", async (t) => {
  const main = requiredExport(
    REGISTRATION_MODULE,
    "main",
  );
  const fixture = await invitationFixture(
    t,
    "bilateral-registration-partial-",
  );
  const records = registrationRecords(fixture);
  const output = join(fixture.root, "registration");
  const arguments_ = registrationArguments(fixture, output);
  let registerCalls = 0;
  await assert.rejects(
    () =>
      main(arguments_, {
        register: async ({ onCheckpoint }) => {
          registerCalls += 1;
          await onCheckpoint(records.intent);
          throw new PartialRegistrationError(
            records.finalRecovery,
            new Error("post-broadcast failure"),
          );
        },
        repositoryStateResolver:
          cleanRepositoryState(),
      }),
    /registration/i,
  );
  assert.deepEqual(
    JSON.parse(
      await readFile(
        join(output, "registration-checkpoint.json"),
        "utf8",
      ),
    ),
    records.finalRecovery,
  );

  let finalizeCalls = 0;
  const artifact = await main(arguments_, {
    finalizeRegistration: async ({ recovery }) => {
      finalizeCalls += 1;
      assert.deepEqual(recovery, records.finalRecovery);
      return records.registration;
    },
    register: async () => {
      registerCalls += 1;
      assert.fail("partial recovery must not re-register");
    },
    repositoryStateResolver:
      cleanRepositoryState(),
  });
  assert.equal(artifact.agentId, "8677");
  assert.equal(registerCalls, 1);
  assert.equal(finalizeCalls, 1);
});

test("registration resumes marker publication from matching durable identity bytes without registration rebroadcast", async (t) => {
  const main = requiredExport(
    REGISTRATION_MODULE,
    "main",
  );
  const fixture = await invitationFixture(
    t,
    "bilateral-registration-publication-resume-",
  );
  const records = registrationRecords(fixture);
  const output = join(fixture.root, "registration");
  const markerPath = join(
    output,
    ".identity.complete.json",
  );
  const arguments_ = registrationArguments(fixture, output);
  let registerCalls = 0;
  const crashFileSystem = {
    ...fileSystem,
    async open(path, flags, mode) {
      if (path === markerPath && flags === "wx") {
        throw new Error("publication crash");
      }
      return fileSystem.open(path, flags, mode);
    },
  };

  await assert.rejects(
    () =>
      main(arguments_, {
        fileSystem: crashFileSystem,
        register: async ({ onCheckpoint }) => {
          registerCalls += 1;
          await onCheckpoint(records.intent);
          await onCheckpoint(records.recovery);
          await onCheckpoint(records.finalRecovery);
          return records.registration;
        },
        repositoryStateResolver:
          cleanRepositoryState(),
      }),
    /registration/i,
  );
  const identityBytes = await readFile(
    join(output, "identity.json"),
  );
  const publicationCheckpointBytes = await readFile(
    join(output, "registration-checkpoint.json"),
  );
  const publicationCheckpoint = JSON.parse(
    publicationCheckpointBytes,
  );
  assert.equal(
    publicationCheckpoint.schema,
    "clockchain.bilateral-identity-registration-publication/v1",
  );
  assert.deepEqual(
    publicationCheckpoint.artifact,
    JSON.parse(identityBytes),
  );
  assert.deepEqual(
    publicationCheckpointBytes,
    canonicalBytes(publicationCheckpoint),
  );
  await assert.rejects(lstat(markerPath), {
    code: "ENOENT",
  });

  let finalizeCalls = 0;
  const artifact = await main(arguments_, {
    finalizeRegistration: async () => {
      finalizeCalls += 1;
      assert.fail(
        "marker-only resume must not invoke a network-capable finalizer",
      );
    },
    register: async () => {
      registerCalls += 1;
      assert.fail("publication resume must not register");
    },
    repositoryStateResolver:
      cleanRepositoryState(),
  });
  assert.equal(artifact.agentId, "8677");
  assert.equal(registerCalls, 1);
  assert.equal(finalizeCalls, 0);
  assert.deepEqual(
    await readFile(join(output, "identity.json")),
    identityBytes,
  );
  assert.equal(
    JSON.parse(await readFile(markerPath, "utf8"))
      .fileSha256,
    createHash("sha256")
      .update(identityBytes)
      .digest("hex"),
  );

  await assert.rejects(
    () =>
      main(arguments_, {
        repositoryStateResolver:
          cleanRepositoryState(),
      }),
    /registration/i,
  );
});

test("registration marker-only resume rejects metadata-block tampering without network-capable calls", async (t) => {
  const main = requiredExport(
    REGISTRATION_MODULE,
    "main",
  );
  const fixture = await invitationFixture(
    t,
    "bilateral-registration-publication-metadata-tamper-",
  );
  const records = registrationRecords(fixture);
  const output = join(fixture.root, "registration");
  const identityPath = join(output, "identity.json");
  const markerPath = join(
    output,
    ".identity.complete.json",
  );
  const arguments_ = registrationArguments(fixture, output);
  const crashFileSystem = {
    ...fileSystem,
    async open(path, flags, mode) {
      if (path === markerPath && flags === "wx") {
        throw new Error("publication crash");
      }
      return fileSystem.open(path, flags, mode);
    },
  };

  await assert.rejects(
    () =>
      main(arguments_, {
        fileSystem: crashFileSystem,
        register: async ({ onCheckpoint }) => {
          await onCheckpoint(records.intent);
          await onCheckpoint(records.recovery);
          await onCheckpoint(records.finalRecovery);
          return records.registration;
        },
        repositoryStateResolver:
          cleanRepositoryState(),
      }),
    /registration/i,
  );
  const identity = JSON.parse(
    await readFile(identityPath),
  );
  identity.metadata.blockHeight = "4002";
  await writeFile(identityPath, canonicalBytes(identity), {
    mode: 0o600,
  });

  let registerCalls = 0;
  let finalizeCalls = 0;
  await assert.rejects(
    () =>
      main(arguments_, {
        finalizeRegistration: async () => {
          finalizeCalls += 1;
          assert.fail(
            "tampered publication must fail locally",
          );
        },
        register: async () => {
          registerCalls += 1;
          assert.fail(
            "tampered publication must not register",
          );
        },
        repositoryStateResolver:
          cleanRepositoryState(),
      }),
    /registration/i,
  );
  assert.equal(registerCalls, 0);
  assert.equal(finalizeCalls, 0);
  await assert.rejects(lstat(markerPath), {
    code: "ENOENT",
  });
});

test("registration publication resume rejects hostile identity mismatch", async (t) => {
  const main = requiredExport(
    REGISTRATION_MODULE,
    "main",
  );
  const fixture = await invitationFixture(
    t,
    "bilateral-registration-publication-hostile-",
  );
  const records = registrationRecords(fixture);
  const output = join(fixture.root, "registration");
  await mkdir(output, { mode: 0o700 });
  await writeFile(
    join(output, "registration-checkpoint.json"),
    JSON.stringify(records.finalRecovery),
    { mode: 0o600 },
  );
  await writeFile(
    join(output, "identity.json"),
    canonicalBytes({
      hostile: true,
      schema:
        "clockchain.bilateral-identity-registration/v1",
    }),
    { mode: 0o600 },
  );
  let finalizeCalls = 0;
  await assert.rejects(
    () =>
      main(registrationArguments(fixture, output), {
        finalizeRegistration: async () => {
          finalizeCalls += 1;
          assert.fail(
            "hostile publication bytes must be rejected locally",
          );
        },
        register: async () => {
          assert.fail("resume must never re-register");
        },
        repositoryStateResolver:
          cleanRepositoryState(),
      }),
    /registration/i,
  );
  assert.equal(finalizeCalls, 0);
  await assert.rejects(
    lstat(join(output, ".identity.complete.json")),
    { code: "ENOENT" },
  );
});

test("registration pins its output directory through checkpoints and publication", async (t) => {
  const main = requiredExport(
    REGISTRATION_MODULE,
    "main",
  );
  const fixture = await invitationFixture(
    t,
    "bilateral-registration-path-swap-",
  );
  const records = registrationRecords(fixture);
  const output = join(fixture.root, "registration");
  const displaced = join(
    fixture.root,
    "registration-displaced",
  );
  await assert.rejects(
    () =>
      main(registrationArguments(fixture, output), {
        register: async ({ onCheckpoint }) => {
          await onCheckpoint(records.intent);
          await onCheckpoint(records.finalRecovery);
          await rename(output, displaced);
          await mkdir(output, { mode: 0o700 });
          return records.registration;
        },
        repositoryStateResolver:
          cleanRepositoryState(),
      }),
    /registration/i,
  );
  await assert.rejects(
    lstat(join(output, "identity.json")),
    { code: "ENOENT" },
  );
});

test("prompt hash uses exact git-show bytes and the same canonical role binding construction", async () => {
  const runCli = requiredExport(
    PROMPT_HASH_MODULE,
    "runCli",
  );
  const payer = Buffer.from("Iris prompt\n", "utf8");
  const payee = Buffer.from(
    "Billie prompt without trailing newline",
    "utf8",
  );
  const expected = createHash("sha256")
    .update(
      canonicalBytes({
        payee: createHash("sha256")
          .update(payee)
          .digest("hex"),
        payer: createHash("sha256")
          .update(payer)
          .digest("hex"),
      }),
    )
    .digest("hex");
  const requests = [];
  const lines = [];
  const exitCode = await runCli(
    ["--repository-sha", REPOSITORY_SHA],
    {
      output: (line) => lines.push(line),
      promptResolver: async (request) => {
        requests.push(request);
        return request.repositoryPath.includes("iris")
          ? payer
          : payee;
      },
      writeError: () => {},
    },
  );

  assert.equal(exitCode, 0);
  assert.deepEqual(lines, [`${expected}\n`]);
  assert.deepEqual(
    requests.map(({ repositoryPath }) => repositoryPath),
    [
      "prompts/run-iris-bilateral-demo.md",
      "prompts/run-billie-bilateral-demo.md",
    ],
  );
  assert.ok(
    requests.every(
      ({ repositorySha }) =>
        repositorySha === REPOSITORY_SHA,
    ),
  );
});

test("prompt hash default resolution accepts commits and rejects trees or invalid revisions", async (t) => {
  const computeBilateralPromptHash = requiredExport(
    PROMPT_HASH_MODULE,
    "computeBilateralPromptHash",
  );
  const root = await privateRoot(
    t,
    "bilateral-prompt-git-",
  );
  await execFileAsync("git", ["init", "--quiet"], {
    cwd: root,
  });
  await execFileAsync(
    "git",
    ["config", "user.email", "tests@example.invalid"],
    { cwd: root },
  );
  await execFileAsync(
    "git",
    ["config", "user.name", "Handshake Tests"],
    { cwd: root },
  );
  await mkdir(join(root, "prompts"));
  const payer = Buffer.from("Iris committed prompt\n");
  const payee = Buffer.from("Billie committed prompt\n");
  await writeFile(
    join(root, "prompts/run-iris-bilateral-demo.md"),
    payer,
  );
  await writeFile(
    join(root, "prompts/run-billie-bilateral-demo.md"),
    payee,
  );
  await execFileAsync("git", ["add", "prompts"], {
    cwd: root,
  });
  await execFileAsync(
    "git",
    ["commit", "--quiet", "-m", "fixture"],
    { cwd: root },
  );
  const repositorySha = (
    await execFileAsync("git", ["rev-parse", "HEAD"], {
      cwd: root,
      encoding: "utf8",
    })
  ).stdout.trim();
  const treeSha = (
    await execFileAsync(
      "git",
      ["rev-parse", "HEAD^{tree}"],
      { cwd: root, encoding: "utf8" },
    )
  ).stdout.trim();
  const expected = createHash("sha256")
    .update(
      canonicalBytes({
        payee: createHash("sha256")
          .update(payee)
          .digest("hex"),
        payer: createHash("sha256")
          .update(payer)
          .digest("hex"),
      }),
    )
    .digest("hex");

  assert.equal(
    await computeBilateralPromptHash({
      repositoryRoot: root,
      repositorySha,
    }),
    expected,
  );
  await assert.rejects(
    () =>
      computeBilateralPromptHash({
        repositoryRoot: root,
        repositorySha: treeSha,
      }),
    /prompt/i,
  );
  await assert.rejects(
    () =>
      computeBilateralPromptHash({
        repositoryRoot: root,
        repositorySha: "f".repeat(40),
      }),
    /prompt/i,
  );
});

test("machine-prep source and status output contain no secret or authorizing surface", async () => {
  for (const path of [
    "../scripts/mint-bilateral-token.mjs",
    "../scripts/register-bilateral-identity.mjs",
    "../scripts/hash-bilateral-prompts.mjs",
  ]) {
    const source = await readFile(
      new URL(path, import.meta.url),
      "utf8",
    ).catch(() => "");
    assert.notEqual(source.length, 0);
    assert.equal(
      source.includes(["AUTHOR", "IZED"].join("")),
      false,
    );
    assert.equal(source.includes("BEGIN PRIVATE KEY"), false);
  }
});
