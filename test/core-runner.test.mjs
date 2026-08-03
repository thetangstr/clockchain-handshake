import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import { constants as fsConstants } from "node:fs";
import {
  chmod,
  lstat,
  mkdir,
  mkdtemp,
  open as nodeOpen,
  readFile,
  rename,
  rm,
  stat,
  symlink,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { promisify } from "node:util";

import {
  deadlineMs,
  liveUpperBoundMs,
} from "../src/core/blocktime.mjs";
import { canonicalBytes } from "../src/core/canonical.mjs";
import { dSession } from "../src/core/descriptor.mjs";
import {
  authoritativeTriple,
  buildAcceptance,
  buildProposal,
  transitionDigest,
} from "../src/core/messages.mjs";
import {
  ProtocolFailureError,
  createRunnerStateMachine,
} from "../src/core/protocol.mjs";
import { sessionKey } from "../src/core/refid.mjs";
import {
  McpNetworkError,
  McpProtocolError,
  McpRateLimitedError,
} from "../src/core/clockchain.mjs";
import {
  MAX_POLL_DURATION_MS,
  MIN_POLL_INTERVAL_MS,
  RUNNER_OUTCOME_KEYS,
  WRITE_INTENT_MARKER_KEYS,
  closePinnedOutputDirectory,
  createWriteIntentMarker,
  pinOutputDirectory,
  pollForTransition,
  writeOrAdoptTransition,
} from "../src/core/runner.mjs";
import {
  createFakeBilateralClockchain,
} from "./helpers/fake-bilateral-clockchain.mjs";

const PAYER_ADDRESS =
  "0x00112233445566778899aabbccddeeff00112233";
const PAYEE_ADDRESS =
  "0xffeeddccbbaa99887766554433221100ffeeddcc";
const execFileAsync = promisify(execFile);
function descriptor() {
  return {
    amountOptions: [
      { currency: "USD", value: "100" },
    ],
    chainId: "11155111",
    expirySeconds: "600",
    mandateDigest: "b".repeat(64),
    namespace: "cbv1",
    payee: {
      address: PAYEE_ADDRESS,
      agentId: "8678",
      displayName: "Iris",
      role: "payee",
    },
    payer: {
      address: PAYER_ADDRESS,
      agentId: "8677",
      displayName: "Billy",
      role: "payer",
    },
    paymentMoved: false,
    promptSha256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    protocol: "clockchain.bilateral-authorization/v1",
    protocolVersion: "1",
    registry:
      "0x8004a818bfb912233c491871b3d84c89a494bd9e",
    repositorySha:
      "0123456789abcdef0123456789abcdef01234567",
    requestDigest: "c".repeat(64),
    schema: "clockchain.bilateral-session-descriptor/v2",
    sessionId: "00112233445566778899aabbccddeeff",
    settlement: "not-executed",
  };
}

function proposal() {
  const sessionDescriptor = descriptor();
  return buildProposal({
    amount: { currency: "USD", value: "100" },
    descriptor: sessionDescriptor,
    sessionDigest: dSession(sessionDescriptor),
  });
}

function markerFor(message) {
  return {
    sessionDigest: message.sessionDigest,
    slot: message.kind,
    digest: transitionDigest(message),
    referenceId: sessionKey(
      message.sessionDigest,
      message.kind,
    ),
  };
}

function exactWriteArgs(message) {
  return {
    allow_degraded: true,
    asset_hash: transitionDigest(message),
    asset_reference_id: sessionKey(
      message.sessionDigest,
      message.kind,
    ),
    hash_type: "SHA-256",
    idempotency_key: createHash("sha256")
      .update(
        `${message.sessionDigest}|${message.kind}`,
        "utf8",
      )
      .digest("hex")
      .slice(0, 32),
    version_number: 1,
    wait: true,
    wait_ms: 20000,
  };
}

function configuredFake() {
  const fake = createFakeBilateralClockchain();
  fake.registerAgent({
    agentId: "8677",
    owner: PAYER_ADDRESS,
    status: "active",
  });
  fake.registerAgent({
    agentId: "8678",
    owner: PAYEE_ADDRESS,
    status: "active",
  });
  return fake;
}

function clientFrom(fake, overrides = {}) {
  return {
    getBlock: fake.getBlock,
    logAction: fake.logAction,
    resolveAgent: fake.resolveAgent,
    searchActions: fake.searchActions,
    verifyCrossParty: fake.verifyCrossParty,
    ...overrides,
  };
}

async function temporaryDirectory(t) {
  const directory = await mkdtemp(
    join(tmpdir(), "bilateral-runner-"),
  );
  t.after(() => rm(directory, {
    force: true,
    recursive: true,
  }));
  return directory;
}

test("pins the runner outcome and write-intent marker schemas", () => {
  assert.deepEqual(WRITE_INTENT_MARKER_KEYS, [
    "sessionDigest",
    "slot",
    "digest",
    "referenceId",
  ]);
  assert.deepEqual(RUNNER_OUTCOME_KEYS, [
    "deadlineMs",
    "discoveryOnly",
    "markerCreated",
    "source",
    "state",
    "transition",
  ]);
  assert.ok(Object.isFrozen(WRITE_INTENT_MARKER_KEYS));
  assert.ok(Object.isFrozen(RUNNER_OUTCOME_KEYS));
});

test("creates one exact mode-0600 fsync'd marker with wx", async (t) => {
  const directory = await temporaryDirectory(t);
  const markerPath = join(directory, "proposal.intent.json");
  const marker = markerFor(proposal());

  assert.equal(
    await createWriteIntentMarker({ marker, markerPath }),
    true,
  );
  assert.equal(
    await readFile(markerPath, "utf8"),
    `${canonicalBytes(marker).toString("utf8")}\n`,
  );
  assert.equal((await stat(markerPath)).mode & 0o777, 0o600);
  assert.equal(
    await createWriteIntentMarker({ marker, markerPath }),
    false,
  );

  const events = [];
  const fileHandle = {
    async close() {
      events.push("file-close");
    },
    async sync() {
      events.push("file-sync");
    },
    async writeFile(value) {
      events.push(["write", value]);
    },
  };
  const directoryHandle = {
    async close() {
      events.push("directory-close");
    },
    async sync() {
      events.push("directory-sync");
    },
    stat: () => stat(directory),
  };
  assert.equal(
    await createWriteIntentMarker({
      fileSystem: {
        async open(path, flag, mode) {
          events.push(["open", path, flag, mode]);
          return path === directory
            ? directoryHandle
            : fileHandle;
        },
      },
      marker,
      markerPath: `${markerPath}.injected`,
    }),
    true,
  );
  assert.deepEqual(events, [
    [
      "open",
      directory,
      fsConstants.O_RDONLY |
        (fsConstants.O_DIRECTORY ?? 0) |
        (fsConstants.O_NOFOLLOW ?? 0),
      undefined,
    ],
    ["open", `${markerPath}.injected`, "wx", 0o600],
    [
      "write",
      `${canonicalBytes(marker).toString("utf8")}\n`,
    ],
    "file-sync",
    "file-close",
    "directory-sync",
    "directory-close",
  ]);
});

function adversarialMarkerHandle(
  handle,
  {
    metadataField,
    onRead,
    overflow = false,
  } = {},
) {
  let statCalls = 0;
  return {
    close: () => handle.close(),
    async read(buffer, offset, length, position) {
      onRead?.(length);
      if (overflow) {
        buffer.fill(0x78, offset, offset + length);
        return { buffer, bytesRead: length };
      }
      return handle.read(buffer, offset, length, position);
    },
    readFile() {
      assert.fail("intent readers must not call readFile()");
    },
    async stat() {
      const metadata = await handle.stat();
      statCalls += 1;
      if (statCalls === 1 || metadataField === undefined) {
        return metadata;
      }
      return {
        ...metadata,
        [metadataField]: metadata[metadataField] + 1,
        isFile: () => true,
      };
    },
  };
}

test("existing intent markers are bounded, private, canonical, and race-stable", async (t) => {
  const scenarios = [
    {
      async prepare(markerPath) {
        await writeFile(
          markerPath,
          `${canonicalBytes(markerFor(proposal())).toString("utf8")}\n`,
          { mode: 0o600 },
        );
        await chmod(markerPath, 0o644);
      },
      name: "permissive mode",
    },
    {
      async prepare(markerPath) {
        await execFileAsync("mkfifo", [markerPath]);
      },
      name: "FIFO",
    },
    {
      async prepare(markerPath) {
        await writeFile(
          markerPath,
          `${JSON.stringify(markerFor(proposal()), null, 2)}\n`,
          { mode: 0o600 },
        );
      },
      name: "noncanonical bytes",
    },
    {
      async prepare(markerPath, state) {
        await writeFile(
          markerPath,
          `${canonicalBytes(markerFor(proposal())).toString("utf8")}\n`,
          { mode: 0o600 },
        );
        state.wrap = {
          overflow: true,
          onRead(length) {
            state.readLength = length;
          },
        };
      },
      name: "growth",
    },
    {
      async prepare(markerPath, state) {
        await writeFile(
          markerPath,
          `${canonicalBytes(markerFor(proposal())).toString("utf8")}\n`,
          { mode: 0o600 },
        );
        state.wrap = {
          metadataField: "ctimeMs",
          onRead(length) {
            state.readLength = Math.max(
              state.readLength,
              length,
            );
          },
        };
      },
      name: "metadata race",
    },
  ];

  for (const scenario of scenarios) {
    await t.test(scenario.name, async (t) => {
      const directory = await temporaryDirectory(t);
      const markerPath = join(
        directory,
        "proposal.intent.json",
      );
      const state = { readLength: 0, wrap: null };
      await scenario.prepare(markerPath, state);
      const fake = configuredFake();
      await assert.rejects(
        writeOrAdoptTransition({
          client: fake,
          fileSystem: {
            lstat,
            async open(path, flags, mode) {
              const handle = await nodeOpen(path, flags, mode);
              return path === markerPath && state.wrap !== null
                ? adversarialMarkerHandle(handle, state.wrap)
                : handle;
            },
          },
          markerPath,
          message: proposal(),
        }),
        (error) =>
          error instanceof ProtocolFailureError &&
          error.terminalCode === "FAILED",
      );
      assert.equal(fake.calls.logAction.length, 0);
      if (state.wrap !== null) {
        assert.equal(state.readLength, 1025);
      }
    });
  }
});

test("a pinned output directory rejects replacement at every pre-dispatch path checkpoint", async (t) => {
  const successfulEvents = [];
  async function runCase(t, replaceAt) {
    const root = await temporaryDirectory(t);
    const directory = join(root, "output");
    const moved = join(root, "moved-output");
    const replacement = join(root, "replacement");
    await mkdir(directory, { mode: 0o700 });
    await mkdir(replacement, { mode: 0o700 });
    let armed = false;
    let checkpoint = 0;
    let replaced = false;
    async function replace() {
      if (replaced) {
        return;
      }
      replaced = true;
      await rename(directory, moved);
      await rename(replacement, directory);
    }
    const fileSystem = {
      async lstat(path) {
        if (armed && path === directory) {
          checkpoint += 1;
          successfulEvents.push(checkpoint);
          if (checkpoint === replaceAt) {
            await replace();
          }
        }
        return lstat(path);
      },
      open: nodeOpen,
    };
    const pin = await pinOutputDirectory({
      directory,
      fileSystem,
    });
    armed = true;
    const fake = configuredFake();
    try {
      const operation = writeOrAdoptTransition({
        client: fake,
        directoryPin: pin,
        fileSystem,
        markerPath: join(
          directory,
          "proposal.intent.json",
        ),
        message: proposal(),
      });
      if (replaceAt === Number.POSITIVE_INFINITY) {
        await operation;
      } else {
        await assert.rejects(
          operation,
          (error) =>
            error instanceof ProtocolFailureError &&
            error.terminalCode === "FAILED",
        );
        assert.equal(fake.calls.logAction.length, 0);
      }
    } finally {
      await closePinnedOutputDirectory(pin);
    }
    return checkpoint;
  }

  const checkpointCount = await runCase(
    t,
    Number.POSITIVE_INFINITY,
  );
  assert.ok(checkpointCount >= 6);
  for (
    let replaceAt = 1;
    replaceAt <= checkpointCount;
    replaceAt += 1
  ) {
    await t.test(`checkpoint ${replaceAt}`, async (t) => {
      await runCase(t, replaceAt);
    });
  }
});

test("directory pins tolerate benign link-count changes while preserving identity", async (t) => {
  const directory = await temporaryDirectory(t);
  const baseline = await lstat(directory);
  let nlink = baseline.nlink;
  const changingStats = () => ({
    dev: baseline.dev,
    gid: baseline.gid,
    ino: baseline.ino,
    isDirectory: () => true,
    mode: baseline.mode,
    nlink: nlink++,
    rdev: baseline.rdev,
    uid: baseline.uid,
  });
  const fileSystem = {
    async lstat(path) {
      assert.equal(path, directory);
      return changingStats();
    },
    async open(path, flags, mode) {
      const handle = await nodeOpen(path, flags, mode);
      return {
        close: () => handle.close(),
        stat: async () => changingStats(),
        sync: () => handle.sync(),
      };
    },
  };

  const pin = await pinOutputDirectory({
    directory,
    fileSystem,
  });
  try {
    await pin.assertCurrent();
    await pin.sync();
  } finally {
    await closePinnedOutputDirectory(pin);
  }
});

test("directory durability failures prevent the Clockchain write after a real marker write", async (t) => {
  for (const operation of ["open", "sync", "close"]) {
    await t.test(operation, async (t) => {
      const directory = await temporaryDirectory(t);
      const markerPath = join(
        directory,
        `${operation}.intent.json`,
      );
      const fake = configuredFake();

      await assert.rejects(
        writeOrAdoptTransition({
          client: fake,
          fileSystem: {
            async open(path, flags, mode) {
              if (
                path === directory &&
                operation === "open"
              ) {
                throw new Error("directory open failed");
              }
              const handle = await nodeOpen(path, flags, mode);
              if (path !== directory) {
                return handle;
              }
              return {
                async close() {
                  await handle.close();
                  if (operation === "close") {
                    throw new Error(
                      "directory close failed",
                    );
                  }
                },
                async sync() {
                  await handle.sync();
                  if (operation === "sync") {
                    throw new Error(
                      "directory sync failed",
                    );
                  }
                },
                stat: () => handle.stat(),
              };
            },
          },
          markerPath,
          message: proposal(),
        }),
        (error) =>
          error instanceof ProtocolFailureError &&
          error.terminalCode === "FAILED",
      );

      assert.equal(
        fake.calls.logAction.length,
        operation === "close" ? 1 : 0,
      );
      if (operation === "open") {
        await assert.rejects(() => stat(markerPath), {
          code: "ENOENT",
        });
      } else {
        assert.equal((await stat(markerPath)).isFile(), true);
      }
    });
  }
});

test("directory pin close failures do not mask an earlier protocol failure", async (t) => {
  const directory = await temporaryDirectory(t);
  const message = proposal();
  const fake = configuredFake();
  let closeCalls = 0;

  await assert.rejects(
    writeOrAdoptTransition({
      client: clientFrom(fake, {
        async searchActions() {
          return [{
            assetHash: "0".repeat(64),
            assetReferenceId: sessionKey(
              message.sessionDigest,
              message.kind,
            ),
            blockHeight: "1",
            hashType: "SHA-256",
            ledgerId:
              "123e4567-e89b-42d3-a456-426614174000",
          }];
        },
      }),
      fileSystem: {
        async open(path, flags, mode) {
          const handle = await nodeOpen(path, flags, mode);
          if (path !== directory) {
            return handle;
          }
          return {
            async close() {
              closeCalls += 1;
              await handle.close();
              throw new Error("directory close failed");
            },
            sync: () => handle.sync(),
            stat: () => handle.stat(),
          };
        },
      },
      markerPath: join(directory, "proposal.intent.json"),
      message,
    }),
    (error) =>
      error instanceof ProtocolFailureError &&
      error.terminalCode === "BINDING_MISMATCH",
  );
  assert.equal(closeCalls, 1);
  assert.equal(fake.calls.logAction.length, 0);
});

test("writes exactly once, then performs mandatory verification", async (t) => {
  const directory = await temporaryDirectory(t);
  const fake = configuredFake();
  const message = proposal();
  const markerPath = join(
    directory,
    "proposal.intent.json",
  );
  const durabilityEvents = [];
  const client = clientFrom(fake, {
    async logAction(options) {
      durabilityEvents.push("log-action");
      return fake.logAction(options);
    },
  });

  const outcome = await writeOrAdoptTransition({
    client,
    fileSystem: {
      async open(path, flags, mode) {
        const handle = await nodeOpen(path, flags, mode);
        if (path === directory) {
          durabilityEvents.push("directory-open");
          return {
            async close() {
              durabilityEvents.push("directory-close");
              await handle.close();
            },
            async sync() {
              durabilityEvents.push("directory-sync");
              await handle.sync();
            },
            stat: () => handle.stat(),
          };
        }
        durabilityEvents.push("marker-open");
        return {
          async close() {
            durabilityEvents.push("marker-close");
            await handle.close();
          },
          async sync() {
            durabilityEvents.push("marker-sync");
            await handle.sync();
          },
          async writeFile(value) {
            durabilityEvents.push("marker-write");
            await handle.writeFile(value);
          },
        };
      },
    },
    markerPath,
    message,
  });

  assert.deepEqual(durabilityEvents, [
    "directory-open",
    "marker-open",
    "marker-write",
    "marker-sync",
    "marker-close",
    "directory-sync",
    "log-action",
    "directory-close",
  ]);
  assert.deepEqual(fake.calls.logAction, [
    exactWriteArgs(message),
  ]);
  assert.deepEqual(
    fake.callSequence.map(({ name }) => name),
    [
      "searchActions",
      "logAction",
      "searchActions",
      "verifyCrossParty",
      "getBlock",
      "resolveAgent",
    ],
  );
  assert.deepEqual(fake.calls.verifyCrossParty[0], {
    blockHeight: outcome.transition.onChain.blockHeight,
    ledgerId: outcome.transition.onChain.ledgerId,
  });
  assert.deepEqual(Object.keys(outcome), RUNNER_OUTCOME_KEYS);
  assert.equal(outcome.source, "written");
  assert.equal(outcome.discoveryOnly, true);
  assert.equal(outcome.markerCreated, true);
  assert.equal(outcome.state, "PROPOSED");
  assert.equal(
    outcome.deadlineMs,
    String(deadlineMs(Number(outcome.transition.blockTimeMs))),
  );
  assert.ok(Object.isFrozen(outcome));
  assert.ok(Object.isFrozen(outcome.transition));
  assert.ok(Object.isFrozen(outcome.transition.onChain));
});

test("a pre-existing marker makes an empty slot discovery-only", async (t) => {
  const directory = await temporaryDirectory(t);
  const fake = configuredFake();
  const message = proposal();
  const markerPath = join(directory, "proposal.intent.json");
  await createWriteIntentMarker({
    marker: markerFor(message),
    markerPath,
  });

  const outcome = await writeOrAdoptTransition({
    client: fake,
    markerPath,
    message,
  });

  assert.equal(fake.calls.logAction.length, 0);
  assert.equal(outcome.source, "pending");
  assert.equal(outcome.discoveryOnly, true);
  assert.equal(outcome.markerCreated, false);
  assert.equal(outcome.transition, null);
});

test("an exclusive marker race permits at most one network write", async (t) => {
  const directory = await temporaryDirectory(t);
  const fake = configuredFake();
  const message = proposal();
  const markerPath = join(directory, "raced.intent.json");

  const settled = await Promise.allSettled([
    writeOrAdoptTransition({
      client: fake,
      markerPath,
      message,
    }),
    writeOrAdoptTransition({
      client: fake,
      markerPath,
      message,
    }),
  ]);

  assert.equal(fake.calls.logAction.length, 1);
  assert.ok(
    settled.every(({ status }) => status === "fulfilled"),
  );
  assert.ok(
    settled.some(
      ({ value }) => value.source === "written",
    ),
  );
  assert.ok(
    settled.every(
      ({ value }) =>
        ["written", "adopted", "pending"].includes(
          value.source,
        ),
    ),
  );
});

test("adopts one digest-identical record without creating a marker", async (t) => {
  const directory = await temporaryDirectory(t);
  const fake = configuredFake();
  const message = proposal();
  await fake.logAction(exactWriteArgs(message));
  const writeCount = fake.calls.logAction.length;

  const outcome = await writeOrAdoptTransition({
    client: fake,
    markerPath: join(directory, "proposal.intent.json"),
    message,
  });

  assert.equal(fake.calls.logAction.length, writeCount);
  assert.equal(outcome.source, "adopted");
  assert.equal(outcome.markerCreated, false);
  assert.equal(outcome.state, "PROPOSED");
});

test("mismatches and duplicates fail closed before any runner write", async (t) => {
  const directory = await temporaryDirectory(t);
  const message = proposal();
  const mismatch = configuredFake();
  await mismatch.logAction({
    ...exactWriteArgs(message),
    asset_hash: "0".repeat(64),
  });

  await assert.rejects(
    writeOrAdoptTransition({
      client: mismatch,
      markerPath: join(directory, "mismatch.intent.json"),
      message,
    }),
    (error) =>
      error instanceof ProtocolFailureError &&
      error.terminalCode === "BINDING_MISMATCH",
  );
  assert.equal(mismatch.calls.logAction.length, 1);

  const duplicate = configuredFake();
  await duplicate.logAction(exactWriteArgs(message));
  await duplicate.logAction(exactWriteArgs(message));
  await assert.rejects(
    writeOrAdoptTransition({
      client: duplicate,
      markerPath: join(directory, "duplicate.intent.json"),
      message,
    }),
    (error) =>
      error instanceof ProtocolFailureError &&
      error.terminalCode === "DUPLICATE",
  );
  assert.equal(duplicate.calls.logAction.length, 2);
});

test("transport and unknown write outcomes retry after confirmed-absent discovery, then stay discovery-only", async (t) => {
  const directory = await temporaryDirectory(t);
  const message = proposal();
  const markerPath = join(directory, "ambiguous.intent.json");
  const fake = configuredFake();
  let attempts = 0;
  const client = clientFrom(fake, {
    async logAction() {
      attempts += 1;
      throw new McpNetworkError("hostile secret");
    },
  });

  await assert.rejects(
    writeOrAdoptTransition({
      client,
      markerPath,
      message,
      sleeper: async () => {},
    }),
    (error) =>
      error instanceof ProtocolFailureError &&
      error.terminalCode === "AMBIGUOUS_WRITE" &&
      !error.message.includes("hostile secret"),
  );
  assert.equal(attempts, 3);
  assert.deepEqual(
    JSON.parse(await readFile(markerPath, "utf8")),
    markerFor(message),
  );

  const resumed = await writeOrAdoptTransition({
    client,
    markerPath,
    message,
  });
  assert.equal(attempts, 3);
  assert.equal(resumed.source, "pending");

  const malformedPath = join(
    directory,
    "malformed-result.intent.json",
  );
  await assert.rejects(
    writeOrAdoptTransition({
      client: clientFrom(fake, {
        async logAction() {
          return {};
        },
      }),
      markerPath: malformedPath,
      message,
    }),
    (error) =>
      error instanceof ProtocolFailureError &&
      error.terminalCode === "AMBIGUOUS_WRITE",
  );

  for (const [name, thrown] of [
    [
      "protocol",
      new McpProtocolError(
        "post-dispatch response validation failed",
      ),
    ],
    ["unknown", new Error("unknown post-dispatch failure")],
  ]) {
    const throwPath = join(
      directory,
      `${name}.intent.json`,
    );
    let throwAttempts = 0;
    const throwingClient = clientFrom(fake, {
      async logAction() {
        throwAttempts += 1;
        throw thrown;
      },
    });
    await assert.rejects(
      writeOrAdoptTransition({
        client: throwingClient,
        markerPath: throwPath,
        message,
        sleeper: async () => {},
      }),
      (error) =>
        error instanceof ProtocolFailureError &&
        error.terminalCode === "AMBIGUOUS_WRITE" &&
        !error.message.includes(thrown.message),
    );
    assert.equal(throwAttempts, 3);
    assert.deepEqual(
      JSON.parse(await readFile(throwPath, "utf8")),
      markerFor(message),
    );
    const discoveryOnly = await writeOrAdoptTransition({
      client: throwingClient,
      markerPath: throwPath,
      message,
    });
    assert.equal(discoveryOnly.source, "pending");
    assert.equal(throwAttempts, 3);
  }
});

test("retries an ambiguous dispatch after confirmed-absent discovery and writes", async (t) => {
  const directory = await temporaryDirectory(t);
  const message = proposal();
  const markerPath = join(directory, "retry.intent.json");
  const fake = configuredFake();
  let attempts = 0;
  const client = clientFrom(fake, {
    async logAction(args) {
      attempts += 1;
      if (attempts === 1) {
        throw new McpNetworkError("transient blip");
      }
      return fake.logAction(args);
    },
  });

  const outcome = await writeOrAdoptTransition({
    client,
    markerPath,
    message,
    sleeper: async () => {},
  });

  assert.equal(attempts, 2);
  assert.equal(outcome.source, "written");
  assert.equal(outcome.markerCreated, true);
  assert.equal(outcome.state, "PROPOSED");
  assert.equal(outcome.transition.digest, transitionDigest(message));
  assert.deepEqual(fake.calls.logAction, [
    exactWriteArgs(message),
  ]);
});

test("adopts the record when a failed dispatch actually landed", async (t) => {
  const directory = await temporaryDirectory(t);
  const message = proposal();
  const markerPath = join(directory, "landed.intent.json");
  const fake = configuredFake();
  let attempts = 0;
  const client = clientFrom(fake, {
    async logAction(args) {
      attempts += 1;
      await fake.logAction(args);
      throw new McpNetworkError("response lost after anchor");
    },
  });

  const outcome = await writeOrAdoptTransition({
    client,
    markerPath,
    message,
    sleeper: async () => {},
  });

  assert.equal(attempts, 1);
  assert.equal(outcome.source, "adopted");
  assert.equal(outcome.state, "PROPOSED");
  assert.equal(outcome.transition.digest, transitionDigest(message));
  assert.deepEqual(fake.calls.logAction, [
    exactWriteArgs(message),
  ]);
});

test("fails closed without re-dispatch when reconciliation discovery errors", async (t) => {
  const directory = await temporaryDirectory(t);
  const message = proposal();
  const markerPath = join(directory, "blind.intent.json");
  const fake = configuredFake();
  let attempts = 0;
  let searchCalls = 0;
  const client = clientFrom(fake, {
    async logAction() {
      attempts += 1;
      throw new McpNetworkError("transient blip");
    },
    async searchActions(args) {
      searchCalls += 1;
      if (searchCalls === 1) {
        return fake.searchActions(args);
      }
      throw new McpRateLimitedError("slow down");
    },
  });

  await assert.rejects(
    writeOrAdoptTransition({
      client,
      markerPath,
      message,
      sleeper: async () => {},
    }),
    (error) =>
      error instanceof ProtocolFailureError &&
      error.terminalCode === "AMBIGUOUS_WRITE",
  );
  assert.equal(attempts, 1);
});

test("rate bodies, malformed searches, and symlink markers never become absence", async (t) => {
  const directory = await temporaryDirectory(t);
  const message = proposal();
  for (const [options, terminalCode] of [
    [{ rateLimitBody: true }, "RATE_BLOCKED"],
    [{ nonArraySearch: true }, "FAILED"],
  ]) {
    const fake = createFakeBilateralClockchain(options);
    await assert.rejects(
      writeOrAdoptTransition({
        client: fake,
        markerPath: join(
          directory,
          `${terminalCode}.intent.json`,
        ),
        message,
      }),
      (error) =>
        error instanceof ProtocolFailureError &&
        error.terminalCode === terminalCode,
    );
    assert.equal(fake.calls.logAction.length, 0);
  }

  const targetPath = join(directory, "marker-target.json");
  const markerPath = join(directory, "marker-link.json");
  await writeFile(
    targetPath,
    `${JSON.stringify(markerFor(message))}\n`,
    { mode: 0o600 },
  );
  await symlink(targetPath, markerPath);
  const fake = configuredFake();
  await assert.rejects(
    writeOrAdoptTransition({
      client: fake,
      markerPath,
      message,
    }),
    (error) =>
      error instanceof ProtocolFailureError &&
      error.terminalCode === "FAILED",
  );
  assert.equal(fake.calls.logAction.length, 0);
});

test("polls at least every 20 seconds and verifies a discovered transition", async () => {
  const fake = configuredFake();
  const message = proposal();
  let monotonicMs = 0;
  const delays = [];
  let published = false;

  const outcome = await pollForTransition({
    client: fake,
    jitter: () => 0,
    message,
    monotonicNow: () => monotonicMs,
    sleeper: async (delayMs) => {
      delays.push(delayMs);
      monotonicMs += delayMs;
      if (!published) {
        published = true;
        await fake.logAction(exactWriteArgs(message));
      }
    },
  });

  assert.deepEqual(delays, [MIN_POLL_INTERVAL_MS]);
  assert.equal(outcome.source, "discovered");
  assert.equal(outcome.markerCreated, false);
  assert.equal(outcome.state, "PROPOSED");
});

test("advances serialized state and applies the live upper-bound deadline", async (t) => {
  const directory = await temporaryDirectory(t);
  const fake = configuredFake();
  const stateMachine = createRunnerStateMachine();
  const proposalMessage = proposal();
  const proposed = await writeOrAdoptTransition({
    client: fake,
    markerPath: join(directory, "proposal.intent.json"),
    message: proposalMessage,
    stateMachine,
  });
  const proposalTriple = authoritativeTriple({
    anchoredHash: proposed.transition.onChain.anchoredHash,
    blockHeight: proposed.transition.onChain.blockHeight,
    kind: "proposal",
    ledgerId: proposed.transition.onChain.ledgerId,
  });
  const acceptance = buildAcceptance({
    proposal: proposalMessage,
    proposalTriple,
  });

  const accepted = await writeOrAdoptTransition({
    client: fake,
    markerPath: join(directory, "acceptance.intent.json"),
    message: acceptance,
    proposalDeadlineMs: proposed.deadlineMs,
    stateMachine,
  });
  assert.equal(accepted.state, "ACCEPTED");
  assert.equal(
    accepted.transition.upperBoundMs,
    String(
      liveUpperBoundMs(
        Number(accepted.transition.blockTimeMs),
      ),
    ),
  );

  const lateFake = configuredFake();
  await lateFake.logAction(exactWriteArgs(acceptance));
  const lateState = createRunnerStateMachine();
  lateState.advance("RENDEZVOUS_OK");
  lateState.advance("PROPOSED");
  await assert.rejects(
    writeOrAdoptTransition({
      client: lateFake,
      markerPath: join(directory, "late.intent.json"),
      message: acceptance,
      proposalDeadlineMs: "0",
      stateMachine: lateState,
    }),
    (error) =>
      error instanceof ProtocolFailureError &&
      error.terminalCode === "EXPIRED" &&
      lateState.failureCode === "EXPIRED",
  );
});

test("poll cap expires empty discovery and honors Retry-After", async () => {
  const empty = configuredFake();
  let monotonicMs = 0;
  const delays = [];
  await assert.rejects(
    pollForTransition({
      client: empty,
      jitter: () => 0,
      message: proposal(),
      monotonicNow: () => monotonicMs,
      sleeper: async (delayMs) => {
        delays.push(delayMs);
        monotonicMs += delayMs;
      },
    }),
    (error) =>
      error instanceof ProtocolFailureError &&
      error.terminalCode === "EXPIRED",
  );
  assert.equal(
    delays.reduce((total, delay) => total + delay, 0),
    MAX_POLL_DURATION_MS,
  );
  assert.ok(
    delays.every((delay) => delay >= MIN_POLL_INTERVAL_MS),
  );

  const fake = configuredFake();
  const message = proposal();
  let calls = 0;
  let rateClock = 0;
  const rateDelays = [];
  const client = clientFrom(fake, {
    async searchActions(args) {
      calls += 1;
      if (calls === 1) {
        throw new McpRateLimitedError("rate", {
          retryAfterMs: 30_000,
        });
      }
      return fake.searchActions(args);
    },
  });
  const outcome = await pollForTransition({
    client,
    jitter: () => 0,
    message,
    monotonicNow: () => rateClock,
    sleeper: async (delayMs) => {
      rateDelays.push(delayMs);
      rateClock += delayMs;
      await fake.logAction(exactWriteArgs(message));
    },
  });
  assert.deepEqual(rateDelays, [30_000]);
  assert.equal(outcome.source, "discovered");
});

test("malformed polling callbacks and runner source fail safely", async () => {
  const fake = configuredFake();
  await assert.rejects(
    pollForTransition({
      client: fake,
      message: proposal(),
      monotonicNow: () => Number.NaN,
      sleeper: async () => {},
    }),
    (error) =>
      error instanceof ProtocolFailureError &&
      error.terminalCode === "FAILED",
  );
  const source = await readFile(
    new URL("../src/core/runner.mjs", import.meta.url),
    "utf8",
  );
  assert.equal(
    source.includes(`AUTHOR${"IZED"}`),
    false,
  );
});
