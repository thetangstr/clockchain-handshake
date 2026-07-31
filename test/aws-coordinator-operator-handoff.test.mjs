import assert from "node:assert/strict";
import {
  createHash,
} from "node:crypto";
import {
  open,
  chmod,
  link,
  lstat,
  mkdir,
  mkdtemp,
  readFile,
  rm,
  symlink,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";

import {
  publishAwsFundingRecord,
  publishAwsVerifierHandoff,
  readAwsFundingRecord,
  readAwsVerifierHandoff,
  readAwsVerifierPublication,
} from "../infra/aws/runtime/coordinator-operator-handoff.mjs";

const SESSION_ID =
  "11111111-1111-4111-8111-111111111111";
const RELEASE_ID = `release-${createHash("sha256").update(SESSION_ID, "utf8").digest("hex").slice(0, 16)}`;
const REPOSITORY_SHA =
  "abcdef0123456789abcdef0123456789abcdef01";
const EVIDENCE_ROOT =
  `/var/lib/clockchain/evidence/releases/${RELEASE_ID}`;
const OUTPUT_ROOT =
  `/var/lib/clockchain/verifier-output/releases/${RELEASE_ID}`;
const TASK_ARN =
  "arn:aws:ecs:us-west-2:123456789012:task/clockchain/11111111111111111111111111111111";

function address(index) {
  return `0x${String(index).repeat(40)}`;
}

function fundingRecord(overrides = {}) {
  const addresses = [
    address(1),
    address(2),
    address(3),
    address(4),
  ];
  return {
    addresses,
    paymentMoved: false,
    participants: addresses.map((item) => ({
      address: item,
      balanceWei: "0",
      nonce: "0",
    })),
    schema:
      "clockchain.bilateral-funding-addresses/v1",
    ...overrides,
  };
}

function handoff(overrides = {}) {
  return {
    descriptorDigest: "a".repeat(64),
    descriptorPath:
      `${EVIDENCE_ROOT}/rehearsal/descriptor.json`,
    evidenceDigest: "b".repeat(64),
    mandateDigest: "c".repeat(64),
    payerMandatePath:
      `${EVIDENCE_ROOT}/rehearsal/payer-mandate.json`,
    payeeResultsPath:
      `${EVIDENCE_ROOT}/payee/results`,
    payerResultsPath:
      `${EVIDENCE_ROOT}/payer/results`,
    paymentMoved: false,
    paymentRequestPath:
      `${EVIDENCE_ROOT}/rehearsal/payment-request.json`,
    publicationPath:
      `${OUTPUT_ROOT}/public/verifier-publication.json`,
    releaseId: RELEASE_ID,
    repositorySha: REPOSITORY_SHA,
    requestDigest: "d".repeat(64),
    schema: "clockchain.aws-verifier-handoff/v1",
    sessionDigest: "e".repeat(64),
    sessionId: SESSION_ID,
    subjectRun: "rehearsal",
    ...overrides,
  };
}

function publication(overrides = {}) {
  return {
    attemptId:
      "22222222-2222-4222-8222-222222222222",
    evidenceDigest: "b".repeat(64),
    paymentMoved: false,
    publicationDigest: "f".repeat(64),
    repositorySha: REPOSITORY_SHA,
    revision: 7,
    schema:
      "clockchain.aws-verifier-task-publication/v1",
    status: "VERIFICATION_PASSED",
    taskArn: TASK_ARN,
    writtenAtMs: "2000000000000",
    ...overrides,
  };
}

function canonical(value) {
  return `${JSON.stringify(value)}\n`;
}

async function tempFile(name = "handoff.json") {
  const root = await mkdtemp(
    join(tmpdir(), "aws-handoff-"),
  );
  return {
    path: join(root, name),
    root,
  };
}

test("publishes and adopts byte-identical funding records as stable private canonical files", async () => {
  const fx = await tempFile("funding.json");
  try {
    const record = fundingRecord();
    await publishAwsFundingRecord({
      path: fx.path,
      record,
    });
    assert.equal(
      (await lstat(fx.path)).mode & 0o777,
      0o600,
    );
    assert.equal(
      await readFile(fx.path, "utf8"),
      canonical(record),
    );
    assert.deepEqual(
      await readAwsFundingRecord({
        path: fx.path,
      }),
      record,
    );
    await publishAwsFundingRecord({
      path: fx.path,
      record: fundingRecord(),
    });
    assert.deepEqual(
      await readAwsFundingRecord({
        path: fx.path,
      }),
      record,
    );
  } finally {
    await rm(fx.root, {
      force: true,
      recursive: true,
    });
  }
});

test("publishers return the exact frozen validated snapshot whose bytes were persisted despite caller mutation", async () => {
  const fundingFx = await tempFile("funding.json");
  const handoffFx = await tempFile("verifier-handoff.json");
  try {
    const record = fundingRecord();
    const activeHandoff = handoff();
    let pauseResolve;
    const pause = new Promise((resolvePause) => {
      pauseResolve = resolvePause;
    });
    let writes = 0;
    const fileSystem = {
      lstat,
      open: async (target, flags, mode) => {
        const handle = await open(target, flags, mode);
        return {
          async close() {
            return handle.close();
          },
          async readFile(...args) {
            return handle.readFile(...args);
          },
          async stat() {
            return handle.stat();
          },
          async sync() {
            return handle.sync();
          },
          async writeFile(bytes) {
            writes += 1;
            if (writes === 1) {
              pauseResolve();
              await pause;
            }
            return handle.writeFile(bytes);
          },
        };
      },
    };
    const fundingPromise = publishAwsFundingRecord({
      path: fundingFx.path,
      record,
    }, { fileSystem });
    await pause;
    record.addresses[0] = address(9);
    record.participants[0].address = address(9);
    const fundingResult = await fundingPromise;
    assert.deepEqual(fundingResult, fundingRecord());
    assert.ok(Object.isFrozen(fundingResult));
    assert.equal(
      await readFile(fundingFx.path, "utf8"),
      canonical(fundingRecord()),
    );

    const handoffPromise = publishAwsVerifierHandoff({
      path: handoffFx.path,
      handoff: activeHandoff,
    });
    activeHandoff.descriptorDigest = "9".repeat(64);
    const handoffResult = await handoffPromise;
    assert.deepEqual(handoffResult, handoff());
    assert.ok(Object.isFrozen(handoffResult));
    assert.equal(
      await readFile(handoffFx.path, "utf8"),
      canonical(handoff()),
    );
  } finally {
    await rm(fundingFx.root, {
      force: true,
      recursive: true,
    });
    await rm(handoffFx.root, {
      force: true,
      recursive: true,
    });
  }
});

test("funding record boundary rejects changed, malformed, noncanonical, symlink, hardlink, and unstable files", async () => {
  const cases = [
    async (path) => {
      await writeFile(
        path,
        canonical(
          fundingRecord({
            addresses: [
              address(5),
              address(6),
              address(7),
              address(8),
            ],
          }),
        ),
        { mode: 0o600 },
      );
      await publishAwsFundingRecord({
        path,
        record: fundingRecord(),
      });
    },
    async (path) => {
      await writeFile(path, "{", { mode: 0o600 });
      await readAwsFundingRecord({ path });
    },
    async (path) => {
      await writeFile(
        path,
        JSON.stringify(fundingRecord()),
        { mode: 0o600 },
      );
      await readAwsFundingRecord({ path });
    },
    async (path, root) => {
      const target = join(root, "target");
      await writeFile(target, canonical(fundingRecord()), {
        mode: 0o600,
      });
      await symlink(target, path);
      await readAwsFundingRecord({ path });
    },
    async (path, root) => {
      const other = join(root, "other");
      await writeFile(path, canonical(fundingRecord()), {
        mode: 0o600,
      });
      await link(path, other);
      await readAwsFundingRecord({ path });
    },
    async (path) => {
      await writeFile(path, canonical(fundingRecord()), {
        mode: 0o600,
      });
      let swapped = false;
      await readAwsFundingRecord({
        path,
      }, {
        fileSystem: {
          lstat: async (target) => lstat(target),
          open: async (target, flags) => {
            if (!swapped) {
              swapped = true;
              await writeFile(
                target,
                canonical(fundingRecord({
                  addresses: [
                    address(5),
                    address(6),
                    address(7),
                    address(8),
                  ],
                })),
                { mode: 0o600 },
              );
            }
            return await import("node:fs/promises").then((fs) =>
              fs.open(target, flags),
            );
          },
        },
      });
    },
  ];
  for (const run of cases) {
    const fx = await tempFile("funding.json");
    try {
      await assert.rejects(
        run(fx.path, fx.root),
        /AWS coordinator operator handoff failed safely/,
      );
    } finally {
      await rm(fx.root, {
        force: true,
        recursive: true,
      });
    }
  }
});

test("publishes and reads exact verifier handoff files without secret canaries", async () => {
  const fx = await tempFile("verifier-handoff.json");
  try {
    const value = handoff();
    const result = await publishAwsVerifierHandoff({
      path: fx.path,
      handoff: value,
    });
    assert.deepEqual(result, value);
    assert.equal(
      (await lstat(fx.path)).mode & 0o777,
      0o600,
    );
    const text = await readFile(fx.path, "utf8");
    assert.equal(text, canonical(value));
    assert.doesNotMatch(
      text,
      /secret-canary|token-canary|private-key-canary|capability-canary/,
    );
    assert.deepEqual(
      await readAwsVerifierHandoff({
        path: fx.path,
      }),
      value,
    );
    await publishAwsVerifierHandoff({
      path: fx.path,
      handoff: handoff(),
    });
  } finally {
    await rm(fx.root, {
      force: true,
      recursive: true,
    });
  }
});

test("all handoff exports sanitize null, proxy, accessor, and raw filesystem caller failures", async () => {
  const fx = await tempFile("hostile.json");
  const proxy = new Proxy({}, {
    get() {
      throw new Error("proxy canary");
    },
  });
  const accessor = {};
  Object.defineProperty(accessor, "path", {
    enumerable: true,
    get() {
      throw new Error("accessor canary");
    },
  });
  const cases = [
    () => publishAwsFundingRecord(null),
    () => publishAwsFundingRecord(proxy),
    () => publishAwsFundingRecord(accessor),
    () => readAwsFundingRecord(null),
    () => readAwsFundingRecord(proxy),
    () => readAwsFundingRecord(accessor),
    () => publishAwsVerifierHandoff(null),
    () => publishAwsVerifierHandoff(proxy),
    () => publishAwsVerifierHandoff(accessor),
    () => readAwsVerifierHandoff(null),
    () => readAwsVerifierHandoff(proxy),
    () => readAwsVerifierHandoff(accessor),
    () => readAwsVerifierPublication(null),
    () => readAwsVerifierPublication(proxy),
    () => readAwsVerifierPublication(accessor),
    () => readAwsFundingRecord({
      path: fx.path,
    }, {
      fileSystem: {
        lstat: async () => {
          throw new Error("raw fs canary");
        },
      },
    }),
  ];
  try {
    for (const run of cases) {
      await assert.rejects(
        run(),
        (error) => {
          assert.equal(
            error.name,
            "AwsCoordinatorOperatorHandoffError",
          );
          assert.equal(
            error.message,
            "AWS coordinator operator handoff failed safely.",
          );
          assert.doesNotMatch(
            String(error),
            /proxy canary|accessor canary|raw fs canary/,
          );
          return true;
        },
      );
    }
  } finally {
    await rm(fx.root, {
      force: true,
      recursive: true,
    });
  }
});

test("byte-identical adoption fsyncs parent and parent sync failure fails closed", async () => {
  const fx = await tempFile("funding.json");
  try {
    await writeFile(
      fx.path,
      canonical(fundingRecord()),
      { mode: 0o600 },
    );
    const calls = [];
    const adoptionFs = {
      lstat,
      open: async (target, flags, mode) => {
        if (target === fx.root) {
          calls.push(["parent-open", target]);
          const handle = await open(target, flags, mode);
          return {
            close: () => handle.close(),
            sync: async () => {
              calls.push(["parent-sync", target]);
              return handle.sync();
            },
          };
        }
        return open(target, flags, mode);
      },
    };
    await publishAwsFundingRecord({
      path: fx.path,
      record: fundingRecord(),
    }, { fileSystem: adoptionFs });
    assert.deepEqual(calls, [
      ["parent-open", fx.root],
      ["parent-sync", fx.root],
    ]);

    await assert.rejects(
      publishAwsFundingRecord({
        path: fx.path,
        record: fundingRecord(),
      }, {
        fileSystem: {
          lstat,
          open: async (target, flags, mode) => {
            if (target === fx.root) {
              return {
                close: async () => {},
                sync: async () => {
                  throw new Error("parent sync canary");
                },
              };
            }
            return open(target, flags, mode);
          },
        },
      }),
      (error) => {
        assert.equal(
          error.name,
          "AwsCoordinatorOperatorHandoffError",
        );
        assert.doesNotMatch(
          String(error),
          /parent sync canary/,
        );
        return true;
      },
    );
  } finally {
    await rm(fx.root, {
      force: true,
      recursive: true,
    });
  }
});

test("verifier handoff rejects traversal, prefix siblings, reordered or unknown keys, mismatches, accessors, and coercion hooks", async () => {
  const badValues = [
    handoff({
      descriptorPath:
        `${EVIDENCE_ROOT}-sibling/descriptor.json`,
    }),
    handoff({
      publicationPath:
        `${OUTPUT_ROOT}/../public/verifier-publication.json`,
    }),
    handoff({
      sessionId:
        "11111111-1111-4111-8111-111111111112",
    }),
    handoff({
      releaseId: "release-0000000000000000",
    }),
    handoff({ subjectRun: "demo" }),
    handoff({
      paymentRequestPath:
        `${EVIDENCE_ROOT}/rehearsal/descriptor.json`,
    }),
    Object.fromEntries(
      Object.entries(handoff()).reverse(),
    ),
    { ...handoff(), unknown: true },
    Object.defineProperty(
      { ...handoff() },
      "descriptorDigest",
      {
        enumerable: true,
        get() {
          assert.fail("getter invoked");
        },
      },
    ),
    {
      ...handoff(),
      descriptorDigest: {
        toString() {
          assert.fail("coercion invoked");
        },
      },
    },
    ...[
      "descriptorDigest",
      "evidenceDigest",
      "mandateDigest",
      "requestDigest",
      "sessionDigest",
      "releaseId",
      "repositorySha",
      "sessionId",
    ].map((key) => ({
      ...handoff(),
      [key]: {
        toString() {
          assert.fail(`coercion invoked for ${key}`);
        },
      },
    })),
  ];
  for (const value of badValues) {
    const fx = await tempFile("verifier-handoff.json");
    try {
      await assert.rejects(
        publishAwsVerifierHandoff({
          path: fx.path,
          handoff: value,
        }),
        /AWS coordinator operator handoff failed safely/,
      );
    } finally {
      await rm(fx.root, {
        force: true,
        recursive: true,
      });
    }
  }
});

test("reads exact verifier task publication bound to handoff path, revision, and evidence", async () => {
  const fx = await tempFile("publication.json");
  try {
    const activeHandoff = handoff();
    await writeFile(
      fx.path,
      canonical(publication()),
      { mode: 0o600 },
    );
    assert.deepEqual(
      await readAwsVerifierPublication({
        expectedRevision: 7,
        handoff: activeHandoff,
        path: activeHandoff.publicationPath,
      }, {
        fileSystem: {
          lstat: async () => lstat(fx.path),
          open: async (_path, flags) => open(fx.path, flags),
        },
      }),
      publication(),
    );
  } finally {
    await rm(fx.root, {
      force: true,
      recursive: true,
    });
  }
});

test("verifier publication validates handoff snapshot before reading publication fields", async () => {
  const fx = await tempFile("publication.json");
  try {
    await writeFile(
      fx.path,
      canonical(publication()),
      { mode: 0o600 },
    );
    const invalidHandoff = handoff({
      evidenceDigest: "not-a-digest",
    });
    const accessorHandoff = {
      ...handoff(),
    };
    Object.defineProperty(
      accessorHandoff,
      "evidenceDigest",
      {
        enumerable: true,
        get() {
          assert.fail("handoff getter invoked");
        },
      },
    );
    const proxyHandoff = new Proxy(
      handoff(),
      {
        get() {
          assert.fail("handoff proxy get invoked");
        },
      },
    );
    for (const candidate of [
      invalidHandoff,
      accessorHandoff,
      proxyHandoff,
      handoff({
        repositorySha: { toString() {
          assert.fail("handoff coercion invoked");
        } },
      }),
    ]) {
      let reads = 0;
      await assert.rejects(
        readAwsVerifierPublication({
          expectedRevision: 7,
          handoff: candidate,
          path: handoff().publicationPath,
        }, {
          fileSystem: {
            lstat: async () => {
              reads += 1;
              throw new Error(
                "publication read should not start",
              );
            },
            open: async () => {
              reads += 1;
              throw new Error(
                "publication open should not start",
              );
            },
          },
        }),
        /AWS coordinator operator handoff failed safely/,
      );
      assert.equal(reads, 0);
    }
  } finally {
    await rm(fx.root, {
      force: true,
      recursive: true,
    });
  }
});

test("verifier publication rejects noncanonical, reordered, stale, mismatched, cross-release, and unsafe material", async () => {
  const cases = [
    {
      body: JSON.stringify(publication()),
    },
    {
      body: canonical(
        Object.fromEntries(
          Object.entries(publication()).reverse(),
        ),
      ),
    },
    {
      value: publication({ revision: 6 }),
    },
    {
      value: publication({
        evidenceDigest: "0".repeat(64),
      }),
    },
    {
      value: publication({
        repositorySha: "0".repeat(40),
      }),
    },
    {
      value: publication({
        status: "FAILED",
      }),
    },
    {
      value: publication({
        writtenAtMs: "01",
      }),
    },
    {
      value: {
        ...publication(),
        unknown: true,
      },
    },
    ...[
      "attemptId",
      "publicationDigest",
      "taskArn",
      "writtenAtMs",
    ].map((key) => ({
      value: {
        ...publication(),
        [key]: {
          toString() {
            assert.fail(`publication coercion invoked for ${key}`);
          },
        },
      },
    })),
  ];
  for (const item of cases) {
    const fx = await tempFile("publication.json");
    const activeHandoff = handoff();
    try {
      await writeFile(
        fx.path,
        item.body ?? canonical(item.value),
        { mode: 0o600 },
      );
      await assert.rejects(
        readAwsVerifierPublication({
          expectedRevision: 7,
          handoff: activeHandoff,
          path: activeHandoff.publicationPath,
        }, {
          fileSystem: {
            lstat: async () => lstat(fx.path),
            open: async (_path, flags) => open(fx.path, flags),
          },
        }),
        /AWS coordinator operator handoff failed safely/,
      );
    } finally {
      await rm(fx.root, {
        force: true,
        recursive: true,
      });
    }
  }
});
