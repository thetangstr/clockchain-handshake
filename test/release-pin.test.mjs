import assert from "node:assert/strict";
import {
  execFileSync,
} from "node:child_process";
import { createHash } from "node:crypto";
import {
  mkdtemp,
  readFile,
  rm,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import {
  assertCleanWorktree,
  buildReleasePin,
  computeKitManifestDigest,
  computeRepositorySha,
  DEFAULT_CHAIN_ID,
  DEFAULT_CLOCKCHAIN_URL,
  DEFAULT_REGISTRY,
  RELEASE_SCHEMA,
  ReleasePinError,
  validateReleasePin,
} from "../scripts/release-pin.mjs";

const KIT_REPO_URL =
  "https://example.com/clockchain/handshake.git";

function git(cwd, args) {
  return execFileSync("git", args, { cwd });
}

async function makeRepo(t, files) {
  const cwd = await mkdtemp(
    join(tmpdir(), "release-pin-test-"),
  );
  t.after(() => rm(cwd, { recursive: true, force: true }));
  git(cwd, ["init", "-q"]);
  git(cwd, ["config", "user.email", "test@example.com"]);
  git(cwd, ["config", "user.name", "Test"]);
  for (const [path, content] of Object.entries(files)) {
    await writeFile(join(cwd, path), content);
    git(cwd, ["add", path]);
  }
  git(cwd, ["commit", "-q", "-m", "seed"]);
  return cwd;
}

test("pins the repository sha and a deterministic manifest digest", async (t) => {
  const cwd = await makeRepo(t, {
    "a.txt": "alpha\n",
    "b.txt": "beta\n",
  });
  const sha = await computeRepositorySha({ cwd });
  assert.equal(
    sha,
    git(cwd, ["rev-parse", "HEAD"]).toString("utf8").trim(),
  );

  const expected = createHash("sha256")
    .update(git(cwd, ["ls-tree", "-r", "-z", "HEAD"]))
    .digest("hex");
  const digest = await computeKitManifestDigest({
    cwd,
    rev: sha,
  });
  assert.equal(digest, expected);
  assert.equal(
    digest,
    await computeKitManifestDigest({ cwd, rev: sha }),
  );

  await writeFile(join(cwd, "c.txt"), "gamma\n");
  git(cwd, ["add", "c.txt"]);
  git(cwd, ["commit", "-q", "-m", "grow"]);
  const nextSha = await computeRepositorySha({ cwd });
  assert.notEqual(nextSha, sha);
  assert.notEqual(
    await computeKitManifestDigest({ cwd, rev: nextSha }),
    digest,
  );
});

test("refuses to pin a dirty worktree", async (t) => {
  const cwd = await makeRepo(t, { "a.txt": "alpha\n" });
  await assertCleanWorktree({ cwd });

  await writeFile(join(cwd, "untracked.txt"), "x\n");
  await assert.rejects(assertCleanWorktree({ cwd }), {
    code: "RELEASE_NOT_CLEAN",
  });
  await rm(join(cwd, "untracked.txt"));

  await writeFile(join(cwd, "a.txt"), "dirty\n");
  await assert.rejects(assertCleanWorktree({ cwd }), {
    code: "RELEASE_NOT_CLEAN",
  });

  await assert.rejects(buildReleasePin({
    cwd,
    kitRepoUrl: KIT_REPO_URL,
  }), {
    code: "RELEASE_NOT_CLEAN",
  });
});

test("builds an exact-key frozen pin with validated fields", async (t) => {
  const cwd = await makeRepo(t, { "a.txt": "alpha\n" });
  const pin = await buildReleasePin({
    cwd,
    kitRepoUrl: KIT_REPO_URL,
    nowMs: 1_800_000_000_000,
  });

  assert.deepEqual(Object.keys(pin).sort(), [
    "chainId",
    "clockchainUrl",
    "generatedAtMs",
    "kitManifestDigest",
    "kitRepoUrl",
    "protocolVersion",
    "registry",
    "repositorySha",
    "schema",
  ]);
  assert.equal(pin.schema, RELEASE_SCHEMA);
  assert.equal(
    pin.protocolVersion,
    "clockchain.bilateral-authorization/v1",
  );
  assert.equal(pin.kitRepoUrl, KIT_REPO_URL);
  assert.equal(pin.clockchainUrl, DEFAULT_CLOCKCHAIN_URL);
  assert.equal(pin.registry, DEFAULT_REGISTRY);
  assert.equal(pin.chainId, DEFAULT_CHAIN_ID);
  assert.equal(pin.generatedAtMs, "1800000000000");
  assert.match(pin.repositorySha, /^[0-9a-f]{40}$/);
  assert.match(pin.kitManifestDigest, /^[0-9a-f]{64}$/);
  assert.ok(Object.isFrozen(pin));
  validateReleasePin(pin);
});

test("rejects malformed pin fields fail-closed", async (t) => {
  const cwd = await makeRepo(t, { "a.txt": "alpha\n" });
  const base = await buildReleasePin({
    cwd,
    kitRepoUrl: KIT_REPO_URL,
  });
  for (const mutate of [
    (pin) => {
      pin.kitRepoUrl = "http://insecure.example.com/x.git";
    },
    (pin) => {
      pin.clockchainUrl = "http://127.0.0.1:8787";
    },
    (pin) => {
      pin.registry = `0x${"AB".repeat(20)}`;
    },
    (pin) => {
      pin.chainId = "0xaaa961";
    },
    (pin) => {
      pin.repositorySha = "latest";
    },
    (pin) => {
      pin.kitManifestDigest = "0".repeat(63);
    },
    (pin) => {
      pin.schema = "handshake-release/v0";
    },
    (pin) => {
      pin.extra = true;
    },
    (pin) => {
      delete pin.generatedAtMs;
    },
  ]) {
    const pin = JSON.parse(JSON.stringify(base));
    mutate(pin);
    assert.throws(
      () => validateReleasePin(pin),
      (error) => {
        assert.ok(error instanceof ReleasePinError);
        assert.equal(error.code, "RELEASE_INPUT");
        return true;
      },
    );
  }
});

test("the CLI writes release.json as the single pin artifact", async (t) => {
  const cwd = await makeRepo(t, { "a.txt": "alpha\n" });
  const out = join(cwd, "release.json");
  execFileSync(
    process.execPath,
    [
      new URL("../scripts/release-pin.mjs", import.meta.url)
        .pathname,
      `--cwd=${cwd}`,
      `--kit-repo-url=${KIT_REPO_URL}`,
      `--out=${out}`,
    ],
  );
  const pin = JSON.parse(await readFile(out, "utf8"));
  validateReleasePin(pin);
  assert.equal(pin.kitRepoUrl, KIT_REPO_URL);
  assert.equal(
    pin.repositorySha,
    git(cwd, ["rev-parse", "HEAD"]).toString("utf8").trim(),
  );
});
