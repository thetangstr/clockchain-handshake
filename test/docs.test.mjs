import assert from "node:assert/strict";
import {
  cp,
  mkdtemp,
  mkdir,
  readFile,
  rm,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";

import {
  checkDocumentation,
  extractReadmePrompt,
} from "../scripts/check-docs.mjs";

const ROOT_DIRECTORY = fileURLToPath(
  new URL("..", import.meta.url),
);
const PUBLIC_DOCUMENTS = Object.freeze([
  "README.md",
  "DEMO.md",
  "prompts/run-turnkey-demo.md",
]);
const SUPPORT_FILES = Object.freeze([
  "package.json",
  "bin/handshake-demo.mjs",
  "invites/README.md",
]);
const OFFICIAL_REGISTRY =
  "0x8004A818BFB912233c491871b3d84c89A494BD9e";

async function temporaryDocumentationFixture(t) {
  const directory = await mkdtemp(
    join(tmpdir(), "handshake-docs-test-"),
  );
  t.after(() => rm(directory, { force: true, recursive: true }));

  for (const relativePath of [
    ...PUBLIC_DOCUMENTS,
    ...SUPPORT_FILES,
  ]) {
    const destination = join(directory, relativePath);
    await mkdir(dirname(destination), { recursive: true });
    await cp(
      join(ROOT_DIRECTORY, relativePath),
      destination,
    );
  }

  return directory;
}

test("public documentation satisfies the turnkey exercise contract", async () => {
  assert.deepEqual(
    await checkDocumentation({
      rootDirectory: ROOT_DIRECTORY,
    }),
    [],
  );

  for (const relativePath of PUBLIC_DOCUMENTS) {
    const contents = await readFile(
      join(ROOT_DIRECTORY, relativePath),
      "utf8",
    );
    assert.match(contents, /Clockchain®/);
    assert.match(contents, /single-validator testnet/i);
    assert.match(contents, /\bno money moves\b/i);
    assert.match(contents, /\bAgentDash\b/);
    assert.match(contents, new RegExp(OFFICIAL_REGISTRY, "i"));
    assert.match(contents, /npm run demo/);
    assert.match(contents, /RESULT\.md/);
    assert.match(contents, /result\.json/);
  }
});

test("README exposes exactly the prompt bytes consumed by clean clients", async () => {
  const [readme, prompt] = await Promise.all([
    readFile(join(ROOT_DIRECTORY, "README.md"), "utf8"),
    readFile(
      join(
        ROOT_DIRECTORY,
        "prompts/run-turnkey-demo.md",
      ),
      "utf8",
    ),
  ]);

  assert.equal(extractReadmePrompt(readme), prompt);
  assert.doesNotMatch(
    prompt,
    /\$\{HANDSHAKE_REPO_(?:URL|REF)/,
  );
});

test("reports a present-capability claim with an exact diagnostic", async (t) => {
  const directory = await temporaryDocumentationFixture(t);
  await writeFile(
    join(directory, "DEMO.md"),
    `${await readFile(join(directory, "DEMO.md"), "utf8")}\nClockchain is trustless.\n`,
  );

  assert.deepEqual(
    (
      await checkDocumentation({
        rootDirectory: directory,
      })
    ).filter((failure) =>
      failure.includes("trustless"),
    ),
    [
      'DEMO.md: presents forbidden capability "trustless" without an explicit negation.',
    ],
  );
});

test("rejects README prompt drift with an exact diagnostic", async (t) => {
  const directory = await temporaryDocumentationFixture(t);
  const readmePath = join(directory, "README.md");
  const readme = await readFile(readmePath, "utf8");
  await writeFile(
    readmePath,
    readme.replace(
      "Run the Clockchain Agent Trust Handshake demo exactly as documented.",
      "Execute the Clockchain Agent Trust Handshake demo exactly as documented.",
    ),
  );

  assert.deepEqual(
    (
      await checkDocumentation({
        rootDirectory: directory,
      })
    ).filter((failure) =>
      failure.includes("byte-for-byte"),
    ),
    [
      "README.md: its single text fence must be byte-for-byte identical to prompts/run-turnkey-demo.md.",
    ],
  );
});

test("reports a broken relative link with an exact diagnostic", async (t) => {
  const directory = await temporaryDocumentationFixture(t);
  const demoPath = join(directory, "DEMO.md");
  await writeFile(
    demoPath,
    `${await readFile(demoPath, "utf8")}\n[Missing runbook](missing.md)\n`,
  );

  assert.deepEqual(
    (
      await checkDocumentation({
        rootDirectory: directory,
      })
    ).filter((failure) =>
      failure.includes("missing.md"),
    ),
    [
      'DEMO.md: broken relative link "missing.md".',
    ],
  );
});
