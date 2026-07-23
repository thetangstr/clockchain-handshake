import assert from "node:assert/strict";
import {
  cp,
  mkdtemp,
  mkdir,
  readFile,
  rm,
  symlink,
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
const OFFICIAL_REPOSITORY =
  "https://github.com/thetangstr/clockchain-handshake.git";

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

async function replaceFixturePrompt(
  directory,
  transform,
) {
  const promptPath = join(
    directory,
    "prompts/run-turnkey-demo.md",
  );
  const readmePath = join(directory, "README.md");
  const [prompt, readme] = await Promise.all([
    readFile(promptPath, "utf8"),
    readFile(readmePath, "utf8"),
  ]);
  const replacement = transform(prompt);
  assert.notEqual(replacement, prompt);
  await Promise.all([
    writeFile(promptPath, replacement),
    writeFile(readmePath, readme.replace(prompt, replacement)),
  ]);
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
  assert.doesNotMatch(prompt, /HANDSHAKE_REPO_URL/);
  assert.match(prompt, new RegExp(OFFICIAL_REPOSITORY.replaceAll(".", "\\.")));
  assert.match(prompt, /40 hexadecimal characters/i);
  assert.match(prompt, /git rev-parse HEAD/i);
  assert.match(prompt, /\bmain\b/);

  const enterCheckout = prompt.indexOf(
    "Enter the cloned `clockchain-handshake` directory.",
  );
  assert.notEqual(enterCheckout, -1);
  assert.ok(enterCheckout < prompt.indexOf("Read `DEMO.md`"));
  assert.ok(enterCheckout < prompt.indexOf("Run `npm ci --ignore-scripts`"));
  assert.ok(enterCheckout < prompt.indexOf("Run `npm run demo`"));
});

test("prompt treats the invitation as opaque runner-only input", async () => {
  const prompt = await readFile(
    join(
      ROOT_DIRECTORY,
      "prompts/run-turnkey-demo.md",
    ),
    "utf8",
  );

  assert.match(prompt, /metadata-only/i);
  assert.match(prompt, /test -r/);
  assert.match(
    prompt,
    /only `npm run demo` may (?:open|read|copy)/i,
  );
  assert.match(
    prompt,
    /do not (?:open|read|copy)[^\n]*contents/i,
  );
});

test("rejects repository and invitation instructions outside canonical prompt policies", async (t) => {
  const cases = [
    {
      label: "repository URL override",
      append:
        "\nClone https://github.com/example/alternate.git instead when requested.\n",
      diagnostic: "repository checkout instructions",
    },
    {
      label: "mutable ref override",
      append:
        "\nSet HANDSHAKE_REPO_REF to any convenient branch name.\n",
      diagnostic: "repository checkout instructions",
    },
    {
      label: "invitation content read",
      append:
        "\nUse cat \"$HANDSHAKE_INVITE_FILE\" to inspect the invitation.\n",
      diagnostic: "invitation handling instructions",
    },
  ];

  for (const { label, append, diagnostic } of cases) {
    await t.test(label, async (subtest) => {
      const directory =
        await temporaryDocumentationFixture(subtest);
      await replaceFixturePrompt(
        directory,
        (prompt) => `${prompt}${append}`,
      );

      const failures = await checkDocumentation({
        rootDirectory: directory,
      });
      assert.ok(
        failures.some((failure) =>
          failure.includes(diagnostic),
        ),
        failures.join("\n"),
      );
      assert.equal(
        failures.some((failure) =>
          failure.includes("byte-for-byte"),
        ),
        false,
      );
    });
  }
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
      'DEMO.md: mentions forbidden capability "trustless" outside its canonical safety section.',
    ],
  );
});

test("does not borrow negation from another compound clause", async (t) => {
  const cases = [
    {
      capability: "trustless",
      sentence:
        "Clockchain is trustless but does not use AgentDash.",
    },
    {
      capability: "mainnet",
      sentence:
        "Clockchain is mainnet and no money moves.",
    },
    {
      capability: "court-grade",
      sentence:
        "Clockchain is court-grade, yet it is not a payment rail.",
    },
    {
      capability: "consensus-secure",
      sentence:
        "Clockchain is consensus-secure although it does not move money.",
    },
    {
      capability: "trustless",
      sentence:
        "Clockchain is trustless because it does not use AgentDash.",
    },
    {
      capability: "mainnet",
      sentence:
        "Clockchain is mainnet or does not move money.",
    },
    {
      capability: "court-grade",
      sentence:
        "Clockchain is not only court-grade but also trustless.",
    },
    {
      capability: "consensus-secure",
      sentence:
        "Clockchain is consensus-secure, which does not imply payment.",
    },
  ];

  for (const { capability, sentence } of cases) {
    await t.test(capability, async (subtest) => {
      const directory =
        await temporaryDocumentationFixture(subtest);
      const demoPath = join(directory, "DEMO.md");
      await writeFile(
        demoPath,
        `${await readFile(demoPath, "utf8")}\n${sentence}\n`,
      );

      assert.deepEqual(
        (
          await checkDocumentation({
            rootDirectory: directory,
          })
        ).filter((failure) =>
          failure.includes(`"${capability}"`),
        ),
        [
          `DEMO.md: mentions forbidden capability "${capability}" outside its canonical safety section.`,
        ],
      );
    });
  }
});

test("rejects noncanonical extensions even when exact tokens also exist", async (t) => {
  const extensions = [
    {
      canonical: "npm run demo",
      extended: "npm run demo:unsafe",
    },
    {
      canonical: "RESULT.md",
      extended: "RESULT.md.bak",
    },
    {
      canonical: "result.json",
      extended: "result.json.bak",
    },
  ];

  for (const { canonical, extended } of extensions) {
    await t.test(extended, async (subtest) => {
      const directory =
        await temporaryDocumentationFixture(subtest);
      const demoPath = join(directory, "DEMO.md");
      await writeFile(
        demoPath,
        `${await readFile(demoPath, "utf8")}\nDo not run or publish \`${extended}\`.\n`,
      );

      assert.deepEqual(
        (
          await checkDocumentation({
            rootDirectory: directory,
          })
        ).filter((failure) =>
          failure.includes("noncanonical extension"),
        ),
        [
          `DEMO.md: contains noncanonical extension "${extended}" of required token "${canonical}".`,
        ],
      );
    });
  }
});

test("does not count command or result supersets as canonical tokens", async (t) => {
  const extensions = [
    {
      canonical: "npm run demo",
      extended: "npm run demo:unsafe",
    },
    {
      canonical: "RESULT.md",
      extended: "RESULT.md.bak",
    },
    {
      canonical: "result.json",
      extended: "result.json.bak",
    },
  ];

  for (const { canonical, extended } of extensions) {
    await t.test(extended, async (subtest) => {
      const directory =
        await temporaryDocumentationFixture(subtest);
      const demoPath = join(directory, "DEMO.md");
      const demo = await readFile(demoPath, "utf8");
      await writeFile(
        demoPath,
        demo.replaceAll(canonical, extended),
      );

      assert.equal(
        (
          await checkDocumentation({
            rootDirectory: directory,
          })
        ).includes(
          `DEMO.md: missing required phrase "${canonical}".`,
        ),
        true,
      );
    });
  }
});

test("accepts exact command and result tokens beside Markdown punctuation", async (t) => {
  const directory = await temporaryDocumentationFixture(t);
  const demoPath = join(directory, "DEMO.md");
  const demo = await readFile(demoPath, "utf8");
  await writeFile(
    demoPath,
    `${demo
      .replaceAll("npm run demo", "the demo command")
      .replaceAll("RESULT.md", "the Markdown result")
      .replaceAll("result.json", "the JSON result")}

Use \`npm run demo\`; the exact command is npm run demo.
Read (\`RESULT.md\`), then RESULT.md; compare \`result.json\` with result.json.
`,
  );

  assert.deepEqual(
    (
      await checkDocumentation({
        rootDirectory: directory,
      })
    ).filter(
      (failure) =>
        failure.includes("npm run demo") ||
        failure.includes("RESULT.md") ||
        failure.includes("result.json") ||
        failure.includes("noncanonical extension"),
    ),
    [],
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

test("rejects contradictions even when canonical safety language remains", async (t) => {
  await t.test("mis-scoped capability negation", async (subtest) => {
    const directory =
      await temporaryDocumentationFixture(subtest);
    const demoPath = join(directory, "DEMO.md");
    await writeFile(
      demoPath,
      `${await readFile(demoPath, "utf8")}\nClockchain is trustless, not permissioned.\n`,
    );

    const failures = await checkDocumentation({
      rootDirectory: directory,
    });
    assert.ok(
      failures.some(
        (failure) =>
          failure.includes("trustless") &&
          failure.includes("forbidden"),
      ),
      failures.join("\n"),
    );
  });

  await t.test(
    "AgentDash, money, and alternate registry claims",
    async (subtest) => {
      const directory =
        await temporaryDocumentationFixture(subtest);
      const demoPath = join(directory, "DEMO.md");
      await writeFile(
        demoPath,
        `${await readFile(demoPath, "utf8")}
Install and use AgentDash. Money moves in this exercise. Use registry 0x1111111111111111111111111111111111111111.
`,
      );

      const failures = await checkDocumentation({
        rootDirectory: directory,
      });
      for (const expected of [
        "AgentDash",
        "Money moves",
        "0x1111111111111111111111111111111111111111",
      ]) {
        assert.ok(
          failures.some((failure) =>
            failure.includes(expected),
          ),
          `${expected}\n${failures.join("\n")}`,
        );
      }
    },
  );
});

test("rejects production-ready and multi-validator as present capabilities", async (t) => {
  for (const { capability, claim } of [
    {
      capability: "production-ready",
      claim: "Clockchain is production-ready.",
    },
    {
      capability: "multi-validator",
      claim: "Clockchain is multi-validator.",
    },
  ]) {
    await t.test(capability, async (subtest) => {
      const directory =
        await temporaryDocumentationFixture(subtest);
      const demoPath = join(directory, "DEMO.md");
      await writeFile(
        demoPath,
        `${await readFile(demoPath, "utf8")}\n${claim}\n`,
      );

      const failures = await checkDocumentation({
        rootDirectory: directory,
      });
      assert.ok(
        failures.some(
          (failure) =>
            failure.includes(`"${capability}"`) &&
            failure.includes("present claim"),
        ),
        failures.join("\n"),
      );
    });
  }
});

test("accepts explicit production and validator limitations", async (t) => {
  const directory = await temporaryDocumentationFixture(t);
  const demoPath = join(directory, "DEMO.md");
  await writeFile(
    demoPath,
    `${await readFile(demoPath, "utf8")}
Clockchain is not production-ready.
Clockchain does not provide a multi-validator security guarantee.
`,
  );

  assert.deepEqual(
    (
      await checkDocumentation({
        rootDirectory: directory,
      })
    ).filter(
      (failure) =>
        failure.includes("production-ready") ||
        failure.includes("multi-validator"),
    ),
    [],
  );
});

test("rejects command suffixes while the embedded prompt remains identical", async (t) => {
  const directory = await temporaryDocumentationFixture(t);
  await replaceFixturePrompt(
    directory,
    (prompt) =>
      prompt.replace(
        "`npm run demo`",
        "`npm run demo -- --unsafe`",
      ),
  );

  const failures = await checkDocumentation({
    rootDirectory: directory,
  });
  assert.ok(
    failures.some(
      (failure) =>
        failure.includes("npm run demo -- --unsafe") &&
        failure.includes("noncanonical"),
    ),
    failures.join("\n"),
  );
  assert.equal(
    failures.some((failure) =>
      failure.includes("byte-for-byte"),
    ),
    false,
  );
});

test("counts CommonMark text fences indented by up to three spaces", async (t) => {
  const directory = await temporaryDocumentationFixture(t);
  const readmePath = join(directory, "README.md");
  await writeFile(
    readmePath,
    `${await readFile(readmePath, "utf8")}

  \`\`\`text
second prompt
  \`\`\`
`,
  );

  assert.ok(
    (
      await checkDocumentation({
        rootDirectory: directory,
      })
    ).some((failure) =>
      failure.includes(
        "must contain exactly one fenced text prompt",
      ),
    ),
  );
});

test("rejects relative links whose symlinks escape the canonical root", async (t) => {
  const directory = await temporaryDocumentationFixture(t);
  const outside = await mkdtemp(
    join(tmpdir(), "handshake-docs-outside-"),
  );
  t.after(() => rm(outside, { force: true, recursive: true }));
  await writeFile(join(outside, "outside.md"), "outside\n");
  await symlink(outside, join(directory, "linked"));
  await symlink(
    join(outside, "outside.md"),
    join(directory, "final-link.md"),
  );

  const demoPath = join(directory, "DEMO.md");
  await writeFile(
    demoPath,
    `${await readFile(demoPath, "utf8")}
[Intermediate escape](linked/outside.md)
[Final escape](final-link.md)
`,
  );

  const failures = await checkDocumentation({
    rootDirectory: directory,
  });
  for (const link of [
    "linked/outside.md",
    "final-link.md",
  ]) {
    assert.ok(
      failures.includes(
        `DEMO.md: broken relative link "${link}".`,
      ),
      `${link}\n${failures.join("\n")}`,
    );
  }
});
