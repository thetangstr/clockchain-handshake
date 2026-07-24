#!/usr/bin/env node

import {
  lstat,
  readFile,
  realpath,
} from "node:fs/promises";
import {
  dirname,
  isAbsolute,
  relative,
  resolve,
} from "node:path";
import {
  fileURLToPath,
  pathToFileURL,
} from "node:url";

const PUBLIC_DOCUMENTS = Object.freeze([
  "README.md",
  "DEMO.md",
  "prompts/run-turnkey-demo.md",
]);
const REQUIRED_REPOSITORY_FILES = Object.freeze([
  "package.json",
  "bin/handshake-demo.mjs",
  "invites/README.md",
]);
const REQUIRED_LINKS = Object.freeze({
  "README.md": Object.freeze([
    "DEMO.md",
    "prompts/run-turnkey-demo.md",
    "invites/README.md",
  ]),
  "DEMO.md": Object.freeze([
    "README.md",
    "prompts/run-turnkey-demo.md",
    "invites/README.md",
  ]),
});
const OFFICIAL_REGISTRY =
  "0x8004A818BFB912233c491871b3d84c89A494BD9e";
const OFFICIAL_REPOSITORY =
  "https://github.com/thetangstr/clockchain-handshake.git";
const FORBIDDEN_PRESENT_CAPABILITIES = Object.freeze([
  "court-grade",
  "trustless",
  "mainnet",
  "consensus-secure",
  "permissionless",
]);
const CONTEXTUAL_PRESENT_CAPABILITIES = Object.freeze([
  "production-ready",
  "multi-validator",
]);
const CLAIM_BOUNDARY_PATTERN =
  /[.!?;,:]+|\b(?:but|yet|however|although|though|while|whereas|and|because|since)\b/gi;
const EXPLICIT_LIMITATION_PATTERN =
  /\b(?:no|never|cannot|can't|isn't|aren't|wasn't|weren't|doesn't|don't|didn't|won't|wouldn't|couldn't|shouldn't|mustn't|not(?!\s+only))\b|\b(?:is|are|was|were|does|do|did|will|would|can|could|should|must|has|have|had)\s+not(?!\s+only)\b/i;
const TOKEN_BOUNDARY_PATTERN =
  /[\s`"'()[\]{}<>,;!?/]/;
const TOKEN_EXTENSION_PATTERN =
  /[a-z0-9_.:/-]/i;
const EXTERNAL_LINK_PATTERN =
  /^(?:[a-z][a-z+.-]*:|\/\/)/i;
const MARKDOWN_LINK_PATTERN =
  /!?\[[^\]]*]\(\s*(?:<([^>]+)>|([^\s)]+))(?:\s+["'][^"']*["'])?\s*\)/g;
const MARKDOWN_REFERENCE_DEFINITION_PATTERN =
  /^ {0,3}\[[^\]\r\n]+]:[ \t]*(?:<([^>\r\n]+)>|([^\s\r\n]+))(?:[ \t]+(?:"[^"]*"|'[^']*'|\([^)]*\)))?[ \t]*$/gm;
const DEFAULT_ROOT_DIRECTORY = resolve(
  dirname(fileURLToPath(import.meta.url)),
  "..",
);
const DEMO_SAFETY_SECTION = `This is an Ethereum Sepolia and Clockchain® single-validator testnet exercise.
No money moves. Do not install or use AgentDash. It is not mainnet, court-grade,
consensus-secure, or trustless.`;
const PROMPT_SAFETY_SECTION = `Work in a new temporary directory. Do not inspect or modify my current project.
Do not install or use AgentDash. Do not invent success states.

This is an Ethereum Sepolia and Clockchain® single-validator testnet exercise.
No money moves. It is not mainnet, court-grade, consensus-secure, or trustless.`;
const README_SAFETY_SECTION = `The exercise runs on Ethereum Sepolia and a Clockchain® single-validator testnet.
No money moves. Do not install or use AgentDash. This exercise is not mainnet,
court-grade, consensus-secure, or trustless.`;
const CANONICAL_SAFETY_SECTIONS = Object.freeze({
  "README.md": Object.freeze([
    Object.freeze({
      label: "repository safety summary",
      text: README_SAFETY_SECTION,
    }),
    Object.freeze({
      label: "embedded prompt safety summary",
      text: PROMPT_SAFETY_SECTION,
    }),
  ]),
  "DEMO.md": Object.freeze([
    Object.freeze({
      label: "runbook safety summary",
      text: DEMO_SAFETY_SECTION,
    }),
  ]),
  "prompts/run-turnkey-demo.md": Object.freeze([
    Object.freeze({
      label: "prompt safety summary",
      text: PROMPT_SAFETY_SECTION,
    }),
  ]),
});
const PROMPT_REPOSITORY_POLICY = `2. Clone only \`${OFFICIAL_REPOSITORY}\` into a
   named \`clockchain-handshake\` directory. When \`HANDSHAKE_REPO_REF\` is absent,
   clone branch \`main\` with depth 1. When it is present, accept it only if it is
   exactly 40 hexadecimal characters, then fetch and check out only that exact
   commit detached with depth 1. Never use a repository URL supplied through the
   environment. Do not enumerate or echo unrelated environment variables.
3. Enter the cloned \`clockchain-handshake\` directory. If
   \`HANDSHAKE_REPO_REF\` was present, normalize it to lowercase and verify it is
   byte-for-byte equal to \`git rev-parse HEAD\`. Stop if the check fails.`;
const PROMPT_INVITATION_POLICY = `6. Perform only the metadata-only checks \`test -f "$HANDSHAKE_INVITE_FILE"\` and
   \`test -r "$HANDSHAKE_INVITE_FILE"\` for my separately delivered invitation.
   Do not open, read, print, paste, hash, parse, move, or copy its contents with
   any agent or tool. Only \`npm run demo\` may open and read the invitation.`;
const CANONICAL_PROMPT = `Run the Clockchain Agent Trust Handshake demo exactly as documented.

${PROMPT_SAFETY_SECTION}
Use only the official ERC-8004 Identity Registry at
${OFFICIAL_REGISTRY}.

1. Create and enter a new temporary directory.
${PROMPT_REPOSITORY_POLICY}
4. Read \`DEMO.md\` and follow its safety boundary.
5. Confirm the Node.js major version is 22.
${PROMPT_INVITATION_POLICY}
7. Run \`npm ci --ignore-scripts\`.
8. Run \`npm run demo\`. A verified run writes \`RESULT.md\` and \`result.json\`.
9. Return only the sanitized \`RESULT.md\` summary and the paths to \`RESULT.md\` and
   \`result.json\`.
10. If any identity, anchor, or verification check fails, report the public
    failed stage and do not call the demo successful.
`;

const REQUIRED_DOCUMENT_PATTERNS = Object.freeze([
  Object.freeze({
    label: "Clockchain®",
    pattern: /Clockchain®/,
  }),
  Object.freeze({
    label: OFFICIAL_REGISTRY,
    pattern: new RegExp(OFFICIAL_REGISTRY, "i"),
  }),
  Object.freeze({
    label: "npm run demo",
    token: "npm run demo",
  }),
  Object.freeze({
    label: "RESULT.md",
    token: "RESULT.md",
  }),
  Object.freeze({
    label: "result.json",
    token: "result.json",
  }),
]);
const CANONICAL_DOCUMENT_TOKENS = Object.freeze(
  REQUIRED_DOCUMENT_PATTERNS.filter(
    (requirement) => requirement.token !== undefined,
  ),
);

function isPlainRoot(rootDirectory) {
  return (
    typeof rootDirectory === "string" &&
    rootDirectory.length > 0 &&
    !rootDirectory.includes("\0") &&
    isAbsolute(rootDirectory)
  );
}

function containedBy(rootDirectory, target) {
  const fromRoot = relative(rootDirectory, target);
  return !(
    fromRoot === ".." ||
    fromRoot.startsWith("../") ||
    isAbsolute(fromRoot)
  );
}

async function canonicalRoot(rootDirectory) {
  if (!isPlainRoot(rootDirectory)) {
    return null;
  }

  try {
    const canonical = await realpath(rootDirectory);
    return (await lstat(canonical)).isDirectory()
      ? canonical
      : null;
  } catch {
    return null;
  }
}

async function canonicalRegularFile(rootDirectory, path) {
  try {
    const canonical = await realpath(path);
    if (!containedBy(rootDirectory, canonical)) {
      return null;
    }
    return (await lstat(canonical)).isFile()
      ? canonical
      : null;
  } catch {
    return null;
  }
}

function countOccurrences(contents, exact) {
  return tokenOccurrences(contents, exact).length;
}

function canonicalSafetyRemainder(relativePath, contents) {
  const failures = [];
  let remainder = contents;
  for (const { label, text } of
    CANONICAL_SAFETY_SECTIONS[relativePath] ?? []) {
    if (countOccurrences(contents, text) !== 1) {
      failures.push(
        `${relativePath}: canonical ${label} is missing or duplicated.`,
      );
    }
    remainder = remainder.replaceAll(text, "");
  }

  return { failures, remainder };
}

function contextualPresentClaimFailures(
  relativePath,
  contents,
) {
  const failures = [];
  const segments = contents
    .replace(/\r?\n/g, " ")
    .split(CLAIM_BOUNDARY_PATTERN);

  for (const capability of CONTEXTUAL_PRESENT_CAPABILITIES) {
    const escaped = capability.replace(
      /[.*+?^${}()|[\]\\]/g,
      "\\$&",
    );
    const pattern = new RegExp(`\\b${escaped}\\b`, "gi");
    const unsafe = segments.some((segment) =>
      [...segment.matchAll(pattern)].some(
        (match) =>
          !EXPLICIT_LIMITATION_PATTERN.test(
            segment.slice(0, match.index),
          ),
      ),
    );
    if (unsafe) {
      failures.push(
        `${relativePath}: mentions forbidden capability "${capability}" as a present claim.`,
      );
    }
  }

  return failures;
}

function structuredSafetyFailures(relativePath, contents) {
  const { failures, remainder } =
    canonicalSafetyRemainder(relativePath, contents);

  for (const capability of FORBIDDEN_PRESENT_CAPABILITIES) {
    const pattern = new RegExp(
      `\\b${capability.replace("-", "\\-")}\\b`,
      "i",
    );
    if (pattern.test(remainder)) {
      failures.push(
        `${relativePath}: mentions forbidden capability "${capability}" outside its canonical safety section.`,
      );
    }
  }

  if (/\bAgentDash\b/i.test(remainder)) {
    failures.push(
      `${relativePath}: contains "AgentDash" outside its canonical prohibition.`,
    );
  }
  if (/\bmoney\b/i.test(remainder)) {
    failures.push(
      `${relativePath}: contains "Money moves" outside its canonical no-money boundary.`,
    );
  }

  for (const match of remainder.matchAll(
    /\b0x[0-9a-fA-F]{40}\b/g,
  )) {
    if (
      match[0].toLowerCase() !==
      OFFICIAL_REGISTRY.toLowerCase()
    ) {
      failures.push(
        `${relativePath}: references non-official registry address "${match[0]}".`,
      );
    }
  }

  failures.push(
    ...contextualPresentClaimFailures(
      relativePath,
      remainder,
    ),
  );

  return failures;
}

function tokenBoundaryBefore(contents, index) {
  return (
    index === 0 ||
    TOKEN_BOUNDARY_PATTERN.test(contents[index - 1])
  );
}

function tokenBoundaryAfter(contents, index) {
  if (index === contents.length) {
    return true;
  }
  const next = contents[index];
  if (TOKEN_BOUNDARY_PATTERN.test(next)) {
    return true;
  }
  if (next !== "." && next !== ":") {
    return false;
  }
  const afterPunctuation = contents[index + 1];
  return (
    afterPunctuation === undefined ||
    TOKEN_BOUNDARY_PATTERN.test(afterPunctuation)
  );
}

function tokenOccurrences(contents, token) {
  const occurrences = [];
  let fromIndex = 0;
  while (fromIndex <= contents.length - token.length) {
    const index = contents.indexOf(token, fromIndex);
    if (index === -1) {
      break;
    }
    occurrences.push(index);
    fromIndex = index + token.length;
  }
  return occurrences;
}

function hasCanonicalToken(contents, token) {
  return tokenOccurrences(contents, token).some(
    (index) =>
      tokenBoundaryBefore(contents, index) &&
      tokenBoundaryAfter(contents, index + token.length),
  );
}

function extendedToken(contents, index, token) {
  let start = index;
  while (
    start > 0 &&
    TOKEN_EXTENSION_PATTERN.test(contents[start - 1])
  ) {
    start -= 1;
  }

  let end = index + token.length;
  while (
    end < contents.length &&
    TOKEN_EXTENSION_PATTERN.test(contents[end])
  ) {
    end += 1;
  }
  return contents.slice(start, end);
}

function noncanonicalTokenFailures(
  relativePath,
  contents,
) {
  const failures = [];
  for (const { token } of CANONICAL_DOCUMENT_TOKENS) {
    for (const index of tokenOccurrences(contents, token)) {
      if (
        tokenBoundaryBefore(contents, index) &&
        tokenBoundaryAfter(
          contents,
          index + token.length,
        )
      ) {
        continue;
      }
      const extension = extendedToken(
        contents,
        index,
        token,
      );
      failures.push(
        `${relativePath}: contains noncanonical extension "${extension}" of required token "${token}".`,
      );
    }
  }
  return failures;
}

function noncanonicalCommandFailures(
  relativePath,
  contents,
) {
  const failures = [];
  for (const match of contents.matchAll(
    /(?<!`)`([^`\r\n]+)`(?!`)/g,
  )) {
    const command = match[1];
    if (
      command.startsWith("npm run demo") &&
      command !== "npm run demo"
    ) {
      failures.push(
        `${relativePath}: contains noncanonical command "${command}" derived from "npm run demo".`,
      );
    }
  }

  const unfolded = contents.replace(
    /\\\r?\n[ \t]*/g,
    " ",
  );
  for (const match of unfolded.matchAll(
    /\bnpm run demo((?:[ \t]*(?:&&|\|\||[;|<>])|[ \t]+--?[^\s`])[^`\r\n]*)/g,
  )) {
    const command = `npm run demo${match[1]}`.trimEnd();
    failures.push(
      `${relativePath}: contains noncanonical command "${command}" derived from "npm run demo".`,
    );
  }

  return failures;
}

function markdownLinks(contents) {
  return [
    ...[...contents.matchAll(MARKDOWN_LINK_PATTERN)].map(
      (match) => match[1] ?? match[2],
    ),
    ...[
      ...contents.matchAll(
        MARKDOWN_REFERENCE_DEFINITION_PATTERN,
      ),
    ].map((match) => match[1] ?? match[2]),
  ];
}

function localLinkTarget(rootDirectory, documentPath, link) {
  if (
    typeof link !== "string" ||
    link.length === 0 ||
    link.startsWith("#") ||
    EXTERNAL_LINK_PATTERN.test(link)
  ) {
    return null;
  }

  const withoutFragment = link.split(/[?#]/, 1)[0];
  let decoded;
  try {
    decoded = decodeURIComponent(withoutFragment);
  } catch {
    return false;
  }
  if (
    decoded.length === 0 ||
    decoded.includes("\0") ||
    isAbsolute(decoded)
  ) {
    return false;
  }

  const target = resolve(
    rootDirectory,
    dirname(documentPath),
    decoded,
  );
  const fromRoot = relative(rootDirectory, target);
  if (
    fromRoot === ".." ||
    fromRoot.startsWith("../") ||
    isAbsolute(fromRoot)
  ) {
    return false;
  }
  return target;
}

async function linkFailures({
  rootDirectory,
  relativePath,
  contents,
}) {
  const failures = [];
  for (const link of markdownLinks(contents)) {
    const target = localLinkTarget(
      rootDirectory,
      relativePath,
      link,
    );
    if (target === null) {
      continue;
    }
    if (
      target === false ||
      !(await canonicalRegularFile(
        rootDirectory,
        target,
      ))
    ) {
      failures.push(
        `${relativePath}: broken relative link "${link}".`,
      );
    }
  }
  return failures;
}

function markdownLines(contents) {
  const lines = [];
  let start = 0;
  while (start < contents.length) {
    const newline = contents.indexOf("\n", start);
    const end =
      newline === -1 ? contents.length : newline + 1;
    const raw = contents.slice(start, end);
    const body = raw.endsWith("\n")
      ? raw
          .slice(0, -1)
          .replace(/\r$/, "")
      : raw;
    lines.push({ body, end, start });
    start = end;
  }
  return lines;
}

function markdownContainerLine(body) {
  let content = body;
  let blockquoteDepth = 0;

  while (true) {
    const prefix = content.match(/^ {0,3}>[ \t]?/);
    if (!prefix) {
      break;
    }
    content = content.slice(prefix[0].length);
    blockquoteDepth += 1;
  }

  return { blockquoteDepth, content };
}

function fencedBlocks(contents) {
  const lines = markdownLines(contents);
  const blocks = [];

  for (let index = 0; index < lines.length; index += 1) {
    const openingLine = markdownContainerLine(
      lines[index].body,
    );
    const opening = openingLine.content.match(
      /^( {0,3})(`{3,}|~{3,})([^\r\n]*)$/,
    );
    if (!opening) {
      continue;
    }

    const marker = opening[2];
    const markerCharacter = marker[0];
    const info = opening[3].trim();
    if (
      markerCharacter === "`" &&
      info.includes("`")
    ) {
      continue;
    }

    const contentStart = lines[index].end;
    let contentEnd = contents.length;
    let closed = false;
    let closingIndex = lines.length;
    for (
      let candidate = index + 1;
      candidate < lines.length;
      candidate += 1
    ) {
      const candidateLine = markdownContainerLine(
        lines[candidate].body,
      );
      const closing = candidateLine.content.match(
        /^( {0,3})(`+|~+)[ \t]*$/,
      );
      if (
        closing &&
        candidateLine.blockquoteDepth ===
          openingLine.blockquoteDepth &&
        closing[2][0] === markerCharacter &&
        closing[2].length >= marker.length
      ) {
        contentEnd = lines[candidate].start;
        closed = true;
        closingIndex = candidate;
        break;
      }
    }

    blocks.push({
      closed,
      content: contents.slice(contentStart, contentEnd),
      info: info.split(/[ \t]+/, 1)[0],
    });
    index = closed ? closingIndex : lines.length;
  }

  return blocks;
}

export function extractReadmePrompt(readme) {
  if (typeof readme !== "string") {
    return null;
  }
  const prompts = fencedBlocks(readme).filter(
    ({ info }) => info === "text",
  );
  return prompts.length === 1 && prompts[0].closed
    ? prompts[0].content
    : null;
}

function promptContractFailures(prompt) {
  const failures = [];
  if (prompt !== CANONICAL_PROMPT) {
    failures.push(
      "prompts/run-turnkey-demo.md: must match the complete canonical prompt byte-for-byte.",
    );
  }
  if (prompt.includes("HANDSHAKE_REPO_URL")) {
    failures.push(
      "prompts/run-turnkey-demo.md: must not accept a repository URL from the environment.",
    );
  }
  if (!prompt.includes(PROMPT_REPOSITORY_POLICY)) {
    failures.push(
      "prompts/run-turnkey-demo.md: canonical fixed-repository and immutable-ref policy is missing.",
    );
  }
  if (!prompt.includes(PROMPT_INVITATION_POLICY)) {
    failures.push(
      "prompts/run-turnkey-demo.md: canonical metadata-only invitation policy is missing.",
    );
  }

  const policyRemainder = prompt
    .replace(PROMPT_REPOSITORY_POLICY, "")
    .replace(PROMPT_INVITATION_POLICY, "");
  if (
    /\bHANDSHAKE_REPO_REF\b/.test(policyRemainder) ||
    /https:\/\/github\.com\/[^\s`)]+/i.test(
      policyRemainder,
    )
  ) {
    failures.push(
      "prompts/run-turnkey-demo.md: contains repository checkout instructions outside the canonical policy.",
    );
  }
  if (
    /\bHANDSHAKE_INVITE_FILE\b/.test(policyRemainder) ||
    /\binvitation\b/i.test(policyRemainder)
  ) {
    failures.push(
      "prompts/run-turnkey-demo.md: contains invitation handling instructions outside the canonical metadata-only policy.",
    );
  }
  return failures;
}

export async function checkDocumentation({
  rootDirectory = DEFAULT_ROOT_DIRECTORY,
} = {}) {
  const root = await canonicalRoot(rootDirectory);
  if (root === null) {
    return ["documentation root must be an absolute path."];
  }

  const failures = [];
  const documents = new Map();

  for (const relativePath of PUBLIC_DOCUMENTS) {
    const path = await canonicalRegularFile(
      root,
      resolve(root, relativePath),
    );
    try {
      if (path === null) {
        throw new Error("not a regular file");
      }
      documents.set(relativePath, await readFile(path, "utf8"));
    } catch {
      failures.push(
        `${relativePath}: required public document is missing or not a regular file.`,
      );
    }
  }

  for (const relativePath of REQUIRED_REPOSITORY_FILES) {
    if (
      !(await canonicalRegularFile(
        root,
        resolve(root, relativePath),
      ))
    ) {
      failures.push(
        `${relativePath}: required referenced file is missing or not a regular file.`,
      );
    }
  }

  for (const [relativePath, contents] of documents) {
    for (const requirement of REQUIRED_DOCUMENT_PATTERNS) {
      const present =
        requirement.token === undefined
          ? requirement.pattern.test(contents)
          : hasCanonicalToken(
              contents,
              requirement.token,
            );
      if (!present) {
        failures.push(
          `${relativePath}: missing required phrase "${requirement.label}".`,
        );
      }
    }
    failures.push(
      ...structuredSafetyFailures(relativePath, contents),
      ...noncanonicalTokenFailures(relativePath, contents),
      ...noncanonicalCommandFailures(relativePath, contents),
      ...(await linkFailures({
        rootDirectory: root,
        relativePath,
        contents,
      })),
    );

    for (const requiredLink of REQUIRED_LINKS[relativePath] ?? []) {
      if (!markdownLinks(contents).includes(requiredLink)) {
        failures.push(
          `${relativePath}: missing required relative link "${requiredLink}".`,
        );
      }
    }
  }

  const readme = documents.get("README.md");
  const prompt = documents.get("prompts/run-turnkey-demo.md");
  if (prompt !== undefined) {
    failures.push(...promptContractFailures(prompt));
  }
  if (readme !== undefined) {
    const embeddedPrompt = extractReadmePrompt(readme);
    if (embeddedPrompt === null) {
      failures.push(
        "README.md: must contain exactly one fenced text prompt.",
      );
    } else if (
      prompt !== undefined &&
      embeddedPrompt !== prompt
    ) {
      failures.push(
        "README.md: its single text fence must be byte-for-byte identical to prompts/run-turnkey-demo.md.",
      );
    }
  }

  return [...new Set(failures)].sort();
}

export async function main({
  rootDirectory = DEFAULT_ROOT_DIRECTORY,
  stdout = process.stdout,
  stderr = process.stderr,
} = {}) {
  const failures = await checkDocumentation({ rootDirectory });
  if (failures.length > 0) {
    stderr.write(
      `${failures.map((failure) => `docs: ${failure}`).join("\n")}\n`,
    );
    return 1;
  }
  stdout.write(
    `Documentation checks passed (${PUBLIC_DOCUMENTS.length} public documents).\n`,
  );
  return 0;
}

const invokedPath = process.argv[1];
if (
  typeof invokedPath === "string" &&
  import.meta.url === pathToFileURL(invokedPath).href
) {
  process.exitCode = await main();
}
