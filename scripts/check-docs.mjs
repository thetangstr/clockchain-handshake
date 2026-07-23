#!/usr/bin/env node

import { lstat, readFile } from "node:fs/promises";
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
const FORBIDDEN_PRESENT_CAPABILITIES = Object.freeze([
  "court-grade",
  "trustless",
  "mainnet",
  "consensus-secure",
]);
const NEGATION_PATTERN =
  /\b(?:no|never|without|neither|nor|cannot|can't|doesn't|isn't|aren't|(?:does|do|is|are|was|were|will|can|must)\s+not(?!\s+only)|not(?!\s+only))\b/i;
const CLAUSE_BOUNDARY_PATTERN =
  /(?<=[.!?])\s+|[;:]|,\s*(?=which\b)|\b(?:but|yet|however|although|though|while|whereas|and|because|since|if|unless)\b|\bor(?=\s+(?:does|do|is|are|was|were|will|can|must|has|have|it|this|that|the|Clockchain)\b)/gi;
const TOKEN_BOUNDARY_PATTERN =
  /[\s`"'()[\]{}<>,;!?/]/;
const TOKEN_EXTENSION_PATTERN =
  /[a-z0-9_.:/-]/i;
const EXTERNAL_LINK_PATTERN =
  /^(?:[a-z][a-z+.-]*:|\/\/)/i;
const MARKDOWN_LINK_PATTERN =
  /!?\[[^\]]*]\(\s*(?:<([^>]+)>|([^\s)]+))(?:\s+["'][^"']*["'])?\s*\)/g;
const DEFAULT_ROOT_DIRECTORY = resolve(
  dirname(fileURLToPath(import.meta.url)),
  "..",
);

const REQUIRED_DOCUMENT_PATTERNS = Object.freeze([
  Object.freeze({
    label: "Clockchain®",
    pattern: /Clockchain®/,
  }),
  Object.freeze({
    label: "single-validator testnet",
    pattern: /single-validator testnet/i,
  }),
  Object.freeze({
    label: "No money moves",
    pattern: /\bno money moves\b/i,
  }),
  Object.freeze({
    label: "AgentDash prohibition",
    pattern:
      /(?:\bdo not\b|\bnever\b|\bno\b)[^\n.!?]{0,80}\bAgentDash\b|\bAgentDash\b[^\n.!?]{0,80}(?:\bis not\b|\bnot required\b)/i,
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

async function regularFile(path) {
  try {
    return (await lstat(path)).isFile();
  } catch {
    return false;
  }
}

function clauseSegments(contents) {
  return contents
    .replace(/\r?\n/g, " ")
    .split(CLAUSE_BOUNDARY_PATTERN)
    .map((segment) => segment.trim())
    .filter(Boolean);
}

function forbiddenCapabilityFailures(
  relativePath,
  contents,
) {
  const failures = [];
  const segments = clauseSegments(contents);
  for (const capability of FORBIDDEN_PRESENT_CAPABILITIES) {
    const pattern = new RegExp(
      `\\b${capability.replace("-", "\\-")}\\b`,
      "i",
    );
    const unsafe = segments.some(
      (segment) =>
        pattern.test(segment) &&
        !NEGATION_PATTERN.test(segment),
    );
    if (unsafe) {
      failures.push(
        `${relativePath}: presents forbidden capability "${capability}" without an explicit negation.`,
      );
    }
  }
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

function markdownLinks(contents) {
  return [...contents.matchAll(MARKDOWN_LINK_PATTERN)].map(
    (match) => match[1] ?? match[2],
  );
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
    if (target === false || !(await regularFile(target))) {
      failures.push(
        `${relativePath}: broken relative link "${link}".`,
      );
    }
  }
  return failures;
}

export function extractReadmePrompt(readme) {
  if (typeof readme !== "string") {
    return null;
  }
  const fences = [
    ...readme.matchAll(
      /^```text[ \t]*\r?\n([\s\S]*?)^```[ \t]*$/gm,
    ),
  ];
  return fences.length === 1 ? fences[0][1] : null;
}

export async function checkDocumentation({
  rootDirectory = DEFAULT_ROOT_DIRECTORY,
} = {}) {
  if (!isPlainRoot(rootDirectory)) {
    return ["documentation root must be an absolute path."];
  }

  const failures = [];
  const documents = new Map();

  for (const relativePath of PUBLIC_DOCUMENTS) {
    const path = resolve(rootDirectory, relativePath);
    try {
      const metadata = await lstat(path);
      if (!metadata.isFile()) {
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
      !(await regularFile(resolve(rootDirectory, relativePath)))
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
      ...forbiddenCapabilityFailures(relativePath, contents),
      ...noncanonicalTokenFailures(relativePath, contents),
      ...(await linkFailures({
        rootDirectory,
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
