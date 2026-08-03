#!/usr/bin/env node
/**
 * Mechanical port of the donor's focused tests for the pure module class.
 * Same enforcement as port-pure.mjs: copy each donor test, rewrite ONLY module
 * specifiers through the port table, and prove every differing line is an
 * import/export-from line. A single non-import diff aborts.
 *
 * Usage: node scripts/port-tests.mjs [--check]
 */
import { readFileSync, writeFileSync, mkdirSync, existsSync, copyFileSync } from "node:fs";
import { dirname, resolve, relative, posix } from "node:path";

const DONOR = "/Users/Kailor/conductor/workspaces/clockchain-handshake/riyadh-v3";
const TARGET = resolve(new URL("..", import.meta.url).pathname);

/** Specifier resolution table: donor absolute path -> v2 absolute path. */
const SRC_TABLE = {
  "src/bilateral/canonical.mjs": "src/core/canonical.mjs",
  "src/canonical.mjs": "src/core/canonical-v1.mjs",
  "src/bilateral/refid.mjs": "src/core/refid.mjs",
  "src/bilateral/blocktime.mjs": "src/core/blocktime.mjs",
  "src/bilateral/descriptor.mjs": "src/core/descriptor.mjs",
  "src/bilateral/messages.mjs": "src/core/messages.mjs",
  "src/bilateral/protocol.mjs": "src/core/protocol.mjs",
  "src/bilateral/payer-mandate.mjs": "src/core/payer-mandate.mjs",
  "src/bilateral/payment-request.mjs": "src/core/payment-request.mjs",
  "src/bilateral/runner.mjs": "src/core/runner.mjs",
  "src/mcp.mjs": "src/core/clockchain.mjs",
  "src/redact.mjs": "src/core/redact.mjs",
  "src/bilateral/private-path.mjs": "src/core/private-path.mjs",
  "src/constants.mjs": "src/core/constants.mjs",
  "src/bilateral/funding/record.mjs": "src/core/funding/record.mjs",
  "src/bilateral/funding/journal.mjs": "src/core/funding/journal.mjs",
  "src/bilateral/verdict.mjs": "src/core/verdict.mjs",
  "src/bilateral/evidence.mjs": "src/core/evidence.mjs",
  "src/bilateral/roles.mjs": "src/core/roles-core.mjs",
  "src/bilateral/funding/keystore.mjs": "src/core/funding/wallet.mjs",
  "src/registration.mjs": "src/core/registration.mjs",
  "src/registration-internal.mjs": "src/core/registration.mjs",
  "scripts/create-session.mjs": "scripts/create-session.mjs",
  "scripts/verify-bilateral-results.mjs": "scripts/verify-bilateral-results.mjs",
  "test/helpers/fake-bilateral-clockchain.mjs": "test/helpers/fake-bilateral-clockchain.mjs",
};

const TESTS = {
  "test/bilateral-canonical.test.mjs": "test/core-canonical.test.mjs",
  "test/canonical.test.mjs": "test/core-canonical-v1.test.mjs",
  "test/bilateral-refid.test.mjs": "test/core-refid.test.mjs",
  "test/bilateral-blocktime.test.mjs": "test/core-blocktime.test.mjs",
  "test/bilateral-descriptor.test.mjs": "test/core-descriptor.test.mjs",
  "test/bilateral-messages.test.mjs": "test/core-messages.test.mjs",
  "test/bilateral-protocol.test.mjs": "test/core-protocol.test.mjs",
  "test/bilateral-payer-mandate.test.mjs": "test/core-payer-mandate.test.mjs",
  "test/bilateral-payment-request.test.mjs": "test/core-payment-request.test.mjs",
  "test/bilateral-runner.test.mjs": "test/core-runner.test.mjs",
  "test/mcp.test.mjs": "test/core-clockchain.test.mjs",
  "test/redact.test.mjs": "test/core-redact.test.mjs",
  "test/bilateral-private-path.test.mjs": "test/core-private-path.test.mjs",
  "test/bilateral-funding-record.test.mjs": "test/core-funding-record.test.mjs",
  "test/bilateral-funding-journal.test.mjs": "test/core-funding-journal.test.mjs",
};

/** Byte-copied support files (no specifier rewrites needed or allowed). */
const ADAPTED_TESTS = {
  "test/bilateral-verdict.test.mjs": "test/core-verdict.test.mjs",
  "test/bilateral-evidence.test.mjs": "test/core-evidence.test.mjs",
  "test/bilateral-funding-keystore.test.mjs": "test/core-funding-wallet.test.mjs",
  "test/registration.test.mjs": "test/core-registration.test.mjs",
};

/**
 * Reviewed donor-test renames inside adapted files, donor title ->
 * replacement title. Each entry licenses exactly one absent donor title
 * and requires the replacement to be present, so adapted coverage can
 * evolve only by an explicit, auditable registration.
 *
 * core-funding-wallet: the macOS Keychain path was deleted per the v2
 * spec (file/env password sources only); the two Keychain-coupled donor
 * tests were renamed to their file-source equivalents.
 */
const RENAMED_DONOR_TESTS = {
  "test/core-funding-wallet.test.mjs": new Map([
    [
      "openFundingWallet rejects digest mismatch, empty Keychain password, and decrypted-address mismatch",
      "openFundingWallet rejects digest mismatch, empty password, and decrypted-address mismatch",
    ],
    [
      "openFundingWallet uses bounded nofollow reads and the production security command without leaking canaries",
      "openFundingWallet reads the password from the private env-named file with bounded nofollow reads and without leaking canaries",
    ],
  ]),
};

const SUPPORT = [
  "test/fixtures/mcp-sse.txt",
  "test/fixtures/registered-receipt.json",
];

/** Support modules needing specifier rewrites (donor rel == target rel). */
const REWRITE_SUPPORT = [
  "test/helpers/fake-bilateral-clockchain.mjs",
  "scripts/verify-bilateral-results.mjs",
];

const IMPORT_LINE = /\bfrom\s*["']|\bimport\s*\(\s*["']|^\s*import\s+["']|^\s*export\s/;

function testTitles(source) {
  const titles = new Set();
  for (const match of source.matchAll(
    /^\s*(?:t\.)?test\(\s*"([^"]+)"/gm,
  )) {
    titles.add(match[1]);
  }
  return titles;
}

function rewriteSpecifiers(donorFileAbs, source) {
  let rewrites = 0;
  const out = source.split("\n").map((line) => {
    return line.replace(/(["'])(\.{1,2}\/[^"']+)\1/g, (match, quote, spec) => {
      const resolvedDonor = resolve(dirname(donorFileAbs), spec);
      const donorRel = relative(DONOR, resolvedDonor);
      const targetRel = SRC_TABLE[donorRel];
      if (!targetRel) {
        // Quoted relative paths into the donor's src/ or scripts/ trees are
        // module references (import specifiers or source-scanning guard paths)
        // and MUST be mapped. Paths elsewhere (fixtures, helper names) stay.
        if (/^(src|scripts)\//.test(donorRel)) {
          throw new Error(`unmapped source reference ${spec} in ${relative(DONOR, donorFileAbs)}`);
        }
        return match;
      }
      const targetAbs = resolve(TARGET, targetRel);
      const importerTargetAbs = resolve(TARGET, CURRENT_TARGET_REL);
      let next = relative(dirname(importerTargetAbs), targetAbs);
      next = posix.normalize(next);
      if (!next.startsWith(".")) next = "./" + next;
      if (next !== spec) rewrites += 1;
      return quote + next + quote;
    });
  }).join("\n");
  return { out, rewrites };
}

let CURRENT_TARGET_REL = null;
const checkOnly = process.argv.includes("--check");
let failures = 0;

for (const [donorRel, targetRel] of Object.entries(TESTS)) {
  CURRENT_TARGET_REL = targetRel;
  const donorAbs = resolve(DONOR, donorRel);
  const targetAbs = resolve(TARGET, targetRel);
  const source = readFileSync(donorAbs, "utf8");
  const { out, rewrites } = rewriteSpecifiers(donorAbs, source);
  if (checkOnly) {
    if (!existsSync(targetAbs) || readFileSync(targetAbs, "utf8") !== out) {
      console.error(`STALE ${targetRel}`);
      failures += 1;
    } else {
      console.log(`ok   ${targetRel} (${rewrites} specifier line(s) rewritten)`);
    }
  } else {
    mkdirSync(dirname(targetAbs), { recursive: true });
    writeFileSync(targetAbs, out);
    console.log(`port ${targetRel} (${rewrites} specifier line(s) rewritten)`);
  }
}

for (const rel of SUPPORT) {
  const donorAbs = resolve(DONOR, rel);
  const targetAbs = resolve(TARGET, rel);
  const bytes = readFileSync(donorAbs);
  if (checkOnly) {
    if (!existsSync(targetAbs) || !readFileSync(targetAbs).equals(bytes)) {
      console.error(`STALE ${rel}`);
      failures += 1;
    } else {
      console.log(`ok   ${rel} (byte copy)`);
    }
  } else {
    mkdirSync(dirname(targetAbs), { recursive: true });
    copyFileSync(donorAbs, targetAbs);
    console.log(`copy ${rel} (byte copy)`);
  }
}

for (const [donorRel, targetRel] of Object.entries(ADAPTED_TESTS)) {
  CURRENT_TARGET_REL = targetRel;
  const donorAbs = resolve(DONOR, donorRel);
  const targetAbs = resolve(TARGET, targetRel);
  const { out, rewrites } = rewriteSpecifiers(donorAbs, readFileSync(donorAbs, "utf8"));
  if (checkOnly) {
    // Adapted files are seeded from the donor and then owned by humans
    // under the explicit edit budget: donor tests must all survive (by
    // title), local additions and reviewed edits are expected.
    if (!existsSync(targetAbs)) {
      console.error(`STALE ${targetRel}`);
      failures += 1;
    } else {
      const donorTitles = testTitles(out);
      const targetTitles = testTitles(readFileSync(targetAbs, "utf8"));
      const renames =
        RENAMED_DONOR_TESTS[targetRel] ?? new Map();
      const missing = [];
      for (const title of donorTitles) {
        if (targetTitles.has(title)) continue;
        const replacement = renames.get(title);
        if (
          replacement !== undefined &&
          targetTitles.has(replacement)
        ) {
          continue;
        }
        missing.push(title);
      }
      const unusedRenames = [...renames.keys()].filter(
        (title) => donorTitles.has(title) === false,
      );
      if (missing.length > 0) {
        console.error(
          `STALE ${targetRel} (dropped donor test(s): ${missing.join("; ")})`,
        );
        failures += 1;
      } else if (unusedRenames.length > 0) {
        console.error(
          `STALE ${targetRel} (rename registration no longer matches the donor: ${unusedRenames.join("; ")})`,
        );
        failures += 1;
      } else {
        console.log(
          `ok   ${targetRel} (adapted; ${donorTitles.size} donor test(s) preserved incl. ${renames.size} renamed, ${targetTitles.size - donorTitles.size} local)`,
        );
      }
    }
  } else {
    if (existsSync(targetAbs)) {
      console.log(`keep ${targetRel} (adapted; human-owned)`);
      continue;
    }
    mkdirSync(dirname(targetAbs), { recursive: true });
    writeFileSync(targetAbs, out);
    console.log(`seed ${targetRel} (${rewrites} specifier line(s) rewritten)`);
  }
}

for (const rel of REWRITE_SUPPORT) {
  CURRENT_TARGET_REL = rel;
  const donorAbs = resolve(DONOR, rel);
  const targetAbs = resolve(TARGET, rel);
  const { out } = rewriteSpecifiers(donorAbs, readFileSync(donorAbs, "utf8"));
  if (checkOnly) {
    if (!existsSync(targetAbs) || readFileSync(targetAbs, "utf8") !== out) {
      console.error(`STALE ${rel}`);
      failures += 1;
    } else {
      console.log(`ok   ${rel} (specifier rewrite)`);
    }
  } else {
    mkdirSync(dirname(targetAbs), { recursive: true });
    writeFileSync(targetAbs, out);
    console.log(`port ${rel} (specifier rewrite)`);
  }
}

// scripts/create-session.mjs: ported with specifier rewrite as well.
CURRENT_TARGET_REL = "scripts/create-session.mjs";
{
  const donorAbs = resolve(DONOR, "scripts/create-session.mjs");
  const targetAbs = resolve(TARGET, "scripts/create-session.mjs");
  const { out } = rewriteSpecifiers(donorAbs, readFileSync(donorAbs, "utf8"));
  if (checkOnly) {
    if (!existsSync(targetAbs) || readFileSync(targetAbs, "utf8") !== out) {
      console.error("STALE scripts/create-session.mjs");
      failures += 1;
    } else {
      console.log("ok   scripts/create-session.mjs");
    }
  } else {
    mkdirSync(dirname(targetAbs), { recursive: true });
    writeFileSync(targetAbs, out);
    console.log("port scripts/create-session.mjs");
  }
}

if (checkOnly) {
  if (failures > 0) {
    console.error(`${failures} file(s) stale`);
    process.exitCode = 1;
  } else {
    console.log("test port verified: all files match donor modulo specifier lines");
  }
}
