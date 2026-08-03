#!/usr/bin/env node
/**
 * Byte-faithful pure port from the riyadh-v3 donor.
 *
 * Plan rule (port classification, "Pure port"): byte-faithful, import paths only.
 * Any behavioral edit is a plan deviation. This script enforces that mechanically:
 * it copies each donor file, rewrites ONLY module specifiers (resolved through the
 * port table, never by hand-written string rules), and then proves that every
 * differing line is an import/export-from line. A single non-import diff aborts.
 *
 * Usage: node scripts/port-pure.mjs [--check]
 *   --check  verify already-ported files still match the donor (no writes)
 */
import { readFileSync, writeFileSync, mkdirSync, existsSync } from "node:fs";
import { dirname, resolve, relative, posix } from "node:path";

const DONOR = "/Users/Kailor/conductor/workspaces/clockchain-handshake/riyadh-v3";
const TARGET = resolve(new URL("..", import.meta.url).pathname);

/** Full port table: donor path -> target path. Includes adapted modules so that
 *  specifier resolution works, but only PURE entries are emitted by this script. */
const TABLE = {
  // --- pure ---
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
  // --- adapted (resolution targets only; ported by hand under edit budgets) ---
  "src/bilateral/verdict.mjs": "src/core/verdict.mjs",
  "src/bilateral/evidence.mjs": "src/core/evidence.mjs",
  "src/bilateral/roles.mjs": "src/core/roles-core.mjs",
  "src/bilateral/funding/keystore.mjs": "src/core/funding/wallet.mjs",
  "src/registration.mjs": "src/core/registration.mjs",
  "src/registration-internal.mjs": "src/core/registration.mjs", // merged
};

const PURE = [
  "src/bilateral/canonical.mjs",
  "src/canonical.mjs",
  "src/bilateral/refid.mjs",
  "src/bilateral/blocktime.mjs",
  "src/bilateral/descriptor.mjs",
  "src/bilateral/messages.mjs",
  "src/bilateral/protocol.mjs",
  "src/bilateral/payer-mandate.mjs",
  "src/bilateral/payment-request.mjs",
  "src/bilateral/runner.mjs",
  "src/mcp.mjs",
  "src/redact.mjs",
  "src/bilateral/private-path.mjs",
  "src/constants.mjs",
  "src/bilateral/funding/record.mjs",
  "src/bilateral/funding/journal.mjs",
];

/** A line that carries a module specifier (import, export-from, dynamic import). */
const SPECIFIER_LINE = /(?:^|[\s({,])(?:import|export)\b|from\s*["']|import\s*\(/;

function rewriteSpecifiers(donorRelPath, source) {
  const targetRelPath = TABLE[donorRelPath];
  const donorDir = dirname(resolve(DONOR, donorRelPath));
  const targetDir = dirname(resolve(TARGET, targetRelPath));
  const unresolved = [];

  const out = source.replace(
    /(["'])(\.[^"']*?)\1/g,
    (whole, quote, spec) => {
      // Only rewrite specifiers that resolve to a donor module in the table.
      const donorTargetAbs = resolve(donorDir, spec);
      const donorTargetRel = relative(DONOR, donorTargetAbs);
      const mapped = TABLE[donorTargetRel];
      if (!mapped) {
        if (spec.endsWith(".mjs")) unresolved.push(`${spec} -> ${donorTargetRel}`);
        return whole; // not a ported module (e.g. a data path string) — leave alone
      }
      let next = posix.relative(
        targetDir.split("/").join(posix.sep),
        resolve(TARGET, mapped).split("/").join(posix.sep),
      );
      if (!next.startsWith(".")) next = `./${next}`;
      return `${quote}${next}${quote}`;
    },
  );
  return { out, unresolved };
}

/** Prove the port is byte-faithful: every differing line must carry a specifier. */
function assertOnlySpecifierLinesChanged(donorRelPath, before, after) {
  const a = before.split("\n");
  const b = after.split("\n");
  const problems = [];
  if (a.length !== b.length) {
    problems.push(`line count changed: ${a.length} -> ${b.length}`);
  }
  for (let i = 0; i < Math.max(a.length, b.length); i += 1) {
    if (a[i] === b[i]) continue;
    if (!SPECIFIER_LINE.test(a[i] ?? "") && !SPECIFIER_LINE.test(b[i] ?? "")) {
      problems.push(`line ${i + 1} changed but carries no module specifier:\n    - ${a[i]}\n    + ${b[i]}`);
    }
  }
  return problems;
}

const checkOnly = process.argv.includes("--check");
let changedLines = 0;
let failures = 0;

for (const donorRelPath of PURE) {
  const targetRelPath = TABLE[donorRelPath];
  const before = readFileSync(resolve(DONOR, donorRelPath), "utf8");
  const { out, unresolved } = rewriteSpecifiers(donorRelPath, before);

  const problems = assertOnlySpecifierLinesChanged(donorRelPath, before, out);
  for (const u of unresolved) {
    problems.push(`unmapped .mjs specifier: ${u}`);
  }

  const diffCount = before.split("\n").filter((l, i) => l !== out.split("\n")[i]).length;
  changedLines += diffCount;

  if (problems.length) {
    failures += 1;
    console.error(`FAIL ${donorRelPath} -> ${targetRelPath}`);
    for (const p of problems) console.error(`  ${p}`);
    continue;
  }

  const abs = resolve(TARGET, targetRelPath);
  if (checkOnly) {
    if (!existsSync(abs)) {
      failures += 1;
      console.error(`FAIL ${targetRelPath}: missing (run without --check to port)`);
    } else if (readFileSync(abs, "utf8") !== out) {
      failures += 1;
      console.error(`FAIL ${targetRelPath}: drifted from donor (pure ports must stay byte-faithful)`);
    } else {
      console.log(`ok   ${targetRelPath} (${diffCount} specifier line(s) rewritten)`);
    }
  } else {
    mkdirSync(dirname(abs), { recursive: true });
    writeFileSync(abs, out);
    console.log(`port ${donorRelPath} -> ${targetRelPath} (${diffCount} specifier line(s) rewritten)`);
  }
}

console.log(
  `\n${checkOnly ? "checked" : "ported"} ${PURE.length} pure modules; ` +
    `${changedLines} total line(s) differ from donor, all specifier lines.`,
);
if (failures) {
  console.error(`\n${failures} module(s) FAILED the byte-faithful check.`);
  process.exit(1);
}
