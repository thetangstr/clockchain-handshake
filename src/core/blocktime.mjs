// The authoritative clock for clockchain.bilateral-authorization/v1 is
// get_block(blockHeight).blockTime, re-fetched by height, and nothing else
// (design section 5.2). This module accepts EXACTLY that wire shape —
// RFC3339 with a 1-9 digit fraction and a literal Z — and rejects every
// other observed gateway format. The built-in date parser is banned
// because it reads "24-07-2026_19:27:50:981" as NaN (silently disarming
// every deadline comparison) and "07-08-2026" as MM-DD-YYYY midnight in
// the HOST'S LOCAL ZONE (silently wrong day, different instant per
// machine). Everything here is pure epoch-millisecond arithmetic on
// injected values; no wall clock, no host time zone, no global Date
// object anywhere — a companion test scans this source to enforce it.

export const BLOCK_TIME_PATTERN =
  /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})\.(\d{1,9})Z$/;

// Descriptor expirySeconds "600", measured in block time (section 5.3).
export const EXPIRY_WINDOW_MS = 600000;

// Live-path upper-bound slack: blockTime is a LOWER bound on the true
// write time, so a naive blockTime(h) <= deadlineMs is optimistic by up
// to one block (~1.024 s at the measured cadence). The live path sides
// up by a pinned 1100 ms; the aggregate verifier uses blockTime(h + 1)
// instead when that block exists (section 5.3).
export const LIVE_UPPER_BOUND_SLACK_MS = 1100;

const MS_PER_SECOND = 1000;
const MS_PER_MINUTE = 60 * MS_PER_SECOND;
const MS_PER_HOUR = 60 * MS_PER_MINUTE;
const MS_PER_DAY = 24 * MS_PER_HOUR;

export class BlockTimeParseError extends Error {
  constructor() {
    // The offending input is deliberately not echoed: block times travel
    // next to material that must never leak through error channels.
    super("Block time is not a canonical RFC3339 nanosecond instant.");
    this.name = "BlockTimeParseError";
    this.code = "BLOCK_TIME_UNPARSEABLE";
  }
}

function isLeapYear(year) {
  return (year % 4 === 0 && year % 100 !== 0) || year % 400 === 0;
}

const DAYS_IN_MONTH = Object.freeze([
  31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31,
]);

function daysInMonth(year, month) {
  if (month === 2 && isLeapYear(year)) {
    return 29;
  }

  return DAYS_IN_MONTH[month - 1];
}

// Days from 1970-01-01 for a valid proleptic-Gregorian civil date
// (Howard Hinnant's days_from_civil, exact over the whole 4-digit range).
function epochDays(year, month, day) {
  const shiftedYear = month <= 2 ? year - 1 : year;
  const era = Math.floor(shiftedYear / 400);
  const yearOfEra = shiftedYear - era * 400;
  const dayOfYear =
    Math.trunc((153 * (month + (month > 2 ? -3 : 9)) + 2) / 5) + day - 1;
  const dayOfEra =
    yearOfEra * 365 +
    Math.trunc(yearOfEra / 4) -
    Math.trunc(yearOfEra / 100) +
    dayOfYear;
  return era * 146097 + dayOfEra - 719468;
}

export function parseBlockTime(value) {
  if (typeof value !== "string") {
    throw new BlockTimeParseError();
  }

  const match = BLOCK_TIME_PATTERN.exec(value);

  if (match === null) {
    throw new BlockTimeParseError();
  }

  const year = Number(match[1]);
  const month = Number(match[2]);
  const day = Number(match[3]);
  const hour = Number(match[4]);
  const minute = Number(match[5]);
  const second = Number(match[6]);

  if (
    month < 1 ||
    month > 12 ||
    day < 1 ||
    day > daysInMonth(year, month) ||
    hour > 23 ||
    minute > 59 ||
    second > 59
  ) {
    throw new BlockTimeParseError();
  }

  // Truncate the fraction toward zero to milliseconds: take the first
  // three digits, right-padded with zeros. Never round.
  const milliseconds = Number(match[7].padEnd(3, "0").slice(0, 3));

  return (
    epochDays(year, month, day) * MS_PER_DAY +
    hour * MS_PER_HOUR +
    minute * MS_PER_MINUTE +
    second * MS_PER_SECOND +
    milliseconds
  );
}

function assertEpochMs(value) {
  if (!Number.isSafeInteger(value) || value < 0) {
    throw new TypeError(
      "Block-time milliseconds must be a nonnegative safe integer.",
    );
  }
}

export function deadlineMs(proposalBlockTimeMs) {
  assertEpochMs(proposalBlockTimeMs);
  return proposalBlockTimeMs + EXPIRY_WINDOW_MS;
}

export function liveUpperBoundMs(blockTimeMs) {
  assertEpochMs(blockTimeMs);
  return blockTimeMs + LIVE_UPPER_BOUND_SLACK_MS;
}

export function verifierUpperBoundMs(nextBlockTimeMs) {
  // upperBound(h) = blockTime(h + 1): the caller passes the NEXT block's
  // parsed time verbatim. The identity is kept as a named function so the
  // siding choice is pinned in one place and testable.
  assertEpochMs(nextBlockTimeMs);
  return nextBlockTimeMs;
}

export function isWithinDeadline(upperBoundMs, deadlineMsValue) {
  assertEpochMs(upperBoundMs);
  assertEpochMs(deadlineMsValue);
  // Section 5.3: "Require upperBound(h) <= deadlineMs". All three
  // transitions must anchor AT or before the deadline — exactly-at
  // passes, one millisecond past fails, and there is no grace period.
  return upperBoundMs <= deadlineMsValue;
}
