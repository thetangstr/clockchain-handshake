// Reference-id scheme for clockchain.bilateral-authorization/v1 (design
// section 4.7). Charset strictly lowercase digits, lowercase letters and
// ":" as the sole separator, at most 120 bytes — because the gateway
// demonstrably normalizes sibling fields, and only ":" has been observed
// surviving in stored ids. The exact pattern lives once, in code, below.
// Every key is a pure function of descriptor-pinned inputs: no I/O, no
// randomness, no timestamps, no server-assigned values. The probe nonce
// is an INPUT here; whoever needs randomness generates it elsewhere.

export const REFID_PATTERN = /^[0-9a-z:]{1,120}$/;

export const SESSION_SLOTS = Object.freeze([
  "proposal",
  "acceptance",
  "acknowledgment",
]);

export const PROBE_ROLES = Object.freeze(["payer", "payee"]);

const NAMESPACE = "cbv1";
const D_SESSION_PATTERN = /^[0-9a-f]{64}$/;
const PROBE_NONCE_PATTERN = /^[0-9a-f]{32}$/;

export class ReferenceIdError extends Error {
  constructor(message, code) {
    super(message);
    this.name = new.target.name;
    this.code = code;
  }
}

export class ReferenceIdFormatError extends ReferenceIdError {
  constructor(message) {
    super(message, "REFERENCE_ID_FORMAT");
  }
}

export class ReferenceIdMismatchError extends ReferenceIdError {
  constructor() {
    // Neither id is echoed: a reference id embeds the session digest and
    // must never leak through error channels.
    super(
      "Reference id is not byte-equal to the derived key.",
      "REFERENCE_ID_MISMATCH",
    );
  }
}

export function assertReferenceId(value) {
  if (typeof value !== "string" || !REFID_PATTERN.test(value)) {
    throw new ReferenceIdFormatError(
      "Reference id must match ^[0-9a-z:]{1,120}$.",
    );
  }
}

export function sessionKey(dSessionHex, slot) {
  if (
    typeof dSessionHex !== "string" ||
    !D_SESSION_PATTERN.test(dSessionHex)
  ) {
    throw new ReferenceIdFormatError(
      "Session digest must be exactly 64 lowercase hex characters.",
    );
  }

  if (!SESSION_SLOTS.includes(slot)) {
    throw new ReferenceIdFormatError(
      "Slot must be proposal, acceptance, or acknowledgment.",
    );
  }

  const key = `${NAMESPACE}:${dSessionHex}:${slot}`;
  assertReferenceId(key);
  return key;
}

export function probeKey(nonce32Hex, role) {
  if (
    typeof nonce32Hex !== "string" ||
    !PROBE_NONCE_PATTERN.test(nonce32Hex)
  ) {
    throw new ReferenceIdFormatError(
      "Probe nonce must be exactly 32 lowercase hex characters.",
    );
  }

  if (!PROBE_ROLES.includes(role)) {
    throw new ReferenceIdFormatError("Role must be payer or payee.");
  }

  const key = `${NAMESPACE}:probe:${nonce32Hex}:${role}`;
  assertReferenceId(key);
  return key;
}

export function assertByteEqualReferenceId(actual, expected) {
  assertReferenceId(expected);

  if (typeof actual !== "string") {
    throw new ReferenceIdFormatError("Reference id must be a string.");
  }

  // The charset is pure ASCII, so string equality against a
  // pattern-valid expected IS byte equality. No normalization, no
  // trimming, no case folding may ever run before this comparison; a
  // passing actual is therefore itself pattern-valid by identity.
  if (actual !== expected) {
    throw new ReferenceIdMismatchError();
  }
}
