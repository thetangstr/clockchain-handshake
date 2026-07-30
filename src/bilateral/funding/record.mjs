export const FUNDING_RECORD_SCHEMA =
  "clockchain.bilateral-funding-addresses/v1";
export const PARTICIPANT_MINIMUM_WEI = 5_000_000_000_000_000n;
export const PARTICIPANT_TARGET_WEI = 10_000_000_000_000_000n;
export const PARTICIPANT_MAXIMUM_WEI = 20_000_000_000_000_000n;

const FUNDING_RECORD_KEYS = Object.freeze([
  "addresses",
  "paymentMoved",
  "participants",
  "schema",
]);
const PARTICIPANT_FACT_KEYS = Object.freeze([
  "address",
  "balanceWei",
  "nonce",
]);
const RECORDED_PARTICIPANT_KEYS = Object.freeze([
  "address",
  "balanceWei",
  "nonce",
]);
const PLAN_INPUT_KEYS = Object.freeze([
  "feePerTransferWei",
  "fundingBalanceWei",
  "fundingNonce",
  "participantFacts",
  "record",
]);
const ADDRESS_PATTERN = /^0x[0-9a-f]{40}$/;
const ZERO_ADDRESS = "0x0000000000000000000000000000000000000000";

export class BilateralFundingError extends Error {
  constructor(code = "BILATERAL_FUNDING_INVALID") {
    super("Bilateral funding failed safely.");
    this.name = "BilateralFundingError";
    this.code = code;
  }
}

function fail(code) {
  throw new BilateralFundingError(code);
}

function guarded(code, operation) {
  try {
    return operation();
  } catch (error) {
    if (error instanceof BilateralFundingError) throw error;
    fail(code);
  }
}

function snapshotExactDataObject(value, keys, code) {
  if (value === null || typeof value !== "object") fail(code);
  const prototype = guarded(code, () => Object.getPrototypeOf(value));
  if (prototype !== Object.prototype && prototype !== null) fail(code);
  const ownKeys = guarded(code, () => Reflect.ownKeys(value));
  if (
    ownKeys.length !== keys.length ||
    !keys.every((key) => ownKeys.includes(key))
  ) {
    fail(code);
  }
  const snapshot = {};
  for (const key of keys) {
    const descriptor = guarded(code, () =>
      Object.getOwnPropertyDescriptor(value, key),
    );
    if (
      !descriptor ||
      !descriptor.enumerable ||
      !Object.hasOwn(descriptor, "value")
    ) {
      fail(code);
    }
    snapshot[key] = descriptor.value;
  }
  return Object.freeze(snapshot);
}

function validateAddress(value, seen) {
  if (
    typeof value !== "string" ||
    !ADDRESS_PATTERN.test(value) ||
    value === ZERO_ADDRESS ||
    seen.has(value)
  ) {
    fail("BILATERAL_FUNDING_INVALID_RECORD");
  }
  seen.add(value);
  return value;
}

function snapshotDenseDataArray(value, length, code) {
  if (
    !guarded(code, () => Array.isArray(value)) ||
    guarded(code, () => Object.getPrototypeOf(value)) !== Array.prototype
  ) {
    fail(code);
  }
  const lengthDescriptor = guarded(code, () =>
    Object.getOwnPropertyDescriptor(value, "length"),
  );
  if (
    !lengthDescriptor ||
    !Object.hasOwn(lengthDescriptor, "value") ||
    lengthDescriptor.value !== length
  ) {
    fail(code);
  }
  const arrayKeys = guarded(code, () => Reflect.ownKeys(value));
  const indexPattern = new RegExp(`^(?:${Array.from(
    { length },
    (_, index) => index,
  ).join("|")})$`);
  if (
    arrayKeys.length !== length + 1 ||
    arrayKeys.some(
      (key) =>
        key !== "length" &&
        (typeof key !== "string" || !indexPattern.test(key)),
    )
  ) {
    fail(code);
  }
  const copy = [];
  for (let index = 0; index < length; index += 1) {
    const descriptor = guarded(code, () =>
      Object.getOwnPropertyDescriptor(value, String(index)),
    );
    if (
      !descriptor ||
      !descriptor.enumerable ||
      !Object.hasOwn(descriptor, "value")
    ) {
      fail(code);
    }
    copy.push(descriptor.value);
  }
  return Object.freeze(copy);
}

function requireBigint(value, code) {
  if (typeof value !== "bigint" || value < 0n) fail(code);
  return value;
}

function validateRecordedParticipants(value, addresses) {
  const participantData = snapshotDenseDataArray(
    value,
    4,
    "BILATERAL_FUNDING_INVALID_RECORD",
  );

  const participants = [];
  for (let index = 0; index < participantData.length; index += 1) {
    const participant = snapshotExactDataObject(
      participantData[index],
      RECORDED_PARTICIPANT_KEYS,
      "BILATERAL_FUNDING_INVALID_RECORD",
    );
    if (
      participant.address !== addresses[index] ||
      participant.balanceWei !== "0" ||
      participant.nonce !== "0"
    ) {
      fail("BILATERAL_FUNDING_INVALID_RECORD");
    }
    participants.push(Object.freeze({
      address: participant.address,
      balanceWei: "0",
      nonce: "0",
    }));
  }
  return Object.freeze(participants);
}

export function validateFundingRecord(value) {
  const snapshot = snapshotExactDataObject(
    value,
    FUNDING_RECORD_KEYS,
    "BILATERAL_FUNDING_INVALID_RECORD",
  );
  if (
    snapshot.schema !== FUNDING_RECORD_SCHEMA ||
    snapshot.paymentMoved !== false
  ) {
    fail("BILATERAL_FUNDING_INVALID_RECORD");
  }
  const addressData = snapshotDenseDataArray(
    snapshot.addresses,
    4,
    "BILATERAL_FUNDING_INVALID_RECORD",
  );

  const seen = new Set();
  const addresses = [];
  for (const address of addressData) {
    addresses.push(validateAddress(address, seen));
  }
  const frozenAddresses = Object.freeze(addresses);
  return Object.freeze({
    addresses: frozenAddresses,
    paymentMoved: false,
    participants: validateRecordedParticipants(
      snapshot.participants,
      frozenAddresses,
    ),
    schema: FUNDING_RECORD_SCHEMA,
  });
}

function validateParticipantFacts(value, addresses) {
  const participantData = snapshotDenseDataArray(
    value,
    4,
    "BILATERAL_FUNDING_INVALID_PARTICIPANTS",
  );

  const facts = [];
  for (let index = 0; index < participantData.length; index += 1) {
    const fact = snapshotExactDataObject(
      participantData[index],
      PARTICIPANT_FACT_KEYS,
      "BILATERAL_FUNDING_INVALID_PARTICIPANTS",
    );
    if (fact.address !== addresses[index]) {
      fail("BILATERAL_FUNDING_INVALID_PARTICIPANTS");
    }
    const balanceWei = requireBigint(
      fact.balanceWei,
      "BILATERAL_FUNDING_INVALID_PARTICIPANTS",
    );
    const nonce = requireBigint(
      fact.nonce,
      "BILATERAL_FUNDING_INVALID_PARTICIPANTS",
    );
    if (nonce !== 0n || balanceWei > PARTICIPANT_MAXIMUM_WEI) {
      fail("BILATERAL_FUNDING_INVALID_PARTICIPANTS");
    }
    facts.push(Object.freeze({
      address: fact.address,
      balanceWei,
      nonce,
    }));
  }
  return facts;
}

export function planFundingTransfers(value) {
  const input = snapshotExactDataObject(
    value,
    PLAN_INPUT_KEYS,
    "BILATERAL_FUNDING_INVALID_PLAN",
  );
  const {
    feePerTransferWei,
    fundingBalanceWei,
    fundingNonce,
    participantFacts,
    record,
  } = input;
  const validatedRecord = validateFundingRecord(record);
  const fee = requireBigint(
    feePerTransferWei,
    "BILATERAL_FUNDING_INVALID_FEE",
  );
  const balance = requireBigint(
    fundingBalanceWei,
    "BILATERAL_FUNDING_INSUFFICIENT_BALANCE",
  );
  const firstNonce = requireBigint(
    fundingNonce,
    "BILATERAL_FUNDING_INVALID_NONCE",
  );
  const facts = validateParticipantFacts(
    participantFacts,
    validatedRecord.addresses,
  );

  const adopted = [];
  const transfers = [];
  let totalValueWei = 0n;
  for (const fact of facts) {
    if (fact.balanceWei < PARTICIPANT_MINIMUM_WEI) {
      const valueWei = PARTICIPANT_TARGET_WEI - fact.balanceWei;
      transfers.push({
        address: fact.address,
        fundingNonce: firstNonce + BigInt(transfers.length),
        valueWei,
      });
      totalValueWei += valueWei;
    } else {
      adopted.push(fact.address);
    }
  }

  const totalFeeWei = fee * BigInt(transfers.length);
  if (totalValueWei + totalFeeWei > balance) {
    fail("BILATERAL_FUNDING_INSUFFICIENT_BALANCE");
  }

  return Object.freeze({
    adopted: Object.freeze(adopted),
    paymentMoved: false,
    totalFeeWei,
    totalValueWei,
    transfers: Object.freeze(
      transfers.map((transfer) => Object.freeze({ ...transfer })),
    ),
  });
}
