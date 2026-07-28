import assert from "node:assert/strict";
import test from "node:test";

import {
  BilateralFundingError,
  FUNDING_RECORD_SCHEMA,
  PARTICIPANT_MAXIMUM_WEI,
  PARTICIPANT_MINIMUM_WEI,
  PARTICIPANT_TARGET_WEI,
  planFundingTransfers,
  validateFundingRecord,
} from "../src/bilateral/funding/record.mjs";

const RECORD = Object.freeze({
  addresses: Object.freeze([
    "0x1111111111111111111111111111111111111111",
    "0x2222222222222222222222222222222222222222",
    "0x3333333333333333333333333333333333333333",
    "0x4444444444444444444444444444444444444444",
  ]),
  paymentMoved: false,
  schema: "clockchain.bilateral-funding-addresses/v1",
});

function mutableRecord() {
  return {
    addresses: [...RECORD.addresses],
    paymentMoved: false,
    schema: RECORD.schema,
  };
}

function arrayWithGetter(index, value) {
  const array = [...RECORD.addresses];
  Object.defineProperty(array, String(index), {
    enumerable: true,
    get() {
      return value;
    },
  });
  return array;
}

test("validateFundingRecord returns an immutable exact copy of the canonical record", () => {
  assert.equal(FUNDING_RECORD_SCHEMA, RECORD.schema);

  const input = mutableRecord();
  const validated = validateFundingRecord(input);

  assert.deepEqual(validated, RECORD);
  assert.notEqual(validated, input);
  assert.notEqual(validated.addresses, input.addresses);
  assert.ok(Object.isFrozen(validated));
  assert.ok(Object.isFrozen(validated.addresses));

  input.addresses[0] = RECORD.addresses[1];
  assert.equal(validated.addresses[0], RECORD.addresses[0]);
  assert.throws(() => {
    validated.addresses[0] = RECORD.addresses[1];
  }, TypeError);
});

test("validateFundingRecord rejects malformed funding records fail-closed", () => {
  const invalidRecords = [
    null,
    { ...mutableRecord(), extra: true },
    { ...mutableRecord(), paymentMoved: true },
    { ...mutableRecord(), addresses: RECORD.addresses.slice(0, 3) },
    {
      ...mutableRecord(),
      addresses: [
        RECORD.addresses[0],
        RECORD.addresses[0],
        ...RECORD.addresses.slice(2),
      ],
    },
    {
      ...mutableRecord(),
      addresses: RECORD.addresses.map((value, index) =>
        index === 0 ? value.toUpperCase() : value,
      ),
    },
    {
      ...mutableRecord(),
      addresses: RECORD.addresses.map((value, index) =>
        index === 0
          ? "0x0000000000000000000000000000000000000000"
          : value,
      ),
    },
    { ...mutableRecord(), addresses: arrayWithGetter(0, RECORD.addresses[0]) },
  ];

  for (const [index, invalid] of invalidRecords.entries()) {
    assert.throws(
      () => validateFundingRecord(invalid),
      BilateralFundingError,
      `expected rejection for invalid record ${index}`,
    );
  }
});

test("funding thresholds are the exact committed wei envelope", () => {
  assert.equal(PARTICIPANT_MINIMUM_WEI, 5_000_000_000_000_000n);
  assert.equal(PARTICIPANT_TARGET_WEI, 10_000_000_000_000_000n);
  assert.equal(PARTICIPANT_MAXIMUM_WEI, 20_000_000_000_000_000n);
});

test("planFundingTransfers tops up only below-floor participants and adopts in-band balances", () => {
  const record = validateFundingRecord(mutableRecord());
  const facts = [
    { address: record.addresses[0], balanceWei: 0n, nonce: 0n },
    {
      address: record.addresses[1],
      balanceWei: 5_000_000_000_000_000n,
      nonce: 0n,
    },
    {
      address: record.addresses[2],
      balanceWei: 9_000_000_000_000_000n,
      nonce: 0n,
    },
    {
      address: record.addresses[3],
      balanceWei: 10_000_000_000_000_000n,
      nonce: 0n,
    },
  ];

  assert.deepEqual(
    planFundingTransfers({
      feePerTransferWei: 100n,
      fundingBalanceWei: 10_000_000_000_000_100n,
      fundingNonce: 7n,
      participantFacts: facts,
      record,
    }),
    {
      adopted: [
        record.addresses[1],
        record.addresses[2],
        record.addresses[3],
      ],
      paymentMoved: false,
      totalFeeWei: 100n,
      totalValueWei: 10_000_000_000_000_000n,
      transfers: [
        {
          address: record.addresses[0],
          fundingNonce: 7n,
          valueWei: 10_000_000_000_000_000n,
        },
      ],
    },
  );
});

test("planFundingTransfers preserves record order and assigns explicit sequential funding nonces", () => {
  const record = validateFundingRecord(mutableRecord());
  const plan = planFundingTransfers({
    feePerTransferWei: 5n,
    fundingBalanceWei: 16_000_000_000_000_010n,
    fundingNonce: 42n,
    participantFacts: [
      { address: record.addresses[0], balanceWei: 4_000_000_000_000_000n, nonce: 0n },
      { address: record.addresses[1], balanceWei: 0n, nonce: 0n },
      { address: record.addresses[2], balanceWei: 5_000_000_000_000_000n, nonce: 0n },
      { address: record.addresses[3], balanceWei: 20_000_000_000_000_000n, nonce: 0n },
    ],
    record,
  });

  assert.deepEqual(plan.transfers, [
    {
      address: record.addresses[0],
      fundingNonce: 42n,
      valueWei: 6_000_000_000_000_000n,
    },
    {
      address: record.addresses[1],
      fundingNonce: 43n,
      valueWei: 10_000_000_000_000_000n,
    },
  ]);
  assert.deepEqual(plan.adopted, [record.addresses[2], record.addresses[3]]);
  assert.equal(plan.totalValueWei, 16_000_000_000_000_000n);
  assert.equal(plan.totalFeeWei, 10n);
  assert.equal(plan.paymentMoved, false);
});

test("planFundingTransfers rejects unsafe or ambiguous planning facts fail-closed", () => {
  const record = validateFundingRecord(mutableRecord());
  const facts = [
    { address: record.addresses[0], balanceWei: 0n, nonce: 0n },
    { address: record.addresses[1], balanceWei: 5_000_000_000_000_000n, nonce: 0n },
    { address: record.addresses[2], balanceWei: 9_000_000_000_000_000n, nonce: 0n },
    { address: record.addresses[3], balanceWei: 10_000_000_000_000_000n, nonce: 0n },
  ];
  const validInput = {
    feePerTransferWei: 100n,
    fundingBalanceWei: 10_000_000_000_000_100n,
    fundingNonce: 7n,
    participantFacts: facts,
    record,
  };
  const invalidInputs = [
    null,
    { ...validInput, extra: true },
    { ...validInput, participantFacts: facts.slice(0, 3) },
    { ...validInput, feePerTransferWei: "100" },
    { ...validInput, fundingBalanceWei: 10_000_000_000_000_100 },
    { ...validInput, fundingNonce: "7" },
    {
      ...validInput,
      participantFacts: facts.map((fact, index) =>
        index === 0 ? { ...fact, extra: true } : fact,
      ),
    },
    {
      ...validInput,
      participantFacts: facts.map((fact, index) =>
        index === 0 ? { ...fact, balanceWei: "0" } : fact,
      ),
    },
    {
      ...validInput,
      participantFacts: facts.map((fact, index) =>
        index === 0 ? { ...fact, balanceWei: -1n } : fact,
      ),
    },
    {
      ...validInput,
      participantFacts: facts.map((fact, index) =>
        index === 0 ? { ...fact, nonce: 1n } : fact,
      ),
    },
    {
      ...validInput,
      participantFacts: [facts[1], facts[0], facts[2], facts[3]],
    },
    {
      ...validInput,
      participantFacts: Object.defineProperty([...facts], "0", {
        enumerable: true,
        get() {
          return facts[0];
        },
      }),
    },
    {
      ...validInput,
      participantFacts: facts.map((fact, index) =>
        index === 3
          ? { ...fact, balanceWei: 20_000_000_000_000_001n }
          : fact,
      ),
    },
    {
      ...validInput,
      fundingBalanceWei: 10_000_000_000_000_099n,
    },
  ];

  for (const invalid of invalidInputs) {
    assert.throws(
      () => planFundingTransfers(invalid),
      BilateralFundingError,
      "expected planner to fail closed",
    );
  }
});
