import {
  MAX_CANONICAL_STRING_LENGTH,
  digestHex,
} from "./canonical.mjs";
import {
  BILATERAL_PROTOCOL,
  DESCRIPTOR_CHAIN_ID,
  DESCRIPTOR_EXPIRY_SECONDS,
  DescriptorValidationError,
  REGISTRY_ADDRESS,
  dSession,
  validateDescriptor,
} from "./descriptor.mjs";

export const TRANSITION_SCHEMA =
  "clockchain.bilateral-transition/v1";

export const AMOUNT_KEYS = Object.freeze([
  "currency",
  "moved",
  "value",
]);
export const PAYEE_BINDING_KEYS = Object.freeze([
  "address",
  "agentId",
]);
export const PAYER_BINDING_KEYS = Object.freeze([
  "address",
  "agentId",
  "reference",
]);
export const PREDECESSOR_TRIPLE_KEYS = Object.freeze([
  "anchoredHash",
  "blockHeight",
  "kind",
  "ledgerId",
]);
export const COMMON_HEAD_KEYS = Object.freeze([
  "amount",
  "expirySeconds",
  "payee",
  "payer",
  "protocol",
  "schema",
  "sessionDigest",
]);
export const PROPOSAL_KEYS = Object.freeze([
  "amount",
  "expirySeconds",
  "kind",
  "payee",
  "payer",
  "predecessor",
  "protocol",
  "schema",
  "sequence",
  "sessionDigest",
]);
export const ACCEPTANCE_KEYS = Object.freeze([
  "amount",
  "decision",
  "expirySeconds",
  "kind",
  "payee",
  "payer",
  "predecessor",
  "protocol",
  "schema",
  "sequence",
  "sessionDigest",
]);
export const ACKNOWLEDGMENT_KEYS = Object.freeze([
  "amount",
  "expirySeconds",
  "kind",
  "outcome",
  "payee",
  "payer",
  "paymentMoved",
  "predecessor",
  "proposal",
  "protocol",
  "schema",
  "sequence",
  "sessionDigest",
]);

export const DERIVABLE_TRANSITION_FIELDS = Object.freeze([
  "amount",
  "amount.currency",
  "amount.moved",
  "amount.value",
  "decision",
  "expirySeconds",
  "kind",
  "outcome",
  "payee",
  "payee.address",
  "payee.agentId",
  "payer",
  "payer.address",
  "payer.agentId",
  "payer.reference",
  "paymentMoved",
  "predecessor",
  "predecessor.anchoredHash",
  "predecessor.blockHeight",
  "predecessor.kind",
  "predecessor.ledgerId",
  "proposal",
  "proposal.anchoredHash",
  "proposal.blockHeight",
  "proposal.kind",
  "proposal.ledgerId",
  "protocol",
  "schema",
  "sequence",
  "sessionDigest",
]);

const PROPOSAL_INPUT_KEYS = Object.freeze([
  "amount",
  "descriptor",
  "sessionDigest",
]);
const ACCEPTANCE_INPUT_KEYS = Object.freeze([
  "proposal",
  "proposalTriple",
]);
const ACKNOWLEDGMENT_INPUT_KEYS = Object.freeze([
  "acceptance",
  "acceptanceTriple",
  "proposalTriple",
]);
const RECOVERY_INPUT_KEYS = Object.freeze([
  "anchoredHash",
  "descriptor",
  "sessionDigest",
]);
const AMOUNT_OPTION_KEYS = Object.freeze(["currency", "value"]);
const TRANSITION_KINDS = Object.freeze([
  "proposal",
  "acceptance",
  "acknowledgment",
]);

const ADDRESS_PATTERN = /^0x[0-9a-f]{40}$/;
const AGENT_ID_PATTERN = /^(?:0|[1-9][0-9]*)$/;
const HASH_PATTERN = /^[0-9a-f]{64}$/;
const UUID_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const CURRENCY_PATTERN = /^[A-Z]{3}$/;
const DECIMAL_AMOUNT_PATTERN =
  /^(?:[1-9][0-9]*|(?:0|[1-9][0-9]*)\.[0-9]*[1-9])$/;
const DECIMAL_INTEGER_PATTERN = /^(?:0|[1-9][0-9]*)$/;
const ARRAY_INDEX_PATTERN = /^(?:0|[1-9][0-9]*)$/;
const MAX_DECIMAL_LENGTH = 256;
const MAX_SNAPSHOT_DEPTH = 32;
const MAX_SNAPSHOT_OBJECTS = 256;
const MAX_SNAPSHOT_ARRAY_LENGTH = 8;
const PAYER_REFERENCE_PREFIX =
  `eip155:${DESCRIPTOR_CHAIN_ID}:${REGISTRY_ADDRESS}:`;
const MAX_PAYER_AGENT_ID_LENGTH =
  MAX_CANONICAL_STRING_LENGTH - PAYER_REFERENCE_PREFIX.length;

export class TransitionError extends Error {
  constructor(
    message = "Bilateral transition processing failed.",
    code = "TRANSITION_ERROR",
  ) {
    super(message);
    this.name = new.target.name;
    this.category = "verification";
    this.code = code;
  }
}

export class TransitionValidationError extends TransitionError {
  constructor(code = "TRANSITION_INVALID") {
    super("Bilateral transition validation failed.", code);
  }
}

export class ProposalRecoveryError extends TransitionError {}

export class ProposalAmountNotFoundError
  extends ProposalRecoveryError {
  constructor() {
    super(
      "No signed amount option produced the anchored proposal digest.",
      "PROPOSAL_AMOUNT_NOT_FOUND",
    );
  }
}

export class ProposalAmountAmbiguousError
  extends ProposalRecoveryError {
  constructor() {
    super(
      "More than one signed amount option produced the anchored proposal digest.",
      "PROPOSAL_AMOUNT_AMBIGUOUS",
    );
  }
}

function invalid(code) {
  throw new TransitionValidationError(code);
}

function validateDescriptorForTransition(descriptor) {
  try {
    validateDescriptor(descriptor);
  } catch (error) {
    if (error instanceof DescriptorValidationError) {
      invalid("TRANSITION_DESCRIPTOR");
    }
    throw error;
  }
}

class SnapshotFailure extends Error {}

function snapshotFailure() {
  throw new SnapshotFailure();
}

function snapshotValue(value, state, depth) {
  if (
    value === null ||
    value === undefined ||
    typeof value === "string" ||
    typeof value === "boolean" ||
    typeof value === "number" ||
    typeof value === "bigint"
  ) {
    return value;
  }
  if (
    typeof value !== "object" ||
    depth > MAX_SNAPSHOT_DEPTH ||
    state.remainingObjects === 0 ||
    state.ancestors.has(value)
  ) {
    snapshotFailure();
  }

  state.remainingObjects -= 1;
  state.ancestors.add(value);
  try {
    if (Array.isArray(value)) {
      const keys = Reflect.ownKeys(value);
      const lengthProperty =
        Object.getOwnPropertyDescriptor(value, "length");
      const length = lengthProperty?.value;
      if (
        !lengthProperty ||
        lengthProperty.enumerable ||
        !Object.hasOwn(lengthProperty, "value") ||
        !Number.isSafeInteger(length) ||
        length < 0 ||
        length > MAX_SNAPSHOT_ARRAY_LENGTH ||
        keys.length !== length + 1 ||
        keys.some(
          (key) =>
            key !== "length" &&
            (typeof key !== "string" ||
              !ARRAY_INDEX_PATTERN.test(key) ||
              Number(key) >= length),
        )
      ) {
        snapshotFailure();
      }
      const snapshot = new Array(length);
      for (let index = 0; index < length; index += 1) {
        const property = Object.getOwnPropertyDescriptor(
          value,
          String(index),
        );
        if (
          property?.enumerable !== true ||
          !Object.hasOwn(property, "value")
        ) {
          snapshotFailure();
        }
        snapshot[index] = snapshotValue(
          property.value,
          state,
          depth + 1,
        );
      }
      return Object.freeze(snapshot);
    }

    const prototype = Object.getPrototypeOf(value);
    if (
      prototype !== Object.prototype &&
      prototype !== null
    ) {
      snapshotFailure();
    }
    const snapshot =
      prototype === null ? Object.create(null) : {};
    for (const key of Reflect.ownKeys(value)) {
      const property = Object.getOwnPropertyDescriptor(value, key);
      if (
        typeof key !== "string" ||
        property?.enumerable !== true ||
        !Object.hasOwn(property, "value")
      ) {
        snapshotFailure();
      }
      snapshot[key] = snapshotValue(
        property.value,
        state,
        depth + 1,
      );
    }
    return Object.freeze(snapshot);
  } catch (error) {
    if (error instanceof SnapshotFailure) {
      throw error;
    }
    snapshotFailure();
  } finally {
    state.ancestors.delete(value);
  }
}

function materializeSnapshot(value) {
  try {
    return snapshotValue(
      value,
      {
        ancestors: new Set(),
        remainingObjects: MAX_SNAPSHOT_OBJECTS,
      },
      1,
    );
  } catch {
    invalid("TRANSITION_SNAPSHOT");
  }
}

function isPlainSnapshotObject(value) {
  if (value === null || typeof value !== "object") {
    return false;
  }
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function hasExactEnumerableDataKeys(value, expectedKeys) {
  if (!isPlainSnapshotObject(value)) {
    return false;
  }
  const keys = Reflect.ownKeys(value);
  if (
    keys.length !== expectedKeys.length ||
    keys.some(
      (key) =>
        typeof key !== "string" ||
        !expectedKeys.includes(key),
    )
  ) {
    return false;
  }
  return keys.every((key) => {
    const property = Object.getOwnPropertyDescriptor(value, key);
    return (
      property?.enumerable === true &&
      Object.hasOwn(property, "value")
    );
  });
}

function validateExactKeys(value, expectedKeys, code) {
  if (!hasExactEnumerableDataKeys(value, expectedKeys)) {
    invalid(code);
  }
}

function validateAmountOption(amount) {
  validateExactKeys(
    amount,
    AMOUNT_OPTION_KEYS,
    "TRANSITION_AMOUNT_OPTION",
  );
  if (
    typeof amount.currency !== "string" ||
    !CURRENCY_PATTERN.test(amount.currency) ||
    typeof amount.value !== "string" ||
    amount.value.length === 0 ||
    amount.value.length > MAX_DECIMAL_LENGTH ||
    !DECIMAL_AMOUNT_PATTERN.test(amount.value)
  ) {
    invalid("TRANSITION_AMOUNT_OPTION");
  }
}

function validateAmount(amount) {
  validateExactKeys(
    amount,
    AMOUNT_KEYS,
    "TRANSITION_AMOUNT",
  );
  if (amount.moved !== false) {
    invalid("TRANSITION_AMOUNT");
  }
  validateAmountOption({
    currency: amount.currency,
    value: amount.value,
  });
}

function validatePayee(payee) {
  validateExactKeys(
    payee,
    PAYEE_BINDING_KEYS,
    "TRANSITION_PAYEE",
  );
  if (
    typeof payee.address !== "string" ||
    !ADDRESS_PATTERN.test(payee.address) ||
    typeof payee.agentId !== "string" ||
    payee.agentId.length > MAX_DECIMAL_LENGTH ||
    !AGENT_ID_PATTERN.test(payee.agentId)
  ) {
    invalid("TRANSITION_PAYEE");
  }
}

function validatePayer(payer) {
  validateExactKeys(
    payer,
    PAYER_BINDING_KEYS,
    "TRANSITION_PAYER",
  );
  if (
    typeof payer.address !== "string" ||
    !ADDRESS_PATTERN.test(payer.address) ||
    typeof payer.agentId !== "string" ||
    payer.agentId.length > MAX_PAYER_AGENT_ID_LENGTH ||
    !AGENT_ID_PATTERN.test(payer.agentId)
  ) {
    invalid("TRANSITION_PAYER");
  }
  const expectedReference =
    PAYER_REFERENCE_PREFIX + payer.agentId;
  if (
    payer.reference !== expectedReference ||
    payer.reference.length > MAX_CANONICAL_STRING_LENGTH
  ) {
    invalid("TRANSITION_PAYER");
  }
}

function validateHead(message) {
  validateAmount(message.amount);
  validatePayee(message.payee);
  validatePayer(message.payer);
  if (
    message.expirySeconds !== DESCRIPTOR_EXPIRY_SECONDS ||
    message.protocol !== BILATERAL_PROTOCOL ||
    message.schema !== TRANSITION_SCHEMA ||
    typeof message.sessionDigest !== "string" ||
    !HASH_PATTERN.test(message.sessionDigest) ||
    message.payee.address === message.payer.address ||
    message.payee.agentId === message.payer.agentId
  ) {
    invalid("TRANSITION_HEAD");
  }
}

function validateTripleSnapshot(triple, expectedKind) {
  validateExactKeys(
    triple,
    PREDECESSOR_TRIPLE_KEYS,
    "TRANSITION_TRIPLE",
  );
  if (
    typeof triple.anchoredHash !== "string" ||
    !HASH_PATTERN.test(triple.anchoredHash) ||
    typeof triple.blockHeight !== "string" ||
    triple.blockHeight.length === 0 ||
    triple.blockHeight.length > MAX_DECIMAL_LENGTH ||
    !DECIMAL_INTEGER_PATTERN.test(triple.blockHeight) ||
    typeof triple.ledgerId !== "string" ||
    !UUID_PATTERN.test(triple.ledgerId) ||
    !TRANSITION_KINDS.includes(triple.kind) ||
    (expectedKind !== undefined && triple.kind !== expectedKind)
  ) {
    invalid("TRANSITION_TRIPLE");
  }
}

function validateTransitionSnapshot(message) {
  if (!isPlainSnapshotObject(message)) {
    invalid("TRANSITION_SHAPE");
  }
  if (message.kind === "proposal") {
    validateExactKeys(
      message,
      PROPOSAL_KEYS,
      "TRANSITION_SHAPE",
    );
    validateHead(message);
    if (
      message.sequence !== "1" ||
      message.predecessor !== null
    ) {
      invalid("TRANSITION_PROPOSAL");
    }
    return;
  }
  if (message.kind === "acceptance") {
    validateExactKeys(
      message,
      ACCEPTANCE_KEYS,
      "TRANSITION_SHAPE",
    );
    validateHead(message);
    validateTripleSnapshot(message.predecessor, "proposal");
    if (
      message.sequence !== "2" ||
      message.decision !== "ACCEPT"
    ) {
      invalid("TRANSITION_ACCEPTANCE");
    }
    return;
  }
  if (message.kind === "acknowledgment") {
    validateExactKeys(
      message,
      ACKNOWLEDGMENT_KEYS,
      "TRANSITION_SHAPE",
    );
    validateHead(message);
    validateTripleSnapshot(message.predecessor, "acceptance");
    validateTripleSnapshot(message.proposal, "proposal");
    if (
      message.sequence !== "3" ||
      message.outcome !== "ACKNOWLEDGED" ||
      message.paymentMoved !== false
    ) {
      invalid("TRANSITION_ACKNOWLEDGMENT");
    }
    return;
  }
  invalid("TRANSITION_KIND");
}

function validatedTransitionSnapshot(message) {
  const snapshot = materializeSnapshot(message);
  validateTransitionSnapshot(snapshot);
  return snapshot;
}

function completedTransition(message) {
  const snapshot = validatedTransitionSnapshot(message);
  digestHex(snapshot);
  return snapshot;
}

function frozenAmount(currency, value) {
  return Object.freeze({
    currency,
    moved: false,
    value,
  });
}

function frozenPayee(payee) {
  return Object.freeze({
    address: payee.address,
    agentId: payee.agentId,
  });
}

function frozenPayer(payer) {
  return Object.freeze({
    address: payer.address,
    agentId: payer.agentId,
    reference:
      `eip155:${DESCRIPTOR_CHAIN_ID}:${REGISTRY_ADDRESS}:${payer.agentId}`,
  });
}

function frozenTriple(triple) {
  return Object.freeze({
    anchoredHash: triple.anchoredHash,
    blockHeight: triple.blockHeight,
    kind: triple.kind,
    ledgerId: triple.ledgerId,
  });
}

function frozenHead(source) {
  return {
    amount: frozenAmount(
      source.amount.currency,
      source.amount.value,
    ),
    expirySeconds: source.expirySeconds,
    payee: frozenPayee(source.payee),
    payer: frozenPayer(source.payer),
    protocol: source.protocol,
    schema: source.schema,
    sessionDigest: source.sessionDigest,
  };
}

function triplesEqual(left, right) {
  return PREDECESSOR_TRIPLE_KEYS.every(
    (key) => left[key] === right[key],
  );
}

export function authoritativeTriple(input) {
  const snapshot = materializeSnapshot(input);
  validateTripleSnapshot(snapshot);
  return frozenTriple(snapshot);
}

export function buildProposal(input) {
  const snapshot = materializeSnapshot(input);
  validateExactKeys(
    snapshot,
    PROPOSAL_INPUT_KEYS,
    "TRANSITION_CONSTRUCTOR_INPUT",
  );
  validateDescriptorForTransition(snapshot.descriptor);
  validateAmountOption(snapshot.amount);
  if (
    typeof snapshot.sessionDigest !== "string" ||
    !HASH_PATTERN.test(snapshot.sessionDigest) ||
    snapshot.sessionDigest !== dSession(snapshot.descriptor)
  ) {
    invalid("TRANSITION_SESSION_DIGEST");
  }
  if (
    !snapshot.descriptor.amountOptions.some(
      (option) =>
        option.currency === snapshot.amount.currency &&
        option.value === snapshot.amount.value,
    )
  ) {
    invalid("TRANSITION_AMOUNT_OPTION");
  }

  return completedTransition({
    amount: frozenAmount(
      snapshot.amount.currency,
      snapshot.amount.value,
    ),
    expirySeconds: snapshot.descriptor.expirySeconds,
    kind: "proposal",
    payee: frozenPayee(snapshot.descriptor.payee),
    payer: frozenPayer(snapshot.descriptor.payer),
    predecessor: null,
    protocol: snapshot.descriptor.protocol,
    schema: TRANSITION_SCHEMA,
    sequence: "1",
    sessionDigest: snapshot.sessionDigest,
  });
}

export function buildAcceptance(input) {
  const snapshot = materializeSnapshot(input);
  validateExactKeys(
    snapshot,
    ACCEPTANCE_INPUT_KEYS,
    "TRANSITION_CONSTRUCTOR_INPUT",
  );
  validateTransitionSnapshot(snapshot.proposal);
  if (snapshot.proposal.kind !== "proposal") {
    invalid("TRANSITION_PROPOSAL");
  }
  validateTripleSnapshot(snapshot.proposalTriple, "proposal");
  if (
    snapshot.proposalTriple.anchoredHash !==
    digestHex(snapshot.proposal)
  ) {
    invalid("TRANSITION_TRIPLE_DIGEST");
  }

  const head = frozenHead(snapshot.proposal);
  return completedTransition({
    ...head,
    decision: "ACCEPT",
    kind: "acceptance",
    predecessor: frozenTriple(snapshot.proposalTriple),
    sequence: "2",
  });
}

export function buildAcknowledgment(input) {
  const snapshot = materializeSnapshot(input);
  validateExactKeys(
    snapshot,
    ACKNOWLEDGMENT_INPUT_KEYS,
    "TRANSITION_CONSTRUCTOR_INPUT",
  );
  validateTransitionSnapshot(snapshot.acceptance);
  if (snapshot.acceptance.kind !== "acceptance") {
    invalid("TRANSITION_ACCEPTANCE");
  }
  validateTripleSnapshot(
    snapshot.acceptanceTriple,
    "acceptance",
  );
  validateTripleSnapshot(snapshot.proposalTriple, "proposal");
  if (
    snapshot.acceptanceTriple.anchoredHash !==
      digestHex(snapshot.acceptance) ||
    !triplesEqual(
      snapshot.proposalTriple,
      snapshot.acceptance.predecessor,
    )
  ) {
    invalid("TRANSITION_TRIPLE_DIGEST");
  }

  const head = frozenHead(snapshot.acceptance);
  return completedTransition({
    ...head,
    kind: "acknowledgment",
    outcome: "ACKNOWLEDGED",
    paymentMoved: false,
    predecessor: frozenTriple(snapshot.acceptanceTriple),
    proposal: frozenTriple(snapshot.proposalTriple),
    sequence: "3",
  });
}

export function validateTransition(message) {
  validatedTransitionSnapshot(message);
}

export function transitionDigest(message) {
  return digestHex(validatedTransitionSnapshot(message));
}

export function selectUniqueProposalMatch(matches) {
  const snapshot = materializeSnapshot(matches);
  if (!Array.isArray(snapshot)) {
    invalid("TRANSITION_PROPOSAL_MATCHES");
  }
  for (const candidate of snapshot) {
    validateTransitionSnapshot(candidate);
    if (candidate.kind !== "proposal") {
      invalid("TRANSITION_PROPOSAL");
    }
  }
  if (snapshot.length === 0) {
    throw new ProposalAmountNotFoundError();
  }
  if (snapshot.length > 1) {
    throw new ProposalAmountAmbiguousError();
  }
  return snapshot[0];
}

export function recoverProposalByDigest(input) {
  if (arguments.length !== 1) {
    invalid("TRANSITION_RECOVERY_INPUT");
  }
  const snapshot = materializeSnapshot(input);
  validateExactKeys(
    snapshot,
    RECOVERY_INPUT_KEYS,
    "TRANSITION_RECOVERY_INPUT",
  );
  validateDescriptorForTransition(snapshot.descriptor);
  if (
    typeof snapshot.anchoredHash !== "string" ||
    !HASH_PATTERN.test(snapshot.anchoredHash) ||
    typeof snapshot.sessionDigest !== "string" ||
    !HASH_PATTERN.test(snapshot.sessionDigest) ||
    snapshot.sessionDigest !== dSession(snapshot.descriptor)
  ) {
    invalid("TRANSITION_RECOVERY_INPUT");
  }

  const matches = [];
  for (const option of snapshot.descriptor.amountOptions) {
    const candidate = buildProposal({
      descriptor: snapshot.descriptor,
      sessionDigest: snapshot.sessionDigest,
      amount: {
        currency: option.currency,
        value: option.value,
      },
    });
    if (transitionDigest(candidate) === snapshot.anchoredHash) {
      matches.push(candidate);
    }
  }
  const recovered = selectUniqueProposalMatch(matches);
  if (transitionDigest(recovered) !== snapshot.anchoredHash) {
    throw new ProposalAmountNotFoundError();
  }
  return recovered;
}
