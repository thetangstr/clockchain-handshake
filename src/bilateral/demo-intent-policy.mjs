function deepFreeze(value) {
  if (value && typeof value === "object") {
    for (const entry of Object.values(value)) deepFreeze(entry);
    Object.freeze(value);
  }
  return value;
}

export const DEMO_INTENT_POLICY = deepFreeze({
  amount: { currency: "USD", value: "100" },
  invoiceReferencePrefix: "invoice-",
  purpose: "Handshake demo",
});
