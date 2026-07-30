import { resolve } from "node:path";
import { pathToFileURL } from "node:url";

const isDirectExecution =
  process.argv[1] !== undefined &&
  import.meta.url === pathToFileURL(resolve(process.argv[1])).href;

if (!isDirectExecution) {
  const rawClockMs = process.env.CLOCKCHAIN_BILATERAL_TEST_CLOCK_MS;

  if (!/^(0|[1-9][0-9]*)$/.test(rawClockMs ?? "")) {
    throw new Error("CLOCKCHAIN_BILATERAL_TEST_CLOCK_MS must be a decimal epoch.");
  }

  const clockMs = Number(rawClockMs);
  if (!Number.isSafeInteger(clockMs) || clockMs < 0) {
    throw new Error("CLOCKCHAIN_BILATERAL_TEST_CLOCK_MS must be a safe epoch.");
  }

  const wallStartMs = Date.now();
  Object.defineProperty(Date, "now", {
    configurable: false,
    enumerable: false,
    value: () => clockMs + (new Date().getTime() - wallStartMs),
    writable: false,
  });
}
