import { lookup as dnsLookupCallback } from "node:dns";
import { isIP } from "node:net";
import { promisify } from "node:util";

const dnsLookup = promisify(dnsLookupCallback);
const MAX_URL_BYTES = 2_048;
const DNS_NAME_PATTERN =
  /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;
const CONTROL_CHARACTER_PATTERN = /[\u0000-\u001f\u007f]/;

function fail() {
  throw new Error("Public endpoint validation failed safely.");
}

function sanitize(error) {
  if (error?.message === "Public endpoint validation failed safely.") throw error;
  fail();
}

function exactPlainObject(value, keys) {
  if (
    value === null ||
    typeof value !== "object" ||
    Array.isArray(value) ||
    Object.getPrototypeOf(value) !== Object.prototype
  ) {
    return false;
  }
  const ownKeys = Reflect.ownKeys(value);
  return (
    ownKeys.length === keys.length &&
    keys.every((key, index) => ownKeys[index] === key)
  );
}

function canonicalIp(value) {
  const family = isIP(value);
  if (family === 0) fail();
  try {
    if (family === 4) {
      const parsed = new URL(`https://${value}/`);
      if (parsed.hostname !== value) fail();
      return Object.freeze({ address: value, family });
    }
    const parsed = new URL(`https://[${value}]/`);
    const normalized = parsed.hostname.slice(1, -1);
    if (normalized !== value) fail();
    return Object.freeze({ address: normalized, family });
  } catch (error) {
    sanitize(error);
  }
  fail();
}

function ipv4Integer(value) {
  return value
    .split(".")
    .reduce((result, octet) => (result << 8n) | BigInt(Number(octet)), 0n);
}

function ipv4InPrefix(value, base, bits) {
  const size = 32n - BigInt(bits);
  return (ipv4Integer(value) >> size) === (ipv4Integer(base) >> size);
}

function ipv6Integer(value) {
  const sections = value.split("::");
  if (sections.length > 2) fail();
  const left = sections[0] === "" ? [] : sections[0].split(":");
  const right =
    sections.length === 1 || sections[1] === ""
      ? []
      : sections[1].split(":");
  const missing = 8 - left.length - right.length;
  if (
    missing < (sections.length === 2 ? 1 : 0) ||
    (sections.length === 1 && missing !== 0)
  ) {
    fail();
  }
  const groups = [
    ...left,
    ...Array.from({ length: missing }, () => "0"),
    ...right,
  ];
  if (
    groups.length !== 8 ||
    groups.some((group) => !/^[0-9a-f]{1,4}$/.test(group))
  ) {
    fail();
  }
  return groups.reduce(
    (result, group) => (result << 16n) | BigInt(`0x${group}`),
    0n,
  );
}

function ipv6InPrefix(value, base, bits) {
  const size = 128n - BigInt(bits);
  return (ipv6Integer(value) >> size) === (ipv6Integer(base) >> size);
}

function isAllowedTestAddress(address, family) {
  if (family === 4) {
    return (
      ipv4InPrefix(address, "127.0.0.0", 8) ||
      ipv4InPrefix(address, "192.0.2.0", 24) ||
      ipv4InPrefix(address, "198.51.100.0", 24) ||
      ipv4InPrefix(address, "203.0.113.0", 24)
    );
  }
  return address === "::1" || ipv6InPrefix(address, "2001:db8::", 32);
}

function isNonPublicIpv4(address) {
  return [
    ["0.0.0.0", 8],
    ["10.0.0.0", 8],
    ["100.64.0.0", 10],
    ["127.0.0.0", 8],
    ["169.254.0.0", 16],
    ["172.16.0.0", 12],
    ["192.0.0.0", 24],
    ["192.0.2.0", 24],
    ["192.88.99.0", 24],
    ["192.168.0.0", 16],
    ["198.18.0.0", 15],
    ["198.51.100.0", 24],
    ["203.0.113.0", 24],
    ["224.0.0.0", 4],
    ["240.0.0.0", 4],
  ].some(([base, bits]) => ipv4InPrefix(address, base, bits));
}

function isNonPublicIpv6(address) {
  const value = ipv6Integer(address);
  const mappedPrefix = 0xffffn;
  if ((value >> 32n) === mappedPrefix) {
    const mapped = Number(value & 0xffffffffn);
    const ipv4 = [
      (mapped >>> 24) & 255,
      (mapped >>> 16) & 255,
      (mapped >>> 8) & 255,
      mapped & 255,
    ].join(".");
    return isNonPublicIpv4(ipv4);
  }
  return (
    address === "::" ||
    address === "::1" ||
    ipv6InPrefix(address, "100::", 64) ||
    ipv6InPrefix(address, "2001::", 23) ||
    ipv6InPrefix(address, "2001:db8::", 32) ||
    ipv6InPrefix(address, "2002::", 16) ||
    ipv6InPrefix(address, "fc00::", 7) ||
    ipv6InPrefix(address, "fe80::", 10) ||
    ipv6InPrefix(address, "fec0::", 10) ||
    ipv6InPrefix(address, "ff00::", 8)
  );
}

export function validatePublicAddress(value, { allowTestAddresses = false } = {}) {
  try {
    if (typeof allowTestAddresses !== "boolean") fail();
    const canonical = canonicalIp(value);
    if (
      (canonical.family === 4
        ? isNonPublicIpv4(canonical.address)
        : isNonPublicIpv6(canonical.address)) &&
      !(allowTestAddresses && isAllowedTestAddress(canonical.address, canonical.family))
    ) {
      fail();
    }
    return canonical;
  } catch (error) {
    sanitize(error);
  }
  fail();
}

function validateOptions(options) {
  if (
    options === null ||
    typeof options !== "object" ||
    Array.isArray(options) ||
    Object.getPrototypeOf(options) !== Object.prototype ||
    !Array.isArray(options.allowedPaths) ||
    options.allowedPaths.length === 0 ||
    options.allowedPaths.some(
      (path) =>
        typeof path !== "string" ||
        !path.startsWith("/") ||
        path.includes("?") ||
        path.includes("#") ||
        CONTROL_CHARACTER_PATTERN.test(path),
    ) ||
    new Set(options.allowedPaths).size !== options.allowedPaths.length ||
    !Number.isSafeInteger(options.defaultPort) ||
    options.defaultPort < 1 ||
    options.defaultPort > 65_535 ||
    !Array.isArray(options.protocols) ||
    options.protocols.length === 0 ||
    options.protocols.some(
      (protocol) => !["https:", "wss:"].includes(protocol),
    ) ||
    new Set(options.protocols).size !== options.protocols.length ||
    (options.allowTestAddresses !== undefined &&
      typeof options.allowTestAddresses !== "boolean")
  ) {
    fail();
  }
  return Object.freeze({
    allowedPaths: options.allowedPaths,
    allowTestAddresses: options.allowTestAddresses ?? false,
    defaultPort: options.defaultPort,
    protocols: options.protocols,
  });
}

function canonicalDnsName(value) {
  if (
    !DNS_NAME_PATTERN.test(value) ||
    value === "localhost" ||
    value.endsWith(".localhost") ||
    value.endsWith(".local") ||
    value.includes("*")
  ) {
    fail();
  }
  return value;
}

export function validatePublicEndpoint(value, options) {
  try {
    const validatedOptions = validateOptions(options);
    if (
      typeof value !== "string" ||
      value.length === 0 ||
      Buffer.byteLength(value, "utf8") > MAX_URL_BYTES ||
      CONTROL_CHARACTER_PATTERN.test(value)
    ) {
      fail();
    }
    let parsed;
    try {
      parsed = new URL(value);
    } catch {
      fail();
    }
    if (
      !validatedOptions.protocols.includes(parsed.protocol) ||
      parsed.username !== "" ||
      parsed.password !== "" ||
      parsed.search !== "" ||
      parsed.hash !== "" ||
      !validatedOptions.allowedPaths.includes(parsed.pathname) ||
      parsed.href !== value
    ) {
      fail();
    }
    const port =
      parsed.port === ""
        ? parsed.protocol === "https:" || parsed.protocol === "wss:"
          ? 443
          : 0
        : Number(parsed.port);
    if (
      port !== validatedOptions.defaultPort ||
      (parsed.port !== "" && String(port) !== parsed.port)
    ) {
      fail();
    }
    const bracketed = parsed.hostname.startsWith("[");
    const hostname = bracketed
      ? parsed.hostname.slice(1, -1)
      : parsed.hostname;
    const family = isIP(hostname);
    if (family === 0) {
      canonicalDnsName(hostname);
    } else {
      validatePublicAddress(hostname, {
        allowTestAddresses: validatedOptions.allowTestAddresses,
      });
    }
    return Object.freeze({
      hostname,
      path: parsed.pathname,
      port,
      protocol: parsed.protocol,
      url: parsed.href,
    });
  } catch (error) {
    sanitize(error);
  }
  fail();
}

function validateEndpointRecord(endpoint) {
  if (
    !exactPlainObject(endpoint, [
      "hostname",
      "path",
      "port",
      "protocol",
      "url",
    ]) ||
    typeof endpoint.hostname !== "string" ||
    typeof endpoint.path !== "string" ||
    !Number.isSafeInteger(endpoint.port) ||
    !["https:", "wss:"].includes(endpoint.protocol) ||
    typeof endpoint.url !== "string"
  ) {
    fail();
  }
  return endpoint;
}

function validateAddressRecord(value, allowTestAddresses) {
  if (!exactPlainObject(value, ["address", "family"])) fail();
  const address = validatePublicAddress(value.address, { allowTestAddresses });
  if (value.family !== address.family) fail();
  return Object.freeze({ address: address.address, family: address.family });
}

export async function resolvePublicEndpoint(
  endpoint,
  {
    allowTestAddresses = false,
    lookup = (hostname) => dnsLookup(hostname, { all: true, verbatim: true }),
  } = {},
) {
  try {
    const validated = validateEndpointRecord(endpoint);
    if (typeof allowTestAddresses !== "boolean" || typeof lookup !== "function") fail();
    const literalFamily = isIP(validated.hostname);
    const rawAddresses =
      literalFamily === 0
        ? await lookup(validated.hostname)
        : [{ address: validated.hostname, family: literalFamily }];
    if (!Array.isArray(rawAddresses) || rawAddresses.length === 0) fail();
    const addresses = rawAddresses.map((record) =>
      validateAddressRecord(record, allowTestAddresses),
    );
    return Object.freeze({
      addresses: Object.freeze(addresses),
      hostname: validated.hostname,
      path: validated.path,
      port: validated.port,
      protocol: validated.protocol,
      url: validated.url,
    });
  } catch (error) {
    sanitize(error);
  }
  fail();
}

export function createResolvedLookup(
  value,
  { allowTestAddresses = false } = {},
) {
  try {
    if (
      value === null ||
      typeof value !== "object" ||
      !Array.isArray(value.addresses) ||
      value.addresses.length === 0 ||
      typeof value.hostname !== "string"
    ) {
      fail();
    }
    if (typeof allowTestAddresses !== "boolean") fail();
    const hostname = value.hostname;
    const addresses = value.addresses.map((entry) =>
      validateAddressRecord(entry, allowTestAddresses),
    );
    return (requestedHostname, options, callback) => {
      try {
        if (
          requestedHostname !== hostname ||
          typeof callback !== "function" ||
          (options !== undefined &&
            typeof options !== "number" &&
            (options === null || typeof options !== "object"))
        ) {
          fail();
        }
        const all =
          typeof options === "object" && options !== null && options.all === true;
        const requestedFamily =
          typeof options === "number"
            ? options
            : typeof options === "object" && options !== null
              ? options.family ?? 0
              : 0;
        if (![0, 4, 6].includes(requestedFamily)) fail();
        const eligible =
          requestedFamily === 0
            ? addresses
            : addresses.filter((entry) => entry.family === requestedFamily);
        if (eligible.length === 0) fail();
        queueMicrotask(() => {
          if (all) callback(null, eligible.map((entry) => ({ ...entry })));
          else callback(null, eligible[0].address, eligible[0].family);
        });
      } catch (error) {
        const safeError =
          error?.message === "Public endpoint validation failed safely."
            ? error
            : new Error("Public endpoint validation failed safely.");
        queueMicrotask(() => callback?.(safeError));
      }
    };
  } catch (error) {
    sanitize(error);
  }
  fail();
}
