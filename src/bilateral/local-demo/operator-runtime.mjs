export const HYBRID_OPERATOR_STATUS_SCHEMA =
  "clockchain.hybrid-local-operator-status/v1";

const DEPENDENCY_KEYS = Object.freeze([
  "createStateRoot",
  "probeCoordinationEdge",
  "publishRequestorDiscovery",
  "runFunding",
  "startBootstrapBroker",
  "startConsole",
  "startCoordinator",
  "startPayer",
  "startPublicEdge",
  "startRelay",
  "waitForPayerMcpReady",
  "waitForPublicEdge",
  "writeFailureRecord",
  "writeStatus",
]);
const PATH_KEYS = Object.freeze([
  "bootstrapBrokerCapabilityFile",
  "bootstrapBrokerStateRoot",
  "payerStateRoot",
  "relayStateRoot",
  "releaseRoot",
]);
const SHA40 = /^[0-9a-f]{40}$/;
const RELEASE_ID = /^release-[0-9a-f]{16}$/;
const SESSION_ID =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

const MESSAGES = Object.freeze({
  BOOTSTRAP_APPROVED:
    "The Requestor bootstrap matched this release and was approved.",
  BOOTSTRAP_BROKER_LISTENING:
    "The private Requestor bootstrap broker is ready.",
  CONSOLE_LISTENING:
    "The local read-only operator console is ready.",
  COORDINATOR_RELEASE_CREATED:
    "The coordinator created one fresh release for the Payer and Requestor.",
  FUNDING_CONFIRMED:
    "Four fresh participant addresses were funded once through the replay-safe journal.",
  PAYER_MCP_READY:
    "The real Payer MCP is ready with the signed mandate protocol.",
  PAYER_SUPERVISOR_STARTED:
    "The Payer agent is running and preparing its mandate.",
  PUBLIC_EDGE_COORDINATION_READY:
    "The public coordination listener reaches the local authenticated relay.",
  PUBLIC_EDGE_READY:
    "Both public listeners reach the local TLS services with the expected certificate pins.",
  PUBLIC_EDGE_STARTED:
    "The transport-only public edge is connected.",
  RELAY_LISTENING:
    "The local authenticated coordination relay is listening.",
  REQUESTOR_DISCOVERY_PUBLISHED:
    "The signed public Requestor entry point is published.",
  REQUESTOR_HANDOFF_READY:
    "The Payer is ready. The stakeholder may now use the single Requestor prompt.",
  RUN_STOPPED_SAFELY:
    "The run stopped safely before authorization. Review the local operator log.",
  SERVICE_FAILED:
    "A required local service stopped unexpectedly. The run failed closed and left a private failure record.",
  STATE_ROOT_CREATED:
    "Fresh isolated operator and Payer state is ready.",
  VERIFICATION_PASSED:
    "Fresh independent verification passed. Open the public receipts for the result.",
});

export const SERVICE_NAMES = new Set([
  "bootstrap-broker",
  "console",
  "coordinator",
  "payer-supervisor",
  "public-edge",
  "relay",
]);

export class HybridOperatorRuntimeError extends Error {
  constructor() {
    super("Hybrid local operator stopped safely.");
    this.name = "HybridOperatorRuntimeError";
    this.code = "HYBRID_OPERATOR_RUN_FAILED";
    this.category = "protocol";
  }
}

function fail() {
  throw new HybridOperatorRuntimeError();
}

function plain(value) {
  return (
    value !== null &&
    typeof value === "object" &&
    !Array.isArray(value) &&
    Object.getPrototypeOf(value) === Object.prototype
  );
}

function exact(value, keys) {
  if (!plain(value)) fail();
  const own = Reflect.ownKeys(value);
  if (own.length !== keys.length || keys.some((key) => !own.includes(key))) {
    fail();
  }
  return value;
}

function dependencies(value) {
  const checked = exact(value, DEPENDENCY_KEYS);
  if (DEPENDENCY_KEYS.some((key) => typeof checked[key] !== "function")) fail();
  return checked;
}

function resource(value, extras = []) {
  if (!plain(value) || typeof value.stop !== "function") fail();
  for (const key of extras) {
    if (!Object.hasOwn(value, key)) fail();
  }
  return value;
}

function release(value, repositorySha) {
  if (
    !plain(value) ||
    value.paymentMoved !== false ||
    value.repositorySha !== repositorySha ||
    !RELEASE_ID.test(value.releaseId) ||
    !SESSION_ID.test(value.sessionId) ||
    !Array.isArray(value.manifests) ||
    value.manifests.length !== 2
  ) {
    fail();
  }
  const roles = value.manifests.map((entry) => entry?.role);
  if (
    roles.filter((role) => role === "payer").length !== 1 ||
    roles.filter((role) => role === "payee").length !== 1 ||
    value.manifests.some(
      (entry) =>
        !plain(entry) ||
        typeof entry.path !== "string" ||
        !entry.path.startsWith("/"),
    )
  ) {
    fail();
  }
  return value;
}

function configInput(value, stateRoot) {
  if (
    !plain(value) ||
    value.paymentMoved !== false ||
    typeof value.repositorySha !== "string" ||
    !SHA40.test(value.repositorySha) ||
    typeof value.payerMcp?.publicUrl !== "string" ||
    typeof value.publishing?.requestorDiscoveryUrl !== "string" ||
    typeof stateRoot !== "string" ||
    !stateRoot.startsWith("/") ||
    stateRoot === "/"
  ) {
    fail();
  }
  return value;
}

function privateCanaries(config, stateRoot) {
  return Object.freeze([
    stateRoot,
    config.funding?.journalDirectory,
    config.funding?.keystoreFile,
    config.operator?.clockchainTokenFile,
    config.operator?.privateKeyFile,
    config.operator?.rpcUrlFile,
    config.payerMcp?.tlsCertificateFile,
    config.payerMcp?.tlsPrivateKeyFile,
    config.publicEdge?.hostKeyFile,
    config.publicEdge?.identityFile,
    config.relay?.tlsCertificateFile,
    config.relay?.tlsPrivateKeyFile,
  ].filter((value) => typeof value === "string" && value.length > 0));
}

function publicStatus(stage, extra = {}) {
  if (!Object.hasOwn(MESSAGES, stage) || !plain(extra)) fail();
  const value = Object.freeze({
    message: MESSAGES[stage],
    paymentMoved: false,
    ...extra,
    schema: HYBRID_OPERATOR_STATUS_SCHEMA,
    stage,
  });
  if (Object.values(extra).some((entry) => typeof entry === "object")) fail();
  return value;
}

function validateStatus(value, canaries) {
  const serialized = JSON.stringify(value);
  if (
    serialized.includes("AUTHORIZED") ||
    canaries.some((canary) => serialized.includes(canary))
  ) {
    fail();
  }
}

async function stopResources(resources) {
  let failed = false;
  for (const current of [...resources].reverse()) {
    try {
      await current.stop();
    } catch {
      failed = true;
    }
  }
  if (failed) fail();
}

function checkedPaths(value) {
  const paths = exact(value, PATH_KEYS);
  if (PATH_KEYS.some((key) => typeof paths[key] !== "string" || !paths[key].startsWith("/"))) {
    fail();
  }
  return paths;
}

export async function runHybridLocalOperator(
  { config, stateRoot } = {},
  dependencyInput = {},
) {
  const resources = [];
  let activeDependencies = null;
  let canaries = Object.freeze([]);
  const emit = async (stage, extra = {}) => {
    const status = publicStatus(stage, extra);
    validateStatus(status, canaries);
    await activeDependencies.writeStatus(status);
  };
  let activeStateRoot = null;
  let stopping = false;
  let rejectDeath = null;
  const death = new Promise((_, reject) => {
    rejectDeath = reject;
  });
  // The death watch never rejects unhandled when the sequence settles first.
  death.catch(() => {});
  const watchService = (name, service) => {
    if (!SERVICE_NAMES.has(name) || typeof service.waitForExit !== "function") {
      fail();
    }
    Promise.resolve(service.waitForExit()).then(async (code) => {
      // Clean exits stay with the protocol gates; supervision only converts
      // abnormal mid-run exits into an immediate, named, fail-closed stop.
      if (stopping || code === 0) return;
      stopping = true;
      let stderrTail = "";
      if (typeof service.readStderrTail === "function") {
        try {
          const tail = service.readStderrTail();
          if (typeof tail === "string") stderrTail = tail.slice(-4096);
        } catch {
          stderrTail = "";
        }
      }
      try {
        await activeDependencies.writeFailureRecord(Object.freeze({
          exitCode: code === null ? "signal" : code,
          service: name,
          stateRoot: activeStateRoot,
          stderrTail,
        }));
      } catch {
        // The failure record is diagnostic only; the public stop proceeds.
      }
      try {
        await emit("SERVICE_FAILED", { service: name });
      } catch {
        // The terminal safe failure remains the fixed public outcome.
      }
      rejectDeath(new HybridOperatorRuntimeError());
    });
  };
  const track = (name, service) => {
    resources.push(service);
    watchService(name, service);
    return service;
  };

  const sequence = async (activeConfig, activeStateRoot) => {
    canaries = privateCanaries(activeConfig, activeStateRoot);

    const paths = checkedPaths(
      await activeDependencies.createStateRoot({
        config: activeConfig,
        stateRoot,
      }),
    );
    await emit("STATE_ROOT_CREATED");

    const relay = resource(
      await activeDependencies.startRelay({ config: activeConfig, paths }),
    );
    track("relay", relay);
    await emit("RELAY_LISTENING");

    const edge = resource(
      await activeDependencies.startPublicEdge({ config: activeConfig, paths }),
    );
    track("public-edge", edge);
    await emit("PUBLIC_EDGE_STARTED");

    const coordinationReady = await activeDependencies.probeCoordinationEdge({
      config: activeConfig,
      paths,
    });
    if (coordinationReady?.paymentMoved !== false || coordinationReady.ready !== true) fail();
    await emit("PUBLIC_EDGE_COORDINATION_READY");

    const coordinator = resource(
      await activeDependencies.startCoordinator({ config: activeConfig, paths }),
      ["release", "waitForTerminal"],
    );
    if (typeof coordinator.waitForTerminal !== "function") fail();
    const activeRelease = release(coordinator.release, activeConfig.repositorySha);
    track("coordinator", coordinator);
    await emit("COORDINATOR_RELEASE_CREATED");

    const consoleServer = resource(
      await activeDependencies.startConsole({
        config: activeConfig,
        paths,
        release: activeRelease,
      }),
    );
    track("console", consoleServer);
    await emit("CONSOLE_LISTENING");

    const broker = resource(
      await activeDependencies.startBootstrapBroker({
        config: activeConfig,
        paths,
        release: activeRelease,
      }),
      ["approveRequestor", "capabilityFile", "url"],
    );
    if (
      typeof broker.approveRequestor !== "function" ||
      typeof broker.capabilityFile !== "string" ||
      typeof broker.url !== "string"
    ) {
      fail();
    }
    track("bootstrap-broker", broker);
    await emit("BOOTSTRAP_BROKER_LISTENING");

    const payer = resource(
      await activeDependencies.startPayer({
        broker,
        config: activeConfig,
        paths,
        release: activeRelease,
      }),
    );
    track("payer-supervisor", payer);
    await emit("PAYER_SUPERVISOR_STARTED");

    const payerReady = await activeDependencies.waitForPayerMcpReady({
      config: activeConfig,
      payer,
      release: activeRelease,
    });
    if (
      payerReady?.paymentMoved !== false ||
      payerReady.status !== "PAYER_MCP_READY" ||
      payerReady.url !== activeConfig.payerMcp.publicUrl
    ) {
      fail();
    }
    await emit("PAYER_MCP_READY");

    const edgeReady = await activeDependencies.waitForPublicEdge({
      config: activeConfig,
      release: activeRelease,
    });
    if (
      edgeReady?.paymentMoved !== false ||
      edgeReady.coordinationReady !== true ||
      edgeReady.payerMcpReady !== true
    ) {
      fail();
    }
    await emit("PUBLIC_EDGE_READY");

    const discovery = await activeDependencies.publishRequestorDiscovery({
      config: activeConfig,
      release: activeRelease,
    });
    if (
      discovery?.paymentMoved !== false ||
      discovery.discoveryUrl !== activeConfig.publishing.requestorDiscoveryUrl
    ) {
      fail();
    }
    await emit("REQUESTOR_DISCOVERY_PUBLISHED");
    await emit("REQUESTOR_HANDOFF_READY", {
      payerMcpUrl: activeConfig.payerMcp.publicUrl,
      repositorySha: activeConfig.repositorySha,
      requestorDiscoveryUrl: discovery.discoveryUrl,
    });

    const approval = await broker.approveRequestor({
      config: activeConfig,
      release: activeRelease,
    });
    if (approval?.paymentMoved !== false || approval.status !== "APPROVED") fail();
    await emit("BOOTSTRAP_APPROVED");

    const funding = await activeDependencies.runFunding({
      config: activeConfig,
      paths,
      release: activeRelease,
    });
    if (
      funding?.paymentMoved !== false ||
      funding.status !== "FUNDING_CONFIRMED"
    ) {
      fail();
    }
    await emit("FUNDING_CONFIRMED");

    const terminal = await coordinator.waitForTerminal();
    if (
      terminal?.paymentMoved !== false ||
      terminal.status !== "VERIFICATION_PASSED"
    ) {
      fail();
    }
    stopping = true;
    await stopResources(resources);
    resources.length = 0;
    await emit("VERIFICATION_PASSED");
    return Object.freeze({
      paymentMoved: false,
      status: "VERIFICATION_PASSED",
    });
  };

  try {
    activeDependencies = dependencies(dependencyInput);
    const activeConfig = configInput(config, stateRoot);
    activeStateRoot = stateRoot;
    return await Promise.race([sequence(activeConfig, stateRoot), death]);
  } catch {
    stopping = true;
    try {
      await stopResources(resources);
    } catch {
      // The fixed terminal status remains non-authorizing after cleanup failure.
    }
    if (activeDependencies !== null) {
      try {
        await emit("RUN_STOPPED_SAFELY");
      } catch {
        // There is no secondary output path when the configured writer fails.
      }
    }
    fail();
  }
}
