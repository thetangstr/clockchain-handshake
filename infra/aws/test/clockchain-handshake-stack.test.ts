import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { test } from "node:test";

import {
  App,
} from "aws-cdk-lib";
import {
  Match,
  Template,
} from "aws-cdk-lib/assertions";

const { buildCoordinatorRuntimeInput } =
  (await import(
    // @ts-expect-error The runtime entrypoint helper is JavaScript; this test supplies the checked shape below.
    "../runtime/operator-task-inputs.mjs"
  )) as {
    buildCoordinatorRuntimeInput: (
      value: unknown,
    ) => unknown;
  };

import {
  ClockchainHandshakeStack,
  ClockchainHandshakeImagesStack,
} from "../lib/clockchain-handshake-stack.js";

const IMAGE =
  "123456789012.dkr.ecr.us-west-2.amazonaws.com/clockchain@sha256:" +
  "a".repeat(64);
const RELAY_TLS_CERTIFICATE_PEM = `-----BEGIN CERTIFICATE-----
MIIBdDCCASagAwIBAgIUPrXOrIpEJb7MiFXU0DDWShb37kIwBQYDK2VwMB8xHTAb
BgNVBAMMFHJlbGF5LmNsb2NrY2hhaW4ubmV0MB4XDTI2MDczMTIyNDIyN1oXDTI2
MDgwMTIyNDIyN1owHzEdMBsGA1UEAwwUcmVsYXkuY2xvY2tjaGFpbi5uZXQwKjAF
BgMrZXADIQDwMVNUm7k6YU4Ra2V4wCNd0g55HJvSHdDe25+8kjDieaN0MHIwHQYD
VR0OBBYEFMWEqIIWZMtV/0sLBCI8b/LPLlxKMB8GA1UdIwQYMBaAFMWEqIIWZMtV
/0sLBCI8b/LPLlxKMA8GA1UdEwEB/wQFMAMBAf8wHwYDVR0RBBgwFoIUcmVsYXku
Y2xvY2tjaGFpbi5uZXQwBQYDK2VwA0EAaeNXc+Bk8jhlk7JOWlWPgajcq14EO03b
GzRaxazJRJqgomGuhMdWNo8pqbWf9+sUnkkr9ZGuAGcK3zyS6UeHDA==
-----END CERTIFICATE-----
`;
const RELAY_TLS_FINGERPRINT =
  "3dbe9d0ea7491d9d6e4586f978ddf2b67c4ac173780b3b8d5b86def84a0d73d9";
const SESSION_ID =
  "11111111-1111-4111-8111-111111111111";
const RELEASE_ID =
  `release-${createHash("sha256")
    .update(SESSION_ID, "utf8")
    .digest("hex")
    .slice(0, 16)}`;
const RELAY_TLS_SECRET_ARN =
  "arn:aws:secretsmanager:us-west-2:123456789012:secret:clockchain-relay-tls-AbCdEf";
const STACK_PROPS = {
  bootstrapBrokerCapabilityDigest:
    "c".repeat(64),
  controlPlaneImage: IMAGE,
  operatorPublicKey:
    "oIcoZqI/cqzG4UbXcaV+k1fxwt8EBb+9S+XNcb9pq3k=",
  relayTlsCertificatePem:
    RELAY_TLS_CERTIFICATE_PEM,
  relayTlsFingerprint:
    RELAY_TLS_FINGERPRINT,
  relayPublicHostname:
    "relay.clockchain.net",
  relayTlsSecretArn: RELAY_TLS_SECRET_ARN,
  receiptSenderEmail:
    "receipts@clockchain.network",
  repositorySha:
    "abcdef0123456789abcdef0123456789abcdef01",
  sessionId: SESSION_ID,
  sourceTreeSha256: "e".repeat(64),
  tunnelHostKeyFingerprint:
    "SHA256:UgP8WeC7EtU7Ik6LFbMNeUckAOfLBKJvnaP1ez/1MwU",
  tunnelHostPublicKey:
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILzWMEVEge8QmmJQH5at7CDm9iuX7O4hop0rjeJ95xnC",
  tunnelImage: IMAGE.replace(
    /a+$/,
    "b".repeat(64),
  ),
} as const;

test("rejects a relay certificate that does not cover the public hostname", () => {
  const app = new App();
  assert.throws(
    () =>
      new ClockchainHandshakeStack(
        app,
        "HostnameMismatchStack",
        {
          ...STACK_PROPS,
          env: {
            account: "123456789012",
            region: "us-west-2",
          },
          relayPublicHostname:
            "other.clockchain.net",
        },
      ),
    /hostname/i,
  );
});

test("rejects a tunnel host public key that does not match its fingerprint", () => {
  const app = new App();
  assert.throws(
    () =>
      new ClockchainHandshakeStack(
        app,
        "TunnelHostMismatchStack",
        {
          ...STACK_PROPS,
          env: {
            account: "123456789012",
            region: "us-west-2",
          },
          tunnelHostKeyFingerprint:
            "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        },
      ),
    /tunnel host/i,
  );
});

test("imports reviewed relay TLS material without synthesizing private key data", () => {
  const output = template().toJSON();
  const secrets = Object.entries(
    output.Resources ?? {},
  ).filter(
    ([, resource]) =>
      (resource as { Type?: string }).Type ===
      "AWS::SecretsManager::Secret",
  );
  assert.equal(
    secrets.some(([logicalId]) =>
      logicalId.startsWith("RelayTls")),
    false,
  );
  assert.match(
    JSON.stringify(output),
    new RegExp(RELAY_TLS_SECRET_ARN),
  );
  assert.doesNotMatch(
    JSON.stringify(output),
    /privateKeyPem/,
  );
});

test("creates immutable bootstrap image repositories independently of runtime images", () => {
  const app = new App();
  const output = Template.fromStack(
    new ClockchainHandshakeImagesStack(
      app,
      "ImageTestStack",
      {
        env: {
          account: "123456789012",
          region: "us-west-2",
        },
      },
    ),
  );
  output.resourceCountIs(
    "AWS::ECR::Repository",
    2,
  );
  output.hasResourceProperties(
    "AWS::ECR::Repository",
    {
      ImageScanningConfiguration: {
        ScanOnPush: true,
      },
      ImageTagMutability: "IMMUTABLE",
      RepositoryName:
        "clockchain-handshake-control-plane",
    },
  );
});

function template(): Template {
  const app = new App();
  return Template.fromStack(
    new ClockchainHandshakeStack(
      app,
      "TestStack",
      {
        activateServices: true,
        ...STACK_PROPS,
        env: {
          account: "123456789012",
          region: "us-west-2",
        },
      },
    ),
  );
}

function rendered(value: unknown): string {
  if (typeof value === "string") return value;
  if (
    value !== null &&
    typeof value === "object" &&
    "Fn::Join" in value
  ) {
    const [separator, parts] = (
      value as {
        "Fn::Join": [string, unknown[]];
      }
    )["Fn::Join"];
    return parts.map(rendered).join(separator);
  }
  if (
    value !== null &&
    typeof value === "object" &&
    "Ref" in value
  ) {
    return `\${Ref:${String(
      (value as { Ref: unknown }).Ref,
    )}}`;
  }
  if (
    value !== null &&
    typeof value === "object" &&
    "Fn::GetAtt" in value
  ) {
    return `\${GetAtt:${(
      value as { "Fn::GetAtt": unknown[] }
    )["Fn::GetAtt"].join(".")}}`;
  }
  return JSON.stringify(value);
}

test("keeps every long-lived service stopped until runtime activation is explicit", () => {
  const app = new App();
  const output = Template.fromStack(
    new ClockchainHandshakeStack(
      app,
      "InactiveStack",
      {
        activateServices: false,
        ...STACK_PROPS,
        env: {
          account: "123456789012",
          region: "us-west-2",
        },
      },
    ),
  );
  const resources = output.findResources(
    "AWS::ECS::Service",
  );
  assert.equal(
    Object.keys(resources).length,
    5,
  );
  for (const resource of Object.values(
    resources,
  )) {
    assert.equal(
      resource.Properties.DesiredCount,
      0,
    );
  }
});

test("permits regional CloudWatch Logs to use the customer-managed data key", () => {
  const resources = template().toJSON()
    .Resources as Record<
    string,
    {
      Properties?: {
        KeyPolicy?: unknown;
      };
      Type: string;
    }
  >;
  const key = Object.values(resources).find(
    (resource) =>
      resource.Type === "AWS::KMS::Key",
  );
  assert.ok(key?.Properties?.KeyPolicy);
  const policy = JSON.stringify(
    key.Properties.KeyPolicy,
  );
  assert.match(policy, /logs\./);
  assert.match(policy, /kms:Encrypt/);
  assert.match(policy, /kms:GenerateDataKey/);
  assert.match(policy, /kms:Decrypt/);
});

test("creates a two-AZ no-NAT public Fargate foundation with encrypted EFS", () => {
  const output = template();
  output.resourceCountIs("AWS::EC2::VPC", 1);
  output.resourceCountIs(
    "AWS::EC2::NatGateway",
    0,
  );
  output.resourceCountIs("AWS::ECS::Cluster", 1);
  output.hasResourceProperties(
    "AWS::EFS::FileSystem",
    {
      Encrypted: true,
    },
  );
  output.resourceCountIs(
    "AWS::EFS::AccessPoint",
    12,
  );
  output.hasResourceProperties(
    "AWS::ECS::Service",
    {
      DeploymentConfiguration: {
        DeploymentCircuitBreaker: {
          Enable: true,
          Rollback: true,
        },
      },
      DesiredCount: 1,
      NetworkConfiguration: {
        AwsvpcConfiguration: {
          AssignPublicIp: "ENABLED",
        },
      },
    },
  );
});

test("exposes only the fixed raw TCP and private bootstrap listener topology", () => {
  const output = template();
  for (const port of [443, 9443, 8443, 9555]) {
    output.hasResourceProperties(
      "AWS::ElasticLoadBalancingV2::Listener",
      { Port: port },
    );
  }
  output.hasResourceProperties(
    "AWS::ElasticLoadBalancingV2::TargetGroup",
    {
      HealthCheckPort: "8080",
      HealthCheckPath: "/host",
      HealthCheckProtocol: "HTTP",
      Port: 2222,
      Protocol: "TCP",
      TargetType: "ip",
    },
  );
  output.hasResourceProperties(
    "AWS::ElasticLoadBalancingV2::TargetGroup",
    {
      HealthCheckPort: "8080",
      HealthCheckPath: "/host",
      HealthCheckProtocol: "HTTP",
      Port: 9443,
      Protocol: "TCP",
      TargetType: "ip",
    },
  );
  output.hasResourceProperties(
    "AWS::ElasticLoadBalancingV2::LoadBalancer",
    {
      Scheme: "internal",
      Type: "network",
    },
  );
});

test("creates the exact bootstrap routes and a separate Cognito-authorized operator API", () => {
  const output = template();
  for (const routeKey of [
    "POST /v1/payer-claims",
    "GET /v1/payer-claims/{claimId}",
    "POST /v1/requestor-claims",
    "GET /v1/requestor-claims/{claimId}",
    "GET /health",
  ]) {
    output.hasResourceProperties(
      "AWS::ApiGatewayV2::Route",
      { RouteKey: routeKey },
    );
  }
  output.hasResourceProperties(
    "AWS::ApiGatewayV2::Route",
    {
      AuthorizationType: "JWT",
      RouteKey: "POST /v1/actions",
    },
  );
  output.resourceCountIs(
    "AWS::Cognito::UserPool",
    1,
  );
  output.hasResourceProperties(
    "AWS::Cognito::UserPoolClient",
    {
      AllowedOAuthFlows: [
        "code",
      ],
      AllowedOAuthFlowsUserPoolClient:
        true,
      GenerateSecret: false,
    },
  );
  output.resourceCountIs(
    "AWS::SQS::Queue",
    1,
  );
  output.resourceCountIs(
    "AWS::DynamoDB::Table",
    2,
  );
});

test("creates the bounded public receipt-email delivery boundary", () => {
  const output = template();
  output.hasResourceProperties(
    "AWS::ApiGatewayV2::Route",
    { RouteKey: "POST /v1/receipt-email" },
  );
  output.hasResourceProperties(
    "AWS::Lambda::Function",
    {
      Environment: {
        Variables: Match.objectLike({
          ALLOWED_ORIGIN:
            "https://clockchain-research.vercel.app",
          PUBLIC_BUCKET_NAME:
            Match.anyValue(),
          RECEIPT_DELIVERY_TABLE_NAME:
            Match.anyValue(),
          RECEIPT_SENDER_EMAIL:
            "receipts@clockchain.network",
        }),
      },
      MemorySize: 256,
      Runtime: "nodejs22.x",
      Timeout: 10,
    },
  );
  const receiptFunctions = output.findResources(
    "AWS::Lambda::Function",
    {
      Properties: {
        Environment: {
          Variables: Match.objectLike({
            RECEIPT_DELIVERY_TABLE_NAME:
              Match.anyValue(),
          }),
        },
      },
    },
  );
  assert.equal(
    Object.values(receiptFunctions).length,
    1,
  );
  const [receiptFunction] =
    Object.values(receiptFunctions);
  assert.ok(receiptFunction);
  assert.equal(
    Object.hasOwn(
      receiptFunction.Properties,
      "ReservedConcurrentExecutions",
    ),
    false,
  );
  output.hasResourceProperties(
    "AWS::DynamoDB::Table",
    {
      BillingMode: "PAY_PER_REQUEST",
      TimeToLiveSpecification: {
        AttributeName: "ttl",
        Enabled: true,
      },
    },
  );
  output.hasResourceProperties(
    "AWS::ApiGatewayV2::Stage",
    {
      DefaultRouteSettings: {
        ThrottlingBurstLimit: 4,
        ThrottlingRateLimit: 2,
      },
    },
  );
});

test("creates private console and monitor distributions, immutable images, logs, alarms, dashboard, and handoff outputs", () => {
  const output = template();
  output.resourceCountIs("AWS::S3::Bucket", 2);
  output.resourceCountIs(
    "AWS::CloudFront::Distribution",
    2,
  );
  output.resourceCountIs(
    "Custom::CDKBucketDeployment",
    1,
  );
  const json = output.toJSON();
  const resources = (json.Resources ??
    {}) as Record<
    string,
    {
      Properties?: unknown;
      Type?: string;
    }
  >;
  const taskDefinitions = Object.values(
    resources,
  ).filter(
    (resource) =>
      resource.Type ===
      "AWS::ECS::TaskDefinition",
  ) as Array<{
    Properties: {
      ContainerDefinitions: Array<{
        Image: unknown;
        ReadonlyRootFilesystem?: boolean;
      }>;
      NetworkMode: string;
      RequiresCompatibilities: string[];
    };
  }>;
  assert.equal(taskDefinitions.length, 10);
  for (const task of taskDefinitions) {
    assert.equal(
      task.Properties.NetworkMode,
      "awsvpc",
    );
    assert.deepEqual(
      task.Properties.RequiresCompatibilities,
      ["FARGATE"],
    );
    for (const container of
      task.Properties.ContainerDefinitions) {
      assert.equal(
        container.ReadonlyRootFilesystem,
        true,
      );
      assert.match(
        JSON.stringify(container.Image),
        /sha256:[0-9a-f]{64}/,
      );
    }
  }
  output.resourceCountIs(
    "AWS::Logs::LogGroup",
    12,
  );
  output.resourceCountIs(
    "AWS::CloudWatch::Alarm",
    6,
  );
  output.resourceCountIs(
    "AWS::CloudWatch::Dashboard",
    1,
  );
  const outputs = Object.keys(
    json.Outputs ?? {},
  );
  for (const prefix of [
    "BootstrapApiUrl",
    "ControlApiUrl",
    "OperatorConsoleUrl",
    "PublicMonitorUrl",
    "RelayEndpoint",
    "PayerMcpEndpoint",
    "ReceiptEmailApiUrl",
    "ReceiptSenderEmail",
    "TaskDefinitions",
    "SecretArns",
  ]) {
    assert.equal(
      outputs.some((key) =>
        key.startsWith(prefix)),
      true,
      prefix,
    );
  }
});

test("pins every AWS workload to its role-specific production entrypoint", () => {
  const resources = template().toJSON()
    .Resources as Record<
    string,
    {
      Properties?: {
        ContainerDefinitions?: Array<{
          Command?: string[];
          Name?: string;
        }>;
      };
      Type: string;
    }
  >;
  const commands = new Map(
    Object.entries(resources)
      .filter(
        ([, resource]) =>
          resource.Type ===
          "AWS::ECS::TaskDefinition",
      )
      .map(([logicalId, resource]) => {
        const container =
          resource.Properties
            ?.ContainerDefinitions?.[0];
        assert.ok(container);
        return [
          logicalId.replace(
            /Task[0-9A-F]+$/,
            "",
          ),
          container.Command,
        ];
      }),
  );
  assert.deepEqual(
    Object.fromEntries(commands),
    {
      Bootstrap: [
        "node",
        "infra/aws/runtime/bootstrap-entrypoint.mjs",
      ],
      BootstrapApproval: [
        "node",
        "infra/aws/runtime/operator-bootstrap-approval-entrypoint.mjs",
      ],
      AbortTunnel: [
        "node",
        "infra/aws/runtime/operator-abort-entrypoint.mjs",
      ],
      Coordinator: [
        "node",
        "infra/aws/runtime/coordinator-entrypoint.mjs",
      ],
      Funding: [
        "node",
        "infra/aws/runtime/funding-entrypoint.mjs",
      ],
      Operator: [
        "node",
        "infra/aws/runtime/operator-worker-entrypoint.mjs",
      ],
      Publisher: [
        "node",
        "infra/aws/runtime/publisher-entrypoint.mjs",
      ],
      Relay: [
        "node",
        "infra/aws/runtime/relay-entrypoint.mjs",
      ],
      Tunnel: [
        "node",
        "infra/aws/runtime/tunnel-entrypoint.mjs",
      ],
      Verifier: [
        "node",
        "infra/aws/runtime/verifier-entrypoint.mjs",
      ],
    },
  );
});

test("runs the coordinator as the operator access-point owner", () => {
  const output = template();
  output.hasResourceProperties(
    "AWS::EFS::AccessPoint",
    {
      PosixUser: {
        Gid: "1104",
        Uid: "1104",
      },
      RootDirectory: {
        Path: "/clockchain/operator",
      },
    },
  );
  output.hasResourceProperties(
    "AWS::ECS::TaskDefinition",
    {
      ContainerDefinitions: Match.arrayWith([
        Match.objectLike({
          Command: [
            "node",
            "infra/aws/runtime/coordinator-entrypoint.mjs",
          ],
          User: "1104:1104",
        }),
      ]),
    },
  );
});

test("emits relay runtime keys in the entrypoint's exact canonical order", () => {
  const resources = template().toJSON()
    .Resources as Record<
    string,
    {
      Properties?: {
        ContainerDefinitions?: Array<{
          Environment?: unknown;
        }>;
      };
      Type: string;
    }
  >;
  const relay = Object.entries(resources).find(
    ([logicalId, resource]) =>
      logicalId.startsWith("RelayTask") &&
      resource.Type ===
        "AWS::ECS::TaskDefinition",
  )?.[1];
  assert.notEqual(relay, undefined);
  const environment = JSON.stringify(
    relay?.Properties?.ContainerDefinitions?.[0]
      ?.Environment,
  );
  const fingerprint = environment.indexOf(
    '\\"tlsFingerprint\\"',
  );
  const secret = environment.indexOf(
    '\\"tlsSecretArn\\"',
  );
  assert.notEqual(fingerprint, -1);
  assert.notEqual(secret, -1);
  assert.equal(fingerprint < secret, true);
  assert.match(
    environment,
    /relay\.clockchain\.net/,
  );
});

test("configures long-lived bootstrap and publisher startup inputs", () => {
  const resources = template().toJSON()
    .Resources as Record<
    string,
    {
      Properties?: {
        ContainerDefinitions?: Array<{
          Environment?: Array<{
            Name?: string;
            Value?: unknown;
          }>;
        }>;
      };
      Type: string;
    }
  >;
  const environment = (prefix: string) =>
    Object.entries(resources).find(
      ([logicalId, resource]) =>
        logicalId.startsWith(prefix) &&
        resource.Type ===
          "AWS::ECS::TaskDefinition",
    )?.[1].Properties?.ContainerDefinitions?.[0]
      ?.Environment ?? [];
  const bootstrap = environment("BootstrapTask");
  assert.deepEqual(
    bootstrap.find(
      (item) =>
        item.Name ===
        "AWS_BOOTSTRAP_CLAIM_EXPIRES_AFTER_MS",
    ),
    {
      Name:
        "AWS_BOOTSTRAP_CLAIM_EXPIRES_AFTER_MS",
      Value: "1800000",
    },
  );
  const publisher = environment("PublisherTask");
  const runtimeInput = publisher.find(
    (item) => item.Name === "AWS_RUNTIME_INPUT",
  );
  assert.notEqual(runtimeInput, undefined);
  const publisherRuntime = JSON.parse(
    rendered(runtimeInput?.Value),
  ) as {
    publisher: {
      bucketName: unknown;
      paymentMoved: boolean;
      publicBaseUrl: unknown;
      publicationInputPath: string;
      schema: string;
      stagedPaths: Record<string, string>;
    };
  };
  const publicRoot =
    `/var/lib/clockchain/public/releases/${RELEASE_ID}`;
  assert.deepEqual(
    publisherRuntime.publisher,
    {
      bucketName:
        publisherRuntime.publisher.bucketName,
      paymentMoved: false,
      publicBaseUrl:
        publisherRuntime.publisher.publicBaseUrl,
      publicationInputPath:
        `${publicRoot}/publisher-input.json`,
      schema:
        "clockchain.aws-publisher-runtime/v1",
      stagedPaths: {
        certificate:
          `${publicRoot}/payer-mcp.crt`,
        payerDiscovery:
          `${publicRoot}/payer.json`,
        publicationGate:
          `${publicRoot}/publication-gate.json`,
        requestorDiscovery:
          `${publicRoot}/requestor.json`,
      },
    },
  );
  const operator = environment("OperatorTask");
  const operatorRuntimeInput = operator.find(
    (item) => item.Name === "AWS_RUNTIME_INPUT",
  );
  assert.notEqual(
    operatorRuntimeInput,
    undefined,
  );
  const operatorRuntime = JSON.stringify(
    operatorRuntimeInput?.Value,
  );
  assert.match(
    operatorRuntime,
    /\\"publicMonitorBucketName\\"/,
  );
  assert.match(
    operatorRuntime,
    /\\"publicMonitorControlKey\\":\\"control\.json\\"/,
  );
  const operatorRuntimeValue = JSON.parse(
    rendered(operatorRuntimeInput?.Value),
  ) as {
    operator: {
      bootstrap: {
        payeeLaunchManifestPath: string;
        payerLaunchManifestPath: string;
      };
    };
  };
  const operatorReleaseRoot =
    `/var/lib/clockchain/operator/releases/${RELEASE_ID}`;
  assert.equal(
    operatorRuntimeValue.operator.bootstrap
      .payerLaunchManifestPath,
    `${operatorReleaseRoot}/payer.launch.json`,
  );
  assert.equal(
    operatorRuntimeValue.operator.bootstrap
      .payeeLaunchManifestPath,
    `${operatorReleaseRoot}/payee.launch.json`,
  );
});

test("configures trusted public staging inputs without leaking private tunnel key material", () => {
  const resources = template().toJSON()
    .Resources as Record<
    string,
    {
      Properties?: {
        ContainerDefinitions?: Array<{
          Environment?: Array<{
            Name?: string;
            Value?: unknown;
          }>;
        }>;
      };
      Type: string;
    }
  >;
  const environment = (prefix: string) =>
    Object.entries(resources).find(
      ([logicalId, resource]) =>
        logicalId.startsWith(prefix) &&
        resource.Type ===
          "AWS::ECS::TaskDefinition",
    )?.[1].Properties?.ContainerDefinitions?.[0]
      ?.Environment ?? [];
  const value = (prefix: string, name: string) =>
    environment(prefix).find(
      (item) => item.Name === name,
    )?.Value;
  const publicRoot =
    `/var/lib/clockchain/public/releases/${RELEASE_ID}`;
  assert.equal(
    value("TunnelTask", "AWS_TUNNEL_HEALTH_PATH"),
    `/var/lib/clockchain/health/releases/${RELEASE_ID}/tunnel-health.json`,
  );
  const operatorRuntime = JSON.parse(
    rendered(
      value(
        "OperatorTask",
        "AWS_RUNTIME_INPUT",
      ),
    ),
  ) as {
    operator: {
      bootstrap: Record<string, unknown>;
      coordinator: {
        publicStaging?: Record<string, unknown>;
      };
    };
  };
  assert.equal(
    operatorRuntime.operator.bootstrap
      .approvedPayerPublicPath,
    `/var/lib/clockchain/approved-payer/releases/${RELEASE_ID}/approved-payer.json`,
  );
  const coordinatorRuntime = JSON.parse(
    rendered(
      value(
        "CoordinatorTask",
        "AWS_RUNTIME_INPUT",
      ),
    ),
  ) as {
    coordinator: {
      publicStaging: {
        bootstrapPayerClaimUrl: string;
        publicBaseUrl: unknown;
      } & Record<string, unknown>;
    };
  };
  assert.match(
    coordinatorRuntime.coordinator.publicStaging
      .bootstrapPayerClaimUrl,
    /v1\/payer-claims$/,
  );
  assert.deepEqual(
    operatorRuntime.operator.coordinator
      .publicStaging,
    coordinatorRuntime.coordinator.publicStaging,
  );
  assert.deepEqual(
    coordinatorRuntime.coordinator.publicStaging,
    {
      approvedPayerPublicPath:
        `/var/lib/clockchain/approved-payer/releases/${RELEASE_ID}/approved-payer.json`,
      bootstrapPayerClaimUrl:
        coordinatorRuntime.coordinator.publicStaging
          .bootstrapPayerClaimUrl,
      imageDigest: STACK_PROPS.controlPlaneImage,
      paths: {
        certificate:
          `${publicRoot}/payer-mcp.crt`,
        gate: `${publicRoot}/publication-gate.json`,
        input:
          `${publicRoot}/publisher-input.json`,
        payer: `${publicRoot}/payer.json`,
        requestor:
          `${publicRoot}/requestor.json`,
      },
      publicBaseUrl:
        coordinatorRuntime.coordinator.publicStaging
          .publicBaseUrl,
      publicMcpHostname:
        "relay.clockchain.net",
      publicMcpUrl:
        "https://relay.clockchain.net:9443/mcp",
      tunnelHealthPath:
        `/var/lib/clockchain/tunnel-health/releases/${RELEASE_ID}/tunnel-health.json`,
      tunnelHostKeyFingerprint:
        STACK_PROPS.tunnelHostKeyFingerprint,
      tunnelHostPublicKey:
        STACK_PROPS.tunnelHostPublicKey,
    },
  );
  const emittedPublicStaging = {
    ...operatorRuntime.operator.coordinator
      .publicStaging,
    bootstrapPayerClaimUrl:
      "https://bootstrap.clockchain.net/v1/payer-claims",
    publicBaseUrl:
      "https://public.clockchain.net/",
  };
  assert.match(
    String(
      operatorRuntime.operator.coordinator
        .publicStaging?.publicBaseUrl,
    ),
    /^https:\/\/\$\{GetAtt:[^}]+\.DomainName\}\/$/,
  );
  assert.doesNotThrow(() =>
    buildCoordinatorRuntimeInput({
      clockchainTokenSecretArn:
        "arn:aws:secretsmanager:us-west-2:123456789012:secret:clockchain-token-AbCdEf",
      operatorKeyId:
        "clockchain-demo-2026",
      operatorKeySecretArn:
        "arn:aws:secretsmanager:us-west-2:123456789012:secret:operator-key-AbCdEf",
      paymentMoved: false,
      provenance: {
        imageDigest:
          STACK_PROPS.controlPlaneImage.split("@")[1],
        operatorPublicKey:
          STACK_PROPS.operatorPublicKey,
        repositorySha:
          STACK_PROPS.repositorySha,
        sourceTreeSha256:
          STACK_PROPS.sourceTreeSha256,
      },
      publicStaging: emittedPublicStaging,
      releaseId: RELEASE_ID,
      releaseRoot:
        `/var/lib/clockchain/operator/releases/${RELEASE_ID}`,
      relayUrl:
        "https://relay.clockchain.net:8443",
      repositorySha:
        STACK_PROPS.repositorySha,
      rpcSecretArn:
        "arn:aws:secretsmanager:us-west-2:123456789012:secret:sepolia-rpc-AbCdEf",
      sessionId: SESSION_ID,
      tlsCertificatePem:
        STACK_PROPS.relayTlsCertificatePem,
      tlsFingerprint:
        STACK_PROPS.relayTlsFingerprint,
    }),
  );
  const serialized = JSON.stringify(
    coordinatorRuntime,
  );
  assert.doesNotMatch(
    serialized,
    /TUNNEL_HOST_KEY_SECRET_ARN|privateKey/i,
  );
});

test("grants operator only control snapshot publication and enables narrow public monitor CORS", () => {
  const resources = template().toJSON()
    .Resources as Record<
    string,
    {
      Properties?: Record<string, unknown>;
      Type: string;
    }
  >;
  const policies = Object.values(
    resources,
  ).filter(
    (resource) =>
      resource.Type === "AWS::IAM::Policy",
  );
  const putObjectStatements = policies.flatMap(
    (policy) => {
      const document = policy.Properties
        ?.PolicyDocument as
        | {
            Statement?: Array<
              Record<string, unknown>
            >;
          }
        | undefined;
      return (
        document?.Statement?.filter(
          (statement) =>
            JSON.stringify(
              statement.Action,
            ).includes("s3:PutObject") &&
            JSON.stringify(
              statement.Resource,
            ).includes("control.json"),
        ) ?? []
      );
    },
  );
  assert.equal(putObjectStatements.length, 1);
  assert.deepEqual(
    putObjectStatements[0]?.Action,
    "s3:PutObject",
  );
  assert.equal(
    JSON.stringify(
      putObjectStatements[0]?.Resource,
    ).includes("/*"),
    false,
  );

  const corsPolicies = Object.entries(
    resources,
  ).filter(
    ([logicalId, resource]) =>
      logicalId.startsWith(
        "PublicMonitorCorsPolicy",
      ) &&
      resource.Type ===
        "AWS::CloudFront::ResponseHeadersPolicy",
  );
  assert.equal(corsPolicies.length, 1);
  const operatorDistributionEntry =
    Object.entries(resources).find(
      ([logicalId, resource]) =>
        logicalId.startsWith(
          "OperatorConsoleDistribution",
        ) &&
        resource.Type ===
          "AWS::CloudFront::Distribution",
    );
  assert.notEqual(
    operatorDistributionEntry,
    undefined,
  );
  const corsConfig = corsPolicies[0]?.[1]
    .Properties
    ?.ResponseHeadersPolicyConfig as {
    CorsConfig?: {
      AccessControlAllowCredentials?: boolean;
      AccessControlAllowMethods?: {
        Items?: string[];
      };
      AccessControlAllowOrigins?: {
        Items?: unknown[];
      };
      OriginOverride?: boolean;
    };
  };
  assert.equal(
    corsConfig.CorsConfig
      ?.AccessControlAllowCredentials,
    false,
  );
  assert.deepEqual(
    corsConfig.CorsConfig
      ?.AccessControlAllowMethods?.Items,
    ["GET", "HEAD", "OPTIONS"],
  );
  assert.equal(
    corsConfig.CorsConfig?.OriginOverride,
    true,
  );
  assert.deepEqual(
    corsConfig.CorsConfig
      ?.AccessControlAllowOrigins?.Items,
    [
      {
        "Fn::Join": [
          "",
          [
            "https://",
            {
              "Fn::GetAtt": [
                operatorDistributionEntry?.[0],
                "DomainName",
              ],
            },
          ],
        ],
      },
      "https://clockchain-research.vercel.app",
    ],
  );

  const publicDistribution = Object.entries(
    resources,
  ).find(
    ([logicalId, resource]) =>
      logicalId.startsWith(
        "PublicMonitorDistribution",
      ) &&
      resource.Type ===
        "AWS::CloudFront::Distribution",
  )?.[1];
  const operatorDistribution =
    operatorDistributionEntry?.[1];
  assert.equal(
    JSON.stringify(publicDistribution).includes(
      "ResponseHeadersPolicyId",
    ),
    true,
  );
  assert.equal(
    JSON.stringify(operatorDistribution).includes(
      "ResponseHeadersPolicyId",
    ),
    false,
  );
});
