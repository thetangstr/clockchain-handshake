import assert from "node:assert/strict";
import { test } from "node:test";

import {
  App,
} from "aws-cdk-lib";
import { Template } from "aws-cdk-lib/assertions";

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
  repositorySha:
    "abcdef0123456789abcdef0123456789abcdef01",
  sessionId: SESSION_ID,
  sourceTreeSha256: "e".repeat(64),
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
    10,
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
    1,
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
    11,
  );
  output.resourceCountIs(
    "AWS::CloudWatch::Alarm",
    5,
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
