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
        controlPlaneImage: IMAGE,
        env: {
          account: "123456789012",
          region: "us-west-2",
        },
        repositorySha:
          "abcdef0123456789abcdef0123456789abcdef01",
        tunnelImage: IMAGE.replace(
          /a+$/,
          "b".repeat(64),
        ),
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
        controlPlaneImage: IMAGE,
        env: {
          account: "123456789012",
          region: "us-west-2",
        },
        repositorySha:
          "abcdef0123456789abcdef0123456789abcdef01",
        tunnelImage: IMAGE.replace(
          /a+$/,
          "b".repeat(64),
        ),
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
    9,
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
  assert.equal(taskDefinitions.length, 8);
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
    9,
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
