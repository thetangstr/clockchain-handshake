import assert from "node:assert/strict";
import { test } from "node:test";

import {
  App,
} from "aws-cdk-lib";
import { Template } from "aws-cdk-lib/assertions";

import {
  ClockchainHandshakeStack,
} from "../lib/clockchain-handshake-stack.js";

const IMAGE =
  "123456789012.dkr.ecr.us-west-2.amazonaws.com/clockchain@sha256:" +
  "a".repeat(64);

function template(): Template {
  const app = new App();
  return Template.fromStack(
    new ClockchainHandshakeStack(
      app,
      "TestStack",
      {
        controlPlaneImage: IMAGE,
        env: {
          account: "123456789012",
          region: "us-west-2",
        },
        tunnelImage: IMAGE.replace(
          /a+$/,
          "b".repeat(64),
        ),
      },
    ),
  );
}

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
