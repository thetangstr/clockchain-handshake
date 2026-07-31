import assert from "node:assert/strict";
import { test } from "node:test";

import { App } from "aws-cdk-lib";
import {
  Template,
} from "aws-cdk-lib/assertions";

import {
  ClockchainHandshakeStack,
} from "../lib/clockchain-handshake-stack.js";

const IMAGE =
  "123456789012.dkr.ecr.us-west-2.amazonaws.com/clockchain@sha256:" +
  "a".repeat(64);

function json(): Record<string, unknown> {
  const app = new App();
  return Template.fromStack(
    new ClockchainHandshakeStack(
      app,
      "BoundaryStack",
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
  ).toJSON() as Record<string, unknown>;
}

function serializedPolicies(
  template: Record<string, unknown>,
): string {
  const resources = template.Resources as
    | Record<string, {
        Type: string;
        Properties?: unknown;
      }>
    | undefined;
  return JSON.stringify(
    Object.fromEntries(
      Object.entries(resources ?? {}).filter(
        ([, value]) =>
          value.Type === "AWS::IAM::Policy",
      ),
    ),
  );
}

test("task secret permissions are resource-scoped and absent from API, console, and publisher roles", () => {
  const template = json();
  const resources = template.Resources as Record<
    string,
    {
      Properties?: {
        PolicyDocument?: {
          Statement?: Array<{
            Action?: string | string[];
            Resource?: unknown;
          }>;
        };
      };
      Type: string;
    }
  >;
  const policies = serializedPolicies(template);
  assert.equal(
    policies.includes(
      '"Action":"secretsmanager:GetSecretValue","Resource":"*"',
    ),
    false,
  );
  for (const name of [
    "OperatorKey",
    "ClockchainToken",
    "RelayTls",
    "SepoliaRpc",
    "TreasuryKeystore",
    "TreasuryPassword",
    "TunnelHostKey",
  ]) {
    assert.equal(
      policies.includes(name),
      true,
      name,
    );
  }
  const matrix = {
    BootstrapTaskRole: ["OperatorKey"],
    CoordinatorTaskRole: [
      "ClockchainToken",
      "OperatorKey",
      "SepoliaRpc",
    ],
    FundingTaskRole: [
      "SepoliaRpc",
      "TreasuryKeystore",
      "TreasuryPassword",
    ],
    OperatorTaskRole: ["OperatorKey"],
    PublisherTaskRole: [],
    RelayTaskRole: ["RelayTls"],
    TunnelTaskRole: ["TunnelHostKey"],
    VerifierTaskRole: [
      "ClockchainToken",
      "SepoliaRpc",
    ],
  } as const;
  for (const [prefix, expected] of
    Object.entries(matrix)) {
    const entry = Object.entries(resources).find(
      ([logicalId, resource]) =>
        logicalId.startsWith(prefix) &&
        logicalId.includes(
          "DefaultPolicy",
        ) &&
        resource.Type === "AWS::IAM::Policy",
    );
    assert.notEqual(entry, undefined, prefix);
    const statements =
      entry?.[1].Properties?.PolicyDocument
        ?.Statement ?? [];
    const secretStatements =
      statements.filter((statement) => {
        const actions = Array.isArray(
          statement.Action,
        )
          ? statement.Action
          : [statement.Action];
        return actions.includes(
          "secretsmanager:GetSecretValue",
        );
      });
    const actual = secretStatements
      .map((statement) => {
        const resource = statement.Resource as
          | { Ref?: string }
          | undefined;
        return Object.keys(matrix).reduce<
          string | null
        >(
          (found) => found,
          resource?.Ref?.replace(
            /[0-9A-F]{8}$/,
            "",
          ) ?? null,
        );
      })
      .filter(
        (value): value is string =>
          value !== null,
      )
      .sort();
    assert.deepEqual(
      actual,
      [...expected].sort(),
      prefix,
    );
  }
  const controlPolicy =
    Object.entries(resources).find(
      ([logicalId, resource]) =>
        logicalId.startsWith(
          "ControlApiFunctionServiceRoleDefaultPolicy",
        ) &&
        resource.Type === "AWS::IAM::Policy",
    );
  assert.equal(
    JSON.stringify(controlPolicy).includes(
      "secretsmanager:GetSecretValue",
    ),
    false,
  );
});

test("no synthesized application policy grants wildcard EFS or wildcard secret authority", () => {
  const policies = serializedPolicies(json());
  assert.equal(
    /elasticfilesystem:(?:ClientMount|ClientWrite)[^}]+\"Resource\":\"\\*\"/.test(
      policies,
    ),
    false,
  );
  assert.equal(
    /secretsmanager:GetSecretValue[^}]+\"Resource\":\"\\*\"/.test(
      policies,
    ),
    false,
  );
});
