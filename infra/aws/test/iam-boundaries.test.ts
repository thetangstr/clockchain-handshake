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
const RELAY_TLS_SECRET_ARN =
  "arn:aws:secretsmanager:us-west-2:123456789012:secret:clockchain-relay-tls-AbCdEf";
const STACK_PROPS = {
  bootstrapBrokerCapabilityDigest:
    "c".repeat(64),
  controlPlaneImage: IMAGE,
  operatorPublicKey:
    "oIcoZqI/cqzG4UbXcaV+k1fxwt8EBb+9S+XNcb9pq3k=",
  relayPublicHostname:
    "relay.clockchain.net",
  relayTlsCertificatePem: `-----BEGIN CERTIFICATE-----
MIIBdDCCASagAwIBAgIUPrXOrIpEJb7MiFXU0DDWShb37kIwBQYDK2VwMB8xHTAb
BgNVBAMMFHJlbGF5LmNsb2NrY2hhaW4ubmV0MB4XDTI2MDczMTIyNDIyN1oXDTI2
MDgwMTIyNDIyN1owHzEdMBsGA1UEAwwUcmVsYXkuY2xvY2tjaGFpbi5uZXQwKjAF
BgMrZXADIQDwMVNUm7k6YU4Ra2V4wCNd0g55HJvSHdDe25+8kjDieaN0MHIwHQYD
VR0OBBYEFMWEqIIWZMtV/0sLBCI8b/LPLlxKMB8GA1UdIwQYMBaAFMWEqIIWZMtV
/0sLBCI8b/LPLlxKMA8GA1UdEwEB/wQFMAMBAf8wHwYDVR0RBBgwFoIUcmVsYXku
Y2xvY2tjaGFpbi5uZXQwBQYDK2VwA0EAaeNXc+Bk8jhlk7JOWlWPgajcq14EO03b
GzRaxazJRJqgomGuhMdWNo8pqbWf9+sUnkkr9ZGuAGcK3zyS6UeHDA==
-----END CERTIFICATE-----
`,
  relayTlsFingerprint:
    "3dbe9d0ea7491d9d6e4586f978ddf2b67c4ac173780b3b8d5b86def84a0d73d9",
  relayTlsSecretArn:
    RELAY_TLS_SECRET_ARN,
  repositorySha:
    "abcdef0123456789abcdef0123456789abcdef01",
  sessionId:
    "11111111-1111-4111-8111-111111111111",
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

function json(): Record<string, unknown> {
  const app = new App();
  return Template.fromStack(
    new ClockchainHandshakeStack(
      app,
      "BoundaryStack",
      {
        ...STACK_PROPS,
        env: {
          account: "123456789012",
          region: "us-west-2",
        },
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
    "BootstrapBrokerCapability",
    "OperatorKey",
    "ClockchainToken",
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
  assert.equal(
    policies.includes(RELAY_TLS_SECRET_ARN),
    true,
    "RelayTls",
  );
  const matrix = {
    AbortTunnelTaskRole: [],
    BootstrapApprovalTaskRole: [
      "BootstrapBrokerCapability",
      "OperatorKey",
    ],
    BootstrapTaskRole: [
      "BootstrapBrokerCapability",
    ],
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
    OperatorTaskRole: [],
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
          | string
          | { Ref?: string }
          | undefined;
        if (resource === RELAY_TLS_SECRET_ARN) {
          return "RelayTls";
        }
        return Object.keys(matrix).reduce<
          string | null
        >(
          (found) => found,
          typeof resource === "object"
            ? resource?.Ref?.replace(
                /[0-9A-F]{8}$/,
                "",
              ) ?? null
            : null,
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

test("relay can decrypt the imported TLS secret only through Secrets Manager", () => {
  const resources = json().Resources as Record<
    string,
    {
      Properties?: {
        KeyPolicy?: {
          Statement?: Array<{
            Action?: string | string[];
            Condition?: unknown;
            Principal?: unknown;
            Resource?: unknown;
          }>;
        };
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
  const keyEntry = Object.entries(resources).find(
    ([logicalId, resource]) =>
      logicalId.startsWith("DataKey") &&
      resource.Type === "AWS::KMS::Key",
  );
  assert.notEqual(keyEntry, undefined);
  const statements =
    keyEntry?.[1].Properties?.KeyPolicy
      ?.Statement ?? [];
  const relayDecryptStatements = statements.filter(
    (statement) => {
      const actions = Array.isArray(
        statement.Action,
      )
        ? statement.Action
        : [statement.Action];
      const serialized = JSON.stringify(statement);
      return (
        actions.includes("kms:Decrypt") &&
        serialized.includes("RelayTaskRole")
      );
    },
  );
  assert.equal(relayDecryptStatements.length, 1);
  assert.deepEqual(
    relayDecryptStatements[0]?.Condition,
    {
      StringEquals: {
        "kms:ViaService":
          "secretsmanager.us-west-2.amazonaws.com",
      },
    },
  );
  assert.equal(
    relayDecryptStatements[0]?.Resource,
    "*",
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

test("operator can run and describe only reviewed child task definitions", () => {
  const resources = json().Resources as Record<
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
  const entry = Object.entries(resources).find(
    ([logicalId, resource]) =>
      logicalId.startsWith(
        "OperatorTaskRoleDefaultPolicy",
      ) &&
      resource.Type === "AWS::IAM::Policy",
  );
  assert.notEqual(entry, undefined);
  const statements =
    entry?.[1].Properties?.PolicyDocument
      ?.Statement ?? [];
  const actions = statements.flatMap(
    (statement) =>
      Array.isArray(statement.Action)
        ? statement.Action
        : [statement.Action],
  );
  assert.equal(actions.includes("ecs:RunTask"), true);
  assert.equal(
    actions.includes("ecs:DescribeTasks"),
    true,
  );
  const serialized = JSON.stringify(entry);
  for (const child of [
    "AbortTunnelTask",
    "BootstrapApprovalTask",
    "CoordinatorTask",
    "FundingTask",
    "VerifierTask",
  ]) {
    assert.equal(
      serialized.includes(child),
      true,
      child,
    );
  }
  assert.equal(
    serialized.includes("ClockchainToken"),
    false,
  );
  assert.equal(
    serialized.includes("TreasuryKeystore"),
    false,
  );
  assert.equal(
    serialized.includes("TreasuryPassword"),
    false,
  );
});
