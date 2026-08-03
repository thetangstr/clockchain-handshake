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
    "arn:aws:secretsmanager:us-west-2:123456789012:secret:clockchain-relay-tls-AbCdEf",
  receiptSenderEmail:
    "receipts@clockchain.network",
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

function template(): Record<string, unknown> {
  const app = new App();
  return Template.fromStack(
    new ClockchainHandshakeStack(
      app,
      "EfsBoundaryStack",
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

test("every EFS task volume uses IAM, transit encryption, and a named access point", () => {
  const resources = template().Resources as Record<
    string,
    {
      Properties?: {
        Volumes?: Array<{
          EFSVolumeConfiguration?: {
            AuthorizationConfig?: {
              AccessPointId?: unknown;
              IAM?: string;
            };
            RootDirectory?: string;
            TransitEncryption?: string;
          };
        }>;
      };
      Type: string;
    }
  >;
  let volumeCount = 0;
  for (const resource of Object.values(
    resources,
  )) {
    if (
      resource.Type !==
      "AWS::ECS::TaskDefinition"
    ) {
      continue;
    }
    for (const volume of
      resource.Properties?.Volumes ?? []) {
      const efs =
        volume.EFSVolumeConfiguration;
      if (efs === undefined) continue;
      volumeCount += 1;
      assert.equal(
        efs.TransitEncryption,
        "ENABLED",
      );
      assert.equal(
        efs.AuthorizationConfig?.IAM,
        "ENABLED",
      );
      assert.notEqual(
        efs.AuthorizationConfig
          ?.AccessPointId,
        undefined,
      );
      assert.equal(efs.RootDirectory, "/");
    }
  }
  assert.equal(volumeCount >= 11, true);
});

test("access points use fixed non-root identities and isolated paths", () => {
  const resources = template().Resources as Record<
    string,
    {
      Properties?: {
        PosixUser?: {
          Gid?: string;
          Uid?: string;
        };
        RootDirectory?: {
          Path?: string;
        };
      };
      Type: string;
    }
  >;
  const paths = [];
  for (const resource of Object.values(
    resources,
  )) {
    if (
      resource.Type !==
      "AWS::EFS::AccessPoint"
    ) {
      continue;
    }
    assert.notEqual(
      resource.Properties?.PosixUser?.Uid,
      "0",
    );
    assert.notEqual(
      resource.Properties?.PosixUser?.Gid,
      "0",
    );
    const path =
      resource.Properties?.RootDirectory?.Path;
    assert.match(
      path ?? "",
      /^\/clockchain\/[a-z-]+$/,
    );
    paths.push(path);
  }
  assert.equal(new Set(paths).size, 12);
});

test("relay container identity matches its dedicated EFS access point", () => {
  const resources = template().Resources as Record<
    string,
    {
      Properties?: {
        ContainerDefinitions?: Array<{
          User?: string;
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
  assert.equal(
    relay?.Properties?.ContainerDefinitions?.[0]
      ?.User,
    "1106:1106",
  );
});

test("operator remains isolated while one-shot approval and abort tasks own bootstrap/tunnel state access", () => {
  const resources = template().Resources as Record<
    string,
    {
      Properties?: {
        ContainerDefinitions?: Array<{
          MountPoints?: Array<{
            ContainerPath?: string;
            ReadOnly?: boolean;
          }>;
        }>;
      };
      Type: string;
    }
  >;
  const taskDefinitions = Object.entries(resources)
    .filter(
      ([, resource]) =>
        resource.Type ===
        "AWS::ECS::TaskDefinition",
    )
    .map(([logicalId, resource]) => [
      logicalId.replace(/Task[0-9A-F]+$/, ""),
      resource.Properties
        ?.ContainerDefinitions?.[0]
        ?.MountPoints ?? [],
    ] as const);
  const entry = taskDefinitions.find(
    ([logicalId]) => logicalId === "Operator",
  );
  assert.notEqual(entry, undefined);
  assert.deepEqual(
    entry?.[1].map((mount) => [
      mount.ContainerPath,
      mount.ReadOnly,
    ]),
    [
      ["/var/lib/clockchain/operator", false],
      ["/var/lib/clockchain/bootstrap", true],
      [
        "/var/lib/clockchain/funding-result",
        true,
      ],
    ],
  );
  const approval = taskDefinitions.find(
    ([logicalId]) =>
      logicalId === "BootstrapApproval",
  );
  assert.notEqual(approval, undefined);
  assert.deepEqual(
    approval?.[1].map((mount) => [
      mount.ContainerPath,
      mount.ReadOnly,
    ]),
    [
      ["/var/lib/clockchain/bootstrap", false],
      ["/var/lib/clockchain/operator", true],
      ["/var/lib/clockchain/tunnel", false],
      ["/var/lib/clockchain/approved-payer", false],
    ],
  );
  const abort = taskDefinitions.find(
    ([logicalId]) =>
      logicalId === "AbortTunnel",
  );
  assert.notEqual(abort, undefined);
  assert.deepEqual(
    abort?.[1].map((mount) => [
      mount.ContainerPath,
      mount.ReadOnly,
    ]),
    [
      ["/var/lib/clockchain/tunnel", false],
    ],
  );
  const tunnel = taskDefinitions.find(
    ([logicalId]) => logicalId === "Tunnel",
  );
  assert.deepEqual(
    tunnel?.[1].map((mount) => [
      mount.ContainerPath,
      mount.ReadOnly,
    ]),
    [
      ["/run/clockchain", false],
      ["/var/lib/clockchain/health", false],
    ],
  );
  const coordinator = taskDefinitions.find(
    ([logicalId]) => logicalId === "Coordinator",
  );
  assert.deepEqual(
    coordinator?.[1].map((mount) => [
      mount.ContainerPath,
      mount.ReadOnly,
    ]),
    [
      ["/var/lib/clockchain/operator", false],
      ["/var/lib/clockchain/verifier-output", true],
      ["/var/lib/clockchain/approved-payer", true],
      ["/var/lib/clockchain/tunnel-health", true],
      ["/var/lib/clockchain/public", false],
    ],
  );
  const publisher = taskDefinitions.find(
    ([logicalId]) => logicalId === "Publisher",
  );
  assert.deepEqual(
    publisher?.[1].map((mount) => [
      mount.ContainerPath,
      mount.ReadOnly,
    ]),
    [["/var/lib/clockchain/public", true]],
  );
  assert.equal(
    JSON.stringify(taskDefinitions).includes(
      "\"ContainerPath\":\"/\"",
    ),
    false,
  );
});
