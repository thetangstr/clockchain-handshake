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

function template(): Record<string, unknown> {
  const app = new App();
  return Template.fromStack(
    new ClockchainHandshakeStack(
      app,
      "EfsBoundaryStack",
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
  assert.equal(new Set(paths).size, 9);
});
