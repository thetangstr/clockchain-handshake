import {
  CfnOutput,
  Duration,
  RemovalPolicy,
  Stack,
  type StackProps,
} from "aws-cdk-lib";
import * as apigwv2 from "aws-cdk-lib/aws-apigatewayv2";
import * as authorizers from "aws-cdk-lib/aws-apigatewayv2-authorizers";
import * as integrations from "aws-cdk-lib/aws-apigatewayv2-integrations";
import * as cloudfront from "aws-cdk-lib/aws-cloudfront";
import * as origins from "aws-cdk-lib/aws-cloudfront-origins";
import * as cloudwatch from "aws-cdk-lib/aws-cloudwatch";
import * as cognito from "aws-cdk-lib/aws-cognito";
import * as dynamodb from "aws-cdk-lib/aws-dynamodb";
import * as ec2 from "aws-cdk-lib/aws-ec2";
import * as ecr from "aws-cdk-lib/aws-ecr";
import * as ecs from "aws-cdk-lib/aws-ecs";
import * as efs from "aws-cdk-lib/aws-efs";
import * as elbv2 from "aws-cdk-lib/aws-elasticloadbalancingv2";
import * as iam from "aws-cdk-lib/aws-iam";
import * as kms from "aws-cdk-lib/aws-kms";
import * as lambda from "aws-cdk-lib/aws-lambda";
import * as lambdaNode from "aws-cdk-lib/aws-lambda-nodejs";
import * as logs from "aws-cdk-lib/aws-logs";
import * as s3 from "aws-cdk-lib/aws-s3";
import * as s3deploy from "aws-cdk-lib/aws-s3-deployment";
import * as secretsmanager from "aws-cdk-lib/aws-secretsmanager";
import * as sqs from "aws-cdk-lib/aws-sqs";
import type { Construct } from "constructs";
import {
  createHash,
  X509Certificate,
} from "node:crypto";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const IMAGE =
  /^[0-9]{12}\.dkr\.ecr\.[a-z]{2}-[a-z]+-[1-9]\.amazonaws\.com\/[a-z0-9][a-z0-9._/-]{0,254}@sha256:[0-9a-f]{64}$/;
const SHA40 = /^[0-9a-f]{40}$/;
const SHA64 = /^[0-9a-f]{64}$/;
const SESSION =
  /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const RAW_ED25519_PUBLIC_KEY =
  /^[A-Za-z0-9+/]{43}=$/;
const SECRET_ARN =
  /^arn:aws(?:-[a-z]+)?:secretsmanager:[a-z0-9-]+:[0-9]{12}:secret:[A-Za-z0-9/_+=.@-]{1,512}$/;
const PUBLIC_HOSTNAME =
  /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?$/;
export const CONTROL_REPOSITORY_NAME =
  "clockchain-handshake-control-plane";
export const TUNNEL_REPOSITORY_NAME =
  "clockchain-handshake-tunnel";

function validOperatorPublicKey(value: string): boolean {
  if (!RAW_ED25519_PUBLIC_KEY.test(value)) {
    return false;
  }
  const decoded = Buffer.from(value, "base64");
  return (
    decoded.length === 32 &&
    decoded.toString("base64") === value
  );
}

type AccessPointName =
  | "bootstrap"
  | "fundingJournal"
  | "fundingRecord"
  | "fundingResult"
  | "operator"
  | "publisher"
  | "relay"
  | "tunnel"
  | "verifierEvidence"
  | "verifierOutput";

interface Mount {
  readonly accessPoint: efs.AccessPoint;
  readonly containerPath: string;
  readonly name: string;
  readonly readOnly: boolean;
}

interface Port {
  readonly containerPort: number;
  readonly name: string;
}

interface Workload {
  readonly container: ecs.ContainerDefinition;
  readonly logGroup: logs.LogGroup;
  readonly role: iam.Role;
  readonly securityGroup: ec2.SecurityGroup;
  readonly service?: ecs.FargateService;
  readonly task: ecs.FargateTaskDefinition;
}

export interface ClockchainHandshakeStackProps
  extends StackProps {
  readonly activateServices?: boolean;
  readonly bootstrapBrokerCapabilityDigest: string;
  readonly controlPlaneImage: string;
  readonly operatorPublicKey: string;
  readonly relayPublicHostname: string;
  readonly relayTlsCertificatePem: string;
  readonly relayTlsFingerprint: string;
  readonly relayTlsSecretArn: string;
  readonly repositorySha: string;
  readonly sessionId: string;
  readonly sourceTreeSha256: string;
  readonly tunnelImage: string;
}

export class ClockchainHandshakeImagesStack extends Stack {
  public readonly controlRepository: ecr.Repository;
  public readonly tunnelRepository: ecr.Repository;

  public constructor(
    scope: Construct,
    id: string,
    props?: StackProps,
  ) {
    super(scope, id, props);
    this.controlRepository =
      this.repository(
        "ControlPlaneRepository",
        CONTROL_REPOSITORY_NAME,
      );
    this.tunnelRepository =
      this.repository(
        "TunnelRepository",
        TUNNEL_REPOSITORY_NAME,
      );
    new CfnOutput(
      this,
      "ControlPlaneRepositoryUri",
      {
        value:
          this.controlRepository
            .repositoryUri,
      },
    );
    new CfnOutput(
      this,
      "TunnelRepositoryUri",
      {
        value:
          this.tunnelRepository
            .repositoryUri,
      },
    );
  }

  private repository(
    id: string,
    repositoryName: string,
  ): ecr.Repository {
    const repository = new ecr.Repository(
      this,
      id,
      {
        emptyOnDelete: false,
        imageScanOnPush: true,
        imageTagMutability:
          ecr.TagMutability.IMMUTABLE,
        removalPolicy: RemovalPolicy.RETAIN,
        repositoryName,
      },
    );
    repository.addLifecycleRule({
      maxImageCount: 20,
      rulePriority: 1,
      tagStatus: ecr.TagStatus.ANY,
    });
    return repository;
  }
}

export class ClockchainHandshakeStack extends Stack {
  public constructor(
    scope: Construct,
    id: string,
    props: ClockchainHandshakeStackProps,
  ) {
    super(scope, id, props);
    if (
      !IMAGE.test(props.controlPlaneImage) ||
      !IMAGE.test(props.tunnelImage) ||
      !SHA40.test(props.repositorySha) ||
      !SESSION.test(props.sessionId) ||
      !SHA64.test(
        props.bootstrapBrokerCapabilityDigest,
      ) ||
      !SHA64.test(
        props.relayTlsFingerprint,
      ) ||
      !PUBLIC_HOSTNAME.test(
        props.relayPublicHostname,
      ) ||
      !SECRET_ARN.test(
        props.relayTlsSecretArn,
      ) ||
      !SHA64.test(props.sourceTreeSha256) ||
      !validOperatorPublicKey(
        props.operatorPublicKey,
      )
    ) {
      throw new Error(
        "Container images and repository release must be immutable.",
      );
    }
    const sessionId = props.sessionId;
    let relayTlsCertificate: X509Certificate;
    try {
      relayTlsCertificate = new X509Certificate(
        props.relayTlsCertificatePem,
      );
    } catch {
      throw new Error(
        "Relay TLS certificate is invalid.",
      );
    }
    if (
      createHash("sha256")
        .update(relayTlsCertificate.raw)
        .digest("hex") !==
      props.relayTlsFingerprint
    ) {
      throw new Error(
        "Relay TLS certificate and fingerprint must match.",
      );
    }
    if (
      relayTlsCertificate.checkHost(
        props.relayPublicHostname,
        { subject: "never" },
      ) === undefined
    ) {
      throw new Error(
        "Relay TLS certificate must cover the public hostname.",
      );
    }
    const releaseId =
      `release-${createHash("sha256")
        .update(sessionId, "utf8")
        .digest("hex")
        .slice(0, 16)}`;

    const dataKey = new kms.Key(this, "DataKey", {
      enableKeyRotation: true,
      removalPolicy: RemovalPolicy.RETAIN,
    });
    dataKey.addToResourcePolicy(
      new iam.PolicyStatement({
        actions: [
          "kms:Encrypt",
          "kms:Decrypt",
          "kms:ReEncrypt*",
          "kms:GenerateDataKey*",
          "kms:Describe*",
        ],
        conditions: {
          ArnLike: {
            "kms:EncryptionContext:aws:logs:arn":
              `arn:${this.partition}:logs:${this.region}:${this.account}:log-group:*`,
          },
          StringEquals: {
            "aws:SourceAccount": this.account,
          },
        },
        principals: [
          new iam.ServicePrincipal(
            `logs.${this.region}.${this.urlSuffix}`,
          ),
        ],
        resources: ["*"],
      }),
    );
    const vpc = new ec2.Vpc(this, "Vpc", {
      maxAzs: 2,
      natGateways: 0,
      subnetConfiguration: [
        {
          cidrMask: 24,
          name: "PublicTasks",
          subnetType: ec2.SubnetType.PUBLIC,
        },
      ],
    });
    const cluster = new ecs.Cluster(
      this,
      "Cluster",
      {
        containerInsightsV2:
          ecs.ContainerInsights.ENHANCED,
        vpc,
      },
    );
    const fileSystem = new efs.FileSystem(
      this,
      "State",
      {
        encrypted: true,
        kmsKey: dataKey,
        lifecyclePolicy:
          efs.LifecyclePolicy.AFTER_30_DAYS,
        outOfInfrequentAccessPolicy:
          efs.OutOfInfrequentAccessPolicy
            .AFTER_1_ACCESS,
        performanceMode:
          efs.PerformanceMode.GENERAL_PURPOSE,
        removalPolicy: RemovalPolicy.RETAIN,
        vpc,
      },
    );
    const accessPoints =
      this.createAccessPoints(fileSystem);

    const controlRepository =
      ecr.Repository.fromRepositoryName(
        this,
        "ControlPlaneRepository",
        CONTROL_REPOSITORY_NAME,
      );
    const tunnelRepository =
      ecr.Repository.fromRepositoryName(
        this,
        "TunnelRepository",
        TUNNEL_REPOSITORY_NAME,
      );
    const controlImage =
      ecs.ContainerImage.fromEcrRepository(
        controlRepository,
        props.controlPlaneImage.split("@")[1],
      );
    const tunnelContainerImage =
      ecs.ContainerImage.fromEcrRepository(
        tunnelRepository,
        props.tunnelImage.split("@")[1],
      );

    const operatorKey = this.secret(
      "OperatorKey",
      dataKey,
    );
    const clockchainToken = this.secret(
      "ClockchainToken",
      dataKey,
    );
    const relayTls =
      secretsmanager.Secret.fromSecretAttributes(
        this,
        "RelayTls",
        {
          encryptionKey: dataKey,
          secretCompleteArn:
            props.relayTlsSecretArn,
        },
      );
    const sepoliaRpc = this.secret(
      "SepoliaRpc",
      dataKey,
    );
    const treasuryKeystore = this.secret(
      "TreasuryKeystore",
      dataKey,
    );
    const treasuryPassword = this.secret(
      "TreasuryPassword",
      dataKey,
    );
    const tunnelHostKey = this.secret(
      "TunnelHostKey",
      dataKey,
    );
    const bootstrapBrokerCapability =
      this.secret(
        "BootstrapBrokerCapability",
        dataKey,
      );

    const relay = this.workload({
      cluster,
      command: [
        "node",
        "infra/aws/runtime/relay-entrypoint.mjs",
      ],
      desiredCount:
        props.activateServices === true ? 1 : 0,
      fileSystem,
      id: "Relay",
      image: controlImage,
      mounts: [
        this.mount(
          "relay",
          accessPoints.relay,
          "/var/lib/clockchain/relay",
          false,
        ),
      ],
      ports: [
        {
          containerPort: 8443,
          name: "relay",
        },
      ],
      service: true,
      user: "1106:1106",
      vpc,
    });
    relayTls.grantRead(relay.role);

    const operator = this.workload({
      cluster,
      command: [
        "node",
        "infra/aws/runtime/operator-worker-entrypoint.mjs",
      ],
      desiredCount:
        props.activateServices === true ? 1 : 0,
      fileSystem,
      id: "Operator",
      image: controlImage,
      mounts: [
        this.mount(
          "operator",
          accessPoints.operator,
          "/var/lib/clockchain/operator",
          false,
        ),
        this.mount(
          "operator-bootstrap",
          accessPoints.bootstrap,
          "/var/lib/clockchain/bootstrap",
          true,
        ),
        this.mount(
          "operator-funding-result",
          accessPoints.fundingResult,
          "/var/lib/clockchain/funding-result",
          true,
        ),
      ],
      ports: [],
      service: true,
      vpc,
    });

    const bootstrap = this.workload({
      cluster,
      command: [
        "node",
        "infra/aws/runtime/bootstrap-entrypoint.mjs",
      ],
      desiredCount:
        props.activateServices === true ? 1 : 0,
      fileSystem,
      id: "Bootstrap",
      image: controlImage,
      mounts: [
        this.mount(
          "bootstrap",
          accessPoints.bootstrap,
          "/var/lib/clockchain/bootstrap",
          false,
        ),
      ],
      ports: [
        {
          containerPort: 9555,
          name: "bootstrap",
        },
      ],
      service: true,
      vpc,
    });
    bootstrap.container.addEnvironment(
      "BILATERAL_RELEASE_ID",
      releaseId,
    );
    bootstrap.container.addEnvironment(
      "BILATERAL_REPOSITORY_SHA",
      props.repositorySha,
    );
    bootstrap.container.addEnvironment(
      "BILATERAL_SESSION_ID",
      sessionId,
    );
    bootstrap.container.addEnvironment(
      "AWS_BOOTSTRAP_STATE_PATH",
      `/var/lib/clockchain/bootstrap/releases/${releaseId}/bootstrap-state.json`,
    );
    bootstrap.container.addEnvironment(
      "AWS_BOOTSTRAP_BROKER_CAPABILITY_DIGEST",
      props.bootstrapBrokerCapabilityDigest,
    );
    bootstrap.container.addEnvironment(
      "AWS_BOOTSTRAP_CLAIM_EXPIRES_AFTER_MS",
      "600000",
    );
    bootstrap.container.addEnvironment(
      "AWS_BOOTSTRAP_BIND_HOST",
      "0.0.0.0",
    );
    bootstrap.container.addEnvironment(
      "AWS_BOOTSTRAP_PORT",
      "9555",
    );
    bootstrapBrokerCapability.grantRead(
      bootstrap.role,
    );

    const tunnel = this.workload({
      cluster,
      command: [
        "node",
        "infra/aws/runtime/tunnel-entrypoint.mjs",
      ],
      desiredCount:
        props.activateServices === true ? 1 : 0,
      fileSystem,
      id: "Tunnel",
      image: tunnelContainerImage,
      mounts: [
        this.mount(
          "tunnel",
          accessPoints.tunnel,
          "/run/clockchain",
          false,
        ),
      ],
      ports: [
        {
          containerPort: 2222,
          name: "ssh",
        },
        {
          containerPort: 9443,
          name: "payer-mcp",
        },
        {
          containerPort: 8080,
          name: "health",
        },
      ],
      service: true,
      vpc,
    });
    tunnelHostKey.grantRead(tunnel.role);
    tunnel.container.addEnvironment(
      "TUNNEL_HOST_KEY_SECRET_ARN",
      tunnelHostKey.secretArn,
    );
    tunnel.container.addEnvironment(
      "AWS_TUNNEL_GRANT_PATH",
      `/run/clockchain/grants/${releaseId}/tunnel-grant.json`,
    );
    tunnel.container.addEnvironment(
      "AWS_TUNNEL_ABORT_MARKER_PATH",
      `/run/clockchain/grants/${releaseId}/abort-marker.json`,
    );
    tunnel.container.addEnvironment(
      "AWS_TUNNEL_STATE_ROOT",
      "/run/clockchain/state",
    );

    const bootstrapApproval = this.workload({
      cluster,
      command: [
        "node",
        "infra/aws/runtime/operator-bootstrap-approval-entrypoint.mjs",
      ],
      desiredCount: 0,
      fileSystem,
      id: "BootstrapApproval",
      image: controlImage,
      mounts: [
        this.mount(
          "approval-bootstrap",
          accessPoints.bootstrap,
          "/var/lib/clockchain/bootstrap",
          false,
        ),
        this.mount(
          "approval-operator",
          accessPoints.operator,
          "/var/lib/clockchain/operator",
          true,
        ),
        this.mount(
          "approval-tunnel",
          accessPoints.tunnel,
          "/var/lib/clockchain/tunnel",
          false,
        ),
      ],
      ports: [],
      service: false,
      vpc,
    });
    operatorKey.grantRead(
      bootstrapApproval.role,
    );
    bootstrapBrokerCapability.grantRead(
      bootstrapApproval.role,
    );

    const abortTunnel = this.workload({
      cluster,
      command: [
        "node",
        "infra/aws/runtime/operator-abort-entrypoint.mjs",
      ],
      desiredCount: 0,
      fileSystem,
      id: "AbortTunnel",
      image: controlImage,
      mounts: [
        this.mount(
          "abort-tunnel",
          accessPoints.tunnel,
          "/var/lib/clockchain/tunnel",
          false,
        ),
      ],
      ports: [],
      service: false,
      vpc,
    });

    const publicMonitorBucket =
      this.privateBucket(
        "PublicMonitorBucket",
      );
    const publisher = this.workload({
      cluster,
      command: [
        "node",
        "infra/aws/runtime/publisher-entrypoint.mjs",
      ],
      desiredCount:
        props.activateServices === true ? 1 : 0,
      fileSystem,
      id: "Publisher",
      image: controlImage,
      mounts: [
        this.mount(
          "publisher-projections",
          accessPoints.publisher,
          "/var/lib/clockchain/public",
          true,
        ),
        this.mount(
          "publisher-verifier",
          accessPoints.verifierOutput,
          "/var/lib/clockchain/verifier-public",
          true,
        ),
      ],
      ports: [],
      service: true,
      vpc,
    });
    publicMonitorBucket.grantReadWrite(
      publisher.role,
    );

    const coordinator = this.workload({
      cluster,
      command: [
        "node",
        "infra/aws/runtime/coordinator-entrypoint.mjs",
      ],
      desiredCount: 0,
      fileSystem,
      id: "Coordinator",
      image: controlImage,
      mounts: [
        this.mount(
          "coordinator-operator",
          accessPoints.operator,
          "/var/lib/clockchain/operator",
          false,
        ),
        this.mount(
          "coordinator-verifier",
          accessPoints.verifierOutput,
          "/var/lib/clockchain/verifier-output",
          true,
        ),
      ],
      ports: [],
      service: false,
      vpc,
    });
    for (const secret of [
      operatorKey,
      clockchainToken,
      sepoliaRpc,
    ]) {
      secret.grantRead(coordinator.role);
    }

    const funding = this.workload({
      cluster,
      command: [
        "node",
        "infra/aws/runtime/funding-entrypoint.mjs",
      ],
      desiredCount: 0,
      fileSystem,
      id: "Funding",
      image: controlImage,
      mounts: [
        this.mount(
          "funding-record",
          accessPoints.fundingRecord,
          "/var/lib/clockchain/funding-record",
          true,
        ),
        this.mount(
          "funding-journal",
          accessPoints.fundingJournal,
          "/var/lib/clockchain/funding-journal",
          false,
        ),
        this.mount(
          "funding-result",
          accessPoints.fundingResult,
          "/var/lib/clockchain/funding-result",
          false,
        ),
      ],
      ports: [],
      service: false,
      vpc,
    });
    for (const secret of [
      sepoliaRpc,
      treasuryKeystore,
      treasuryPassword,
    ]) {
      secret.grantRead(funding.role);
    }

    const verifier = this.workload({
      cluster,
      command: [
        "node",
        "infra/aws/runtime/verifier-entrypoint.mjs",
      ],
      desiredCount: 0,
      fileSystem,
      id: "Verifier",
      image: controlImage,
      mounts: [
        this.mount(
          "verifier-evidence",
          accessPoints.verifierEvidence,
          "/var/lib/clockchain/evidence",
          true,
        ),
        this.mount(
          "verifier-output",
          accessPoints.verifierOutput,
          "/var/lib/clockchain/verifier-output",
          false,
        ),
      ],
      ports: [],
      service: false,
      vpc,
    });
    for (const secret of [
      clockchainToken,
      sepoliaRpc,
    ]) {
      secret.grantRead(verifier.role);
    }

    const publicNlbGroup =
      new ec2.SecurityGroup(
        this,
        "PublicNlbGroup",
        {
          allowAllOutbound: false,
          vpc,
        },
      );
    for (const port of [443, 9443, 8443]) {
      publicNlbGroup.addIngressRule(
        ec2.Peer.anyIpv4(),
        ec2.Port.tcp(port),
      );
    }
    publicNlbGroup.addEgressRule(
      tunnel.securityGroup,
      ec2.Port.tcp(2222),
    );
    publicNlbGroup.addEgressRule(
      tunnel.securityGroup,
      ec2.Port.tcp(9443),
    );
    publicNlbGroup.addEgressRule(
      tunnel.securityGroup,
      ec2.Port.tcp(8080),
    );
    publicNlbGroup.addEgressRule(
      relay.securityGroup,
      ec2.Port.tcp(8443),
    );
    tunnel.securityGroup.addIngressRule(
      publicNlbGroup,
      ec2.Port.tcp(2222),
    );
    tunnel.securityGroup.addIngressRule(
      publicNlbGroup,
      ec2.Port.tcp(9443),
    );
    tunnel.securityGroup.addIngressRule(
      publicNlbGroup,
      ec2.Port.tcp(8080),
    );
    relay.securityGroup.addIngressRule(
      publicNlbGroup,
      ec2.Port.tcp(8443),
    );

    const publicNlb =
      new elbv2.NetworkLoadBalancer(
        this,
        "PublicNlb",
        {
          internetFacing: true,
          securityGroups: [publicNlbGroup],
          vpc,
          vpcSubnets: {
            subnetType: ec2.SubnetType.PUBLIC,
          },
        },
      );
    relay.container.addEnvironment(
      "AWS_RUNTIME_INPUT",
      JSON.stringify({
        paymentMoved: false,
        relay: {
          argv: [
            "--advertised-host",
            props.relayPublicHostname,
            "--host",
            "0.0.0.0",
            "--port",
            "8443",
            "--repository-sha",
            props.repositorySha,
            "--state",
            `/var/lib/clockchain/relay/releases/${releaseId}/relay-state.json`,
            "--tls-certificate",
            "/var/lib/clockchain/relay/runtime/tls.crt",
            "--tls-private-key",
            "/var/lib/clockchain/relay/runtime/tls.key",
          ],
          certificatePath:
            "/var/lib/clockchain/relay/runtime/tls.crt",
          privateKeyPath:
            "/var/lib/clockchain/relay/runtime/tls.key",
          provenance: {
            imageDigest:
              props.controlPlaneImage.split("@")[1],
            operatorKeyId:
              "clockchain-demo-2026",
            operatorPublicKey:
              props.operatorPublicKey,
            repositorySha: props.repositorySha,
            sourceTreeSha256:
              props.sourceTreeSha256,
          },
          tlsFingerprint:
            props.relayTlsFingerprint,
          tlsSecretArn: relayTls.secretArn,
        },
        schema:
          "clockchain.aws-runtime-input/v1",
      }),
    );
    this.tunnelListener({
      containerPort: 2222,
      healthPort: "8080",
      id: "TunnelSsh",
      listenerPort: 443,
      loadBalancer: publicNlb,
      service: tunnel,
    });
    this.tunnelListener({
      containerPort: 9443,
      healthPort: "8080",
      id: "PayerMcp",
      listenerPort: 9443,
      loadBalancer: publicNlb,
      service: tunnel,
    });
    this.tunnelListener({
      containerPort: 8443,
      healthPort: "traffic-port",
      id: "Relay",
      listenerPort: 8443,
      loadBalancer: publicNlb,
      service: relay,
    });

    const bootstrapNlbGroup =
      new ec2.SecurityGroup(
        this,
        "BootstrapNlbGroup",
        {
          allowAllOutbound: false,
          vpc,
        },
      );
    const vpcLinkGroup =
      new ec2.SecurityGroup(
        this,
        "BootstrapVpcLinkGroup",
        {
          allowAllOutbound: false,
          vpc,
        },
      );
    bootstrapNlbGroup.addIngressRule(
      vpcLinkGroup,
      ec2.Port.tcp(9555),
    );
    bootstrapNlbGroup.addEgressRule(
      bootstrap.securityGroup,
      ec2.Port.tcp(9555),
    );
    bootstrap.securityGroup.addIngressRule(
      bootstrapNlbGroup,
      ec2.Port.tcp(9555),
    );
    const bootstrapNlb =
      new elbv2.NetworkLoadBalancer(
        this,
        "BootstrapNlb",
        {
          internetFacing: false,
          securityGroups: [bootstrapNlbGroup],
          vpc,
          vpcSubnets: {
            subnetType: ec2.SubnetType.PUBLIC,
          },
        },
      );
    const bootstrapListener =
      bootstrapNlb.addListener(
        "BootstrapListener",
        {
          port: 9555,
          protocol: elbv2.Protocol.TCP,
        },
      );
    bootstrapListener.addTargets(
      "BootstrapTargets",
      {
        port: 9555,
        protocol: elbv2.Protocol.TCP,
        targets: [
          bootstrap.service!.loadBalancerTarget(
            {
              containerName: "bootstrap",
              containerPort: 9555,
            },
          ),
        ],
      },
    );
    const vpcLink = new apigwv2.VpcLink(
      this,
      "BootstrapVpcLink",
      {
        securityGroups: [vpcLinkGroup],
        subnets: {
          subnetType: ec2.SubnetType.PUBLIC,
        },
        vpc,
      },
    );
    vpcLinkGroup.addEgressRule(
      bootstrapNlbGroup,
      ec2.Port.tcp(9555),
    );
    const bootstrapApi = new apigwv2.HttpApi(
      this,
      "BootstrapApi",
      {
        createDefaultStage: true,
      },
    );
    const bootstrapIntegration =
      new integrations.HttpNlbIntegration(
        "BootstrapIntegration",
        bootstrapListener,
        {
          vpcLink,
        },
      );
    for (const route of [
      {
        method: apigwv2.HttpMethod.POST,
        path: "/v1/payer-claims",
      },
      {
        method: apigwv2.HttpMethod.GET,
        path: "/v1/payer-claims/{claimId}",
      },
      {
        method: apigwv2.HttpMethod.POST,
        path: "/v1/requestor-claims",
      },
      {
        method: apigwv2.HttpMethod.GET,
        path: "/v1/requestor-claims/{claimId}",
      },
      {
        method: apigwv2.HttpMethod.GET,
        path: "/health",
      },
    ] as const) {
      bootstrapApi.addRoutes({
        integration: bootstrapIntegration,
        methods: [route.method],
        path: route.path,
      });
    }
    const bootstrapStage =
      bootstrapApi.defaultStage?.node
        .defaultChild as
        | apigwv2.CfnStage
        | undefined;
    if (bootstrapStage === undefined) {
      throw new Error(
        "Bootstrap API default stage missing.",
      );
    }
    bootstrapStage.defaultRouteSettings = {
      throttlingBurstLimit: 20,
      throttlingRateLimit: 10,
    };

    const actionQueue = new sqs.Queue(
      this,
      "ActionQueue",
      {
        encryption:
          sqs.QueueEncryption.KMS_MANAGED,
        fifo: true,
        retentionPeriod: Duration.days(1),
        visibilityTimeout:
          Duration.minutes(10),
      },
    );
    const actionTable = new dynamodb.Table(
      this,
      "ActionTable",
      {
        billingMode:
          dynamodb.BillingMode.PAY_PER_REQUEST,
        encryption:
          dynamodb.TableEncryption.AWS_MANAGED,
        partitionKey: {
          name: "actionId",
          type: dynamodb.AttributeType.STRING,
        },
        pointInTimeRecoverySpecification: {
          pointInTimeRecoveryEnabled: true,
        },
        removalPolicy: RemovalPolicy.RETAIN,
      },
    );
    const userPool = new cognito.UserPool(
      this,
      "OperatorUserPool",
      {
        selfSignUpEnabled: false,
        signInAliases: {
          email: true,
        },
      },
    );
    const operatorConsoleBucket =
      this.privateBucket(
        "OperatorConsoleBucket",
      );
    const operatorDistribution =
      this.distribution(
        "OperatorConsoleDistribution",
        operatorConsoleBucket,
      );
    const publicDistribution =
      this.distribution(
        "PublicMonitorDistribution",
        publicMonitorBucket,
      );
    publisher.container.addEnvironment(
      "AWS_RUNTIME_INPUT",
      JSON.stringify({
        paymentMoved: false,
        publisher: {
          bucketName:
            publicMonitorBucket.bucketName,
          paymentMoved: false,
          publicBaseUrl:
            `https://${publicDistribution.distributionDomainName}`,
          publicationInputPath:
            "/var/lib/clockchain/public/publisher-input.json",
          schema:
            "clockchain.aws-publisher-runtime/v1",
          stagedPaths: {
            certificate:
              "/var/lib/clockchain/public/payer-mcp.crt",
            payerDiscovery:
              "/var/lib/clockchain/public/payer.json",
            publicationGate:
              "/var/lib/clockchain/public/publication-gate.json",
            requestorDiscovery:
              "/var/lib/clockchain/public/requestor.json",
          },
        },
        schema:
          "clockchain.aws-runtime-input/v1",
      }),
    );
    const operatorUrl =
      `https://${operatorDistribution.distributionDomainName}`;
    const userPoolClient =
      userPool.addClient("OperatorClient", {
        authFlows: {
          userSrp: true,
        },
        generateSecret: false,
        oAuth: {
          callbackUrls: [`${operatorUrl}/`],
          flows: {
            authorizationCodeGrant: true,
            implicitCodeGrant: false,
          },
          logoutUrls: [`${operatorUrl}/`],
          scopes: [
            cognito.OAuthScope.OPENID,
            cognito.OAuthScope.EMAIL,
          ],
        },
        preventUserExistenceErrors: true,
      });
    new cognito.CfnUserPoolGroup(
      this,
      "OperatorUserGroup",
      {
        groupName: "clockchain-operators",
        userPoolId: userPool.userPoolId,
      },
    );
    const operatorDomain =
      userPool.addDomain("OperatorDomain", {
        cognitoDomain: {
          domainPrefix: `clockchain-${this.account}`,
        },
      });
    const controlApiLog = new logs.LogGroup(
      this,
      "ControlApiLog",
      {
        encryptionKey: dataKey,
        retention: logs.RetentionDays.ONE_MONTH,
        removalPolicy: RemovalPolicy.RETAIN,
      },
    );
    const controlFunction =
      new lambdaNode.NodejsFunction(
      this,
      "ControlApiFunction",
      {
        bundling: {
          format:
            lambdaNode.OutputFormat.ESM,
          minify: true,
          sourceMap: false,
          target: "node22",
        },
        entry: join(
          join(
            dirname(
              fileURLToPath(import.meta.url),
            ),
            "../lambda",
          ),
          "handler.mjs",
        ),
        environment: {
          ACTION_QUEUE_URL:
            actionQueue.queueUrl,
          ACTION_TABLE_NAME:
            actionTable.tableName,
          ALLOWED_ORIGIN: `https://${operatorDistribution.distributionDomainName}`,
          COGNITO_AUDIENCE:
            userPoolClient.userPoolClientId,
          COGNITO_ISSUER: `https://cognito-idp.${this.region}.amazonaws.com/${userPool.userPoolId}`,
          OPERATOR_GROUP:
            "clockchain-operators",
        },
        handler: "handler",
        logGroup: controlApiLog,
        memorySize: 256,
        runtime: lambda.Runtime.NODEJS_22_X,
        timeout: Duration.seconds(10),
      },
    );
    actionQueue.grantSendMessages(controlFunction);
    actionTable.grantReadWriteData(
      controlFunction,
    );
    const controlApi = new apigwv2.HttpApi(
      this,
      "ControlApi",
      {
        corsPreflight: {
          allowHeaders: [
            "authorization",
            "content-type",
          ],
          allowMethods: [
            apigwv2.CorsHttpMethod.POST,
            apigwv2.CorsHttpMethod.OPTIONS,
          ],
          allowOrigins: [operatorUrl],
        },
        createDefaultStage: true,
      },
    );
    const jwt =
      new authorizers.HttpJwtAuthorizer(
        "OperatorAuthorizer",
        `https://cognito-idp.${this.region}.amazonaws.com/${userPool.userPoolId}`,
        {
          jwtAudience: [
            userPoolClient.userPoolClientId,
          ],
        },
      );
    controlApi.addRoutes({
      authorizer: jwt,
      integration:
        new integrations.HttpLambdaIntegration(
          "ControlIntegration",
          controlFunction,
        ),
      methods: [apigwv2.HttpMethod.POST],
      path: "/v1/actions",
    });
    new s3deploy.BucketDeployment(
      this,
      "OperatorConsoleDeployment",
      {
        destinationBucket:
          operatorConsoleBucket,
        distribution: operatorDistribution,
        distributionPaths: ["/*"],
        prune: true,
        sources: [
          s3deploy.Source.asset(
            join(
              dirname(
                fileURLToPath(import.meta.url),
              ),
              "../operator-console",
            ),
          ),
          s3deploy.Source.jsonData(
            "config.json",
            {
              cognitoClientId:
                userPoolClient.userPoolClientId,
              cognitoHostedUiUrl:
                operatorDomain.baseUrl(),
              cognitoIssuer:
                `https://cognito-idp.${this.region}.amazonaws.com/${userPool.userPoolId}`,
              controlApiUrl:
                controlApi.url!,
              monitorUrl:
                `https://${publicDistribution.distributionDomainName}`,
              repositorySha:
                props.repositorySha,
              schema:
                "clockchain.operator-console-config/v1",
            },
          ),
        ],
      },
    );
    actionQueue.grantConsumeMessages(
      operator.role,
    );
    actionTable.grantReadWriteData(
      operator.role,
    );
    operator.container.addEnvironment(
      "AWS_RUNTIME_INPUT",
      JSON.stringify({
        operator: {
          actionQueueUrl:
            actionQueue.queueUrl,
          actionTableName:
            actionTable.tableName,
          bootstrap: {
            abortMarkerPath:
              `/var/lib/clockchain/tunnel/grants/${releaseId}/abort-marker.json`,
            bootstrapBrokerCapabilitySecretArn:
              bootstrapBrokerCapability.secretArn,
            bootstrapBrokerUrl:
              `${bootstrapApi.url!}v1/`,
            bootstrapStatePath:
              `/var/lib/clockchain/bootstrap/releases/${releaseId}/bootstrap-state.json`,
            operatorKeyId:
              "clockchain-demo-2026",
            operatorKeySecretArn:
              operatorKey.secretArn,
            payeeLaunchManifestPath:
              `/var/lib/clockchain/operator/releases/${releaseId}/requestor-launch-manifest.json`,
            payerLaunchManifestPath:
              `/var/lib/clockchain/operator/releases/${releaseId}/payer-launch-manifest.json`,
            publicMcpHostname:
              props.relayPublicHostname,
            tunnelGrantPath:
              `/var/lib/clockchain/tunnel/grants/${releaseId}/tunnel-grant.json`,
          },
          children: {
            abort: {
              containerName: "aborttunnel",
              securityGroupId:
                abortTunnel.securityGroup
                  .securityGroupId,
              subnetIds: vpc.publicSubnets.map(
                (subnet) => subnet.subnetId,
              ),
              taskDefinitionArn:
                abortTunnel.task
                  .taskDefinitionArn,
            },
            bootstrapApproval: {
              containerName:
                "bootstrapapproval",
              securityGroupId:
                bootstrapApproval.securityGroup
                  .securityGroupId,
              subnetIds: vpc.publicSubnets.map(
                (subnet) => subnet.subnetId,
              ),
              taskDefinitionArn:
                bootstrapApproval.task
                  .taskDefinitionArn,
            },
            clusterArn: cluster.clusterArn,
            funding: {
              containerName: "funding",
              createdAt:
                "2026-07-31T00:00:00.000Z",
              expectedTreasuryAddress:
                "0x157a377e4181f3f87c7f6efed5ddc340ccc00dce",
              fundingRecordPath:
                `/var/lib/clockchain/funding-record/releases/${releaseId}/funding-record.json`,
              journalDirectory:
                `/var/lib/clockchain/funding-journal/releases/${releaseId}/journal`,
              keystoreSecretArn:
                treasuryKeystore.secretArn,
              passwordSecretArn:
                treasuryPassword.secretArn,
              securityGroupId:
                funding.securityGroup
                  .securityGroupId,
              subnetIds: vpc.publicSubnets.map(
                (subnet) => subnet.subnetId,
              ),
              taskDefinitionArn:
                funding.task
                  .taskDefinitionArn,
            },
            rpcSecretArn: sepoliaRpc.secretArn,
            verifier: {
              clockchainTokenSecretArn:
                clockchainToken.secretArn,
              containerName: "verifier",
              securityGroupId:
                verifier.securityGroup
                  .securityGroupId,
              subnetIds: vpc.publicSubnets.map(
                (subnet) => subnet.subnetId,
              ),
              taskDefinitionArn:
                verifier.task
                  .taskDefinitionArn,
            },
          },
          coordinator: {
            clockchainTokenSecretArn:
              clockchainToken.secretArn,
            clusterArn: cluster.clusterArn,
            containerName: "coordinator",
            operatorKeyId:
              "clockchain-demo-2026",
            operatorKeySecretArn:
              operatorKey.secretArn,
            relayUrl:
              `https://${props.relayPublicHostname}:8443`,
            rpcSecretArn: sepoliaRpc.secretArn,
            securityGroupId:
              coordinator.securityGroup
                .securityGroupId,
            subnetIds: vpc.publicSubnets.map(
              (subnet) => subnet.subnetId,
            ),
            taskDefinitionArn:
              coordinator.task.taskDefinitionArn,
            tlsCertificatePem:
              props.relayTlsCertificatePem,
            tlsFingerprint:
              props.relayTlsFingerprint,
          },
          paymentMoved: false,
          releaseId,
          repositorySha: props.repositorySha,
          schema:
            "clockchain.aws-operator-runtime/v1",
          sessionId,
        },
        paymentMoved: false,
        schema:
          "clockchain.aws-runtime-input/v1",
      }),
    );
    operator.role.addToPrincipalPolicy(
      new iam.PolicyStatement({
        actions: ["ecs:RunTask"],
        resources: [
          abortTunnel.task.taskDefinitionArn,
          bootstrapApproval.task
            .taskDefinitionArn,
          coordinator.task.taskDefinitionArn,
          funding.task.taskDefinitionArn,
          verifier.task.taskDefinitionArn,
        ],
      }),
    );
    operator.role.addToPrincipalPolicy(
      new iam.PolicyStatement({
        actions: ["ecs:DescribeTasks"],
        conditions: {
          ArnEquals: {
            "ecs:cluster": cluster.clusterArn,
          },
        },
        resources: [
          Stack.of(this).formatArn({
            service: "ecs",
            resource: "task",
            resourceName: `${cluster.clusterName}/*`,
          }),
        ],
      }),
    );
    operator.role.addToPrincipalPolicy(
      new iam.PolicyStatement({
        actions: ["iam:PassRole"],
        conditions: {
          StringEquals: {
            "iam:PassedToService":
              "ecs-tasks.amazonaws.com",
          },
        },
        resources: [
          abortTunnel.role.roleArn,
          bootstrapApproval.role.roleArn,
          coordinator.role.roleArn,
          funding.role.roleArn,
          verifier.role.roleArn,
          abortTunnel.task.executionRole!
            .roleArn,
          bootstrapApproval.task.executionRole!
            .roleArn,
          coordinator.task.executionRole!
            .roleArn,
          funding.task.executionRole!.roleArn,
          verifier.task.executionRole!
            .roleArn,
        ],
      }),
    );

    const dashboard = new cloudwatch.Dashboard(
      this,
      "Dashboard",
      {
        dashboardName:
          "clockchain-handshake-control-plane",
      },
    );
    const services = [
      relay,
      operator,
      bootstrap,
      tunnel,
      publisher,
    ];
    dashboard.addWidgets(
      new cloudwatch.GraphWidget({
        left: services.map((item) =>
          item.service!.metricCpuUtilization()),
        title: "Stateful service CPU",
      }),
    );
    for (const [index, workload] of
      services.entries()) {
      new cloudwatch.Alarm(
        this,
        `ServiceRunningAlarm${index + 1}`,
        {
          comparisonOperator:
            cloudwatch.ComparisonOperator
              .LESS_THAN_THRESHOLD,
          evaluationPeriods: 2,
          metric: new cloudwatch.Metric({
            dimensionsMap: {
              ClusterName:
                cluster.clusterName,
              ServiceName:
                workload.service!
                  .serviceName,
            },
            metricName: "RunningTaskCount",
            namespace: "ECS/ContainerInsights",
            period: Duration.minutes(1),
            statistic: "Minimum",
          }),
          threshold: 1,
          treatMissingData:
            cloudwatch.TreatMissingData
              .BREACHING,
        },
      );
    }

    new CfnOutput(this, "BootstrapApiUrl", {
      value: bootstrapApi.url!,
    });
    new CfnOutput(this, "ControlApiUrl", {
      value: controlApi.url!,
    });
    new CfnOutput(
      this,
      "OperatorConsoleUrl",
      {
        value: `https://${operatorDistribution.distributionDomainName}`,
      },
    );
    new CfnOutput(this, "PublicMonitorUrl", {
      value: `https://${publicDistribution.distributionDomainName}`,
    });
    new CfnOutput(this, "RelayEndpoint", {
      value: `${props.relayPublicHostname}:8443`,
    });
    new CfnOutput(this, "PayerMcpEndpoint", {
      value: `${props.relayPublicHostname}:9443`,
    });
    new CfnOutput(this, "PublicNlbDnsName", {
      value: publicNlb.loadBalancerDnsName,
    });
    new CfnOutput(this, "TaskDefinitions", {
      value: [
        relay,
        operator,
        bootstrap,
        bootstrapApproval,
        abortTunnel,
        tunnel,
        publisher,
        coordinator,
        funding,
        verifier,
      ]
        .map(
          (item) =>
            item.task.taskDefinitionArn,
        )
        .join(","),
    });
    new CfnOutput(this, "SecretArns", {
      value: [
        bootstrapBrokerCapability,
        operatorKey,
        clockchainToken,
        relayTls,
        sepoliaRpc,
        treasuryKeystore,
        treasuryPassword,
        tunnelHostKey,
      ]
        .map((secret) => secret.secretArn)
        .join(","),
    });
    new CfnOutput(
      this,
      "OperatorConsoleBucketName",
      {
        value:
          operatorConsoleBucket.bucketName,
      },
    );
    new CfnOutput(
      this,
      "PublicMonitorBucketName",
      {
        value: publicMonitorBucket.bucketName,
      },
    );
    new CfnOutput(
      this,
      "ControlPlaneRepositoryUri",
      {
        value:
          controlRepository.repositoryUri,
      },
    );
    new CfnOutput(
      this,
      "TunnelRepositoryUri",
      {
        value: tunnelRepository.repositoryUri,
      },
    );
  }

  private createAccessPoints(
    fileSystem: efs.FileSystem,
  ): Record<
    AccessPointName,
    efs.AccessPoint
  > {
    const definitions = {
      bootstrap: ["Bootstrap", "1101"],
      fundingJournal: [
        "FundingJournal",
        "1102",
      ],
      fundingRecord: [
        "FundingRecord",
        "1103",
      ],
      fundingResult: [
        "FundingResult",
        "1110",
      ],
      operator: ["Operator", "1104"],
      publisher: ["Publisher", "1105"],
      relay: ["Relay", "1106"],
      tunnel: ["Tunnel", "1107"],
      verifierEvidence: [
        "VerifierEvidence",
        "1108",
      ],
      verifierOutput: [
        "VerifierOutput",
        "1109",
      ],
    } as const satisfies Record<
      AccessPointName,
      readonly [string, string]
    >;
    return Object.fromEntries(
      Object.entries(definitions).map(
        ([key, [label, identity]]) => [
          key,
          fileSystem.addAccessPoint(
            `${label}AccessPoint`,
            {
              createAcl: {
                ownerGid: identity,
                ownerUid: identity,
                permissions: "0750",
              },
              path: `/clockchain/${key
                .replace(
                  /[A-Z]/g,
                  (letter) =>
                    `-${letter.toLowerCase()}`,
                )}`,
              posixUser: {
                gid: identity,
                uid: identity,
              },
            },
          ),
        ],
      ),
    ) as Record<
      AccessPointName,
      efs.AccessPoint
    >;
  }

  private distribution(
    id: string,
    bucket: s3.Bucket,
  ): cloudfront.Distribution {
    return new cloudfront.Distribution(
      this,
      id,
      {
        defaultBehavior: {
          allowedMethods:
            cloudfront.AllowedMethods
              .ALLOW_GET_HEAD_OPTIONS,
          cachePolicy:
            cloudfront.CachePolicy
              .CACHING_DISABLED,
          origin:
            origins.S3BucketOrigin.withOriginAccessControl(
              bucket,
            ),
          viewerProtocolPolicy:
            cloudfront.ViewerProtocolPolicy
              .REDIRECT_TO_HTTPS,
        },
        defaultRootObject: "index.html",
        minimumProtocolVersion:
          cloudfront.SecurityPolicyProtocol
            .TLS_V1_2_2021,
      },
    );
  }

  private mount(
    name: string,
    accessPoint: efs.AccessPoint,
    containerPath: string,
    readOnly: boolean,
  ): Mount {
    return {
      accessPoint,
      containerPath,
      name,
      readOnly,
    };
  }

  private privateBucket(
    id: string,
  ): s3.Bucket {
    return new s3.Bucket(this, id, {
      blockPublicAccess:
        s3.BlockPublicAccess.BLOCK_ALL,
      encryption:
        s3.BucketEncryption.S3_MANAGED,
      enforceSSL: true,
      removalPolicy: RemovalPolicy.RETAIN,
      versioned: true,
    });
  }

  private secret(
    id: string,
    key: kms.Key,
  ): secretsmanager.Secret {
    return new secretsmanager.Secret(this, id, {
      encryptionKey: key,
      generateSecretString: {
        excludePunctuation: false,
        passwordLength: 64,
      },
      removalPolicy: RemovalPolicy.RETAIN,
    });
  }

  private tunnelListener({
    containerPort,
    healthPort,
    id,
    listenerPort,
    loadBalancer,
    service,
  }: {
    readonly containerPort: number;
    readonly healthPort: string;
    readonly id: string;
    readonly listenerPort: number;
    readonly loadBalancer: elbv2.NetworkLoadBalancer;
    readonly service: Workload;
  }): void {
    if (loadBalancer.vpc === undefined) {
      throw new Error(
        "Network load balancer VPC missing.",
      );
    }
    const listener = loadBalancer.addListener(
      `${id}Listener`,
      {
        port: listenerPort,
        protocol: elbv2.Protocol.TCP,
      },
    );
    const target = new elbv2.NetworkTargetGroup(
      this,
      `${id}TargetGroup`,
      {
        healthCheck:
          healthPort === "8080"
            ? {
                enabled: true,
                healthyHttpCodes: "200",
                interval:
                  Duration.seconds(10),
                path: "/host",
                port: healthPort,
                protocol:
                  elbv2.Protocol.HTTP,
              }
            : {
                enabled: true,
                port: healthPort,
                protocol:
                  elbv2.Protocol.TCP,
              },
        port: containerPort,
        preserveClientIp: false,
        protocol: elbv2.Protocol.TCP,
        targetType: elbv2.TargetType.IP,
        targets: [
          service.service!.loadBalancerTarget(
            {
              containerName:
                id === "Relay"
                  ? "relay"
                  : "tunnel",
              containerPort,
            },
          ),
        ],
        vpc: loadBalancer.vpc,
      },
    );
    listener.addTargetGroups(
      `${id}Targets`,
      target,
    );
  }

  private workload({
    cluster,
    command,
    desiredCount,
    fileSystem,
    id,
    image,
    mounts,
    ports,
    service,
    user,
    vpc,
  }: {
    readonly cluster: ecs.Cluster;
    readonly command: readonly string[];
    readonly desiredCount: number;
    readonly fileSystem: efs.FileSystem;
    readonly id: string;
    readonly image: ecs.ContainerImage;
    readonly mounts: readonly Mount[];
    readonly ports: readonly Port[];
    readonly service: boolean;
    readonly user?: string;
    readonly vpc: ec2.Vpc;
  }): Workload {
    const role = new iam.Role(
      this,
      `${id}TaskRole`,
      {
        assumedBy: new iam.ServicePrincipal(
          "ecs-tasks.amazonaws.com",
        ),
      },
    );
    const task =
      new ecs.FargateTaskDefinition(
        this,
        `${id}Task`,
        {
          cpu: 512,
          memoryLimitMiB: 1024,
          runtimePlatform: {
            cpuArchitecture:
              ecs.CpuArchitecture.X86_64,
            operatingSystemFamily:
              ecs.OperatingSystemFamily.LINUX,
          },
          taskRole: role,
        },
      );
    const logGroup = new logs.LogGroup(
      this,
      `${id}Log`,
      {
        retention: logs.RetentionDays.ONE_MONTH,
        removalPolicy: RemovalPolicy.RETAIN,
      },
    );
    const container = task.addContainer(
      id.toLowerCase(),
      {
        essential: true,
        image:
          image,
        command: [...command],
        logging: ecs.LogDrivers.awsLogs({
          logGroup,
          mode:
            ecs.AwsLogDriverMode.BLOCKING,
          streamPrefix: id.toLowerCase(),
        }),
        readonlyRootFilesystem: true,
        stopTimeout: Duration.seconds(60),
        user,
      },
    );
    if (ports.length > 0) {
      container.addPortMappings(
        ...ports.map((port) => ({
          containerPort:
            port.containerPort,
          name: port.name,
          protocol: ecs.Protocol.TCP,
        })),
      );
    }
    for (const mount of mounts) {
      task.addVolume({
        efsVolumeConfiguration: {
          authorizationConfig: {
            accessPointId:
              mount.accessPoint.accessPointId,
            iam: "ENABLED",
          },
          fileSystemId:
            fileSystem.fileSystemId,
          rootDirectory: "/",
          transitEncryption: "ENABLED",
        },
        name: mount.name,
      });
      container.addMountPoints({
        containerPath: mount.containerPath,
        readOnly: mount.readOnly,
        sourceVolume: mount.name,
      });
      role.addToPrincipalPolicy(
        new iam.PolicyStatement({
          actions: mount.readOnly
            ? [
                "elasticfilesystem:ClientMount",
              ]
            : [
                "elasticfilesystem:ClientMount",
                "elasticfilesystem:ClientWrite",
              ],
          conditions: {
            StringEquals: {
              "elasticfilesystem:AccessPointArn":
                mount.accessPoint
                  .accessPointArn,
            },
          },
          resources: [
            fileSystem.fileSystemArn,
          ],
        }),
      );
    }
    const securityGroup =
      new ec2.SecurityGroup(
        this,
        `${id}Group`,
        {
          allowAllOutbound: true,
          vpc,
        },
      );
    let fargateService:
      | ecs.FargateService
      | undefined;
    fileSystem.connections.allowDefaultPortFrom(
      securityGroup,
    );
    if (service) {
      fargateService = new ecs.FargateService(
        this,
        `${id}Service`,
        {
          assignPublicIp: true,
          circuitBreaker: {
            rollback: true,
          },
          cluster,
          desiredCount,
          maxHealthyPercent: 200,
          minHealthyPercent: 100,
          platformVersion:
            ecs.FargatePlatformVersion.LATEST,
          securityGroups: [securityGroup],
          taskDefinition: task,
          vpcSubnets: {
            subnetType: ec2.SubnetType.PUBLIC,
          },
        },
      );
    }
    return {
      container,
      logGroup,
      role,
      securityGroup,
      ...(fargateService === undefined
        ? {}
        : { service: fargateService }),
      task,
    };
  }
}
