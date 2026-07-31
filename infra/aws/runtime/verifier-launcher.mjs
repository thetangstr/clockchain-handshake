import {
  RunTaskCommand,
} from "@aws-sdk/client-ecs";

export function createVerifierLauncher({
  ecs,
  task,
}) {
  if (
    typeof ecs?.send !== "function" ||
    task === null ||
    typeof task !== "object"
  ) {
    throw new Error(
      "AWS verifier launcher configuration invalid.",
    );
  }
  return Object.freeze({
    async launch(overrides) {
      const response = await ecs.send(
        new RunTaskCommand({
          ...task,
          overrides,
        }),
      );
      const arn = response.tasks?.[0]?.taskArn;
      if (
        typeof arn !== "string" ||
        arn.length === 0 ||
        (response.failures?.length ?? 0) !== 0
      ) {
        throw new Error(
          "AWS verifier launch failed safely.",
        );
      }
      return Object.freeze({
        paymentMoved: false,
        status: "LAUNCHED",
        taskArn: arn,
      });
    },
  });
}
