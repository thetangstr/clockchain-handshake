#!/usr/bin/env node

import {
  main,
} from "../../../scripts/run-aws-bootstrap-service.mjs";

main().catch(() => {
  process.stderr.write(
    "AWS_BOOTSTRAP_ENTRYPOINT_FAILED\n",
  );
  process.exitCode = 1;
});
