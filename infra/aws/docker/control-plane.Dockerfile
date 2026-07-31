FROM node:22-bookworm-slim

ARG REPOSITORY_SHA

RUN apt-get update \
    && apt-get install --yes --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/clockchain/source
COPY package.json package-lock.json ./
RUN npm ci --ignore-scripts
COPY . .
RUN npm ci --prefix infra/aws --omit=dev --ignore-scripts

RUN test -n "$REPOSITORY_SHA" \
    && mkdir -p /opt/clockchain /var/lib/clockchain \
    && node -e 'const fs=require("node:fs"); const sha=process.env.REPOSITORY_SHA; if (!/^[0-9a-f]{40}$/.test(sha)) process.exit(1); fs.writeFileSync("/opt/clockchain/release.json", JSON.stringify({repositorySha:sha,schema:"clockchain.container-release/v1"})+"\\n",{mode:0o444})'

ENV NODE_ENV=production
VOLUME ["/var/lib/clockchain"]
USER node
CMD ["node", "infra/aws/runtime/operator-worker-entrypoint.mjs"]
