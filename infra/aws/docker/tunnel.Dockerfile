FROM node:22-bookworm-slim

ARG REPOSITORY_SHA

RUN apt-get update \
    && apt-get install --yes --no-install-recommends openssh-server ca-certificates \
    && groupadd --gid 1107 clockchain-tunnel \
    && useradd --uid 1107 --gid 1107 --create-home --home-dir /var/empty/clockchain-tunnel --shell /usr/sbin/nologin clockchain-tunnel \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/clockchain/source
COPY package.json package-lock.json ./
RUN npm ci --ignore-scripts
COPY . .
RUN npm ci --prefix infra/aws --omit=dev --ignore-scripts \
    && cp infra/aws/docker/sshd_config /etc/ssh/clockchain_sshd_config

RUN test -n "$REPOSITORY_SHA" \
    && mkdir -p /opt/clockchain /run/clockchain /run/sshd \
    && chown clockchain-tunnel:clockchain-tunnel /run/clockchain \
    && chmod 0700 /run/clockchain \
    && chmod 0755 /run/sshd \
    && node -e 'const fs=require("node:fs"); const sha=process.env.REPOSITORY_SHA; if (!/^[0-9a-f]{40}$/.test(sha)) process.exit(1); fs.writeFileSync("/opt/clockchain/release.json", JSON.stringify({repositorySha:sha,schema:"clockchain.container-release/v1"})+"\\n",{mode:0o444})'

ENV NODE_ENV=production
EXPOSE 2222 9443 8080
VOLUME ["/run/clockchain"]
CMD ["node", "infra/aws/runtime/tunnel-entrypoint.mjs"]
