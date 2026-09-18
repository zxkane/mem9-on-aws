FROM node:24-bookworm-slim AS runtime

ENV DEBIAN_FRONTEND=noninteractive \
    PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD=1 \
    MEM9_HUMAN_E2E_TASK=1 \
    MEM9_HUMAN_BROWSER_EXECUTABLE=/usr/bin/google-chrome-stable \
    NODE_EXTRA_CA_CERTS=/app/global-bundle.pem

RUN apt-get update \
    && apt-get dist-upgrade -y \
    && apt-get install -y --no-install-recommends ca-certificates curl gnupg gosu unzip \
    && curl -fsSL https://dl.google.com/linux/linux_signing_key.pub \
      | gpg --dearmor -o /usr/share/keyrings/google-chrome.gpg \
    && echo "deb [arch=arm64 signed-by=/usr/share/keyrings/google-chrome.gpg] https://dl.google.com/linux/chrome/deb/ stable main" \
      > /etc/apt/sources.list.d/google-chrome.list \
    && apt-get update \
    && apt-get install -y --no-install-recommends google-chrome-stable \
    && curl -fsSL https://awscli.amazonaws.com/awscli-exe-linux-aarch64.zip -o /tmp/awscliv2.zip \
    && unzip -q /tmp/awscliv2.zip -d /tmp \
    && /tmp/aws/install \
    && curl -fsSL https://truststore.pki.rds.amazonaws.com/global/global-bundle.pem -o /app-global-bundle.pem \
    && rm -rf /var/lib/apt/lists/* /tmp/aws /tmp/awscliv2.zip

WORKDIR /app
COPY docker/human-acceptance/package.json docker/human-acceptance/package-lock.json ./
RUN npm ci --omit=dev
COPY scripts/ ./scripts/
COPY infra/gateway/namespace-auth.mjs infra/gateway/service-auth.mjs ./infra/gateway/
COPY docker/human-acceptance/entrypoint.sh ./entrypoint.sh
RUN mv /app-global-bundle.pem /app/global-bundle.pem \
    && chmod 755 /app/entrypoint.sh \
    && chown -R node:node /app

ENTRYPOINT ["/app/entrypoint.sh"]
