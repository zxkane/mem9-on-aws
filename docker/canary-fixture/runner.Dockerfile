# Test-only image: inherit the exact deployed bootstrap modules, then add tests.
ARG BOOTSTRAP_IMAGE
FROM ${BOOTSTRAP_IMAGE} AS runtime
USER root
RUN apk upgrade --no-cache \
    && cp /bootstrap/schema.sql /bootstrap/runtime-contract.sql /bootstrap/operator/docker/bootstrap/ \
    && cp -R /bootstrap/migrations /bootstrap/operator/docker/bootstrap/ \
    && cd /bootstrap/operator && npm ci --include=dev
COPY scripts/production-consolidation-operator.postgres.test.mjs /bootstrap/operator/scripts/
COPY scripts/canary-fixture-runner.mjs /bootstrap/operator/scripts/
USER node
RUN --network=none node --input-type=module -e "await import('/bootstrap/operator/scripts/canary-fixture-runner.mjs');"
ENTRYPOINT ["node","/bootstrap/operator/scripts/canary-fixture-runner.mjs"]
