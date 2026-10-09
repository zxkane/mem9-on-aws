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
RUN chmod -R a+rX,go-w /bootstrap \
    && rm /bootstrap/nonroot-manifest.json \
    && node /usr/local/lib/mem9/build-nonroot-manifest.mjs
USER node
RUN --network=none node --input-type=module -e "await import('/bootstrap/operator/scripts/canary-fixture-runner.mjs');"
ENTRYPOINT ["/bin/setpriv","--no-new-privs","--","/usr/local/bin/node","/bootstrap/nonroot-dispatch.mjs","canary-fixture"]
