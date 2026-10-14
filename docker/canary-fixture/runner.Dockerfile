# Test-only image: inherit the exact deployed bootstrap modules, then add tests.
ARG BOOTSTRAP_IMAGE
FROM ${BOOTSTRAP_IMAGE} AS runtime
USER root
# Install the fixture's Vitest dependency alongside the locked production
# dependencies, then restore the bootstrap package metadata.
RUN apk upgrade --no-cache \
    && cp /bootstrap/schema.sql /bootstrap/runtime-contract.sql /bootstrap/operator/docker/bootstrap/ \
    && cp -R /bootstrap/migrations /bootstrap/operator/docker/bootstrap/ \
    && cd /bootstrap/operator \
    && cp package.json /tmp/mem9-canary-package.json \
    && node --input-type=commonjs -e "\
      const fs = require('node:fs'); \
      const pkg = JSON.parse(fs.readFileSync('package.json', 'utf8')); \
      if (typeof pkg.devDependencies?.vitest !== 'string') throw new Error('Missing canary test runner'); \
      pkg.devDependencies = { vitest: pkg.devDependencies.vitest }; \
      fs.writeFileSync('package.json', JSON.stringify(pkg));" \
    && npm ci --include=dev \
    && mv /tmp/mem9-canary-package.json package.json
COPY scripts/production-consolidation-operator.postgres.test.mjs /bootstrap/operator/scripts/
COPY scripts/canary-fixture-runner.mjs /bootstrap/operator/scripts/
RUN chmod -R a+rX,go-w /bootstrap \
    && rm /bootstrap/nonroot-manifest.json \
    && node /usr/local/lib/mem9/build-nonroot-manifest.mjs
USER node
RUN --network=none node --input-type=module -e "await import('/bootstrap/operator/scripts/canary-fixture-runner.mjs');"
ENTRYPOINT ["/bin/setpriv","--no-new-privs","--","/usr/local/bin/node","/bootstrap/nonroot-dispatch.mjs","canary-fixture"]
