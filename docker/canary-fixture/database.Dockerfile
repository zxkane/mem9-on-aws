# Synthetic PostgreSQL only; the task has no production credentials or data.
FROM pgvector/pgvector:pg17@sha256:ac08538c6f8b9904c33c8224c5e5706dbe760aca29db1d096972b4052c22a75d AS runtime
USER root
RUN apt-get update && apt-get upgrade -y && rm -rf /var/lib/apt/lists/*
COPY docker/canary-fixture/pg-hba.conf /fixture-pg-hba.conf
ENV PGDATA=/tmp/mem9-fixture-postgres \
    POSTGRES_DB=runtime_credentials_test \
    POSTGRES_HOST_AUTH_METHOD=trust
USER postgres
CMD ["postgres","-c","listen_addresses=127.0.0.1","-c","hba_file=/fixture-pg-hba.conf","-c","log_min_error_statement=panic","-c","log_error_verbosity=terse"]
