FROM postgres:17

COPY init.sql /docker-entrypoint-initdb.d/

ENV POSTGRES_DB=logsdb
ENV POSTGRES_USER=postgres
ENV POSTGRES_PASSWORD=postgres