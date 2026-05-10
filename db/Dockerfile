FROM postgres:18

# Copy initialization scripts
COPY init.sql /docker-entrypoint-initdb.d/

# Optional: set default database configuration
ENV POSTGRES_DB=docdb
ENV POSTGRES_USER=postgres
ENV POSTGRES_PASSWORD=postgres

# Need to change that