CREATE TABLE audit_logs (
    id SERIAL PRIMARY KEY,
    timestamp TIMESTAMPTZ DEFAULT NOW() NOT NULL,
    user_id INTEGER,
    action VARCHAR(50) NOT NULL,
    detail TEXT
);

REVOKE DELETE, UPDATE ON audit_logs FROM PUBLIC;