CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    is_disabled BOOLEAN DEFAULT FALSE
);

CREATE TABLE documents (
    id SERIAL PRIMARY KEY,
    owner_id INTEGER REFERENCES users(id),
    title TEXT NOT NULL,
    filename TEXT NOT NULL,
    metadata TEXT,
    uploaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE document_shares (
    id SERIAL PRIMARY KEY,
    document_id INTEGER REFERENCES documents(id),
    shared_with INTEGER REFERENCES users(id)
);

-- ---------------------------------------------------------------------------
-- IMPORTANT — VALIDATOR ACCOUNTS
--
-- The following user accounts are required for the automated validation
-- system used in the course. These accounts MUST always exist in the system.
--
-- The usernames and logical identities of these accounts must NOT be removed
-- or changed, as the validator depends on them to execute security tests.
--
-- The validator authenticates using the plaintext credentials defined below.
-- Therefore:
--
--  • These credentials must remain valid for authentication.
--  • The passwords themselves must not be changed.
--
-- You are free to improve the authentication system (e.g., password hashing,
-- stronger password policies, etc.). If you implement password hashing or
-- other changes to the login mechanism, ensure that the credentials below
-- still successfully authenticate.
--
-- In other words: the authentication implementation may change, but the
-- following username/password combinations must continue to work.
--
-- These accounts are used by the automated validator to test:
--   • authentication
--   • authorization
--   • document sharing
--   • access control
--   • administrative operations
--
-- Removing or altering these accounts will cause automated validation to fail.
-- ---------------------------------------------------------------------------
-- The passwords before hashed are:
-- admin: L|fP1D%327mB
-- alice: tth1mJj5?£58
-- bob: De586:Iq6}?!
INSERT INTO users (username, password, is_disabled) VALUES
('admin', '$argon2id$v=19$m=19456,t=2,p=1$7fCejpSSM5fZ8l/FtvPagQ$MgdO3kMtWGh9cffS6DUVTvOi3jhYtCLNdmcCnlrrMKE', FALSE),
('alice', '$argon2id$v=19$m=19456,t=2,p=1$mleksTrIeVyVOJR7V3q7RA$kBbxqeJFJFsrwVBSVZPtcwZKByeW5NqH9r543VJOfgg', FALSE),
('bob', '$argon2id$v=19$m=19456,t=2,p=1$mY1dnZmAEtk3mStb7iL95A$87+exckdOicEVdvyrZTt9AFJdvGkljlovQKRjKIveog', FALSE);