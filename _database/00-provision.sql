
-- Schema creation

CREATE TABLE users (
    login_name VARCHAR(20) PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    email VARCHAR(100) NOT NULL,
    password BYTEA NOT NULL,
    created_on TIMESTAMP NOT NULL DEFAULT now()
);

CREATE TABLE sessions (
    id SERIAL PRIMARY KEY,
    login_name VARCHAR(20) NOT NULL REFERENCES users(login_name),
    agent VARCHAR(100) NOT NULL,
    secret VARCHAR(8) NOT NULL,
    created_on TIMESTAMP NOT NULL DEFAULT now(),
    expires_on TIMESTAMP NOT NULL
);

CREATE INDEX sessions_idx ON sessions (login_name);

CREATE TABLE access_tokens (
    id SERIAL PRIMARY KEY,
    login_name VARCHAR(20) NOT NULL REFERENCES users(login_name),
    name VARCHAR(20),
    secret VARCHAR(8) NOT NULL,
    created_on TIMESTAMP NOT NULL DEFAULT now(),
    last_used TIMESTAMP,
    revoked BOOLEAN NOT NULL DEFAULT FALSE,
    revoked_on TIMESTAMP
);

CREATE INDEX access_tokens_idx ON access_tokens (login_name);