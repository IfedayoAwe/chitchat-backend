CREATE EXTENSION IF NOT EXISTS citext;

CREATE TABLE IF NOT EXISTS users (
    id bigserial PRIMARY KEY,
    created_at timestamp(0) with time zone NOT NULL DEFAULT NOW(),
    full_name text NOT NULL,
    username text NOT NULL,
    email citext UNIQUE NOT NULL,
    phone_no text UNIQUE NOT NULL,
    password_hash bytea NOT NULL,
    activated bool NOT NULL DEFAULT false,
    admin bool NOT NULL DEFAULT false,
    phone_no_verified bool NOT NULL DEFAULT false,
    version integer NOT NULL DEFAULT 1
);