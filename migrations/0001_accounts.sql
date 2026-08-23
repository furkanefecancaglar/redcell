-- Accounts, sessions and API keys.
--
-- These lived in KV until 2026-08-23, when the free plan's 1,000 writes a day ran out and
-- registration returned a bare Cloudflare 1101 for the rest of the day — nobody could create an
-- account. D1's free tier allows 100,000 row writes a day for the same price: nothing.
--
-- Apply:  wrangler d1 execute redcell-db --remote --file=migrations/0001_accounts.sql
-- Local:  wrangler d1 execute redcell-db --local  --file=migrations/0001_accounts.sql
CREATE TABLE IF NOT EXISTS users (
  email      TEXT PRIMARY KEY,
  id         TEXT NOT NULL UNIQUE,
  name       TEXT,
  salt       TEXT NOT NULL,
  hash       TEXT NOT NULL,
  iters      INTEGER NOT NULL,
  created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS users_by_id ON users(id);

CREATE TABLE IF NOT EXISTS sessions (
  token   TEXT PRIMARY KEY,
  uid     TEXT NOT NULL,
  created INTEGER NOT NULL,
  expires INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS sessions_by_uid ON sessions(uid);
CREATE INDEX IF NOT EXISTS sessions_by_expiry ON sessions(expires);

CREATE TABLE IF NOT EXISTS api_keys (
  hash    TEXT PRIMARY KEY,
  uid     TEXT NOT NULL,
  prefix  TEXT NOT NULL,
  created INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS api_keys_by_uid ON api_keys(uid);
