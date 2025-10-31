-- Admin tokens table for Worker-based authentication
CREATE TABLE IF NOT EXISTS admin_tokens (
  token TEXT PRIMARY KEY,
  issued_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  expires_at DATETIME NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_admin_tokens_expires ON admin_tokens(expires_at);