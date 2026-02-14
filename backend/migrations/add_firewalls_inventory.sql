-- Firewall source tracking (syslog vs import) for retention and UI.
-- Run once on existing SQLite DBs if the table was not created by create_all().
CREATE TABLE IF NOT EXISTS firewalls (
  device_key TEXT PRIMARY KEY,
  source_syslog INTEGER NOT NULL DEFAULT 0,
  source_import INTEGER NOT NULL DEFAULT 0,
  first_seen_ts TEXT,
  last_seen_ts TEXT,
  last_import_ts TEXT,
  updated_at TEXT NOT NULL
);
