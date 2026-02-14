-- Firewall display name overrides (device_key = standalone device or HA base).
-- Run once on existing SQLite DBs if the table was not created by create_all().
CREATE TABLE IF NOT EXISTS firewall_overrides (
  device_key TEXT PRIMARY KEY,
  display_name TEXT NOT NULL,
  comment TEXT,
  updated_at TEXT NOT NULL
);
