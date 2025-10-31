-- D1 schema for NFC Verification System

CREATE TABLE IF NOT EXISTS products (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  nfc_code TEXT UNIQUE NOT NULL,
  product_name TEXT NOT NULL,
  is_authentic INTEGER DEFAULT 1,
  country TEXT,
  country_name TEXT,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS scan_records (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  nfc_code TEXT NOT NULL,
  ip_address TEXT,
  country TEXT,
  scanned_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_products_nfc_code ON products(nfc_code);
CREATE INDEX IF NOT EXISTS idx_scan_records_nfc_code ON scan_records(nfc_code);