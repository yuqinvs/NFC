-- Cloudflare D1 Database Schema for NFC Verification System

-- Products table
CREATE TABLE IF NOT EXISTS products (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    nfc_code TEXT UNIQUE NOT NULL,
    product_name TEXT NOT NULL,
    is_authentic INTEGER DEFAULT 1,
    country TEXT,
    country_name TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Scan records table
CREATE TABLE IF NOT EXISTS scan_records (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    nfc_code TEXT NOT NULL,
    ip_address TEXT,
    country TEXT,
    scan_time DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (nfc_code) REFERENCES products (nfc_code)
);

-- Create indexes for better performance
CREATE INDEX IF NOT EXISTS idx_products_nfc_code ON products(nfc_code);
CREATE INDEX IF NOT EXISTS idx_scan_records_nfc_code ON scan_records(nfc_code);
CREATE INDEX IF NOT EXISTS idx_scan_records_country ON scan_records(country);
CREATE INDEX IF NOT EXISTS idx_scan_records_scan_time ON scan_records(scan_time);

-- Insert sample data
INSERT OR IGNORE INTO products (nfc_code, product_name, is_authentic) VALUES
('NFC001', '高端手表 Model A', 1),
('NFC002', '奢侈品包包 Series B', 1),
('NFC003', '电子产品 Device C', 1),
('NFC004', '珠宝首饰 Collection D', 1),
('NFC005', '运动鞋款 Edition E', 1);