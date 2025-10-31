#!/usr/bin/env node
/**
 * Export local SQLite data (products, scan_records) into a SQL file
 * suitable for Cloudflare D1 execution. This does not create tables;
 * run D1 migrations first, then execute the generated seed file.
 *
 * Usage:
 *   node scripts/export_sqlite_to_sql.js [path_to_sqlite_db]
 *
 * Output:
 *   migrations/0003_seed_from_sqlite.sql
 */

const fs = require('fs');
const path = require('path');
const initSqlJs = require('sql.js/dist/sql-wasm.js');

const inputPath = process.argv[2] || path.resolve(process.cwd(), 'nfc_verification.db');
const fallbackPath = path.resolve(process.cwd(), 'database.db');
let dbPath = inputPath;

if (!fs.existsSync(dbPath)) {
  if (fs.existsSync(fallbackPath)) {
    dbPath = fallbackPath;
    console.log(`Using fallback SQLite DB: ${dbPath}`);
  } else {
    console.error(`SQLite DB not found at ${inputPath} or ${fallbackPath}`);
    process.exit(1);
  }
}

function escapeString(str) {
  if (str === null || str === undefined) return 'NULL';
  return `'${String(str).replace(/'/g, "''")}'`;
}

function toInt(val) {
  if (val === null || val === undefined) return 'NULL';
  const num = Number(val);
  return Number.isFinite(num) ? String(num) : 'NULL';
}

(async () => {
  const wasmPath = path.resolve(process.cwd(), 'node_modules/sql.js/dist/sql-wasm.wasm');
  const SQL = await initSqlJs({ locateFile: () => wasmPath });
  const fileBuffer = fs.readFileSync(dbPath);
  const u8 = new Uint8Array(fileBuffer);
  const db = new SQL.Database(u8);

  // Helper to run query and return rows
  function all(sql) {
    const stmt = db.prepare(sql);
    const rows = [];
    while (stmt.step()) {
      rows.push(stmt.getAsObject());
    }
    stmt.free();
    return rows;
  }

  const products = all('SELECT nfc_code, product_name, is_authentic, country, country_name FROM products');
  const scans = all('SELECT id, nfc_code, ip_address, country, created_at FROM scan_records');

  let sqlOut = '';
  sqlOut += '-- Seed data exported from local SQLite\n';
  sqlOut += 'BEGIN TRANSACTION;\n\n';

  for (const p of products) {
    const nfc = escapeString(p.nfc_code);
    const name = escapeString(p.product_name);
    const authentic = toInt(p.is_authentic);
    const country = escapeString(p.country);
    const countryName = escapeString(p.country_name);
    sqlOut += `INSERT OR IGNORE INTO products (nfc_code, product_name, is_authentic, country, country_name) VALUES (${nfc}, ${name}, ${authentic}, ${country}, ${countryName});\n`;
  }

  sqlOut += '\n';
  for (const s of scans) {
    const nfc = escapeString(s.nfc_code);
    const ip = escapeString(s.ip_address);
    const country = escapeString(s.country);
    const createdAt = escapeString(s.created_at);
    sqlOut += `INSERT INTO scan_records (nfc_code, ip_address, country, created_at) VALUES (${nfc}, ${ip}, ${country}, ${createdAt});\n`;
  }

  sqlOut += '\nCOMMIT;\n';

  const outDir = path.resolve(process.cwd(), 'migrations');
  const outFile = path.join(outDir, '0003_seed_from_sqlite.sql');
  fs.mkdirSync(outDir, { recursive: true });
  fs.writeFileSync(outFile, sqlOut, 'utf8');
  console.log(`Wrote seed SQL to ${outFile}`);
})();