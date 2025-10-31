/* Cloudflare Worker for NFC Verification System */

function json(data, init = {}) {
  return new Response(JSON.stringify(data), {
    headers: { 'Content-Type': 'application/json' },
    ...init,
  });
}

function getCountryName(code) {
  try {
    if (!code || code === 'Unknown' || code === '-') return 'Unknown';
    const regionNames = new Intl.DisplayNames(['en'], { type: 'region' });
    return regionNames.of(code) || code;
  } catch {
    return code || 'Unknown';
  }
}

// Ensure required D1 tables exist (runtime bootstrap fallback)
async function ensureSchema(env) {
  try {
    await env.DB.prepare(`CREATE TABLE IF NOT EXISTS products (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      nfc_code TEXT UNIQUE NOT NULL,
      product_name TEXT NOT NULL,
      is_authentic INTEGER DEFAULT 1,
      country TEXT,
      country_name TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );`).run();

    await env.DB.prepare(`CREATE TABLE IF NOT EXISTS scan_records (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      nfc_code TEXT NOT NULL,
      ip_address TEXT,
      country TEXT,
      scanned_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );`).run();

    await env.DB.prepare(`CREATE TABLE IF NOT EXISTS admin_tokens (
      token TEXT PRIMARY KEY,
      issued_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      expires_at DATETIME NOT NULL
    );`).run();

    await env.DB.prepare(`CREATE INDEX IF NOT EXISTS idx_products_nfc_code ON products(nfc_code);`).run();
    await env.DB.prepare(`CREATE INDEX IF NOT EXISTS idx_scan_records_nfc_code ON scan_records(nfc_code);`).run();
    await env.DB.prepare(`CREATE INDEX IF NOT EXISTS idx_admin_tokens_expires ON admin_tokens(expires_at);`).run();
  } catch (e) {
    // no-op: if creation fails, queries below will surface errors
  }
}

async function verifyAdminToken(request, env) {
  const auth = request.headers.get('Authorization') || '';
  const token = auth.startsWith('Bearer ') ? auth.slice(7) : '';
  if (!token) return { ok: false, error: 'Missing Authorization header' };
  const now = new Date().toISOString();
  const row = await env.DB.prepare('SELECT token FROM admin_tokens WHERE token = ? AND expires_at > ?')
    .bind(token, now)
    .first();
  return row ? { ok: true, token } : { ok: false, error: 'Invalid or expired token' };
}

async function handleAdminLogin(request, env) {
  if (request.method !== 'POST') return json({ error: 'Method Not Allowed' }, { status: 405 });
  let body = {};
  try {
    body = await request.json();
  } catch {}
  const { username, password } = body;
  const validUser = (username === env.ADMIN_USERNAME) && (password === env.ADMIN_PASSWORD);
  if (!validUser) return json({ error: 'Invalid credentials' }, { status: 401 });
  const ttlHours = parseInt(env.ADMIN_TOKEN_TTL_HOURS || '24', 10);
  const expiresAt = new Date(Date.now() + ttlHours * 3600 * 1000).toISOString();
  const token = crypto.randomUUID();
  await ensureSchema(env);
  await env.DB.prepare('INSERT INTO admin_tokens (token, expires_at) VALUES (?, ?)')
    .bind(token, expiresAt)
    .run();
  return json({ token, expiresAt });
}

async function handleAdminVerify(request, env) {
  const auth = await verifyAdminToken(request, env);
  if (!auth.ok) return json({ error: auth.error }, { status: 401 });
  return json({ success: true, message: 'Token is valid' });
}

async function handleAdminStats(request, env) {
  const auth = await verifyAdminToken(request, env);
  if (!auth.ok) return json({ error: auth.error }, { status: 401 });
  await ensureSchema(env);
  try {
    const { results } = await env.DB.prepare(`
      SELECT 
        p.nfc_code,
        p.product_name,
        p.country,
        p.country_name,
        p.is_authentic,
        COALESCE(sc.total_scans, 0) as total_scans
      FROM products p
      LEFT JOIN (
        SELECT nfc_code, COUNT(id) as total_scans
        FROM scan_records
        GROUP BY nfc_code
      ) sc ON p.nfc_code = sc.nfc_code
      ORDER BY total_scans DESC
    `).all();
    return json({ products: results || [] });
  } catch (e) {
    return json({ error: 'Failed to get statistics', details: String(e) }, { status: 500 });
  }
}

async function handleAdminAddProduct(request, env) {
  if (request.method !== 'POST') return json({ error: 'Method Not Allowed' }, { status: 405 });
  const auth = await verifyAdminToken(request, env);
  if (!auth.ok) return json({ error: auth.error }, { status: 401 });
  let body = {};
  try {
    body = await request.json();
  } catch {}
  const { nfcCode, productName, isAuthentic } = body;
  if (!nfcCode || !productName) return json({ error: 'nfcCode and productName are required' }, { status: 400 });
  const authentic = (String(isAuthentic ?? '1').trim() === '1') ? 1 : 0;
  try {
    await ensureSchema(env);
    await env.DB.prepare('INSERT OR IGNORE INTO products (nfc_code, product_name, is_authentic) VALUES (?, ?, ?)')
      .bind(String(nfcCode).trim(), String(productName).trim(), authentic)
      .run();
    return json({ success: true });
  } catch (e) {
    return json({ error: 'Failed to add product', details: String(e) }, { status: 500 });
  }
}

// Verify API (unchanged)
async function handleVerify(request, env, nfcCode) {
  if (request.method !== 'POST' && request.method !== 'GET') {
    return json({ error: 'Method Not Allowed' }, { status: 405 });
  }

  const clientIP = request.headers.get('CF-Connecting-IP') || '';
  const country = (request.cf && request.cf.country) || 'Unknown';
  const countryName = getCountryName(country);

  await ensureSchema(env);

  try {
    const product = await env.DB.prepare('SELECT * FROM products WHERE nfc_code = ?').bind(nfcCode).first();

    if (!product) {
      return json({
        productName: 'Unknown Product',
        isAuthentic: false,
        message: 'This product failed verification and may be counterfeit',
        timestamp: new Date().toISOString(),
      });
    }

    // Count scans before inserting to determine if this is the first scan
    const prevRes = await env.DB.prepare('SELECT COUNT(*) as total_before FROM scan_records WHERE nfc_code = ?')
      .bind(nfcCode)
      .first();
    const isFirstScan = !(prevRes && prevRes.total_before > 0);

    await env.DB.prepare('INSERT INTO scan_records (nfc_code, ip_address, country) VALUES (?, ?, ?)')
      .bind(nfcCode, clientIP, country)
      .run();

    if (!product.country) {
      await env.DB.prepare('UPDATE products SET country = ?, country_name = ? WHERE nfc_code = ?')
        .bind(country, countryName, nfcCode)
        .run();
    }

    const scanResult = await env.DB.prepare('SELECT COUNT(*) as total_scans FROM scan_records WHERE nfc_code = ?')
      .bind(nfcCode)
      .first();

    const totalScans = scanResult ? scanResult.total_scans : 1;
    const boundCountry = product.country || country;
    const boundCountryName = product.country_name || countryName;

    // Country ranking for this product (number of scans in bound country)
    const countryCountRes = await env.DB.prepare(
      'SELECT COUNT(*) as country_scans FROM scan_records WHERE nfc_code = ? AND country = ?'
    ).bind(nfcCode, boundCountry).first();
    const countryRank = countryCountRes ? countryCountRes.country_scans : 1;

    return json({
      productName: product.product_name,
      isAuthentic: Boolean(product.is_authentic),
      scanCount: totalScans,
      country: boundCountry,
      countryName: boundCountryName,
      countryRank,
      isNewUser: isFirstScan,
      timestamp: new Date().toISOString(),
    });
  } catch (error) {
    return json({ error: 'Internal server error', details: String(error) }, { status: 500 });
  }
}

async function handleTestIP(request) {
  const clientIP = request.headers.get('CF-Connecting-IP') || '';
  const country = (request.cf && request.cf.country) || 'Unknown';
  const countryName = getCountryName(country);
  return json({ ip: clientIP, country, countryName });
}

// Import products via Excel or CSV
async function handleImportProducts(request, env) {
  if (request.method !== 'POST') return json({ error: 'Method Not Allowed' }, { status: 405 });
  const auth = await verifyAdminToken(request, env);
  if (!auth.ok) return json({ error: auth.error }, { status: 401 });

  await ensureSchema(env);

  const formData = await request.formData();
  const file = formData.get('excelFile') || formData.get('file') || formData.get('upload');
  if (!file) return json({ error: 'Missing file field: excelFile' }, { status: 400 });

  const contentType = file.type || '';
  const buffer = await file.arrayBuffer();

  // Try XLSX first if MIME indicates Excel, else fallback to CSV
  let rows = [];
  try {
    if (contentType.includes('spreadsheet') || contentType.includes('xlsx') || contentType.includes('excel')) {
      // Dynamic import to keep Worker lightweight
      const XLSX = await import('xlsx/xlsx.mjs');
      const wb = XLSX.read(buffer, { type: 'array' });
      const sheet = wb.Sheets[wb.SheetNames[0]];
      rows = XLSX.utils.sheet_to_json(sheet, { defval: '' });
    } else {
      const text = new TextDecoder().decode(new Uint8Array(buffer));
      rows = csvToJson(text);
    }
  } catch (e) {
    // If XLSX parse fails, fallback to CSV
    try {
      const text = new TextDecoder().decode(new Uint8Array(buffer));
      rows = csvToJson(text);
    } catch (err) {
      return json({ error: 'Failed to parse file', details: String(err) }, { status: 400 });
    }
  }

  let inserted = 0;
  const errors = [];
  for (const r of rows) {
    const nfc = (r.nfc_code || r.NFC || r.NFC_CODE || r.nfc || '').toString().trim();
    const name = (r.product_name || r.PRODUCT_NAME || r.name || '').toString().trim();
    const authenticRaw = r.is_authentic ?? r.authentic ?? r.IS_AUTHENTIC;
    const isAuthentic = (String(authenticRaw ?? '1').trim() === '1') ? 1 : 0;
    if (!nfc || !name) {
      errors.push(`Missing nfc_code or product_name in row: ${JSON.stringify(r)}`);
      continue;
    }
    try {
      await env.DB.prepare('INSERT OR IGNORE INTO products (nfc_code, product_name, is_authentic) VALUES (?, ?, ?)')
        .bind(nfc, name, isAuthentic)
        .run();
      inserted++;
    } catch (e) {
      errors.push(`Failed to insert ${nfc}: ${String(e)}`);
    }
  }

  return json({ successCount: inserted, errorCount: errors.length, errors, message: `Imported ${inserted} products` });
}

function csvToJson(text) {
  const lines = text.split(/\r?\n/).filter(Boolean);
  if (lines.length === 0) return [];
  const headers = lines[0].split(',').map(h => h.trim());
  const data = [];
  for (let i = 1; i < lines.length; i++) {
    const cols = splitCSVLine(lines[i]);
    if (cols.length === 0) continue;
    const obj = {};
    headers.forEach((h, idx) => obj[h] = (cols[idx] ?? '').trim());
    data.push(obj);
  }
  return data;
}

function splitCSVLine(line) {
  const result = [];
  let current = '';
  let inQuotes = false;
  for (let i = 0; i < line.length; i++) {
    const ch = line[i];
    if (ch === '"') {
      inQuotes = !inQuotes;
      continue;
    }
    if (ch === ',' && !inQuotes) {
      result.push(current);
      current = '';
    } else {
      current += ch;
    }
  }
  result.push(current);
  return result;
}

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    // Admin routes
    if (url.pathname === '/api/admin/login') {
      return handleAdminLogin(request, env);
    }
    if (url.pathname === '/api/admin/verify') {
      return handleAdminVerify(request, env);
    }
    if (url.pathname === '/api/admin/stats') {
      return handleAdminStats(request, env);
    }
    if (url.pathname === '/api/admin/products') {
      return handleAdminAddProduct(request, env);
    }
    if (url.pathname === '/api/admin/products/import') {
      return handleImportProducts(request, env);
    }

    // API routes
    if (url.pathname === '/api/verify') {
      const sp = url.searchParams;
      let nfcCode = sp.get('nfcid') || sp.get('nfc_code') || sp.get('nfc');
      if (!nfcCode) {
        try {
          const body = await request.json();
          nfcCode = body && (body.nfcid || body.nfcCode || body.nfc || body.nfc_code);
        } catch {}
      }
      if (!nfcCode) {
        return json({ error: 'Missing nfcid parameter' }, { status: 400 });
      }
      return handleVerify(request, env, String(nfcCode).trim());
    }

    // path-based /api/verify/:code disabled; use /api/verify?nfcid=XXX

    if (url.pathname.startsWith('/api/test/ip-location')) {
      return handleTestIP(request);
    }

    // Static page path rewrites for nicer URLs
    if (env.ASSETS && typeof env.ASSETS.fetch === 'function') {
      const rewriteMap = new Map([
        ['/', '/index.html'],
        ['/admin-login', '/admin-login.html'],
        ['/admin-dashboard', '/admin-dashboard.html'],
        ['/verify', '/verify.html']
      ]);
      const target = rewriteMap.get(url.pathname);
      if (target) {
        const rewritten = new URL(request.url);
        rewritten.pathname = target;
        return env.ASSETS.fetch(new Request(rewritten.toString(), request));
      }
      // dynamic rewrite for /verify/:code disabled; only /verify and ?nfcid=XXX are supported
      return env.ASSETS.fetch(request);
    }

    return new Response('Not Found', { status: 404 });
  },
};