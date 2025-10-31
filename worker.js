/**
 * NFC Verification System - Cloudflare Workers Edition
 */

// Import static assets (will be handled by Cloudflare Pages)
import { Router } from 'itty-router';

// Initialize router
const router = Router();

// CORS headers
const corsHeaders = {
  'Access-Control-Allow-Origin': 'https://verify.plearance.com',
  'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization',
  'Access-Control-Max-Age': '86400',
};

// Security headers
const securityHeaders = {
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'DENY',
  'X-XSS-Protection': '1; mode=block',
  'Referrer-Policy': 'strict-origin-when-cross-origin',
  'Content-Security-Policy': "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline';",
};

// Rate limiting using KV
const rateLimitKey = (ip) => `rate_limit:${ip}`;
const REQUEST_LIMIT = 100;
const TIME_WINDOW = 60 * 1000; // 1 minute

async function checkRateLimit(env, ip) {
  const key = rateLimitKey(ip);
  const current = await env.CACHE.get(key);
  
  if (!current) {
    await env.CACHE.put(key, '1', { expirationTtl: 60 });
    return true;
  }
  
  const count = parseInt(current);
  if (count >= REQUEST_LIMIT) {
    return false;
  }
  
  await env.CACHE.put(key, (count + 1).toString(), { expirationTtl: 60 });
  return true;
}

// Get client IP
function getClientIP(request) {
  return request.headers.get('CF-Connecting-IP') || 
         request.headers.get('X-Forwarded-For') || 
         request.headers.get('X-Real-IP') || 
         '127.0.0.1';
}

// IP to country using Cloudflare's built-in geolocation
function getCountryFromRequest(request) {
  const country = request.cf?.country || 'Unknown';
  const countryName = getCountryName(country);
  return { country, countryName };
}

// Country code to name mapping
function getCountryName(countryCode) {
  const countryNames = {
    'US': 'United States',
    'CN': 'China',
    'JP': 'Japan',
    'DE': 'Germany',
    'GB': 'United Kingdom',
    'FR': 'France',
    'CA': 'Canada',
    'AU': 'Australia',
    'IN': 'India',
    'BR': 'Brazil',
    // Add more as needed
  };
  return countryNames[countryCode] || countryCode;
}

// Validate and sanitize input
function validateInput(input, type = 'string', maxLength = 255) {
  if (!input) return null;
  
  let sanitized = String(input).trim();
  
  if (sanitized.length > maxLength) {
    sanitized = sanitized.substring(0, maxLength);
  }
  
  if (type === 'nfc_code') {
    // Only allow alphanumeric characters and hyphens
    sanitized = sanitized.replace(/[^a-zA-Z0-9-]/g, '');
  }
  
  return sanitized || null;
}

// Generate JWT token (simplified)
async function generateToken(payload, secret) {
  const header = { alg: 'HS256', typ: 'JWT' };
  const encodedHeader = btoa(JSON.stringify(header));
  const encodedPayload = btoa(JSON.stringify(payload));
  
  const data = `${encodedHeader}.${encodedPayload}`;
  const key = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );
  
  const signature = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(data));
  const encodedSignature = btoa(String.fromCharCode(...new Uint8Array(signature)));
  
  return `${data}.${encodedSignature}`;
}

// Verify JWT token
async function verifyToken(token, secret) {
  try {
    const [header, payload, signature] = token.split('.');
    const data = `${header}.${payload}`;
    
    const key = await crypto.subtle.importKey(
      'raw',
      new TextEncoder().encode(secret),
      { name: 'HMAC', hash: 'SHA-256' },
      false,
      ['verify']
    );
    
    const signatureBuffer = Uint8Array.from(atob(signature), c => c.charCodeAt(0));
    const isValid = await crypto.subtle.verify('HMAC', key, signatureBuffer, new TextEncoder().encode(data));
    
    if (isValid) {
      return JSON.parse(atob(payload));
    }
    return null;
  } catch {
    return null;
  }
}

// Middleware for admin authentication
async function requireAuth(request, env) {
  const authHeader = request.headers.get('Authorization');
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return new Response('Unauthorized', { status: 401 });
  }
  
  const token = authHeader.substring(7);
  const payload = await verifyToken(token, env.JWT_SECRET);
  
  if (!payload || payload.role !== 'admin') {
    return new Response('Unauthorized', { status: 401 });
  }
  
  return null; // Continue
}

// API Routes

// Product verification endpoint
router.post('/api/verify/:nfcCode', async (request, env) => {
  try {
    const { nfcCode } = request.params;
    const sanitizedCode = validateInput(nfcCode, 'nfc_code');
    
    if (!sanitizedCode) {
      return new Response(JSON.stringify({ error: 'Invalid NFC code' }), {
        status: 400,
        headers: { 'Content-Type': 'application/json', ...corsHeaders }
      });
    }
    
    const clientIP = getClientIP(request);
    const { country, countryName } = getCountryFromRequest(request);
    
    // Check rate limit
    const rateLimitOk = await checkRateLimit(env, clientIP);
    if (!rateLimitOk) {
      return new Response(JSON.stringify({ error: 'Rate limit exceeded' }), {
        status: 429,
        headers: { 'Content-Type': 'application/json', ...corsHeaders }
      });
    }
    
    // Query product from D1 database
    const product = await env.DB.prepare('SELECT * FROM products WHERE nfc_code = ?')
      .bind(sanitizedCode)
      .first();
    
    if (!product) {
      return new Response(JSON.stringify({
        productName: 'Unknown Product',
        isAuthentic: false,
        message: 'This product failed verification and may be counterfeit',
        timestamp: new Date().toISOString()
      }), {
        status: 200,
        headers: { 'Content-Type': 'application/json', ...corsHeaders }
      });
    }
    
    // Record scan
    await env.DB.prepare('INSERT INTO scan_records (nfc_code, ip_address, country) VALUES (?, ?, ?)')
      .bind(sanitizedCode, clientIP, country)
      .run();
    
    // Bind country on first scan
    if (!product.country) {
      await env.DB.prepare('UPDATE products SET country = ?, country_name = ? WHERE nfc_code = ?')
        .bind(country, countryName, sanitizedCode)
        .run();
    }
    
    // Get scan count
    const scanResult = await env.DB.prepare('SELECT COUNT(*) as total_scans FROM scan_records WHERE nfc_code = ?')
      .bind(sanitizedCode)
      .first();
    
    const totalScans = scanResult?.total_scans || 1;
    const boundCountry = product.country || country;
    const boundCountryName = product.country_name || countryName;
    
    return new Response(JSON.stringify({
      productName: product.product_name,
      isAuthentic: Boolean(product.is_authentic),
      scanCount: totalScans,
      country: boundCountry,
      countryName: boundCountryName,
      timestamp: new Date().toISOString()
    }), {
      status: 200,
      headers: { 'Content-Type': 'application/json', ...corsHeaders }
    });
    
  } catch (error) {
    console.error('Verification error:', error);
    return new Response(JSON.stringify({ error: 'Internal server error' }), {
      status: 500,
      headers: { 'Content-Type': 'application/json', ...corsHeaders }
    });
  }
});

// Admin login endpoint
router.post('/api/admin/login', async (request, env) => {
  try {
    const { username, password } = await request.json();
    
    if (username === env.ADMIN_USERNAME && password === env.ADMIN_PASSWORD) {
      const token = await generateToken({ role: 'admin', username }, env.JWT_SECRET);
      
      return new Response(JSON.stringify({ 
        success: true, 
        token,
        message: 'Login successful' 
      }), {
        status: 200,
        headers: { 'Content-Type': 'application/json', ...corsHeaders }
      });
    }
    
    return new Response(JSON.stringify({ error: 'Invalid credentials' }), {
      status: 401,
      headers: { 'Content-Type': 'application/json', ...corsHeaders }
    });
    
  } catch (error) {
    return new Response(JSON.stringify({ error: 'Invalid request' }), {
      status: 400,
      headers: { 'Content-Type': 'application/json', ...corsHeaders }
    });
  }
});

// Admin verify token endpoint
router.get('/api/admin/verify', async (request, env) => {
  const authError = await requireAuth(request, env);
  if (authError) return authError;
  
  return new Response(JSON.stringify({ valid: true }), {
    status: 200,
    headers: { 'Content-Type': 'application/json', ...corsHeaders }
  });
});

// Admin stats endpoint
router.get('/api/admin/stats', async (request, env) => {
  const authError = await requireAuth(request, env);
  if (authError) return authError;
  
  try {
    const totalProducts = await env.DB.prepare('SELECT COUNT(*) as count FROM products').first();
    const totalScans = await env.DB.prepare('SELECT COUNT(*) as count FROM scan_records').first();
    const authenticProducts = await env.DB.prepare('SELECT COUNT(*) as count FROM products WHERE is_authentic = 1').first();
    
    return new Response(JSON.stringify({
      totalProducts: totalProducts?.count || 0,
      totalScans: totalScans?.count || 0,
      authenticProducts: authenticProducts?.count || 0,
      counterfeitProducts: (totalProducts?.count || 0) - (authenticProducts?.count || 0)
    }), {
      status: 200,
      headers: { 'Content-Type': 'application/json', ...corsHeaders }
    });
    
  } catch (error) {
    return new Response(JSON.stringify({ error: 'Failed to get stats' }), {
      status: 500,
      headers: { 'Content-Type': 'application/json', ...corsHeaders }
    });
  }
});

// Handle CORS preflight
router.options('*', () => {
  return new Response(null, {
    status: 200,
    headers: corsHeaders
  });
});

// Handle all other requests (static files will be served by Cloudflare Pages)
router.all('*', () => {
  return new Response('Not Found', { status: 404 });
});

// Main handler
export default {
  async fetch(request, env, ctx) {
    return router.handle(request, env, ctx).catch(err => {
      console.error('Worker error:', err);
      return new Response('Internal Server Error', { 
        status: 500,
        headers: { ...corsHeaders, ...securityHeaders }
      });
    });
  }
};