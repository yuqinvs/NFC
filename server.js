const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const cors = require('cors');
const bodyParser = require('body-parser');
const path = require('path');
const crypto = require('crypto');
const multer = require('multer');
const XLSX = require('xlsx');
const fs = require('fs');
const geoip = require('geoip-lite');
require('dotenv').config();

// IP2Location database cache
let ip2locationData = [];
let isIP2LocationLoaded = false;

const app = express();
const PORT = process.env.PORT || 3000;

// Simple admin credentials and token storage
const ADMIN_CREDENTIALS = {
    username: process.env.ADMIN_USERNAME || 'admin',
    password: process.env.ADMIN_PASSWORD || 'admin123'
};

// Store valid admin tokens (should use Redis or database in production)
const adminTokens = new Set();

// Request rate limiting storage
const requestCounts = new Map();
const REQUEST_LIMIT = 100; // Maximum 100 requests per minute
const TIME_WINDOW = 60 * 1000; // 1 minute

// Request rate limiting middleware
function rateLimitMiddleware(req, res, next) {
    const clientIP = getClientIP(req);
    const now = Date.now();
    
    // Clean up expired records
    for (const [ip, data] of requestCounts.entries()) {
        if (now - data.firstRequest > TIME_WINDOW) {
            requestCounts.delete(ip);
        }
    }
    
    // Check current IP request count
    if (!requestCounts.has(clientIP)) {
        requestCounts.set(clientIP, {
            count: 1,
            firstRequest: now
        });
    } else {
        const ipData = requestCounts.get(clientIP);
        if (now - ipData.firstRequest < TIME_WINDOW) {
            ipData.count++;
            if (ipData.count > REQUEST_LIMIT) {
                return res.status(429).json({ 
                    error: 'Too many requests, please try again later',
                    retryAfter: Math.ceil((TIME_WINDOW - (now - ipData.firstRequest)) / 1000)
                });
            }
        } else {
            // Reset counter
            ipData.count = 1;
            ipData.firstRequest = now;
        }
    }
    
    next();
}

// Security headers middleware
function securityHeadersMiddleware(req, res, next) {
    // Prevent XSS attacks
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('X-XSS-Protection', '1; mode=block');
    
    // Content Security Policy
    res.setHeader('Content-Security-Policy', 
        "default-src 'self'; " +
        "script-src 'self' 'unsafe-inline'; " +
        "style-src 'self' 'unsafe-inline'; " +
        "img-src 'self' data:; " +
        "connect-src 'self'"
    );
    
    // Prevent information leakage
    res.removeHeader('X-Powered-By');
    
    next();
}

// Middleware
app.use(cors());
app.use(express.json({ limit: '10mb' }));
app.use(express.static('public'));

// Apply security headers
app.use(securityHeadersMiddleware);

// Apply rate limiting to all API routes
app.use('/api', rateLimitMiddleware);

// Input validation and sanitization function
function validateAndSanitizeInput(input, type = 'string', maxLength = 255) {
    if (input === null || input === undefined) return null;
    
    // Convert to string and trim
    const sanitized = String(input).trim();
    
    // Length limit
    if (sanitized.length > maxLength) {
        throw new Error(`Input length exceeds limit (${maxLength} characters)`);
    }
    
    switch (type) {
        case 'nfc_code':
            // NFC code only allows numbers and letters, maximum 8 characters
            if (!/^[A-Za-z0-9]{1,8}$/.test(sanitized)) {
                throw new Error('NFC code can only contain letters and numbers, and cannot exceed 8 characters');
            }
            break;
        case 'product_name':
            // Product name allows Chinese, English, numbers and common symbols
            if (!/^[\u4e00-\u9fff\w\s\-\.\(\)（）]+$/.test(sanitized)) {
                throw new Error('Invalid product name format');
            }
            break;
        case 'username':
            // Username only allows letters, numbers and underscores
            if (!/^[A-Za-z0-9_]{1,50}$/.test(sanitized)) {
                throw new Error('Invalid username format');
            }
            break;
        case 'country':
            // Country code only allows uppercase letters
            if (!/^[A-Z]{2}$/.test(sanitized)) {
                return 'Unknown';
            }
            break;
    }
    
    return sanitized;
}

// Error handling middleware
function handleError(res, error, defaultMessage = 'Internal server error') {
    console.error('Error:', error);
    if (error.message && error.message.includes('Invalid format') || error.message.includes('exceeds limit')) {
        return res.status(400).json({ error: error.message });
    }
    return res.status(500).json({ error: defaultMessage });
}

// Initialize database
const db = new sqlite3.Database('nfc_verification.db');

// Create tables
db.serialize(() => {
    // Products table - 添加country字段用于存储首次扫描的国家
    db.run(`CREATE TABLE IF NOT EXISTS products (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        nfc_code TEXT UNIQUE NOT NULL,
        product_name TEXT NOT NULL,
        is_authentic INTEGER NOT NULL DEFAULT 1,
        country TEXT,
        country_name TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);

    // 为现有的products表添加country字段（如果不存在）
    db.run(`ALTER TABLE products ADD COLUMN country TEXT`, (err) => {
        if (err && !err.message.includes('duplicate column name')) {
            console.error('Error adding country column:', err);
        }
    });
    
    db.run(`ALTER TABLE products ADD COLUMN country_name TEXT`, (err) => {
        if (err && !err.message.includes('duplicate column name')) {
            console.error('Error adding country_name column:', err);
        }
    });

    // Scan records table - 保留扫描历史记录
    db.run(`CREATE TABLE IF NOT EXISTS scan_records (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        nfc_code TEXT NOT NULL,
        ip_address TEXT NOT NULL,
        country TEXT,
        scan_time DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);

    // Insert some sample product data
    db.run(`INSERT OR IGNORE INTO products (nfc_code, product_name, is_authentic) VALUES 
        ('NFC001', 'Premium Watch Model A', 1),
        ('NFC002', 'Luxury Bag Series B', 1),
        ('NFC003', 'Electronic Device C', 1),
        ('FAKE001', 'Counterfeit Product Sample', 0)`);
});

// Get client real IP address
function getClientIP(req) {
    const xff = req.headers['x-forwarded-for'];
    if (xff) {
        const ip = xff.split(',')[0].trim();
        return normalizeIP(ip);
    }
    const addr = (req.socket && req.socket.remoteAddress) ||
                 (req.connection && req.connection.remoteAddress) ||
                 (req.connection && req.connection.socket ? req.connection.socket.remoteAddress : null);
    return normalizeIP(addr || '');
}

function normalizeIP(ip) {
    if (!ip) return '127.0.0.1';
    if (ip.startsWith('::ffff:')) return ip.substring(7);
    if (ip.startsWith('::1')) return '127.0.0.1';
    const percentIndex = ip.indexOf('%');
    if (percentIndex !== -1) ip = ip.substring(0, percentIndex);
    return ip;
}

// Load IP2Location database from CSV file
function loadIP2LocationDatabase() {
    if (isIP2LocationLoaded) return;
    
    console.log('Loading IP2Location database...');
    
    try {
        const csvPath = path.join(__dirname, 'public', 'IP2LOCATION-LITE-DB1.CSV');
        
        // Check if file exists
        if (!fs.existsSync(csvPath)) {
            console.error('IP2Location CSV file not found:', csvPath);
            isIP2LocationLoaded = false;
            return;
        }
        
        const csvContent = fs.readFileSync(csvPath, 'utf8');
        const lines = csvContent.split('\n');
        
        ip2locationData = [];
        let validRecords = 0;
        let invalidRecords = 0;
        
        for (const line of lines) {
            if (line.trim()) {
                // Parse CSV line: "startIP","endIP","countryCode","countryName"
                const matches = line.match(/"([^"]*)"/g);
                if (matches && matches.length >= 4) {
                    const startIP = parseInt(matches[0].replace(/"/g, ''));
                    const endIP = parseInt(matches[1].replace(/"/g, ''));
                    const countryCode = matches[2].replace(/"/g, '');
                    const countryName = matches[3].replace(/"/g, '');
                    
                    if (!isNaN(startIP) && !isNaN(endIP) && countryCode !== '-' && countryName !== '-') {
                        ip2locationData.push({
                            startIP,
                            endIP,
                            countryCode,
                            countryName
                        });
                        validRecords++;
                    } else {
                        invalidRecords++;
                    }
                } else {
                    invalidRecords++;
                }
            }
        }
        
        // Sort by startIP for binary search
        ip2locationData.sort((a, b) => a.startIP - b.startIP);
        isIP2LocationLoaded = true;
        console.log(`IP2Location database loaded successfully:`);
        console.log(`- Valid records: ${validRecords}`);
        console.log(`- Invalid records: ${invalidRecords}`);
        console.log(`- Total usable records: ${ip2locationData.length}`);
    } catch (error) {
        console.error('Failed to load IP2Location database:', error);
        isIP2LocationLoaded = false;
    }
}

// Convert IP address to decimal
function ipToDecimal(ip) {
    // Handle IPv6 mapped IPv4 is already normalized in normalizeIP
    const parts = ip.split('.');
    if (parts.length !== 4) return 0;

    return (parseInt(parts[0]) << 24) + 
           (parseInt(parts[1]) << 16) + 
           (parseInt(parts[2]) << 8) + 
           parseInt(parts[3]);
}

// Binary search for IP location
function getCountryFromIP(ip) {
    try {
        const cleanIP = normalizeIP(ip);
        console.log(`Looking up IP: ${ip} -> ${cleanIP}`);

        // Prefer geoip-lite for IPv6
        const isIPv6 = cleanIP.includes(':') && !cleanIP.startsWith('::ffff:');
        if (isIPv6) {
            console.log('Using geoip-lite for IPv6 address');
            const geo = geoip.lookup(cleanIP);
            if (geo && geo.country) {
                return {
                    country: geo.country,
                    countryName: geo.country
                };
            }
        }

        if (!isIP2LocationLoaded) {
            console.log('IP2Location not loaded, attempting to load...');
            loadIP2LocationDatabase();
        }

        const ipDecimal = ipToDecimal(cleanIP);
        console.log(`IP decimal: ${ipDecimal}, IP2Location records: ${ip2locationData.length}`);

        if (ipDecimal > 0 && ip2locationData.length > 0 && isIP2LocationLoaded) {
            // Binary search
            let left = 0;
            let right = ip2locationData.length - 1;
            while (left <= right) {
                const mid = Math.floor((left + right) / 2);
                const record = ip2locationData[mid];
                if (ipDecimal >= record.startIP && ipDecimal <= record.endIP) {
                    console.log(`Found in IP2Location: ${record.countryCode} - ${record.countryName}`);
                    return {
                        country: record.countryCode,
                        countryName: record.countryName
                    };
                } else if (ipDecimal < record.startIP) {
                    right = mid - 1;
                } else {
                    left = mid + 1;
                }
            }
            console.log(`IP ${cleanIP} (${ipDecimal}) not found in IP2Location database`);
        } else {
            console.log('Using geoip-lite fallback due to invalid IP decimal or missing IP2Location data');
        }

        // Fallback to geoip-lite for IPv4 or unresolved cases
        const geo = geoip.lookup(cleanIP);
        if (geo && geo.country) {
            console.log(`Found in geoip-lite: ${geo.country}`);
            return {
                country: geo.country,
                countryName: geo.country
            };
        }

        // Final fallback
        console.log('No location found, returning Unknown');
        return { country: 'Unknown', countryName: 'Unknown' };
    } catch (error) {
        console.error('Error in getCountryFromIP:', error, 'for IP:', ip);
        return { country: 'Unknown', countryName: 'Unknown' };
    }
}

// Generate random token
function generateToken() {
    return crypto.randomBytes(32).toString('hex');
}

// Verify admin token middleware
function verifyAdminToken(req, res, next) {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ error: 'No authentication token provided' });
    }
    
    const token = authHeader.substring(7);
    if (!adminTokens.has(token)) {
        return res.status(401).json({ error: 'Invalid or expired token' });
    }
    
    req.adminToken = token;
    next();
}

// NFC scan verification API
app.post('/api/verify/:nfcCode', (req, res) => {
    try {
        // Validate and sanitize NFC code
        const nfcCode = validateAndSanitizeInput(req.params.nfcCode, 'nfc_code');
        if (!nfcCode) {
            return res.status(400).json({ error: 'NFC code cannot be empty' });
        }

        const clientIP = getClientIP(req);
        
        // Get geographic location information using IP2Location
        const geoInfo = getCountryFromIP(clientIP);
        const country = geoInfo.country;
        const countryName = geoInfo.countryName;

        // Use parameterized query to prevent SQL injection
        db.get('SELECT * FROM products WHERE nfc_code = ?', [nfcCode], (err, product) => {
            if (err) {
                return handleError(res, err, 'Database query error');
            }

            // If product doesn't exist, return counterfeit information directly
            if (!product) {
                return res.json({
                    productName: 'Unknown Product',
                    isAuthentic: false,
                    message: 'This product failed verification and may be counterfeit',
                    timestamp: new Date().toISOString()
                });
            }

            // Record scan in history (always record for audit trail)
            db.run('INSERT INTO scan_records (nfc_code, ip_address, country) VALUES (?, ?, ?)', 
                [nfcCode, clientIP, country], function(err) {
                if (err) {
                    console.error('Failed to record scan:', err);
                }
            });

            // Check if this is the first scan for this product (no country bound yet)
            if (!product.country) {
                // First scan - bind country to this product
                db.run('UPDATE products SET country = ?, country_name = ? WHERE nfc_code = ?', 
                    [country, countryName, nfcCode], function(err) {
                    if (err) {
                        console.error('Failed to bind country to product:', err);
                    }
                });
            }

            // Get total scan count for this product
            db.get('SELECT COUNT(*) as total_scans FROM scan_records WHERE nfc_code = ?', 
                [nfcCode], (err, scanResult) => {
                if (err) {
                    return handleError(res, err, 'Failed to get scan count');
                }

                const totalScans = scanResult ? scanResult.total_scans : 1;
                const boundCountry = product.country || country;
                const boundCountryName = product.country_name || countryName;

                // Return product information
                res.json({
                    productName: product.product_name,
                    isAuthentic: Boolean(product.is_authentic),
                    scanCount: totalScans,
                    country: boundCountry,
                    countryName: boundCountryName,
                    timestamp: new Date().toISOString()
                });
            });
        });
    } catch (error) {
        handleError(res, error);
    }
});

// Admin login API
app.post('/api/admin/login', (req, res) => {
    try {
        const { username, password } = req.body;
        
        // Validate input
        if (!username || !password) {
            return res.status(400).json({ error: 'Username and password cannot be empty' });
        }

        // Validate and sanitize input
        const cleanUsername = validateAndSanitizeInput(username, 'username');
        const cleanPassword = validateAndSanitizeInput(password, 'string', 100);
        
        if (!cleanUsername || !cleanPassword) {
            return res.status(400).json({ error: 'Invalid username or password format' });
        }

        // Verify credentials
        if (cleanUsername === ADMIN_CREDENTIALS.username && 
            cleanPassword === ADMIN_CREDENTIALS.password) {
            
            const token = generateToken();
            adminTokens.add(token);
            
            // Set token expiration (auto cleanup after 24 hours)
            setTimeout(() => {
                adminTokens.delete(token);
            }, 24 * 60 * 60 * 1000);

            res.json({ 
                token: token,
                message: 'Login successful'
            });
        } else {
            // Add delay to prevent brute force attacks
            setTimeout(() => {
                res.status(401).json({ error: 'Incorrect username or password' });
            }, 1000);
        }
    } catch (error) {
        handleError(res, error);
    }
});

// Verify admin token API
app.get('/api/admin/verify', verifyAdminToken, (req, res) => {
    res.json({ success: true, message: 'Token is valid' });
});

// Admin get statistics API
app.get('/api/admin/stats', verifyAdminToken, (req, res) => {
    try {
        // Get product statistics with bound country information
        db.all(`SELECT 
            p.nfc_code, 
            p.product_name, 
            p.country,
            p.country_name,
            COUNT(sr.id) as total_scans
        FROM products p 
        LEFT JOIN scan_records sr ON p.nfc_code = sr.nfc_code 
        WHERE p.is_authentic = 1
        GROUP BY p.nfc_code, p.product_name, p.country, p.country_name
        ORDER BY total_scans DESC`, [], (err, products) => {
            if (err) {
                return handleError(res, err, 'Failed to get statistics');
            }

            res.json({
                products: products || []
            });
        });
    } catch (error) {
        handleError(res, error);
    }
});

// Admin add product API
app.post('/api/admin/products', verifyAdminToken, (req, res) => {
    try {
        const { nfcCode, productName, isAuthentic } = req.body;
        
        // Validate required fields
        if (!nfcCode || !productName || isAuthentic === undefined) {
            return res.status(400).json({ error: 'All fields are required' });
        }

        // Validate and sanitize input
        const cleanNfcCode = validateAndSanitizeInput(nfcCode, 'nfc_code');
        const cleanProductName = validateAndSanitizeInput(productName, 'product_name');
        
        if (!cleanNfcCode || !cleanProductName) {
            return res.status(400).json({ error: 'Invalid input format' });
        }

        // Validate isAuthentic is boolean
        const authenticValue = Boolean(isAuthentic);

        // Use parameterized query to insert product
        db.run('INSERT INTO products (nfc_code, product_name, is_authentic) VALUES (?, ?, ?)', 
            [cleanNfcCode, cleanProductName, authenticValue ? 1 : 0], function(err) {
            if (err) {
                if (err.message.includes('UNIQUE constraint failed')) {
                    return res.status(400).json({ error: 'NFC code already exists' });
                }
                return handleError(res, err, 'Failed to add product');
            }

            res.json({ 
                success: true,
                message: 'Product added successfully',
                productId: this.lastID
            });
        });
    } catch (error) {
        handleError(res, error);
    }
});

// Admin get NFC code scan details API
app.get('/api/admin/nfc/:nfcCode/scans', verifyAdminToken, (req, res) => {
    try {
        const nfcCode = req.params.nfcCode;
        
        // Validate and sanitize NFC code
        const cleanNfcCode = validateAndSanitizeInput(nfcCode, 'nfc_code');
        if (!cleanNfcCode) {
            return res.status(400).json({ error: 'Invalid NFC code format' });
        }

        // Get product information
        db.get('SELECT * FROM products WHERE nfc_code = ?', [cleanNfcCode], (err, product) => {
            if (err) {
                return handleError(res, err, 'Failed to get product information');
            }

            if (!product) {
                return res.status(404).json({ error: 'Product not found' });
            }

            // Get scan records with pagination
            const page = parseInt(req.query.page) || 1;
            const limit = parseInt(req.query.limit) || 50;
            const offset = (page - 1) * limit;

            // Get total scan count
            db.get('SELECT COUNT(*) as total FROM scan_records WHERE nfc_code = ?', [cleanNfcCode], (err, countResult) => {
                if (err) {
                    return handleError(res, err, 'Failed to get scan count');
                }

                const totalScans = countResult.total;

                // Get scan records with details
                db.all(`SELECT 
                    sr.ip_address,
                    sr.country,
                    sr.scan_time
                FROM scan_records sr 
                WHERE sr.nfc_code = ? 
                ORDER BY sr.scan_time DESC 
                LIMIT ? OFFSET ?`, 
                [cleanNfcCode, limit, offset], (err, scanRecords) => {
                    if (err) {
                        return handleError(res, err, 'Failed to get scan records');
                    }

                    res.json({
                        product: {
                            nfc_code: product.nfc_code,
                            product_name: product.product_name,
                            is_authentic: Boolean(product.is_authentic),
                            country: product.country,
                            country_name: product.country_name,
                            created_at: product.created_at
                        },
                        statistics: {
                            total_scans: totalScans
                        },
                        scan_records: scanRecords || [],
                        pagination: {
                            current_page: page,
                            total_pages: Math.ceil(totalScans / limit),
                            total_records: totalScans,
                            limit: limit
                        }
                    });
                });
            });
        });
    } catch (error) {
        handleError(res, error);
    }
});

// Configure file upload
const upload = multer({
    dest: 'uploads/',
    limits: {
        fileSize: 5 * 1024 * 1024 // 5MB limit
    },
    fileFilter: (req, file, cb) => {
        // Only allow Excel files
        const allowedTypes = [
            'application/vnd.ms-excel',
            'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
        ];
        
        if (allowedTypes.includes(file.mimetype)) {
            cb(null, true);
        } else {
            cb(new Error('Only Excel file formats are supported (.xls, .xlsx)'));
        }
    }
});

// Excel batch import products
app.post('/api/admin/products/import', verifyAdminToken, upload.single('excelFile'), (req, res) => {
    try {
        if (!req.file) {
            return res.status(400).json({ error: 'Please select an Excel file' });
        }

        // Read Excel file
        const workbook = XLSX.readFile(req.file.path);
        const sheetName = workbook.SheetNames[0];
        const worksheet = workbook.Sheets[sheetName];
        const data = XLSX.utils.sheet_to_json(worksheet);

        // Clean up uploaded file
        if (!data || data.length === 0) {
            fs.unlinkSync(req.file.path);
            return res.status(400).json({ error: 'Excel file is empty or format is incorrect' });
        }

        let successCount = 0;
        let errorCount = 0;
        const errors = [];

        // Validate Excel data format
        const requiredColumns = ['NFC Code', 'Product Name'];
        const firstRow = data[0];
        const hasRequiredColumns = requiredColumns.some(col => 
            Object.keys(firstRow).some(key => 
                key.toLowerCase().includes(col.toLowerCase()) || 
                key.includes('NFC') || 
                key.includes('Product') ||
                key.includes('Name')
            )
        );

        if (!hasRequiredColumns) {
            fs.unlinkSync(req.file.path);
            return res.status(400).json({ 
                error: 'Incorrect Excel file format, please ensure it contains "NFC Code" and "Product Name" columns'
            });
        }

        // Process each row of data
        const processRow = (index) => {
            if (index >= data.length) {
                // All data processing completed
                fs.unlinkSync(req.file.path); // Clean up uploaded file
                return res.json({
                    message: `Import completed: ${successCount} successful, ${errorCount} failed`,
                    successCount,
                    errorCount,
                    errors: errors.slice(0, 10) // Only return first 10 errors
                });
            }

            const row = data[index];
            
            // Try to get data from different possible column names
            let nfcCode = row['NFC Code'] || row['nfc code'] || row['NFC'] || row['nfc'] || row['Code'] || row['code'];
            let productName = row['Product Name'] || row['Product'] || row['Name'] || row['name'] || row['Product'] || row['Product'];

            // Data validation and sanitization
            try {
                if (!nfcCode || !productName) {
                    errors.push(`Row ${index + 2}: NFC code or product name is empty`);
                    errorCount++;
                    return processRow(index + 1);
                }

                // Convert to string and sanitize
                nfcCode = String(nfcCode).trim();
                productName = String(productName).trim();

                // Validate NFC code format - use try-catch to handle validation errors
                let cleanNfcCode, cleanProductName;
                try {
                    cleanNfcCode = validateAndSanitizeInput(nfcCode, 'nfc_code');
                    cleanProductName = validateAndSanitizeInput(productName, 'product_name');
                } catch (validationError) {
                    errors.push(`Row ${index + 2}: Incorrect data format - ${validationError.message}`);
                    errorCount++;
                    return processRow(index + 1);
                }

                if (!cleanNfcCode || !cleanProductName) {
                    errors.push(`Row ${index + 2}: Data validation failed (NFC: ${nfcCode}, Name: ${productName})`);
                    errorCount++;
                    return processRow(index + 1);
                }

                // Check if NFC code already exists
                db.get('SELECT id FROM products WHERE nfc_code = ?', [cleanNfcCode], (err, existing) => {
                    if (err) {
                        errors.push(`Row ${index + 2}: Database query error`);
                        errorCount++;
                        return processRow(index + 1);
                    }

                    if (existing) {
                        errors.push(`Row ${index + 2}: NFC code ${cleanNfcCode} already exists`);
                        errorCount++;
                        return processRow(index + 1);
                    }

                    // Insert new product
                    db.run('INSERT INTO products (nfc_code, product_name, is_authentic) VALUES (?, ?, 1)', 
                        [cleanNfcCode, cleanProductName], function(insertErr) {
                        if (insertErr) {
                            errors.push(`Row ${index + 2}: Insert failed - ${insertErr.message}`);
                            errorCount++;
                        } else {
                            successCount++;
                        }
                        
                        // Process next row
                        processRow(index + 1);
                    });
                });

            } catch (error) {
                errors.push(`Row ${index + 2}: Processing error - ${error.message}`);
                errorCount++;
                processRow(index + 1);
            }
        };

        // Start processing data
        processRow(0);

    } catch (error) {
        // Clean up uploaded file
        if (req.file && req.file.path) {
            try {
                fs.unlinkSync(req.file.path);
            } catch (cleanupError) {
                console.error('Failed to clean up file:', cleanupError);
            }
        }
        return handleError(res, error, 'Excel file processing failed');
    }
});

// Test IP geolocation endpoint (for debugging)
app.get('/api/test/ip-location/:ip?', (req, res) => {
    try {
        const testIP = req.params.ip || getClientIP(req);
        const geoInfo = getCountryFromIP(testIP);
        
        res.json({
            ip: testIP,
            country: geoInfo.country,
            countryName: geoInfo.countryName,
            ip2locationLoaded: isIP2LocationLoaded,
            ip2locationRecords: ip2locationData.length,
            ipDecimal: ipToDecimal(normalizeIP(testIP))
        });
    } catch (error) {
        handleError(res, error, 'Failed to get IP location');
    }
});

// Homepage route
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
})

// Admin login page route
app.get('/admin-login', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'admin-login.html'));
});

// Admin dashboard page route
app.get('/admin-dashboard', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'admin-dashboard.html'));
});

// Verification page route
app.get('/verify/:nfcCode', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'verify.html'));
});

// Start server
app.listen(PORT, () => {
    console.log(`NFC Verification Server running at http://localhost:${PORT}`);
    // Load IP2Location database on server start
    loadIP2LocationDatabase();
});

// Graceful shutdown
process.on('SIGINT', () => {
    console.log('Shutting down server...');
    db.close((err) => {
        if (err) {
            console.error(err.message);
        }
        console.log('Database connection closed');
        process.exit(0);
    });
});