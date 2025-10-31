// Country code to flag emoji mapping
// Country code to flag icon markup (SVG via flag-icons)
function getCountryFlag(countryCode) {
    if (!countryCode || typeof countryCode !== 'string') return '';
    const code = countryCode.toLowerCase();
    // Normalize special codes if needed
    const normalizeMap = { uk: 'gb' };
    const finalCode = normalizeMap[code] || code;
    // Ensure two-letter lowercase code
    if (!/^[a-z]{2}$/.test(finalCode)) return '';
    return `<span class="fi fi-${finalCode}"></span>`;
}

function getCountryFlag(countryCode) {
    const flagMap = {
        'CN': '🇨🇳', 'US': '🇺🇸', 'JP': '🇯🇵', 'KR': '🇰🇷', 'GB': '🇬🇧',
        'DE': '🇩🇪', 'FR': '🇫🇷', 'IT': '🇮🇹', 'ES': '🇪🇸', 'CA': '🇨🇦',
        'AU': '🇦🇺', 'BR': '🇧🇷', 'IN': '🇮🇳', 'RU': '🇷🇺', 'MX': '🇲🇽',
        'TH': '🇹🇭', 'SG': '🇸🇬', 'MY': '🇲🇾', 'ID': '🇮🇩', 'PH': '🇵🇭',
        'VN': '🇻🇳', 'TW': '🇹🇼', 'HK': '🇭🇰', 'NL': '🇳🇱', 'SE': '🇸🇪',
        'NO': '🇳🇴', 'DK': '🇩🇰', 'FI': '🇫🇮', 'CH': '🇨🇭', 'AT': '🇦🇹',
        'BE': '🇧🇪', 'PT': '🇵🇹', 'IE': '🇮🇪', 'NZ': '🇳🇿', 'ZA': '🇿🇦'
    };
    return flagMap[countryCode] || '🌍'; // Default to world emoji if country not found
}

// Validate NFC code format
function validateNFCCode(nfcCode) {
    // Check if empty
    if (!nfcCode) {
        return { valid: false, message: 'Please enter NFC code' };
    }
    
    // Check length
    if (nfcCode.length > 8) {
        return { valid: false, message: 'NFC code cannot exceed 8 characters' };
    }
    
    // Check character format (only allow numbers and letters)
    if (!/^[A-Za-z0-9]+$/.test(nfcCode)) {
        return { valid: false, message: 'NFC code can only contain letters and numbers' };
    }
    
    return { valid: true };
}

// Create verification modal
function createVerificationModal() {
    const modal = document.createElement('div');
    modal.className = 'verification-modal';
    modal.innerHTML = `
        <div class="modal-content">
            <button class="close-btn" onclick="closeVerificationModal()">&times;</button>
            <div id="modal-body">
                <!-- Content will be dynamically inserted here -->
            </div>
        </div>
    `;
    document.body.appendChild(modal);
    return modal;
}

// Show loading animation
function showLoadingAnimation(modalBody) {
    modalBody.innerHTML = `
        <div class="loading-stage show">
            <div class="loading-spinner"></div>
            <div class="loading-text">Verifying product authenticity...</div>
        </div>
    `;
}

// Show success animation with stages
function showSuccessAnimation(modalBody, data) {
    // Get country flag from API data
    const countryFlag = getCountryFlag(data.country);
    const countryName = data.countryName || data.country;
    const userRank = data.countryRank || 1;
    const scanCount = data.scanCount || 1;
    const isNewUser = data.isNewUser;
    
    // Stage 1: Show verification success
    modalBody.innerHTML = `
        <div class="success-stage" id="success-stage-1">
            <div class="success-icon"></div>
            <h2 style="color: #48bb78; margin-bottom: 10px;">Verification Successful!</h2>
            <p style="color: #666; font-size: 16px;">Product is authentic</p>
        </div>
        <div class="success-stage" id="success-stage-2" style="display: none;">
            <div class="country-info">
                <div class="country-flag">${countryFlag}</div>
                <div class="country-text">
                    ${isNewUser ? 
                        `You are the <strong>#${userRank}</strong> person<br>to scan this product in <strong>${countryName}</strong>` :
                        `Welcome back! You've scanned this product before<br>in <strong>${countryName}</strong>`
                    }
                </div>
                <div class="purchase-stats">
                    <div style="margin-bottom: 8px;">
                        <strong>This product:</strong> ${scanCount.toLocaleString()} total scans
                    </div>
                </div>
            </div>
        </div>
    `;

    // Show first stage immediately
    setTimeout(() => {
        const stage1 = document.getElementById('success-stage-1');
        if (stage1) {
            stage1.classList.add('show');
        }
    }, 100);
    
    // Show second stage after delay
    setTimeout(() => {
        const stage2 = document.getElementById('success-stage-2');
        if (stage2) {
            stage2.style.display = 'block';
            setTimeout(() => {
                if (stage2) {
                    stage2.classList.add('show');
                }
            }, 100);
        }
    }, 1500);
}

// Show error animation
function showErrorAnimation(modalBody, message) {
    modalBody.innerHTML = `
        <div class="error-stage">
            <div class="error-icon"></div>
            <div class="error-message">Verification Failed</div>
            <div class="error-details">${message}</div>
        </div>
    `;
    
    setTimeout(() => {
        const errorStage = modalBody.querySelector('.error-stage');
        if (errorStage) {
            errorStage.classList.add('show');
        }
    }, 100);
}

// Close verification modal
function closeVerificationModal() {
    const modal = document.querySelector('.verification-modal');
    if (modal) {
        modal.classList.remove('show');
        setTimeout(() => {
            if (modal && modal.parentNode) {
                modal.remove();
            }
        }, 300);
    }
}

// Product verification function with animation
async function verifyProduct() {
    const nfcCode = document.getElementById('nfcCode').value.trim();
    
    // Validate NFC code format
    const validation = validateNFCCode(nfcCode);
    if (!validation.valid) {
        // Close any existing modal first
        closeVerificationModal();
        
        // Show error modal for validation failure
        const modal = createVerificationModal();
        const modalBody = modal.querySelector('#modal-body');
        
        showErrorAnimation(modalBody, validation.message);
        modal.classList.add('show');
        return;
    }

    // Close any existing modal first
    closeVerificationModal();
    
    // Create and show modal
    const modal = createVerificationModal();
    const modalBody = modal.querySelector('#modal-body');
    modal.classList.add('show');
    
    // Show loading animation
    showLoadingAnimation(modalBody);

    try {
        const response = await fetch(`/api/verify/${nfcCode}`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            }
        });

        const data = await response.json();
        
        // Wait a bit for loading effect
        setTimeout(() => {
            if (response.ok && data.isAuthentic) {
                showSuccessAnimation(modalBody, data);
            } else {
                showErrorAnimation(modalBody, data.error || 'Product verification failed. This may be a counterfeit product.');
            }
        }, 1500);
        
    } catch (error) {
        setTimeout(() => {
            showErrorAnimation(modalBody, 'Network error, please try again later');
        }, 1500);
    }
}

// Legacy display functions (kept for compatibility)
function displayResult(data) {
    const resultDiv = document.getElementById('result');
    const isAuthentic = data.isAuthentic;
    
    if (isAuthentic) {
        resultDiv.innerHTML = `
            <div class="result-card authentic">
                <div class="result-header">
                    <h2>✅ Authentic Product</h2>
                    <div class="product-name">${data.productName}</div>
                </div>
                
                <div class="result-details">
                    <div class="detail-item">
                        <span class="label">Scan Count:</span>
                        <span class="value">${data.scanCount} times</span>
                    </div>
                    <div class="detail-item">
                        <span class="label">Scan Region:</span>
                        <span class="value">${data.country}</span>
                    </div>
                    <div class="detail-item">
                        <span class="label">Regional Ranking:</span>
                        <span class="value">#${data.countryRank} user</span>
                    </div>
                    <div class="detail-item">
                        <span class="label">Verification Time:</span>
                        <span class="value">${new Date(data.timestamp).toLocaleString('en-US')}</span>
                    </div>
                </div>
                
                <div class="authenticity-message">
                    <p>🎉 Congratulations! This is an authentic product. Thank you for choosing genuine products!</p>
                </div>
            </div>
        `;
    } else {
        resultDiv.innerHTML = `
            <div class="result-card fake">
                <div class="result-header">
                    <h2>❌ Suspected Counterfeit</h2>
                    <div class="product-name">${data.productName}</div>
                </div>
                
                <div class="result-details">
                    <div class="detail-item">
                        <span class="label">Verification Time:</span>
                        <span class="value">${new Date(data.timestamp).toLocaleString('en-US')}</span>
                    </div>
                </div>
                
                <div class="authenticity-message">
                    <p>⚠️ Warning: This product failed verification and may be counterfeit. Please purchase with caution and consider buying through official channels.</p>
                    ${data.message ? `<p class="additional-info">${data.message}</p>` : ''}
                </div>
            </div>
        `;
    }
}

// Display error message
function displayError(message) {
    const resultDiv = document.getElementById('result');
    resultDiv.innerHTML = `
        <div class="error">
            <h3>❌ Verification Failed</h3>
            <p>${message}</p>
        </div>
    `;
}

// Initialization when page loads
document.addEventListener('DOMContentLoaded', function() {
    // Add Enter key support
    document.getElementById('nfcCode').addEventListener('keypress', function(e) {
        if (e.key === 'Enter') {
            verifyProduct();
        }
    });
    
    // Close modal when clicking outside
    document.addEventListener('click', function(e) {
        if (e.target.classList.contains('verification-modal')) {
            closeVerificationModal();
        }
    });
    
    // Close modal with Escape key
    document.addEventListener('keydown', function(e) {
        if (e.key === 'Escape') {
            closeVerificationModal();
        }
    });
});

// Helper function to generate NFC link (for admin)
function generateNFCLink(nfcCode) {
    const baseUrl = window.location.origin;
    return `${baseUrl}/verify/${nfcCode}`;
}

// Copy link to clipboard
function copyToClipboard(text) {
    navigator.clipboard.writeText(text).then(function() {
        alert('Link copied to clipboard');
    }, function(err) {
        console.error('Copy failed: ', err);
    });
}