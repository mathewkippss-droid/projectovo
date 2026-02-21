/**
 * Security.js - Client-side security utilities
 * Nyota Youth Empowerment Loan System
 */

(function() {
    'use strict';

    // ==========================================
    // 1. PREVENT COMMON ATTACKS
    // ==========================================

    // Prevent right-click (optional - can be annoying for users)
    // document.addEventListener('contextmenu', function(e) {
    //     e.preventDefault();
    // });

    // Prevent F12, Ctrl+Shift+I, Ctrl+Shift+J, Ctrl+U
    document.addEventListener('keydown', function(e) {
        // F12 key
        if (e.key === 'F12') {
            e.preventDefault();
            return false;
        }
        // Ctrl+Shift+I (DevTools)
        if (e.ctrlKey && e.shiftKey && e.key === 'I') {
            e.preventDefault();
            return false;
        }
        // Ctrl+Shift+J (Console)
        if (e.ctrlKey && e.shiftKey && e.key === 'J') {
            e.preventDefault();
            return false;
        }
        // Ctrl+U (View Source)
        if (e.ctrlKey && e.key === 'u') {
            e.preventDefault();
            return false;
        }
    });

    // ==========================================
    // 2. INPUT SANITIZATION
    // ==========================================

    /**
     * Sanitize user input to prevent XSS attacks
     * @param {string} input - Raw user input
     * @returns {string} - Sanitized input
     */
    window.sanitizeInput = function(input) {
        if (typeof input !== 'string') return input;
        
        const div = document.createElement('div');
        div.textContent = input;
        return div.innerHTML
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#x27;')
            .replace(/\//g, '&#x2F;');
    };

    /**
     * Validate phone number (Kenyan format)
     * @param {string} phone - Phone number to validate
     * @returns {boolean}
     */
    window.validatePhone = function(phone) {
        const phoneRegex = /^(?:\+?254|0)[17]\d{8}$/;
        return phoneRegex.test(phone);
    };

    /**
     * Validate ID number (7-10 digits)
     * @param {string} id - ID number to validate
     * @returns {boolean}
     */
    window.validateID = function(id) {
        const idRegex = /^\d{7,10}$/;
        return idRegex.test(id);
    };

    /**
     * Validate name (letters only)
     * @param {string} name - Name to validate
     * @returns {boolean}
     */
    window.validateName = function(name) {
        const nameRegex = /^[a-zA-Z\s.'-]{2,}$/;
        return nameRegex.test(name);
    };

    // ==========================================
    // 3. SESSION MANAGEMENT
    // ==========================================

    /**
     * Set session data with expiry
     * @param {string} key - Storage key
     * @param {*} value - Data to store
     * @param {number} expiryMinutes - Expiry time in minutes
     */
    window.setSecureSession = function(key, value, expiryMinutes = 30) {
        const now = new Date();
        const item = {
            value: value,
            expiry: now.getTime() + (expiryMinutes * 60 * 1000)
        };
        sessionStorage.setItem(key, JSON.stringify(item));
    };

    /**
     * Get session data (checks expiry)
     * @param {string} key - Storage key
     * @returns {*} - Stored data or null if expired
     */
    window.getSecureSession = function(key) {
        const itemStr = sessionStorage.getItem(key);
        
        if (!itemStr) {
            return null;
        }

        try {
            const item = JSON.parse(itemStr);
            const now = new Date();

            // Check if expired
            if (now.getTime() > item.expiry) {
                sessionStorage.removeItem(key);
                return null;
            }

            return item.value;
        } catch (e) {
            return null;
        }
    };

    /**
     * Clear all session data
     */
    window.clearSecureSession = function() {
        sessionStorage.clear();
    };

    // ==========================================
    // 4. CSRF PROTECTION
    // ==========================================

    /**
     * Generate CSRF token
     * @returns {string} - Random token
     */
    window.generateCSRFToken = function() {
        const array = new Uint8Array(32);
        crypto.getRandomValues(array);
        return Array.from(array, byte => byte.toString(16).padStart(2, '0')).join('');
    };

    /**
     * Set CSRF token in session
     */
    window.setCSRFToken = function() {
        const token = generateCSRFToken();
        sessionStorage.setItem('csrf_token', token);
        return token;
    };

    /**
     * Get CSRF token from session
     */
    window.getCSRFToken = function() {
        let token = sessionStorage.getItem('csrf_token');
        if (!token) {
            token = setCSRFToken();
        }
        return token;
    };

    // ==========================================
    // 5. RATE LIMITING
    // ==========================================

    const requestCounts = {};

    /**
     * Check if request is rate-limited
     * @param {string} action - Action identifier
     * @param {number} maxRequests - Max requests allowed
     * @param {number} windowMs - Time window in milliseconds
     * @returns {boolean} - True if allowed, false if rate-limited
     */
    window.checkRateLimit = function(action, maxRequests = 5, windowMs = 60000) {
        const now = Date.now();
        
        if (!requestCounts[action]) {
            requestCounts[action] = [];
        }

        // Remove old requests outside the time window
        requestCounts[action] = requestCounts[action].filter(
            timestamp => now - timestamp < windowMs
        );

        // Check if limit exceeded
        if (requestCounts[action].length >= maxRequests) {
            return false; // Rate limited
        }

        // Add current request
        requestCounts[action].push(now);
        return true; // Allowed
    };

    // ==========================================
    // 6. SECURE DATA TRANSMISSION
    // ==========================================

    /**
     * Encrypt sensitive data before sending (basic obfuscation)
     * NOTE: This is NOT real encryption. For production, use proper encryption libraries.
     * @param {string} data - Data to encrypt
     * @returns {string} - Base64 encoded data
     */
    window.obfuscateData = function(data) {
        try {
            return btoa(unescape(encodeURIComponent(data)));
        } catch (e) {
            console.error('Obfuscation failed:', e);
            return data;
        }
    };

    /**
     * Decrypt data (basic deobfuscation)
     * @param {string} data - Data to decrypt
     * @returns {string} - Decoded data
     */
    window.deobfuscateData = function(data) {
        try {
            return decodeURIComponent(escape(atob(data)));
        } catch (e) {
            console.error('Deobfuscation failed:', e);
            return data;
        }
    };

    // ==========================================
    // 7. FORM PROTECTION
    // ==========================================

    /**
     * Protect forms from multiple submissions
     */
    window.protectForm = function(formId) {
        const form = document.getElementById(formId);
        if (!form) return;

        form.addEventListener('submit', function(e) {
            const submitBtn = form.querySelector('button[type="submit"]');
            if (submitBtn && submitBtn.disabled) {
                e.preventDefault();
                return false;
            }

            if (submitBtn) {
                submitBtn.disabled = true;
                setTimeout(() => {
                    submitBtn.disabled = false;
                }, 3000); // Re-enable after 3 seconds
            }
        });
    };

    // ==========================================
    // 8. SECURE API CALLS
    // ==========================================

    /**
     * Make a secure API call with CSRF protection
     * @param {string} url - API endpoint
     * @param {object} data - Request data
     * @param {string} method - HTTP method
     * @returns {Promise} - Fetch promise
     */
    window.secureApiCall = async function(url, data = {}, method = 'POST') {
        // Check rate limit
        if (!checkRateLimit(url, 10, 60000)) {
            throw new Error('Too many requests. Please try again later.');
        }

        const headers = {
            'Content-Type': 'application/json',
            'X-CSRF-Token': getCSRFToken(),
            'X-Requested-With': 'XMLHttpRequest'
        };

        const config = {
            method: method,
            headers: headers,
            credentials: 'same-origin' // Important for CORS
        };

        if (method !== 'GET') {
            config.body = JSON.stringify(data);
        }

        try {
            const response = await fetch(url, config);
            
            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`);
            }
            
            return await response.json();
        } catch (error) {
            console.error('API call failed:', error);
            throw error;
        }
    };

    // ==========================================
    // 9. DETECT DEVTOOLS (Optional)
    // ==========================================

    let devtoolsOpen = false;
    const element = new Image();
    
    Object.defineProperty(element, 'id', {
        get: function() {
            devtoolsOpen = true;
            // You can redirect or show warning here
            // window.location.href = 'about:blank';
        }
    });

    setInterval(function() {
        devtoolsOpen = false;
        console.log(element);
        console.clear();
    }, 1000);

    // ==========================================
    // 10. INITIALIZE ON LOAD
    // ==========================================

    window.addEventListener('DOMContentLoaded', function() {
        // Generate CSRF token on page load
        setCSRFToken();

        // Log security initialization
        console.log('%c⚠️ Security Warning', 'color: red; font-size: 20px; font-weight: bold;');
        console.log('%cDo not paste any code here unless you know what you are doing!', 'color: orange; font-size: 14px;');
        console.log('%cScammers may ask you to paste code that could steal your information.', 'color: orange; font-size: 14px;');
    });

    // ==========================================
    // 11. ENFORCE HTTPS (Production Only)
    // ==========================================

    if (location.protocol !== 'https:' && location.hostname !== 'localhost' && location.hostname !== '127.0.0.1') {
        // Uncomment for production to force HTTPS
        // location.replace(`https:${location.href.substring(location.protocol.length)}`);
    }

})();

// Export for use in modules (optional)
if (typeof module !== 'undefined' && module.exports) {
    module.exports = {
        sanitizeInput: window.sanitizeInput,
        validatePhone: window.validatePhone,
        validateID: window.validateID,
        validateName: window.validateName,
        secureApiCall: window.secureApiCall
    };
}
