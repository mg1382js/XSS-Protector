class XSSProtector {
    constructor() {
        this.defaultOptions = {
            escapeQuotes: true,
            escapeAngleBrackets: true,
            escapeSlash: true,
        };
    }

    sanitize(input, options = {}) {
        const config = { ...this.defaultOptions, ...options };

        let sanitizedInput = input;

        if (config.escapeQuotes) {
            sanitizedInput = sanitizedInput.replace(/"/g, '&quot;').replace(/'/g, '&#x27;');
        }

        if (config.escapeAngleBrackets) {
            sanitizedInput = sanitizedInput.replace(/</g, '&lt;').replace(/>/g, '&gt;');
        }

        if (config.escapeSlash) {
            sanitizedInput = sanitizedInput.replace(/\//g, '&#x2F;');
        }

        return sanitizedInput;
    }

    setSecurityHeaders(res) {
        res.setHeader('Content-Security-Policy', "default-src 'self'");
        res.setHeader('X-Content-Type-Options', 'nosniff');
        res.setHeader('X-Frame-Options', 'DENY');
        res.setHeader('X-XSS-Protection', '1; mode=block');
    }

    sanitizeHTML(html, options = {}) {
        // Add more comprehensive HTML sanitization if needed
        return this.sanitize(html, options);
    }
}

module.exports = XSSProtector;