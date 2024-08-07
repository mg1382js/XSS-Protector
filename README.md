# XSSProtector
XSSProtector is a simple tool to protect web applications from Cross-Site Scripting (XSS) attacks. It provides methods to sanitize user inputs and set security headers to prevent XSS vulnerabilities.

## Features
- Sanitize user inputs to prevent XSS attacks
- Set security headers to enhance protection
- Configurable options for input sanitization
- Simple and easy to integrate
## Installation
This project does not require any external dependencies and can be run with Node.js.

## Usage
1. Copy the Code
   First, save the following code in a file named xssProtector.js:

```js
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
        return this.sanitize(html, options);
    }
}

// Example Usage

const http = require('http');
const { parse } = require('querystring');

const xssProtector = new XSSProtector();

http.createServer((req, res) => {
if (req.method === 'POST' && req.url === '/submit') {
let body = '';
req.on('data', chunk => {
body += chunk.toString();
});
req.on('end', () => {
const post = parse(body);
const sanitizedInput = xssProtector.sanitize(post.input);

            res.writeHead(200, { 'Content-Type': 'text/html' });
            res.end(`<p>Sanitized Input: ${sanitizedInput}</p>`);
        });
    } else if (req.method === 'GET' && req.url === '/') {
        xssProtector.setSecurityHeaders(res);
        res.writeHead(200, { 'Content-Type': 'text/html' });
        res.end(`
            <form method="POST" action="/submit">
                <input type="text" name="input" />
                <button type="submit">Submit</button>
            </form>
        `);
    } else {
        res.writeHead(404, { 'Content-Type': 'text/plain' });
        res.end('Not Found');
    }
}).listen(3000, () => {
console.log('Server running at http://localhost:3000');
});
```

2. Run the Server
   To start the server, run the following command in your terminal:

```bash
node xssProtector.js
The server will run on port 3000, and you can access it in your browser at http://localhost:3000.
```
## Adding New Routes
To add new routes and handlers, modify the example server code. Simply add new routes and their corresponding handlers to the server's request handling logic.

## Method Descriptions
sanitize(input, options): Sanitizes the input based on the provided options. By default, it escapes quotes, angle brackets, and slashes.
setSecurityHeaders(res): Sets security headers to prevent XSS attacks.
sanitizeHTML(html, options): Sanitizes HTML content based on the provided options.
