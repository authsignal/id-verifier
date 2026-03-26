#!/usr/bin/env node

/**
 * OID4VP Redirect Flow Integration Test Server
 *
 * Usage:
 *   node tests/integration/test-server.js --iaca /path/to/iaca.pem
 *
 * Options:
 *   --iaca <path>       Path to IACA certificate PEM file (required)
 *   --port <number>     Port to listen on (default: 8443)
 *   --host <ip>         Host/IP to bind and advertise (default: auto-detect LAN IP)
 *   --scheme <url>      Wallet URL scheme (default: mdoc-openid4vp://)
 *   --doctype <string>  mdoc doctype to request (default: org.iso.18013.5.1.mDL)
 *   --http              Use plain HTTP instead of HTTPS (not recommended, most wallets reject it)
 */

import https from 'node:https';
import http from 'node:http';
import fs from 'node:fs';
import { execSync } from 'node:child_process';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import * as jose from 'jose';
import { Certificate } from 'pkijs';
import { Integer } from 'asn1js';

import {
    createAuthorizationRequestUrl,
    createRequestObject,
    parseWalletPost,
    processDirectPostResponse,
    verifyRedirectResponse,
    createDirectPostSuccessResponse,
    generateX509Hash,
    certToX5cChain,
    generateNonce,
    generateJWK,
} from '../../scripts/id-verifier.js';

// ---------------------------------------------------------------------------
// CLI args
// ---------------------------------------------------------------------------
const args = process.argv.slice(2);
function getArg(name, defaultValue) {
    const idx = args.indexOf(`--${name}`);
    if (idx === -1) return defaultValue;
    return args[idx + 1];
}
const hasFlag = (name) => args.includes(`--${name}`);

const IACA_PATH = getArg('iaca', null);
const PORT = parseInt(getArg('port', '8443'), 10);
const WALLET_SCHEME = getArg('scheme', 'mdoc-openid4vp://');
const DOC_TYPE = getArg('doctype', 'org.iso.18013.5.1.mDL');
const USE_HTTP = hasFlag('http');

if (!IACA_PATH) {
    console.error('Error: --iaca <path> is required (path to IACA PEM certificate)');
    console.error('Usage: node tests/integration/test-server.js --iaca /path/to/iaca.pem');
    process.exit(1);
}

// ---------------------------------------------------------------------------
// Detect LAN IP
// ---------------------------------------------------------------------------
function getLanIP() {
    const explicit = getArg('host', null);
    if (explicit) return explicit;
    const ifaces = os.networkInterfaces();
    for (const name of Object.keys(ifaces)) {
        for (const iface of ifaces[name]) {
            if (iface.family === 'IPv4' && !iface.internal) {
                return iface.address;
            }
        }
    }
    return '127.0.0.1';
}
const HOST = getLanIP();
const PROTOCOL = USE_HTTP ? 'http' : 'https';
const BASE_URL = `${PROTOCOL}://${HOST}:${PORT}`;

// ---------------------------------------------------------------------------
// Generate self-signed TLS cert + reader auth cert at startup
// ---------------------------------------------------------------------------
const __dirname = path.dirname(fileURLToPath(import.meta.url));
const CERT_DIR = path.join(__dirname, '.certs');

async function generateSelfSignedCert() {
    if (!fs.existsSync(CERT_DIR)) fs.mkdirSync(CERT_DIR, { recursive: true });

    const keyPath = path.join(CERT_DIR, 'key.pem');
    const certPath = path.join(CERT_DIR, 'cert.pem');

    // Generate using openssl CLI (fast, reliable)
    execSync(
        `openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 ` +
        `-keyout "${keyPath}" -out "${certPath}" -days 30 -nodes ` +
        `-subj "/CN=OID4VP Test Server" ` +
        `-addext "subjectAltName=IP:${HOST}" 2>/dev/null`
    );

    return { keyPath, certPath };
}

async function generateReaderKeyAndCert() {
    const keyPair = await crypto.subtle.generateKey(
        { name: 'ECDSA', namedCurve: 'P-256' },
        true,
        ['sign', 'verify']
    );

    const cert = new Certificate();
    cert.version = 2;
    cert.serialNumber = new Integer({ value: Date.now() });
    await cert.subjectPublicKeyInfo.importKey(keyPair.publicKey);
    cert.notBefore.value = new Date();
    cert.notAfter.value = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000); // 30 days
    await cert.sign(keyPair.privateKey, 'SHA-256');

    const certDer = new Uint8Array(cert.toSchema().toBER(false));
    const x5cChain = certToX5cChain([certDer]);
    const hash = await generateX509Hash(certDer);
    const clientId = `x509_hash:${hash}`;

    const privateJwk = await crypto.subtle.exportKey('jwk', keyPair.privateKey);
    const signingKey = await jose.importJWK(privateJwk, 'ES256');

    return { clientId, signingKey, x5cChain };
}

// ---------------------------------------------------------------------------
// Session store (in-memory)
// ---------------------------------------------------------------------------
const sessions = new Map();

function createSession() {
    const id = crypto.randomUUID();
    const session = {
        id,
        state: `state-${id}`,
        nonce: generateNonce(),
        encJwk: null,       // set after generateJWK
        result: null,       // set after verification
        createdAt: Date.now(),
    };
    sessions.set(id, session);
    return session;
}

// ---------------------------------------------------------------------------
// Default claims per doctype
// ---------------------------------------------------------------------------
const DEFAULT_CLAIMS = {
    'org.iso.18013.5.1.mDL': [
        ['org.iso.18013.5.1', 'given_name'],
        ['org.iso.18013.5.1', 'family_name'],
        ['org.iso.18013.5.1', 'birth_date'],
        ['org.iso.18013.5.1', 'portrait'],
        ['org.iso.18013.5.1', 'document_number'],
        ['org.iso.18013.5.1', 'issuing_country'],
        ['org.iso.18013.5.1', 'expiry_date'],
    ],
    'org.iso.23220.photoid.1': [
        ['org.iso.23220.1', 'given_name'],
        ['org.iso.23220.1', 'family_name'],
        ['org.iso.23220.1', 'birth_date'],
        ['org.iso.23220.1', 'portrait'],
    ],
};

// ---------------------------------------------------------------------------
// Route handlers
// ---------------------------------------------------------------------------
async function handleIndex(req, res) {
    const session = createSession();
    session.encJwk = await generateJWK();

    const requestUri = `${BASE_URL}/request/${session.id}`;

    const authUrl = createAuthorizationRequestUrl({
        clientId: readerAuth.clientId,
        requestUri,
        walletScheme: WALLET_SCHEME,
        requestUriMethod: 'post',
    });

    const html = `<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>OID4VP Redirect Flow Test</title>
    <script src="https://cdn.jsdelivr.net/npm/qrcode@1.5.4/build/qrcode.min.js"></script>
    <style>
        body { font-family: system-ui, sans-serif; max-width: 800px; margin: 40px auto; padding: 0 20px; background: #f8f9fa; }
        .card { background: white; border-radius: 12px; padding: 24px; margin: 16px 0; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }
        h1 { color: #1a1a2e; }
        .qr-container { text-align: center; margin: 24px 0; }
        canvas { border: 8px solid white; border-radius: 8px; box-shadow: 0 2px 8px rgba(0,0,0,0.15); }
        .url { word-break: break-all; font-family: monospace; font-size: 12px; background: #f0f0f0; padding: 12px; border-radius: 6px; margin: 12px 0; }
        .info { color: #666; font-size: 14px; }
        .badge { display: inline-block; background: #e8f5e9; color: #2e7d32; padding: 2px 8px; border-radius: 4px; font-size: 12px; font-weight: 600; }
        #status { font-size: 18px; font-weight: 600; }
        .success { color: #2e7d32; }
        .waiting { color: #f57c00; }
        .error { color: #c62828; }
        pre { background: #f5f5f5; padding: 16px; border-radius: 8px; overflow-x: auto; font-size: 13px; }
        table { width: 100%; border-collapse: collapse; }
        td, th { text-align: left; padding: 8px 12px; border-bottom: 1px solid #eee; }
        th { color: #666; font-weight: 500; font-size: 13px; }
    </style>
</head>
<body>
    <h1>OID4VP Redirect Flow Test</h1>

    <div class="card">
        <h2>Scan with MATTR Wallet</h2>
        <div class="qr-container">
            <canvas id="qr"></canvas>
        </div>
        <div class="info">
            <strong>Session:</strong> ${session.id}<br>
            <strong>Scheme:</strong> <span class="badge">${WALLET_SCHEME}</span>
            <strong>DocType:</strong> <span class="badge">${DOC_TYPE}</span>
        </div>
        <details>
            <summary>Authorization URL</summary>
            <div class="url">${authUrl}</div>
        </details>
    </div>

    <div class="card">
        <h2>Status</h2>
        <div id="status" class="waiting">Waiting for wallet response...</div>
        <div id="result"></div>
    </div>

    <script>
        QRCode.toCanvas(document.getElementById('qr'), ${JSON.stringify(authUrl)}, {
            width: 300,
            margin: 2,
            color: { dark: '#1a1a2e' }
        });

        // Poll for result
        const sessionId = ${JSON.stringify(session.id)};
        async function poll() {
            try {
                const res = await fetch('/result/' + sessionId);
                const data = await res.json();
                if (data.status === 'complete') {
                    const el = document.getElementById('status');
                    const resultEl = document.getElementById('result');
                    if (data.result.valid) {
                        el.className = 'success';
                        el.textContent = 'Verification successful!';
                    } else {
                        el.className = 'error';
                        el.textContent = 'Verification failed';
                    }
                    let html = '<h3>Claims</h3><table>';
                    for (const [key, val] of Object.entries(data.result.claims || {})) {
                        let display = val;
                        if (val instanceof Object && val.type === 'Buffer') display = '(binary data)';
                        else if (typeof val === 'object') display = JSON.stringify(val);
                        if (key === 'portrait') display = '<img src="data:image/jpeg;base64,' + data.result.portraitBase64 + '" style="width:80px;border-radius:8px">';
                        html += '<tr><th>' + key + '</th><td>' + display + '</td></tr>';
                    }
                    html += '</table>';
                    html += '<details><summary>Full result</summary><pre>' + JSON.stringify(data.result, null, 2) + '</pre></details>';
                    resultEl.innerHTML = html;
                    return;
                }
            } catch (e) { /* ignore */ }
            setTimeout(poll, 1500);
        }
        poll();
    </script>
</body>
</html>`;
    res.writeHead(200, { 'Content-Type': 'text/html' });
    res.end(html);
}

async function handleRequestUri(req, res, sessionId) {
    const session = sessions.get(sessionId);
    if (!session) {
        res.writeHead(404, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Session not found' }));
        return;
    }

    let walletNonce = undefined;

    // Handle POST (request_uri_method=post wallet negotiation)
    if (req.method === 'POST') {
        const body = await readBody(req);
        console.log('\n--- Wallet POST to request_uri ---');
        console.log('Body:', body);
        const parsed = parseWalletPost(body);
        walletNonce = parsed.walletNonce;
        if (parsed.walletMetadata) {
            console.log('Wallet metadata:', JSON.stringify(parsed.walletMetadata, null, 2));
        }
        if (walletNonce) {
            console.log('Wallet nonce:', walletNonce);
        }
    }

    // Get public part of encryption JWK
    const { d, dp, dq, qi, ...encPublicJwk } = session.encJwk;

    const claims = DEFAULT_CLAIMS[DOC_TYPE] || DEFAULT_CLAIMS['org.iso.18013.5.1.mDL'];

    const jwt = await createRequestObject({
        clientId: readerAuth.clientId,
        nonce: session.nonce,
        state: session.state,
        responseUri: `${BASE_URL}/response`,
        documentTypes: [DOC_TYPE],
        claims,
        privateKey: readerAuth.signingKey,
        x5cChain: readerAuth.x5cChain,
        encryptionJwk: encPublicJwk,
        walletNonce,
    });

    console.log('\n--- Serving request object ---');
    console.log('Session:', sessionId);
    console.log('Client ID:', readerAuth.clientId);
    console.log('Nonce:', session.nonce);
    console.log('Response URI:', `${BASE_URL}/response`);

    res.writeHead(200, { 'Content-Type': 'application/oauth-authz-req+jwt' });
    res.end(jwt);
}

async function handleResponseUri(req, res) {
    const body = await readBody(req);
    console.log('\n--- Wallet POST to response_uri ---');

    // Parse form-encoded body
    const params = new URLSearchParams(body);
    const responseBody = {};
    for (const [key, value] of params.entries()) {
        responseBody[key] = value;
    }

    console.log('Keys:', Object.keys(responseBody));

    // Find the session by state
    let session = null;
    const stateFromBody = responseBody.state;

    // For encrypted responses, we need to try each session's key
    // First try to find by state if available in plain
    if (stateFromBody) {
        for (const s of sessions.values()) {
            if (s.state === stateFromBody) { session = s; break; }
        }
    }

    // If encrypted (direct_post.jwt), state is inside the JWE — try recent sessions
    if (!session && responseBody.response) {
        // Try each recent session's encryption key
        for (const s of sessions.values()) {
            if (s.result) continue; // skip already-completed sessions
            try {
                const { state } = await processDirectPostResponse({
                    responseBody,
                    encryptionJwk: s.encJwk,
                });
                if (state === s.state) {
                    session = s;
                    break;
                }
            } catch (e) {
                continue; // wrong key, try next
            }
        }
    }

    if (!session) {
        console.error('No matching session found');
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'No matching session' }));
        return;
    }

    console.log('Matched session:', session.id);

    try {
        // Decrypt the response
        const { vpToken, state } = await processDirectPostResponse({
            responseBody,
            encryptionJwk: session.encJwk,
        });

        console.log('State:', state);
        console.log('VP Token keys:', Object.keys(vpToken));

        // Get public part of encryption JWK for thumbprint
        const { d, dp, dq, qi, ...encPublicJwk } = session.encJwk;

        // Verify the credentials
        const result = await verifyRedirectResponse({
            vpToken,
            clientId: readerAuth.clientId,
            nonce: session.nonce,
            responseUri: `${BASE_URL}/response`,
            encryptionJwk: encPublicJwk,
        });

        console.log('\n--- Verification Result ---');
        console.log('Valid:', result.valid);
        console.log('Trusted:', result.trusted);
        console.log('Claims:', Object.keys(result.claims));

        // Extract portrait as base64 for display
        let portraitBase64 = null;
        if (result.claims.portrait) {
            if (result.claims.portrait instanceof Uint8Array) {
                portraitBase64 = Buffer.from(result.claims.portrait).toString('base64');
            } else if (Buffer.isBuffer(result.claims.portrait)) {
                portraitBase64 = result.claims.portrait.toString('base64');
            }
        }

        // Store result (without the binary portrait in claims for JSON)
        const claimsForDisplay = { ...result.claims };
        if (claimsForDisplay.portrait) {
            claimsForDisplay.portrait = `(${result.claims.portrait.length} bytes)`;
        }

        session.result = {
            valid: result.valid,
            trusted: result.trusted,
            claims: claimsForDisplay,
            portraitBase64,
            processedDocuments: result.processedDocuments.map(doc => ({
                valid: doc.valid,
                trusted: doc.trusted,
                invalidReasons: doc.invalidReasons,
                issuer: doc.issuer ? { issuer_id: doc.issuer.issuer_id } : null,
            })),
        };

        // Respond to wallet
        const walletResponse = createDirectPostSuccessResponse({});
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(walletResponse));

    } catch (error) {
        console.error('\n--- Verification Error ---');
        console.error(error);

        session.result = {
            valid: false,
            trusted: false,
            error: error.message,
            stack: error.stack,
        };

        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({}));
    }
}

async function handleResult(req, res, sessionId) {
    const session = sessions.get(sessionId);
    if (!session) {
        res.writeHead(404, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Session not found' }));
        return;
    }

    if (session.result) {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ status: 'complete', result: session.result }));
    } else {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ status: 'pending' }));
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------
function readBody(req) {
    return new Promise((resolve, reject) => {
        let data = '';
        req.on('data', chunk => data += chunk);
        req.on('end', () => resolve(data));
        req.on('error', reject);
    });
}

function route(req, res) {
    // CORS headers for wallet requests
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

    if (req.method === 'OPTIONS') {
        res.writeHead(204);
        res.end();
        return;
    }

    const url = new URL(req.url, BASE_URL);
    const pathname = url.pathname;

    console.log(`${req.method} ${pathname}`);

    if (pathname === '/' && req.method === 'GET') {
        return handleIndex(req, res);
    }

    const requestMatch = pathname.match(/^\/request\/(.+)$/);
    if (requestMatch) {
        return handleRequestUri(req, res, requestMatch[1]);
    }

    if (pathname === '/response' && req.method === 'POST') {
        return handleResponseUri(req, res);
    }

    const resultMatch = pathname.match(/^\/result\/(.+)$/);
    if (resultMatch && req.method === 'GET') {
        return handleResult(req, res, resultMatch[1]);
    }

    res.writeHead(404, { 'Content-Type': 'text/plain' });
    res.end('Not found');
}

// ---------------------------------------------------------------------------
// Startup
// ---------------------------------------------------------------------------
let readerAuth;

async function start() {
    console.log('=== OID4VP Redirect Flow Test Server ===\n');

    // Load IACA
    const iacaPem = fs.readFileSync(IACA_PATH, 'utf-8');
    console.log('IACA loaded from:', IACA_PATH);

    // Generate reader auth key + cert
    console.log('Generating self-signed reader certificate...');
    readerAuth = await generateReaderKeyAndCert();
    console.log('Client ID:', readerAuth.clientId);

    // Start server
    let server;
    if (USE_HTTP) {
        server = http.createServer(route);
    } else {
        const { keyPath, certPath } = await generateSelfSignedCert();
        server = https.createServer({
            key: fs.readFileSync(keyPath),
            cert: fs.readFileSync(certPath),
        }, route);
        console.log('TLS certificate generated for:', HOST);
    }

    server.listen(PORT, '0.0.0.0', () => {
        console.log(`\nServer running at ${BASE_URL}`);
        console.log(`\nOpen in your browser: ${BASE_URL}`);
        console.log(`Wallet scheme: ${WALLET_SCHEME}`);
        console.log(`DocType: ${DOC_TYPE}`);
        console.log('\nThe wallet will need to trust the self-signed TLS cert.');
        console.log('If the wallet rejects the connection, try using --http or a tunnel (ngrok/cloudflare).\n');
    });
}

start().catch(err => {
    console.error('Failed to start:', err);
    process.exit(1);
});
