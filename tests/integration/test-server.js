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
import QRCode from 'qrcode';

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
const BASE_URL_OVERRIDE = getArg('base-url', null);

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
const BASE_URL = BASE_URL_OVERRIDE || `${PROTOCOL}://${HOST}:${PORT}`;

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
    // Generate a proper 2-cert chain: CA cert → reader leaf cert
    // This is required for wallets that verify the x5c chain (Multipaz, etc.)
    const baseHost = new URL(BASE_URL).hostname;

    const caKeyPath = path.join(CERT_DIR, 'ca-key.pem');
    const caCertPath = path.join(CERT_DIR, 'ca-cert.pem');
    const readerKeyPath = path.join(CERT_DIR, 'reader-key.pem');
    const readerCsrPath = path.join(CERT_DIR, 'reader.csr');
    const readerCertPath = path.join(CERT_DIR, 'reader-cert.pem');
    const extFilePath = path.join(CERT_DIR, 'reader-ext.cnf');

    if (!fs.existsSync(CERT_DIR)) fs.mkdirSync(CERT_DIR, { recursive: true });

    // Step 1: Generate CA key + self-signed CA cert
    execSync(
        `openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -pkeyopt ec_param_enc:named_curve ` +
        `-keyout "${caKeyPath}" -out "${caCertPath}" -days 30 -nodes ` +
        `-subj "/CN=OID4VP Test CA/O=id-verifier" ` +
        `-addext "basicConstraints=critical,CA:TRUE" ` +
        `-addext "keyUsage=critical,keyCertSign,cRLSign" 2>/dev/null`
    );

    // Step 2: Generate reader key + CSR
    execSync(
        `openssl req -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -pkeyopt ec_param_enc:named_curve ` +
        `-keyout "${readerKeyPath}" -out "${readerCsrPath}" -nodes ` +
        `-subj "/CN=${baseHost}" 2>/dev/null`
    );

    // Step 3: Sign reader cert with CA, adding SAN extension
    fs.writeFileSync(extFilePath, `subjectAltName=DNS:${baseHost}\n`);
    execSync(
        `openssl x509 -req -in "${readerCsrPath}" -CA "${caCertPath}" -CAkey "${caKeyPath}" ` +
        `-CAcreateserial -out "${readerCertPath}" -days 30 ` +
        `-extfile "${extFilePath}" 2>/dev/null`
    );

    // Read the PEM files
    const keyPem = fs.readFileSync(readerKeyPath, 'utf-8');
    const readerCertPem = fs.readFileSync(readerCertPath, 'utf-8');
    const caCertPem = fs.readFileSync(caCertPath, 'utf-8');

    // Import private key as Web Crypto (extractable) then convert for jose
    const privateKeyObj = await crypto.subtle.importKey(
        'pkcs8',
        Buffer.from(keyPem.replace(/-----BEGIN PRIVATE KEY-----/, '').replace(/-----END PRIVATE KEY-----/, '').replace(/\s/g, ''), 'base64'),
        { name: 'ECDSA', namedCurve: 'P-256' },
        true,
        ['sign']
    );
    const privateJwk = await crypto.subtle.exportKey('jwk', privateKeyObj);
    const signingKey = await jose.importJWK(privateJwk, 'ES256');

    // Export public key JWK for .well-known/oauth-client
    const kid = crypto.randomUUID();
    const { d: _d, ...publicKeyJwk } = privateJwk;
    publicKeyJwk.kid = kid;
    publicKeyJwk.alg = 'ES256';
    publicKeyJwk.use = 'sig';

    // Build x5c chains
    const readerCertBase64 = readerCertPem
        .replace(/-----BEGIN CERTIFICATE-----/, '')
        .replace(/-----END CERTIFICATE-----/, '')
        .replace(/\s/g, '');
    const caCertBase64 = caCertPem
        .replace(/-----BEGIN CERTIFICATE-----/, '')
        .replace(/-----END CERTIFICATE-----/, '')
        .replace(/\s/g, '');
    const readerCertDer = Buffer.from(readerCertBase64, 'base64');

    // Two-cert chain for OID4VP 1.0 wallets that verify the chain (Multipaz)
    const x5cChainFull = [readerCertBase64, caCertBase64];

    // Also generate a single self-signed cert for ISO 18013-7 wallets (ISO 18013-7)
    // that were working with single certs before
    const singleCertKeyPath = path.join(CERT_DIR, 'single-key.pem');
    const singleCertPath = path.join(CERT_DIR, 'single-cert.pem');
    execSync(
        `openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -pkeyopt ec_param_enc:named_curve ` +
        `-keyout "${singleCertKeyPath}" -out "${singleCertPath}" -days 30 -nodes ` +
        `-subj "/CN=${baseHost}" ` +
        `-addext "subjectAltName=DNS:${baseHost}" 2>/dev/null`
    );
    const singleCertPem = fs.readFileSync(singleCertPath, 'utf-8');
    const singleKeyPem = fs.readFileSync(singleCertKeyPath, 'utf-8');
    const singleCertBase64 = singleCertPem
        .replace(/-----BEGIN CERTIFICATE-----/, '')
        .replace(/-----END CERTIFICATE-----/, '')
        .replace(/\s/g, '');
    const singleCertDer = Buffer.from(singleCertBase64, 'base64');
    const singlePrivateKeyObj = await crypto.subtle.importKey(
        'pkcs8',
        Buffer.from(singleKeyPem.replace(/-----BEGIN PRIVATE KEY-----/, '').replace(/-----END PRIVATE KEY-----/, '').replace(/\s/g, ''), 'base64'),
        { name: 'ECDSA', namedCurve: 'P-256' },
        true,
        ['sign']
    );
    const singlePrivateJwk = await crypto.subtle.exportKey('jwk', singlePrivateKeyObj);
    const singleSigningKey = await jose.importJWK(singlePrivateJwk, 'ES256');
    const singleKid = crypto.randomUUID();
    const { d: _d2, ...singlePublicKeyJwk } = singlePrivateJwk;
    singlePublicKeyJwk.kid = singleKid;
    singlePublicKeyJwk.alg = 'ES256';
    singlePublicKeyJwk.use = 'sig';
    const singleHash = await generateX509Hash(new Uint8Array(singleCertDer));

    const hash = await generateX509Hash(new Uint8Array(readerCertDer));
    const clientId = `x509_hash:${hash}`;

    console.log('Reader cert SAN:', `DNS:${baseHost}`);
    console.log('x5c chain: leaf + CA (2 certs) for OID4VP 1.0');
    console.log('x5c single: self-signed for ISO 18013-7');

    return {
        clientId, signingKey, x5cChain: x5cChainFull, publicKeyJwk, kid,
        // ISO 18013-7 mode uses single self-signed cert (ISO 18013-7 compatible)
        iso: {
            clientId: `x509_hash:${singleHash}`,
            signingKey: singleSigningKey,
            x5cChain: [singleCertBase64],
            publicKeyJwk: singlePublicKeyJwk,
            kid: singleKid,
        },
    };
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
    const url = new URL(req.url, BASE_URL);
    const mode = url.searchParams.get('mode') || 'iso18013';

    const session = createSession();
    session.encJwk = await generateJWK();
    session.mode = mode;

    const requestUri = `${BASE_URL}/request/${session.id}`;
    const baseHost = new URL(BASE_URL).hostname;

    let authUrl;
    if (mode === 'oid4vp') {
        // OID4VP 1.0 — x509_hash prefix in client_id, openid4vp:// scheme, DCQL
        authUrl = createAuthorizationRequestUrl({
            clientId: `x509_hash:${readerAuth.clientId.split(':')[1]}`,
            requestUri,
            walletScheme: 'openid4vp://',
            requestUriMethod: 'post',
        });
    } else {
        // ISO 18013-7 — x509_san_dns as separate param, mdoc-openid4vp:// scheme, PEX
        authUrl = createAuthorizationRequestUrl({
            clientId: baseHost,
            clientIdScheme: 'x509_san_dns',
            requestUri,
            walletScheme: WALLET_SCHEME,
        });
    }

    const qrSvg = await QRCode.toString(authUrl, { type: 'svg', width: 300, margin: 2, color: { dark: '#1a1a2e' } });

    const html = `<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>OID4VP Redirect Flow Test</title>
    <style>
        body { font-family: system-ui, sans-serif; max-width: 800px; margin: 40px auto; padding: 0 20px; background: #f8f9fa; }
        .card { background: white; border-radius: 12px; padding: 24px; margin: 16px 0; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }
        h1 { color: #1a1a2e; }
        .qr-container { text-align: center; margin: 24px 0; }
        .qr-container svg { border: 8px solid white; border-radius: 8px; box-shadow: 0 2px 8px rgba(0,0,0,0.15); }
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

    <div class="card" style="text-align:center">
        <div style="display:inline-flex;border-radius:8px;overflow:hidden;border:2px solid #1a1a2e">
            <a href="/?mode=iso18013" style="padding:10px 20px;text-decoration:none;font-weight:600;font-size:14px;${mode === 'iso18013' ? 'background:#1a1a2e;color:white' : 'background:white;color:#1a1a2e'}">ISO 18013-7 / PEX</a>
            <a href="/?mode=oid4vp" style="padding:10px 20px;text-decoration:none;font-weight:600;font-size:14px;${mode === 'oid4vp' ? 'background:#1a1a2e;color:white' : 'background:white;color:#1a1a2e'}">OID4VP 1.0 / DCQL</a>
        </div>
    </div>

    <div class="card">
        <h2>Scan with Wallet</h2>
        <div class="qr-container">
            ${qrSvg}
        </div>
        <div class="info">
            <strong>Session:</strong> ${session.id}<br>
            <strong>Mode:</strong> <span class="badge">${mode === 'oid4vp' ? 'OID4VP 1.0 / DCQL' : 'ISO 18013-7 / PEX'}</span>
            <strong>Scheme:</strong> <span class="badge">${mode === 'oid4vp' ? 'openid4vp://' : WALLET_SCHEME}</span>
            <strong>DocType:</strong> <span class="badge">${DOC_TYPE}</span>
        </div>
        <a href="${authUrl}" style="display:block;text-align:center;margin:16px 0;padding:14px 24px;background:#1a1a2e;color:white;border-radius:8px;text-decoration:none;font-weight:600;font-size:16px;">Open in Wallet</a>
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
        // Poll for result
        const sessionId = ${JSON.stringify(session.id)};
        async function poll() {
            try {
                const res = await fetch('/result/' + sessionId);
                const data = await res.json();
                if (data.status === 'complete') {
                    const el = document.getElementById('status');
                    const resultEl = document.getElementById('result');
                    const r = data.result;

                    if (r.valid) {
                        el.className = 'success';
                        el.textContent = 'Verification Passed';
                    } else {
                        el.className = 'error';
                        el.textContent = 'Verification Failed';
                    }

                    const check = (val, label, desc) => {
                        const icon = val ? '<span style="color:#2e7d32">&#10003;</span>' : '<span style="color:#c62828">&#10007;</span>';
                        return '<li>' + icon + ' ' + label + ' <small style="color:#999">(' + desc + ')</small></li>';
                    };

                    let html = '<ul style="list-style:none;padding:0;margin:16px 0;font-size:15px">';
                    html += check(r.credentialVerified, 'Credential Verified', 'signatures & digests');
                    html += check(r.issuerTrusted, 'Issuer Trusted', 'certificate chain');
                    html += check(!r.issuerRevoked, 'Issuer Not Revoked', 'CRL check');
                    html += check(!r.credentialRevoked, 'Credential Not Revoked', 'status list');
                    html += '</ul>';

                    if (r.invalidReasons && r.invalidReasons.length > 0) {
                        html += '<div style="background:#fff3f3;border:1px solid #ffcdd2;border-radius:8px;padding:12px;margin:12px 0;color:#c62828;font-size:14px"><strong>Issues:</strong><br>' + r.invalidReasons.join('<br>') + '</div>';
                    }

                    const issuerInfo = r.processedDocuments?.[0]?.issuer?.certificateInfo;
                    if (issuerInfo) {
                        html += '<div style="background:#f5f5f5;border-radius:8px;padding:12px;margin:12px 0;font-size:13px"><strong>Issuer Certificate</strong><dl style="margin:8px 0">';
                        if (issuerInfo.subject?.commonName) html += '<dt style="font-weight:600;color:#666">Subject</dt><dd style="margin:0 0 8px 0">' + issuerInfo.subject.commonName + '</dd>';
                        if (issuerInfo.subject?.organization) html += '<dt style="font-weight:600;color:#666">Organization</dt><dd style="margin:0 0 8px 0">' + issuerInfo.subject.organization + '</dd>';
                        if (issuerInfo.subject?.country) html += '<dt style="font-weight:600;color:#666">Country</dt><dd style="margin:0 0 8px 0">' + issuerInfo.subject.country + '</dd>';
                        if (issuerInfo.issuer?.commonName) html += '<dt style="font-weight:600;color:#666">Issued By</dt><dd style="margin:0 0 8px 0">' + issuerInfo.issuer.commonName + '</dd>';
                        html += '<dt style="font-weight:600;color:#666">Valid</dt><dd style="margin:0 0 8px 0">' + (issuerInfo.notBefore?.split('T')[0] || '?') + ' to ' + (issuerInfo.notAfter?.split('T')[0] || '?') + '</dd>';
                        html += '</dl></div>';
                    }

                    html += '<h3>Claims</h3><table style="width:100%;border-collapse:collapse">';
                    for (const [key, val] of Object.entries(r.claims || {})) {
                        let display = val;
                        if (val instanceof Object && val.type === 'Buffer') display = '(binary data)';
                        else if (typeof val === 'object') display = JSON.stringify(val);
                        if (key === 'portrait') display = '<img src="data:image/jpeg;base64,' + r.portraitBase64 + '" style="width:80px;border-radius:8px">';
                        html += '<tr><th style="text-align:left;padding:8px 12px;border-bottom:1px solid #eee;color:#666;font-weight:500;font-size:13px;width:40%">' + key + '</th><td style="text-align:left;padding:8px 12px;border-bottom:1px solid #eee">' + display + '</td></tr>';
                    }
                    html += '</table>';
                    html += '<details><summary>Full result</summary><pre style="background:#f5f5f5;padding:16px;border-radius:8px;overflow-x:auto;font-size:12px">' + JSON.stringify(r, null, 2) + '</pre></details>';
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

    const claims = DEFAULT_CLAIMS[DOC_TYPE] || DEFAULT_CLAIMS['org.iso.18013.5.1.mDL'];

    const baseHost = new URL(BASE_URL).hostname;
    const { d, dp, dq, qi, ...encPublicJwk } = session.encJwk;

    let jwt;
    if (session.mode === 'oid4vp') {
        // OID4VP 1.0 — x509_hash client_id, DCQL, oauth-authz-req+jwt typ
        jwt = await createRequestObject({
            clientId: `x509_hash:${readerAuth.clientId.split(':')[1]}`,
            nonce: session.nonce,
            state: session.state,
            responseUri: `${BASE_URL}/response`,
            documentTypes: [DOC_TYPE],
            claims,
            privateKey: readerAuth.signingKey,
            x5cChain: readerAuth.x5cChain,
            walletNonce,
            responseMode: 'direct_post.jwt',
            usePresentationExchange: false,
            encryptionJwk: encPublicJwk,
            kid: readerAuth.kid,
        });
    } else {
        // ISO 18013-7 — x509_san_dns, PEX, no typ, single self-signed cert
        const iso = readerAuth.iso;
        jwt = await createRequestObject({
            clientId: baseHost,
            clientIdScheme: 'x509_san_dns',
            nonce: session.nonce,
            state: session.state,
            responseUri: `${BASE_URL}/response`,
            documentTypes: [DOC_TYPE],
            claims,
            privateKey: iso.signingKey,
            x5cChain: iso.x5cChain,
            walletNonce,
            responseMode: 'direct_post.jwt',
            usePresentationExchange: true,
            encryptionJwk: encPublicJwk,
            typ: null,
            kid: iso.kid,
        });
    }

    console.log('\n--- Serving request object ---');
    console.log('Session:', sessionId);
    console.log('Client ID:', baseHost);
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
    console.log('Raw body (first 500 chars):', body.substring(0, 500));

    // Find the session by state
    let session = null;
    let vpToken = null;
    let state = null;

    // For plain direct_post: vp_token and state are form fields
    if (responseBody.vp_token) {
        state = responseBody.state;
        // vp_token for mdoc is base64url-encoded DeviceResponse
        vpToken = responseBody.vp_token;
        console.log('Plain direct_post — state:', state);
    }

    // For encrypted direct_post.jwt: single "response" field containing JWE
    if (responseBody.response) {
        console.log('Attempting JWE decryption...');
        for (const s of sessions.values()) {
            if (s.result) continue;
            console.log('Trying session:', s.id);
            try {
                // Decrypt the JWE directly — the wallet may send raw CBOR (ISO 18013-7)
                // or JSON (OID4VP 1.0) inside the JWE
                const privateKey = await jose.importJWK(s.encJwk, 'ECDH-ES');
                const { plaintext, protectedHeader: jweHeader } = await jose.compactDecrypt(responseBody.response, privateKey);
                console.log('Decryption succeeded! Plaintext length:', plaintext.length);

                // Extract mdocGeneratedNonce from JWE apu header (ISO 18013-7)
                if (jweHeader.apu) {
                    const apuBytes = typeof jweHeader.apu === 'string'
                        ? Buffer.from(jweHeader.apu, 'base64url')
                        : jweHeader.apu;
                    s.mdocGeneratedNonce = new TextDecoder().decode(apuBytes);
                    console.log('mdocGeneratedNonce (from apu):', s.mdocGeneratedNonce);
                }

                // Check if it's JSON or CBOR
                let decoded;
                try {
                    decoded = JSON.parse(new TextDecoder().decode(plaintext));
                    console.log('Plaintext is JSON:', Object.keys(decoded));
                    vpToken = typeof decoded.vp_token === 'string' ? decoded.vp_token : JSON.stringify(decoded.vp_token);
                    state = decoded.state;
                } catch {
                    // Not JSON — it's raw CBOR DeviceResponse (ISO 18013-7 format)
                    console.log('Plaintext is CBOR (ISO 18013-7 format)');
                    const { bufferToBase64Url } = await import('../../scripts/utils.js');
                    vpToken = bufferToBase64Url(plaintext);
                    state = s.state; // State not in payload — use session's state
                }

                session = s;
                break;
            } catch (e) {
                console.error('Decryption failed for session', s.id, ':', e.message);
                continue;
            }
        }
    }

    // Match session by state
    if (!session && state) {
        for (const s of sessions.values()) {
            if (s.state === state) { session = s; break; }
        }
    }

    if (!session) {
        console.error('No matching session found. State:', state);
        console.error('Available sessions:', [...sessions.keys()]);
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'No matching session' }));
        return;
    }

    console.log('Matched session:', session.id);

    try {
        // For plain direct_post with ISO 18013-7 wallets, vp_token is the raw
        // base64url-encoded DeviceResponse, not a JSON object keyed by credential ID.
        // We need to handle both formats.
        let vpTokenObj = vpToken;
        if (typeof vpToken === 'string') {
            // Check if it's JSON (OID4VP 1.0 format) or raw base64url (ISO 18013-7 format)
            try {
                vpTokenObj = JSON.parse(vpToken);
            } catch {
                // It's a raw base64url DeviceResponse — wrap it in the expected format
                const credId = `cred-mso_mdoc-${DOC_TYPE.replace(/[^a-zA-Z0-9]/g, '_')}`;
                vpTokenObj = { [credId]: [vpToken] };
                console.log('Wrapped raw vp_token as:', credId);
            }
        }

        console.log('VP Token keys:', typeof vpTokenObj === 'object' ? Object.keys(vpTokenObj) : typeof vpTokenObj);

        // Verify the credentials
        const baseHost = new URL(BASE_URL).hostname;
        const verifyClientId = session.mode === 'oid4vp'
            ? `x509_hash:${readerAuth.clientId.split(':')[1]}`
            : baseHost;

        // Get public part of encryption JWK for thumbprint computation
        const { d: _d, dp: _dp, dq: _dq, qi: _qi, ...encPublicJwk } = session.encJwk;

        const result = await verifyRedirectResponse({
            vpToken: vpTokenObj,
            clientId: verifyClientId,
            nonce: session.nonce,
            responseUri: `${BASE_URL}/response`,
            mdocGeneratedNonce: session.mdocGeneratedNonce,
            encryptionJwk: encPublicJwk,
            trustedCertificates: iacaPem ? [iacaPem] : undefined,
            enableCrl: true,
            enableStatusList: true,
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
            credentialVerified: result.credentialVerified,
            issuerTrusted: result.issuerTrusted,
            issuerRevoked: result.issuerRevoked,
            credentialRevoked: result.credentialRevoked,
            claims: claimsForDisplay,
            portraitBase64,
            invalidReasons: result.processedDocuments.flatMap(doc => doc.invalidReasons || []),
            processedDocuments: result.processedDocuments.map(doc => ({
                valid: doc.valid,
                credentialVerified: doc.credentialVerified,
                issuerTrusted: doc.issuerTrusted,
                issuerRevoked: doc.issuerRevoked,
                credentialRevoked: doc.credentialRevoked,
                invalidReasons: doc.invalidReasons,
                issuer: doc.issuer || null,
                statusListRef: doc.statusListRef || null,
            })),
        };

        // Respond to wallet — include redirect_uri for same-device flow
        const walletResponse = createDirectPostSuccessResponse({
            redirectUri: `${BASE_URL}/callback`,
        });
        // Store response_code for callback lookup
        if (walletResponse.response_code) {
            session.responseCode = walletResponse.response_code;
        }
        console.log('Wallet response:', JSON.stringify(walletResponse));
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

    if (pathname === '/callback' && req.method === 'GET') {
        const url = new URL(req.url, BASE_URL);
        const responseCode = url.searchParams.get('response_code');
        console.log('Callback with response_code:', responseCode);

        // Find session by response_code
        let session = null;
        for (const s of sessions.values()) {
            if (s.responseCode === responseCode) { session = s; break; }
        }

        if (!session || !session.result) {
            res.writeHead(400, { 'Content-Type': 'text/html' });
            res.end('<h1>Invalid or expired response code</h1>');
            return;
        }

        const r = session.result;

        const checkIcon = (val, label) => {
            if (val === true) return `<span style="color:#2e7d32">&#10003;</span> ${label}`;
            if (val === false) return `<span style="color:#c62828">&#10007;</span> ${label}`;
            return `<span style="color:#999">&#8212;</span> ${label}`;
        };

        let claimsHtml = '<table>';
        for (const [key, val] of Object.entries(r.claims || {})) {
            let display = val;
            if (key === 'portrait' && r.portraitBase64) {
                display = `<img src="data:image/jpeg;base64,${r.portraitBase64}" style="width:80px;border-radius:8px">`;
            }
            claimsHtml += `<tr><th>${key}</th><td>${display}</td></tr>`;
        }
        claimsHtml += '</table>';

        const title = r.valid ? 'Verification Passed' : 'Verification Failed';
        const titleColor = r.valid ? '#2e7d32' : '#c62828';

        const html = `<!DOCTYPE html>
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Verification Result</title>
<style>
    body { font-family: system-ui, sans-serif; max-width: 600px; margin: 40px auto; padding: 0 20px; background: #f8f9fa; }
    .card { background: white; border-radius: 12px; padding: 24px; margin: 16px 0; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }
    h1 { color: ${titleColor}; }
    .checks { list-style: none; padding: 0; margin: 16px 0; font-size: 15px; }
    .checks li { padding: 6px 0; border-bottom: 1px solid #f0f0f0; }
    .checks span { font-weight: 600; font-size: 16px; margin-right: 8px; }
    table { width: 100%; border-collapse: collapse; }
    td, th { text-align: left; padding: 8px 12px; border-bottom: 1px solid #eee; }
    th { color: #666; font-weight: 500; font-size: 13px; width: 40%; }
    .reasons { background: #fff3f3; border: 1px solid #ffcdd2; border-radius: 8px; padding: 12px; margin: 12px 0; color: #c62828; font-size: 14px; }
    .issuer-info { background: #f5f5f5; border-radius: 8px; padding: 12px; margin: 12px 0; font-size: 13px; }
    .issuer-info dt { font-weight: 600; color: #666; }
    .issuer-info dd { margin: 0 0 8px 0; }
</style>
</head><body>
    <div class="card">
        <h1>${title}</h1>
        <ul class="checks">
            <li>${checkIcon(r.credentialVerified, 'Credential Verified')} <small>(signatures &amp; digests)</small></li>
            <li>${checkIcon(r.issuerTrusted, 'Issuer Trusted')} <small>(certificate chain)</small></li>
            <li>${checkIcon(!r.issuerRevoked, 'Issuer Not Revoked')} <small>(CRL check)</small></li>
            <li>${checkIcon(!r.credentialRevoked, 'Credential Not Revoked')} <small>(status list)</small></li>
        </ul>
        ${r.invalidReasons?.length ? `<div class="reasons"><strong>Issues:</strong><br>${r.invalidReasons.join('<br>')}</div>` : ''}
        ${r.processedDocuments?.[0]?.issuer?.certificateInfo ? `
        <div class="issuer-info">
            <strong>Issuer Certificate</strong>
            <dl>
                ${r.processedDocuments[0].issuer.certificateInfo.subject?.commonName ? `<dt>Subject</dt><dd>${r.processedDocuments[0].issuer.certificateInfo.subject.commonName}</dd>` : ''}
                ${r.processedDocuments[0].issuer.certificateInfo.subject?.organization ? `<dt>Organization</dt><dd>${r.processedDocuments[0].issuer.certificateInfo.subject.organization}</dd>` : ''}
                ${r.processedDocuments[0].issuer.certificateInfo.subject?.country ? `<dt>Country</dt><dd>${r.processedDocuments[0].issuer.certificateInfo.subject.country}</dd>` : ''}
                ${r.processedDocuments[0].issuer.certificateInfo.issuer?.commonName ? `<dt>Issued By</dt><dd>${r.processedDocuments[0].issuer.certificateInfo.issuer.commonName}</dd>` : ''}
                <dt>Valid</dt><dd>${r.processedDocuments[0].issuer.certificateInfo.notBefore?.split('T')[0] || '?'} to ${r.processedDocuments[0].issuer.certificateInfo.notAfter?.split('T')[0] || '?'}</dd>
            </dl>
        </div>` : ''}
    </div>
    <div class="card">
        <h2>Claims</h2>
        ${claimsHtml}
    </div>
</body></html>`;
        res.writeHead(200, { 'Content-Type': 'text/html' });
        res.end(html);
        return;
    }

    // OAuth client metadata endpoint — wallet may request this for x509_san_dns validation
    if (pathname === '/.well-known/oauth-client' || pathname === '/.well-known/openid-credential-verifier') {
        const metadata = {
            jwks: {
                keys: [readerAuth.publicKeyJwk, readerAuth.iso.publicKeyJwk],
            },
            authorization_encrypted_response_enc: 'A256GCM',
            authorization_encrypted_response_alg: 'ECDH-ES',
            vp_formats: {
                mso_mdoc: {
                    alg: ['ES256', 'ES384', 'ES512'],
                },
            },
            require_signed_request_object: true,
        };
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(metadata));
        return;
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
let iacaPem;

async function start() {
    console.log('=== OID4VP Redirect Flow Test Server ===\n');

    // Load IACA
    iacaPem = fs.readFileSync(IACA_PATH, 'utf-8');
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
