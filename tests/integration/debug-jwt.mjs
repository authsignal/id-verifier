import * as jose from 'jose';
import fs from 'node:fs';
import path from 'node:path';
import { execSync } from 'node:child_process';
import {
    createRequestObject,
    generateX509Hash,
    generateNonce,
    generateJWK,
} from '../../scripts/id-verifier.js';

const baseHost = 'seatless-incremental-lainey.ngrok-free.dev';
const certDir = path.join(import.meta.dirname, '.certs');

// Use the same cert generation as the test server
if (!fs.existsSync(certDir)) fs.mkdirSync(certDir, { recursive: true });
const keyPath = path.join(certDir, 'debug-key.pem');
const certPath = path.join(certDir, 'debug-cert.pem');
execSync(
    `openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 ` +
    `-keyout "${keyPath}" -out "${certPath}" -days 30 -nodes ` +
    `-subj "/CN=${baseHost}" ` +
    `-addext "subjectAltName=DNS:${baseHost}" 2>/dev/null`
);
const keyPem = fs.readFileSync(keyPath, 'utf-8');
const certPem = fs.readFileSync(certPath, 'utf-8');
const signingKey = await jose.importPKCS8(keyPem, 'ES256');
const certBase64 = certPem.replace(/-----BEGIN CERTIFICATE-----/, '').replace(/-----END CERTIFICATE-----/, '').replace(/\s/g, '');

const encJwk = await generateJWK();
const { d, dp, dq, qi, ...encPublicJwk } = encJwk;

const jwt = await createRequestObject({
    clientId: baseHost,
    clientIdScheme: 'x509_san_dns',
    nonce: generateNonce(),
    state: 'test-state',
    responseUri: `https://${baseHost}/response`,
    documentTypes: ['org.iso.18013.5.1.mDL'],
    claims: [
        ['org.iso.18013.5.1', 'given_name'],
        ['org.iso.18013.5.1', 'family_name'],
        ['org.iso.18013.5.1', 'birth_date'],
        ['org.iso.18013.5.1', 'portrait'],
        ['org.iso.18013.5.1', 'document_number'],
        ['org.iso.18013.5.1', 'issuing_country'],
        ['org.iso.18013.5.1', 'expiry_date'],
    ],
    privateKey: signingKey,
    x5cChain: [certBase64],
    encryptionJwk: encPublicJwk,
    responseMode: 'direct_post',
    usePresentationExchange: true,
});

const parts = jwt.split('.');
const header = JSON.parse(Buffer.from(parts[0], 'base64url').toString());
const payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString());

console.log('=== JWT Header ===');
console.log(JSON.stringify(header, null, 2));
console.log('\n=== JWT Payload ===');
console.log(JSON.stringify(payload, null, 2));
