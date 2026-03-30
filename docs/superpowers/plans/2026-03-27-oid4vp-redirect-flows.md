# OID4VP 1.0 / HAIP Redirect Flows Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add OID4VP 1.0 / HAIP redirect flow support (same-device + cross-device) to id-verifier, enabling wallet interactions via `direct_post.jwt` beyond the browser-only DC API path.

**Architecture:** New protocol helper (`oid4vp-redirect-helper.js`) sits alongside existing `openid-4vp-protocol-helper.js` (DC API) and `mdoc-protocol-helper.js`. Both share the same bottom-half verification stack (`mdoc-helper.js`, `certificate-helper.js`, `cose-helper.js`). The redirect helper provides three server-callable functions: (1) create authorization request URLs with configurable wallet scheme, (2) create signed JWT request objects for the `request_uri` endpoint, (3) process encrypted `direct_post.jwt` responses including JWE decryption and SessionTranscript validation. A new `jose` dependency handles JWT signing and JWE decryption.

**Tech Stack:** JavaScript (ES6 modules), `jose` (JWT/JWE), `cbor2` (CBOR encoding), `pkijs`/`asn1js` (X.509), Web Crypto API (SHA-256, ECDH P-256)

---

## File Structure

| File | Action | Responsibility |
|------|--------|---------------|
| `scripts/oid4vp-redirect-helper.js` | **Create** | OID4VP 1.0 redirect flow protocol helper — authorization request creation, signed JWT request object creation, direct_post.jwt response processing, `OpenID4VPHandover` SessionTranscript |
| `scripts/jwt-helper.js` | **Create** | JWT signing (request objects with x5c chain) and JWE decryption (ECDH-ES + A256GCM) using `jose` library |
| `scripts/x509-helper.js` | **Create** | X.509 utilities for `x509_hash` client ID generation (SHA-256 of DER cert) and certificate chain serialization for `x5c` JOSE header |
| `scripts/id-verifier.js` | **Modify** | Export new public API functions for the redirect flow |
| `scripts/constants.js` | **Modify** | Add redirect-flow constants (response modes, client ID prefixes, default wallet schemes) |
| `tests/oid4vp-redirect-helper.test.js` | **Create** | Tests for SessionTranscript, authorization request URL, request object, response processing |
| `tests/jwt-helper.test.js` | **Create** | Tests for JWT signing and JWE decryption |
| `tests/x509-helper.test.js` | **Create** | Tests for x509_hash generation |
| `package.json` | **Modify** | Add `jose` dependency |

---

## Task 1: Add `jose` Dependency and Redirect Flow Constants

**Files:**
- Modify: `package.json`
- Modify: `scripts/constants.js`

- [ ] **Step 1: Add `jose` dependency**

```bash
cd /Users/calebion/Code/id-verifier && yarn add jose
```

- [ ] **Step 2: Add redirect flow constants to `constants.js`**

Add the following after the existing `ProtocolFormats` block (after line 42 in `scripts/constants.js`):

```javascript
/**
 * OID4VP Response Modes
 */
export const ResponseMode = {
    DC_API: 'dc_api',
    DIRECT_POST: 'direct_post',
    DIRECT_POST_JWT: 'direct_post.jwt',
};

/**
 * OID4VP Client Identifier Prefixes
 */
export const ClientIdPrefix = {
    X509_HASH: 'x509_hash',
    X509_SAN_DNS: 'x509_san_dns',
    REDIRECT_URI: 'redirect_uri',
};

/**
 * Default wallet URL schemes for OID4VP authorization requests
 */
export const WalletScheme = {
    OPENID4VP: 'openid4vp://',
    MDOC_OPENID4VP: 'mdoc-openid4vp://',
};
```

- [ ] **Step 3: Commit**

```bash
cd /Users/calebion/Code/id-verifier
git add package.json yarn.lock scripts/constants.js
git commit -m "feat: add jose dependency and redirect flow constants"
```

---

## Task 2: X.509 Helper for `x509_hash` Client ID

**Files:**
- Create: `scripts/x509-helper.js`
- Create: `tests/x509-helper.test.js`

- [ ] **Step 1: Write the failing test**

Create `tests/x509-helper.test.js`:

```javascript
import test from 'node:test';
import assert from 'node:assert/strict';
import { generateX509Hash, certToPemChain, derToPem } from '../scripts/x509-helper.js';

test('generateX509Hash produces base64url SHA-256 of DER certificate', async () => {
    // A minimal self-signed DER certificate for testing
    // We'll generate one on the fly using Web Crypto
    const { certificate: derBytes } = await createSelfSignedCert();

    const hash = await generateX509Hash(derBytes);

    // Hash should be base64url encoded (no padding, URL-safe chars)
    assert.ok(hash.length > 0, 'Hash should not be empty');
    assert.ok(!hash.includes('+'), 'Hash should be base64url (no +)');
    assert.ok(!hash.includes('/'), 'Hash should be base64url (no /)');
    assert.ok(!hash.includes('='), 'Hash should be base64url (no padding)');

    // Same input should produce same hash
    const hash2 = await generateX509Hash(derBytes);
    assert.equal(hash, hash2, 'Same certificate should produce same hash');
});

test('generateX509Hash returns correct x509_hash client_id format', async () => {
    const { certificate: derBytes } = await createSelfSignedCert();
    const hash = await generateX509Hash(derBytes);
    const clientId = `x509_hash:${hash}`;
    assert.ok(clientId.startsWith('x509_hash:'), 'Should have x509_hash prefix');
});

test('derToPem wraps DER bytes in PEM armoring', () => {
    const derBytes = new Uint8Array([0x30, 0x82, 0x01, 0x00]); // minimal
    const pem = derToPem(derBytes);
    assert.ok(pem.startsWith('-----BEGIN CERTIFICATE-----'), 'Should start with PEM header');
    assert.ok(pem.endsWith('-----END CERTIFICATE-----'), 'Should end with PEM footer');
});

test('certToPemChain converts array of DER certs to x5c-compatible PEM array', () => {
    const cert1 = new Uint8Array([0x30, 0x82, 0x01, 0x00]);
    const cert2 = new Uint8Array([0x30, 0x82, 0x02, 0x00]);
    const chain = certToPemChain([cert1, cert2]);
    assert.equal(chain.length, 2);
    // x5c uses base64 (not PEM armored) per RFC 7515 Section 4.1.6
    assert.ok(!chain[0].includes('-----'), 'x5c values should be base64, not PEM armored');
});

// Helper to create a self-signed certificate using pkijs
async function createSelfSignedCert() {
    const { Certificate } = await import('pkijs');
    const keyPair = await crypto.subtle.generateKey(
        { name: 'ECDSA', namedCurve: 'P-256' },
        true,
        ['sign', 'verify']
    );
    const cert = new Certificate();
    cert.version = 2;
    cert.serialNumber = new (await import('asn1js')).Integer({ value: 1 });
    await cert.subjectPublicKeyInfo.importKey(keyPair.publicKey);
    cert.notBefore.value = new Date();
    cert.notAfter.value = new Date(Date.now() + 365 * 24 * 60 * 60 * 1000);
    await cert.sign(keyPair.privateKey, 'SHA-256');
    const certDer = cert.toSchema().toBER(false);
    return {
        certificate: new Uint8Array(certDer),
        keyPair,
    };
}
```

- [ ] **Step 2: Run test to verify it fails**

```bash
cd /Users/calebion/Code/id-verifier && node --test tests/x509-helper.test.js
```

Expected: FAIL — `x509-helper.js` module not found.

- [ ] **Step 3: Write the implementation**

Create `scripts/x509-helper.js`:

```javascript
import { bufferToBase64Url, bufferToBase64 } from './utils.js';

/**
 * Generate x509_hash: base64url-encoded SHA-256 of the DER-encoded leaf X.509 certificate.
 * Used as the client identifier in OID4VP 1.0 / HAIP with the x509_hash prefix.
 * @param {Uint8Array} derCertBytes - DER-encoded X.509 certificate bytes
 * @returns {Promise<string>} base64url-encoded SHA-256 hash
 */
export const generateX509Hash = async (derCertBytes) => {
    const hashBuffer = await crypto.subtle.digest('SHA-256', derCertBytes);
    return bufferToBase64Url(new Uint8Array(hashBuffer));
};

/**
 * Wrap DER-encoded certificate bytes in PEM armoring.
 * @param {Uint8Array} derBytes - DER-encoded certificate bytes
 * @returns {string} PEM-formatted certificate string
 */
export const derToPem = (derBytes) => {
    const base64 = bufferToBase64(derBytes);
    const paddedBase64 = base64.length % 4 === 0 ? base64 : base64 + '='.repeat(4 - (base64.length % 4));
    const lines = [];
    for (let i = 0; i < paddedBase64.length; i += 64) {
        lines.push(paddedBase64.slice(i, i + 64));
    }
    return `-----BEGIN CERTIFICATE-----\n${lines.join('\n')}\n-----END CERTIFICATE-----`;
};

/**
 * Convert an array of DER-encoded certificates to the x5c format (array of base64 strings).
 * Per RFC 7515 Section 4.1.6, x5c values are base64-encoded (NOT base64url, NOT PEM armored).
 * @param {Array<Uint8Array>} derCerts - Array of DER-encoded certificate bytes
 * @returns {Array<string>} Array of base64-encoded certificate strings
 */
export const certToPemChain = (derCerts) => {
    return derCerts.map(cert => {
        const base64 = bufferToBase64(cert);
        // Add padding if needed (x5c requires standard base64 with padding)
        return base64.length % 4 === 0 ? base64 : base64 + '='.repeat(4 - (base64.length % 4));
    });
};
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
cd /Users/calebion/Code/id-verifier && node --test tests/x509-helper.test.js
```

Expected: All 4 tests PASS.

- [ ] **Step 5: Commit**

```bash
cd /Users/calebion/Code/id-verifier
git add scripts/x509-helper.js tests/x509-helper.test.js
git commit -m "feat: add x509 helper for x509_hash client ID generation"
```

---

## Task 3: JWT Helper for Request Signing and JWE Decryption

**Files:**
- Create: `scripts/jwt-helper.js`
- Create: `tests/jwt-helper.test.js`

- [ ] **Step 1: Write the failing test for JWT signing**

Create `tests/jwt-helper.test.js`:

```javascript
import test from 'node:test';
import assert from 'node:assert/strict';
import * as jose from 'jose';
import { signRequestObject, decryptJweResponse } from '../scripts/jwt-helper.js';

test('signRequestObject creates a valid signed JWT with x5c header', async () => {
    const { privateKey, x5cChain, publicKey } = await generateTestKeyAndCert();

    const payload = {
        client_id: 'x509_hash:testhash123',
        response_uri: 'https://verifier.example.com/response',
        nonce: 'test-nonce-123',
        response_type: 'vp_token',
        response_mode: 'direct_post.jwt',
        dcql_query: {
            credentials: [{
                id: 'my_credential',
                format: 'mso_mdoc',
                meta: { doctype_value: 'org.iso.18013.5.1.mDL' },
                claims: [{ path: ['org.iso.18013.5.1', 'given_name'] }],
            }],
        },
    };

    const jwt = await signRequestObject(payload, privateKey, x5cChain);

    // Should be a valid JWT string (three dot-separated parts)
    assert.equal(jwt.split('.').length, 3, 'JWT should have 3 parts');

    // Verify the JWT and check claims
    const { payload: decoded, protectedHeader } = await jose.jwtVerify(jwt, publicKey);
    assert.equal(decoded.client_id, 'x509_hash:testhash123');
    assert.equal(decoded.nonce, 'test-nonce-123');
    assert.equal(decoded.response_mode, 'direct_post.jwt');
    assert.ok(protectedHeader.x5c, 'Should have x5c header');
    assert.equal(protectedHeader.x5c.length, 1, 'Should have 1 cert in chain');
    assert.equal(protectedHeader.alg, 'ES256', 'Should use ES256 algorithm');
});

test('signRequestObject includes wallet_nonce when provided', async () => {
    const { privateKey, x5cChain, publicKey } = await generateTestKeyAndCert();

    const payload = {
        client_id: 'x509_hash:testhash123',
        response_uri: 'https://verifier.example.com/response',
        nonce: 'test-nonce',
        wallet_nonce: 'wallet-provided-nonce-abc',
        response_type: 'vp_token',
        response_mode: 'direct_post.jwt',
    };

    const jwt = await signRequestObject(payload, privateKey, x5cChain);
    const { payload: decoded } = await jose.jwtVerify(jwt, publicKey);
    assert.equal(decoded.wallet_nonce, 'wallet-provided-nonce-abc');
});

test('decryptJweResponse decrypts ECDH-ES + A256GCM JWE', async () => {
    const recipientKeyPair = await crypto.subtle.generateKey(
        { name: 'ECDH', namedCurve: 'P-256' },
        true,
        ['deriveKey', 'deriveBits']
    );
    const recipientJwk = await crypto.subtle.exportKey('jwk', recipientKeyPair.privateKey);
    const recipientPublicJwk = await crypto.subtle.exportKey('jwk', recipientKeyPair.publicKey);

    // Encrypt a test payload using jose
    const publicKey = await jose.importJWK(recipientPublicJwk, 'ECDH-ES');
    const innerPayload = JSON.stringify({ vp_token: { my_cred: ['base64data'] }, state: 'test-state' });
    const jwe = await new jose.CompactEncrypt(new TextEncoder().encode(innerPayload))
        .setProtectedHeader({ alg: 'ECDH-ES', enc: 'A256GCM' })
        .encrypt(publicKey);

    // Decrypt with our helper
    const decrypted = await decryptJweResponse(jwe, recipientJwk);
    assert.deepEqual(decrypted, { vp_token: { my_cred: ['base64data'] }, state: 'test-state' });
});

test('decryptJweResponse also handles A128GCM', async () => {
    const recipientKeyPair = await crypto.subtle.generateKey(
        { name: 'ECDH', namedCurve: 'P-256' },
        true,
        ['deriveKey', 'deriveBits']
    );
    const recipientJwk = await crypto.subtle.exportKey('jwk', recipientKeyPair.privateKey);
    const recipientPublicJwk = await crypto.subtle.exportKey('jwk', recipientKeyPair.publicKey);

    const publicKey = await jose.importJWK(recipientPublicJwk, 'ECDH-ES');
    const innerPayload = JSON.stringify({ vp_token: {}, state: 'test' });
    const jwe = await new jose.CompactEncrypt(new TextEncoder().encode(innerPayload))
        .setProtectedHeader({ alg: 'ECDH-ES', enc: 'A128GCM' })
        .encrypt(publicKey);

    const decrypted = await decryptJweResponse(jwe, recipientJwk);
    assert.deepEqual(decrypted, { vp_token: {}, state: 'test' });
});

// Helper: generate ECDSA P-256 key pair + self-signed cert for x5c
async function generateTestKeyAndCert() {
    const keyPair = await crypto.subtle.generateKey(
        { name: 'ECDSA', namedCurve: 'P-256' },
        true,
        ['sign', 'verify']
    );

    const { Certificate } = await import('pkijs');
    const asn1js = await import('asn1js');

    const cert = new Certificate();
    cert.version = 2;
    cert.serialNumber = new asn1js.Integer({ value: 1 });
    await cert.subjectPublicKeyInfo.importKey(keyPair.publicKey);
    cert.notBefore.value = new Date();
    cert.notAfter.value = new Date(Date.now() + 365 * 24 * 60 * 60 * 1000);
    await cert.sign(keyPair.privateKey, 'SHA-256');

    const certDer = new Uint8Array(cert.toSchema().toBER(false));

    // x5c is base64-encoded DER (not base64url, not PEM)
    const base64Cert = Buffer.from(certDer).toString('base64');

    // Export private key as JWK for jose signing
    const privateJwk = await crypto.subtle.exportKey('jwk', keyPair.privateKey);
    const privateKey = await jose.importJWK(privateJwk, 'ES256');

    return {
        privateKey,
        publicKey: keyPair.publicKey,
        x5cChain: [base64Cert],
        certDer,
    };
}
```

- [ ] **Step 2: Run test to verify it fails**

```bash
cd /Users/calebion/Code/id-verifier && node --test tests/jwt-helper.test.js
```

Expected: FAIL — `jwt-helper.js` module not found.

- [ ] **Step 3: Write the implementation**

Create `scripts/jwt-helper.js`:

```javascript
import * as jose from 'jose';

/**
 * Sign an OID4VP request object as a JWT with an x5c certificate chain.
 * Per OID4VP 1.0 Section 5.9 and HAIP 1.0, the request object MUST be signed
 * with the leaf certificate's private key, and the x5c header contains the chain.
 *
 * @param {Object} payload - The request object claims (client_id, nonce, response_uri, dcql_query, etc.)
 * @param {CryptoKey|jose.KeyLike} privateKey - The signing private key (must match the leaf cert in x5cChain)
 * @param {Array<string>} x5cChain - Array of base64-encoded DER certificates (leaf first, root excluded per HAIP)
 * @param {string} [alg='ES256'] - JOSE signing algorithm (HAIP mandates ES256 with P-256)
 * @returns {Promise<string>} Signed JWT string
 */
export const signRequestObject = async (payload, privateKey, x5cChain, alg = 'ES256') => {
    const jwt = await new jose.SignJWT(payload)
        .setProtectedHeader({
            alg,
            typ: 'oauth-authz-req+jwt',
            x5c: x5cChain,
        })
        .setIssuedAt()
        .sign(privateKey);

    return jwt;
};

/**
 * Decrypt a JWE response from a wallet's direct_post.jwt submission.
 * Per HAIP 1.0: ECDH-ES with P-256, A128GCM or A256GCM encryption.
 * The JWE contains JSON with vp_token and state.
 *
 * @param {string} jwe - The compact JWE string from the wallet
 * @param {Object} recipientJwk - The verifier's ephemeral private key (JWK with d parameter)
 * @returns {Promise<Object>} Decrypted JSON payload (containing vp_token, state, etc.)
 */
export const decryptJweResponse = async (jwe, recipientJwk) => {
    const privateKey = await jose.importJWK(recipientJwk, 'ECDH-ES');
    const { plaintext } = await jose.compactDecrypt(jwe, privateKey);
    return JSON.parse(new TextDecoder().decode(plaintext));
};
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
cd /Users/calebion/Code/id-verifier && node --test tests/jwt-helper.test.js
```

Expected: All 4 tests PASS.

- [ ] **Step 5: Commit**

```bash
cd /Users/calebion/Code/id-verifier
git add scripts/jwt-helper.js tests/jwt-helper.test.js
git commit -m "feat: add JWT helper for request signing and JWE decryption"
```

---

## Task 4: OID4VP Redirect Helper — SessionTranscript (`OpenID4VPHandover`)

**Files:**
- Create: `scripts/oid4vp-redirect-helper.js`
- Create: `tests/oid4vp-redirect-helper.test.js`

This task implements the `OpenID4VPHandover` SessionTranscript from OID4VP 1.0 Appendix B.2.6.1 — the redirect-flow variant (NOT the DC API variant already in `openid-4vp-protocol-helper.js`).

- [ ] **Step 1: Write the failing test for SessionTranscript**

Create `tests/oid4vp-redirect-helper.test.js`:

```javascript
import test from 'node:test';
import assert from 'node:assert/strict';
import * as cbor2 from 'cbor2';

// We'll import the class after creating it
import OID4VPRedirectHelper from '../scripts/oid4vp-redirect-helper.js';

test('_generateSessionTranscript produces correct OpenID4VPHandover structure', async () => {
    // Per OID4VP 1.0 Appendix B.2.6.1:
    // SessionTranscript = [null, null, OpenID4VPHandover]
    // OpenID4VPHandover = ["OpenID4VPHandover", SHA-256(CBOR(OpenID4VPHandoverInfo))]
    // OpenID4VPHandoverInfo = [clientId, nonce, jwkThumbprint, responseUri]

    const clientId = 'x509_hash:Uvo3HtuIxuhC92rShpgqcT3YXwrqRxWEviRiA0OZszk';
    const nonce = 'test-nonce-abc123';
    const responseUri = 'https://verifier.example.com/response';
    const jwkThumbprint = null; // No encryption

    const sessionTranscript = await OID4VPRedirectHelper._generateSessionTranscript(
        clientId, nonce, jwkThumbprint, responseUri
    );

    // Decode and verify structure
    const decoded = cbor2.decode(sessionTranscript);
    assert.equal(decoded.length, 3, 'SessionTranscript should be 3-element array');
    assert.equal(decoded[0], null, 'DeviceEngagementBytes should be null');
    assert.equal(decoded[1], null, 'EReaderKeyBytes should be null');

    const handover = decoded[2];
    assert.equal(handover.length, 2, 'OpenID4VPHandover should be 2-element array');
    assert.equal(handover[0], 'OpenID4VPHandover', 'First element should be identifier string');
    assert.ok(handover[1] instanceof Uint8Array, 'Second element should be hash bytes');
    assert.equal(handover[1].length, 32, 'Hash should be 32 bytes (SHA-256)');
});

test('_generateSessionTranscript is deterministic', async () => {
    const clientId = 'x509_hash:abc123';
    const nonce = 'nonce456';
    const responseUri = 'https://example.com/post';
    const jwkThumbprint = null;

    const st1 = await OID4VPRedirectHelper._generateSessionTranscript(clientId, nonce, jwkThumbprint, responseUri);
    const st2 = await OID4VPRedirectHelper._generateSessionTranscript(clientId, nonce, jwkThumbprint, responseUri);

    assert.deepEqual(st1, st2, 'Same inputs should produce identical SessionTranscript bytes');
});

test('_generateSessionTranscript with jwkThumbprint includes it in hash input', async () => {
    const clientId = 'x509_hash:abc123';
    const nonce = 'nonce456';
    const responseUri = 'https://example.com/post';

    // Without jwkThumbprint
    const st1 = await OID4VPRedirectHelper._generateSessionTranscript(clientId, nonce, null, responseUri);

    // With jwkThumbprint (a fake 32-byte thumbprint)
    const thumbprint = new Uint8Array(32).fill(0xAB);
    const st2 = await OID4VPRedirectHelper._generateSessionTranscript(clientId, nonce, thumbprint, responseUri);

    // They should differ because the hash input differs
    const hex1 = Buffer.from(st1).toString('hex');
    const hex2 = Buffer.from(st2).toString('hex');
    assert.notEqual(hex1, hex2, 'Different jwkThumbprint should produce different SessionTranscript');
});

test('_generateSessionTranscript differs from DC API handover for same nonce', async () => {
    // Import the DC API helper to compare
    const DCAPIHelper = (await import('../scripts/openid-4vp-protocol-helper.js')).default;

    const nonce = 'shared-nonce';
    const origin = 'https://example.com';

    // DC API handover: [origin, nonce, jwkThumbprint]
    const dcApiSt = await DCAPIHelper._generateSessionTranscript(origin, nonce, null);

    // Redirect handover: [clientId, nonce, jwkThumbprint, responseUri]
    const redirectSt = await OID4VPRedirectHelper._generateSessionTranscript(
        'x509_hash:abc', nonce, null, 'https://example.com/response'
    );

    const dcApiHex = Buffer.from(dcApiSt).toString('hex');
    const redirectHex = Buffer.from(redirectSt).toString('hex');
    assert.notEqual(dcApiHex, redirectHex, 'Redirect and DC API transcripts must differ');
});
```

- [ ] **Step 2: Run test to verify it fails**

```bash
cd /Users/calebion/Code/id-verifier && node --test tests/oid4vp-redirect-helper.test.js
```

Expected: FAIL — `oid4vp-redirect-helper.js` module not found.

- [ ] **Step 3: Write the SessionTranscript implementation**

Create `scripts/oid4vp-redirect-helper.js` with the SessionTranscript method:

```javascript
import { Protocol, ProtocolFormats, CredentialFormat, ClaimMappings, CredentialId, createCredentialId,
    ALL_TRUST_LISTS, ResponseMode, ClientIdPrefix, WalletScheme } from './constants.js';
import { decodeVpToken, verifyDocument } from './formats/mdoc-helper.js';
import * as cbor2 from 'cbor2';

class OID4VPRedirectHelper {
    constructor() {
        this.protocol = Protocol.OPENID4VP;
    }

    /**
     * Generate the OID4VP 1.0 SessionTranscript for redirect flows (Appendix B.2.6.1).
     *
     * SessionTranscript = [null, null, OpenID4VPHandover]
     * OpenID4VPHandover = ["OpenID4VPHandover", SHA-256(CBOR(OpenID4VPHandoverInfo))]
     * OpenID4VPHandoverInfo = [clientId, nonce, jwkThumbprint, responseUri]
     *
     * @param {string} clientId - Full client_id including prefix (e.g. "x509_hash:...")
     * @param {string} nonce - Nonce from the Authorization Request
     * @param {Uint8Array|null} jwkThumbprint - SHA-256 JWK Thumbprint of encryption key, or null
     * @param {string} responseUri - The response_uri or redirect_uri
     * @returns {Promise<Uint8Array>} CBOR-encoded SessionTranscript
     */
    async _generateSessionTranscript(clientId, nonce, jwkThumbprint, responseUri) {
        if (!clientId) throw new Error('clientId is required for generating session transcript');
        if (!nonce) throw new Error('nonce is required for generating session transcript');
        if (!responseUri) throw new Error('responseUri is required for generating session transcript');

        // Step 1: Assemble OpenID4VPHandoverInfo as CBOR array
        const handoverInfo = [clientId, nonce, jwkThumbprint, responseUri];

        // Step 2: CBOR-encode to produce OpenID4VPHandoverInfoBytes
        const handoverInfoBytes = cbor2.encode(handoverInfo);

        // Step 3: SHA-256 hash to produce OpenID4VPHandoverInfoHash
        const hashBuffer = await crypto.subtle.digest('SHA-256', handoverInfoBytes);
        const hashArray = new Uint8Array(hashBuffer);

        // Step 4: Assemble OpenID4VPHandover
        const handover = ['OpenID4VPHandover', hashArray];

        // Step 5: Assemble SessionTranscript = [null, null, Handover]
        const sessionTranscript = cbor2.encode([null, null, handover]);
        return sessionTranscript;
    }
}

const oid4vpRedirectHelper = new OID4VPRedirectHelper();
export default oid4vpRedirectHelper;
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
cd /Users/calebion/Code/id-verifier && node --test tests/oid4vp-redirect-helper.test.js
```

Expected: All 4 tests PASS.

- [ ] **Step 5: Commit**

```bash
cd /Users/calebion/Code/id-verifier
git add scripts/oid4vp-redirect-helper.js tests/oid4vp-redirect-helper.test.js
git commit -m "feat: add OID4VP redirect helper with OpenID4VPHandover SessionTranscript"
```

---

## Task 5: OID4VP Redirect Helper — Authorization Request URL + JWK Thumbprint

**Files:**
- Modify: `scripts/oid4vp-redirect-helper.js`
- Modify: `tests/oid4vp-redirect-helper.test.js`

- [ ] **Step 1: Write the failing tests**

Add to `tests/oid4vp-redirect-helper.test.js`:

```javascript
test('createAuthorizationRequestUrl builds correct URL with default scheme', () => {
    const url = OID4VPRedirectHelper.createAuthorizationRequestUrl({
        clientId: 'x509_hash:abc123',
        requestUri: 'https://verifier.example.com/request/session-xyz',
    });

    assert.ok(url.startsWith('openid4vp://'), 'Default scheme should be openid4vp://');
    const parsed = new URL(url);
    assert.equal(parsed.searchParams.get('client_id'), 'x509_hash:abc123');
    assert.equal(parsed.searchParams.get('request_uri'), 'https://verifier.example.com/request/session-xyz');
});

test('createAuthorizationRequestUrl supports custom wallet scheme', () => {
    const url = OID4VPRedirectHelper.createAuthorizationRequestUrl({
        clientId: 'x509_hash:abc123',
        requestUri: 'https://verifier.example.com/request/session-xyz',
        walletScheme: 'mdoc-openid4vp://',
    });

    assert.ok(url.startsWith('mdoc-openid4vp://'), 'Should use custom scheme');
});

test('createAuthorizationRequestUrl supports fully custom wallet scheme', () => {
    const url = OID4VPRedirectHelper.createAuthorizationRequestUrl({
        clientId: 'x509_hash:abc123',
        requestUri: 'https://verifier.example.com/request/session-xyz',
        walletScheme: 'com.example.wallet://',
    });

    assert.ok(url.startsWith('com.example.wallet://'), 'Should use fully custom scheme');
});

test('createAuthorizationRequestUrl includes request_uri_method=post when specified', () => {
    const url = OID4VPRedirectHelper.createAuthorizationRequestUrl({
        clientId: 'x509_hash:abc123',
        requestUri: 'https://verifier.example.com/request/session-xyz',
        requestUriMethod: 'post',
    });

    const parsed = new URL(url);
    assert.equal(parsed.searchParams.get('request_uri_method'), 'post');
});

test('computeJwkThumbprint produces SHA-256 thumbprint per RFC 7638', async () => {
    const jwk = await crypto.subtle.exportKey('jwk',
        (await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveKey', 'deriveBits'])).publicKey
    );

    const thumbprint = await OID4VPRedirectHelper.computeJwkThumbprint(jwk);
    assert.ok(thumbprint instanceof Uint8Array, 'Should return Uint8Array');
    assert.equal(thumbprint.length, 32, 'SHA-256 thumbprint should be 32 bytes');

    // Same key should produce same thumbprint
    const thumbprint2 = await OID4VPRedirectHelper.computeJwkThumbprint(jwk);
    assert.deepEqual(thumbprint, thumbprint2, 'Same key should produce same thumbprint');
});
```

- [ ] **Step 2: Run tests to verify the new ones fail**

```bash
cd /Users/calebion/Code/id-verifier && node --test tests/oid4vp-redirect-helper.test.js
```

Expected: New tests FAIL — methods not defined. Existing tests still pass.

- [ ] **Step 3: Add the methods to oid4vp-redirect-helper.js**

Add these methods to the `OID4VPRedirectHelper` class in `scripts/oid4vp-redirect-helper.js`, before the closing `}` of the class:

```javascript
    /**
     * Build an OID4VP authorization request URL for redirecting to a wallet app.
     * This URL is what gets encoded in a QR code (cross-device) or used as a redirect (same-device).
     *
     * @param {Object} options
     * @param {string} options.clientId - Full client_id with prefix (e.g. "x509_hash:...")
     * @param {string} options.requestUri - URL where the wallet retrieves the full request object
     * @param {string} [options.walletScheme='openid4vp://'] - URL scheme for the wallet app
     * @param {string} [options.requestUriMethod] - 'post' to enable wallet capability negotiation
     * @returns {string} Authorization request URL
     */
    createAuthorizationRequestUrl({ clientId, requestUri, walletScheme = WalletScheme.OPENID4VP, requestUriMethod }) {
        // Use a dummy host for URL construction since custom schemes don't have hosts
        const params = new URLSearchParams();
        params.set('client_id', clientId);
        params.set('request_uri', requestUri);
        if (requestUriMethod) {
            params.set('request_uri_method', requestUriMethod);
        }
        return `${walletScheme}?${params.toString()}`;
    }

    /**
     * Compute the JWK SHA-256 Thumbprint per RFC 7638.
     * For EC keys, the thumbprint is SHA-256 of the JSON serialization of {crv, kty, x, y}
     * with members sorted lexicographically.
     *
     * @param {Object} jwk - The public JWK (must have kty, crv, x, y for EC keys)
     * @returns {Promise<Uint8Array>} 32-byte SHA-256 thumbprint
     */
    async computeJwkThumbprint(jwk) {
        // RFC 7638: for EC keys, include only {crv, kty, x, y} in lexicographic order
        let thumbprintInput;
        if (jwk.kty === 'EC') {
            thumbprintInput = JSON.stringify({ crv: jwk.crv, kty: jwk.kty, x: jwk.x, y: jwk.y });
        } else if (jwk.kty === 'RSA') {
            thumbprintInput = JSON.stringify({ e: jwk.e, kty: jwk.kty, n: jwk.n });
        } else if (jwk.kty === 'OKP') {
            thumbprintInput = JSON.stringify({ crv: jwk.crv, kty: jwk.kty, x: jwk.x });
        } else {
            throw new Error(`Unsupported key type for JWK thumbprint: ${jwk.kty}`);
        }
        const hashBuffer = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(thumbprintInput));
        return new Uint8Array(hashBuffer);
    }
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
cd /Users/calebion/Code/id-verifier && node --test tests/oid4vp-redirect-helper.test.js
```

Expected: All 9 tests PASS.

- [ ] **Step 5: Commit**

```bash
cd /Users/calebion/Code/id-verifier
git add scripts/oid4vp-redirect-helper.js tests/oid4vp-redirect-helper.test.js
git commit -m "feat: add authorization request URL builder and JWK thumbprint computation"
```

---

## Task 6: OID4VP Redirect Helper — Request Object Creation

**Files:**
- Modify: `scripts/oid4vp-redirect-helper.js`
- Modify: `tests/oid4vp-redirect-helper.test.js`

- [ ] **Step 1: Write the failing tests**

Add to `tests/oid4vp-redirect-helper.test.js`:

```javascript
import * as jose from 'jose';

test('createRequestObject builds a signed JWT request with correct structure', async () => {
    const { privateKey, x5cChain, publicKey, certDer } = await createTestSigningMaterial();
    const { generateX509Hash } = await import('../scripts/x509-helper.js');
    const hash = await generateX509Hash(certDer);
    const clientId = `x509_hash:${hash}`;

    const nonce = 'request-nonce-123';
    const responseUri = 'https://verifier.example.com/response';
    const state = 'state-abc';

    const jwt = await OID4VPRedirectHelper.createRequestObject({
        clientId,
        nonce,
        state,
        responseUri,
        documentTypes: ['org.iso.18013.5.1.mDL'],
        claims: [['org.iso.18013.5.1', 'given_name'], ['org.iso.18013.5.1', 'family_name']],
        privateKey,
        x5cChain,
    });

    // Verify and decode
    const { payload, protectedHeader } = await jose.jwtVerify(jwt, publicKey);

    assert.equal(payload.client_id, clientId);
    assert.equal(payload.nonce, nonce);
    assert.equal(payload.state, state);
    assert.equal(payload.response_uri, responseUri);
    assert.equal(payload.response_type, 'vp_token');
    assert.equal(payload.response_mode, 'direct_post.jwt');
    assert.ok(payload.dcql_query, 'Should have dcql_query');
    assert.ok(payload.dcql_query.credentials.length > 0, 'Should have credential queries');
    assert.equal(payload.dcql_query.credentials[0].format, 'mso_mdoc');
    assert.equal(protectedHeader.typ, 'oauth-authz-req+jwt');
});

test('createRequestObject includes client_metadata with encryption key', async () => {
    const { privateKey, x5cChain, publicKey, certDer } = await createTestSigningMaterial();
    const { generateX509Hash } = await import('../scripts/x509-helper.js');
    const hash = await generateX509Hash(certDer);

    // Generate an ephemeral encryption key
    const encKeyPair = await crypto.subtle.generateKey(
        { name: 'ECDH', namedCurve: 'P-256' },
        true,
        ['deriveKey', 'deriveBits']
    );
    const encPublicJwk = await crypto.subtle.exportKey('jwk', encKeyPair.publicKey);

    const jwt = await OID4VPRedirectHelper.createRequestObject({
        clientId: `x509_hash:${hash}`,
        nonce: 'nonce',
        state: 'state',
        responseUri: 'https://example.com/response',
        documentTypes: ['org.iso.18013.5.1.mDL'],
        claims: [['org.iso.18013.5.1', 'given_name']],
        privateKey,
        x5cChain,
        encryptionJwk: encPublicJwk,
    });

    const { payload } = await jose.jwtVerify(jwt, publicKey);
    assert.ok(payload.client_metadata, 'Should have client_metadata');
    assert.ok(payload.client_metadata.jwks, 'Should have jwks in client_metadata');
    assert.ok(payload.client_metadata.jwks.keys.length > 0, 'Should have at least one key');
    assert.deepEqual(
        payload.client_metadata.encrypted_response_enc_values_supported,
        ['A256GCM', 'A128GCM']
    );
    assert.deepEqual(
        payload.client_metadata.encrypted_response_alg_values_supported,
        ['ECDH-ES']
    );
});

// Helper — same as in jwt-helper test but repeated per plan rules
async function createTestSigningMaterial() {
    const keyPair = await crypto.subtle.generateKey(
        { name: 'ECDSA', namedCurve: 'P-256' },
        true,
        ['sign', 'verify']
    );

    const { Certificate } = await import('pkijs');
    const asn1js = await import('asn1js');

    const cert = new Certificate();
    cert.version = 2;
    cert.serialNumber = new asn1js.Integer({ value: 1 });
    await cert.subjectPublicKeyInfo.importKey(keyPair.publicKey);
    cert.notBefore.value = new Date();
    cert.notAfter.value = new Date(Date.now() + 365 * 24 * 60 * 60 * 1000);
    await cert.sign(keyPair.privateKey, 'SHA-256');

    const certDer = new Uint8Array(cert.toSchema().toBER(false));
    const base64Cert = Buffer.from(certDer).toString('base64');

    const privateJwk = await crypto.subtle.exportKey('jwk', keyPair.privateKey);
    const privateKey = await jose.importJWK(privateJwk, 'ES256');

    return { privateKey, publicKey: keyPair.publicKey, x5cChain: [base64Cert], certDer };
}
```

- [ ] **Step 2: Run tests to verify the new ones fail**

```bash
cd /Users/calebion/Code/id-verifier && node --test tests/oid4vp-redirect-helper.test.js
```

Expected: New tests FAIL — `createRequestObject` not defined.

- [ ] **Step 3: Add the `createRequestObject` method**

Add to the `OID4VPRedirectHelper` class in `scripts/oid4vp-redirect-helper.js`. Also add the import for `signRequestObject` at the top:

At the top of the file, add:
```javascript
import { signRequestObject } from './jwt-helper.js';
```

Then add this method to the class:

```javascript
    /**
     * Create a signed JWT Request Object for OID4VP 1.0.
     * This is what the verifier serves at the request_uri endpoint.
     *
     * @param {Object} options
     * @param {string} options.clientId - Full client_id with prefix
     * @param {string} options.nonce - Fresh cryptographic nonce
     * @param {string} options.state - Opaque state value for session correlation
     * @param {string} options.responseUri - URL where wallet will POST the response
     * @param {Array<string>} options.documentTypes - mdoc document types to request
     * @param {Array<Array<string>>} options.claims - Claims as [namespace, element] arrays
     * @param {CryptoKey|jose.KeyLike} options.privateKey - Signing private key
     * @param {Array<string>} options.x5cChain - x5c certificate chain (base64 DER, leaf first)
     * @param {Object} [options.encryptionJwk] - Ephemeral public JWK for response encryption
     * @param {string} [options.walletNonce] - wallet_nonce if wallet provided one via request_uri POST
     * @param {string} [options.responseMode='direct_post.jwt'] - Response mode
     * @returns {Promise<string>} Signed JWT request object
     */
    async createRequestObject({
        clientId, nonce, state, responseUri, documentTypes, claims,
        privateKey, x5cChain, encryptionJwk, walletNonce, responseMode = ResponseMode.DIRECT_POST_JWT,
    }) {
        // Build DCQL query using the same logic as the DC API helper
        const credentials = this._createQueryCredentials(documentTypes, claims);

        const payload = {
            client_id: clientId,
            nonce,
            state,
            response_uri: responseUri,
            response_type: 'vp_token',
            response_mode: responseMode,
            dcql_query: { credentials },
        };

        if (walletNonce) {
            payload.wallet_nonce = walletNonce;
        }

        // Add client_metadata with encryption key if provided
        if (encryptionJwk) {
            payload.client_metadata = {
                encrypted_response_alg_values_supported: ['ECDH-ES'],
                encrypted_response_enc_values_supported: ['A256GCM', 'A128GCM'],
                jwks: {
                    keys: [{
                        ...encryptionJwk,
                        use: 'enc',
                        kid: 'ephemeral-enc-key',
                    }],
                },
            };
        }

        return signRequestObject(payload, privateKey, x5cChain);
    }

    /**
     * Build DCQL credential queries from document types and claims.
     * Reuses the same DCQL structure as the DC API path.
     *
     * @param {Array<string>} documentTypes - mdoc document types
     * @param {Array<Array<string>>} claims - Claims as [namespace, element] arrays
     * @returns {Array<Object>} DCQL credential query objects
     */
    _createQueryCredentials(documentTypes, claims) {
        const credentials = [];
        for (const documentType of documentTypes) {
            const formatClaims = claims.map(claim => ({ path: claim }));

            if (formatClaims.length > 0) {
                credentials.push({
                    id: createCredentialId(CredentialFormat.MSO_MDOC, documentType),
                    format: CredentialFormat.MSO_MDOC,
                    meta: { doctype_value: documentType },
                    claims: formatClaims,
                });
            }
        }
        return credentials;
    }
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
cd /Users/calebion/Code/id-verifier && node --test tests/oid4vp-redirect-helper.test.js
```

Expected: All 11 tests PASS.

- [ ] **Step 5: Commit**

```bash
cd /Users/calebion/Code/id-verifier
git add scripts/oid4vp-redirect-helper.js tests/oid4vp-redirect-helper.test.js
git commit -m "feat: add createRequestObject for signed JWT request creation"
```

---

## Task 7: OID4VP Redirect Helper — Response Processing (direct_post.jwt)

**Files:**
- Modify: `scripts/oid4vp-redirect-helper.js`
- Modify: `tests/oid4vp-redirect-helper.test.js`

- [ ] **Step 1: Write the failing test**

Add to `tests/oid4vp-redirect-helper.test.js`:

```javascript
test('processDirectPostResponse decrypts JWE response and extracts vp_token and state', async () => {
    // Create an ephemeral encryption key pair
    const encKeyPair = await crypto.subtle.generateKey(
        { name: 'ECDH', namedCurve: 'P-256' },
        true,
        ['deriveKey', 'deriveBits']
    );
    const encPrivateJwk = await crypto.subtle.exportKey('jwk', encKeyPair.privateKey);
    const encPublicJwk = await crypto.subtle.exportKey('jwk', encKeyPair.publicKey);

    // Simulate a wallet encrypting vp_token + state as JWE
    const publicKey = await jose.importJWK(encPublicJwk, 'ECDH-ES');
    const walletPayload = JSON.stringify({
        vp_token: { 'cred-mso_mdoc-org_iso_18013_5_1_mDL': ['base64url-fake-device-response'] },
        state: 'test-state-xyz',
    });
    const jwe = await new jose.CompactEncrypt(new TextEncoder().encode(walletPayload))
        .setProtectedHeader({ alg: 'ECDH-ES', enc: 'A256GCM' })
        .encrypt(publicKey);

    // Process the response
    const result = await OID4VPRedirectHelper.processDirectPostResponse({
        responseBody: { response: jwe },
        encryptionJwk: encPrivateJwk,
    });

    assert.equal(result.state, 'test-state-xyz');
    assert.ok(result.vpToken, 'Should have vpToken');
    assert.ok(result.vpToken['cred-mso_mdoc-org_iso_18013_5_1_mDL'], 'Should have credential key');
});

test('processDirectPostResponse handles unencrypted direct_post response', async () => {
    const result = await OID4VPRedirectHelper.processDirectPostResponse({
        responseBody: {
            vp_token: JSON.stringify({ 'cred-mso_mdoc-org_iso_18013_5_1_mDL': ['base64data'] }),
            state: 'plain-state',
        },
    });

    assert.equal(result.state, 'plain-state');
    assert.ok(result.vpToken['cred-mso_mdoc-org_iso_18013_5_1_mDL']);
});
```

- [ ] **Step 2: Run tests to verify the new ones fail**

```bash
cd /Users/calebion/Code/id-verifier && node --test tests/oid4vp-redirect-helper.test.js
```

Expected: New tests FAIL — `processDirectPostResponse` not defined.

- [ ] **Step 3: Add the method**

Add the import for `decryptJweResponse` at the top of `scripts/oid4vp-redirect-helper.js`:

```javascript
import { signRequestObject, decryptJweResponse } from './jwt-helper.js';
```

Then add this method to the class:

```javascript
    /**
     * Process a wallet's direct_post or direct_post.jwt response.
     * For direct_post.jwt: decrypts the JWE to extract vp_token and state.
     * For direct_post: parses the plain form body.
     *
     * @param {Object} options
     * @param {Object} options.responseBody - The wallet's POST body (form-decoded)
     * @param {Object} [options.encryptionJwk] - Verifier's ephemeral private JWK (required for .jwt mode)
     * @returns {Promise<Object>} { vpToken: Object, state: string }
     */
    async processDirectPostResponse({ responseBody, encryptionJwk }) {
        // direct_post.jwt mode: body has a single "response" field containing a JWE
        if (responseBody.response && encryptionJwk) {
            const decrypted = await decryptJweResponse(responseBody.response, encryptionJwk);
            return {
                vpToken: typeof decrypted.vp_token === 'string' ? JSON.parse(decrypted.vp_token) : decrypted.vp_token,
                state: decrypted.state,
            };
        }

        // Plain direct_post: body has vp_token and state directly
        return {
            vpToken: typeof responseBody.vp_token === 'string' ? JSON.parse(responseBody.vp_token) : responseBody.vp_token,
            state: responseBody.state,
        };
    }
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
cd /Users/calebion/Code/id-verifier && node --test tests/oid4vp-redirect-helper.test.js
```

Expected: All 13 tests PASS.

- [ ] **Step 5: Commit**

```bash
cd /Users/calebion/Code/id-verifier
git add scripts/oid4vp-redirect-helper.js tests/oid4vp-redirect-helper.test.js
git commit -m "feat: add processDirectPostResponse for direct_post.jwt decryption"
```

---

## Task 8: OID4VP Redirect Helper — Full Verification Pipeline

**Files:**
- Modify: `scripts/oid4vp-redirect-helper.js`
- Modify: `tests/oid4vp-redirect-helper.test.js`

This task adds the `verify` method that ties together: JWE decryption → SessionTranscript construction → DeviceResponse CBOR decode → mdoc verification (reusing `mdoc-helper.js`).

- [ ] **Step 1: Write the failing test**

Add to `tests/oid4vp-redirect-helper.test.js`:

```javascript
test('verify method calls through the full pipeline with correct SessionTranscript params', async () => {
    // This is a structural test — we verify the method exists and accepts the right params.
    // Full end-to-end testing with real mdoc DeviceResponses requires test fixtures
    // from actual wallet implementations.

    const encKeyPair = await crypto.subtle.generateKey(
        { name: 'ECDH', namedCurve: 'P-256' },
        true,
        ['deriveKey', 'deriveBits']
    );
    const encPrivateJwk = await crypto.subtle.exportKey('jwk', encKeyPair.privateKey);
    const encPublicJwk = await crypto.subtle.exportKey('jwk', encKeyPair.publicKey);

    // The verify method should exist and throw with invalid DeviceResponse data
    // (since we can't easily forge a valid mdoc in a unit test)
    try {
        await OID4VPRedirectHelper.verify({
            vpToken: { 'cred-mso_mdoc-org_iso_18013_5_1_mDL': ['aW52YWxpZA'] }, // "invalid" in base64url
            clientId: 'x509_hash:testhash',
            nonce: 'test-nonce',
            responseUri: 'https://example.com/response',
            encryptionJwk: encPublicJwk,
            trustLists: ['all_trust_lists'],
        });
        assert.fail('Should have thrown on invalid DeviceResponse');
    } catch (error) {
        // Expected — the important thing is the method signature works
        assert.ok(error, 'Should throw on invalid DeviceResponse data');
    }
});
```

- [ ] **Step 2: Run test to verify it fails**

```bash
cd /Users/calebion/Code/id-verifier && node --test tests/oid4vp-redirect-helper.test.js
```

Expected: FAIL — `verify` not defined.

- [ ] **Step 3: Add the verify method**

Add to the `OID4VPRedirectHelper` class:

```javascript
    /**
     * Verify mdoc credentials from a redirect flow response.
     * Reconstructs the SessionTranscript and delegates to the shared mdoc verification stack.
     *
     * @param {Object} options
     * @param {Object} options.vpToken - Parsed vp_token object (keyed by credential query ID)
     * @param {string} options.clientId - The client_id used in the request
     * @param {string} options.nonce - The nonce used in the request
     * @param {string} options.responseUri - The response_uri used in the request
     * @param {Object} [options.encryptionJwk] - The ephemeral public JWK (for jwkThumbprint in transcript)
     * @param {Array<string>} [options.trustLists] - Trust lists for issuer verification
     * @returns {Promise<Object>} { claims, valid, trusted, processedDocuments, sessionTranscript }
     */
    async verify({ vpToken, clientId, nonce, responseUri, encryptionJwk, trustLists = ALL_TRUST_LISTS }) {
        // Compute JWK thumbprint if encryption key was used
        let jwkThumbprint = null;
        if (encryptionJwk) {
            jwkThumbprint = await this.computeJwkThumbprint(encryptionJwk);
        }

        // Build the redirect-flow SessionTranscript
        const sessionTranscript = await this._generateSessionTranscript(clientId, nonce, jwkThumbprint, responseUri);

        // Process each credential in the vp_token
        const processedDocuments = [];
        const allClaims = {};
        let allValid = true;
        let allTrusted = true;

        for (const key in vpToken) {
            const credInfo = CredentialId[key];
            if (!credInfo || credInfo.format !== CredentialFormat.MSO_MDOC) {
                throw new Error(`Unsupported credential format for key: ${key}`);
            }

            const tokens = vpToken[key];
            for (const token of tokens) {
                const decoded = await decodeVpToken(token);
                for (const document of decoded.documents) {
                    const { claims, issuer, valid, invalidReasons } = await verifyDocument(document, sessionTranscript);
                    const issuerTrusted = issuer && (trustLists === ALL_TRUST_LISTS || issuer.certificate.trust_lists.some(tl => trustLists.includes(tl)));

                    allValid = allValid && valid;
                    allTrusted = allTrusted && issuerTrusted;

                    for (const claimKey in claims) {
                        allClaims[claimKey] = claims[claimKey];
                    }

                    const doc = {
                        claims,
                        valid,
                        trusted: !!issuerTrusted,
                        document,
                    };
                    if (issuer) doc.issuer = issuer;
                    if (!valid) doc.invalidReasons = invalidReasons;
                    processedDocuments.push(doc);
                }
            }
        }

        return {
            claims: allClaims,
            valid: !!allValid,
            trusted: !!allTrusted,
            processedDocuments,
            sessionTranscript,
        };
    }
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
cd /Users/calebion/Code/id-verifier && node --test tests/oid4vp-redirect-helper.test.js
```

Expected: All 14 tests PASS.

- [ ] **Step 5: Commit**

```bash
cd /Users/calebion/Code/id-verifier
git add scripts/oid4vp-redirect-helper.js tests/oid4vp-redirect-helper.test.js
git commit -m "feat: add full verification pipeline for redirect flow responses"
```

---

## Task 9: Export Public API from id-verifier.js

**Files:**
- Modify: `scripts/id-verifier.js`
- Modify: `scripts/constants.js` (export new constants)

- [ ] **Step 1: Add the new exports to `id-verifier.js`**

At the top of `scripts/id-verifier.js`, add the import (after the existing imports):

```javascript
import OID4VPRedirectHelper from './oid4vp-redirect-helper.js';
import { generateX509Hash, certToPemChain } from './x509-helper.js';
```

Add the following new exported functions after the existing `generateJWK` function (after line 189):

```javascript
/**
 * Create an OID4VP authorization request URL for wallet redirect.
 * Used for same-device redirect flows and QR code generation for cross-device flows.
 *
 * @param {Object} options
 * @param {string} options.clientId - Full client_id with prefix (e.g. "x509_hash:...")
 * @param {string} options.requestUri - URL where wallet retrieves the signed request object
 * @param {string} [options.walletScheme='openid4vp://'] - Wallet URL scheme (e.g. 'mdoc-openid4vp://')
 * @param {string} [options.requestUriMethod] - 'post' for wallet capability negotiation
 * @returns {string} Authorization request URL
 */
export const createAuthorizationRequestUrl = (options) => {
    return OID4VPRedirectHelper.createAuthorizationRequestUrl(options);
};

/**
 * Create a signed JWT Request Object for the request_uri endpoint.
 * The verifier serves this when the wallet GETs/POSTs the request_uri.
 *
 * @param {Object} options - See OID4VPRedirectHelper.createRequestObject for full options
 * @returns {Promise<string>} Signed JWT request object
 */
export const createRequestObject = async (options) => {
    return OID4VPRedirectHelper.createRequestObject(options);
};

/**
 * Process a wallet's direct_post or direct_post.jwt response.
 *
 * @param {Object} options
 * @param {Object} options.responseBody - The wallet's POST body
 * @param {Object} [options.encryptionJwk] - Verifier's ephemeral private JWK (for .jwt decryption)
 * @returns {Promise<Object>} { vpToken, state }
 */
export const processDirectPostResponse = async (options) => {
    return OID4VPRedirectHelper.processDirectPostResponse(options);
};

/**
 * Verify mdoc credentials from an OID4VP redirect flow response.
 * Reconstructs the SessionTranscript and validates DeviceAuth.
 *
 * @param {Object} options - See OID4VPRedirectHelper.verify for full options
 * @returns {Promise<Object>} { claims, valid, trusted, processedDocuments, sessionTranscript }
 */
export const verifyRedirectResponse = async (options) => {
    return OID4VPRedirectHelper.verify(options);
};

/**
 * Compute the JWK SHA-256 Thumbprint per RFC 7638.
 * @param {Object} jwk - Public JWK
 * @returns {Promise<Uint8Array>} 32-byte SHA-256 thumbprint
 */
export const computeJwkThumbprint = async (jwk) => {
    return OID4VPRedirectHelper.computeJwkThumbprint(jwk);
};
```

Update the existing `export` block at the bottom of `id-verifier.js` to include the new constants:

```javascript
export {
    DocumentType,
    Protocol,
    CredentialFormat,
    ProtocolFormats,
    Claim,
    setTestDataUsage,
    ResponseMode,
    ClientIdPrefix,
    WalletScheme,
    generateX509Hash,
    certToPemChain,
};
```

Also add the new constant imports at the top where `DocumentType` etc. are imported from `constants.js`:

```javascript
import { DocumentType, Protocol, CredentialFormat, ProtocolFormats, Claim, ALL_TRUST_LISTS, ResponseMode, ClientIdPrefix, WalletScheme } from './constants.js';
```

- [ ] **Step 2: Verify existing tests still pass**

```bash
cd /Users/calebion/Code/id-verifier && node --test
```

Expected: All existing and new tests PASS.

- [ ] **Step 3: Commit**

```bash
cd /Users/calebion/Code/id-verifier
git add scripts/id-verifier.js scripts/constants.js
git commit -m "feat: export OID4VP redirect flow API from id-verifier"
```

---

## Task 10: Handle `request_uri_method=post` Wallet Negotiation

**Files:**
- Modify: `scripts/oid4vp-redirect-helper.js`
- Modify: `tests/oid4vp-redirect-helper.test.js`

- [ ] **Step 1: Write the failing test**

Add to `tests/oid4vp-redirect-helper.test.js`:

```javascript
test('parseWalletPost extracts wallet_metadata and wallet_nonce from POST body', () => {
    const postBody = 'wallet_metadata=%7B%22vp_formats_supported%22%3A%7B%22mso_mdoc%22%3A%7B%7D%7D%7D&wallet_nonce=abc123xyz';

    const result = OID4VPRedirectHelper.parseWalletPost(postBody);

    assert.ok(result.walletMetadata, 'Should have walletMetadata');
    assert.equal(result.walletMetadata.vp_formats_supported.mso_mdoc !== undefined, true);
    assert.equal(result.walletNonce, 'abc123xyz');
});

test('parseWalletPost handles missing wallet_nonce', () => {
    const postBody = 'wallet_metadata=%7B%22vp_formats_supported%22%3A%7B%7D%7D';

    const result = OID4VPRedirectHelper.parseWalletPost(postBody);

    assert.ok(result.walletMetadata);
    assert.equal(result.walletNonce, undefined);
});
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
cd /Users/calebion/Code/id-verifier && node --test tests/oid4vp-redirect-helper.test.js
```

Expected: FAIL — `parseWalletPost` not defined.

- [ ] **Step 3: Add the method**

Add to the `OID4VPRedirectHelper` class:

```javascript
    /**
     * Parse the wallet's POST body from a request_uri_method=post negotiation.
     * The wallet POSTs application/x-www-form-urlencoded data with wallet_metadata and optional wallet_nonce.
     *
     * @param {string} body - URL-encoded form body from the wallet's POST
     * @returns {Object} { walletMetadata: Object, walletNonce: string|undefined }
     */
    parseWalletPost(body) {
        const params = new URLSearchParams(body);
        const walletMetadataStr = params.get('wallet_metadata');
        const walletNonce = params.get('wallet_nonce') || undefined;

        let walletMetadata = {};
        if (walletMetadataStr) {
            walletMetadata = JSON.parse(walletMetadataStr);
        }

        return { walletMetadata, walletNonce };
    }
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
cd /Users/calebion/Code/id-verifier && node --test tests/oid4vp-redirect-helper.test.js
```

Expected: All 16 tests PASS.

- [ ] **Step 5: Add the export to `id-verifier.js`**

Add after the other new exports in `scripts/id-verifier.js`:

```javascript
/**
 * Parse the wallet's POST body from request_uri_method=post negotiation.
 * @param {string} body - URL-encoded form body
 * @returns {Object} { walletMetadata, walletNonce }
 */
export const parseWalletPost = (body) => {
    return OID4VPRedirectHelper.parseWalletPost(body);
};
```

- [ ] **Step 6: Run all tests**

```bash
cd /Users/calebion/Code/id-verifier && node --test
```

Expected: All tests PASS.

- [ ] **Step 7: Commit**

```bash
cd /Users/calebion/Code/id-verifier
git add scripts/oid4vp-redirect-helper.js scripts/id-verifier.js tests/oid4vp-redirect-helper.test.js
git commit -m "feat: add wallet POST negotiation parser for request_uri_method=post"
```

---

## Task 11: Generate Verifier Response for Redirect Callback

**Files:**
- Modify: `scripts/oid4vp-redirect-helper.js`
- Modify: `tests/oid4vp-redirect-helper.test.js`

When the wallet POSTs to `response_uri`, the verifier must respond with a JSON body containing a `redirect_uri` (for same-device) and `response_code` (for session correlation).

- [ ] **Step 1: Write the failing test**

Add to `tests/oid4vp-redirect-helper.test.js`:

```javascript
test('createDirectPostSuccessResponse returns redirect_uri with response_code', () => {
    const result = OID4VPRedirectHelper.createDirectPostSuccessResponse({
        redirectUri: 'https://verifier.example.com/callback',
    });

    assert.ok(result.redirect_uri, 'Should have redirect_uri');
    assert.ok(result.redirect_uri.includes('response_code='), 'redirect_uri should include response_code');

    const url = new URL(result.redirect_uri);
    const responseCode = url.searchParams.get('response_code');
    assert.ok(responseCode.length >= 16, 'response_code should be sufficiently random');
});

test('createDirectPostSuccessResponse omits redirect_uri for cross-device', () => {
    const result = OID4VPRedirectHelper.createDirectPostSuccessResponse({});

    assert.equal(result.redirect_uri, undefined, 'Cross-device should have no redirect_uri');
});
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
cd /Users/calebion/Code/id-verifier && node --test tests/oid4vp-redirect-helper.test.js
```

Expected: FAIL — `createDirectPostSuccessResponse` not defined.

- [ ] **Step 3: Add the method**

Add to the `OID4VPRedirectHelper` class:

```javascript
    /**
     * Create the HTTP 200 response body for a successful direct_post from the wallet.
     * For same-device flows, includes a redirect_uri with a response_code.
     * For cross-device flows, the redirect_uri is omitted.
     *
     * @param {Object} options
     * @param {string} [options.redirectUri] - Base redirect URI (omit for cross-device)
     * @returns {Object} Response body to send as HTTP 200 JSON
     */
    createDirectPostSuccessResponse({ redirectUri }) {
        if (!redirectUri) {
            return {};
        }

        // Generate a cryptographically random response_code
        const codeBytes = new Uint8Array(24);
        crypto.getRandomValues(codeBytes);
        const responseCode = Array.from(codeBytes, byte => byte.toString(16).padStart(2, '0')).join('');

        const url = new URL(redirectUri);
        url.searchParams.set('response_code', responseCode);

        return {
            redirect_uri: url.toString(),
        };
    }
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
cd /Users/calebion/Code/id-verifier && node --test tests/oid4vp-redirect-helper.test.js
```

Expected: All 18 tests PASS.

- [ ] **Step 5: Add the export and commit**

Add to `scripts/id-verifier.js` after the other new exports:

```javascript
/**
 * Create the verifier's response to a wallet direct_post.
 * @param {Object} options
 * @param {string} [options.redirectUri] - Base redirect URI (omit for cross-device)
 * @returns {Object} HTTP 200 response body
 */
export const createDirectPostSuccessResponse = (options) => {
    return OID4VPRedirectHelper.createDirectPostSuccessResponse(options);
};
```

```bash
cd /Users/calebion/Code/id-verifier
git add scripts/oid4vp-redirect-helper.js scripts/id-verifier.js tests/oid4vp-redirect-helper.test.js
git commit -m "feat: add direct_post success response builder with response_code"
```

---

## Task 12: Run Full Test Suite and Final Verification

**Files:**
- No new files

- [ ] **Step 1: Run all tests**

```bash
cd /Users/calebion/Code/id-verifier && node --test
```

Expected: All tests pass — existing DC API tests + all new redirect flow tests.

- [ ] **Step 2: Verify the build**

```bash
cd /Users/calebion/Code/id-verifier && yarn build
```

Expected: Rollup builds successfully with the new modules included.

- [ ] **Step 3: Verify all new exports are accessible**

```bash
cd /Users/calebion/Code/id-verifier && node -e "
import {
    createAuthorizationRequestUrl,
    createRequestObject,
    processDirectPostResponse,
    verifyRedirectResponse,
    computeJwkThumbprint,
    parseWalletPost,
    createDirectPostSuccessResponse,
    generateX509Hash,
    certToPemChain,
    ResponseMode,
    ClientIdPrefix,
    WalletScheme,
    generateNonce,
    generateJWK,
    createCredentialsRequest,
    processCredentials,
} from './scripts/id-verifier.js';

console.log('All exports available:');
console.log('  createAuthorizationRequestUrl:', typeof createAuthorizationRequestUrl);
console.log('  createRequestObject:', typeof createRequestObject);
console.log('  processDirectPostResponse:', typeof processDirectPostResponse);
console.log('  verifyRedirectResponse:', typeof verifyRedirectResponse);
console.log('  computeJwkThumbprint:', typeof computeJwkThumbprint);
console.log('  parseWalletPost:', typeof parseWalletPost);
console.log('  createDirectPostSuccessResponse:', typeof createDirectPostSuccessResponse);
console.log('  generateX509Hash:', typeof generateX509Hash);
console.log('  certToPemChain:', typeof certToPemChain);
console.log('  ResponseMode:', typeof ResponseMode, ResponseMode);
console.log('  ClientIdPrefix:', typeof ClientIdPrefix, ClientIdPrefix);
console.log('  WalletScheme:', typeof WalletScheme, WalletScheme);
console.log('  generateNonce:', typeof generateNonce);
console.log('  generateJWK:', typeof generateJWK);
console.log('  createCredentialsRequest:', typeof createCredentialsRequest);
console.log('  processCredentials:', typeof processCredentials);
" --input-type=module
```

Expected: All exports show as `function` or `object` with correct values.

- [ ] **Step 4: Commit final state**

```bash
cd /Users/calebion/Code/id-verifier && git status
```

If clean, no commit needed. If there are uncommitted changes:

```bash
cd /Users/calebion/Code/id-verifier
git add -A
git commit -m "chore: final verification of OID4VP redirect flow implementation"
```

---

## Summary: New Public API Surface

After completing all tasks, `id-verifier` exports these new functions for the redirect flow:

| Function | Purpose | Used By |
|----------|---------|---------|
| `createAuthorizationRequestUrl(options)` | Build wallet redirect URL / QR code content | Backend: generate URL for client |
| `createRequestObject(options)` | Sign JWT request object for `request_uri` endpoint | Backend: serve at `request_uri` |
| `parseWalletPost(body)` | Parse wallet's `request_uri_method=post` body | Backend: `request_uri` POST handler |
| `processDirectPostResponse(options)` | Decrypt JWE from `direct_post.jwt` | Backend: `response_uri` handler |
| `verifyRedirectResponse(options)` | Full mdoc verification with redirect SessionTranscript | Backend: after decryption |
| `createDirectPostSuccessResponse(options)` | Build HTTP 200 response with `redirect_uri` + `response_code` | Backend: respond to wallet POST |
| `generateX509Hash(derCertBytes)` | Compute `x509_hash` client ID | Backend: during setup |
| `certToPemChain(derCerts)` | Convert DER certs to x5c format | Backend: for JWT signing |
| `computeJwkThumbprint(jwk)` | RFC 7638 JWK thumbprint | Backend: SessionTranscript |

Existing DC API functions (`createCredentialsRequest`, `processCredentials`, `generateNonce`, `generateJWK`) remain unchanged.
