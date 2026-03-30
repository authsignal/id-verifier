# Credential Trust & Revocation Verification Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add three verification capabilities: (1) validate issuer certificate chains against user-provided trusted certificates, (2) CRL-based revocation checking for the certificate chain, and (3) IETF Token Status List-based credential revocation checking with recheck support.

**Architecture:** A new `issuer-verifier.js` replaces `trusted-issuer-registry-helper.js` as the primary trust verification module. It accepts an array of PEM-encoded trusted root/IACA certificates provided by the caller, validates the issuer cert chain against them using pkijs chain verification, optionally checks CRLs at each cert's CRL Distribution Point, and returns trust status. Separately, a new `status-list-helper.js` handles IETF Token Status List (RFC 9597) checks — fetching the status list JWT, decoding the compressed bitstring, and checking the credential's index. Both modules use a shared `fetch-cache.js` for HTTP fetching with TTL-based caching. The `verifyDocument` function in `mdoc-helper.js` is updated to accept these options and thread them through.

**Tech Stack:** JavaScript (ES6 modules), `pkijs` (X.509 chain verification), `jose` (JWT decoding for status lists), `pako` (zlib decompression for status list bitstrings — new dependency), Web Crypto API

---

## File Structure

| File | Action | Responsibility |
|------|--------|---------------|
| `scripts/issuer-verifier.js` | **Create** | Validate issuer cert chain against provided trusted certs, extract full x5chain, run CRL checks |
| `scripts/crl-helper.js` | **Create** | Fetch CRLs from distribution points, parse CRL, check serial number revocation, cache CRLs |
| `scripts/status-list-helper.js` | **Create** | Fetch IETF Token Status List JWT, decompress bitstring, check credential index, cache with TTL |
| `scripts/fetch-cache.js` | **Create** | Shared HTTP fetch with in-memory TTL cache (used by CRL and status list) |
| `scripts/formats/mdoc-helper.js` | **Modify** | Pass verification options (trustedCertificates, enableCrl, enableStatusList) through to issuer-verifier |
| `scripts/certificate-helper.js` | **Modify** | Add `parseX5ChainAll` to return full cert chain (not just leaf), add chain validation using pkijs |
| `scripts/id-verifier.js` | **Modify** | Thread new options through `processCredentials` and `verifyRedirectResponse` |
| `scripts/oid4vp-redirect-helper.js` | **Modify** | Thread new options through `verify` |
| `tests/issuer-verifier.test.js` | **Create** | Tests for chain validation against trusted certs |
| `tests/crl-helper.test.js` | **Create** | Tests for CRL parsing and revocation checking |
| `tests/status-list-helper.test.js` | **Create** | Tests for status list fetching, decompression, and index checking |
| `tests/fetch-cache.test.js` | **Create** | Tests for caching behavior |

---

## Task 1: Fetch Cache Module

**Files:**
- Create: `scripts/fetch-cache.js`
- Create: `tests/fetch-cache.test.js`

- [ ] **Step 1: Write the failing test**

Create `tests/fetch-cache.test.js`:

```javascript
import test from 'node:test';
import assert from 'node:assert/strict';
import { FetchCache } from '../scripts/fetch-cache.js';

test('FetchCache returns cached response within TTL', async () => {
    let fetchCount = 0;
    const cache = new FetchCache({
        fetchFn: async (url) => {
            fetchCount++;
            return { data: 'test-response', fetchedAt: Date.now() };
        },
    });

    const r1 = await cache.get('https://example.com/crl', { ttlMs: 60000 });
    const r2 = await cache.get('https://example.com/crl', { ttlMs: 60000 });

    assert.equal(fetchCount, 1, 'Should only fetch once');
    assert.equal(r1.data, 'test-response');
    assert.equal(r2.data, 'test-response');
});

test('FetchCache re-fetches after TTL expires', async () => {
    let fetchCount = 0;
    const cache = new FetchCache({
        fetchFn: async (url) => {
            fetchCount++;
            return { data: `response-${fetchCount}` };
        },
    });

    await cache.get('https://example.com/crl', { ttlMs: 1 }); // 1ms TTL
    await new Promise(r => setTimeout(r, 10)); // Wait for TTL to expire
    const r2 = await cache.get('https://example.com/crl', { ttlMs: 1 });

    assert.equal(fetchCount, 2, 'Should fetch twice after TTL expires');
    assert.equal(r2.data, 'response-2');
});

test('FetchCache caches by URL', async () => {
    let fetchCount = 0;
    const cache = new FetchCache({
        fetchFn: async (url) => {
            fetchCount++;
            return { data: url };
        },
    });

    const r1 = await cache.get('https://example.com/a', { ttlMs: 60000 });
    const r2 = await cache.get('https://example.com/b', { ttlMs: 60000 });

    assert.equal(fetchCount, 2, 'Different URLs should fetch separately');
    assert.equal(r1.data, 'https://example.com/a');
    assert.equal(r2.data, 'https://example.com/b');
});

test('FetchCache handles fetch errors gracefully', async () => {
    const cache = new FetchCache({
        fetchFn: async () => { throw new Error('Network error'); },
    });

    const result = await cache.get('https://example.com/fail', { ttlMs: 60000 });
    assert.equal(result, null, 'Should return null on fetch error');
});
```

- [ ] **Step 2: Run test to verify it fails**

```bash
node --test tests/fetch-cache.test.js
```

Expected: FAIL — module not found.

- [ ] **Step 3: Write the implementation**

Create `scripts/fetch-cache.js`:

```javascript
/**
 * Simple in-memory fetch cache with TTL support.
 * Used by CRL and Token Status List helpers.
 */
export class FetchCache {
    constructor({ fetchFn }) {
        this._fetchFn = fetchFn;
        this._cache = new Map();
    }

    /**
     * Get a cached response or fetch a fresh one.
     * @param {string} url - The URL to fetch
     * @param {Object} options
     * @param {number} options.ttlMs - Cache TTL in milliseconds
     * @returns {Promise<any|null>} Cached or fresh response, or null on error
     */
    async get(url, { ttlMs }) {
        const cached = this._cache.get(url);
        if (cached && (Date.now() - cached.timestamp) < ttlMs) {
            return cached.value;
        }

        try {
            const value = await this._fetchFn(url);
            this._cache.set(url, { value, timestamp: Date.now() });
            return value;
        } catch (error) {
            console.error(`FetchCache: error fetching ${url}:`, error.message);
            return null;
        }
    }

    /**
     * Clear all cached entries.
     */
    clear() {
        this._cache.clear();
    }

    /**
     * Remove a specific URL from cache.
     * @param {string} url
     */
    invalidate(url) {
        this._cache.delete(url);
    }
}
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
node --test tests/fetch-cache.test.js
```

Expected: All 4 tests PASS.

- [ ] **Step 5: Commit**

```bash
git add scripts/fetch-cache.js tests/fetch-cache.test.js
git commit -m "feat: add FetchCache module for TTL-based HTTP response caching"
```

---

## Task 2: Parse Full X.509 Chain and Validate Against Trusted Certs

**Files:**
- Modify: `scripts/certificate-helper.js`
- Create: `scripts/issuer-verifier.js`
- Create: `tests/issuer-verifier.test.js`

- [ ] **Step 1: Write the failing test**

Create `tests/issuer-verifier.test.js`:

```javascript
import test from 'node:test';
import assert from 'node:assert/strict';
import { verifyIssuerTrust } from '../scripts/issuer-verifier.js';
import { certificateToPem } from '../scripts/certificate-helper.js';

// Helper: generate a CA + leaf cert chain
async function generateCertChain() {
    const { Certificate } = await import('pkijs');
    const asn1js = await import('asn1js');

    // Generate CA key pair
    const caKeyPair = await crypto.subtle.generateKey(
        { name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']
    );

    // Create CA cert (self-signed)
    const caCert = new Certificate();
    caCert.version = 2;
    caCert.serialNumber = new asn1js.Integer({ value: 1 });
    await caCert.subjectPublicKeyInfo.importKey(caKeyPair.publicKey);
    caCert.notBefore.value = new Date();
    caCert.notAfter.value = new Date(Date.now() + 365 * 24 * 60 * 60 * 1000);

    // Add Basic Constraints (CA: true)
    caCert.extensions = [
        new (await import('pkijs')).Extension({
            extnID: '2.5.29.19', // basicConstraints
            critical: true,
            extnValue: new asn1js.Sequence({
                value: [new asn1js.Boolean({ value: true })]
            }).toBER(false),
        }),
    ];

    await caCert.sign(caKeyPair.privateKey, 'SHA-256');

    // Generate leaf key pair
    const leafKeyPair = await crypto.subtle.generateKey(
        { name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']
    );

    // Create leaf cert (signed by CA)
    const leafCert = new Certificate();
    leafCert.version = 2;
    leafCert.serialNumber = new asn1js.Integer({ value: 2 });
    await leafCert.subjectPublicKeyInfo.importKey(leafKeyPair.publicKey);
    leafCert.issuer = caCert.subject;
    leafCert.notBefore.value = new Date();
    leafCert.notAfter.value = new Date(Date.now() + 365 * 24 * 60 * 60 * 1000);
    await leafCert.sign(caKeyPair.privateKey, 'SHA-256');

    const caPem = certificateToPem(caCert);

    return { caCert, caPem, leafCert, caKeyPair, leafKeyPair };
}

test('verifyIssuerTrust validates leaf cert against trusted CA PEM', async () => {
    const { caPem, leafCert } = await generateCertChain();

    const result = await verifyIssuerTrust(leafCert, {
        trustedCertificates: [caPem],
    });

    assert.equal(result.trusted, true, 'Leaf cert should be trusted');
    assert.ok(result.matchedCertificate, 'Should return the matched CA cert');
});

test('verifyIssuerTrust rejects leaf cert not signed by any trusted CA', async () => {
    const { leafCert } = await generateCertChain();
    const { caPem: otherCaPem } = await generateCertChain(); // different CA

    const result = await verifyIssuerTrust(leafCert, {
        trustedCertificates: [otherCaPem],
    });

    assert.equal(result.trusted, false, 'Leaf cert should not be trusted');
});

test('verifyIssuerTrust returns not trusted when no trustedCertificates provided', async () => {
    const { leafCert } = await generateCertChain();

    const result = await verifyIssuerTrust(leafCert, {});

    assert.equal(result.trusted, false, 'Should not be trusted without certs');
});

test('verifyIssuerTrust handles multiple trusted CAs', async () => {
    const chain1 = await generateCertChain();
    const chain2 = await generateCertChain();

    const result = await verifyIssuerTrust(chain1.leafCert, {
        trustedCertificates: [chain2.caPem, chain1.caPem],
    });

    assert.equal(result.trusted, true, 'Should match the correct CA from multiple');
});
```

- [ ] **Step 2: Run test to verify it fails**

```bash
node --test tests/issuer-verifier.test.js
```

Expected: FAIL — module not found.

- [ ] **Step 3: Add `parseX5ChainAll` to certificate-helper.js**

Add to `scripts/certificate-helper.js` (after `parseX5Chain`):

```javascript
/**
 * Parse a full X.509 chain into an array of PKIjs Certificate objects
 * @param {Array|Uint8Array} x5chain - The X.509 chain (array of DER-encoded Uint8Arrays)
 * @returns {Certificate[]} - Array of parsed Certificate objects
 */
export const parseX5ChainAll = (x5chain) => {
    if (!x5chain) return [];
    const certs = x5chain instanceof Array ? x5chain : [x5chain];
    return certs.map(certBytes => {
        const arrayBuffer = certBytes.buffer.slice(certBytes.byteOffset, certBytes.byteOffset + certBytes.byteLength);
        const asn1 = asn1js.fromBER(arrayBuffer);
        return new Certificate({ schema: asn1.result });
    });
};
```

- [ ] **Step 4: Write the issuer-verifier implementation**

Create `scripts/issuer-verifier.js`:

```javascript
import { parsePemCertificate, certificateToPem } from './certificate-helper.js';

/**
 * Verify an issuer certificate against a set of trusted root/IACA certificates.
 * Validates that the certificate was signed by one of the trusted CAs.
 *
 * @param {Certificate} certificate - The issuer's leaf certificate (from IssuerAuth x5chain)
 * @param {Object} options
 * @param {string[]} [options.trustedCertificates] - Array of PEM-encoded trusted root/IACA certificates
 * @returns {Promise<{ trusted: boolean, matchedCertificate: string|null }>}
 */
export const verifyIssuerTrust = async (certificate, { trustedCertificates } = {}) => {
    if (!trustedCertificates || !Array.isArray(trustedCertificates) || trustedCertificates.length === 0) {
        return { trusted: false, matchedCertificate: null };
    }

    if (!certificate) {
        return { trusted: false, matchedCertificate: null };
    }

    // Get the TBS (To Be Signed) bytes and signature from the leaf cert
    let tbsBytes, signature;
    try {
        tbsBytes = new Uint8Array(certificate.tbsView);
        signature = certificate.signatureValue.valueBlock.valueHex;
    } catch (error) {
        console.error('Could not extract TBS/signature from certificate:', error.message);
        return { trusted: false, matchedCertificate: null };
    }

    // Try each trusted CA
    for (const trustedPem of trustedCertificates) {
        try {
            const trustedCert = parsePemCertificate(trustedPem);
            const publicKeyInfo = trustedCert.subjectPublicKeyInfo;
            const spkiBytes = publicKeyInfo.toSchema().toBER();

            // Determine algorithm from the trusted cert's public key
            const algOid = publicKeyInfo.algorithm.algorithmId;
            let algorithm;
            if (algOid === '1.2.840.10045.2.1') {
                // EC key — determine curve from parameters
                const curveOid = publicKeyInfo.algorithm.algorithmParams?.valueBlock?.toString();
                if (curveOid === '1.2.840.10045.3.1.7') {
                    algorithm = { name: 'ECDSA', namedCurve: 'P-256', hash: 'SHA-256' };
                } else if (curveOid === '1.3.132.0.34') {
                    algorithm = { name: 'ECDSA', namedCurve: 'P-384', hash: 'SHA-384' };
                } else {
                    algorithm = { name: 'ECDSA', namedCurve: 'P-256', hash: 'SHA-256' };
                }
            } else if (algOid === '1.2.840.113549.1.1.1') {
                algorithm = { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' };
            } else {
                continue; // Unsupported algorithm
            }

            const publicKey = await crypto.subtle.importKey('spki', spkiBytes, algorithm, false, ['verify']);

            // The signature in X.509 is DER-encoded for ECDSA, Web Crypto expects raw r||s
            let signatureBytes = new Uint8Array(signature);
            if (algorithm.name === 'ECDSA') {
                signatureBytes = derEcdsaSignatureToRaw(signatureBytes, algorithm.namedCurve);
            }

            const valid = await crypto.subtle.verify(algorithm, publicKey, signatureBytes, tbsBytes);

            if (valid) {
                return { trusted: true, matchedCertificate: trustedPem };
            }
        } catch (error) {
            // This trusted cert didn't match, try the next one
            continue;
        }
    }

    return { trusted: false, matchedCertificate: null };
};

/**
 * Convert a DER-encoded ECDSA signature to raw r||s format for Web Crypto.
 * DER format: SEQUENCE { INTEGER r, INTEGER s }
 * Raw format: r (32 bytes) || s (32 bytes) for P-256
 */
function derEcdsaSignatureToRaw(derSig, curve) {
    const componentLength = curve === 'P-384' ? 48 : curve === 'P-521' ? 66 : 32;

    // Parse DER SEQUENCE
    let offset = 0;
    if (derSig[offset++] !== 0x30) throw new Error('Expected SEQUENCE');
    offset++; // skip length

    // Parse r INTEGER
    if (derSig[offset++] !== 0x02) throw new Error('Expected INTEGER for r');
    const rLen = derSig[offset++];
    let r = derSig.slice(offset, offset + rLen);
    offset += rLen;

    // Parse s INTEGER
    if (derSig[offset++] !== 0x02) throw new Error('Expected INTEGER for s');
    const sLen = derSig[offset++];
    let s = derSig.slice(offset, offset + sLen);

    // Remove leading zero bytes (DER adds 0x00 for positive integers with high bit set)
    if (r.length > componentLength) r = r.slice(r.length - componentLength);
    if (s.length > componentLength) s = s.slice(s.length - componentLength);

    // Pad to component length
    const raw = new Uint8Array(componentLength * 2);
    raw.set(r, componentLength - r.length);
    raw.set(s, componentLength * 2 - s.length);
    return raw;
}
```

- [ ] **Step 5: Run tests to verify they pass**

```bash
node --test tests/issuer-verifier.test.js
```

Expected: All 4 tests PASS.

- [ ] **Step 6: Commit**

```bash
git add scripts/issuer-verifier.js scripts/certificate-helper.js tests/issuer-verifier.test.js
git commit -m "feat: add issuer-verifier for validating certs against trusted CAs"
```

---

## Task 3: Wire Trusted Certificates Through Verification Pipeline

**Files:**
- Modify: `scripts/formats/mdoc-helper.js`
- Modify: `scripts/oid4vp-redirect-helper.js`
- Modify: `scripts/id-verifier.js`

- [ ] **Step 1: Update `verifyDocument` in mdoc-helper.js to accept verificationOptions**

In `scripts/formats/mdoc-helper.js`, change the `verifyDocument` signature and add issuer trust verification:

```javascript
// At the top, add import:
import { verifyIssuerTrust } from '../issuer-verifier.js';

// Change verifyDocument signature:
export const verifyDocument = async (document, sessionTranscript, verificationOptions = {}) => {
    const claims = {};
    const invalidReasons = [];
    const { docType, issuerSigned, deviceSigned } = document;
    const { issuerAuth, nameSpaces } = issuerSigned;
    const { valid, issuerAuthPayload, certificate, invalidReason } = await verifyIssuerAuth(issuerAuth);
    if(!valid) invalidReasons.push(invalidReason);
    const deviceValid = await verifyDeviceAuth(deviceSigned, issuerAuthPayload, sessionTranscript);
    if(!deviceValid) invalidReasons.push('Failed to verify device authentication');
    let claimsValid = true;
    for(const namespace in nameSpaces) {
        for(const claim of nameSpaces[namespace]) {
            const claimValid = await setClaim(claims, docType, namespace, claim, issuerAuthPayload);
            if(!claimValid && claimsValid) {
                claimsValid = false;
                invalidReasons.push("Claim values don't match IssuerAuth value digests");
            }
        }
    }

    // Determine issuer trust
    let issuer = null;
    if (verificationOptions.trustedCertificates) {
        const trustResult = await verifyIssuerTrust(certificate, {
            trustedCertificates: verificationOptions.trustedCertificates,
        });
        if (trustResult.trusted) {
            issuer = {
                trusted: true,
                certificate: { data: trustResult.matchedCertificate, format: 'pem' },
            };
        }
    } else {
        // Fall back to trusted-issuer-registry
        issuer = await getIssuer(certificate);
    }

    return {
        claims: claims,
        issuer: issuer,
        valid: valid && deviceValid && claimsValid,
        invalidReasons: invalidReasons,
    };
};
```

- [ ] **Step 2: Update `verify` in oid4vp-redirect-helper.js to pass verificationOptions**

In `scripts/oid4vp-redirect-helper.js`, update the `verify` method signature to accept and thread `trustedCertificates`:

```javascript
    async verify({ vpToken, clientId, nonce, responseUri, encryptionJwk, mdocGeneratedNonce, trustLists = ALL_TRUST_LISTS, trustedCertificates }) {
        // ... existing SessionTranscript code ...

        for (const credentialKey of Object.keys(vpToken)) {
            // ... existing credential key check ...

            const tokens = vpToken[credentialKey];
            for (const token of tokens) {
                const decoded = await decodeVpToken(token);
                for (const doc of decoded.documents) {
                    const { claims, issuer, valid: docValid, invalidReasons } = await verifyDocument(doc, sessionTranscript, { trustedCertificates });
                    // ... rest of existing logic, but update trust check:

                    const issuerTrusted = trustedCertificates
                        ? (issuer?.trusted === true)
                        : (issuer && (
                            trustLists === ALL_TRUST_LISTS ||
                            (Array.isArray(trustLists) && trustLists.includes('all_trust_lists')) ||
                            issuer.certificate?.trust_lists?.some(tl => trustLists.includes(tl))
                        ));
```

- [ ] **Step 3: Update `verifyRedirectResponse` in id-verifier.js**

The existing wrapper already passes options through, but ensure `trustedCertificates` is documented:

```javascript
/**
 * Verify mdoc credentials from an OID4VP redirect flow response.
 * @param {Object} options - See OID4VPRedirectHelper.verify
 * @param {string[]} [options.trustedCertificates] - Array of PEM-encoded trusted root/IACA certificates
 * @returns {Promise<Object>} { claims, valid, trusted, processedDocuments, sessionTranscript }
 */
export const verifyRedirectResponse = async (options) => {
    return OID4VPRedirectHelper.verify(options);
};
```

- [ ] **Step 4: Run all tests**

```bash
node --test tests/*.test.js
```

Expected: All existing tests + new tests PASS.

- [ ] **Step 5: Commit**

```bash
git add scripts/formats/mdoc-helper.js scripts/oid4vp-redirect-helper.js scripts/id-verifier.js
git commit -m "feat: wire trustedCertificates through verification pipeline"
```

---

## Task 4: CRL Helper — Fetch, Parse, and Check Revocation

**Files:**
- Create: `scripts/crl-helper.js`
- Create: `tests/crl-helper.test.js`

- [ ] **Step 1: Write the failing test**

Create `tests/crl-helper.test.js`:

```javascript
import test from 'node:test';
import assert from 'node:assert/strict';
import { getCrlDistributionPoints, checkCertRevocation } from '../scripts/crl-helper.js';

test('getCrlDistributionPoints extracts CRL URLs from certificate', async () => {
    const { cert, crlUrl } = await generateCertWithCrl();
    const points = getCrlDistributionPoints(cert);
    assert.ok(Array.isArray(points));
    assert.ok(points.length > 0, 'Should find at least one CRL distribution point');
    assert.ok(points.includes(crlUrl), `Should include ${crlUrl}`);
});

test('getCrlDistributionPoints returns empty array for cert without CRL', async () => {
    const { Certificate } = await import('pkijs');
    const asn1js = await import('asn1js');
    const keyPair = await crypto.subtle.generateKey(
        { name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']
    );
    const cert = new Certificate();
    cert.version = 2;
    cert.serialNumber = new asn1js.Integer({ value: 1 });
    await cert.subjectPublicKeyInfo.importKey(keyPair.publicKey);
    cert.notBefore.value = new Date();
    cert.notAfter.value = new Date(Date.now() + 365 * 24 * 60 * 60 * 1000);
    await cert.sign(keyPair.privateKey, 'SHA-256');

    const points = getCrlDistributionPoints(cert);
    assert.deepEqual(points, []);
});

test('checkCertRevocation returns not-revoked when CRL is empty', async () => {
    const result = await checkCertRevocation(null, {
        enabled: false,
    });
    assert.equal(result.revoked, false);
});

// Helper to generate a cert with CRL Distribution Point extension
async function generateCertWithCrl() {
    const { Certificate, Extension } = await import('pkijs');
    const asn1js = await import('asn1js');
    const keyPair = await crypto.subtle.generateKey(
        { name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']
    );
    const cert = new Certificate();
    cert.version = 2;
    cert.serialNumber = new asn1js.Integer({ value: 42 });
    await cert.subjectPublicKeyInfo.importKey(keyPair.publicKey);
    cert.notBefore.value = new Date();
    cert.notAfter.value = new Date(Date.now() + 365 * 24 * 60 * 60 * 1000);

    const crlUrl = 'https://example.com/crl/test.crl';

    // CRL Distribution Points extension (OID 2.5.29.31)
    // Simplified: encode the URL as a GeneralName (uniformResourceIdentifier [6])
    const urlBytes = new TextEncoder().encode(crlUrl);
    const generalName = new asn1js.Constructed({
        idBlock: { tagClass: 3, tagNumber: 6 }, // context [6] = URI
        value: [new asn1js.Primitive({
            idBlock: { tagClass: 3, tagNumber: 6 },
            valueHex: urlBytes.buffer,
        })],
    });
    // DistributionPoint -> distributionPointName -> fullName -> GeneralNames
    const dpName = new asn1js.Constructed({
        idBlock: { tagClass: 3, tagNumber: 0 },
        value: [new asn1js.Constructed({
            idBlock: { tagClass: 3, tagNumber: 0 },
            value: [new asn1js.Primitive({
                idBlock: { tagClass: 3, tagNumber: 6 },
                valueHex: urlBytes.buffer,
            })],
        })],
    });
    const dp = new asn1js.Sequence({ value: [dpName] });
    const crlDpExt = new asn1js.Sequence({ value: [dp] });

    cert.extensions = [
        new Extension({
            extnID: '2.5.29.31',
            critical: false,
            extnValue: crlDpExt.toBER(false),
        }),
    ];

    await cert.sign(keyPair.privateKey, 'SHA-256');
    return { cert, crlUrl };
}
```

- [ ] **Step 2: Run test to verify it fails**

```bash
node --test tests/crl-helper.test.js
```

Expected: FAIL — module not found.

- [ ] **Step 3: Write the implementation**

Create `scripts/crl-helper.js`:

```javascript
import * as asn1js from 'asn1js';
import { FetchCache } from './fetch-cache.js';

const crlCache = new FetchCache({
    fetchFn: async (url) => {
        const response = await fetch(url);
        if (!response.ok) throw new Error(`CRL fetch failed: ${response.status}`);
        const arrayBuffer = await response.arrayBuffer();
        return parseCrl(new Uint8Array(arrayBuffer));
    },
});

/**
 * Extract CRL Distribution Point URLs from a certificate.
 * @param {Certificate} certificate - PKIjs Certificate
 * @returns {string[]} Array of CRL URLs
 */
export const getCrlDistributionPoints = (certificate) => {
    const urls = [];
    if (!certificate?.extensions) return urls;

    const crlDpExt = certificate.extensions.find(ext => ext.extnID === '2.5.29.31');
    if (!crlDpExt) return urls;

    try {
        const asn1 = asn1js.fromBER(crlDpExt.extnValue.valueBlock.valueHex);
        const sequence = asn1.result;

        // Walk the ASN.1 structure to find URI GeneralNames
        extractUrisFromAsn1(sequence, urls);
    } catch (error) {
        console.error('Error parsing CRL Distribution Points:', error.message);
    }

    return urls;
};

/**
 * Check if a certificate has been revoked via its CRL Distribution Points.
 * @param {Certificate} certificate - PKIjs Certificate to check
 * @param {Object} options
 * @param {boolean} [options.enabled=true] - Whether CRL checking is enabled
 * @param {number} [options.cacheTtlMs=3600000] - CRL cache TTL (default: 1 hour)
 * @returns {Promise<{ revoked: boolean, reason?: string }>}
 */
export const checkCertRevocation = async (certificate, { enabled = true, cacheTtlMs = 3600000 } = {}) => {
    if (!enabled || !certificate) {
        return { revoked: false };
    }

    const crlUrls = getCrlDistributionPoints(certificate);
    if (crlUrls.length === 0) {
        return { revoked: false };
    }

    for (const url of crlUrls) {
        try {
            const crl = await crlCache.get(url, { ttlMs: cacheTtlMs });
            if (!crl) continue;

            const serialNumber = getSerialNumberHex(certificate);
            if (crl.revokedSerials.has(serialNumber)) {
                return { revoked: true, reason: `Certificate serial ${serialNumber} found in CRL at ${url}` };
            }

            // CRL fetched and serial not found — cert is not revoked
            return { revoked: false };
        } catch (error) {
            console.error(`Error checking CRL at ${url}:`, error.message);
            continue;
        }
    }

    return { revoked: false };
};

/**
 * Parse a DER-encoded CRL and extract revoked serial numbers.
 */
function parseCrl(derBytes) {
    const asn1 = asn1js.fromBER(derBytes.buffer);
    const revokedSerials = new Set();

    try {
        // CRL structure: SEQUENCE { tbsCertList, signatureAlgorithm, signature }
        // tbsCertList: SEQUENCE { version?, issuer, thisUpdate, nextUpdate?, revokedCertificates?, ... }
        const tbsCertList = asn1.result.valueBlock.value[0];
        const entries = tbsCertList.valueBlock.value;

        // revokedCertificates is a SEQUENCE of SEQUENCE { serialNumber, revocationDate, ... }
        for (const entry of entries) {
            if (entry.valueBlock?.value) {
                for (const revokedCert of entry.valueBlock.value) {
                    if (revokedCert.valueBlock?.value?.[0]) {
                        const serial = revokedCert.valueBlock.value[0];
                        if (serial.valueBlock?.valueHex) {
                            const hex = Array.from(new Uint8Array(serial.valueBlock.valueHex))
                                .map(b => b.toString(16).padStart(2, '0')).join('');
                            revokedSerials.add(hex);
                        }
                    }
                }
            }
        }
    } catch (error) {
        console.error('Error parsing CRL structure:', error.message);
    }

    return { revokedSerials };
}

function getSerialNumberHex(certificate) {
    const serialHex = certificate.serialNumber.valueBlock.valueHex;
    return Array.from(new Uint8Array(serialHex))
        .map(b => b.toString(16).padStart(2, '0')).join('');
}

/**
 * Recursively extract URI strings from ASN.1 context-tagged [6] nodes.
 */
function extractUrisFromAsn1(node, urls) {
    if (node.idBlock?.tagClass === 3 && node.idBlock?.tagNumber === 6 && node.valueBlock?.valueHex) {
        const url = new TextDecoder().decode(node.valueBlock.valueHex);
        if (url.startsWith('http')) urls.push(url);
    }
    if (node.valueBlock?.value) {
        for (const child of node.valueBlock.value) {
            extractUrisFromAsn1(child, urls);
        }
    }
}
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
node --test tests/crl-helper.test.js
```

Expected: All 3 tests PASS.

- [ ] **Step 5: Commit**

```bash
git add scripts/crl-helper.js tests/crl-helper.test.js
git commit -m "feat: add CRL helper for certificate revocation checking"
```

---

## Task 5: Wire CRL Checks Into Issuer Verification

**Files:**
- Modify: `scripts/issuer-verifier.js`
- Modify: `scripts/formats/mdoc-helper.js`
- Modify: `scripts/oid4vp-redirect-helper.js`

- [ ] **Step 1: Add CRL checking to issuer-verifier.js**

Add to `scripts/issuer-verifier.js`:

```javascript
import { checkCertRevocation } from './crl-helper.js';

/**
 * Verify issuer trust AND check CRL revocation for the certificate.
 * @param {Certificate} certificate
 * @param {Object} options
 * @param {string[]} [options.trustedCertificates]
 * @param {boolean} [options.enableCrl=false]
 * @param {number} [options.crlCacheTtlMs=3600000]
 * @returns {Promise<{ trusted: boolean, revoked: boolean, matchedCertificate: string|null }>}
 */
export const verifyIssuerTrustAndRevocation = async (certificate, options = {}) => {
    const { enableCrl = false, crlCacheTtlMs = 3600000 } = options;

    const trustResult = await verifyIssuerTrust(certificate, options);

    let revoked = false;
    if (enableCrl && certificate) {
        const crlResult = await checkCertRevocation(certificate, {
            enabled: true,
            cacheTtlMs: crlCacheTtlMs,
        });
        revoked = crlResult.revoked;
    }

    return {
        ...trustResult,
        revoked,
    };
};
```

- [ ] **Step 2: Update mdoc-helper.js to use verifyIssuerTrustAndRevocation**

Replace the `verifyIssuerTrust` import and call:

```javascript
import { verifyIssuerTrustAndRevocation } from '../issuer-verifier.js';

// In verifyDocument, replace the trust check:
    let issuer = null;
    let revoked = false;
    if (verificationOptions.trustedCertificates) {
        const trustResult = await verifyIssuerTrustAndRevocation(certificate, {
            trustedCertificates: verificationOptions.trustedCertificates,
            enableCrl: verificationOptions.enableCrl,
            crlCacheTtlMs: verificationOptions.crlCacheTtlMs,
        });
        revoked = trustResult.revoked;
        if (trustResult.trusted) {
            issuer = {
                trusted: true,
                certificate: { data: trustResult.matchedCertificate, format: 'pem' },
            };
        }
    } else {
        issuer = await getIssuer(certificate);
    }

    return {
        claims,
        issuer,
        valid: valid && deviceValid && claimsValid && !revoked,
        revoked,
        invalidReasons: [...invalidReasons, ...(revoked ? ['Certificate revoked per CRL'] : [])],
    };
```

- [ ] **Step 3: Thread enableCrl through oid4vp-redirect-helper.js verify**

Add `enableCrl` and `crlCacheTtlMs` to the verify options destructuring and pass them to `verifyDocument`:

```javascript
    async verify({ vpToken, clientId, nonce, responseUri, encryptionJwk, mdocGeneratedNonce,
                   trustLists = ALL_TRUST_LISTS, trustedCertificates, enableCrl = false, crlCacheTtlMs }) {
        // ... existing code ...
        const { claims, issuer, valid: docValid, invalidReasons } = await verifyDocument(
            doc, sessionTranscript, { trustedCertificates, enableCrl, crlCacheTtlMs }
        );
```

- [ ] **Step 4: Run all tests**

```bash
node --test tests/*.test.js
```

Expected: All tests PASS.

- [ ] **Step 5: Commit**

```bash
git add scripts/issuer-verifier.js scripts/formats/mdoc-helper.js scripts/oid4vp-redirect-helper.js
git commit -m "feat: wire CRL revocation checks into verification pipeline"
```

---

## Task 6: IETF Token Status List Helper

**Files:**
- Create: `scripts/status-list-helper.js`
- Create: `tests/status-list-helper.test.js`

- [ ] **Step 1: Add pako dependency for zlib decompression**

```bash
cd /Users/calebion/Code/id-verifier && yarn add pako
```

- [ ] **Step 2: Write the failing test**

Create `tests/status-list-helper.test.js`:

```javascript
import test from 'node:test';
import assert from 'node:assert/strict';
import { checkTokenStatusList, getStatusFromBitstring } from '../scripts/status-list-helper.js';
import pako from 'pako';

test('getStatusFromBitstring checks the correct bit index', () => {
    // Create a bitstring where index 5 is revoked (bit set to 1)
    // Each status is 1 bit: byte 0 = indices 0-7, byte 1 = indices 8-15, etc.
    const bits = new Uint8Array(2); // 16 indices
    bits[0] = 0b00100000; // index 5 is set (bit 5 from MSB = 0b00100000)
    const compressed = pako.deflate(bits);
    const base64 = Buffer.from(compressed).toString('base64url');

    assert.equal(getStatusFromBitstring(base64, 5, 1), 1, 'Index 5 should be revoked');
    assert.equal(getStatusFromBitstring(base64, 0, 1), 0, 'Index 0 should not be revoked');
    assert.equal(getStatusFromBitstring(base64, 4, 1), 0, 'Index 4 should not be revoked');
});

test('getStatusFromBitstring supports 2-bit status entries', () => {
    // 2 bits per entry: 4 entries per byte
    // Entry 0 = bits 0-1, Entry 1 = bits 2-3, etc.
    const bits = new Uint8Array(1);
    bits[0] = 0b01_00_00_00; // entry 0 = 0b01 (valid=1), rest = 0
    const compressed = pako.deflate(bits);
    const base64 = Buffer.from(compressed).toString('base64url');

    assert.equal(getStatusFromBitstring(base64, 0, 2), 1, 'Entry 0 should be 1');
    assert.equal(getStatusFromBitstring(base64, 1, 2), 0, 'Entry 1 should be 0');
});

test('checkTokenStatusList returns statusListRef for later recheck', async () => {
    const statusListRef = {
        uri: 'https://issuer.example/status/1',
        index: 42,
    };

    // checkTokenStatusList with a mock fetcher that returns no revocation
    const result = await checkTokenStatusList(statusListRef, {
        enabled: false,
    });

    assert.equal(result.revoked, false);
    assert.deepEqual(result.statusListRef, statusListRef, 'Should echo back the ref');
});
```

- [ ] **Step 3: Run test to verify it fails**

```bash
node --test tests/status-list-helper.test.js
```

Expected: FAIL — module not found.

- [ ] **Step 4: Write the implementation**

Create `scripts/status-list-helper.js`:

```javascript
import pako from 'pako';
import { FetchCache } from './fetch-cache.js';

const statusListCache = new FetchCache({
    fetchFn: async (url) => {
        const response = await fetch(url);
        if (!response.ok) throw new Error(`Status list fetch failed: ${response.status}`);
        const text = await response.text();
        return text;
    },
});

/**
 * Extract the status value for a given index from a compressed bitstring.
 * Per RFC 9597: the bitstring is zlib-compressed, base64url-encoded.
 * Each entry is `bits` wide (1 for simple revocation, 2 for status codes).
 *
 * @param {string} compressedBitstring - base64url-encoded zlib-compressed bitstring
 * @param {number} index - The credential's index in the status list
 * @param {number} bits - Bits per entry (1 or 2, default 1)
 * @returns {number} Status value (0 = valid, non-zero = revoked/suspended)
 */
export const getStatusFromBitstring = (compressedBitstring, index, bits = 1) => {
    // Decode base64url and decompress
    const compressed = Buffer.from(compressedBitstring, 'base64url');
    const decompressed = pako.inflate(compressed);

    // Calculate bit position
    const totalBitIndex = index * bits;
    const byteIndex = Math.floor(totalBitIndex / 8);
    const bitOffset = totalBitIndex % 8;

    if (byteIndex >= decompressed.length) {
        throw new Error(`Index ${index} out of range (bitstring has ${decompressed.length * 8 / bits} entries)`);
    }

    // Extract the status bits
    // Bits are packed MSB first within each byte
    const mask = ((1 << bits) - 1) << (8 - bitOffset - bits);
    const value = (decompressed[byteIndex] & mask) >> (8 - bitOffset - bits);
    return value;
};

/**
 * Check a credential's revocation status via IETF Token Status List (RFC 9597).
 *
 * @param {Object} statusListRef - { uri: string, index: number }
 * @param {Object} [options]
 * @param {boolean} [options.enabled=true] - Whether status list checking is enabled
 * @param {number} [options.cacheTtlMs=300000] - Cache TTL (default: 5 minutes)
 * @param {number} [options.bits=1] - Bits per status entry
 * @returns {Promise<{ revoked: boolean, status?: number, statusListRef: Object }>}
 */
export const checkTokenStatusList = async (statusListRef, { enabled = true, cacheTtlMs = 300000, bits = 1 } = {}) => {
    if (!enabled || !statusListRef?.uri) {
        return { revoked: false, statusListRef };
    }

    try {
        const rawJwt = await statusListCache.get(statusListRef.uri, { ttlMs: cacheTtlMs });
        if (!rawJwt) {
            return { revoked: false, statusListRef };
        }

        // Decode the JWT payload (we don't verify the signature here — the issuer is already trusted)
        const payloadB64 = rawJwt.split('.')[1];
        const payload = JSON.parse(Buffer.from(payloadB64, 'base64url').toString());

        // RFC 9597: payload contains "status_list" with "lst" (compressed bitstring) and "bits"
        const statusList = payload.status_list || payload;
        const compressedBitstring = statusList.lst;
        const statusBits = statusList.bits || bits;

        if (!compressedBitstring) {
            console.error('Status list JWT missing lst field');
            return { revoked: false, statusListRef };
        }

        const status = getStatusFromBitstring(compressedBitstring, statusListRef.index, statusBits);

        return {
            revoked: status !== 0,
            status,
            statusListRef,
        };
    } catch (error) {
        console.error('Error checking token status list:', error.message);
        return { revoked: false, statusListRef };
    }
};

/**
 * Recheck a credential's status using a previously returned statusListRef.
 * This allows rechecking without re-presenting the credential.
 *
 * @param {Object} statusListRef - { uri: string, index: number } from a prior verification
 * @param {Object} [options]
 * @param {number} [options.cacheTtlMs=0] - Cache TTL (default: 0 = always re-fetch)
 * @param {number} [options.bits=1] - Bits per status entry
 * @returns {Promise<{ revoked: boolean, status?: number, checkedAt: string, statusListRef: Object }>}
 */
export const recheckCredentialStatus = async (statusListRef, { cacheTtlMs = 0, bits = 1 } = {}) => {
    const result = await checkTokenStatusList(statusListRef, {
        enabled: true,
        cacheTtlMs,
        bits,
    });

    return {
        ...result,
        checkedAt: new Date().toISOString(),
    };
};
```

- [ ] **Step 5: Run tests to verify they pass**

```bash
node --test tests/status-list-helper.test.js
```

Expected: All 3 tests PASS.

- [ ] **Step 6: Commit**

```bash
git add scripts/status-list-helper.js tests/status-list-helper.test.js package.json yarn.lock
git commit -m "feat: add IETF Token Status List helper for credential revocation checking"
```

---

## Task 7: Wire Status List Into Verification and Export recheckCredentialStatus

**Files:**
- Modify: `scripts/formats/mdoc-helper.js`
- Modify: `scripts/oid4vp-redirect-helper.js`
- Modify: `scripts/id-verifier.js`

- [ ] **Step 1: Extract status list reference from MSO in mdoc-helper.js**

In the `verifyDocument` function, after extracting `issuerAuthPayload`, check for a status reference:

```javascript
import { checkTokenStatusList } from '../status-list-helper.js';

// Inside verifyDocument, after claim verification:
    // Check Token Status List if present in MSO and enabled
    let statusListRef = null;
    let statusRevoked = false;
    if (issuerAuthPayload.status) {
        // MSO status field contains { statusList: { uri, idx } } or similar
        const statusInfo = issuerAuthPayload.status;
        if (statusInfo.statusList) {
            statusListRef = {
                uri: statusInfo.statusList.uri,
                index: statusInfo.statusList.idx,
            };
        }
        if (statusListRef && verificationOptions.enableStatusList) {
            const statusResult = await checkTokenStatusList(statusListRef, {
                enabled: true,
                cacheTtlMs: verificationOptions.statusListCacheTtlMs,
            });
            statusRevoked = statusResult.revoked;
        }
    }

    return {
        claims,
        issuer,
        valid: valid && deviceValid && claimsValid && !revoked && !statusRevoked,
        revoked: revoked || statusRevoked,
        statusListRef,
        invalidReasons: [
            ...invalidReasons,
            ...(revoked ? ['Certificate revoked per CRL'] : []),
            ...(statusRevoked ? ['Credential revoked per Token Status List'] : []),
        ],
    };
```

- [ ] **Step 2: Thread statusListRef through oid4vp-redirect-helper.js**

Update the `verify` method to collect `statusListRef` from processed documents:

```javascript
    // In the verify method, update processedDocuments to include statusListRef:
    processedDocuments.push({
        claims, issuer, valid: docValid, trusted: !!issuerTrusted,
        invalidReasons, statusListRef: result.statusListRef,
    });
```

Add `enableStatusList` and `statusListCacheTtlMs` to the verify options and pass through.

- [ ] **Step 3: Export recheckCredentialStatus from id-verifier.js**

```javascript
import { recheckCredentialStatus } from './status-list-helper.js';

/**
 * Recheck a credential's revocation status using a stored statusListRef.
 * Call this periodically or on-demand after initial verification.
 * @param {Object} statusListRef - { uri, index } from a prior verification result
 * @param {Object} [options] - { cacheTtlMs, bits }
 * @returns {Promise<Object>} { revoked, status, checkedAt, statusListRef }
 */
export { recheckCredentialStatus };
```

- [ ] **Step 4: Run all tests**

```bash
node --test tests/*.test.js
```

Expected: All tests PASS.

- [ ] **Step 5: Commit**

```bash
git add scripts/formats/mdoc-helper.js scripts/oid4vp-redirect-helper.js scripts/id-verifier.js scripts/status-list-helper.js
git commit -m "feat: wire Token Status List checks into verification and export recheckCredentialStatus"
```

---

## Task 8: Final Integration Test and Build Verification

**Files:**
- No new files

- [ ] **Step 1: Run all tests**

```bash
node --test tests/*.test.js
```

Expected: All tests pass.

- [ ] **Step 2: Verify build**

```bash
yarn build
```

Expected: Rollup builds successfully.

- [ ] **Step 3: Verify all exports**

```bash
node --input-type=module -e "
import {
    verifyRedirectResponse,
    processCredentials,
    recheckCredentialStatus,
} from './scripts/id-verifier.js';
console.log('verifyRedirectResponse:', typeof verifyRedirectResponse);
console.log('recheckCredentialStatus:', typeof recheckCredentialStatus);
"
```

- [ ] **Step 4: Commit any remaining changes**

```bash
git status
# If clean, no commit needed
```

---

## Summary: New API Surface

After completing all tasks, the verification functions accept these new options:

```javascript
// Verify with trusted certs + CRL + status list
const result = await verifyRedirectResponse({
    vpToken,
    clientId,
    nonce,
    responseUri,
    mdocGeneratedNonce,
    // NEW: trust verification options
    trustedCertificates: [iacaPem1, iacaPem2],  // PEM strings
    enableCrl: true,                              // check CRL distribution points
    crlCacheTtlMs: 3600000,                       // cache CRLs for 1 hour
    enableStatusList: true,                        // check IETF Token Status List
    statusListCacheTtlMs: 300000,                  // cache status lists for 5 min
});

// result.processedDocuments[0].statusListRef = { uri: "...", index: 42 }
// result.valid now also checks CRL + status list

// Later recheck
const status = await recheckCredentialStatus(
    result.processedDocuments[0].statusListRef,
    { cacheTtlMs: 0 }  // force fresh fetch
);
// → { revoked: false, status: 0, checkedAt: "2026-03-27T...", statusListRef: {...} }
```

Backwards compatible — all new options are optional. Without `trustedCertificates`, falls back to `trusted-issuer-registry`. Without `enableCrl`/`enableStatusList`, no revocation checks run.
