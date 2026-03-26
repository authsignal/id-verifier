import test from 'node:test';
import assert from 'node:assert/strict';
import * as cbor2 from 'cbor2';
import oid4vpRedirectHelper from '../scripts/oid4vp-redirect-helper.js';
import openid4vpProtocolHelper from '../scripts/openid-4vp-protocol-helper.js';

// Test 1: SessionTranscript produces correct structure
test('_generateSessionTranscript produces [null, null, ["OpenID4VPHandover", <32-byte-hash>]]', async () => {
    const clientId = 'https://verifier.example.com';
    const nonce = 'test-nonce-abc123';
    const responseUri = 'https://verifier.example.com/response';
    const jwkThumbprint = null;

    const sessionTranscriptBytes = await oid4vpRedirectHelper._generateSessionTranscript(clientId, nonce, jwkThumbprint, responseUri);

    assert.ok(sessionTranscriptBytes instanceof Uint8Array, 'should return Uint8Array');

    const decoded = cbor2.decode(sessionTranscriptBytes);
    assert.ok(Array.isArray(decoded), 'decoded should be an array');
    assert.equal(decoded.length, 3, 'array should have 3 elements');
    assert.equal(decoded[0], null, 'first element should be null');
    assert.equal(decoded[1], null, 'second element should be null');

    const handover = decoded[2];
    assert.ok(Array.isArray(handover), 'handover should be an array');
    assert.equal(handover.length, 2, 'handover should have 2 elements');
    assert.equal(handover[0], 'OpenID4VPHandover', 'handover label should be "OpenID4VPHandover"');

    const hash = handover[1];
    assert.ok(hash instanceof Uint8Array, 'handover hash should be Uint8Array');
    assert.equal(hash.length, 32, 'handover hash should be 32 bytes (SHA-256)');
});

// Test 2: SessionTranscript is deterministic
test('_generateSessionTranscript is deterministic: same inputs produce identical bytes', async () => {
    const clientId = 'https://verifier.example.com';
    const nonce = 'deterministic-nonce';
    const responseUri = 'https://verifier.example.com/cb';
    const jwkThumbprint = new Uint8Array(32).fill(0xAB);

    const result1 = await oid4vpRedirectHelper._generateSessionTranscript(clientId, nonce, jwkThumbprint, responseUri);
    const result2 = await oid4vpRedirectHelper._generateSessionTranscript(clientId, nonce, jwkThumbprint, responseUri);

    assert.deepEqual(result1, result2, 'same inputs should produce identical bytes');
});

// Test 3: SessionTranscript with jwkThumbprint differs from without
test('_generateSessionTranscript with jwkThumbprint differs from without', async () => {
    const clientId = 'https://verifier.example.com';
    const nonce = 'nonce-xyz';
    const responseUri = 'https://verifier.example.com/response';
    const jwkThumbprint = new Uint8Array(32).fill(0x55);

    const withThumbprint = await oid4vpRedirectHelper._generateSessionTranscript(clientId, nonce, jwkThumbprint, responseUri);
    const withoutThumbprint = await oid4vpRedirectHelper._generateSessionTranscript(clientId, nonce, null, responseUri);

    assert.notDeepEqual(withThumbprint, withoutThumbprint, 'results should differ when jwkThumbprint changes');
});

// Test 4: SessionTranscript differs from DC API handover
test('_generateSessionTranscript differs from DC API (OpenID4VPDCAPIHandover)', async () => {
    const origin = 'https://example.com';
    const nonce = 'shared-nonce';
    const jwkThumbprint = new Uint8Array(32).fill(0x42);

    // DC API uses (origin, nonce, jwkThumbprint)
    const dcApiTranscript = await openid4vpProtocolHelper._generateSessionTranscript(origin, nonce, jwkThumbprint);

    // Redirect uses (clientId, nonce, jwkThumbprint, responseUri)
    const redirectTranscript = await oid4vpRedirectHelper._generateSessionTranscript(
        origin,
        nonce,
        jwkThumbprint,
        'https://example.com/response'
    );

    assert.notDeepEqual(dcApiTranscript, redirectTranscript, 'redirect handover should differ from DC API handover');

    // Also verify the handover labels differ
    const dcDecoded = cbor2.decode(dcApiTranscript);
    const redirectDecoded = cbor2.decode(redirectTranscript);
    assert.equal(dcDecoded[2][0], 'OpenID4VPDCAPIHandover', 'DC API label should be OpenID4VPDCAPIHandover');
    assert.equal(redirectDecoded[2][0], 'OpenID4VPHandover', 'Redirect label should be OpenID4VPHandover');
});

// Test 5: Auth URL uses default scheme openid4vp://
test('createAuthorizationRequestUrl uses default scheme openid4vp://', () => {
    const url = oid4vpRedirectHelper.createAuthorizationRequestUrl({
        clientId: 'https://verifier.example.com',
        requestUri: 'https://verifier.example.com/request/abc123',
    });

    assert.ok(url.startsWith('openid4vp://'), 'URL should start with openid4vp://');
    assert.ok(url.includes('client_id='), 'URL should include client_id');
    assert.ok(url.includes('request_uri='), 'URL should include request_uri');
    assert.ok(url.includes(encodeURIComponent('https://verifier.example.com')), 'URL should include encoded clientId');
    assert.ok(url.includes(encodeURIComponent('https://verifier.example.com/request/abc123')), 'URL should include encoded requestUri');
});

// Test 6: Auth URL supports custom schemes
test('createAuthorizationRequestUrl supports custom wallet schemes', () => {
    const mdocUrl = oid4vpRedirectHelper.createAuthorizationRequestUrl({
        clientId: 'https://verifier.example.com',
        requestUri: 'https://verifier.example.com/request/xyz',
        walletScheme: 'mdoc-openid4vp://',
    });
    assert.ok(mdocUrl.startsWith('mdoc-openid4vp://'), 'should support mdoc-openid4vp:// scheme');

    const customUrl = oid4vpRedirectHelper.createAuthorizationRequestUrl({
        clientId: 'https://verifier.example.com',
        requestUri: 'https://verifier.example.com/request/xyz',
        walletScheme: 'com.example.wallet://',
    });
    assert.ok(customUrl.startsWith('com.example.wallet://'), 'should support custom wallet scheme');
});

// Test 7: Auth URL includes request_uri_method=post when specified
test('createAuthorizationRequestUrl includes request_uri_method when specified', () => {
    const urlWithMethod = oid4vpRedirectHelper.createAuthorizationRequestUrl({
        clientId: 'https://verifier.example.com',
        requestUri: 'https://verifier.example.com/request/abc',
        requestUriMethod: 'post',
    });
    assert.ok(urlWithMethod.includes('request_uri_method=post'), 'URL should include request_uri_method=post');

    const urlWithoutMethod = oid4vpRedirectHelper.createAuthorizationRequestUrl({
        clientId: 'https://verifier.example.com',
        requestUri: 'https://verifier.example.com/request/abc',
    });
    assert.ok(!urlWithoutMethod.includes('request_uri_method'), 'URL without requestUriMethod should not include request_uri_method');
});

// Test 8: JWK thumbprint returns 32-byte Uint8Array and is deterministic
test('computeJwkThumbprint returns 32-byte Uint8Array and is deterministic', async () => {
    const ecJwk = {
        kty: 'EC',
        crv: 'P-256',
        x: 'f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU',
        y: 'x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0',
    };

    const result1 = await oid4vpRedirectHelper.computeJwkThumbprint(ecJwk);
    const result2 = await oid4vpRedirectHelper.computeJwkThumbprint(ecJwk);

    assert.ok(result1 instanceof Uint8Array, 'should return Uint8Array');
    assert.equal(result1.length, 32, 'should return 32 bytes');
    assert.deepEqual(result1, result2, 'should be deterministic');

    // Test RSA thumbprint
    const rsaJwk = {
        kty: 'RSA',
        n: 'sAPRqXau14mLJeK5RDL5jAMCwQfKwqUE6M0sQKQ0siU',
        e: 'AQAB',
    };
    const rsaResult = await oid4vpRedirectHelper.computeJwkThumbprint(rsaJwk);
    assert.ok(rsaResult instanceof Uint8Array, 'RSA result should be Uint8Array');
    assert.equal(rsaResult.length, 32, 'RSA result should be 32 bytes');

    // Test OKP thumbprint
    const okpJwk = {
        kty: 'OKP',
        crv: 'Ed25519',
        x: 'H3C2AVvLMv6gmMNam3uVAjZpfOC2l11OgEP6KqbJjc4',
    };
    const okpResult = await oid4vpRedirectHelper.computeJwkThumbprint(okpJwk);
    assert.ok(okpResult instanceof Uint8Array, 'OKP result should be Uint8Array');
    assert.equal(okpResult.length, 32, 'OKP result should be 32 bytes');
});
