import test from 'node:test';
import assert from 'node:assert/strict';
import * as cbor2 from 'cbor2';
import * as jose from 'jose';
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

// Helper for creating test signing material
async function createTestSigningMaterial() {
    const keyPair = await crypto.subtle.generateKey(
        { name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']
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

// Test 9: createRequestObject creates a signed JWT with correct structure
test('createRequestObject creates a signed JWT with correct structure', async () => {
    const { privateKey, publicKey, x5cChain } = await createTestSigningMaterial();

    const clientId = 'https://verifier.example.com';
    const nonce = 'test-nonce-123';
    const state = 'test-state-456';
    const responseUri = 'https://verifier.example.com/response';
    const documentTypes = ['org.iso.18013.5.1.mDL'];
    const claims = ['given_name', 'family_name'];

    const jwt = await oid4vpRedirectHelper.createRequestObject({
        clientId,
        nonce,
        state,
        responseUri,
        documentTypes,
        claims,
        privateKey,
        x5cChain,
    });

    assert.ok(typeof jwt === 'string', 'should return a string JWT');

    // Verify the JWT using the public key
    const publicKeyJwk = await crypto.subtle.exportKey('jwk', publicKey);
    const josePublicKey = await jose.importJWK(publicKeyJwk, 'ES256');
    const { payload, protectedHeader } = await jose.jwtVerify(jwt, josePublicKey, {
        typ: 'oauth-authz-req+jwt',
    });

    // Check header
    assert.equal(protectedHeader.typ, 'oauth-authz-req+jwt', 'header typ should be oauth-authz-req+jwt');
    assert.ok(Array.isArray(protectedHeader.x5c), 'header should have x5c array');
    assert.equal(protectedHeader.x5c.length, 1, 'x5c should have one cert');

    // Check payload claims
    assert.equal(payload.client_id, clientId, 'payload should have client_id');
    assert.equal(payload.nonce, nonce, 'payload should have nonce');
    assert.equal(payload.state, state, 'payload should have state');
    assert.equal(payload.response_uri, responseUri, 'payload should have response_uri');
    assert.equal(payload.response_type, 'vp_token', 'payload should have response_type=vp_token');
    assert.equal(payload.response_mode, 'direct_post.jwt', 'payload should have response_mode=direct_post.jwt');

    // Check dcql_query
    assert.ok(payload.dcql_query, 'payload should have dcql_query');
    assert.ok(Array.isArray(payload.dcql_query.credentials), 'dcql_query should have credentials array');
    assert.equal(payload.dcql_query.credentials.length, 1, 'should have one credential query');

    const cred = payload.dcql_query.credentials[0];
    assert.equal(cred.id, 'cred-mso_mdoc-org_iso_18013_5_1_mDL', 'credential id should match');
    assert.equal(cred.format, 'mso_mdoc', 'credential format should be mso_mdoc');
    assert.equal(cred.meta.doctype_value, 'org.iso.18013.5.1.mDL', 'meta should have doctype_value');
    assert.ok(Array.isArray(cred.claims), 'cred should have claims array');
    assert.equal(cred.claims.length, 2, 'should have 2 claims');
    assert.deepEqual(cred.claims[0], { path: 'given_name' }, 'first claim should be given_name');
    assert.deepEqual(cred.claims[1], { path: 'family_name' }, 'second claim should be family_name');
});

// Test 10: createRequestObject includes client_metadata with encryption key when encryptionJwk provided
test('createRequestObject includes client_metadata with encryption key when encryptionJwk provided', async () => {
    const { privateKey, publicKey, x5cChain } = await createTestSigningMaterial();

    // Generate an encryption key pair
    const encKeyPair = await crypto.subtle.generateKey(
        { name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveKey']
    );
    const encPublicJwk = await crypto.subtle.exportKey('jwk', encKeyPair.publicKey);
    const encPrivateJwk = await crypto.subtle.exportKey('jwk', encKeyPair.privateKey);
    const encryptionJwk = encPrivateJwk; // pass the private JWK as encryptionJwk

    const jwt = await oid4vpRedirectHelper.createRequestObject({
        clientId: 'https://verifier.example.com',
        nonce: 'nonce-enc',
        state: 'state-enc',
        responseUri: 'https://verifier.example.com/response',
        documentTypes: ['org.iso.18013.5.1.mDL'],
        claims: ['age_over_18'],
        privateKey,
        x5cChain,
        encryptionJwk,
    });

    const publicKeyJwk = await crypto.subtle.exportKey('jwk', publicKey);
    const josePublicKey = await jose.importJWK(publicKeyJwk, 'ES256');
    const { payload } = await jose.jwtVerify(jwt, josePublicKey, {
        typ: 'oauth-authz-req+jwt',
    });

    assert.ok(payload.client_metadata, 'payload should have client_metadata');
    assert.deepEqual(
        payload.client_metadata.encrypted_response_alg_values_supported,
        ['ECDH-ES'],
        'should include ECDH-ES alg'
    );
    assert.deepEqual(
        payload.client_metadata.encrypted_response_enc_values_supported,
        ['A256GCM', 'A128GCM'],
        'should include enc values'
    );
    assert.ok(payload.client_metadata.jwks, 'client_metadata should have jwks');
    assert.ok(Array.isArray(payload.client_metadata.jwks.keys), 'jwks should have keys array');
    assert.equal(payload.client_metadata.jwks.keys.length, 1, 'should have one key in jwks');
    assert.equal(payload.client_metadata.jwks.keys[0].use, 'enc', 'key use should be enc');
    assert.equal(payload.client_metadata.jwks.keys[0].kid, 'ephemeral-enc-key', 'key kid should be ephemeral-enc-key');
});

// Test 11: processDirectPostResponse decrypts JWE response and extracts vp_token and state
test('processDirectPostResponse decrypts JWE response and extracts vp_token and state', async () => {
    // Generate P-256 ECDH key pair for the verifier's encryption key
    const encKeyPair = await crypto.subtle.generateKey(
        { name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveKey', 'deriveBits']
    );
    const encPrivateJwk = await crypto.subtle.exportKey('jwk', encKeyPair.privateKey);
    const encPublicJwk = await crypto.subtle.exportKey('jwk', encKeyPair.publicKey);

    const vpTokenPayload = { 'cred-mso_mdoc-org_iso_18013_5_1_mDL': ['base64data'] };
    const testState = 'test-state';
    const plaintext = JSON.stringify({ vp_token: vpTokenPayload, state: testState });

    // Encrypt using ECDH-ES + A256GCM using the verifier's public key
    const recipientPublicKey = await jose.importJWK(encPublicJwk, 'ECDH-ES');
    const jwe = await new jose.CompactEncrypt(new TextEncoder().encode(plaintext))
        .setProtectedHeader({ alg: 'ECDH-ES', enc: 'A256GCM' })
        .encrypt(recipientPublicKey);

    const result = await oid4vpRedirectHelper.processDirectPostResponse({
        responseBody: { response: jwe },
        encryptionJwk: encPrivateJwk,
    });

    assert.ok(result, 'should return a result');
    assert.deepEqual(result.vpToken, vpTokenPayload, 'vpToken should match the original payload');
    assert.equal(result.state, testState, 'state should match');
});

// Test 12: processDirectPostResponse handles unencrypted direct_post
test('processDirectPostResponse handles unencrypted direct_post', async () => {
    const vpTokenPayload = { 'cred-mso_mdoc-org_iso_18013_5_1_mDL': ['base64data'] };
    const responseBody = {
        vp_token: JSON.stringify(vpTokenPayload),
        state: 'plain-state',
    };

    const result = await oid4vpRedirectHelper.processDirectPostResponse({
        responseBody,
    });

    assert.ok(result, 'should return a result');
    assert.deepEqual(result.vpToken, vpTokenPayload, 'vpToken should be parsed from JSON string');
    assert.equal(result.state, 'plain-state', 'state should match');
});
