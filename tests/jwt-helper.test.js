import test from 'node:test';
import assert from 'node:assert/strict';
import * as jose from 'jose';
import { signRequestObject, decryptJweResponse } from '../scripts/jwt-helper.js';

async function generateTestSigningMaterial() {
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
    return { privateKey, base64Cert, keyPair };
}

test('signRequestObject creates valid JWT with x5c header', async () => {
    const { privateKey, base64Cert, keyPair } = await generateTestSigningMaterial();
    const x5cChain = [base64Cert];

    const payload = {
        client_id: 'https://verifier.example.com',
        nonce: 'test-nonce-123',
        response_uri: 'https://verifier.example.com/response',
        response_mode: 'direct_post.jwt',
        dcql_query: { credentials: [] },
    };

    const jwt = await signRequestObject(payload, privateKey, x5cChain);

    // Must be a 3-part JWT
    const parts = jwt.split('.');
    assert.equal(parts.length, 3, 'JWT must have 3 parts');

    // Verify the JWT using the public key
    const publicKey = await crypto.subtle.exportKey('jwk', keyPair.publicKey);
    const verifyKey = await jose.importJWK({ ...publicKey, key_ops: ['verify'] }, 'ES256');
    const { payload: decoded, protectedHeader } = await jose.jwtVerify(jwt, verifyKey);

    // Check claims
    assert.equal(decoded.client_id, payload.client_id);
    assert.equal(decoded.nonce, payload.nonce);
    assert.equal(decoded.response_mode, payload.response_mode);

    // Check header
    assert.deepEqual(protectedHeader.x5c, x5cChain, 'x5c header must be present');
    assert.equal(protectedHeader.alg, 'ES256');
    // typ defaults to undefined when not passed via options
});

test('signRequestObject includes wallet_nonce when provided', async () => {
    const { privateKey, base64Cert, keyPair } = await generateTestSigningMaterial();
    const x5cChain = [base64Cert];

    const payload = {
        client_id: 'https://verifier.example.com',
        nonce: 'test-nonce-456',
        response_uri: 'https://verifier.example.com/response',
        response_mode: 'direct_post.jwt',
        wallet_nonce: 'wallet-nonce-abc',
    };

    const jwt = await signRequestObject(payload, privateKey, x5cChain);

    const publicKey = await crypto.subtle.exportKey('jwk', keyPair.publicKey);
    const verifyKey = await jose.importJWK({ ...publicKey, key_ops: ['verify'] }, 'ES256');
    const { payload: decoded } = await jose.jwtVerify(jwt, verifyKey);

    assert.equal(decoded.wallet_nonce, 'wallet-nonce-abc', 'wallet_nonce must appear in decoded JWT');
});

test('decryptJweResponse decrypts ECDH-ES + A256GCM', async () => {
    // Generate a P-256 ECDH key pair
    const ecdhKeyPair = await crypto.subtle.generateKey(
        { name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveKey', 'deriveBits']
    );
    const publicJwk = await crypto.subtle.exportKey('jwk', ecdhKeyPair.publicKey);
    const privateJwk = await crypto.subtle.exportKey('jwk', ecdhKeyPair.privateKey);

    const originalPayload = { vp_token: 'test-token', state: 'abc123' };
    const plaintext = JSON.stringify(originalPayload);

    // Encrypt using jose
    const recipientPublicKey = await jose.importJWK(publicJwk, 'ECDH-ES');
    const jwe = await new jose.CompactEncrypt(new TextEncoder().encode(plaintext))
        .setProtectedHeader({ alg: 'ECDH-ES', enc: 'A256GCM' })
        .encrypt(recipientPublicKey);

    // Decrypt using our helper
    const decoded = await decryptJweResponse(jwe, privateJwk);

    assert.deepEqual(decoded, originalPayload);
});

test('decryptJweResponse also handles A128GCM', async () => {
    // Generate a P-256 ECDH key pair
    const ecdhKeyPair = await crypto.subtle.generateKey(
        { name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveKey', 'deriveBits']
    );
    const publicJwk = await crypto.subtle.exportKey('jwk', ecdhKeyPair.publicKey);
    const privateJwk = await crypto.subtle.exportKey('jwk', ecdhKeyPair.privateKey);

    const originalPayload = { vp_token: 'another-token', presentation_submission: { id: 'ps1' } };
    const plaintext = JSON.stringify(originalPayload);

    // Encrypt using jose with A128GCM
    const recipientPublicKey = await jose.importJWK(publicJwk, 'ECDH-ES');
    const jwe = await new jose.CompactEncrypt(new TextEncoder().encode(plaintext))
        .setProtectedHeader({ alg: 'ECDH-ES', enc: 'A128GCM' })
        .encrypt(recipientPublicKey);

    // Decrypt using our helper
    const decoded = await decryptJweResponse(jwe, privateJwk);

    assert.deepEqual(decoded, originalPayload);
});
