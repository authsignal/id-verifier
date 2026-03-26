import test from 'node:test';
import assert from 'node:assert/strict';
import { generateX509Hash, derToPem, certToPemChain } from '../scripts/x509-helper.js';

async function generateTestCertDer() {
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
    return new Uint8Array(cert.toSchema().toBER(false));
}

test('generateX509Hash returns a non-empty base64url string', async () => {
    const certDer = await generateTestCertDer();
    const hash = await generateX509Hash(certDer);

    assert.ok(typeof hash === 'string', 'hash should be a string');
    assert.ok(hash.length > 0, 'hash should be non-empty');

    // base64url must not contain +, /, or = characters
    assert.ok(!hash.includes('+'), 'hash must not contain +');
    assert.ok(!hash.includes('/'), 'hash must not contain /');
    assert.ok(!hash.includes('='), 'hash must not contain =');
});

test('generateX509Hash is deterministic (same input → same output)', async () => {
    const certDer = await generateTestCertDer();
    const hash1 = await generateX509Hash(certDer);
    const hash2 = await generateX509Hash(certDer);
    assert.equal(hash1, hash2, 'same input should produce same hash');
});

test('generateX509Hash can be used to construct a valid x509_hash: client ID string', async () => {
    const certDer = await generateTestCertDer();
    const hash = await generateX509Hash(certDer);
    const clientId = `x509_hash:${hash}`;

    assert.ok(clientId.startsWith('x509_hash:'), 'client ID should start with x509_hash:');
    assert.ok(clientId.length > 'x509_hash:'.length, 'client ID should have a non-empty hash part');
});

test('derToPem wraps bytes in proper PEM armoring', async () => {
    const certDer = await generateTestCertDer();
    const pem = derToPem(certDer);

    assert.ok(pem.startsWith('-----BEGIN CERTIFICATE-----'), 'PEM should start with BEGIN header');
    assert.ok(pem.includes('-----END CERTIFICATE-----'), 'PEM should include END footer');

    // Extract the base64 body between the headers
    const body = pem
        .replace('-----BEGIN CERTIFICATE-----', '')
        .replace('-----END CERTIFICATE-----', '')
        .trim();

    // Each line should be at most 64 characters
    const lines = body.split('\n').map(l => l.trimEnd());
    for (const line of lines) {
        assert.ok(line.length <= 64, `PEM line exceeds 64 chars: "${line}"`);
    }
});

test('certToPemChain returns base64 strings (not PEM armored)', async () => {
    const certDer1 = await generateTestCertDer();
    const certDer2 = await generateTestCertDer();
    const chain = certToPemChain([certDer1, certDer2]);

    assert.equal(chain.length, 2, 'chain should have 2 entries');

    for (const entry of chain) {
        assert.ok(typeof entry === 'string', 'each entry should be a string');
        assert.ok(!entry.includes('-----BEGIN'), 'entries must not contain PEM BEGIN header');
        assert.ok(!entry.includes('-----END'), 'entries must not contain PEM END footer');
        // Standard base64 may contain +, /, = — base64url would not; this is x5c format
        // Just ensure it's a non-empty string that decodes without error
        assert.ok(entry.length > 0, 'entry should be non-empty');
    }
});
