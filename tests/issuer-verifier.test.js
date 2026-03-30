import test from 'node:test';
import assert from 'node:assert/strict';
import { verifyIssuerTrust } from '../scripts/issuer-verifier.js';

async function generateCertChain() {
    const { Certificate, Extension, BasicConstraints } = await import('pkijs');
    const asn1js = await import('asn1js');

    // Generate CA key pair
    const caKeyPair = await crypto.subtle.generateKey(
        { name: 'ECDSA', namedCurve: 'P-256' },
        true,
        ['sign', 'verify']
    );

    // Create self-signed CA cert
    const caCert = new Certificate();
    caCert.version = 2;
    caCert.serialNumber = new asn1js.Integer({ value: 1 });
    caCert.notBefore.value = new Date();
    caCert.notAfter.value = new Date(Date.now() + 365 * 24 * 60 * 60 * 1000);

    caCert.subject.typesAndValues.push(
        new (await import('pkijs')).AttributeTypeAndValue({
            type: '2.5.4.3',
            value: new asn1js.Utf8String({ value: 'Test CA' }),
        })
    );
    caCert.issuer.typesAndValues.push(
        new (await import('pkijs')).AttributeTypeAndValue({
            type: '2.5.4.3',
            value: new asn1js.Utf8String({ value: 'Test CA' }),
        })
    );

    await caCert.subjectPublicKeyInfo.importKey(caKeyPair.publicKey);

    const basicConstraints = new BasicConstraints({ cA: true });
    caCert.extensions = [
        new Extension({
            extnID: '2.5.29.19',
            critical: true,
            extnValue: basicConstraints.toSchema().toBER(false),
        }),
    ];

    await caCert.sign(caKeyPair.privateKey, 'SHA-256');

    // Convert CA cert to PEM
    const { certificateToPem } = await import('../scripts/certificate-helper.js');
    const caPem = certificateToPem(caCert);

    // Generate leaf key pair
    const leafKeyPair = await crypto.subtle.generateKey(
        { name: 'ECDSA', namedCurve: 'P-256' },
        true,
        ['sign', 'verify']
    );

    // Create leaf cert signed by CA
    const leafCert = new Certificate();
    leafCert.version = 2;
    leafCert.serialNumber = new asn1js.Integer({ value: 2 });
    leafCert.notBefore.value = new Date();
    leafCert.notAfter.value = new Date(Date.now() + 365 * 24 * 60 * 60 * 1000);

    leafCert.subject.typesAndValues.push(
        new (await import('pkijs')).AttributeTypeAndValue({
            type: '2.5.4.3',
            value: new asn1js.Utf8String({ value: 'Test Leaf' }),
        })
    );

    // Set issuer to CA's subject
    leafCert.issuer = caCert.subject;

    await leafCert.subjectPublicKeyInfo.importKey(leafKeyPair.publicKey);
    await leafCert.sign(caKeyPair.privateKey, 'SHA-256');

    return { caCert, caPem, leafCert, caKeyPair, leafKeyPair };
}

test('verifyIssuerTrust validates leaf cert against trusted CA PEM', async () => {
    const { leafCert, caPem } = await generateCertChain();
    const result = await verifyIssuerTrust(leafCert, { trustedCertificates: [caPem] });
    assert.equal(result.trusted, true);
    assert.equal(result.matchedCertificate, caPem);
});

test('verifyIssuerTrust rejects leaf cert not signed by any trusted CA', async () => {
    const { leafCert } = await generateCertChain();
    // Generate a completely different CA
    const { caPem: otherCaPem } = await generateCertChain();
    const result = await verifyIssuerTrust(leafCert, { trustedCertificates: [otherCaPem] });
    assert.equal(result.trusted, false);
    assert.equal(result.matchedCertificate, null);
});

test('verifyIssuerTrust returns not trusted when no trustedCertificates provided', async () => {
    const { leafCert } = await generateCertChain();
    const result = await verifyIssuerTrust(leafCert, {});
    assert.equal(result.trusted, false);
    assert.equal(result.matchedCertificate, null);
});

test('verifyIssuerTrust handles multiple trusted CAs (correct one is second in array)', async () => {
    const { leafCert, caPem } = await generateCertChain();
    const { caPem: otherCaPem } = await generateCertChain();
    const result = await verifyIssuerTrust(leafCert, { trustedCertificates: [otherCaPem, caPem] });
    assert.equal(result.trusted, true);
    assert.equal(result.matchedCertificate, caPem);
});
