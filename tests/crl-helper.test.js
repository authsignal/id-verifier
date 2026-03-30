import test from 'node:test';
import assert from 'node:assert/strict';
import { getCrlDistributionPoints, checkCertRevocation } from '../scripts/crl-helper.js';

async function generateTestCertWithCrlDp(crlUrl) {
    const { Certificate, Extension } = await import('pkijs');
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

    const urlBytes = new TextEncoder().encode(crlUrl);
    // Build the ASN.1 structure for CRL DP
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
    const crlDpSequence = new asn1js.Sequence({ value: [new asn1js.Sequence({ value: [dpName] })] });
    cert.extensions = [
        new Extension({
            extnID: '2.5.29.31',
            critical: false,
            extnValue: crlDpSequence.toBER(false),
        }),
    ];

    await cert.sign(keyPair.privateKey, 'SHA-256');
    return cert;
}

async function generateTestCertWithoutCrlDp() {
    const { Certificate } = await import('pkijs');
    const asn1js = await import('asn1js');

    const keyPair = await crypto.subtle.generateKey(
        { name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']
    );
    const cert = new Certificate();
    cert.version = 2;
    cert.serialNumber = new asn1js.Integer({ value: 2 });
    await cert.subjectPublicKeyInfo.importKey(keyPair.publicKey);
    cert.notBefore.value = new Date();
    cert.notAfter.value = new Date(Date.now() + 365 * 24 * 60 * 60 * 1000);
    await cert.sign(keyPair.privateKey, 'SHA-256');
    return cert;
}

test('getCrlDistributionPoints extracts CRL URLs from a certificate with the extension', async () => {
    const crlUrl = 'https://example.com/crl/test.crl';
    const cert = await generateTestCertWithCrlDp(crlUrl);

    const urls = getCrlDistributionPoints(cert);

    assert.ok(Array.isArray(urls), 'should return an array');
    assert.equal(urls.length, 1, 'should have exactly one URL');
    assert.equal(urls[0], crlUrl, 'should return the correct CRL URL');
});

test('getCrlDistributionPoints returns empty array for cert without CRL extension', async () => {
    const cert = await generateTestCertWithoutCrlDp();

    const urls = getCrlDistributionPoints(cert);

    assert.ok(Array.isArray(urls), 'should return an array');
    assert.equal(urls.length, 0, 'should return empty array for cert without CRL extension');
});

test('checkCertRevocation returns not-revoked when disabled', async () => {
    const cert = await generateTestCertWithoutCrlDp();

    const result = await checkCertRevocation(cert, { enabled: false });

    assert.ok(typeof result === 'object', 'should return an object');
    assert.equal(result.revoked, false, 'should return revoked: false when disabled');
});
