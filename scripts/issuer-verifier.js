import * as asn1js from 'asn1js';
import { parsePemCertificate } from './certificate-helper.js';
import { checkCertRevocation } from './crl-helper.js';

/**
 * Convert a DER-encoded ECDSA signature (SEQUENCE { INTEGER r, INTEGER s }) to
 * the raw r||s format expected by Web Crypto.
 *
 * @param {ArrayBuffer} derSig - DER-encoded ECDSA signature bytes
 * @param {string} curve - 'P-256' or 'P-384'
 * @returns {Uint8Array} - Raw r||s signature bytes
 */
const derEcdsaSignatureToRaw = (derSig, curve) => {
    const componentLength = curve === 'P-384' ? 48 : 32;

    // Parse the outer SEQUENCE
    const asn1 = asn1js.fromBER(derSig);
    const sequence = asn1.result;
    const [rInteger, sInteger] = sequence.valueBlock.value;

    const extractInteger = (integerBlock) => {
        // valueBlock.valueHex is an ArrayBuffer
        let bytes = new Uint8Array(integerBlock.valueBlock.valueHex);
        // Strip leading zero byte(s) that DER adds to indicate positive sign
        let start = 0;
        while (start < bytes.length - 1 && bytes[start] === 0x00) {
            start++;
        }
        bytes = bytes.slice(start);
        // Pad to component length
        const padded = new Uint8Array(componentLength);
        padded.set(bytes, componentLength - bytes.length);
        return padded;
    };

    const r = extractInteger(rInteger);
    const s = extractInteger(sInteger);

    const raw = new Uint8Array(componentLength * 2);
    raw.set(r, 0);
    raw.set(s, componentLength);
    return raw;
};

/**
 * Determine the Web Crypto algorithm parameters from an SPKI public key.
 *
 * @param {ArrayBuffer} spkiBytes - SPKI-encoded public key bytes
 * @returns {{ name: string, namedCurve?: string, hash: string }} - Web Crypto algorithm params
 */
const algorithmFromSpki = (spkiBytes) => {
    const asn1 = asn1js.fromBER(spkiBytes);
    // SPKI structure: SEQUENCE { SEQUENCE { OID, params }, BIT STRING }
    const algorithmSequence = asn1.result.valueBlock.value[0];
    const oidBlock = algorithmSequence.valueBlock.value[0];
    const oid = oidBlock.valueBlock.toString();

    if (oid === '1.2.840.10045.2.1') {
        // EC key — check curve OID from params
        const curveOidBlock = algorithmSequence.valueBlock.value[1];
        const curveOid = curveOidBlock.valueBlock.toString();
        // P-256: 1.2.840.10045.3.1.7
        // P-384: 1.3.132.0.34
        const namedCurve = curveOid === '1.3.132.0.34' ? 'P-384' : 'P-256';
        const hash = namedCurve === 'P-384' ? 'SHA-384' : 'SHA-256';
        return { name: 'ECDSA', namedCurve, hash };
    }

    if (oid === '1.2.840.113549.1.1.1') {
        // RSA key
        return { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' };
    }

    throw new Error(`Unsupported public key algorithm OID: ${oid}`);
};

/**
 * Verify whether a leaf certificate is signed by one of the provided trusted CA PEMs.
 *
 * @param {import('pkijs').Certificate} certificate - The issuer leaf cert (pkijs Certificate)
 * @param {{ trustedCertificates?: string[] }} options
 * @returns {Promise<{ trusted: boolean, matchedCertificate: string|null }>}
 */
export const verifyIssuerTrust = async (certificate, { trustedCertificates } = {}) => {
    if (!trustedCertificates || trustedCertificates.length === 0) {
        return { trusted: false, matchedCertificate: null };
    }

    // Extract TBS bytes and signature from the leaf cert
    const tbsBytes = new Uint8Array(certificate.tbsView);
    const signatureDer = certificate.signatureValue.valueBlock.valueHex;

    for (const trustedPem of trustedCertificates) {
        try {
            const trustedCert = parsePemCertificate(trustedPem);

            // Get SPKI bytes from the trusted (issuer) cert
            const spkiBytes = trustedCert.subjectPublicKeyInfo.toSchema().toBER();

            const algParams = algorithmFromSpki(spkiBytes);

            let importAlgorithm, verifyAlgorithm, signatureBytes;

            if (algParams.name === 'ECDSA') {
                importAlgorithm = { name: 'ECDSA', namedCurve: algParams.namedCurve };
                verifyAlgorithm = { name: 'ECDSA', hash: algParams.hash };
                // Convert DER ECDSA signature to raw r||s
                signatureBytes = derEcdsaSignatureToRaw(signatureDer, algParams.namedCurve);
            } else {
                importAlgorithm = { name: 'RSASSA-PKCS1-v1_5', hash: algParams.hash };
                verifyAlgorithm = { name: 'RSASSA-PKCS1-v1_5' };
                signatureBytes = new Uint8Array(signatureDer);
            }

            const publicKey = await crypto.subtle.importKey(
                'spki',
                spkiBytes,
                importAlgorithm,
                false,
                ['verify']
            );

            const isValid = await crypto.subtle.verify(
                verifyAlgorithm,
                publicKey,
                signatureBytes,
                tbsBytes
            );

            if (isValid) {
                return { trusted: true, matchedCertificate: trustedPem };
            }
        } catch {
            // Try next trusted cert
            continue;
        }
    }

    return { trusted: false, matchedCertificate: null };
};

export const verifyIssuerTrustAndRevocation = async (certificate, options = {}) => {
    const { enableCrl = false, crlCacheTtlMs = 3600000 } = options;

    const trustResult = await verifyIssuerTrust(certificate, options);

    let revoked = false;
    let crlReason = null;
    if (enableCrl && certificate) {
        const crlResult = await checkCertRevocation(certificate, {
            enabled: true,
            cacheTtlMs: crlCacheTtlMs,
        });
        revoked = crlResult.revoked;
        crlReason = crlResult.reason;
    }

    return { ...trustResult, revoked, crlReason };
};
