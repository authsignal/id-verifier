import { bufferToBase64Url, bufferToBase64 } from './utils.js';

/**
 * Generate a base64url-encoded SHA-256 hash of a DER-encoded X.509 certificate.
 * Used for the `x509_hash` client ID prefix in OID4VP 1.0 / HAIP.
 * @param {Uint8Array} derCertBytes - DER-encoded X.509 certificate bytes
 * @returns {Promise<string>} - base64url-encoded SHA-256 hash
 */
export const generateX509Hash = async (derCertBytes) => {
    const hashBuffer = await crypto.subtle.digest('SHA-256', derCertBytes);
    return bufferToBase64Url(hashBuffer);
};

/**
 * Convert DER-encoded certificate bytes to a PEM-formatted string.
 * @param {Uint8Array} derBytes - DER-encoded certificate bytes
 * @returns {string} - PEM-formatted certificate string
 */
export const derToPem = (derBytes) => {
    const base64 = bufferToBase64(derBytes);

    // Wrap at 64 characters per line
    const lines = [];
    for (let i = 0; i < base64.length; i += 64) {
        lines.push(base64.slice(i, i + 64));
    }

    return `-----BEGIN CERTIFICATE-----\n${lines.join('\n')}\n-----END CERTIFICATE-----`;
};

/**
 * Convert an array of DER-encoded certificates to the x5c format (RFC 7515 Section 4.1.6).
 * Returns an array of base64-encoded strings (NOT PEM armored, NOT base64url).
 * @param {Uint8Array[]} derCerts - Array of DER-encoded certificate bytes
 * @returns {string[]} - Array of base64-encoded certificate strings
 */
export const certToX5cChain = (derCerts) => {
    return derCerts.map(derBytes => bufferToBase64(derBytes));
};
