import { WalletScheme } from './constants.js';
import * as cbor2 from 'cbor2';

class OID4VPRedirectHelper {
    /**
     * Generates a SessionTranscript for OID4VP redirect-based flows.
     * Per OID4VP 1.0 Appendix B.2.6.1.
     *
     * @param {string} clientId
     * @param {string} nonce
     * @param {Uint8Array|null} jwkThumbprint - null if no encryption, otherwise 32-byte Uint8Array
     * @param {string} responseUri
     * @returns {Promise<Uint8Array>} CBOR-encoded SessionTranscript
     */
    async _generateSessionTranscript(clientId, nonce, jwkThumbprint, responseUri) {
        if (!clientId) throw new Error('clientId is required for generating session transcript');
        if (!nonce) throw new Error('nonce is required for generating session transcript');
        if (!responseUri) throw new Error('responseUri is required for generating session transcript');

        // OpenID4VPHandoverInfo = [clientId, nonce, jwkThumbprint, responseUri]
        const handoverInfo = [clientId, nonce, jwkThumbprint, responseUri];

        // Encode as CBOR
        const handoverInfoBytes = cbor2.encode(handoverInfo);

        // SHA-256 hash
        const hashBuffer = await crypto.subtle.digest('SHA-256', handoverInfoBytes);
        const hashArray = new Uint8Array(hashBuffer);

        // OpenID4VPHandover = ["OpenID4VPHandover", hash]
        const handover = ['OpenID4VPHandover', hashArray];

        // SessionTranscript = [null, null, OpenID4VPHandover]
        const sessionTranscript = cbor2.encode([null, null, handover]);
        return sessionTranscript;
    }

    /**
     * Creates an OID4VP authorization request URL for redirect-based flows.
     *
     * @param {object} options
     * @param {string} options.clientId
     * @param {string} options.requestUri
     * @param {string} [options.walletScheme] - defaults to 'openid4vp://'
     * @param {string} [options.requestUriMethod] - e.g. 'post'
     * @returns {string}
     */
    createAuthorizationRequestUrl({ clientId, requestUri, walletScheme = WalletScheme.OPENID4VP, requestUriMethod } = {}) {
        const params = new URLSearchParams();
        params.set('client_id', clientId);
        params.set('request_uri', requestUri);
        if (requestUriMethod !== undefined && requestUriMethod !== null) {
            params.set('request_uri_method', requestUriMethod);
        }
        return `${walletScheme}?${params.toString()}`;
    }

    /**
     * Computes the JWK Thumbprint per RFC 7638.
     * Supported key types: EC ({crv, kty, x, y}), RSA ({e, kty, n}), OKP ({crv, kty, x})
     *
     * @param {object} jwk - JWK object
     * @returns {Promise<Uint8Array>} 32-byte SHA-256 thumbprint
     */
    async computeJwkThumbprint(jwk) {
        let canonicalMembers;

        if (jwk.kty === 'EC') {
            canonicalMembers = { crv: jwk.crv, kty: jwk.kty, x: jwk.x, y: jwk.y };
        } else if (jwk.kty === 'RSA') {
            canonicalMembers = { e: jwk.e, kty: jwk.kty, n: jwk.n };
        } else if (jwk.kty === 'OKP') {
            canonicalMembers = { crv: jwk.crv, kty: jwk.kty, x: jwk.x };
        } else {
            throw new Error(`Unsupported key type: ${jwk.kty}`);
        }

        const json = JSON.stringify(canonicalMembers);
        const encoded = new TextEncoder().encode(json);
        const hashBuffer = await crypto.subtle.digest('SHA-256', encoded);
        return new Uint8Array(hashBuffer);
    }
}

const oid4vpRedirectHelper = new OID4VPRedirectHelper();
export default oid4vpRedirectHelper;
