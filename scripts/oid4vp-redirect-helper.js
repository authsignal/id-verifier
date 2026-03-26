import { WalletScheme, CredentialFormat, ResponseMode, createCredentialId } from './constants.js';
import * as cbor2 from 'cbor2';
import { signRequestObject, decryptJweResponse } from './jwt-helper.js';

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

    /**
     * Creates a signed OID4VP request object JWT.
     *
     * @param {object} options
     * @param {string} options.clientId
     * @param {string} options.nonce
     * @param {string} options.state
     * @param {string} options.responseUri
     * @param {string[]} options.documentTypes
     * @param {string[]} options.claims
     * @param {import('jose').KeyLike} options.privateKey
     * @param {string[]} options.x5cChain
     * @param {object} [options.encryptionJwk]
     * @param {string} [options.walletNonce]
     * @param {string} [options.responseMode]
     * @returns {Promise<string>} Signed JWT string
     */
    async createRequestObject({
        clientId, nonce, state, responseUri, documentTypes, claims,
        privateKey, x5cChain, encryptionJwk, walletNonce,
        responseMode = ResponseMode.DIRECT_POST_JWT,
    }) {
        const credentials = documentTypes.map(docType => ({
            id: createCredentialId(CredentialFormat.MSO_MDOC, docType),
            format: CredentialFormat.MSO_MDOC,
            meta: { doctype_value: docType },
            claims: claims.map(c => ({ path: c })),
        }));

        const payload = {
            client_id: clientId,
            nonce,
            state,
            response_uri: responseUri,
            response_type: 'vp_token',
            response_mode: responseMode,
            dcql_query: { credentials },
        };

        if (walletNonce !== undefined && walletNonce !== null) {
            payload.wallet_nonce = walletNonce;
        }

        if (encryptionJwk) {
            payload.client_metadata = {
                encrypted_response_alg_values_supported: ['ECDH-ES'],
                encrypted_response_enc_values_supported: ['A256GCM', 'A128GCM'],
                jwks: {
                    keys: [{ ...encryptionJwk, use: 'enc', kid: 'ephemeral-enc-key' }],
                },
            };
        }

        return signRequestObject(payload, privateKey, x5cChain);
    }

    /**
     * Processes a direct_post or direct_post.jwt response from a wallet.
     *
     * @param {object} options
     * @param {object} options.responseBody
     * @param {object} [options.encryptionJwk]
     * @returns {Promise<{ vpToken: any, state: string }>}
     */
    async processDirectPostResponse({ responseBody, encryptionJwk }) {
        let vpToken;
        let state;

        if (responseBody.response && encryptionJwk) {
            // direct_post.jwt — decrypt the JWE
            const decrypted = await decryptJweResponse(responseBody.response, encryptionJwk);
            vpToken = typeof decrypted.vp_token === 'string'
                ? JSON.parse(decrypted.vp_token)
                : decrypted.vp_token;
            state = decrypted.state;
        } else {
            // plain direct_post
            vpToken = typeof responseBody.vp_token === 'string'
                ? JSON.parse(responseBody.vp_token)
                : responseBody.vp_token;
            state = responseBody.state;
        }

        return { vpToken, state };
    }
}

const oid4vpRedirectHelper = new OID4VPRedirectHelper();
export default oid4vpRedirectHelper;
