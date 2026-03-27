import { WalletScheme, CredentialFormat, ResponseMode, createCredentialId, CredentialId, ALL_TRUST_LISTS } from './constants.js';
import * as cbor2 from 'cbor2';
import { signRequestObject, decryptJweResponse } from './jwt-helper.js';
import { decodeVpToken, verifyDocument } from './formats/mdoc-helper.js';

class OID4VPRedirectHelper {
    /**
     * Generates a SessionTranscript for OID4VP 1.0 redirect flows (Appendix B.2.6.1).
     * Used with DCQL-based wallets.
     *
     * SessionTranscript = [null, null, ["OpenID4VPHandover", SHA256(CBOR([clientId, nonce, jwkThumbprint, responseUri]))]]
     *
     * @param {string} clientId
     * @param {string} nonce
     * @param {Uint8Array|null} jwkThumbprint
     * @param {string} responseUri
     * @returns {Promise<Uint8Array>} CBOR-encoded SessionTranscript
     */
    async _generateSessionTranscript(clientId, nonce, jwkThumbprint, responseUri) {
        if (!clientId) throw new Error('clientId is required for generating session transcript');
        if (!nonce) throw new Error('nonce is required for generating session transcript');
        if (!responseUri) throw new Error('responseUri is required for generating session transcript');

        const handoverInfo = [clientId, nonce, jwkThumbprint, responseUri];
        const handoverInfoBytes = cbor2.encode(handoverInfo);
        const hashBuffer = await crypto.subtle.digest('SHA-256', handoverInfoBytes);
        const hashArray = new Uint8Array(hashBuffer);

        const handover = ['OpenID4VPHandover', hashArray];
        return cbor2.encode([null, null, handover]);
    }

    /**
     * Generates a SessionTranscript for ISO 18013-7 Annex B / OID4VP 1.0 Appendix B.3.4.1.
     * Used with Presentation Exchange-based wallets (MATTR, EUDI, etc.).
     *
     * SessionTranscript = [null, null, OID4VPHandover]
     * OID4VPHandover = [clientIdHash, responseUriHash, nonce]
     * clientIdHash    = SHA-256(CBOR([clientId, mdocGeneratedNonce]))
     * responseUriHash = SHA-256(CBOR([responseUri, mdocGeneratedNonce]))
     *
     * @param {string} clientId - client_id from the Authorization Request
     * @param {string} responseUri - response_uri from the Authorization Request
     * @param {string} nonce - nonce from the Authorization Request
     * @param {string} mdocGeneratedNonce - wallet-generated nonce from JWE apu header
     * @returns {Promise<Uint8Array>} CBOR-encoded SessionTranscript
     */
    async _generateISO18013SessionTranscript(clientId, responseUri, nonce, mdocGeneratedNonce) {
        if (!clientId) throw new Error('clientId is required');
        if (!responseUri) throw new Error('responseUri is required');
        if (!nonce) throw new Error('nonce is required');
        if (!mdocGeneratedNonce) throw new Error('mdocGeneratedNonce is required');

        // clientIdHash = SHA-256(CBOR([clientId, mdocGeneratedNonce]))
        const clientIdToHash = cbor2.encode([clientId, mdocGeneratedNonce]);
        const clientIdHash = new Uint8Array(await crypto.subtle.digest('SHA-256', clientIdToHash));

        // responseUriHash = SHA-256(CBOR([responseUri, mdocGeneratedNonce]))
        const responseUriToHash = cbor2.encode([responseUri, mdocGeneratedNonce]);
        const responseUriHash = new Uint8Array(await crypto.subtle.digest('SHA-256', responseUriToHash));

        // OID4VPHandover = [clientIdHash, responseUriHash, nonce]
        const handover = [clientIdHash, responseUriHash, nonce];

        return cbor2.encode([null, null, handover]);
    }

    /**
     * Creates an OID4VP authorization request URL for redirect-based flows.
     *
     * @param {object} options
     * @param {string} options.clientId - The client identifier value
     * @param {string} options.requestUri
     * @param {string} [options.walletScheme] - defaults to 'openid4vp://'
     * @param {string} [options.requestUriMethod] - e.g. 'post'
     * @param {string} [options.clientIdScheme] - If set, added as separate param (pre-1.0 / ISO 18013-7 format).
     *   When provided, clientId should be the plain value (e.g. DNS name), not prefixed.
     * @returns {string}
     */
    createAuthorizationRequestUrl({ clientId, requestUri, walletScheme = WalletScheme.OPENID4VP, requestUriMethod, clientIdScheme } = {}) {
        const params = new URLSearchParams();
        params.set('client_id', clientId);
        if (clientIdScheme) {
            params.set('client_id_scheme', clientIdScheme);
        }
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
        usePresentationExchange = false,
        clientIdScheme,
        typ = 'oauth-authz-req+jwt',
        kid,
    }) {
        const payload = {
            aud: 'https://self-issued.me/v2',
            client_id: clientId,
            nonce,
            state,
            response_uri: responseUri,
            response_type: 'vp_token',
            response_mode: responseMode,
        };

        if (clientIdScheme) {
            payload.client_id_scheme = clientIdScheme;
        }

        if (usePresentationExchange) {
            // ISO 18013-7 / OID4VP draft 18 format — Presentation Exchange
            payload.presentation_definition = this._createPresentationDefinition(documentTypes, claims);
        } else {
            // OID4VP 1.0 format — DCQL
            const credentials = documentTypes.map(docType => ({
                id: createCredentialId(CredentialFormat.MSO_MDOC, docType),
                format: CredentialFormat.MSO_MDOC,
                meta: { doctype_value: docType },
                claims: claims.map(c => ({ path: c })),
            }));
            payload.dcql_query = { credentials };
        }

        if (walletNonce !== undefined && walletNonce !== null) {
            payload.wallet_nonce = walletNonce;
        }

        if (encryptionJwk) {
            // Strip private key material — only embed public key in the JWT payload
            const { d, dp, dq, qi, ...publicJwk } = encryptionJwk;
            payload.client_metadata = {
                authorization_encrypted_response_alg: 'ECDH-ES',
                authorization_encrypted_response_enc: 'A256GCM',
                vp_formats: {
                    mso_mdoc: {
                        alg: ['ES256', 'ES384', 'ES512'],
                    },
                },
                require_signed_request_object: true,
                jwks: {
                    keys: [{ ...publicJwk, use: 'enc', kid: 'ephemeral-enc-key', alg: 'ECDH-ES' }],
                },
            };
        }

        return signRequestObject(payload, privateKey, x5cChain, 'ES256', { typ, kid, includeIat: !usePresentationExchange });
    }

    /**
     * Full verification pipeline for redirect flow mdoc responses.
     *
     * @param {object} options
     * @param {object} options.vpToken - Map of credentialId to array of base64url-encoded tokens
     * @param {string} options.clientId
     * @param {string} options.nonce
     * @param {string} options.responseUri
     * @param {object} [options.encryptionJwk] - Public JWK used for encryption (to compute thumbprint for OID4VP 1.0)
     * @param {string} [options.mdocGeneratedNonce] - Wallet-generated nonce from JWE apu header (for ISO 18013-7)
     * @param {string[]} [options.trustLists] - Trust list identifiers; defaults to ALL_TRUST_LISTS
     * @returns {Promise<{ claims, valid, trusted, processedDocuments, sessionTranscript }>}
     */
    async verify({ vpToken, clientId, nonce, responseUri, encryptionJwk, mdocGeneratedNonce,
                   trustLists = ALL_TRUST_LISTS, trustedCertificates,
                   enableCrl = false, crlCacheTtlMs, enableStatusList = false, statusListCacheTtlMs }) {
        let sessionTranscript;

        if (mdocGeneratedNonce) {
            // ISO 18013-7 Annex B / OID4VP 1.0 Appendix B.3.4.1
            sessionTranscript = await this._generateISO18013SessionTranscript(clientId, responseUri, nonce, mdocGeneratedNonce);
        } else {
            // OID4VP 1.0 Appendix B.2.6.1 (DC API-adjacent redirect flow)
            const jwkThumbprint = encryptionJwk
                ? await this.computeJwkThumbprint(encryptionJwk)
                : null;
            sessionTranscript = await this._generateSessionTranscript(clientId, nonce, jwkThumbprint, responseUri);
        }

        const allClaims = {};
        let valid = true;
        let credentialVerified = true;
        let issuerTrusted = true;
        let issuerRevoked = false;
        let credentialRevoked = false;
        const processedDocuments = [];

        for (const credentialKey of Object.keys(vpToken)) {
            const credInfo = CredentialId[credentialKey];
            if (!credInfo || credInfo.format !== CredentialFormat.MSO_MDOC) {
                throw new Error(`Unsupported credential format for key: ${credentialKey}`);
            }

            const tokens = vpToken[credentialKey];
            for (const token of tokens) {
                const decoded = await decodeVpToken(token);
                for (const doc of decoded.documents) {
                    const docResult = await verifyDocument(
                        doc, sessionTranscript, { trustedCertificates, enableCrl, crlCacheTtlMs, enableStatusList, statusListCacheTtlMs }
                    );

                    Object.assign(allClaims, docResult.claims);

                    if (!docResult.credentialVerified) credentialVerified = false;
                    if (!docResult.issuerTrusted) issuerTrusted = false;
                    if (docResult.issuerRevoked) issuerRevoked = true;
                    if (docResult.credentialRevoked) credentialRevoked = true;
                    if (!docResult.valid) valid = false;

                    processedDocuments.push({
                        claims: docResult.claims,
                        issuer: docResult.issuer,
                        valid: docResult.valid,
                        credentialVerified: docResult.credentialVerified,
                        issuerTrusted: docResult.issuerTrusted,
                        issuerRevoked: docResult.issuerRevoked,
                        credentialRevoked: docResult.credentialRevoked,
                        invalidReasons: docResult.invalidReasons,
                        statusListRef: docResult.statusListRef,
                    });
                }
            }
        }

        return {
            claims: allClaims,
            valid,
            credentialVerified,
            issuerTrusted,
            issuerRevoked,
            credentialRevoked,
            processedDocuments,
            sessionTranscript,
        };
    }

    /**
     * Parses the wallet's POST body from request_uri_method=post negotiation.
     *
     * @param {string} body - URL-encoded form string (application/x-www-form-urlencoded)
     * @returns {{ walletMetadata: Object, walletNonce: string|undefined }}
     */
    parseWalletPost(body) {
        const params = new URLSearchParams(body);
        const walletMetadataRaw = params.get('wallet_metadata');
        const walletNonce = params.get('wallet_nonce') ?? undefined;
        const walletMetadata = walletMetadataRaw ? JSON.parse(walletMetadataRaw) : undefined;
        return { walletMetadata, walletNonce };
    }

    /**
     * Builds the HTTP 200 response for the wallet after receiving direct_post.
     *
     * @param {object} options
     * @param {string} [options.redirectUri] - Present for same-device flow; absent for cross-device
     * @returns {{ redirect_uri?: string }}
     */
    createDirectPostSuccessResponse({ redirectUri } = {}) {
        if (redirectUri) {
            const responseCodeBytes = new Uint8Array(24);
            crypto.getRandomValues(responseCodeBytes);
            const responseCode = Array.from(responseCodeBytes)
                .map(b => b.toString(16).padStart(2, '0'))
                .join('');
            const url = new URL(redirectUri);
            url.searchParams.set('response_code', responseCode);
            return { redirect_uri: url.toString(), response_code: responseCode };
        }
        return {};
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

        if (responseBody.response) {
            if (!encryptionJwk) {
                throw new Error('encryptionJwk is required to decrypt a direct_post.jwt response');
            }
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

    /**
     * Build a Presentation Exchange presentation_definition for ISO 18013-7 / OID4VP draft 18.
     * This is the legacy format that older wallets (MATTR, etc.) expect.
     *
     * @param {string[]} documentTypes
     * @param {Array<[string, string]>} claims - [namespace, element] pairs
     * @returns {Object} presentation_definition
     */
    _createPresentationDefinition(documentTypes, claims) {
        const inputDescriptors = documentTypes.map((docType, idx) => {
            const fields = claims.map(([namespace, element]) => ({
                path: [`$['${namespace}']['${element}']`],
                intent_to_retain: false,
            }));

            return {
                id: `${docType}`,
                format: {
                    mso_mdoc: {
                        alg: ['ES256'],
                    },
                },
                constraints: {
                    limit_disclosure: 'required',
                    fields,
                },
            };
        });

        return {
            id: crypto.randomUUID(),
            input_descriptors: inputDescriptors,
        };
    }
}

const oid4vpRedirectHelper = new OID4VPRedirectHelper();
export default oid4vpRedirectHelper;
