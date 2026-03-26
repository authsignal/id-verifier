import { DocumentType, Protocol, CredentialFormat, ProtocolFormats, Claim, ALL_TRUST_LISTS, ResponseMode, ClientIdPrefix, WalletScheme } from './constants.js';
import { setTestDataUsage } from './trusted-issuer-registry-helper.js';
import OpenID4VPProtocolHelper from './openid-4vp-protocol-helper.js';
import MDOCProtocolHelper from './mdoc-protocol-helper.js';
import OID4VPRedirectHelper from './oid4vp-redirect-helper.js';
import { generateX509Hash, certToPemChain } from './x509-helper.js';

/**
 * Digital Credentials API Wrapper
 * A library to simplify digital ID verification using the W3C Digital Credentials API
 */

/**
 * Creates request structure for digital credentials
 *
 * @param {Object} options - Configuration options
 * @param {Array<string>} options.documentTypes - Type(s) of documents to request
 * @param {Array<string>} options.claims - Array of Claim enum values to request
 * @param {string} options.nonce - Security nonce to use in the request
 * @param {Object} options.jwk - JSON Web Key to use for encryption
 * @returns {Object} Request parameters compatible with Digital Credentials API
 */
export const createCredentialsRequest = (options = {}) => {
    const {
        nonce = generateNonce(),
        jwk,
        documentTypes = [DocumentType.MOBILE_DRIVERS_LICENSE],
        claims = [],
    } = options;

    // Normalize credential types to array
    const types = Array.isArray(documentTypes) ? documentTypes : [documentTypes];

    // Validate credential types
    const validTypes = Object.values(DocumentType);
    const invalidTypes = types.filter(type => !validTypes.includes(type));
    if (invalidTypes.length > 0) {
        throw new Error(`Invalid document types: ${invalidTypes.join(', ')}`);
    }

    // Create requests for both protocols
    const requests = [];

    for (const protocol of Object.values(Protocol)) {
        let request;
        if (protocol === Protocol.OPENID4VP) {
            request = OpenID4VPProtocolHelper.createRequest(types, claims, nonce);
        } else if (protocol === Protocol.MDOC) {
            request = MDOCProtocolHelper.createRequest(types, claims, nonce, jwk);
        }
        if (request) requests.push(request);
    }

    // Return the Digital Credentials API compatible structure
    return {
        mediation: 'required',
        digital: {
            requests: requests
        }
    };
};

/**
 * Requests digital credentials from the user
 *
 * @param {Object} requestParams - Request parameters from createRequestParams
 * @param {Object} options - Additional options for the request
 * @param {number} options.timeout - Request timeout in milliseconds (default: 300000)
 * @returns {Promise<Object>} Promise that resolves to credential data or rejects with error
 */
export const requestCredentials = async (requestParams, options = {}) => {
    const { timeout = 300000 } = options;

    // Validate that we're in a browser environment
    if (typeof window === 'undefined') {
        throw new Error('getCredentials can only be called in a browser environment');
    }

    // Validate that the Digital Credentials API is available
    if (!navigator.credentials) {
        throw new Error('Digital Credentials API not supported in this browser');
    }

    //filter out requests that are not supported by the browser
    requestParams.digital.requests = requestParams.digital.requests.filter(request => {
        const isSafari = navigator.userAgent.includes('Safari') && !navigator.userAgent.includes('Chrome');

        if (isSafari) {
            return request.protocol === Protocol.MDOC;
        }

        return true;
    });

    try {
        // Create the credential request options following the official spec
        const credentialRequestOptions = {
            ...requestParams,
            mediation: 'required',
            signal: AbortSignal.timeout(timeout)
        };

        console.log('DCAPI Request Options:', JSON.stringify(credentialRequestOptions, null, 2));

        // Request the credential
        const credential = await navigator.credentials.get(credentialRequestOptions);

        if (!credential) {
            throw new Error('No credential was provided by the user');
        }

        // Return the credential data
        return {
            id: credential.id,
            type: credential.type,
            data: credential.data,
            protocol: credential.protocol,
            timestamp: new Date().toISOString()
        };

    } catch (error) {
        console.error('Error getting credentials', error);
        throw error;
    }
};

/**
 * Processes a digital credential response
 *
 * @param {Object} credentials - The credentials response from requestCredentials
 * @param {Object} params - Verification params
 * @param {Array<string>} params.trustLists - Names of trust lists to use for determining trust. Defaults to all
 * @param {string|string[]} params.origin - The origin(s) of the request (for session transcript generation). Can be a single origin or array of origins to try.
 * @param {string} params.nonce - The nonce from the original request (for session transcript generation)
 * @param {Object} params.jwk - The JWK used to encrypt the request
 * @returns {Promise<Object>} Promise that resolves to the processed credential information
 */
export const processCredentials = async (credentials, params = {}) => {
    const {
        trustLists = ALL_TRUST_LISTS,
        origin = null,
        nonce = null,
        jwk = null
    } = params;

    if (!credentials || typeof credentials !== 'object')
        throw new Error('Invalid credential response');
    if (!credentials.data)
        throw new Error('Credential response missing data');

    // Convert single origin to array, or use provided array
    const origins = Array.isArray(origin) ? origin : (origin ? [origin] : [null]);

    if (credentials.protocol === Protocol.OPENID4VP) {
        return await OpenID4VPProtocolHelper.verify(credentials.data, trustLists, origins, nonce);
    } else if (credentials.protocol === Protocol.MDOC) {
        return await MDOCProtocolHelper.verify(credentials.data, trustLists, origins, nonce, jwk);
    } else {
        throw new Error(`Unsupported protocol: ${credentials.protocol}`);
    }
};

/**
 * Helper function to generate a nonce for request security
 * @returns {string} Nonce hex string with 128 bits of entropy
 */
export const generateNonce = () => {
    const array = new Uint8Array(16);
    if (typeof crypto !== 'undefined' && crypto.getRandomValues) {
        crypto.getRandomValues(array);
    } else {
        // Fallback for environments without crypto API
        for (let i = 0; i < array.length; i++) {
            array[i] = Math.floor(Math.random() * 256);
        }
    }
    return Array.from(array, byte => byte.toString(16).padStart(2, '0')).join('');
};

/**
 * Generates a JWK (JSON Web Key) using the P-256 curve
 * @returns {Promise<Object>} Promise that resolves to the JWK
 */
export const generateJWK = async () => {
    const keyPair = await crypto.subtle.generateKey({
        name: 'ECDH',
        namedCurve: 'P-256',
    }, true, ['deriveKey', 'deriveBits']);
    const jwk = await crypto.subtle.exportKey('jwk', keyPair.privateKey);
    return jwk;
};

/**
 * Create an OID4VP authorization request URL for wallet redirect.
 * @param {Object} options - { clientId, requestUri, walletScheme?, requestUriMethod? }
 * @returns {string} Authorization request URL
 */
export const createAuthorizationRequestUrl = (options) => {
    return OID4VPRedirectHelper.createAuthorizationRequestUrl(options);
};

/**
 * Create a signed JWT Request Object for the request_uri endpoint.
 * @param {Object} options - See OID4VPRedirectHelper.createRequestObject
 * @returns {Promise<string>} Signed JWT request object
 */
export const createRequestObject = async (options) => {
    return OID4VPRedirectHelper.createRequestObject(options);
};

/**
 * Process a wallet's direct_post or direct_post.jwt response.
 * @param {Object} options - { responseBody, encryptionJwk? }
 * @returns {Promise<Object>} { vpToken, state }
 */
export const processDirectPostResponse = async (options) => {
    return OID4VPRedirectHelper.processDirectPostResponse(options);
};

/**
 * Verify mdoc credentials from an OID4VP redirect flow response.
 * @param {Object} options - See OID4VPRedirectHelper.verify
 * @returns {Promise<Object>} { claims, valid, trusted, processedDocuments, sessionTranscript }
 */
export const verifyRedirectResponse = async (options) => {
    return OID4VPRedirectHelper.verify(options);
};

/**
 * Compute the JWK SHA-256 Thumbprint per RFC 7638.
 * @param {Object} jwk - Public JWK
 * @returns {Promise<Uint8Array>} 32-byte SHA-256 thumbprint
 */
export const computeJwkThumbprint = async (jwk) => {
    return OID4VPRedirectHelper.computeJwkThumbprint(jwk);
};

/**
 * Parse the wallet's POST body from request_uri_method=post negotiation.
 * @param {string} body - URL-encoded form body
 * @returns {Object} { walletMetadata, walletNonce }
 */
export const parseWalletPost = (body) => {
    return OID4VPRedirectHelper.parseWalletPost(body);
};

/**
 * Create the verifier's response to a wallet direct_post.
 * @param {Object} options - { redirectUri? }
 * @returns {Object} HTTP 200 response body
 */
export const createDirectPostSuccessResponse = (options) => {
    return OID4VPRedirectHelper.createDirectPostSuccessResponse(options);
};

export {
    DocumentType,
    Protocol,
    CredentialFormat,
    ProtocolFormats,
    Claim,
    setTestDataUsage,
    ResponseMode,
    ClientIdPrefix,
    WalletScheme,
    generateX509Hash,
    certToPemChain,
};