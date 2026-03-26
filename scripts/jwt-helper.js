import { SignJWT, importJWK, compactDecrypt } from 'jose';

/**
 * Signs an OID4VP request object as a JWT.
 * @param {Object} payload - Claims to include (client_id, nonce, response_uri, dcql_query, etc.)
 * @param {import('jose').KeyLike} privateKey - jose KeyLike signing key
 * @param {string[]} x5cChain - Array of base64-encoded DER certificates for the x5c JOSE header
 * @param {string} alg - Signing algorithm (default: 'ES256')
 * @returns {Promise<string>} Signed JWT
 */
export async function signRequestObject(payload, privateKey, x5cChain, alg = 'ES256') {
    return new SignJWT(payload)
        .setProtectedHeader({ alg, typ: 'oauth-authz-req+jwt', x5c: x5cChain })
        .setIssuedAt()
        .sign(privateKey);
}

/**
 * Decrypts a JWE response from a wallet's direct_post.jwt submission.
 * @param {string} jwe - Compact JWE string
 * @param {Object} recipientJwk - Verifier's ephemeral private JWK (with `d` parameter)
 * @returns {Promise<Object>} Parsed JSON payload
 */
export async function decryptJweResponse(jwe, recipientJwk) {
    const privateKey = await importJWK(recipientJwk, 'ECDH-ES');
    const { plaintext } = await compactDecrypt(jwe, privateKey);
    return JSON.parse(new TextDecoder().decode(plaintext));
}
