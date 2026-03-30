import pako from 'pako';
import * as cbor2 from 'cbor2';
import { FetchCache } from './fetch-cache.js';

// CWT payload keys per Token Status List spec
const CWT_STATUS_LIST_KEY = -65538; // status_list
const CWT_STATUS_LIST_BITS = 'bits';
const CWT_STATUS_LIST_LST = 'lst';

// Cache for status list tokens (JWT or CWT), keyed by URI
const statusListCache = new FetchCache({
    fetchFn: async (url) => {
        // Don't send restrictive Accept header — let the server decide format
        const response = await fetch(url);
        if (!response.ok) {
            throw new Error(`Failed to fetch status list from ${url}: ${response.status}`);
        }
        const contentType = response.headers.get('content-type') || '';
        if (contentType.includes('cwt') || contentType.includes('cbor') || contentType.includes('octet-stream')) {
            // CWT format — return raw bytes + format indicator
            const arrayBuffer = await response.arrayBuffer();
            return { format: 'cwt', data: new Uint8Array(arrayBuffer) };
        }
        // JWT format — return text + format indicator
        const text = await response.text();
        // Check if it looks like a JWT (three dot-separated parts)
        if (text.includes('.')) {
            return { format: 'jwt', data: text };
        }
        // Might be binary CWT returned without proper content-type
        return { format: 'cwt', data: new Uint8Array(await new Blob([text]).arrayBuffer()) };
    },
});

/**
 * Extract the status list (compressed bitstring + bits) from a JWT or CWT token.
 * @param {{ format: string, data: any }} token - The fetched token
 * @returns {{ lst: Uint8Array|string, bits: number }} The status list data
 */
function extractStatusList(token) {
    if (token.format === 'jwt') {
        // JWT: decode payload (base64url), extract status_list.lst and status_list.bits
        const parts = token.data.split('.');
        if (parts.length < 2) throw new Error('Invalid JWT format');
        const payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8'));
        const statusList = payload?.status_list;
        if (!statusList?.lst) throw new Error('JWT missing status_list.lst');
        return { lst: statusList.lst, bits: statusList.bits || 1, isBase64url: true };
    }

    if (token.format === 'cwt') {
        // CWT: COSE_Sign1 = Tag(18, [protectedHeaders, unprotectedHeaders, payload, signature])
        const decoded = cbor2.decode(token.data);
        const coseArray = decoded.contents || decoded;
        const payloadRaw = coseArray[2]; // third element is the payload
        const payload = cbor2.decode(payloadRaw);

        // Payload is a CBOR Map with key -65538 for status_list
        let statusList;
        if (payload instanceof Map) {
            statusList = payload.get(CWT_STATUS_LIST_KEY);
        } else {
            statusList = payload[CWT_STATUS_LIST_KEY] || payload.status_list;
        }

        if (!statusList) throw new Error('CWT missing status_list');

        const lst = statusList instanceof Map ? statusList.get(CWT_STATUS_LIST_LST) : statusList[CWT_STATUS_LIST_LST] || statusList.lst;
        const bits = statusList instanceof Map ? statusList.get(CWT_STATUS_LIST_BITS) : statusList[CWT_STATUS_LIST_BITS] || statusList.bits || 1;

        if (!lst) throw new Error('CWT status_list missing lst');
        return { lst, bits, isBase64url: false };
    }

    throw new Error(`Unknown token format: ${token.format}`);
}

/**
 * Decodes a zlib-compressed bitstring and extracts the status value at the given index.
 * RFC 9597 MSB-first bit ordering: index 0 is bit 7 of byte 0.
 *
 * @param {string|Uint8Array} compressedBitstring - base64url string or raw bytes
 * @param {number} index - credential's position in the status list
 * @param {number} bits - bits per entry (1 or 2, default 1)
 * @param {boolean} [isBase64url=true] - whether the input is base64url-encoded
 * @returns {number} numeric status value (0 = valid, non-zero = revoked/suspended)
 */
export function getStatusFromBitstring(compressedBitstring, index, bits = 1, isBase64url = true) {
    let compressed;
    if (isBase64url && typeof compressedBitstring === 'string') {
        compressed = Buffer.from(compressedBitstring, 'base64url');
    } else if (compressedBitstring instanceof Uint8Array) {
        compressed = compressedBitstring;
    } else {
        compressed = Buffer.from(compressedBitstring, 'base64url');
    }
    const bitstring = pako.inflate(compressed);

    // RFC 9597 Section 4.1: bit position starts from the LEAST significant bit
    const byteIndex = Math.floor((index * bits) / 8);
    const bitPosition = (index * bits) % 8; // from LSB
    const mask = ((1 << bits) - 1) << bitPosition;
    return (bitstring[byteIndex] & mask) >> bitPosition;
}

/**
 * Checks the revocation status of a credential using an IETF Token Status List.
 * Supports both JWT and CWT (CBOR Web Token) formats.
 *
 * @param {{ uri: string, index: number }} statusListRef
 * @param {object} [options]
 * @param {boolean} [options.enabled=true]
 * @param {number} [options.cacheTtlMs=300000]
 * @param {number} [options.bits=1]
 * @returns {Promise<{ revoked: boolean, status?: number, statusListRef: object }>}
 */
export async function checkTokenStatusList(statusListRef, options = {}) {
    const { enabled = true, cacheTtlMs = 300000, bits = 1 } = options;

    if (!enabled) {
        return { revoked: false, statusListRef };
    }

    const token = await statusListCache.get(statusListRef.uri, { ttlMs: cacheTtlMs });
    if (!token) {
        console.error(`Failed to fetch status list from ${statusListRef.uri}`);
        return { revoked: false, statusListRef };
    }

    const { lst, bits: tokenBits, isBase64url } = extractStatusList(token);
    const effectiveBits = tokenBits || bits;

    const status = getStatusFromBitstring(lst, statusListRef.index, effectiveBits, isBase64url);
    const revoked = status !== 0;

    return { revoked, status, statusListRef };
}

/**
 * Re-checks credential status, bypassing cache by default.
 *
 * @param {{ uri: string, index: number }} statusListRef
 * @param {object} [options]
 * @param {number} [options.cacheTtlMs=0]
 * @param {number} [options.bits=1]
 * @returns {Promise<{ revoked: boolean, status: number, checkedAt: string, statusListRef: object }>}
 */
export async function recheckCredentialStatus(statusListRef, options = {}) {
    const { cacheTtlMs = 0, bits = 1 } = options;
    const result = await checkTokenStatusList(statusListRef, {
        enabled: true,
        cacheTtlMs,
        bits,
    });
    return {
        ...result,
        checkedAt: new Date().toISOString(),
    };
}
