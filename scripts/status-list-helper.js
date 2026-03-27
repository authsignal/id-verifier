import pako from 'pako';
import { FetchCache } from './fetch-cache.js';

// Cache for status list JWTs, keyed by URI
const statusListCache = new FetchCache({
    fetchFn: async (url) => {
        const response = await fetch(url, {
            headers: { Accept: 'application/statuslist+jwt' },
        });
        if (!response.ok) {
            throw new Error(`Failed to fetch status list from ${url}: ${response.status}`);
        }
        return response.text();
    },
});

/**
 * Decodes a base64url-encoded, zlib-compressed bitstring and extracts the
 * status value at the given index, using RFC 9597 MSB-first bit ordering.
 *
 * @param {string} compressedBitstring - base64url-encoded zlib-compressed bitstring
 * @param {number} index - credential's position in the status list
 * @param {number} bits - bits per entry (1 or 2, default 1)
 * @returns {number} numeric status value (0 = valid, non-zero = revoked/suspended)
 */
export function getStatusFromBitstring(compressedBitstring, index, bits = 1) {
    const compressed = Buffer.from(compressedBitstring, 'base64url');
    const bitstring = pako.inflate(compressed);

    // RFC 9597: index 0 is the MSB of byte 0 (bit 7), index 1 is bit 6, etc.
    const bitOffset = index * bits;
    const byteIndex = Math.floor(bitOffset / 8);
    const bitPositionFromMSB = bitOffset % 8;
    // Bit position from LSB within the byte for the MSB of our value
    const msbBitFromLSB = 7 - bitPositionFromMSB;

    let value = 0;
    for (let i = 0; i < bits; i++) {
        const currentBitFromLSB = msbBitFromLSB - i;
        if (currentBitFromLSB < 0) {
            // Span across byte boundary
            const nextByteIndex = byteIndex + 1;
            const nextBitFromLSB = 7 - (bitPositionFromMSB + i - 8);
            const bit = (bitstring[nextByteIndex] >> nextBitFromLSB) & 1;
            value = (value << 1) | bit;
        } else {
            const bit = (bitstring[byteIndex] >> currentBitFromLSB) & 1;
            value = (value << 1) | bit;
        }
    }

    return value;
}

/**
 * Checks the revocation status of a credential using an IETF Token Status List.
 *
 * @param {{ uri: string, index: number }} statusListRef - status list reference
 * @param {object} options
 * @param {boolean} [options.enabled=true] - if false, skip check and return not revoked
 * @param {number} [options.cacheTtlMs=300000] - cache TTL in ms (default 5 min)
 * @param {number} [options.bits=1] - bits per entry
 * @returns {Promise<{ revoked: boolean, status?: number, statusListRef: object }>}
 */
export async function checkTokenStatusList(statusListRef, options = {}) {
    const { enabled = true, cacheTtlMs = 300000, bits = 1 } = options;

    if (!enabled) {
        return { revoked: false, statusListRef };
    }

    const jwt = await statusListCache.get(statusListRef.uri, { ttlMs: cacheTtlMs });
    if (!jwt) {
        throw new Error(`Failed to fetch status list from ${statusListRef.uri}`);
    }

    // Decode JWT payload (base64url, no signature verification — issuer already trusted)
    const parts = jwt.split('.');
    if (parts.length < 2) {
        throw new Error(`Invalid JWT format from ${statusListRef.uri}`);
    }
    const payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8'));

    const lst = payload?.status_list?.lst;
    const payloadBits = payload?.status_list?.bits ?? bits;

    if (!lst) {
        throw new Error(`Status list JWT from ${statusListRef.uri} missing status_list.lst`);
    }

    const status = getStatusFromBitstring(lst, statusListRef.index, payloadBits);
    const revoked = status !== 0;

    return { revoked, status, statusListRef };
}

/**
 * Re-checks credential status, bypassing cache by default.
 *
 * @param {{ uri: string, index: number }} statusListRef - status list reference
 * @param {object} options
 * @param {number} [options.cacheTtlMs=0] - cache TTL in ms (default 0 = always re-fetch)
 * @param {number} [options.bits=1] - bits per entry
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
