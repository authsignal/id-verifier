import * as asn1js from 'asn1js';
import { FetchCache } from './fetch-cache.js';

const crlCache = new FetchCache({
    fetchFn: async (url) => {
        const response = await fetch(url);
        if (!response.ok) {
            throw new Error(`Failed to fetch CRL from ${url}: ${response.status} ${response.statusText}`);
        }
        return await response.arrayBuffer();
    },
});

/**
 * Recursively extract URIs from an ASN.1 node tree.
 * Looks for context-tagged [6] nodes (uniformResourceIdentifier in GeneralName).
 * @param {object} node - ASN.1 node
 * @param {string[]} urls - array to push found URLs into
 */
function extractUrisFromAsn1(node, urls) {
    if (
        node.idBlock.tagClass === 3 &&
        node.idBlock.tagNumber === 6 &&
        node.valueBlock.valueHex
    ) {
        const uri = new TextDecoder('utf-8').decode(node.valueBlock.valueHex);
        if (uri.startsWith('http')) {
            urls.push(uri);
        }
    }

    const children = node.valueBlock?.value;
    if (Array.isArray(children)) {
        for (const child of children) {
            extractUrisFromAsn1(child, urls);
        }
    }
}

/**
 * Extract CRL Distribution Point URLs from a pkijs Certificate.
 * @param {object} certificate - pkijs Certificate object
 * @returns {string[]} array of HTTP(S) CRL URLs
 */
export function getCrlDistributionPoints(certificate) {
    const extensions = certificate.extensions;
    if (!extensions) return [];

    const crlDpExt = extensions.find(ext => ext.extnID === '2.5.29.31');
    if (!crlDpExt) return [];

    const derBytes = crlDpExt.extnValue.valueBlock?.valueHex ?? crlDpExt.extnValue;
    const parsed = asn1js.fromBER(derBytes instanceof ArrayBuffer ? derBytes : derBytes.buffer ?? derBytes);
    if (parsed.offset === -1) return [];

    const urls = [];
    extractUrisFromAsn1(parsed.result, urls);
    return urls;
}

/**
 * Parse a DER-encoded CRL and extract revoked serial numbers.
 * @param {ArrayBuffer} derBytes
 * @returns {{ revokedSerials: Set<string> }}
 */
function parseCrl(derBytes) {
    const parsed = asn1js.fromBER(derBytes);
    if (parsed.offset === -1) {
        return { revokedSerials: new Set() };
    }

    const revokedSerials = new Set();

    try {
        // CRL structure: SEQUENCE { tbsCertList SEQUENCE { version, signature, issuer, thisUpdate, nextUpdate, revokedCertificates SEQUENCE OF { SEQUENCE { serialNumber INTEGER, ... } } } }
        const crlSequence = parsed.result;
        const tbsCertList = crlSequence.valueBlock.value[0]; // first element of outer SEQUENCE is tbsCertList
        const tbsChildren = tbsCertList.valueBlock.value;

        // Find revokedCertificates — it's a SEQUENCE OF, and comes after the mandatory fields.
        // Mandatory: version(optional), signature, issuer, thisUpdate, nextUpdate
        // We look for a SEQUENCE whose first child is a SEQUENCE (revokedCertEntry)
        for (const child of tbsChildren) {
            if (
                child.idBlock.tagClass === 1 &&
                child.idBlock.tagNumber === 16 // SEQUENCE
            ) {
                const innerChildren = child.valueBlock.value;
                if (
                    innerChildren &&
                    innerChildren.length > 0 &&
                    innerChildren[0].idBlock?.tagClass === 1 &&
                    innerChildren[0].idBlock?.tagNumber === 16
                ) {
                    // This looks like revokedCertificates SEQUENCE OF SEQUENCE
                    for (const entry of innerChildren) {
                        const entryChildren = entry.valueBlock?.value;
                        if (entryChildren && entryChildren.length > 0) {
                            const serialNode = entryChildren[0];
                            if (serialNode.valueBlock?.valueHex) {
                                const hexStr = Buffer.from(serialNode.valueBlock.valueHex).toString('hex');
                                revokedSerials.add(hexStr);
                            }
                        }
                    }
                    break;
                }
            }
        }
    } catch (err) {
        // If parsing fails, return empty set (safe default)
    }

    return { revokedSerials };
}

/**
 * Get the serial number of a pkijs Certificate as a hex string.
 * @param {object} certificate - pkijs Certificate object
 * @returns {string}
 */
function getSerialNumberHex(certificate) {
    return Buffer.from(certificate.serialNumber.valueBlock.valueHex).toString('hex');
}

/**
 * Check whether a certificate has been revoked via CRL.
 * @param {object} certificate - pkijs Certificate object
 * @param {object} options
 * @param {boolean} [options.enabled=true] - if false, skip revocation check
 * @param {number} [options.cacheTtlMs=3600000] - CRL cache TTL in milliseconds
 * @returns {Promise<{ revoked: boolean, reason?: string }>}
 */
export async function checkCertRevocation(certificate, options = {}) {
    const { enabled = true, cacheTtlMs = 3600000 } = options;

    if (!enabled) {
        return { revoked: false };
    }

    const crlUrls = getCrlDistributionPoints(certificate);
    if (crlUrls.length === 0) {
        return { revoked: false };
    }

    const serialHex = getSerialNumberHex(certificate);

    for (const url of crlUrls) {
        const derBytes = await crlCache.get(url, { ttlMs: cacheTtlMs });
        if (!derBytes) continue;

        const { revokedSerials } = parseCrl(derBytes);
        if (revokedSerials.has(serialHex)) {
            return { revoked: true, reason: `Certificate serial ${serialHex} found in CRL at ${url}` };
        }
    }

    return { revoked: false };
}
