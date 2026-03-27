import * as cbor2 from 'cbor2';
import { getIssuer } from '../trusted-issuer-registry-helper.js';
import { verifyIssuerTrustAndRevocation } from '../issuer-verifier.js';
import { checkTokenStatusList } from '../status-list-helper.js';
import { REVERSE_CLAIM_MAPPINGS, CredentialFormat } from '../constants.js';
import { parseX5Chain, x509ToWebCryptoKey, getCertificateInfo } from '../certificate-helper.js';
import { verifyCoseSign1, coseKeyToWebCryptoKey } from '../cose-helper.js';
import { base64urlToUint8Array } from '../utils.js';

export const decodeVpToken = async (vp_token) => {
    const uint8Array = base64urlToUint8Array(vp_token);
    const decoded = await cbor2.decode(uint8Array);
    return decoded;
};

export const verifyDocument = async (document, sessionTranscript, verificationOptions = {}) => {
    const claims = {};
    const invalidReasons = [];
    const { docType, issuerSigned, deviceSigned } = document;
    const { issuerAuth, nameSpaces } = issuerSigned;
    const { valid, issuerAuthPayload, certificate, invalidReason } = await verifyIssuerAuth(issuerAuth);
    if(!valid) invalidReasons.push(invalidReason);
    const deviceValid = await verifyDeviceAuth(deviceSigned, issuerAuthPayload, sessionTranscript);
    if(!deviceValid) invalidReasons.push('Failed to verify device authentication');
    let claimsValid = true;
    for(const namespace in nameSpaces) {
        for(const claim of nameSpaces[namespace]) {
            const claimValid = await setClaim(claims, docType, namespace, claim, issuerAuthPayload);
            if(!claimValid && claimsValid) {
                claimsValid = false;
                invalidReasons.push("Claim values don't match IssuerAuth value digests");
            }
        }
    }
    // Determine issuer trust and CRL revocation
    let issuerTrusted = false;
    let issuerRevoked = false;
    let issuer = null;
    let statusListRef = null;
    let credentialRevoked = false;

    if (verificationOptions.trustedCertificates) {
        const trustResult = await verifyIssuerTrustAndRevocation(certificate, {
            trustedCertificates: verificationOptions.trustedCertificates,
            enableCrl: verificationOptions.enableCrl,
            crlCacheTtlMs: verificationOptions.crlCacheTtlMs,
        });
        issuerTrusted = trustResult.trusted;
        issuerRevoked = trustResult.revoked;
        if (trustResult.trusted) {
            issuer = {
                certificateInfo: getCertificateInfo(certificate),
                certificate: { data: trustResult.matchedCertificate, format: 'pem' },
            };
        }
    } else {
        // Fall back to trusted-issuer-registry
        issuer = await getIssuer(certificate);
        issuerTrusted = !!issuer;
    }

    // Check Token Status List if present in MSO and enabled
    // Support both standard 'status' (RFC 9597) and vendor-prefixed '_status' (MATTR)
    const msoStatusInfo = issuerAuthPayload.status || issuerAuthPayload._status;
    if (msoStatusInfo && verificationOptions.enableStatusList) {
        const statusList = msoStatusInfo.statusList || msoStatusInfo.status_list;
        if (statusList) {
            statusListRef = {
                uri: statusList.uri,
                index: statusList.idx ?? statusList.index,
            };
            const statusResult = await checkTokenStatusList(statusListRef, {
                enabled: true,
                cacheTtlMs: verificationOptions.statusListCacheTtlMs,
            });
            credentialRevoked = statusResult.revoked;
        }
    }

    const credentialVerified = valid && deviceValid && claimsValid;

    return {
        claims,
        issuer,
        valid: credentialVerified && issuerTrusted && !issuerRevoked && !credentialRevoked,
        credentialVerified,
        issuerTrusted,
        issuerRevoked,
        credentialRevoked,
        statusListRef,
        invalidReasons: [
            ...invalidReasons,
            ...(issuerRevoked ? ['Issuer certificate revoked via CRL'] : []),
            ...(credentialRevoked ? ['Credential revoked via status list'] : []),
        ],
    };
};

async function verifyIssuerAuth(issuerAuth) {
    let invalidReason, certificate;
    const [protectedHeadersRaw, unprotectedHeaders, payloadRaw, _signatureRaw] = issuerAuth;
    const protectedHeaders = await cbor2.decode(protectedHeadersRaw);
    const payload = await cbor2.decode(payloadRaw);
    const issuerAuthPayload = cbor2.decode(payload.contents); //This is the Mobile Security Object (MSO)
    const now = new Date();
    if(new Date(issuerAuthPayload.validityInfo.validFrom) > now) {
        invalidReason = 'MSO is not yet valid';
    } else if(new Date(issuerAuthPayload.validityInfo.validUntil) < now) {
        invalidReason = 'MSO is expired';
    }
    // Always extract the certificate for issuer info, even if MSO validity failed
    const coseAlg = protectedHeaders.get(1);
    //https://datatracker.ietf.org/doc/rfc9360/
    const x5bag = unprotectedHeaders.get(32);
    const x5chain = unprotectedHeaders.get(33);
    const x5t = unprotectedHeaders.get(34);
    const x5u = unprotectedHeaders.get(35);
    if(x5bag) {
    } else if(x5chain) {
        certificate = parseX5Chain(x5chain);
    } else if(x5t) {
    } else if(x5u) {
    }

    if(!invalidReason) {
        if(certificate) {
            const publicKey = await x509ToWebCryptoKey(certificate, coseAlg);
            const signatureValid = await verifyCoseSign1(issuerAuth, publicKey);
            if(!signatureValid)
                invalidReason = 'IssuerAuth signature verification failed';
        } else {
            invalidReason = 'No certificate found in IssuerAuth header';
        }
    }

    return {
        certificate: certificate,
        issuerAuthPayload: issuerAuthPayload,
        valid: !invalidReason,
        invalidReason: invalidReason,
    };
}

async function verifyDeviceAuth(deviceSigned, issuerAuthPayload, sessionTranscript) {
    const { deviceAuth, nameSpaces } = deviceSigned;
    const { deviceSignature } = deviceAuth;
    const { deviceKeyInfo, docType } = issuerAuthPayload;
    const deviceKey = await coseKeyToWebCryptoKey(deviceKeyInfo.deviceKey);
    const deviceAuthentication = cbor2.encode(['DeviceAuthentication', cbor2.decode(sessionTranscript), docType, nameSpaces]);
    const encodedDeviceAuthentication = cbor2.encode(new cbor2.Tag(24, deviceAuthentication));
    //console.log('encodedDeviceAuthentication as hex', Array.from(encodedDeviceAuthentication).map(b => b.toString(16).padStart(2, '0')).join(''));
    const signatureValid = await verifyCoseSign1([deviceSignature[0], deviceSignature[1], encodedDeviceAuthentication, deviceSignature[3]], deviceKey);
    return signatureValid;
}

async function setClaim(claims, docType, namespace, claim, issuerAuthPayload) {
    const { isValid, decodedClaim } = await verifyClaim(namespace, claim, issuerAuthPayload);
    let claimIdentifier = decodedClaim.elementIdentifier;
    let claimValue = decodedClaim.elementValue;
    if(claimValue.tag === 1004) {
        claimValue = claimValue.contents;
    } else if(namespace === 'org.iso.18013.5.1') {
        if(claimIdentifier === 'sex' && typeof claimValue === 'number') {
            claimValue = claimValue === 1 ? 'M' : claimValue === 2 ? 'F' : null;
        } else if(claimIdentifier === 'driving_privileges' && claimValue && claimValue.length > 0) {
            claimValue = JSON.parse(JSON.stringify(claimValue));
            for(const privilege of claimValue) {
                for(const key in privilege) {
                    if(privilege[key]?.tag === 1004) {
                        privilege[key] = privilege[key].contents;
                    }
                }
            }
        }
    } else if(namespace === 'org.iso.23220.1') {
        if(claimIdentifier === 'birth_date' && claimValue.birth_date && claimValue.birth_date.tag === 1004) {
            claimValue = claimValue.birth_date.contents;
        } else if(claimIdentifier === 'sex' && typeof claimValue === 'number') {
            claimValue = claimValue === 1 ? 'M' : claimValue === 2 ? 'F' : null;
        }
    } else if(namespace === 'eu.europa.ec.eudi.pid.1') {
        if(claimIdentifier === 'sex' && typeof claimValue === 'number') {
            claimValue = claimValue === 1 ? 'M' : claimValue === 2 ? 'F' : null;
        }
    }
    const reverseClaimMapping = REVERSE_CLAIM_MAPPINGS[CredentialFormat.MSO_MDOC][docType][claimIdentifier];
    if(reverseClaimMapping) claimIdentifier = reverseClaimMapping;
    claims[claimIdentifier] = claimValue;
    return isValid;
}

async function verifyClaim(namespace, claim, issuerAuthPayload) {
    const decodedClaim = cbor2.decode(claim.contents);
    const digestId = decodedClaim.digestID;
    const digest = issuerAuthPayload.valueDigests[namespace].get(digestId);
    const encodedClaim = cbor2.encode(claim);
    const sha256 = await crypto.subtle.digest('SHA-256', encodedClaim);
    const sha256Uint8Array = new Uint8Array(sha256);
    return {
        isValid: uint8ArrayBytewiseEqual(sha256Uint8Array, digest),
        decodedClaim: decodedClaim
    };
}

function uint8ArrayBytewiseEqual(a, b) {
    return a.length === b.length && a.every((value, index) => value === b[index]);
}