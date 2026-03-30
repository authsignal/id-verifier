# OID4VP Redirect Flows

Supporting OID4VP redirect-based flows would enable same-device and cross-device credential presentation without requiring browser support for the W3C Digital Credentials API.

## What's Needed

### Protocol Support
- [ ] Signed JWT request objects with `x5c` certificate chain
- [ ] JWE response decryption (ECDH-ES + A256GCM)
- [ ] `direct_post` and `direct_post.jwt` response modes
- [ ] Configurable wallet URL scheme (`openid4vp://`, `mdoc-openid4vp://`)

### Query Formats
- [ ] DCQL (OID4VP 1.0)
- [ ] Presentation Exchange (ISO 18013-7 / OID4VP draft 18)

### Client Identification
- [ ] `x509_hash` (OID4VP 1.0 / HAIP)
- [ ] `x509_san_dns` (ISO 18013-7)

### SessionTranscript
- [ ] `OpenID4VPHandover` (OID4VP 1.0 Appendix B.2.6.1)
- [ ] ISO 18013-7 Annex B handover with `mdocGeneratedNonce`

### Credential Trust & Revocation
- [ ] Issuer certificate chain validation against provided root/IACA certificates
- [ ] CRL distribution point checking
- [ ] IETF Token Status List (RFC 9597) — JWT and CWT formats

## References
- [OID4VP 1.0](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html)
- [HAIP 1.0](https://openid.net/specs/openid4vc-high-assurance-interoperability-profile-1_0.html)
- [ISO 18013-7:2025](https://www.iso.org/standard/82772.html)
- [RFC 9597 — Token Status List](https://datatracker.ietf.org/doc/rfc9597/)
