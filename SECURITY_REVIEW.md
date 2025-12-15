# StampTime Security / Evidence Review (2025-12-15)

This document summarizes a security-oriented ("red team") review of StampTime focused on **court-grade timestamp verification** and resistance to "looks valid but isn't trusted" failure modes.

## Key finding: "hash-only verification" is not TSA trust verification

An RFC3161 timestamp file (`.tsr`) contains a *message imprint* (hash of the document) and a TSA-signed token.

- A **hash match** proves: *"this `.tsr` claims to timestamp a document with this hash."*
- A **trust-anchored cryptographic verification** proves: *"a TSA certificate chain that we trust signed this token."*

For legal admissibility, you typically need both.

## Fix implemented in this repo

### 1) `stamp verify` now supports strict TSA verification

`stamp verify` supports:

- `--query-file <file.tsq>`: the original query used at creation time (required for cryptographic verification)
- `--tsa-cert <chain.pem>`: a trusted CA chain bundle anchoring trust
- `--hash-only`: explicitly request the weaker integrity-only check

If `.tsq` is not provided, the tool tries to infer it by replacing `.tsr` with `.tsq` in the same directory.

### 2) "verify after creation" now uses the configured CA chain (if present)

Timestamp creation verification now prefers trust-anchored verification using the user-provided `--tsa-cert` (stored as `tsa_cert_path` in config).
If no chain is provided, the tool warns and skips trust-anchored verification rather than falsely implying "court-grade" verification.

### 3) Warning for HTTP TSA URLs

The default TSA URL historically used `http://...`. The tool now warns when the TSA endpoint is HTTP because on-path attackers can tamper with responses unless you perform strict trust-anchored verification.

## Concrete attack scenario (what this prevents)

If a verifier only checks "hash matches imprint," an attacker can:

1. Run their own TSA with their own (untrusted) certificate.
2. Produce a valid RFC3161 response (`.tsr`) for a chosen document hash.
3. Provide that `.tsr` alongside the document.

Hash-only verification would pass, despite the timestamp being issued by an untrusted authority.
Strict verification prevents this by requiring the TSA signature to validate against a known trust chain.

## Evidence bundle to preserve

For each document you plan to use in legal proceedings, preserve:

- The **original file**
- The **timestamp response**: `file.tsr`
- The **timestamp query**: `file.tsq` (critical for strict verification)
- The **trusted CA chain bundle** used to verify (e.g., `digicert_tsa_chain.pem`)
- Optional: tool output logs + your chain-of-custody documentation

## Known limitations (not solved here)

- **Revocation / long-term validation (LTV)**: This tool does not currently validate OCSP/CRLs nor produce an archival validation package. Court-grade long-term validation often requires preserving revocation evidence at/near signing time.
- **Time accuracy assurance**: A TSA timestamp is only as reliable as the TSA's audited time source and policy. Choose an accredited TSA and retain its policy references.
- **Platform dependency**: Verification relies on the system `openssl` binary and its behavior/version.

---

## Blockchain Anchoring (NEW - December 2025)

### Ultra-solid timestamps via "belt and suspenders" approach

StampTime now supports **blockchain anchoring** via OpenTimestamps, creating a secondary proof layer anchored in the Bitcoin blockchain. This provides:

1. **Decentralized trust**: No single entity can modify or revoke the timestamp
2. **Immutability**: Would require a 51% attack on Bitcoin to modify
3. **Permanence**: Bitcoin's 15+ year track record of security
4. **Independent verification**: Anyone can verify without contacting any authority

### How to use

```bash
# Create both RFC 3161 and blockchain timestamps
stamp blockchain anchor document.pdf --with-rfc3161

# After Bitcoin confirmation (1-24 hours), upgrade the proof
stamp blockchain upgrade document.pdf.ots

# Verify both proofs
stamp blockchain verify-anchor document.pdf --with-rfc3161
```

### Legal recognition of blockchain timestamps

- **El Salvador**: Official government documents timestamped on Bitcoin (2024)
- **US Courts**: Increasingly accepting blockchain evidence
- **EU (eIDAS 2.0)**: Exploring blockchain trust services
- **Academic/Research**: Widely accepted for manuscript timestamps

### Attack resistance with dual proofs

| Attack Scenario | RFC 3161 Alone | + Blockchain |
|-----------------|----------------|--------------|
| TSA compromise | Vulnerable | Protected (independent proof) |
| TSA ceases operation | Vulnerable | Protected (permanent) |
| Blockchain reorg | N/A | Protected (RFC 3161 backup) |
| Both attacked | N/A | Astronomically improbable |

### See also

- `LEGAL_EVIDENCE_GUIDE.md` - Comprehensive legal evidence documentation
- `stamp blockchain explain` - Detailed explanation of blockchain timestamping
