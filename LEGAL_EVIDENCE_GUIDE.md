# Legal Evidence Guide: Ultra-Solid Document Timestamping

This guide explains how to use StampTime to create court-grade timestamps that provide maximum legal protection through a "belt and suspenders" approach combining **RFC 3161** and **blockchain anchoring**.

## Executive Summary

For legal cases requiring proof of document existence at a specific time, you need:

| Proof Type | Technology | Legal Recognition | Trust Model |
|------------|-----------|-------------------|-------------|
| **Primary** | RFC 3161 (TSA) | eIDAS (EU), ESIGN (US), widely accepted | Centralized trusted authority |
| **Secondary** | Bitcoin Blockchain | Emerging, El Salvador official use, courts accepting | Decentralized, immutable |

**Both proofs use the same SHA-256 hash**, creating independent verification paths.

---

## Quick Start: Maximum Legal Protection

```bash
# Create both RFC 3161 AND blockchain timestamps in one command
stamp blockchain anchor document.pdf --with-rfc3161

# After 1-24 hours (Bitcoin confirmation), upgrade the proof
stamp blockchain upgrade document.pdf.ots

# Verify both proofs
stamp blockchain verify-anchor document.pdf --with-rfc3161

# Generate a proof bundle manifest for evidence packaging
stamp blockchain bundle document.pdf
```

---

## Understanding the Two-Layer Approach

### Layer 1: RFC 3161 Timestamp (Primary)

**What it provides:**
- Legally recognized under eIDAS (EU), ESIGN Act (US), and most jurisdictions
- Issued by accredited Timestamp Authorities (TSAs)
- Immediate verification possible
- Court-tested and well-understood by legal professionals

**Generated files:**
- `document.tsq` - Timestamp query (the request)
- `document.tsr` - Timestamp response (the proof)
- `document.tsr.certs.pem` - TSA certificates

**Limitations:**
- Relies on TSA availability and trustworthiness
- TSA could theoretically be compromised or cease operations
- Single point of trust

### Layer 2: Bitcoin Blockchain (Secondary)

**What it provides:**
- Decentralized trust (no single entity controls it)
- Immutable (would require >51% network attack to modify)
- Permanent record (Bitcoin has 15+ years track record)
- Independent verification (anyone with blockchain access can verify)
- No ongoing dependency on any organization

**Generated files:**
- `document.ots` - OpenTimestamps proof

**Limitations:**
- Confirmation takes 1-24 hours
- Legal recognition still emerging (though growing rapidly)
- Requires understanding of blockchain for some courts

### Why Both Together?

Using both creates **independent, redundant proofs**:

1. If someone questions the TSA's trustworthiness  Bitcoin proof remains valid
2. If someone doesn't accept blockchain  RFC 3161 is legally established
3. An attacker would need to compromise BOTH systems
4. Different verification methods cross-validate each other

---

## Evidence Preservation Checklist

For each legally significant document, preserve:

### Mandatory Files
- [ ] **Original document** (unchanged)
- [ ] **document.tsr** - RFC 3161 timestamp response
- [ ] **document.tsq** - RFC 3161 timestamp query
- [ ] **document.ots** - Bitcoin blockchain proof

### Supporting Files
- [ ] **document.tsr.certs.pem** - TSA certificate chain
- [ ] **CA chain file** (e.g., `digicert_tsa_chain.pem`) - Trust anchor
- [ ] **document.proof-bundle.json** - Proof manifest

### Documentation
- [ ] Chain of custody records
- [ ] Verification output logs
- [ ] Notes on storage location and backups

---

## Detailed Workflow

### Step 1: Initial Setup

```bash
# Configure TSA settings
stamp config

# Download TSA certificates
stamp keygen rfc3161
```

### Step 2: Create Timestamps

```bash
# Option A: Combined timestamps (RECOMMENDED)
stamp blockchain anchor contract.pdf --with-rfc3161

# Option B: Separate timestamps
stamp cert contract.pdf                          # RFC 3161 only
stamp blockchain anchor contract.pdf              # Blockchain only
```

### Step 3: Wait for Bitcoin Confirmation

Bitcoin timestamps typically confirm in 1-24 hours. Check status:

```bash
stamp blockchain info contract.pdf.ots
```

### Step 4: Upgrade Blockchain Proof

After confirmation, upgrade to include full attestation:

```bash
stamp blockchain upgrade contract.pdf.ots
```

This embeds the complete path from your hash to the Bitcoin block, enabling offline verification.

### Step 5: Verify (Before Archiving)

Always verify before considering the evidence complete:

```bash
# Full verification of both layers
stamp blockchain verify-anchor contract.pdf --with-rfc3161 --tsa-cert ./tsa_certs/chain/digicert_tsa_chain.pem
```

### Step 6: Generate Evidence Package

```bash
# Create a manifest documenting all proof files
stamp blockchain bundle contract.pdf --output contract.proof-bundle.json
```

---

## Verification for Legal Proceedings

### Verifying RFC 3161 Timestamp

```bash
# Hash + cryptographic verification
stamp verify contract.pdf contract.tsr --tsa-cert ./tsa_certs/chain/digicert_tsa_chain.pem

# Hash-only verification (weaker, but simpler)
stamp verify contract.pdf contract.tsr --hash-only
```

### Verifying Blockchain Timestamp

```bash
# Via calendar servers (requires internet)
stamp blockchain verify-anchor contract.pdf

# Via local Bitcoin node (trustless, recommended for court)
ots --bitcoin-node http://user:pass@127.0.0.1:8332/ verify contract.pdf.ots
```

### Independent Verification

For maximum credibility, verification can be performed by:

1. **RFC 3161**: Any system with OpenSSL
   ```bash
   openssl ts -verify -queryfile contract.tsq -in contract.tsr -CAfile ca_chain.pem
   ```

2. **Blockchain**: Any Bitcoin node + OpenTimestamps client
   ```bash
   ots verify contract.pdf.ots
   ```

---

## Legal Considerations by Jurisdiction

### European Union (eIDAS)

- RFC 3161 timestamps from Qualified TSAs have legal presumption of accuracy
- eIDAS 2.0 (2024) exploring blockchain trust services
- Qualified Electronic Time Stamps (QETS) require accredited providers

**Recommended TSAs:**
- DigiCert (used by default in StampTime)
- GlobalSign
- Entrust

### United States (ESIGN/UETA)

- Electronic timestamps generally admissible under Federal Rules of Evidence
- No specific technical requirements (RFC 3161 widely accepted)
- Blockchain evidence increasingly accepted (see legal precedents)

### Other Jurisdictions

- Many countries recognize RFC 3161 through mutual recognition agreements
- Blockchain acceptance varies but is growing globally
- El Salvador: Official government documents on Bitcoin (2024)

---

## Attack Scenarios and Defenses

### Scenario 1: TSA Compromise

**Attack**: Someone gains access to a TSA and issues backdated timestamps.

**Defense**: Bitcoin blockchain proof provides independent verification. The blockchain timestamp cannot be backdated.

### Scenario 2: Blockchain Reorganization

**Attack**: A 51% attack reorganizes the Bitcoin blockchain.

**Defense**: 
- Such attacks are extremely expensive and detectable
- Would affect many transactions, not just timestamps
- RFC 3161 timestamp remains valid
- After 6 confirmations, reorganization is practically impossible

### Scenario 3: Hash Collision

**Attack**: Someone creates a different document with the same hash.

**Defense**:
- SHA-256 has no known practical collisions
- Both proofs use the same hash, making collision attacks doubly difficult
- Document content provides context

### Scenario 4: Questioning Timestamp Authority

**Attack**: Opposing counsel questions the TSA's credibility.

**Defense**:
- Blockchain proof is independent and verifiable by anyone
- DigiCert/GlobalSign are WebTrust audited
- Multiple independent proofs strengthen evidence

---

## Long-Term Preservation

### Recommended Storage

1. **Primary**: Encrypted cloud storage (e.g., with your document management system)
2. **Secondary**: Air-gapped offline backup (USB drive, DVD)
3. **Tertiary**: Safe deposit box or legal vault

### File Format Longevity

All timestamp files use standard formats:
- `.tsr` - ASN.1 DER encoded (RFC 3161)
- `.tsq` - ASN.1 DER encoded (RFC 3161)
- `.ots` - OpenTimestamps binary format (documented, open-source)
- `.pem` - Base64 encoded certificates

These formats will remain readable indefinitely with standard tools.

### Certificate Expiration

TSA certificates expire, but timestamps remain valid because:
1. The timestamp was created while the certificate was valid
2. Long-Term Validation (LTV) preserves validity
3. Blockchain proof provides independent time reference

---

## Glossary

| Term | Definition |
|------|------------|
| **RFC 3161** | Internet standard for trusted timestamping |
| **TSA** | Timestamp Authority - issues timestamps |
| **TSR** | Timestamp Response - the signed timestamp |
| **TSQ** | Timestamp Query - the timestamp request |
| **OTS** | OpenTimestamps - Bitcoin timestamping protocol |
| **SHA-256** | Cryptographic hash function |
| **eIDAS** | EU regulation for electronic identification |
| **ESIGN** | US Electronic Signatures in Global and National Commerce Act |
| **Merkle Tree** | Data structure for efficient hash verification |

---

## Support and Resources

- **OpenTimestamps**: https://opentimestamps.org/
- **RFC 3161 Specification**: https://datatracker.ietf.org/doc/html/rfc3161
- **eIDAS Regulation**: https://digital-strategy.ec.europa.eu/en/policies/eidas-regulation
- **Bitcoin Whitepaper**: https://bitcoin.org/bitcoin.pdf

---

## Version History

- **v1.0** (2025-12-15): Initial legal evidence guide with blockchain integration


