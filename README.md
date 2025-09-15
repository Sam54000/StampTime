# StampTime

A humble try of a CLI for RFC3161 cryptographic timestamping operations, written in Rust.

## What It Does

StampTime creates cryptographic timestamps that prove a file existed at a specific point in time. The process begins by generating a SHA-256 hash of the file, which serves as a unique digital fingerprint. This hash is then sent to a trusted Timestamp Authority (TSA) server, which cryptographically signs the hash along with the current timestamp, creating an immutable record. Later verification is performed by comparing the current file's hash against the timestamped hash to ensure the file remains unchanged.

## Real-World Use Case

Consider a scenario where an author creates a legal document and needs to prove its authenticity in a potential dispute. The author first timestamps the document using StampTime, then sends both the document and its timestamp to a recipient. 

If a dispute later arises, the recipient might claim that the document they received is the original version, even if they have modified it. However, the timestamp provides irrefutable proof of tampering. When the author's original document is verified against its timestamp, the hash matches perfectly, confirming the document's authenticity. In contrast, when the recipient's modified version is checked, the hash differs from the timestamped value, proving that the file was altered after the original timestamp was created.

This cryptographic evidence provides strong legal protection, intellectual property safeguards, and reliable audit trails. Any modification to a timestamped file will cause verification to fail, making tampering immediately detectable and legally provable.

# Overview

StampTime provides a single, unified interface for all timestamping operations through the `stamp` command with subcommands:

1. **`stamp config`** - Configuration management (interactive setup and key-value operations)
2. **`stamp keygen`** - Certificate and key generation (RFC3161 certificates and PKCS#12)
3. **`stamp cert`** - File timestamping (single file or batch processing)
4. **`stamp verify`** - Timestamp verification

# Quick Start

## Basic Usage

```bash
# 1. Configure TSA settings (interactive)
stamp config

# 2. Download certificates
stamp keygen rfc3161

# 3. Generate signing certificate
stamp keygen pkcs12 "Your Name"

# 4. Timestamp a single file
stamp cert document.pdf

# 5. Timestamp all files in a directory
stamp cert --batch ./documents --output ./timestamps

# 6. Verify a timestamp
stamp verify document.pdf document.pdf.tsr
```

# Configuration Management (`stamp config`)

## Interactive Configuration Setup
```bash
stamp config
```
This launches an interactive session to configure all TSA settings, certificate URLs, and storage paths.

## Set Configuration Values
```bash
stamp config tsa.url "http://timestamp.digicert.com"
stamp config certificates.sha256_responder "https://knowledge.digicert.com/content/dam/kb/attachments/time-stamp/DigiCertSHA256RSA4096TimestampResponder20251.cer"
stamp config path.base "./tsa_certs"
```

## Get Configuration Values
```bash
stamp config tsa.url
stamp config certificates.sha256_responder
```

## Available Configuration Keys
- `tsa.url` - TSA server URL
- `certificates.sha256_responder` - SHA256 responder certificate URL
- `certificates.sha384_responder` - SHA384 responder certificate URL (optional)
- `certificates.sha512_responder` - SHA512 responder certificate URL (optional)
- `certificates.intermediate` - Intermediate certificate URL
- `certificates.root` - Root certificate URL
- `path.base` - Base directory for storing certificates
- `path.chain_dir` - Chain subdirectory name
- `path.chain_filename` - Certificate chain filename

## Automated Installation (Recommended)

```bash
# Make installation script executable
chmod +x install.sh

# Install to default location (~/.local/bin)
./install.sh

# Or specify custom location
./install.sh /usr/local/bin
./install.sh ~/bin
```

The installation script automatically:
- Checks dependencies (Rust, OpenSSL, curl)
- Compiles all tools in release mode
- Installs binaries and verification script
- Configures PATH (with instructions)
- Tests the installation

## Manual Building

```bash
# Build all tools
cargo build --release

# Build specific tool
cargo build --release --bin stamp
```

## Manual Installation

```bash
# Install to system PATH
cargo install --path stamp
```

## Usage

### TSA Setup and Configuration

```bash
# Interactive configuration setup
stamp config

# Get specific configuration value
stamp config tsa.url

# Set specific configuration value
stamp config tsa.url "http://timestamp.digicert.com"

# Download RFC3161 certificates
stamp keygen rfc3161
```

### RFC3161 Timestamping

```bash
# Basic usage - timestamp any file
stamp cert document.pdf

# Specify output directory
stamp cert document.pdf --output /path/to/timestamp/files

# Use custom TSA server
stamp cert document.pdf --tsa-url http://timestamp.globalsign.com

# Use custom certificate (overrides config)
stamp cert document.pdf --tsa-cert /path/to/cert.pem

# Verbose output
stamp cert document.pdf --verbose

# Batch processing - timestamp all files in a directory
stamp cert --batch ./documents --output ./timestamps

# Recursive batch processing
stamp cert --batch ./documents --recursive --output ./timestamps

# Dry run to see what would be processed
stamp cert --batch ./documents --dry-run
```

### Batch Timestamping

```bash
# Timestamp all files in a directory
stamp cert --batch input_dir --output output_dir

# Recursive processing
stamp cert --batch input_dir --output output_dir --recursive

# Dry run to see what would be processed
stamp cert --batch input_dir --output output_dir --dry-run
```

### PKCS#12 Certificate Creation

```bash
# Create a new certificate (interactive password input)
stamp keygen pkcs12 "Your Name"

# Create with custom output directory
stamp keygen pkcs12 "Test User" --output-dir /path/to/certs

# Create with custom settings
stamp keygen pkcs12 "Test User" --days 3650 --key-size 4096 --filename "my_cert.p12"
```

# Tool Specifications

## `stamp` - Unified RFC3161 Timestamping Tool

**Purpose**: Unified command-line tool for RFC3161 timestamping operations with configuration management, certificate generation, and timestamping capabilities.

**Usage**:
```bash
stamp <command> [options]
```

**Subcommands**:
- `config` - Configuration management
- `keygen` - Certificate and key generation
- `cert` - File timestamping
- `verify` - Timestamp verification

## `stamp config`

**Purpose**: Manage TSA configuration settings

**Usage**:
```bash
stamp config [key] [value]
```

**Options**:
- Interactive setup: `stamp config` (no arguments)
- Get value: `stamp config <key>`
- Set value: `stamp config <key> <value>`

**Configuration Keys**:
- `tsa.url` - TSA server URL
- `certificates.sha256_responder` - SHA256 responder certificate URL
- `certificates.sha384_responder` - SHA384 responder certificate URL (optional)
- `certificates.sha512_responder` - SHA512 responder certificate URL (optional)
- `certificates.intermediate` - Intermediate certificate URL
- `certificates.root` - Root certificate URL
- `path.base` - Base certificate directory
- `path.chain_dir` - Chain subdirectory name
- `path.chain_filename` - Certificate chain filename

**Configuration File** (`config.toml`):
```toml
[tsa]
url = "http://timestamp.digicert.com"

[certificates]
sha256_responder = "https://..."
sha384_responder = "https://..."  # Optional
sha512_responder = "https://..."  # Optional
intermediate = "https://..."
root = "https://..."

[path]
base = "./tsa_certs"
chain_dir = "chain"
chain_filename = "digicert_tsa_chain.pem"
```

## `stamp keygen`

**Purpose**: Generate certificates and download RFC3161 certificates

**Usage**:
```bash
stamp keygen <type> [options]
```

**Subcommands**:
- `rfc3161` - Download RFC3161 certificates
- `pkcs12` - Generate PKCS#12 certificate

### `stamp keygen rfc3161`

**Purpose**: Download RFC3161 certificates from configured URLs

**Usage**:
```bash
stamp keygen rfc3161
```

### `stamp keygen pkcs12`

**Purpose**: Create PKCS#12 certificates with timestamping

**Usage**:
```bash
stamp keygen pkcs12 <common_name> [options]
```

**Arguments**:
- `common_name` (required): Common name for the certificate

**Options**:
- Password: Interactive password input (prompted securely, required)
- `--days`: Validity period in days (default: 3650)
- `--filename`: Output filename for the PKCS#12 file (default: "signer.p12")
- `--key-size`: RSA key size in bits (default: 3072)
- `--output-dir`: Output directory for certificate files
- `--tsa-url`: TSA URL for timestamping

**Examples**:
```bash
stamp keygen pkcs12 "Your Name"
stamp keygen pkcs12 "Your Name" --days 3650 --key-size 3072 --filename "my_cert.p12"
```

**Generated Files**:
- `cert.pem` - Certificate file
- `signer.p12` - PKCS#12 file
- `signer.p12.tsq` - Timestamp query
- `signer.p12.tsr` - Timestamp response
- `signer.p12.tsr.certs.pem` - Certificate chain

## `stamp cert`

**Purpose**: Add RFC3161 cryptographic timestamps to files

**Usage**:
```bash
stamp cert <input> [options]
```

**Arguments**:
- `input` (required): Path to input file or directory

**Options**:
- `--output, -o`: Output directory for timestamp files
- `--batch`: Process all files in input directory
- `--tsa-url`: URL of the timestamp authority
- `--tsa-cert`: Path to TSA certificate chain
- `--no-verify`: Skip timestamp verification after creation
- `--recursive, -r`: Process subdirectories recursively (batch mode)
- `--dry-run`: Show what would be processed without actually doing it
- `--verbose, -v`: Enable verbose output

**Single File Examples**:
```bash
stamp cert document.pdf
stamp cert document.pdf --output ./timestamps
stamp cert document.pdf --tsa-url "http://timestamp.digicert.com" --tsa-cert ./certs/chain.pem
```

**Batch Processing Examples**:
```bash
stamp cert --batch ./documents --output ./timestamps
stamp cert --batch ./documents --recursive --dry-run
```

**Generated Files**:
- `{filename}.tsq` - Timestamp query
- `{filename}.tsr` - Timestamp response
- `{filename}.tsr.certs.pem` - Certificate chain

## `stamp verify`

**Purpose**: Verify RFC3161 timestamps

**Usage**:
```bash
stamp verify <file> <timestamp_file>
```

**Arguments**:
- `file` (required): Original file to verify
- `timestamp_file` (required): Timestamp file (.tsr)

**Exit Codes**:
- `0` - Success
- `1` - Error

# Examples

## Complete Setup Workflow
```bash
# 1. Configure TSA settings
stamp config

# 2. Download certificates
stamp keygen rfc3161

# 3. Generate signing certificate
stamp keygen pkcs12 "John Doe"

# 4. Timestamp a single file
stamp cert document.pdf

# 5. Timestamp all files in a directory
stamp cert --batch ./documents --output ./timestamps

# 6. Verify a timestamp
stamp verify document.pdf document.pdf.tsr
```

## Quick Configuration Changes
```bash
# Change TSA URL
stamp config tsa.url "https://timestamp.example.com"

# Update certificate URL
stamp config certificates.sha256_responder "https://new-cert-url.com/cert.cer"

# Check current configuration
stamp config tsa.url
```

## Timestamp Verification Details
The `stamp verify` command verifies that:
1. The timestamp file is valid
2. The file's current hash matches the timestamped hash
3. The timestamp was issued by a trusted authority

```bash
stamp verify document.pdf document.pdf.tsr
stamp verify data.json data.json.tsr
stamp verify image.jpg image.jpg.tsr
```

# Configuration File

The tool uses `config.toml` for configuration storage. This file is automatically created during interactive setup or when setting individual values.

Example `config.toml`:
```toml
[tsa]
url = "http://timestamp.digicert.com"

[certificates]
sha256_responder = "https://knowledge.digicert.com/content/dam/kb/attachments/time-stamp/DigiCertSHA256RSA4096TimestampResponder20251.cer"
sha384_responder = "https://knowledge.digicert.com/content/dam/kb/attachments/time-stamp/DigiCertSHA384RSA4096TimestampResponder20251.cer"
sha512_responder = "https://knowledge.digicert.com/content/dam/kb/attachments/time-stamp/DigiCertSHA512RSA4096TimestampResponder20251.cer"
intermediate = "https://knowledge.digicert.com/content/dam/kb/attachments/time-stamp/DigiCertTrustedG4TimeStampingRSA4096SHA2562025CA1.pem"
root = "https://knowledge.digicert.com/content/dam/kb/attachments/time-stamp/DigiCertTrustedRootG4.cer"

[path]
base = "./tsa_certs"
chain_dir = "chain"
chain_filename = "digicert_tsa_chain.pem"
```

# Help and Documentation

Get help for any command:
```bash
stamp --help
stamp config --help
stamp keygen --help
stamp keygen pkcs12 --help
stamp cert --help
stamp verify --help
```

# Future Implementation
- Batch Verify
- Try with other TSA
