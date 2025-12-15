//! Command-line interface structures and handlers
//!
//! Copyright (C) 2025 Dr. Samuel Louviot, Ph.D
//!
//! This program is free software: you can redistribute it and/or modify
//! it under the terms of the GNU General Public License as published by
//! the Free Software Foundation, either version 3 of the License, or
//! (at your option) any later version.
//!
//! This program is distributed in the hope that it will be useful,
//! but WITHOUT ANY WARRANTY; without even the implied warranty of
//! MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//! GNU General Public License for more details.
//!
//! You should have received a copy of the GNU General Public License
//! along with this program.  If not, see <https://www.gnu.org/licenses/>.
//!
//! Contact: tech.swerve263@slmail.me

use anyhow::{Context, Result as AnyhowResult};
use clap::{Parser, Subcommand};
use std::path::PathBuf;
use tracing::{error, info, warn};
use crate::config::{self, load_config_file, find_default_tsa_cert};
use crate::timestamp::{self, TimestampConfig, process_directory_batch, BatchResult};
use crate::certificates::{download_rfc3161_certificates, generate_pkcs12_certificate};
use crate::blockchain;

/// StampTime - RFC3161 Timestamping Tool
#[derive(Parser)]
#[command(
    name = "stamp",
    version = "0.1.0",
    about = "RFC3161 timestamping tool with configuration, certificate generation, and timestamping capabilities",
    long_about = "StampTime is a unified tool for RFC3161 timestamping operations.\n\nIt provides:\n- Configuration management (stamp config)\n- Certificate generation (stamp keygen)\n- File timestamping (stamp cert)\n- Timestamp verification (stamp verify)\n\nThe tool creates RFC3161 timestamps for any file using a trusted timestamp authority (TSA)."
)]
pub struct Args {
    /// Subcommand to execute
    #[command(subcommand)]
    pub command: Commands,
    
    /// Verbose output
    #[arg(short, long, help = "Enable verbose output")]
    pub verbose: bool,
}

/// Available subcommands
#[derive(Subcommand)]
pub enum Commands {
    Config {
        /// Configuration key (e.g., 'tsa.url', 'certificates.sha256_responder')
        key: Option<String>,
        /// Configuration value
        value: Option<String>,
    },
    /// Show warranty information
    #[command(name = "show w")]
    ShowWarranty,
    /// Show copying conditions
    #[command(name = "show c")]
    ShowCopying,
    /// Certificate and key generation
    Keygen {
        /// Type of key/certificate to generate
        #[command(subcommand)]
        keygen_type: KeygenType,
    },
    /// Timestamp files
    Cert {
        /// Input file or directory
        input: PathBuf,
        
        /// Output directory for timestamp files
        #[arg(short, long, help = "Directory for generated timestamp files")]
        output: Option<PathBuf>,
        
        /// Batch processing mode
        #[arg(long, help = "Process all files in input directory")]
        batch: bool,
        
        /// TSA URL
        #[arg(long, help = "URL of the timestamp authority")]
        tsa_url: Option<String>,
        
        /// TSA certificate path
        #[arg(long, help = "Path to TSA certificate chain")]
        tsa_cert: Option<PathBuf>,
        
        /// Disable verification
        #[arg(long, help = "Skip timestamp verification after creation")]
        no_verify: bool,
        
        /// Recursive processing (for batch mode)
        #[arg(short, long, help = "Process subdirectories recursively")]
        recursive: bool,
        
        /// Dry run - show what would be processed without actually doing it
        #[arg(long, help = "Show what would be processed without actually doing it")]
        dry_run: bool,
        
        /// Re-timestamp files that have changed since their last timestamp
        #[arg(long, help = "Re-timestamp files that have been modified since their last timestamp (checks file hash)")]
        re_timestamp: bool,
        
        /// Use git to detect file changes (faster than hash comparison)
        #[arg(long, help = "Use git to detect file changes for re-timestamping (requires git repository)")]
        use_git: bool,
        
        /// Verbose logging - show detailed file processing logs in real-time
        #[arg(short, long, help = "Show detailed file processing logs with timestamps and status")]
        verbose: bool,
        
        /// Clean up orphaned timestamp files (remove timestamps for files no longer in source)
        #[arg(long, help = "Remove timestamp files for files that no longer exist in source directory (requires --use-git)")]
        cleanup: bool,
    },
    /// Verify timestamp files
    Verify {
        /// Original file to verify
        file: PathBuf,
        
        /// Timestamp file (.tsr)
        timestamp_file: PathBuf,

        /// Timestamp query file (.tsq). Required for cryptographic verification of the TSA response.
        /// If omitted, the tool will try to infer it by replacing the timestamp file extension with .tsq.
        #[arg(long, help = "Path to the timestamp query file (.tsq) used when the timestamp was created")]
        query_file: Option<PathBuf>,

        /// TSA certificate chain used to anchor trust (e.g., digicert_tsa_chain.pem).
        /// If omitted, the tool will try to find a default chain from config/known locations.
        #[arg(long, help = "Path to a trusted TSA certificate chain file (PEM) used to verify the timestamp signature")]
        tsa_cert: Option<PathBuf>,

        /// Only perform hash comparison (checks document integrity vs TSR imprint) and skip TSA trust verification.
        /// This can be useful when you don't have the original .tsq or a trusted chain, but it is NOT court-grade verification.
        #[arg(long, help = "Skip cryptographic trust verification (hash-only check)")]
        hash_only: bool,
    },
    /// Inspect timestamp responses, queries, and certificates
    Inspect {
        /// File to inspect (timestamp response, query, or certificate)
        file: PathBuf,
    },
    /// Blockchain anchoring for ultra-solid legal timestamps
    Blockchain {
        /// Blockchain subcommand
        #[command(subcommand)]
        action: BlockchainAction,
    },
}

/// Blockchain subcommands for creating and verifying blockchain-anchored timestamps
#[derive(Subcommand)]
pub enum BlockchainAction {
    /// Create a blockchain timestamp (Bitcoin via OpenTimestamps)
    Anchor {
        /// File to timestamp on the blockchain
        file: PathBuf,
        
        /// Also create RFC 3161 timestamp (recommended for "belt and suspenders" approach)
        #[arg(long, help = "Also create RFC 3161 timestamp for maximum legal protection")]
        with_rfc3161: bool,
        
        /// TSA URL for RFC 3161 timestamp (if --with-rfc3161 is used)
        #[arg(long, help = "TSA URL for RFC 3161 timestamp")]
        tsa_url: Option<String>,
        
        /// TSA certificate path for RFC 3161 verification
        #[arg(long, help = "Path to TSA certificate chain")]
        tsa_cert: Option<PathBuf>,
    },
    /// Verify a blockchain timestamp
    VerifyAnchor {
        /// Original file
        file: PathBuf,
        
        /// OpenTimestamps proof file (.ots)
        #[arg(long, help = "Path to .ots proof file (defaults to <file>.ots)")]
        ots_file: Option<PathBuf>,
        
        /// Also verify RFC 3161 timestamp if present
        #[arg(long, help = "Also verify RFC 3161 timestamp (.tsr) if present")]
        with_rfc3161: bool,
        
        /// TSA certificate path for RFC 3161 verification
        #[arg(long, help = "Path to TSA certificate chain for RFC 3161 verification")]
        tsa_cert: Option<PathBuf>,
    },
    /// Upgrade a pending blockchain timestamp (after Bitcoin confirmation)
    Upgrade {
        /// OpenTimestamps proof file (.ots) to upgrade
        ots_file: PathBuf,
    },
    /// Show information about an OpenTimestamps proof
    Info {
        /// OpenTimestamps proof file (.ots)
        ots_file: PathBuf,
    },
    /// Show comprehensive information about blockchain timestamping
    Explain,
    /// Generate a combined proof bundle manifest (RFC 3161 + blockchain)
    Bundle {
        /// Original file
        file: PathBuf,
        
        /// Output path for the JSON manifest
        #[arg(long, help = "Output path for the proof bundle manifest")]
        output: Option<PathBuf>,
    },
}

/// Keygen subcommands
#[derive(Subcommand)]
pub enum KeygenType {
    /// Download RFC3161 certificates
    Rfc3161,
    /// Generate PKCS#12 certificate
    Pkcs12 {
        /// Common Name (CN) for the certificate
        common_name: String,
        
        /// Validity period in days
        #[arg(long, default_value = "3650", help = "Validity period in days")]
        days: u32,
        
        /// Output filename
        #[arg(long, default_value = "signer.p12", help = "Output filename for the PKCS#12 file")]
        filename: String,
        
        /// Key size in bits
        #[arg(long, default_value = "3072", help = "RSA key size in bits")]
        key_size: u32,
        
        /// Output directory
        #[arg(short, long, help = "Output directory for the certificate files")]
        output_dir: Option<PathBuf>,
        
        /// TSA URL for timestamping
        #[arg(long, help = "TSA URL for timestamping")]
        tsa_url: Option<String>,
    },
}

pub fn handle_config_command(key: Option<String>, value: Option<String>) -> AnyhowResult<()> {
    match (key, value) {
        (Some(k), Some(v)) => {
            config::set_config_value(&k, &v)?;
        }
        (Some(k), None) => {
            config::get_config_value(&k)?;
        }
        (None, None) => {
            config::interactive_config_setup()?;
        }
        (None, Some(_)) => {
            return Err(anyhow::anyhow!("Cannot set value without specifying key"));
        }
    }
    Ok(())
}

pub fn handle_keygen_command(keygen_type: KeygenType) -> AnyhowResult<()> {
    match keygen_type {
        KeygenType::Rfc3161 => {
            download_rfc3161_certificates()?;
        }
        KeygenType::Pkcs12 { 
            common_name, 
            days, 
            filename, 
            key_size, 
            output_dir, 
            tsa_url 
        } => {
            generate_pkcs12_certificate(common_name, days, filename, key_size, output_dir, tsa_url)?;
        }
    }
    Ok(())
}

pub fn handle_cert_command(
    input: PathBuf,
    output: Option<PathBuf>,
    batch: bool,
    tsa_url: Option<String>,
    tsa_cert: Option<PathBuf>,
    no_verify: bool,
    recursive: bool,
    dry_run: bool,
    re_timestamp: bool,
    use_git: bool,
    verbose: bool,
    cleanup: bool,
) -> AnyhowResult<()> {
    if batch {
        handle_batch_timestamping(input, output, tsa_url, tsa_cert, no_verify, recursive, dry_run, re_timestamp, use_git, verbose, cleanup)?;
    } else {
        handle_single_file_timestamping(input, output, tsa_url, tsa_cert, no_verify)?;
    }
    Ok(())
}

pub fn handle_verify_command(
    file: PathBuf,
    timestamp_file: PathBuf,
    query_file: Option<PathBuf>,
    tsa_cert: Option<PathBuf>,
    hash_only: bool,
) -> AnyhowResult<()> {
    info!("Verifying timestamp for file: {}", file.display());
    info!("Timestamp file: {}", timestamp_file.display());
    
    if !file.exists() {
        error!("Original file does not exist: {}", file.display());
        std::process::exit(1);
    }
    
    if !file.is_file() {
        error!("Original path is not a file: {}", file.display());
        std::process::exit(1);
    }
    
    if !timestamp_file.exists() {
        error!("Timestamp file does not exist: {}", timestamp_file.display());
        std::process::exit(1);
    }
    
    if !timestamp_file.is_file() {
        error!("Timestamp path is not a file: {}", timestamp_file.display());
        std::process::exit(1);
    }
    
    let hash_result = match timestamp::verify_timestamp(&file, &timestamp_file) {
        Ok(result) => {
            if !result.success {
                eprintln!("VERIFICATION FAILED");
                eprintln!("The file '{}' does NOT match its timestamp imprint", file.display());
                eprintln!("Hash comparison:");
                eprintln!("  Current file hash:  {}", result.current_hash);
                eprintln!("  Timestamped hash:   {}", result.timestamped_hash);
                eprintln!("This could mean:");
                eprintln!("   The file has been modified since timestamping");
                eprintln!("   The timestamp file is corrupted");
                eprintln!("   The files don't belong together");
                std::process::exit(1);
            }

            // If hash matches, we can optionally perform cryptographic verification of the TSA response.
            // Note: this requires BOTH the original .tsq and a trusted CA chain to anchor trust.
            // If either is missing, hash-only verification does not establish that a trusted TSA issued the timestamp.
            println!("HASH CHECK PASSED");
            println!("The file '{}' matches the timestamp imprint (integrity check)", file.display());
            println!("Timestamped on: {}", result.timestamp_date);
            println!("Hash algorithm: {}", result.hash_algorithm);
            result
        }
        Err(e) => {
            eprintln!("Error during verification: {}", e);
            std::process::exit(1);
        }
    };

    if hash_only {
        println!();
        println!("NOTE: Hash-only verification was requested (--hash-only).");
        println!("This confirms the file matches the imprint in the .tsr, but does NOT establish that a trusted TSA issued it.");
        std::process::exit(0);
    }

    // Determine query file path (needed for cryptographic verification)
    let inferred_tsq = if timestamp_file.extension().and_then(|e| e.to_str()).map(|e| e.eq_ignore_ascii_case("tsr")).unwrap_or(false) {
        timestamp_file.with_extension("tsq")
    } else {
        timestamp_file.with_extension("tsq")
    };

    let query_path = query_file.unwrap_or(inferred_tsq);
    if !query_path.exists() {
        eprintln!("ERROR: Timestamp query file (.tsq) not found: {}", query_path.display());
        eprintln!("Cryptographic TSA verification requires the ORIGINAL .tsq used at timestamp creation.");
        eprintln!("Provide it with --query-file, or re-run with --hash-only for a weaker (integrity-only) check.");
        std::process::exit(2);
    }

    // Determine trusted TSA chain path
    let ca_chain_path = tsa_cert.or_else(|| find_default_tsa_cert());
    let ca_chain_path = match ca_chain_path {
        Some(p) if p.exists() => p,
        Some(p) => {
            eprintln!("ERROR: TSA certificate chain not found: {}", p.display());
            eprintln!("Run `stamp keygen rfc3161` to download a default chain, or pass --tsa-cert <chain.pem>.");
            std::process::exit(2);
        }
        None => {
            eprintln!("ERROR: No TSA certificate chain provided/found.");
            eprintln!("Run `stamp keygen rfc3161` to download a default chain, or pass --tsa-cert <chain.pem>.");
            eprintln!("Without a trusted chain, you cannot establish that a trusted TSA issued this timestamp.");
            std::process::exit(2);
        }
    };

    // Cryptographic verification (trust-anchored)
    match timestamp::verify_timestamp_response_files(&timestamp_file, &query_path, &ca_chain_path) {
        Ok(true) => {
            println!();
            println!("CRYPTOGRAPHIC VERIFICATION PASSED");
            println!("The TSA signature and certificate chain validate against: {}", ca_chain_path.display());
            // Also print a short reminder about evidentiary bundle
            println!("Preserve as evidence: original file + .tsr + .tsq + CA chain used for verification.");
            std::process::exit(0);
        }
        Ok(false) => {
            eprintln!();
            eprintln!("CRYPTOGRAPHIC VERIFICATION FAILED");
            eprintln!("The .tsr could not be validated against the provided query/CA chain.");
            eprintln!("Hash matched (integrity), but TSA trust is NOT established.");
            eprintln!("File: {}", file.display());
            eprintln!("TSR:  {}", timestamp_file.display());
            eprintln!("TSQ:  {}", query_path.display());
            eprintln!("CA:   {}", ca_chain_path.display());
            // Keep hash_result in scope so the compiler doesn't warn about unused (and we may extend output later)
            let _ = hash_result;
            std::process::exit(1);
        }
        Err(e) => {
            eprintln!();
            eprintln!("Error during cryptographic verification: {}", e);
            let _ = hash_result;
            std::process::exit(1);
        }
    }
}

pub fn handle_inspect_command(file: PathBuf) -> AnyhowResult<()> {
    info!("Inspecting file: {}", file.display());
    
    if !file.exists() {
        error!("File does not exist: {}", file.display());
        std::process::exit(1);
    }
    
    if !file.is_file() {
        error!("Path is not a file: {}", file.display());
        std::process::exit(1);
    }
    
    match timestamp::inspect_file(&file) {
        Ok(_) => {
            std::process::exit(0);
        }
        Err(e) => {
            eprintln!("Error during inspection: {}", e);
            std::process::exit(1);
        }
    }
}

fn handle_single_file_timestamping(
    input: PathBuf,
    output: Option<PathBuf>,
    tsa_url: Option<String>,
    tsa_cert: Option<PathBuf>,
    no_verify: bool,
) -> AnyhowResult<()> {
    info!("Input file: {}", input.display());
    
    if !input.exists() {
        error!("Input file does not exist: {}", input.display());
        std::process::exit(1);
    }
    
    if !input.is_file() {
        error!("Input path is not a file: {}", input.display());
        std::process::exit(1);
    }
    
    let config_path = PathBuf::from("config.toml");
    let config_file = if config_path.exists() {
        Some(load_config_file(&config_path)?)
    } else {
        None
    };
    
    let tsa_url = tsa_url.unwrap_or_else(|| {
        if let Some(ref config) = config_file {
            config.tsa.url.clone()
        } else {
            "http://timestamp.digicert.com".to_string()
        }
    });
    
    let tsa_cert_path = tsa_cert
        .or_else(|| find_default_tsa_cert())
        .unwrap_or_default();
    
    if !tsa_cert_path.as_os_str().is_empty() && tsa_cert_path.exists() {
        info!("Using TSA certificate: {}", tsa_cert_path.display());
    } else if !tsa_cert_path.as_os_str().is_empty() {
        tracing::warn!("TSA certificate not found: {}", tsa_cert_path.display());
    } else {
        info!("No TSA certificate specified, using default TSA server without certificate verification");
    }
    
    let config = TimestampConfig::new(tsa_url)
        .with_tsa_cert_path(tsa_cert_path)
        .with_output_dir(output.unwrap_or_else(|| input.parent().unwrap_or_else(|| std::path::Path::new(".")).to_path_buf()))
        .with_verification(!no_verify);
    
    match timestamp::timestamp_file(&input, &config) {
        Ok(result) => {
            if result.success {
                info!("Timestamping completed successfully");
                info!("Generated files:");
                for file in &result.generated_files {
                    info!("  - {}", file.display());
                }
                
                if !result.metadata.is_empty() {
                    info!("Metadata:");
                    for (key, value) in &result.metadata {
                        info!("  {}: {}", key, value);
                    }
                }
            } else {
                error!("Timestamping failed: {}", result.error.as_deref().unwrap_or("Unknown error"));
                std::process::exit(1);
            }
        }
        Err(e) => {
            error!("Error during timestamping: {}", e);
            std::process::exit(1);
        }
    }
    
    Ok(())
}

fn handle_batch_timestamping(
    input: PathBuf,
    output: Option<PathBuf>,
    tsa_url: Option<String>,
    tsa_cert: Option<PathBuf>,
    no_verify: bool,
    recursive: bool,
    dry_run: bool,
    re_timestamp: bool,
    use_git: bool,
    verbose: bool,
    cleanup: bool,
) -> AnyhowResult<()> {
    info!("Input directory: {}", input.display());
    
    if !input.exists() {
        error!("Input directory does not exist: {}", input.display());
        std::process::exit(1);
    }
    
    if !input.is_dir() {
        error!("Input path is not a directory: {}", input.display());
        std::process::exit(1);
    }
    
    let output_dir = output.unwrap_or_else(|| input.clone());
    
    if !dry_run {
        std::fs::create_dir_all(&output_dir)
            .with_context(|| format!("Failed to create output directory: {}", output_dir.display()))?;
    }
    
    let config_path = PathBuf::from("config.toml");
    let config_file = if config_path.exists() {
        Some(load_config_file(&config_path)?)
    } else {
        None
    };
    
    let tsa_url = tsa_url.unwrap_or_else(|| {
        if let Some(ref config) = config_file {
            config.tsa.url.clone()
        } else {
            "http://timestamp.digicert.com".to_string()
        }
    });
    
    let tsa_cert_path = tsa_cert
        .or_else(|| find_default_tsa_cert());
    
    if let Some(ref cert_path) = tsa_cert_path {
        if cert_path.exists() {
            info!("Using TSA certificate: {}", cert_path.display());
        } else {
            tracing::warn!("TSA certificate not found: {}", cert_path.display());
        }
    } else {
        info!("No TSA certificate specified, using default TSA server without certificate verification");
    }
    
    let mut result = BatchResult::new();
    process_directory_batch(&input, &output_dir, &tsa_url, &tsa_cert_path, no_verify, recursive, dry_run, re_timestamp, use_git, verbose, cleanup, &mut result)?;
    
    result.print_summary();
    
    if result.failed_files > 0 {
        std::process::exit(1);
    }
    
    Ok(())
}

/// Handle blockchain timestamping commands
pub fn handle_blockchain_command(action: BlockchainAction) -> AnyhowResult<()> {
    match action {
        BlockchainAction::Anchor { file, with_rfc3161, tsa_url, tsa_cert } => {
            handle_blockchain_anchor(file, with_rfc3161, tsa_url, tsa_cert)?;
        }
        BlockchainAction::VerifyAnchor { file, ots_file, with_rfc3161, tsa_cert } => {
            handle_blockchain_verify(file, ots_file, with_rfc3161, tsa_cert)?;
        }
        BlockchainAction::Upgrade { ots_file } => {
            handle_blockchain_upgrade(ots_file)?;
        }
        BlockchainAction::Info { ots_file } => {
            handle_blockchain_info(ots_file)?;
        }
        BlockchainAction::Explain => {
            blockchain::print_blockchain_info();
        }
        BlockchainAction::Bundle { file, output } => {
            handle_proof_bundle(file, output)?;
        }
    }
    Ok(())
}

fn handle_blockchain_anchor(
    file: PathBuf,
    with_rfc3161: bool,
    tsa_url: Option<String>,
    tsa_cert: Option<PathBuf>,
) -> AnyhowResult<()> {
    if !file.exists() {
        error!("File does not exist: {}", file.display());
        std::process::exit(1);
    }
    
    // Check if OTS is installed
    if !blockchain::check_ots_installed() {
        println!("\n  OpenTimestamps client is not installed.");
        println!("Install it with: pip3 install opentimestamps-client\n");
        println!("After installation, run this command again.");
        std::process::exit(1);
    }
    
    println!("\n=== CREATING BLOCKCHAIN-ANCHORED TIMESTAMP ===\n");
    
    // Create RFC 3161 timestamp first if requested
    if with_rfc3161 {
        println!("Step 1: Creating RFC 3161 timestamp (for legal recognition)...");
        
        let config_path = PathBuf::from("config.toml");
        let config_file = if config_path.exists() {
            Some(load_config_file(&config_path)?)
        } else {
            None
        };
        
        let tsa_url = tsa_url.unwrap_or_else(|| {
            if let Some(ref config) = config_file {
                config.tsa.url.clone()
            } else {
                "http://timestamp.digicert.com".to_string()
            }
        });
        
        let tsa_cert_path = tsa_cert
            .or_else(|| find_default_tsa_cert())
            .unwrap_or_default();
        
        let output_dir = file.parent().unwrap_or_else(|| std::path::Path::new(".")).to_path_buf();
        
        let config = TimestampConfig::new(tsa_url)
            .with_tsa_cert_path(tsa_cert_path)
            .with_output_dir(output_dir)
            .with_verification(true);
        
        match timestamp::timestamp_file(&file, &config) {
            Ok(result) => {
                if result.success {
                    println!("   RFC 3161 timestamp created successfully");
                    for f in &result.generated_files {
                        println!("    - {}", f.display());
                    }
                } else {
                    warn!("RFC 3161 timestamp creation failed: {}", result.error.as_deref().unwrap_or("Unknown"));
                }
            }
            Err(e) => {
                warn!("RFC 3161 timestamp creation failed: {}", e);
            }
        }
        println!();
    }
    
    // Create blockchain timestamp
    let step = if with_rfc3161 { "Step 2" } else { "Creating" };
    println!("{}: Creating Bitcoin blockchain timestamp (via OpenTimestamps)...", step);
    
    match blockchain::create_blockchain_timestamp(&file) {
        Ok(result) => {
            println!("   Blockchain timestamp created: {}", result.proof_file.display());
            println!("  File SHA-256: {}", result.file_hash);
            println!("  Status: {}", result.status);
            println!();
            println!("    Bitcoin confirmation typically takes 1-24 hours.");
            println!("  Run 'stamp blockchain upgrade {}' after confirmation to complete the proof.", result.proof_file.display());
        }
        Err(e) => {
            error!("Failed to create blockchain timestamp: {}", e);
            std::process::exit(1);
        }
    }
    
    if with_rfc3161 {
        println!();
        println!("=== COMBINED PROOF CREATED ===");
        println!("Your document now has two independent proofs of existence:");
        println!("  1. RFC 3161 timestamp (.tsr) - legally recognized, immediate");
        println!("  2. Bitcoin blockchain (.ots) - decentralized, permanent (pending confirmation)");
        println!();
        println!("For legal evidence, preserve all generated files together.");
    }
    
    Ok(())
}

fn handle_blockchain_verify(
    file: PathBuf,
    ots_file: Option<PathBuf>,
    with_rfc3161: bool,
    tsa_cert: Option<PathBuf>,
) -> AnyhowResult<()> {
    if !file.exists() {
        error!("File does not exist: {}", file.display());
        std::process::exit(1);
    }
    
    // Check if OTS is installed
    if !blockchain::check_ots_installed() {
        println!("\n  OpenTimestamps client is not installed.");
        println!("Install it with: pip3 install opentimestamps-client\n");
        std::process::exit(1);
    }
    
    let ots_path = ots_file.unwrap_or_else(|| PathBuf::from(format!("{}.ots", file.display())));
    
    println!("\n=== VERIFYING BLOCKCHAIN TIMESTAMP ===\n");
    
    // Verify blockchain timestamp
    println!("Checking blockchain proof: {}", ots_path.display());
    
    match blockchain::verify_blockchain_timestamp(&file, &ots_path) {
        Ok(result) => {
            match &result.status {
                blockchain::BlockchainStatus::Confirmed => {
                    println!("   BLOCKCHAIN VERIFICATION PASSED");
                    if let Some(block) = result.bitcoin_block {
                        println!("  Bitcoin block: {}", block);
                    }
                    if let Some(time) = &result.block_time {
                        println!("  Block time: {}", time);
                    }
                }
                blockchain::BlockchainStatus::Pending => {
                    println!("   Timestamp is PENDING Bitcoin confirmation");
                    println!("  Run 'stamp blockchain upgrade {}' after confirmation", ots_path.display());
                }
                blockchain::BlockchainStatus::Failed(msg) => {
                    println!("   VERIFICATION FAILED: {}", msg);
                    std::process::exit(1);
                }
                blockchain::BlockchainStatus::Unknown => {
                    println!("  ? Unknown verification status");
                }
            }
        }
        Err(e) => {
            error!("Blockchain verification error: {}", e);
            std::process::exit(1);
        }
    }
    
    // Verify RFC 3161 timestamp if requested
    if with_rfc3161 {
        println!();
        println!("Checking RFC 3161 timestamp...");
        
        let tsr_path = PathBuf::from(format!("{}.tsr", file.file_stem().unwrap().to_str().unwrap()));
        let _tsq_path = PathBuf::from(format!("{}.tsq", file.file_stem().unwrap().to_str().unwrap()));
        
        // Try multiple path patterns
        let tsr_paths = vec![
            file.with_extension("tsr"),
            PathBuf::from(format!("{}.tsr", file.display())),
            tsr_path.clone(),
        ];
        
        let found_tsr = tsr_paths.iter().find(|p| p.exists());
        
        if let Some(tsr_path) = found_tsr {
            let ca_chain = tsa_cert.or_else(|| find_default_tsa_cert());
            
            match timestamp::verify_timestamp(&file, tsr_path) {
                Ok(result) => {
                    if result.success {
                        println!("   RFC 3161 hash verification PASSED");
                        println!("  Timestamp date: {}", result.timestamp_date);
                        
                        // Try cryptographic verification if we have a CA chain
                        if let Some(ca_path) = ca_chain {
                            let tsq_path = tsr_path.with_extension("tsq");
                            if tsq_path.exists() && ca_path.exists() {
                                match timestamp::verify_timestamp_response_files(tsr_path, &tsq_path, &ca_path) {
                                    Ok(true) => {
                                        println!("   RFC 3161 cryptographic verification PASSED");
                                    }
                                    Ok(false) => {
                                        println!("    RFC 3161 cryptographic verification FAILED");
                                    }
                                    Err(e) => {
                                        println!("    RFC 3161 cryptographic verification error: {}", e);
                                    }
                                }
                            }
                        }
                    } else {
                        println!("   RFC 3161 verification FAILED - file hash mismatch");
                    }
                }
                Err(e) => {
                    println!("    RFC 3161 verification error: {}", e);
                }
            }
        } else {
            println!("  No RFC 3161 timestamp (.tsr) found for this file");
        }
    }
    
    println!();
    println!("File: {}", file.display());
    
    Ok(())
}

fn handle_blockchain_upgrade(ots_file: PathBuf) -> AnyhowResult<()> {
    if !ots_file.exists() {
        error!("OTS file does not exist: {}", ots_file.display());
        std::process::exit(1);
    }
    
    if !blockchain::check_ots_installed() {
        println!("\n  OpenTimestamps client is not installed.");
        println!("Install it with: pip3 install opentimestamps-client\n");
        std::process::exit(1);
    }
    
    println!("Upgrading blockchain timestamp: {}", ots_file.display());
    
    match blockchain::upgrade_blockchain_timestamp(&ots_file) {
        Ok(true) => {
            println!("   Timestamp upgraded successfully!");
            println!("  The proof file now contains the complete path to the Bitcoin block.");
            println!("  This allows verification without contacting calendar servers.");
        }
        Ok(false) => {
            println!("   Timestamp is still pending Bitcoin confirmation.");
            println!("  Try again in a few hours.");
        }
        Err(e) => {
            error!("Upgrade failed: {}", e);
            std::process::exit(1);
        }
    }
    
    Ok(())
}

fn handle_blockchain_info(ots_file: PathBuf) -> AnyhowResult<()> {
    if !ots_file.exists() {
        error!("OTS file does not exist: {}", ots_file.display());
        std::process::exit(1);
    }
    
    if !blockchain::check_ots_installed() {
        println!("\n  OpenTimestamps client is not installed.");
        println!("Install it with: pip3 install opentimestamps-client\n");
        std::process::exit(1);
    }
    
    println!("=== OPENTIMESTAMPS PROOF INFORMATION ===\n");
    println!("File: {}\n", ots_file.display());
    
    match blockchain::get_ots_info(&ots_file) {
        Ok(info) => {
            println!("{}", info);
        }
        Err(e) => {
            error!("Failed to get info: {}", e);
            std::process::exit(1);
        }
    }
    
    Ok(())
}

fn handle_proof_bundle(file: PathBuf, output: Option<PathBuf>) -> AnyhowResult<()> {
    if !file.exists() {
        error!("File does not exist: {}", file.display());
        std::process::exit(1);
    }
    
    println!("Generating proof bundle manifest for: {}", file.display());
    
    // Look for existing proof files
    let tsr_path = PathBuf::from(format!("{}.tsr", file.file_stem().unwrap().to_str().unwrap()));
    let tsq_path = PathBuf::from(format!("{}.tsq", file.file_stem().unwrap().to_str().unwrap()));
    
    let rfc3161_tsr = if tsr_path.exists() { Some(tsr_path.as_path()) } else { None };
    let rfc3161_tsq = if tsq_path.exists() { Some(tsq_path.as_path()) } else { None };
    
    match blockchain::create_combined_proof_bundle(&file, rfc3161_tsr, rfc3161_tsq, false) {
        Ok(bundle) => {
            match blockchain::generate_proof_manifest(&bundle) {
                Ok(manifest) => {
                    let output_path = output.unwrap_or_else(|| {
                        PathBuf::from(format!("{}.proof-bundle.json", file.file_stem().unwrap().to_str().unwrap()))
                    });
                    
                    std::fs::write(&output_path, &manifest)
                        .with_context(|| format!("Failed to write manifest to {}", output_path.display()))?;
                    
                    println!("   Proof bundle manifest created: {}", output_path.display());
                    println!();
                    println!("Bundle contents:");
                    if bundle.rfc3161_tsr.is_some() {
                        println!("   RFC 3161 timestamp (.tsr)");
                    }
                    if bundle.rfc3161_tsq.is_some() {
                        println!("   RFC 3161 query (.tsq)");
                    }
                    if bundle.ots_proof.is_some() {
                        println!("   Blockchain proof (.ots)");
                    }
                    println!();
                    println!("Preserve all files listed in the manifest for legal evidence.");
                }
                Err(e) => {
                    error!("Failed to generate manifest: {}", e);
                    std::process::exit(1);
                }
            }
        }
        Err(e) => {
            error!("Failed to create proof bundle: {}", e);
            std::process::exit(1);
        }
    }
    
    Ok(())
}
