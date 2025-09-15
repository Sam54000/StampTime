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
use tracing::{error, info};
use crate::config::{self, load_config_file, find_default_tsa_cert};
use crate::timestamp::{self, TimestampConfig, process_directory_batch, BatchResult};
use crate::certificates::{download_rfc3161_certificates, generate_pkcs12_certificate};

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
    },
    /// Inspect timestamp responses, queries, and certificates
    Inspect {
        /// File to inspect (timestamp response, query, or certificate)
        file: PathBuf,
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

pub fn handle_verify_command(file: PathBuf, timestamp_file: PathBuf) -> AnyhowResult<()> {
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
    
    match timestamp::verify_timestamp(&file, &timestamp_file) {
        Ok(result) => {
            if result.success {
                println!("VERIFICATION SUCCESSFUL");
                println!("The file '{}' matches its timestamp", file.display());
                println!("Timestamped on: {}", result.timestamp_date);
                println!("Hash algorithm: {}", result.hash_algorithm);
                println!("The file has not been modified since it was timestamped.");
                std::process::exit(0);
            } else {
                eprintln!("VERIFICATION FAILED");
                eprintln!("The file '{}' does NOT match its timestamp", file.display());
                eprintln!("Hash comparison:");
                eprintln!("  Current file hash:  {}", result.current_hash);
                eprintln!("  Timestamped hash:   {}", result.timestamped_hash);
                eprintln!("This could mean:");
                eprintln!("  • The file has been modified since timestamping");
                eprintln!("  • The timestamp file is corrupted");
                eprintln!("  • The files don't belong together");
                std::process::exit(1);
            }
        }
        Err(e) => {
            eprintln!("Error during verification: {}", e);
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
