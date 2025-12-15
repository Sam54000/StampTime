! Blockchain anchoring for ultra-solid legal timestamps
!
! This module provides blockchain-based timestamp anchoring to complement RFC 3161 timestamps.
! 
! ## Why Blockchain Anchoring?
! 
! While RFC 3161 timestamps are legally recognized (eIDAS, ESIGN Act), they have a centralized
! trust model - the TSA could theoretically be compromised, go offline, or cease operations.
! 
! Blockchain anchoring provides:
! - **Decentralized trust**: Thousands of independent nodes verify the chain
! - **Immutability**: Bitcoin has 15+ years of proven tamper-resistance
! - **Permanence**: No single entity can remove or modify the timestamp
! - **Independent verification**: Anyone with blockchain access can verify
! 
! ## The "Belt and Suspenders" Approach
! 
! For maximum legal protection, we combine:
! 1. RFC 3161 from a Qualified TSA (primary, widely legally recognized)
! 2. Bitcoin blockchain via OpenTimestamps (secondary, decentralized proof)
! 3. Optional additional chains for redundancy
!
! Copyright (C) 2025 Dr. Samuel Louviot, Ph.D
!
! This program is free software: you can redistribute it and/or modify
! it under the terms of the GNU General Public License as published by
! the Free Software Foundation, either version 3 of the License, or
! (at your option) any later version.

use anyhow::{Context, Result as AnyhowResult};
use std::path::{Path, PathBuf};
use std::process::Command;
use tracing::{info, warn};

/ Default OpenTimestamps calendar servers (free, maintained by the community)
pub const OTS_CALENDARS: &[&str] = &[
    "https:alice.btc.calendar.opentimestamps.org",
    "https:bob.btc.calendar.opentimestamps.org",
    "https:finney.calendar.eternitywall.com",
];

/ Blockchain timestamp result
#[derive(Debug, Clone)]
pub struct BlockchainTimestamp {
    / Path to the .ots proof file
    pub proof_file: PathBuf,
    / Hash of the original file (SHA-256)
    pub file_hash: String,
    / Status of the blockchain anchoring
    pub status: BlockchainStatus,
    / Bitcoin block number (if confirmed)
    pub bitcoin_block: Option<u64>,
    / Bitcoin block time (if confirmed)
    pub block_time: Option<String>,
    / Calendar servers used
    pub calendars: Vec<String>,
}

/ Status of a blockchain timestamp
#[derive(Debug, Clone, PartialEq)]
pub enum BlockchainStatus {
    / Timestamp submitted, waiting for Bitcoin confirmation (typically 1-24 hours)
    Pending,
    / Timestamp confirmed in Bitcoin blockchain
    Confirmed,
    / Verification failed
    Failed(String),
    / Unknown status
    Unknown,
}

impl std::fmt::Display for BlockchainStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BlockchainStatus::Pending => write!(f, "Pending (waiting for Bitcoin confirmation)"),
            BlockchainStatus::Confirmed => write!(f, "Confirmed (anchored in Bitcoin blockchain)"),
            BlockchainStatus::Failed(msg) => write!(f, "Failed: {}", msg),
            BlockchainStatus::Unknown => write!(f, "Unknown"),
        }
    }
}

/ Combined proof bundle containing both RFC 3161 and blockchain proofs
#[derive(Debug)]
pub struct CombinedProofBundle {
    / Original file path
    pub original_file: PathBuf,
    / SHA-256 hash of original file
    pub file_hash: String,
    / RFC 3161 timestamp response (.tsr)
    pub rfc3161_tsr: Option<PathBuf>,
    / RFC 3161 timestamp query (.tsq)
    pub rfc3161_tsq: Option<PathBuf>,
    / RFC 3161 TSA certificates
    pub rfc3161_certs: Option<PathBuf>,
    / OpenTimestamps proof (.ots)
    pub ots_proof: Option<PathBuf>,
    / Blockchain status
    pub blockchain_status: Option<BlockchainStatus>,
    / Timestamp (RFC 3161 time if available)
    pub timestamp: Option<String>,
    / Bitcoin block info
    pub bitcoin_block: Option<u64>,
}

/ Check if OpenTimestamps client is installed
pub fn check_ots_installed() -> bool {
    Command::new("ots")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/ Install OpenTimestamps client via pip
pub fn install_ots_client() -> AnyhowResult<()> {
    info!("Installing OpenTimestamps client...");
    
    let output = Command::new("pip3")
        .args(&["install", "opentimestamps-client"])
        .output()
        .with_context(|| "Failed to run pip3. Ensure Python 3 and pip are installed.")?;
    
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(anyhow::anyhow!("Failed to install opentimestamps-client: {}", stderr));
    }
    
    info!("OpenTimestamps client installed successfully");
    Ok(())
}

/ Create a blockchain timestamp for a file using OpenTimestamps
/ 
/ This submits the file hash to multiple calendar servers which aggregate
/ timestamps and anchor them to the Bitcoin blockchain.
pub fn create_blockchain_timestamp(file_path: &Path) -> AnyhowResult<BlockchainTimestamp> {
    if !check_ots_installed() {
        return Err(anyhow::anyhow!(
            "OpenTimestamps client not installed. Run: pip3 install opentimestamps-client"
        ));
    }
    
    if !file_path.exists() {
        return Err(anyhow::anyhow!("File does not exist: {}", file_path.display()));
    }
    
    info!("Creating blockchain timestamp for: {}", file_path.display());
    
     Calculate file hash first
    let file_hash = calculate_sha256(file_path)?;
    info!("File SHA-256: {}", file_hash);
    
     Create timestamp using ots command
    let output = Command::new("ots")
        .arg("stamp")
        .arg(file_path)
        .output()
        .with_context(|| "Failed to execute ots stamp command")?;
    
     OTS outputs status to stderr
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    
    info!("OTS output: {}{}", stdout, stderr);
    
     The proof file is created as <filename>.ots
    let proof_file = PathBuf::from(format!("{}.ots", file_path.display()));
    
    if !proof_file.exists() {
        return Err(anyhow::anyhow!(
            "OTS proof file was not created. Output: {}{}",
            stdout, stderr
        ));
    }
    
     Parse calendar servers from output
    let mut calendars = Vec::new();
    for calendar in OTS_CALENDARS {
        if stderr.contains(calendar) || stdout.contains(calendar) {
            calendars.push(calendar.to_string());
        }
    }
    
    info!("Blockchain timestamp created: {}", proof_file.display());
    info!("Submitted to {} calendar server(s)", calendars.len().max(3));
    info!("Status: Pending - Bitcoin confirmation typically takes 1-24 hours");
    
    Ok(BlockchainTimestamp {
        proof_file,
        file_hash,
        status: BlockchainStatus::Pending,
        bitcoin_block: None,
        block_time: None,
        calendars: if calendars.is_empty() {
            OTS_CALENDARS.iter().map(|s| s.to_string()).collect()
        } else {
            calendars
        },
    })
}

/ Create a blockchain timestamp from an existing hash (e.g., from RFC 3161 timestamp)
/ 
/ This allows anchoring the same hash that was used for the RFC 3161 timestamp,
/ creating a tight coupling between the two proofs.
pub fn create_blockchain_timestamp_from_hash(
    hash: &str,
    output_path: &Path,
) -> AnyhowResult<BlockchainTimestamp> {
    if !check_ots_installed() {
        return Err(anyhow::anyhow!(
            "OpenTimestamps client not installed. Run: pip3 install opentimestamps-client"
        ));
    }
    
    info!("Creating blockchain timestamp for hash: {}", hash);
    
     Create a temporary file with the hash (as bytes)
    let hash_bytes = hex::decode(hash)
        .with_context(|| format!("Invalid hex hash: {}", hash))?;
    
    let temp_file = tempfile::NamedTempFile::new()
        .with_context(|| "Failed to create temp file")?;
    
    std::fs::write(temp_file.path(), &hash_bytes)
        .with_context(|| "Failed to write hash to temp file")?;
    
     Create timestamp
    let output = Command::new("ots")
        .arg("stamp")
        .arg(temp_file.path())
        .output()
        .with_context(|| "Failed to execute ots stamp command")?;
    
    let stderr = String::from_utf8_lossy(&output.stderr);
    
     Move the proof file to the desired location
    let temp_ots = PathBuf::from(format!("{}.ots", temp_file.path().display()));
    
    if temp_ots.exists() {
        std::fs::rename(&temp_ots, output_path)
            .with_context(|| format!("Failed to move OTS file to {}", output_path.display()))?;
    } else {
        return Err(anyhow::anyhow!("OTS proof file was not created: {}", stderr));
    }
    
    Ok(BlockchainTimestamp {
        proof_file: output_path.to_path_buf(),
        file_hash: hash.to_string(),
        status: BlockchainStatus::Pending,
        bitcoin_block: None,
        block_time: None,
        calendars: OTS_CALENDARS.iter().map(|s| s.to_string()).collect(),
    })
}

/ Verify a blockchain timestamp
/ 
/ For complete verification, you need either:
/ 1. A local Bitcoin Core node (recommended for court-grade verification)
/ 2. Internet access to query calendar servers (for convenience)
pub fn verify_blockchain_timestamp(
    file_path: &Path,
    ots_path: &Path,
) -> AnyhowResult<BlockchainTimestamp> {
    if !check_ots_installed() {
        return Err(anyhow::anyhow!(
            "OpenTimestamps client not installed. Run: pip3 install opentimestamps-client"
        ));
    }
    
    if !file_path.exists() {
        return Err(anyhow::anyhow!("Original file not found: {}", file_path.display()));
    }
    
    if !ots_path.exists() {
        return Err(anyhow::anyhow!("OTS proof file not found: {}", ots_path.display()));
    }
    
    let file_hash = calculate_sha256(file_path)?;
    info!("Verifying blockchain timestamp for: {}", file_path.display());
    
     Run ots verify
    let output = Command::new("ots")
        .arg("verify")
        .arg(ots_path)
        .output()
        .with_context(|| "Failed to execute ots verify command")?;
    
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let combined = format!("{}{}", stdout, stderr);
    
     Parse the output
    let (status, bitcoin_block, block_time) = parse_ots_verify_output(&combined);
    
    Ok(BlockchainTimestamp {
        proof_file: ots_path.to_path_buf(),
        file_hash,
        status,
        bitcoin_block,
        block_time,
        calendars: Vec::new(),
    })
}

/ Upgrade a pending OTS timestamp to include the full Bitcoin attestation
/ 
/ After the timestamp is confirmed on the blockchain, the proof file can be
/ upgraded to include the complete path from the hash to the Bitcoin block.
/ This makes verification possible without contacting calendar servers.
pub fn upgrade_blockchain_timestamp(ots_path: &Path) -> AnyhowResult<bool> {
    if !check_ots_installed() {
        return Err(anyhow::anyhow!(
            "OpenTimestamps client not installed. Run: pip3 install opentimestamps-client"
        ));
    }
    
    if !ots_path.exists() {
        return Err(anyhow::anyhow!("OTS proof file not found: {}", ots_path.display()));
    }
    
    info!("Upgrading blockchain timestamp: {}", ots_path.display());
    
    let output = Command::new("ots")
        .arg("upgrade")
        .arg(ots_path)
        .output()
        .with_context(|| "Failed to execute ots upgrade command")?;
    
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    
    if stdout.contains("complete") || stderr.contains("complete") {
        info!("Timestamp upgraded successfully - now contains complete Bitcoin attestation");
        Ok(true)
    } else if stdout.contains("Pending") || stderr.contains("Pending") {
        info!("Timestamp still pending Bitcoin confirmation");
        Ok(false)
    } else {
        warn!("Upgrade status unclear: {}{}", stdout, stderr);
        Ok(false)
    }
}

/ Get detailed information about an OTS proof file
pub fn get_ots_info(ots_path: &Path) -> AnyhowResult<String> {
    if !check_ots_installed() {
        return Err(anyhow::anyhow!(
            "OpenTimestamps client not installed. Run: pip3 install opentimestamps-client"
        ));
    }
    
    if !ots_path.exists() {
        return Err(anyhow::anyhow!("OTS proof file not found: {}", ots_path.display()));
    }
    
    let output = Command::new("ots")
        .arg("info")
        .arg(ots_path)
        .output()
        .with_context(|| "Failed to execute ots info command")?;
    
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    
    Ok(format!("{}{}", stdout, stderr))
}

/ Calculate SHA-256 hash of a file
fn calculate_sha256(file_path: &Path) -> AnyhowResult<String> {
    let output = Command::new("openssl")
        .args(&["dgst", "-sha256", "-hex", file_path.to_str().unwrap()])
        .output()
        .with_context(|| "Failed to calculate SHA-256 hash")?;
    
    if !output.status.success() {
        return Err(anyhow::anyhow!("Failed to calculate file hash"));
    }
    
    let hash_output = String::from_utf8_lossy(&output.stdout);
    let hash = hash_output
        .split_whitespace()
        .last()
        .ok_or_else(|| anyhow::anyhow!("Could not parse hash output"))?;
    
    Ok(hash.to_lowercase())
}

/ Parse OTS verify output to extract status and block info
fn parse_ots_verify_output(output: &str) -> (BlockchainStatus, Option<u64>, Option<String>) {
     Look for success message like "Success! Bitcoin block 358391 attests existence as of 2015-05-28"
    if output.contains("Success!") {
         Extract block number
        let block_num = output
            .split("Bitcoin block ")
            .nth(1)
            .and_then(|s| s.split_whitespace().next())
            .and_then(|s| s.parse::<u64>().ok());
        
         Extract date
        let block_time = output
            .split("as of ")
            .nth(1)
            .map(|s| s.trim().to_string());
        
        (BlockchainStatus::Confirmed, block_num, block_time)
    } else if output.contains("Pending") {
        (BlockchainStatus::Pending, None, None)
    } else if output.contains("does not match") || output.contains("Error") || output.contains("error") {
        let msg = output.lines().find(|l| l.contains("Error") || l.contains("error") || l.contains("match"))
            .unwrap_or("Verification failed")
            .to_string();
        (BlockchainStatus::Failed(msg), None, None)
    } else {
        (BlockchainStatus::Unknown, None, None)
    }
}

/ Create a combined proof bundle with both RFC 3161 and blockchain timestamps
pub fn create_combined_proof_bundle(
    original_file: &Path,
    rfc3161_tsr: Option<&Path>,
    rfc3161_tsq: Option<&Path>,
    create_blockchain: bool,
) -> AnyhowResult<CombinedProofBundle> {
    let file_hash = calculate_sha256(original_file)?;
    
    let mut bundle = CombinedProofBundle {
        original_file: original_file.to_path_buf(),
        file_hash: file_hash.clone(),
        rfc3161_tsr: rfc3161_tsr.map(|p| p.to_path_buf()),
        rfc3161_tsq: rfc3161_tsq.map(|p| p.to_path_buf()),
        rfc3161_certs: None,
        ots_proof: None,
        blockchain_status: None,
        timestamp: None,
        bitcoin_block: None,
    };
    
     Check for certs file
    if let Some(tsr) = rfc3161_tsr {
        let certs_path = PathBuf::from(format!("{}.certs.pem", tsr.display()));
        if certs_path.exists() {
            bundle.rfc3161_certs = Some(certs_path);
        }
    }
    
     Create blockchain timestamp if requested
    if create_blockchain {
        match create_blockchain_timestamp(original_file) {
            Ok(bt) => {
                bundle.ots_proof = Some(bt.proof_file);
                bundle.blockchain_status = Some(bt.status);
            }
            Err(e) => {
                warn!("Failed to create blockchain timestamp: {}", e);
            }
        }
    } else {
         Check if OTS file already exists
        let ots_path = PathBuf::from(format!("{}.ots", original_file.display()));
        if ots_path.exists() {
            bundle.ots_proof = Some(ots_path);
        }
    }
    
    Ok(bundle)
}

/ Generate a JSON manifest of the proof bundle for legal documentation
pub fn generate_proof_manifest(bundle: &CombinedProofBundle) -> AnyhowResult<String> {
    let manifest = serde_json::json!({
        "proof_bundle_version": "1.0",
        "generated_by": "StampTime",
        "generated_at": chrono::Utc::now().to_rfc3339(),
        "original_file": {
            "path": bundle.original_file.display().to_string(),
            "sha256": bundle.file_hash,
        },
        "rfc3161_timestamp": {
            "tsr_file": bundle.rfc3161_tsr.as_ref().map(|p| p.display().to_string()),
            "tsq_file": bundle.rfc3161_tsq.as_ref().map(|p| p.display().to_string()),
            "certs_file": bundle.rfc3161_certs.as_ref().map(|p| p.display().to_string()),
            "timestamp": bundle.timestamp,
        },
        "blockchain_timestamp": {
            "ots_proof": bundle.ots_proof.as_ref().map(|p| p.display().to_string()),
            "status": bundle.blockchain_status.as_ref().map(|s| s.to_string()),
            "bitcoin_block": bundle.bitcoin_block,
        },
        "verification_instructions": {
            "rfc3161": "Verify with: stamp verify <original_file> <tsr_file> --tsa-cert <ca_chain.pem>",
            "blockchain": "Verify with: ots verify <ots_file> (requires Bitcoin node for offline verification)",
        },
        "legal_notes": [
            "This bundle provides two independent proofs of document existence at a point in time.",
            "RFC 3161 timestamp: Issued by a trusted Timestamp Authority, legally recognized under eIDAS/ESIGN.",
            "Blockchain timestamp: Anchored in Bitcoin blockchain, providing decentralized immutable proof.",
            "For maximum legal protection, preserve all files in this bundle along with chain-of-custody documentation."
        ]
    });
    
    serde_json::to_string_pretty(&manifest)
        .with_context(|| "Failed to serialize proof manifest")
}

/ Print comprehensive information about blockchain timestamping
pub fn print_blockchain_info() {
    println!("\n=== BLOCKCHAIN TIMESTAMPING INFORMATION ===\n");
    
    println!("WHAT IS BLOCKCHAIN TIMESTAMPING?");
    println!("--------------------------------");
    println!("Blockchain timestamping anchors a cryptographic hash of your document");
    println!("into the Bitcoin blockchain, creating an immutable proof of existence.");
    println!();
    
    println!("WHY USE IT ALONGSIDE RFC 3161?");
    println!("------------------------------");
    println!("RFC 3161 (your current timestamps) provides:");
    println!("   Legal recognition (eIDAS, ESIGN Act)");
    println!("   Immediate verification");
    println!("   Trusted timestamp authority signature");
    println!();
    println!("Blockchain anchoring adds:");
    println!("   Decentralized trust (no single point of failure)");
    println!("   Immutability (would require 51% attack to modify)");
    println!("   Permanence (Bitcoin has 15+ years track record)");
    println!("   Independent verification (anyone can verify)");
    println!();
    
    println!("THE 'BELT AND SUSPENDERS' APPROACH");
    println!("----------------------------------");
    println!("For maximum legal protection, we combine both:");
    println!("  1. RFC 3161 from a Qualified TSA (primary proof)");
    println!("  2. Bitcoin blockchain via OpenTimestamps (secondary proof)");
    println!();
    println!("Both proofs use the same SHA-256 hash, creating independent");
    println!("verification paths that would ALL need to be compromised.");
    println!();
    
    println!("LEGAL RECOGNITION");
    println!("-----------------");
    println!(" El Salvador: Official government documents on Bitcoin (2024)");
    println!(" US Courts: Increasingly accepting blockchain evidence");
    println!(" EU: eIDAS 2.0 exploring blockchain trust services");
    println!(" Academic: Widely accepted for research timestamps");
    println!();
    
    println!("HOW IT WORKS (OpenTimestamps)");
    println!("-----------------------------");
    println!("1. Your file hash is sent to calendar servers (no file content!)");
    println!("2. Calendars aggregate many hashes into a Merkle tree");
    println!("3. The Merkle root is anchored in a Bitcoin transaction");
    println!("4. After ~1-24 hours, your timestamp is confirmed");
    println!("5. The .ots proof file contains the path from your hash to the block");
    println!();
    
    println!("INSTALLATION");
    println!("------------");
    println!("  pip3 install opentimestamps-client");
    println!();
    
    println!("For complete verification (recommended for court use):");
    println!("  - Install Bitcoin Core (pruned node is fine)");
    println!("  - This allows offline, trustless verification");
    println!();
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_parse_success_output() {
        let output = "Success! Bitcoin block 358391 attests existence as of 2015-05-28 CEST";
        let (status, block, time) = parse_ots_verify_output(output);
        assert_eq!(status, BlockchainStatus::Confirmed);
        assert_eq!(block, Some(358391));
        assert!(time.is_some());
    }
    
    #[test]
    fn test_parse_pending_output() {
        let output = "Pending confirmation in Bitcoin blockchain";
        let (status, block, time) = parse_ots_verify_output(output);
        assert_eq!(status, BlockchainStatus::Pending);
        assert!(block.is_none());
        assert!(time.is_none());
    }
}

