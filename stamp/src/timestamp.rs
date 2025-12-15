//! Timestamp creation, verification, and related functions
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
use std::path::PathBuf;
use std::io::Write;
use tracing::{info, warn};
use walkdir::WalkDir;
use colored::*;
use std::path::Path;

/// Custom logging functions for file processing

#[derive(Debug, Clone)]
pub struct TimestampConfig {
    pub tsa_url: String,
    pub tsa_cert_path: PathBuf,
    pub output_dir: PathBuf,
    pub verify_after_creation: bool,
}

impl TimestampConfig {
    pub fn new(tsa_url: String) -> Self {
        Self {
            tsa_url,
            tsa_cert_path: PathBuf::new(),
            output_dir: PathBuf::new(),
            verify_after_creation: true,
        }
    }

    pub fn with_tsa_cert_path(mut self, path: PathBuf) -> Self {
        self.tsa_cert_path = path;
        self
    }

    pub fn with_output_dir(mut self, dir: PathBuf) -> Self {
        self.output_dir = dir;
        self
    }

    pub fn with_verification(mut self, verify: bool) -> Self {
        self.verify_after_creation = verify;
        self
    }
}

#[derive(Debug)]
pub struct TimestampResult {
    pub success: bool,
    pub error: Option<String>,
    pub generated_files: Vec<PathBuf>,
    pub metadata: std::collections::HashMap<String, String>,
}

impl TimestampResult {
    pub fn success(_timestamp_type: TimestampType, _input_file: PathBuf, generated_files: Vec<PathBuf>) -> Self {
        Self {
            success: true,
            error: None,
            generated_files,
            metadata: std::collections::HashMap::new(),
        }
    }

    pub fn with_metadata(mut self, key: String, value: String) -> Self {
        self.metadata.insert(key, value);
        self
    }
}

#[derive(Debug, Clone)]
pub enum TimestampType {
    Rfc3161,
}

#[derive(Debug)]
pub struct OutputPaths {
    pub base_dir: PathBuf,
    pub timestamp_query: Option<PathBuf>,
    pub timestamp_response: Option<PathBuf>,
    pub timestamp_certs: Option<PathBuf>,
}

impl OutputPaths {
    pub fn existing_paths(&self) -> Vec<PathBuf> {
        let mut paths = Vec::new();
        if let Some(ref path) = self.timestamp_query {
            if path.exists() {
                paths.push(path.clone());
            }
        }
        if let Some(ref path) = self.timestamp_response {
            if path.exists() {
                paths.push(path.clone());
            }
        }
        if let Some(ref path) = self.timestamp_certs {
            if path.exists() {
                paths.push(path.clone());
            }
        }
        paths
    }
}

pub fn generate_output_paths(input_file: &PathBuf, output_dir: &PathBuf, _timestamp_type: TimestampType) -> AnyhowResult<OutputPaths> {
    let base_name = input_file.file_stem()
        .and_then(|s| s.to_str())
        .ok_or_else(|| anyhow::anyhow!("Invalid file name"))?;
    
    let base_dir = output_dir.clone();
    
    let timestamp_query = Some(base_dir.join(format!("{}.tsq", base_name)));
    let timestamp_response = Some(base_dir.join(format!("{}.tsr", base_name)));
    let timestamp_certs = Some(base_dir.join(format!("{}.tsr.certs.pem", base_name)));
    
    Ok(OutputPaths {
        base_dir,
        timestamp_query,
        timestamp_response,
        timestamp_certs,
    })
}

pub fn create_timestamp_query(data: &[u8]) -> AnyhowResult<Vec<u8>> {
    use std::process::Command;
    use tempfile::NamedTempFile;
    
    let mut temp_file = NamedTempFile::new()
        .with_context(|| "Failed to create temporary file")?;
    temp_file.write_all(data)
        .with_context(|| "Failed to write data to temporary file")?;
    temp_file.flush()
        .with_context(|| "Failed to flush temporary file")?;
    
    let output_file = NamedTempFile::new()
        .with_context(|| "Failed to create output temporary file")?;
    let output_path = output_file.path().to_path_buf();
    drop(output_file);
    
    // Use OpenSSL to create timestamp query with SHA-256 hash algorithm
    // SHA-256 is required for legal admissibility (SHA-1 is deprecated)
    // The -cert flag requests the TSA to include its certificate in the response
    // This is critical for independent verification without external certificate lookup
    let output = Command::new("openssl")
        .args(&[
            "ts", "-query", 
            "-data", temp_file.path().to_str().unwrap(),
            "-sha256",  // Explicitly use SHA-256 for legal compliance
            "-cert",    // Request TSA certificate in response for verification
            "-out", output_path.to_str().unwrap()
        ])
        .output()
        .with_context(|| "Failed to execute openssl ts command")?;
    
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(anyhow::anyhow!("OpenSSL ts command failed: {}", stderr));
    }
    
    let tsq_data = std::fs::read(&output_path)
        .with_context(|| "Failed to read generated timestamp query")?;
    
    let _ = std::fs::remove_file(temp_file.path());
    let _ = std::fs::remove_file(&output_path);
    
    Ok(tsq_data)
}

pub fn extract_timestamp_certificates(tsr_data: &[u8]) -> AnyhowResult<Vec<String>> {
    use std::process::Command;
    use tempfile::NamedTempFile;
    
    let mut temp_tsr = NamedTempFile::new()
        .with_context(|| "Failed to create temporary TSR file")?;
    temp_tsr.write_all(tsr_data)
        .with_context(|| "Failed to write TSR data to temporary file")?;
    temp_tsr.flush()
        .with_context(|| "Failed to flush temporary TSR file")?;
    
    // Extract embedded certificates from the timestamp response using PKCS7 extraction
    // This is the proper way to extract certificates for legal verification
    // First, extract the token (PKCS7 signed data) from the TSR
    let token_output = Command::new("openssl")
        .args(&[
            "ts", "-reply",
            "-in", temp_tsr.path().to_str().unwrap(),
            "-token_out"
        ])
        .output()
        .with_context(|| "Failed to extract token from TSR")?;
    
    if token_output.status.success() && !token_output.stdout.is_empty() {
        // Extract certificates from the PKCS7 token
        let pkcs7_output = Command::new("openssl")
            .args(&["pkcs7", "-inform", "DER", "-print_certs"])
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .spawn();
        
        if let Ok(mut child) = pkcs7_output {
            if let Some(stdin) = child.stdin.as_mut() {
                let _ = stdin.write_all(&token_output.stdout);
            }
            
            if let Ok(output) = child.wait_with_output() {
                if output.status.success() {
                    let certs_text = String::from_utf8_lossy(&output.stdout);
                    let pem_certs = extract_pem_certificates(&certs_text)?;
                    if !pem_certs.is_empty() {
                        let _ = std::fs::remove_file(temp_tsr.path());
                        return Ok(pem_certs);
                    }
                }
            }
        }
    }
    
    // Fallback: try the text output method
    let output = Command::new("openssl")
        .args(&[
            "ts", "-reply", 
            "-in", temp_tsr.path().to_str().unwrap(),
            "-text"
        ])
        .output()
        .with_context(|| "Failed to execute openssl ts command")?;
    
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(anyhow::anyhow!("OpenSSL ts command failed: {}", stderr));
    }
    
    let tsr_text = String::from_utf8_lossy(&output.stdout);
    
    let certificates = extract_certificates_from_text(&tsr_text)?;
    
    let _ = std::fs::remove_file(temp_tsr.path());
    
    Ok(certificates)
}

fn extract_certificates_from_text(tsr_text: &str) -> AnyhowResult<Vec<String>> {
    let mut certificates = Vec::new();
    let mut in_certificate = false;
    let mut current_cert = String::new();
    
    for line in tsr_text.lines() {
        let line = line.trim();
        
        if line.contains("Certificate:") {
            if !current_cert.is_empty() {
                certificates.push(current_cert.clone());
                current_cert.clear();
            }
            in_certificate = true;
            continue;
        }
        
        if in_certificate {
            if line.is_empty() && !current_cert.is_empty() {
                certificates.push(current_cert.clone());
                current_cert.clear();
                in_certificate = false;
            } else if !line.is_empty() {
                current_cert.push_str(line);
                current_cert.push('\n');
            }
        }
    }
    
    if !current_cert.is_empty() {
        certificates.push(current_cert);
    }
    
    if certificates.is_empty() {
        let pem_certs = extract_pem_certificates(tsr_text)?;
        if !pem_certs.is_empty() {
            return Ok(pem_certs);
        }
        
        return Ok(vec!["No certificates found in timestamp response".to_string()]);
    }
    
    Ok(certificates)
}

fn extract_pem_certificates(text: &str) -> AnyhowResult<Vec<String>> {
    let mut certificates = Vec::new();
    let mut current_cert = String::new();
    let mut in_cert = false;
    
    for line in text.lines() {
        let line = line.trim();
        
        if line == "-----BEGIN CERTIFICATE-----" {
            if !current_cert.is_empty() {
                certificates.push(current_cert.clone());
                current_cert.clear();
            }
            current_cert.push_str(line);
            current_cert.push('\n');
            in_cert = true;
        } else if line == "-----END CERTIFICATE-----" {
            current_cert.push_str(line);
            current_cert.push('\n');
            certificates.push(current_cert.clone());
            current_cert.clear();
            in_cert = false;
        } else if in_cert {
            current_cert.push_str(line);
            current_cert.push('\n');
        }
    }
    
    Ok(certificates)
}

pub fn verify_timestamp_response(tsr_data: &[u8], tsq_data: &[u8]) -> AnyhowResult<bool> {
    use std::process::Command;
    use tempfile::NamedTempFile;
    
    let mut temp_tsr = NamedTempFile::new()
        .with_context(|| "Failed to create temporary TSR file")?;
    temp_tsr.write_all(tsr_data)
        .with_context(|| "Failed to write TSR data to temporary file")?;
    temp_tsr.flush()
        .with_context(|| "Failed to flush temporary TSR file")?;
    
    let mut temp_tsq = NamedTempFile::new()
        .with_context(|| "Failed to create temporary TSQ file")?;
    temp_tsq.write_all(tsq_data)
        .with_context(|| "Failed to write TSQ data to temporary file")?;
    temp_tsq.flush()
        .with_context(|| "Failed to flush temporary TSQ file")?;
    
    // Extract certificates embedded in the TSR for verification
    // This allows self-contained verification using the certificates included in the response
    let token_output = Command::new("openssl")
        .args(&[
            "ts", "-reply",
            "-in", temp_tsr.path().to_str().unwrap(),
            "-token_out"
        ])
        .output();
    
    let mut temp_chain: Option<NamedTempFile> = None;
    
    if let Ok(token_result) = token_output {
        if token_result.status.success() && !token_result.stdout.is_empty() {
            // Extract certificates from the PKCS7 token
            let pkcs7_output = Command::new("openssl")
                .args(&["pkcs7", "-inform", "DER", "-print_certs"])
                .stdin(std::process::Stdio::piped())
                .stdout(std::process::Stdio::piped())
                .spawn();
            
            if let Ok(mut child) = pkcs7_output {
                if let Some(stdin) = child.stdin.as_mut() {
                    let _ = stdin.write_all(&token_result.stdout);
                }
                
                if let Ok(output) = child.wait_with_output() {
                    if output.status.success() && !output.stdout.is_empty() {
                        // Create temporary file with extracted certificates
                        if let Ok(mut chain_file) = NamedTempFile::new() {
                            if chain_file.write_all(&output.stdout).is_ok() && chain_file.flush().is_ok() {
                                temp_chain = Some(chain_file);
                            }
                        }
                    }
                }
            }
        }
    }
    
    // Build verification command
    // Use -partial_chain to allow verification with embedded certificates
    // This is appropriate when certificates are embedded in the response
    let mut args = vec![
        "ts", "-verify",
        "-queryfile", temp_tsq.path().to_str().unwrap(),
        "-in", temp_tsr.path().to_str().unwrap(),
    ];
    
    let chain_path_str;
    if let Some(ref chain_file) = temp_chain {
        chain_path_str = chain_file.path().to_str().unwrap().to_string();
        args.push("-CAfile");
        args.push(&chain_path_str);
        args.push("-partial_chain");  // Allow partial chain verification with embedded certs
    }
    
    let output = Command::new("openssl")
        .args(&args)
        .output()
        .with_context(|| "Failed to execute openssl ts verify command")?;
    
    let _ = std::fs::remove_file(temp_tsr.path());
    let _ = std::fs::remove_file(temp_tsq.path());
    
    if output.status.success() {
        info!("Timestamp cryptographic verification successful");
        Ok(true)
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        warn!("Timestamp verification failed: {}", stderr);
        Ok(false)
    }
}

/// Verify a timestamp response (.tsr) against the original query (.tsq) AND a trusted CA chain.
///
/// This is the court-grade check: it validates the TSA signature and the certificate chain anchored to the
/// provided trust bundle. Unlike the byte-based verifier, this does NOT attempt to "self-trust" embedded certs.
pub fn verify_timestamp_response_files(
    tsr_path: &Path,
    tsq_path: &Path,
    ca_chain_path: &Path,
) -> AnyhowResult<bool> {
    use std::process::Command;

    if !tsr_path.exists() {
        return Err(anyhow::anyhow!("TSR file not found: {}", tsr_path.display()));
    }
    if !tsq_path.exists() {
        return Err(anyhow::anyhow!("TSQ file not found: {}", tsq_path.display()));
    }
    if !ca_chain_path.exists() {
        return Err(anyhow::anyhow!("CA chain file not found: {}", ca_chain_path.display()));
    }

    let output = Command::new("openssl")
        .args(&[
            "ts",
            "-verify",
            "-queryfile",
            tsq_path.to_str().unwrap(),
            "-in",
            tsr_path.to_str().unwrap(),
            "-CAfile",
            ca_chain_path.to_str().unwrap(),
        ])
        .output()
        .with_context(|| "Failed to execute openssl ts -verify command")?;

    if output.status.success() {
        Ok(true)
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        warn!("OpenSSL ts -verify failed: {}", stderr);
        Ok(false)
    }
}

pub fn send_timestamp_request(tsq_data: &[u8], tsa_url: &str) -> AnyhowResult<Vec<u8>> {
    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .with_context(|| "Failed to create HTTP client")?;
    
    if tsa_url.to_lowercase().starts_with("http://") {
        warn!("TSA URL uses HTTP (not HTTPS): {}. This allows on-path attackers to tamper with responses unless you perform strict trust-anchored verification with a known CA chain.", tsa_url);
    }

    info!("Sending {} bytes to TSA: {}", tsq_data.len(), tsa_url);
    
    let response = client
        .post(tsa_url)
        .header("Content-Type", "application/timestamp-query")
        .header("User-Agent", "stamp/0.1.0")
        .body(tsq_data.to_vec())
        .send()
        .with_context(|| format!("Failed to send request to TSA: {}", tsa_url))?;
    
    info!("TSA response status: {}", response.status());
    
    if !response.status().is_success() {
        let status = response.status();
        let headers: std::collections::HashMap<String, String> = response.headers()
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_string()))
            .collect();
        
        let response_text = response.text().unwrap_or_else(|_| "Could not read response body".to_string());
        
        return Err(anyhow::anyhow!(
            "TSA request failed with status: {} - Headers: {:?} - Response: {}",
            status, headers, response_text
        ));
    }
    
    let tsr_data = response.bytes()
        .with_context(|| "Failed to read TSA response")?
        .to_vec();
    
    if tsr_data.is_empty() {
        return Err(anyhow::anyhow!("Empty response from TSA"));
    }
    
    info!("Received timestamp response: {} bytes", tsr_data.len());
    Ok(tsr_data)
}

pub fn timestamp_file(input_file: &PathBuf, config: &TimestampConfig) -> AnyhowResult<TimestampResult> {
    info!("Reading file: {}", input_file.display());
    
    let file_data = std::fs::read(input_file)
        .with_context(|| format!("Failed to read file: {}", input_file.display()))?;
    
    info!("File size: {} bytes", file_data.len());
    
    let output_paths = generate_output_paths(
        input_file,
        &config.output_dir,
        TimestampType::Rfc3161,
    )?;
    
    std::fs::create_dir_all(&output_paths.base_dir)
        .with_context(|| format!("Failed to create output directory: {}", output_paths.base_dir.display()))?;
    
    info!("Creating timestamp query");
    let tsq_data = create_timestamp_query(&file_data)
        .with_context(|| "Failed to create timestamp query")?;
    
    if let Some(ref tsq_path) = output_paths.timestamp_query {
        std::fs::write(tsq_path, &tsq_data)
            .with_context(|| format!("Failed to write timestamp query: {}", tsq_path.display()))?;
        info!("Timestamp query written: {}", tsq_path.display());
    }
    
    info!("Sending timestamp request to TSA: {}", config.tsa_url);
    let tsr_data = send_timestamp_request(&tsq_data, &config.tsa_url)
        .with_context(|| "Failed to send timestamp request to TSA")?;
    
    if let Some(ref tsr_path) = output_paths.timestamp_response {
        std::fs::write(tsr_path, &tsr_data)
            .with_context(|| format!("Failed to write timestamp response: {}", tsr_path.display()))?;
        info!("Timestamp response written: {}", tsr_path.display());
    }
    
    if let Some(ref certs_path) = output_paths.timestamp_certs {
        match extract_timestamp_certificates(&tsr_data) {
            Ok(certificates) => {
                if !certificates.is_empty() {
                    let cert_data = certificates.join("\n\n");
                    std::fs::write(certs_path, cert_data)
                        .with_context(|| format!("Failed to write certificates: {}", certs_path.display()))?;
                    info!("Certificates written: {} ({} certificates)", certs_path.display(), certificates.len());
                } else {
                    let cert_data = "# No certificates found in timestamp response\n";
                    std::fs::write(certs_path, cert_data)
                        .with_context(|| format!("Failed to write certificates: {}", certs_path.display()))?;
                    info!("No certificates found in timestamp response");
                }
            }
            Err(e) => {
                warn!("Failed to extract certificates from timestamp response: {}", e);
                let cert_data = format!("# Error extracting certificates: {}\n", e);
                let _ = std::fs::write(certs_path, cert_data);
            }
        }
    }
    
    if config.verify_after_creation {
        info!("Verifying timestamp (trust-anchored)");

        let has_chain = !config.tsa_cert_path.as_os_str().is_empty() && config.tsa_cert_path.exists();
        if !has_chain {
            warn!(
                "Skipping trust-anchored verification: no TSA CA chain provided/found (tsa_cert_path='{}'). \
For court-grade verification, run `stamp keygen rfc3161` and then pass --tsa-cert <chain.pem> (or configure a default).",
                config.tsa_cert_path.display()
            );
        } else if let (Some(ref tsr_path), Some(ref tsq_path)) = (output_paths.timestamp_response.as_ref(), output_paths.timestamp_query.as_ref()) {
            let verification_result = verify_timestamp_response_files(tsr_path, tsq_path, &config.tsa_cert_path);
            match verification_result {
                Ok(true) => info!("Timestamp cryptographic verification successful (trusted chain)"),
                Ok(false) => warn!("Timestamp cryptographic verification FAILED (trusted chain)"),
                Err(e) => warn!("Timestamp cryptographic verification ERROR: {}", e),
            }
        } else {
            warn!("Skipping verification: expected output .tsr/.tsq paths were not available");
        }
    }
    
    let generated_files = output_paths.existing_paths();
    
    let mut result = TimestampResult::success(
        TimestampType::Rfc3161,
        input_file.clone(),
        generated_files,
    );
    
    result = result
        .with_metadata("tsa_url".to_string(), config.tsa_url.clone())
        .with_metadata("file_size".to_string(), file_data.len().to_string())
        .with_metadata("timestamp_created".to_string(), chrono::Utc::now().to_rfc3339());
    
    Ok(result)
}

#[derive(Debug)]
pub struct VerificationResult {
    pub success: bool,
    pub current_hash: String,
    pub timestamped_hash: String,
    pub timestamp_date: String,
    pub hash_algorithm: String,
}

pub fn verify_timestamp(file: &PathBuf, timestamp_file: &PathBuf) -> AnyhowResult<VerificationResult> {
    use std::process::Command;
    
    let output = Command::new("openssl")
        .args(&["ts", "-reply", "-in", timestamp_file.to_str().unwrap(), "-text"])
        .output()
        .with_context(|| "Failed to execute openssl ts command")?;
    
    if !output.status.success() {
        return Err(anyhow::anyhow!("Timestamp file is invalid or corrupted"));
    }
    
    let timestamp_info = String::from_utf8_lossy(&output.stdout);
    
    let status = extract_timestamp_status(&timestamp_info)?;
    if status != "Granted" {
        return Err(anyhow::anyhow!("Timestamp status is not Granted: {}", status));
    }
    
    let timestamp_date = extract_timestamp_date(&timestamp_info)?;
    let hash_algorithm = extract_hash_algorithm(&timestamp_info)?;
    
    if hash_algorithm != "sha256" {
        return Err(anyhow::anyhow!("Unsupported hash algorithm: {}", hash_algorithm));
    }
    
    let current_hash = calculate_file_hash(file)?;
    
    let timestamped_hash = extract_timestamped_hash(&timestamp_info)?;
    
    let success = current_hash == timestamped_hash;
    
    Ok(VerificationResult {
        success,
        current_hash,
        timestamped_hash,
        timestamp_date,
        hash_algorithm,
    })
}

fn extract_timestamp_status(timestamp_info: &str) -> AnyhowResult<String> {
    for line in timestamp_info.lines() {
        if line.contains("Status:") {
            let status = line.split_whitespace()
                .nth(1)
                .ok_or_else(|| anyhow::anyhow!("Could not extract status"))?
                .trim_end_matches('.');
            return Ok(status.to_string());
        }
    }
    Err(anyhow::anyhow!("Could not find timestamp status"))
}

fn extract_timestamp_date(timestamp_info: &str) -> AnyhowResult<String> {
    for line in timestamp_info.lines() {
        if line.contains("Time stamp:") {
            let date = line.replace("Time stamp: ", "").trim().to_string();
            return Ok(date);
        }
    }
    Err(anyhow::anyhow!("Could not extract timestamp date"))
}

fn extract_hash_algorithm(timestamp_info: &str) -> AnyhowResult<String> {
    for line in timestamp_info.lines() {
        if line.contains("Hash Algorithm:") {
            let algo = line.split_whitespace()
                .nth(2)
                .ok_or_else(|| anyhow::anyhow!("Could not extract hash algorithm"))?;
            return Ok(algo.to_string());
        }
    }
    Err(anyhow::anyhow!("Could not find hash algorithm"))
}

fn calculate_file_hash(file: &PathBuf) -> AnyhowResult<String> {
    use std::process::Command;
    
    let output = Command::new("openssl")
        .args(&["dgst", "-sha256", "-hex", file.to_str().unwrap()])
        .output()
        .with_context(|| "Failed to calculate file hash")?;
    
    if !output.status.success() {
        return Err(anyhow::anyhow!("Failed to calculate file hash"));
    }
    
    let hash_output = String::from_utf8_lossy(&output.stdout);
    let hash = hash_output.split_whitespace()
        .nth(1)
        .ok_or_else(|| anyhow::anyhow!("Could not extract hash from openssl output"))?;
    
    Ok(hash.to_lowercase())
}

fn extract_timestamped_hash(timestamp_info: &str) -> AnyhowResult<String> {
    let mut in_message_data = false;
    let mut line1 = String::new();
    let mut line2 = String::new();
    
    for line in timestamp_info.lines() {
        if line.contains("Message data:") {
            in_message_data = true;
            continue;
        }
        
        if in_message_data {
            if line.contains("0000") {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 17 {
                    for i in 2..17 {
                        if i < parts.len() {
                            line1.push_str(parts[i]);
                        }
                    }
                }
            } else if line.contains("0010") {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 17 {
                    for i in 2..17 {
                        if i < parts.len() {
                            line2.push_str(parts[i]);
                        }
                    }
                }
                break;
            }
        }
    }
    
    if line1.is_empty() || line2.is_empty() {
        return Err(anyhow::anyhow!("Could not extract hash from timestamp"));
    }
    
    let combined_hash = format!("{}{}", line1, line2).to_lowercase();
    
    let clean_hash = combined_hash.chars()
        .filter(|c| c.is_ascii_hexdigit())
        .collect::<String>();
    
    if clean_hash.len() != 64 {
        return Err(anyhow::anyhow!("Invalid hash length: expected 64 characters, got {}", clean_hash.len()));
    }
    
    Ok(clean_hash)
}

#[derive(Debug, Default)]
pub struct BatchResult {
    pub total_files: usize,
    pub processed_files: usize,
    pub skipped_files: usize,
    pub failed_files: usize,
    pub errors: Vec<String>,
}

impl BatchResult {
    pub fn new() -> Self {
        Self::default()
    }
    
    pub fn add_processed(&mut self) {
        self.processed_files += 1;
    }
    
    pub fn add_skipped(&mut self) {
        self.skipped_files += 1;
    }
    
    pub fn add_failed(&mut self, error: String) {
        self.failed_files += 1;
        self.errors.push(error);
    }
    
    pub fn print_summary(&self) {
        println!("");
        println!("Batch Processing Summary:");
        println!("  Total files found: {}", self.total_files);
        println!("  Files processed: {}", self.processed_files);
        println!("  Files skipped: {}", self.skipped_files);
        println!("  Files failed: {}", self.failed_files);
        
        if !self.errors.is_empty() {
            eprintln!("");
            eprintln!("Errors encountered:");
            for error in &self.errors {
                eprintln!("  - {}", error);
            }
        }
        
        if self.failed_files == 0 && self.processed_files > 0 {
            println!("");
            println!("Batch processing completed successfully!");
        } else if self.failed_files > 0 {
            eprintln!("");
            eprintln!("Batch processing completed with {} errors", self.failed_files);
        }
    }
}

pub fn process_directory_batch(
    input_dir: &PathBuf,
    output_dir: &PathBuf,
    tsa_url: &str,
    tsa_cert_path: &Option<PathBuf>,
    no_verify: bool,
    recursive: bool,
    dry_run: bool,
    re_timestamp: bool,
    use_git: bool,
    verbose: bool,
    cleanup: bool,
    result: &mut BatchResult,
) -> AnyhowResult<()> {
    // Clean up orphaned timestamp files if requested (only with git)
    if cleanup && !use_git {
        return Err(anyhow::anyhow!("Cleanup option requires --use-git flag. Git provides reliable change detection needed for timestamp synchronization."));
    }
    
    if use_git {
        // Git-based workflow
        let input_dir_abs = input_dir.canonicalize()
            .with_context(|| format!("Cannot canonicalize input directory: {}", input_dir.display()))?;
        let parent_dir = input_dir_abs.parent()
            .ok_or_else(|| anyhow::anyhow!("Cannot determine parent directory of input directory"))?;
        
        
        // Ensure git repository exists
        ensure_git_repository(parent_dir)?;
        
        // Get changed, untracked, and deleted files
        let changed_files = get_git_changed_files(&input_dir_abs, parent_dir)?;
        let untracked_files = get_git_untracked_files(&input_dir_abs, parent_dir)?;
        
        // Clean up timestamps for deleted files if cleanup is requested
        if cleanup {
            let deleted_files = get_git_deleted_files(&input_dir_abs, parent_dir)?;
            cleanup_deleted_file_timestamps(&deleted_files, output_dir, verbose)?;
        }
        
        let files_to_process: Vec<_> = changed_files.clone().into_iter()
            .chain(untracked_files.clone().into_iter())
            .collect();
        
        // Count total files in source directory for accurate reporting
        let total_files = if recursive {
            WalkDir::new(input_dir).into_iter().filter(|entry| {
                if let Ok(entry) = entry {
                    entry.path().is_file() && !should_skip_file(entry.path())
                } else {
                    false
                }
            }).count()
        } else {
            WalkDir::new(input_dir).max_depth(1).into_iter().filter(|entry| {
                if let Ok(entry) = entry {
                    entry.path().is_file() && !should_skip_file(entry.path())
                } else {
                    false
                }
            }).count()
        };
        
        result.total_files = total_files;
        
        if files_to_process.is_empty() {
            println!("Git detected {} files in source directory, but none have changed since last commit", total_files);
            println!("No files to process (no changes detected by git)");
            
            // Log all files as "Not Modified" and "Skipped"
            if verbose {
                let walker = if recursive {
                    WalkDir::new(input_dir).into_iter()
                } else {
                    WalkDir::new(input_dir).max_depth(1).into_iter()
                };
                
                for entry in walker {
                    if let Ok(entry) = entry {
                        let path = entry.path();
                        if path.is_file() && !should_skip_file(path) {
                            let filename = path.file_name()
                                .and_then(|name| name.to_str())
                                .unwrap_or("unknown");
                            log_file_processing("INFO", FileStatus::NotModified, filename, TimestampProcess::Skipped, verbose);
                        }
                    }
                }
            }
            
            // Mark all files as skipped since none needed processing
            for _ in 0..total_files {
                result.add_skipped();
            }
        } else {
            println!("Git detected {} files to process:", files_to_process.len());
            
            
            // Mark non-processed files as skipped
            let skipped_count = total_files - files_to_process.len();
            for _ in 0..skipped_count {
                result.add_skipped();
            }
        }
        
        let files_to_process_count = files_to_process.len();
        
        for path in &files_to_process {
            let filename = path.file_name()
                .and_then(|name| name.to_str())
                .unwrap_or("unknown");
            
            // Determine if this is a new file or modified file
            let file_status = if untracked_files.contains(path) {
                FileStatus::New
            } else {
                FileStatus::Modified
            };
            
            if dry_run {
                println!("Would process: {}", path.display());
                log_file_processing("INFO", file_status, filename, TimestampProcess::Processed, verbose);
                result.add_processed();
            } else {
                match process_single_file_batch(path, output_dir, tsa_url, tsa_cert_path, no_verify) {
                    Ok(_) => {
                        println!("Processed: {}", path.display());
                        log_file_processing("INFO", file_status, filename, TimestampProcess::Processed, verbose);
                        result.add_processed();
                    }
                    Err(e) => {
                        eprintln!("Failed to process {}: {}", path.display(), e);
                        log_file_processing("ERROR", file_status, filename, TimestampProcess::Error, verbose);
                        result.add_failed(format!("{}: {}", path.display(), e));
                    }
                }
            }
        }
        
        // Log skipped files
        if verbose {
            let skipped_count = total_files - files_to_process_count;
            if skipped_count > 0 {
                let walker = if recursive {
                    WalkDir::new(input_dir).into_iter()
                } else {
                    WalkDir::new(input_dir).max_depth(1).into_iter()
                };
                
                for entry in walker {
                    if let Ok(entry) = entry {
                        let path = entry.path();
                        if path.is_file() && !should_skip_file(path) && !files_to_process.contains(&path.to_path_buf()) {
                            let filename = path.file_name()
                                .and_then(|name| name.to_str())
                                .unwrap_or("unknown");
                            log_file_processing("INFO", FileStatus::NotModified, filename, TimestampProcess::Skipped, verbose);
                        }
                    }
                }
            }
        }
        
        // Commit changes after processing
        if !dry_run {
            git_add_and_commit(&input_dir_abs, parent_dir)?;
        }
    } else {
        // Traditional workflow
        let walker = if recursive {
            WalkDir::new(input_dir).into_iter()
        } else {
            WalkDir::new(input_dir).max_depth(1).into_iter()
        };
        
        for entry in walker {
            let entry = entry?;
            let path = entry.path();
            
            if path.is_dir() {
                continue;
            }
            
            if should_skip_file(path) {
                continue;
            }
            
            result.total_files += 1;
            
            if has_timestamp(path, output_dir) {
                if re_timestamp {
                    // Check if file has changed since timestamping using existing verification logic
                    match file_has_changed_since_timestamp(path, output_dir) {
                        Ok(has_changed) => {
                            if has_changed {
                                println!("Re-timestamping {} (file has changed since last timestamp)", path.display());
                                let filename = path.file_name()
                                    .and_then(|name| name.to_str())
                                    .unwrap_or("unknown");
                                log_file_processing("INFO", FileStatus::Modified, filename, TimestampProcess::Processed, verbose);
                                // Continue to process the file
                            } else {
                                println!("Skipping {} (already timestamped and unchanged)", path.display());
                                let filename = path.file_name()
                                    .and_then(|name| name.to_str())
                                    .unwrap_or("unknown");
                                log_file_processing("INFO", FileStatus::NotModified, filename, TimestampProcess::Skipped, verbose);
                                result.add_skipped();
                                continue;
                            }
                        }
                        Err(e) => {
                            eprintln!("Warning: Could not verify timestamp for {}: {}", path.display(), e);
                            println!("Re-timestamping {} (verification failed)", path.display());
                            let filename = path.file_name()
                                .and_then(|name| name.to_str())
                                .unwrap_or("unknown");
                            log_file_processing("WARNING", FileStatus::Modified, filename, TimestampProcess::Processed, verbose);
                            // Continue to process the file
                        }
                    }
                } else {
                    println!("Skipping {} (already timestamped)", path.display());
                    let filename = path.file_name()
                        .and_then(|name| name.to_str())
                        .unwrap_or("unknown");
                    log_file_processing("INFO", FileStatus::NotModified, filename, TimestampProcess::Skipped, verbose);
                    result.add_skipped();
                    continue;
                }
            } else {
                // New file (no existing timestamp)
                let filename = path.file_name()
                    .and_then(|name| name.to_str())
                    .unwrap_or("unknown");
                log_file_processing("INFO", FileStatus::New, filename, TimestampProcess::Processed, verbose);
            }
            
            if dry_run {
                println!("Would process: {}", path.display());
                result.add_processed();
            } else {
                match process_single_file_batch(path, output_dir, tsa_url, tsa_cert_path, no_verify) {
                    Ok(_) => {
                        println!("Processed: {}", path.display());
                        result.add_processed();
                    }
                    Err(e) => {
                        eprintln!("Failed to process {}: {}", path.display(), e);
                        result.add_failed(format!("{}: {}", path.display(), e));
                        
                        // Log error if verbose logging is enabled
                        let filename = path.file_name()
                            .and_then(|name| name.to_str())
                            .unwrap_or("unknown");
                        log_file_processing("ERROR", FileStatus::New, filename, TimestampProcess::Error, verbose);
                    }
                }
            }
        }
    }
    
    Ok(())
}

fn should_skip_file(path: &std::path::Path) -> bool {
    if let Some(filename) = path.file_name() {
        if let Some(name) = filename.to_str() {
            if name.starts_with('.') {
                return true;
            }
        }
    }
    
    if let Some(extension) = path.extension() {
        if let Some(ext) = extension.to_str() {
            match ext.to_lowercase().as_str() {
                "tmp" | "temp" | "log" | "bak" | "backup" | "old" => return true,
                _ => {}
            }
        }
    }
    
    false
}

fn has_timestamp(input_file: &std::path::Path, output_dir: &PathBuf) -> bool {
    if let Some(filename) = input_file.file_stem() {
        if let Some(name) = filename.to_str() {
            let tsr_path = output_dir.join(format!("{}.tsr", name));
            return tsr_path.exists();
        }
    }
    false
}

fn file_has_changed_since_timestamp(input_file: &std::path::Path, output_dir: &PathBuf) -> AnyhowResult<bool> {
    if let Some(filename) = input_file.file_stem() {
        if let Some(name) = filename.to_str() {
            let tsr_path = output_dir.join(format!("{}.tsr", name));
            if !tsr_path.exists() {
                return Ok(false);
            }
            
            // Use existing verification logic to check if file hash matches timestamp
            match verify_timestamp(&input_file.to_path_buf(), &tsr_path) {
                Ok(verification_result) => {
                    // If verification fails (success = false), file has changed
                    return Ok(!verification_result.success);
                }
                Err(_) => {
                    // If verification fails due to error, assume file needs re-timestamping
                    return Ok(true);
                }
            }
        }
    }
    Ok(false)
}

/// Git-based change detection functions
fn create_git_command() -> std::process::Command {
    std::process::Command::new("/usr/bin/git")
}

/// Get git-deleted files (files that existed before but are now deleted)
fn get_git_deleted_files(source_dir: &std::path::Path, parent_dir: &std::path::Path) -> AnyhowResult<Vec<std::path::PathBuf>> {
    let mut cmd = create_git_command();
    cmd.current_dir(parent_dir)
        .args(&["diff", "--name-only", "--diff-filter=D", "HEAD"]);
    
    let output = cmd.output()
        .with_context(|| "Failed to execute git diff for deleted files")?;
    
    if !output.status.success() {
        // If no commits exist yet, return empty list
        if output.status.code() == Some(128) {
            return Ok(Vec::new());
        }
        return Err(anyhow::anyhow!("Git diff failed: {}", String::from_utf8_lossy(&output.stderr)));
    }
    
    let deleted_files: Vec<std::path::PathBuf> = String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter_map(|line| {
            let path = std::path::Path::new(line);
            // Only include files within the source directory
            if path.starts_with(source_dir.strip_prefix(parent_dir).unwrap_or(source_dir)) {
                Some(source_dir.join(path.strip_prefix(source_dir.strip_prefix(parent_dir).unwrap_or(source_dir)).unwrap_or(path)))
            } else {
                None
            }
        })
        .filter(|path| !should_skip_file(path))
        .collect();
    
    Ok(deleted_files)
}

/// Clean up timestamp files for deleted source files
fn cleanup_deleted_file_timestamps(
    deleted_files: &[std::path::PathBuf],
    output_dir: &PathBuf,
    verbose: bool,
) -> AnyhowResult<()> {
    let mut cleaned_count = 0;
    
    for deleted_file in deleted_files {
        // Get the file stem (name without extension) to find the corresponding timestamp file
        if let Some(file_stem) = deleted_file.file_stem() {
            if let Some(stem_str) = file_stem.to_str() {
                let timestamp_file = output_dir.join(format!("{}.tsr", stem_str));
                let timestamp_query = output_dir.join(format!("{}.tsq", stem_str));
                let timestamp_certs = output_dir.join(format!("{}.tsr.certs.pem", stem_str));
                
                if timestamp_file.exists() {
                    if verbose {
                        let filename = deleted_file.file_name()
                            .and_then(|name| name.to_str())
                            .unwrap_or("unknown");
                        log_file_processing("INFO", FileStatus::NotModified, filename, TimestampProcess::Skipped, true);
                        println!("Cleaning up timestamp for deleted file: {} -> {}", deleted_file.display(), timestamp_file.display());
                    }
                    
                    // Remove all associated timestamp files
                    let files_to_remove = vec![timestamp_file.clone(), timestamp_query, timestamp_certs];
                    for file in files_to_remove {
                        if file.exists() {
                            if let Err(e) = std::fs::remove_file(&file) {
                                eprintln!("Warning: Failed to remove timestamp file {}: {}", file.display(), e);
                            } else if verbose {
                                println!("Removed timestamp file: {}", file.display());
                            }
                        }
                    }
                    
                    cleaned_count += 1;
                    if verbose {
                        println!("Removed timestamp for deleted file: {}", timestamp_file.display());
                    }
                }
            }
        }
    }
    
    if cleaned_count > 0 {
        println!("Cleaned up {} timestamp files for deleted source files", cleaned_count);
    } else if verbose {
        println!("No timestamp files to clean up for deleted files");
    }
    
    Ok(())
}


/// Logging functions for detailed file processing information
#[derive(Debug, Clone, Copy)]
pub enum FileStatus {
    New,
    Modified,
    NotModified,
}

#[derive(Debug, Clone, Copy)]
pub enum TimestampProcess {
    Processed,
    Skipped,
    Error,
}

fn log_file_processing(
    level: &str,
    file_status: FileStatus,
    filename: &str,
    timestamp_process: TimestampProcess,
    verbose: bool,
) {
    if verbose {
        let now = chrono::Utc::now();
        let timestamp = now.format("%Y-%m-%d@%H:%M:%S:%3f").to_string();
        
        // Color the log level
        let colored_level = match level {
            "ERROR" => level.red().bold(),
            "WARNING" => level.yellow().bold(),
            _ => level.normal(), // INFO uses default terminal color
        };
        
        // Color the file status and everything after the date
        let (_file_status_str, colored_content) = match file_status {
            FileStatus::New => {
                let status = "New".green().bold();
                let colored_filename = filename.green().bold();
                let colored_line = format!("{} {} {}", status, colored_filename, match timestamp_process {
                    TimestampProcess::Processed => "Processed".green(),
                    TimestampProcess::Skipped => "Skipped".bright_black(),
                    TimestampProcess::Error => "Error".red(),
                });
                ("New", colored_line)
            },
            FileStatus::Modified => {
                let status = "Modified".bright_yellow().bold();
                let colored_filename = filename.bright_yellow().bold();
                let colored_line = format!("{} {} {}", status, colored_filename, match timestamp_process {
                    TimestampProcess::Processed => "Processed".bright_yellow(),
                    TimestampProcess::Skipped => "Skipped".bright_black(),
                    TimestampProcess::Error => "Error".red(),
                });
                ("Modified", colored_line)
            },
            FileStatus::NotModified => {
                let status = "Not Modified".bright_black();
                let colored_filename = filename.bright_black();
                let colored_line = format!("{} {} {}", status, colored_filename, match timestamp_process {
                    TimestampProcess::Processed => "Processed".green(),
                    TimestampProcess::Skipped => "Skipped".bright_black(),
                    TimestampProcess::Error => "Error".red(),
                });
                ("Not Modified", colored_line)
            },
        };
        
        let log_message = format!(
            "[{}] {} {}",
            colored_level,
            timestamp,
            colored_content
        );
        
        match level {
            "ERROR" => eprintln!("{}", log_message),
            "WARNING" => eprintln!("{}", log_message),
            _ => println!("{}", log_message),
        }
    }
}

fn ensure_git_repository(parent_dir: &std::path::Path) -> AnyhowResult<()> {
    let git_dir = parent_dir.join(".git");
    
    if !git_dir.exists() {
        println!("Initializing git repository in parent directory: {}", parent_dir.display());
        let output = create_git_command()
            .args(&["init"])
            .current_dir(parent_dir)
            .output()
            .with_context(|| "Failed to initialize git repository. Make sure git is installed.")?;
        
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(anyhow::anyhow!("Failed to initialize git repository: {}", stderr));
        }
        
        // Create a .gitignore to avoid tracking timestamp files and other artifacts
        let gitignore_content = "# StampTime - Ignore timestamp files and artifacts\n*.tsr\n*.tsq\n*.p12\n*.pem\n*.crt\n.DS_Store\n*.tmp\n*.log\n";
        std::fs::write(parent_dir.join(".gitignore"), gitignore_content)
            .with_context(|| "Failed to create .gitignore file")?;
    }
    
    Ok(())
}

fn get_git_changed_files(source_dir: &std::path::Path, parent_dir: &std::path::Path) -> AnyhowResult<Vec<std::path::PathBuf>> {
    // Check if there are any commits (if not, no files are changed relative to HEAD)
    let log_output = create_git_command()
        .args(&["log", "--oneline", "-1"])
        .current_dir(parent_dir)
        .output()
        .with_context(|| "Failed to check git log")?;
    
    // If no commits exist (exit code 128 is typical for "no commits"), return empty list
    if !log_output.status.success() {
        let stderr = String::from_utf8_lossy(&log_output.stderr);
        if stderr.contains("does not have any commits") || log_output.status.code() == Some(128) {
            return Ok(Vec::new());
        } else {
            return Err(anyhow::anyhow!("Git log failed: {}", stderr));
        }
    }
    
    let output = create_git_command()
        .args(&["diff", "--name-only", "--diff-filter=AM", "HEAD"])
        .current_dir(parent_dir)
        .output()
        .with_context(|| "Failed to run git diff command")?;
    
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(anyhow::anyhow!("Git diff failed: {}", stderr));
    }
    
    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut changed_files = Vec::new();
    
    for line in stdout.lines() {
        let file_path = parent_dir.join(line);
        if file_path.starts_with(source_dir) && file_path.is_file() && !should_skip_file(&file_path) {
            changed_files.push(file_path);
        }
    }
    
    Ok(changed_files)
}

fn get_git_untracked_files(source_dir: &std::path::Path, parent_dir: &std::path::Path) -> AnyhowResult<Vec<std::path::PathBuf>> {
    let output = create_git_command()
        .args(&["ls-files", "--others", "--exclude-standard"])
        .current_dir(parent_dir)
        .output()
        .with_context(|| "Failed to run git ls-files command")?;
    
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(anyhow::anyhow!("Git ls-files failed: {}", stderr));
    }
    
    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut untracked_files = Vec::new();
    
    for line in stdout.lines() {
        let file_path = parent_dir.join(line);
        if file_path.starts_with(source_dir) && file_path.is_file() && !should_skip_file(&file_path) {
            untracked_files.push(file_path);
        }
    }
    
    Ok(untracked_files)
}

fn git_add_and_commit(source_dir: &std::path::Path, parent_dir: &std::path::Path) -> AnyhowResult<()> {
    // Add all files in the source directory
    let output = create_git_command()
        .args(&["add", source_dir.to_str().unwrap()])
        .current_dir(parent_dir)
        .output()
        .with_context(|| "Failed to run git add command")?;
    
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(anyhow::anyhow!("Git add failed: {}", stderr));
    }
    
    // Check if there are any changes to commit
    let status_output = create_git_command()
        .args(&["diff", "--cached", "--quiet"])
        .current_dir(parent_dir)
        .output()
        .with_context(|| "Failed to check git status")?;
    
    // If exit code is 0, there are no changes to commit
    if status_output.status.success() {
        println!("No changes to commit");
        return Ok(());
    }
    
    // Commit the changes
    let timestamp = chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC").to_string();
    let commit_message = format!("StampTime batch processing - {}", timestamp);
    
    let output = create_git_command()
        .args(&["commit", "-m", &commit_message])
        .current_dir(parent_dir)
        .output()
        .with_context(|| "Failed to run git commit command")?;
    
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(anyhow::anyhow!("Git commit failed: {}", stderr));
    }
    
    println!("Git commit successful: {}", commit_message);
    Ok(())
}

fn process_single_file_batch(
    input_file: &std::path::Path,
    output_dir: &PathBuf,
    tsa_url: &str,
    tsa_cert_path: &Option<PathBuf>,
    no_verify: bool,
) -> AnyhowResult<()> {
    let config = TimestampConfig::new(tsa_url.to_string())
        .with_tsa_cert_path(tsa_cert_path.clone().unwrap_or_default())
        .with_output_dir(output_dir.clone())
        .with_verification(!no_verify);
    
    timestamp_file(&input_file.to_path_buf(), &config)?;
    
    Ok(())
}

/// File types that can be inspected
#[derive(Debug, Clone)]
pub enum InspectableFileType {
    TimestampResponse,
    TimestampQuery,
    Certificate,
    Unknown,
}

/// Main inspection function that determines file type and displays appropriate information
pub fn inspect_file(file_path: &PathBuf) -> AnyhowResult<()> {
    let file_type = detect_file_type(file_path)?;
    
    println!("File: {}", file_path.display());
    println!("Type: {}", format_file_type(&file_type));
    println!("Size: {} bytes", std::fs::metadata(file_path)?.len());
    println!();
    
    match file_type {
        InspectableFileType::TimestampResponse => {
            inspect_timestamp_response(file_path)?;
        }
        InspectableFileType::TimestampQuery => {
            inspect_timestamp_query(file_path)?;
        }
        InspectableFileType::Certificate => {
            inspect_certificate(file_path)?;
        }
        InspectableFileType::Unknown => {
            println!("Unknown file type. Cannot determine if this is a timestamp response, query, or certificate.");
            println!("Supported file types:");
            println!("   Timestamp Response (.tsr)");
            println!("   Timestamp Query (.tsq)");
            println!("   Certificate (.pem, .crt, .cer, .p12)");
        }
    }
    
    Ok(())
}

/// Detect the type of file based on extension and content
fn detect_file_type(file_path: &PathBuf) -> AnyhowResult<InspectableFileType> {
    // First check by file extension
    if let Some(extension) = file_path.extension() {
        if let Some(ext) = extension.to_str() {
            match ext.to_lowercase().as_str() {
                "tsr" => return Ok(InspectableFileType::TimestampResponse),
                "tsq" => return Ok(InspectableFileType::TimestampQuery),
                "pem" | "crt" | "cer" => return Ok(InspectableFileType::Certificate),
                "p12" | "pfx" => return Ok(InspectableFileType::Certificate),
                _ => {}
            }
        }
    }
    
    // If extension doesn't help, try to detect by content
    let file_data = std::fs::read(file_path)?;
    
    // Check if it's a timestamp response by trying to parse it
    if is_timestamp_response(&file_data) {
        return Ok(InspectableFileType::TimestampResponse);
    }
    
    // Check if it's a timestamp query
    if is_timestamp_query(&file_data) {
        return Ok(InspectableFileType::TimestampQuery);
    }
    
    // Check if it's a certificate
    if is_certificate(&file_data) {
        return Ok(InspectableFileType::Certificate);
    }
    
    Ok(InspectableFileType::Unknown)
}

/// Check if data appears to be a timestamp response
fn is_timestamp_response(data: &[u8]) -> bool {
    // Try to use OpenSSL to parse as timestamp response
    use std::process::Command;
    use tempfile::NamedTempFile;
    
    if let Ok(mut temp_file) = NamedTempFile::new() {
        if temp_file.write_all(data).is_ok() && temp_file.flush().is_ok() {
            let output = Command::new("openssl")
                .args(&["ts", "-reply", "-in", temp_file.path().to_str().unwrap(), "-text"])
                .output();
            
            if let Ok(output) = output {
                return output.status.success();
            }
        }
    }
    false
}

/// Check if data appears to be a timestamp query
fn is_timestamp_query(data: &[u8]) -> bool {
    // Try to use OpenSSL to parse as timestamp query
    use std::process::Command;
    use tempfile::NamedTempFile;
    
    if let Ok(mut temp_file) = NamedTempFile::new() {
        if temp_file.write_all(data).is_ok() && temp_file.flush().is_ok() {
            let output = Command::new("openssl")
                .args(&["ts", "-query", "-in", temp_file.path().to_str().unwrap(), "-text"])
                .output();
            
            if let Ok(output) = output {
                return output.status.success();
            }
        }
    }
    false
}

/// Check if data appears to be a certificate
fn is_certificate(data: &[u8]) -> bool {
    // Check for PEM format
    if let Ok(text) = std::str::from_utf8(data) {
        if text.contains("-----BEGIN CERTIFICATE-----") {
            return true;
        }
        if text.contains("-----BEGIN PKCS12-----") {
            return true;
        }
    }
    
    // Try to parse as DER certificate
    use std::process::Command;
    use tempfile::NamedTempFile;
    
    if let Ok(mut temp_file) = NamedTempFile::new() {
        if temp_file.write_all(data).is_ok() && temp_file.flush().is_ok() {
            let output = Command::new("openssl")
                .args(&["x509", "-inform", "DER", "-in", temp_file.path().to_str().unwrap(), "-text", "-noout"])
                .output();
            
            if let Ok(output) = output {
                return output.status.success();
            }
            
            // Try PEM format
            let output = Command::new("openssl")
                .args(&["x509", "-in", temp_file.path().to_str().unwrap(), "-text", "-noout"])
                .output();
            
            if let Ok(output) = output {
                return output.status.success();
            }
        }
    }
    
    false
}

/// Format file type for display
fn format_file_type(file_type: &InspectableFileType) -> &'static str {
    match file_type {
        InspectableFileType::TimestampResponse => "Timestamp Response (.tsr)",
        InspectableFileType::TimestampQuery => "Timestamp Query (.tsq)",
        InspectableFileType::Certificate => "Certificate",
        InspectableFileType::Unknown => "Unknown",
    }
}

/// Inspect a timestamp response file
fn inspect_timestamp_response(file_path: &PathBuf) -> AnyhowResult<()> {
    let file_data = std::fs::read(file_path)?;
    
    // Get detailed information using OpenSSL
    let tsr_info = get_timestamp_response_info(&file_data)?;
    
    println!("=== TIMESTAMP RESPONSE INFORMATION ===");
    println!("=== (RFC 3161 Compliant - Legal Evidence) ===");
    println!();
    
    // Status - critical for legal validity
    if let Some(status) = tsr_info.get("Status") {
        println!("Status: {}", status);
        if status.contains("Granted") {
            println!("  [VALID] Timestamp was successfully granted by TSA");
        }
    }
    
    // Policy OID - important for legal traceability
    if let Some(policy) = tsr_info.get("Policy OID") {
        println!("Policy OID: {}", policy);
        println!("  (Identifies the TSA's timestamping policy for legal reference)");
    }
    
    // Timestamp - the legally binding time
    if let Some(timestamp) = tsr_info.get("Time stamp") {
        println!("Timestamp (UTC): {}", timestamp);
        println!("  (This is the legally binding time of existence proof)");
    }
    
    // Hash Algorithm - must be SHA-256 or stronger for legal validity
    if let Some(hash_algo) = tsr_info.get("Hash Algorithm") {
        println!("Hash Algorithm: {}", hash_algo);
        if hash_algo.contains("sha256") || hash_algo.contains("sha384") || hash_algo.contains("sha512") {
            println!("  [COMPLIANT] Algorithm meets legal requirements");
        } else if hash_algo.contains("sha1") {
            println!("  [WARNING] SHA-1 is deprecated and may not be accepted in legal contexts");
        }
    }
    
    // Serial Number - unique identifier for this timestamp
    if let Some(serial) = tsr_info.get("Serial number") {
        println!("Serial Number: {}", serial);
        println!("  (Unique identifier for this timestamp - useful for audit trails)");
    }
    
    // Message Imprint (Hash of the original document)
    if let Some(message_imprint) = tsr_info.get("Message data") {
        println!("Message Imprint (Document Hash): {}", message_imprint);
    }
    
    // TSA Information
    if let Some(tsa) = tsr_info.get("TSA") {
        println!("TSA (Timestamp Authority): {}", tsa);
    }
    
    // Accuracy
    if let Some(accuracy) = tsr_info.get("Accuracy") {
        println!("Accuracy: {}", accuracy);
    }
    
    // Ordering
    if let Some(ordering) = tsr_info.get("Ordering") {
        println!("Ordering: {}", ordering);
    }
    
    // Nonce - prevents replay attacks
    if let Some(nonce) = tsr_info.get("Nonce") {
        println!("Nonce: {}", nonce);
        println!("  (Anti-replay protection - ensures timestamp freshness)");
    }
    
    if let Some(tsa_cert_id) = tsr_info.get("TSA Cert ID") {
        println!("TSA Certificate ID: {}", tsa_cert_id);
    }
    
    // Version
    if let Some(version) = tsr_info.get("Version") {
        println!("TST Version: {}", version);
    }
    
    // Show embedded certificates for verification chain
    let certificates = extract_timestamp_certificates(&file_data)?;
    if !certificates.is_empty() && certificates[0] != "No certificates found in timestamp response" {
        println!();
        println!("=== EMBEDDED CERTIFICATES ({} found) ===", certificates.len());
        println!("(These certificates form the trust chain for verification)");
        println!();
        
        for (i, cert) in certificates.iter().enumerate() {
            println!("--- Certificate {} ---", i + 1);
            // Parse and display key certificate info
            if cert.contains("-----BEGIN CERTIFICATE-----") {
                // Extract subject and issuer from the certificate
                use std::process::Command;
                use tempfile::NamedTempFile;
                
                if let Ok(mut temp_cert) = NamedTempFile::new() {
                    if temp_cert.write_all(cert.as_bytes()).is_ok() && temp_cert.flush().is_ok() {
                        let cert_info = Command::new("openssl")
                            .args(&["x509", "-in", temp_cert.path().to_str().unwrap(), "-noout", "-subject", "-issuer", "-dates"])
                            .output();
                        
                        if let Ok(output) = cert_info {
                            if output.status.success() {
                                println!("{}", String::from_utf8_lossy(&output.stdout));
                            }
                        }
                    }
                }
            } else {
                println!("{}", cert);
            }
            if i < certificates.len() - 1 {
                println!();
            }
        }
    } else {
        println!();
        println!("Note: No embedded certificates found in response.");
        println!("For legal verification, use the TSA certificate chain from 'stamp keygen rfc3161'");
    }
    
    println!();
    println!("=== LEGAL NOTES ===");
    println!(" This timestamp provides cryptographic proof that the document existed at the stated time");
    println!(" For court admissibility, preserve both the original file and this .tsr file");
    println!(" Verification can be performed independently using OpenSSL or this tool");
    println!(" The Policy OID identifies the legal framework under which the timestamp was issued");
    
    Ok(())
}

/// Inspect a timestamp query file
fn inspect_timestamp_query(file_path: &PathBuf) -> AnyhowResult<()> {
    let file_data = std::fs::read(file_path)?;
    
    // Get detailed information using OpenSSL
    let tsq_info = get_timestamp_query_info(&file_data)?;
    
    println!("=== TIMESTAMP QUERY INFORMATION ===");
    println!();
    
    // Basic information
    if let Some(version) = tsq_info.get("Version") {
        println!("Version: {}", version);
    }
    
    if let Some(policy) = tsq_info.get("Policy") {
        println!("Policy: {}", policy);
    }
    
    if let Some(hash_algo) = tsq_info.get("Hash Algorithm") {
        println!("Hash Algorithm: {}", hash_algo);
    }
    
    if let Some(message_imprint) = tsq_info.get("Message data") {
        println!("Message Imprint (Hash): {}", message_imprint);
    }
    
    if let Some(nonce) = tsq_info.get("Nonce") {
        println!("Nonce: {}", nonce);
    }
    
    if let Some(cert_req) = tsq_info.get("Cert req") {
        println!("Certificate Request: {}", cert_req);
    }
    
    if let Some(extensions) = tsq_info.get("Extensions") {
        println!("Extensions: {}", extensions);
    }
    
    Ok(())
}

/// Inspect a certificate file
fn inspect_certificate(file_path: &PathBuf) -> AnyhowResult<()> {
    let file_data = std::fs::read(file_path)?;
    
    // Determine certificate format and get information
    let cert_info = get_certificate_info(&file_data, file_path)?;
    
    println!("=== CERTIFICATE INFORMATION ===");
    println!();
    
    // Basic information
    if let Some(version) = cert_info.get("Version") {
        println!("Version: {}", version);
    }
    
    if let Some(serial) = cert_info.get("Serial Number") {
        println!("Serial Number: {}", serial);
    }
    
    if let Some(signature_algo) = cert_info.get("Signature Algorithm") {
        println!("Signature Algorithm: {}", signature_algo);
    }
    
    if let Some(issuer) = cert_info.get("Issuer") {
        println!("Issuer: {}", issuer);
    }
    
    if let Some(validity) = cert_info.get("Validity") {
        println!("Validity: {}", validity);
    }
    
    if let Some(not_before) = cert_info.get("Not Before") {
        println!("Not Before: {}", not_before);
    }
    
    if let Some(not_after) = cert_info.get("Not After") {
        println!("Not After: {}", not_after);
    }
    
    if let Some(subject) = cert_info.get("Subject") {
        println!("Subject: {}", subject);
    }
    
    if let Some(public_key) = cert_info.get("Public Key") {
        println!("Public Key: {}", public_key);
    }
    
    if let Some(key_usage) = cert_info.get("X509v3 Key Usage") {
        println!("Key Usage: {}", key_usage);
    }
    
    if let Some(ext_key_usage) = cert_info.get("X509v3 Extended Key Usage") {
        println!("Extended Key Usage: {}", ext_key_usage);
    }
    
    if let Some(basic_constraints) = cert_info.get("X509v3 Basic Constraints") {
        println!("Basic Constraints: {}", basic_constraints);
    }
    
    if let Some(subject_alt_name) = cert_info.get("X509v3 Subject Alternative Name") {
        println!("Subject Alternative Name: {}", subject_alt_name);
    }
    
    Ok(())
}

/// Get detailed information from a timestamp response
fn get_timestamp_response_info(tsr_data: &[u8]) -> AnyhowResult<std::collections::HashMap<String, String>> {
    use std::process::Command;
    use tempfile::NamedTempFile;
    
    let mut temp_tsr = NamedTempFile::new()
        .with_context(|| "Failed to create temporary TSR file")?;
    temp_tsr.write_all(tsr_data)
        .with_context(|| "Failed to write TSR data to temporary file")?;
    temp_tsr.flush()
        .with_context(|| "Failed to flush temporary TSR file")?;
    
    let output = Command::new("openssl")
        .args(&[
            "ts", "-reply", 
            "-in", temp_tsr.path().to_str().unwrap(),
            "-text"
        ])
        .output()
        .with_context(|| "Failed to execute openssl ts command")?;
    
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(anyhow::anyhow!("OpenSSL ts command failed: {}", stderr));
    }
    
    let tsr_text = String::from_utf8_lossy(&output.stdout);
    let _ = std::fs::remove_file(temp_tsr.path());
    
    parse_timestamp_info(&tsr_text)
}

/// Get detailed information from a timestamp query
fn get_timestamp_query_info(tsq_data: &[u8]) -> AnyhowResult<std::collections::HashMap<String, String>> {
    use std::process::Command;
    use tempfile::NamedTempFile;
    
    let mut temp_tsq = NamedTempFile::new()
        .with_context(|| "Failed to create temporary TSQ file")?;
    temp_tsq.write_all(tsq_data)
        .with_context(|| "Failed to write TSQ data to temporary file")?;
    temp_tsq.flush()
        .with_context(|| "Failed to flush temporary TSQ file")?;
    
    let output = Command::new("openssl")
        .args(&[
            "ts", "-query", 
            "-in", temp_tsq.path().to_str().unwrap(),
            "-text"
        ])
        .output()
        .with_context(|| "Failed to execute openssl ts command")?;
    
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(anyhow::anyhow!("OpenSSL ts command failed: {}", stderr));
    }
    
    let tsq_text = String::from_utf8_lossy(&output.stdout);
    let _ = std::fs::remove_file(temp_tsq.path());
    
    parse_timestamp_info(&tsq_text)
}

/// Get detailed information from a certificate
fn get_certificate_info(cert_data: &[u8], file_path: &PathBuf) -> AnyhowResult<std::collections::HashMap<String, String>> {
    use std::process::Command;
    use tempfile::NamedTempFile;
    
    let mut temp_cert = NamedTempFile::new()
        .with_context(|| "Failed to create temporary certificate file")?;
    temp_cert.write_all(cert_data)
        .with_context(|| "Failed to write certificate data to temporary file")?;
    temp_cert.flush()
        .with_context(|| "Failed to flush temporary certificate file")?;
    
    // Try different formats
    let mut output = Command::new("openssl")
        .args(&[
            "x509", "-in", temp_cert.path().to_str().unwrap(),
            "-text", "-noout"
        ])
        .output();
    
    // If PEM format fails, try DER format
    if output.as_ref().map(|o| !o.status.success()).unwrap_or(true) {
        output = Command::new("openssl")
            .args(&[
                "x509", "-inform", "DER", "-in", temp_cert.path().to_str().unwrap(),
                "-text", "-noout"
            ])
            .output();
    }
    
    // If both fail, try PKCS#12 format
    if output.as_ref().map(|o| !o.status.success()).unwrap_or(true) {
        if let Some(extension) = file_path.extension() {
            if let Some(ext) = extension.to_str() {
                if ext.to_lowercase() == "p12" || ext.to_lowercase() == "pfx" {
                    output = Command::new("openssl")
                        .args(&[
                            "pkcs12", "-in", temp_cert.path().to_str().unwrap(),
                            "-nokeys", "-clcerts", "-passin", "pass:"
                        ])
                        .output();
                }
            }
        }
    }
    
    let output = output.with_context(|| "Failed to execute openssl x509 command")?;
    
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(anyhow::anyhow!("OpenSSL x509 command failed: {}", stderr));
    }
    
    let cert_text = String::from_utf8_lossy(&output.stdout);
    let _ = std::fs::remove_file(temp_cert.path());
    
    parse_certificate_info(&cert_text)
}

/// Parse timestamp information from OpenSSL output
fn parse_timestamp_info(text: &str) -> AnyhowResult<std::collections::HashMap<String, String>> {
    let mut info = std::collections::HashMap::new();
    
    for line in text.lines() {
        let line = line.trim();
        
        // Parse key-value pairs
        if let Some(colon_pos) = line.find(':') {
            let key = line[..colon_pos].trim();
            let value = line[colon_pos + 1..].trim();
            
            if !value.is_empty() {
                info.insert(key.to_string(), value.to_string());
            }
        }
    }
    
    Ok(info)
}

/// Parse certificate information from OpenSSL output
fn parse_certificate_info(text: &str) -> AnyhowResult<std::collections::HashMap<String, String>> {
    let mut info = std::collections::HashMap::new();
    
    for line in text.lines() {
        let line = line.trim();
        
        if line.is_empty() {
            continue;
        }
        
        // Parse key-value pairs with more flexible matching
        if let Some(colon_pos) = line.find(':') {
            let key = line[..colon_pos].trim();
            let value = line[colon_pos + 1..].trim();
            
            if !value.is_empty() {
                // Map OpenSSL output keys to our display keys
                let display_key = match key {
                    "Version" => "Version",
                    "Serial Number" => "Serial Number", 
                    "Signature Algorithm" => "Signature Algorithm",
                    "Issuer" => "Issuer",
                    "Validity" => "Validity",
                    "Not Before" => "Not Before",
                    "Not After" => "Not After", 
                    "Subject" => "Subject",
                    "Public Key" => "Public Key",
                    "X509v3 Key Usage" => "X509v3 Key Usage",
                    "X509v3 Extended Key Usage" => "X509v3 Extended Key Usage",
                    "X509v3 Basic Constraints" => "X509v3 Basic Constraints",
                    "X509v3 Subject Alternative Name" => "X509v3 Subject Alternative Name",
                    _ => continue, // Skip unknown keys
                };
                info.insert(display_key.to_string(), value.to_string());
            }
        }
    }
    
    Ok(info)
}
