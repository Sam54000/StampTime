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
    
    // Use OpenSSL to create timestamp query
    let output = Command::new("openssl")
        .args(&[
            "ts", "-query", 
            "-data", temp_file.path().to_str().unwrap(),
            "-cert",
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
    let output = Command::new("openssl")
        .args(&[
            "ts", "-verify",
            "-queryfile", temp_tsq.path().to_str().unwrap(),
            "-in", temp_tsr.path().to_str().unwrap(),
            "-no_check_time"  // Skip time validation for now
        ])
        .output()
        .with_context(|| "Failed to execute openssl ts verify command")?;
    
    let _ = std::fs::remove_file(temp_tsr.path());
    let _ = std::fs::remove_file(temp_tsq.path());
    
    if output.status.success() {
        Ok(true)
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        warn!("Timestamp verification failed: {}", stderr);
        Ok(false)
    }
}

pub fn send_timestamp_request(tsq_data: &[u8], tsa_url: &str) -> AnyhowResult<Vec<u8>> {
    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .with_context(|| "Failed to create HTTP client")?;
    
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
        info!("Verifying timestamp");
        let verification_result = verify_timestamp_response(&tsr_data, &tsq_data);
        match verification_result {
            Ok(true) => info!("Timestamp verification successful"),
            Ok(false) => warn!("Timestamp verification failed"),
            Err(e) => warn!("Timestamp verification error: {}", e),
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
