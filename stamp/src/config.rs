//! Configuration management for StampTime
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
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::io::{self, Write};
use tracing::info;

/// Validate that a path does not contain path traversal sequences or absolute paths
fn validate_path_component(path: &str) -> AnyhowResult<()> {
    if path.contains("..") {
        return Err(anyhow::anyhow!("Path cannot contain '..' sequences"));
    }
    if path.starts_with('/') {
        return Err(anyhow::anyhow!("Path cannot be absolute. Use relative paths only."));
    }
    if path.contains('\0') {
        return Err(anyhow::anyhow!("Path cannot contain null bytes"));
    }
    Ok(())
}

/// Validate and sanitize a path value
fn validate_path_value(path: &str) -> AnyhowResult<String> {
    let trimmed = path.trim();
    if trimmed.is_empty() {
        return Err(anyhow::anyhow!("Path cannot be empty"));
    }
    validate_path_component(trimmed)?;
    Ok(trimmed.to_string())
}

/// Validate a URL to prevent SSRF attacks
pub fn validate_url(url: &str) -> AnyhowResult<()> {
    let trimmed = url.trim();
    if trimmed.is_empty() {
        return Err(anyhow::anyhow!("URL cannot be empty"));
    }
    
    let url_lower = trimmed.to_lowercase();
    
    // Only allow http:// and https:// schemes
    if !url_lower.starts_with("http://") && !url_lower.starts_with("https://") {
        return Err(anyhow::anyhow!("URL must use http:// or https:// scheme"));
    }
    
    // Parse URL to check for private IPs
    if let Ok(parsed) = url::Url::parse(trimmed) {
        if let Some(host) = parsed.host_str() {
            // Block private IP ranges and localhost
            if host == "localhost" || host == "127.0.0.1" || host == "::1" {
                return Err(anyhow::anyhow!("URL cannot point to localhost"));
            }
            
            // Check for IP addresses
            if let Ok(ip) = host.parse::<std::net::IpAddr>() {
                match ip {
                    std::net::IpAddr::V4(ipv4) => {
                        let octets = ipv4.octets();
                        // Block private IP ranges
                        if octets[0] == 10
                            || (octets[0] == 172 && octets[1] >= 16 && octets[1] <= 31)
                            || (octets[0] == 192 && octets[1] == 168)
                            || (octets[0] == 169 && octets[1] == 254) // Link-local
                            || (octets[0] == 127) // Loopback
                        {
                            return Err(anyhow::anyhow!("URL cannot point to private or link-local IP addresses"));
                        }
                    }
                    std::net::IpAddr::V6(ipv6) => {
                        // Block IPv6 loopback and link-local
                        if ipv6.is_loopback() || ipv6.is_unspecified() {
                            return Err(anyhow::anyhow!("URL cannot point to IPv6 loopback or unspecified addresses"));
                        }
                    }
                }
            }
        }
    } else {
        return Err(anyhow::anyhow!("Invalid URL format"));
    }
    
    Ok(())
}

/// Get the default stamp configuration directory.
/// Returns `$HOME/.config/stamp/` on Unix-like systems.
pub fn get_config_dir() -> AnyhowResult<PathBuf> {
    let home = std::env::var("HOME")
        .with_context(|| "HOME environment variable not set")?;
    Ok(PathBuf::from(home).join(".config").join("stamp"))
}

/// Get the default configuration file path.
/// Returns `$HOME/.config/stamp/stamp.conf`
pub fn get_config_file_path() -> AnyhowResult<PathBuf> {
    Ok(get_config_dir()?.join("stamp.conf"))
}

/// Get the default TSA certificates directory.
/// Returns `$HOME/.config/stamp/tsa_certs/`
pub fn get_default_tsa_certs_dir() -> AnyhowResult<PathBuf> {
    Ok(get_config_dir()?.join("tsa_certs"))
}

/// Check if stamp has been initialized (config directory exists with config file)
pub fn is_initialized() -> bool {
    if let Ok(config_path) = get_config_file_path() {
        config_path.exists()
    } else {
        false
    }
}

/// Initialize the stamp configuration directory and create default config.
/// Creates `$HOME/.config/stamp/` with a default `stamp.conf` file.
pub fn initialize_config_dir() -> AnyhowResult<PathBuf> {
    let config_dir = get_config_dir()?;
    let config_file = get_config_file_path()?;
    let tsa_certs_dir = get_default_tsa_certs_dir()?;
    
    // Create directories
    std::fs::create_dir_all(&config_dir)
        .with_context(|| format!("Failed to create config directory: {}", config_dir.display()))?;
    std::fs::create_dir_all(&tsa_certs_dir)
        .with_context(|| format!("Failed to create TSA certs directory: {}", tsa_certs_dir.display()))?;
    
    // Create default config file if it doesn't exist
    if !config_file.exists() {
        let default_config = TsaConfigFile::with_default_paths()?;
        save_config_file(&default_config, &config_file)?;
        info!("Created default configuration: {}", config_file.display());
    }
    
    Ok(config_dir)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TsaConfigFile {
    pub tsa: TsaServerConfig,
    pub certificates: CertificateUrls,
    pub path: CertificatePath,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TsaServerConfig {
    pub url: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificateUrls {
    pub sha256_responder: String,
    pub sha384_responder: Option<String>,
    pub sha512_responder: Option<String>,
    pub intermediate: String,
    pub root: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificatePath {
    pub base: String,
    pub chain_dir: String,
    pub chain_filename: String,
}

impl Default for TsaConfigFile {
    fn default() -> Self {
        Self {
            tsa: TsaServerConfig {
                url: "https://timestamp.digicert.com".to_string(),
            },
            certificates: CertificateUrls {
                sha256_responder: "https://knowledge.digicert.com/content/dam/kb/attachments/time-stamp/DigiCertSHA256RSA4096TimestampResponder20251.cer".to_string(),
                sha384_responder: Some("https://knowledge.digicert.com/content/dam/kb/attachments/time-stamp/DigiCertSHA384RSA4096TimestampResponder20251.cer".to_string()),
                sha512_responder: Some("https://knowledge.digicert.com/content/dam/kb/attachments/time-stamp/DigiCertSHA512RSA4096TimestampResponder20251.cer".to_string()),
                intermediate: "https://knowledge.digicert.com/content/dam/kb/attachments/time-stamp/DigiCertTrustedG4TimeStampingRSA4096SHA2562025CA1.pem".to_string(),
                root: "https://knowledge.digicert.com/content/dam/kb/attachments/time-stamp/DigiCertTrustedRootG4.cer".to_string(),
            },
            path: CertificatePath {
                base: "./tsa_certs".to_string(),
                chain_dir: "chain".to_string(),
                chain_filename: "digicert_tsa_chain.pem".to_string(),
            },
        }
    }
}

impl TsaConfigFile {
    /// Create a config with default paths pointing to $HOME/.config/stamp/tsa_certs
    pub fn with_default_paths() -> AnyhowResult<Self> {
        let tsa_certs_dir = get_default_tsa_certs_dir()?;
        Ok(Self {
            tsa: TsaServerConfig {
                url: "https://timestamp.digicert.com".to_string(),
            },
            certificates: CertificateUrls {
                sha256_responder: "https://knowledge.digicert.com/content/dam/kb/attachments/time-stamp/DigiCertSHA256RSA4096TimestampResponder20251.cer".to_string(),
                sha384_responder: Some("https://knowledge.digicert.com/content/dam/kb/attachments/time-stamp/DigiCertSHA384RSA4096TimestampResponder20251.cer".to_string()),
                sha512_responder: Some("https://knowledge.digicert.com/content/dam/kb/attachments/time-stamp/DigiCertSHA512RSA4096TimestampResponder20251.cer".to_string()),
                intermediate: "https://knowledge.digicert.com/content/dam/kb/attachments/time-stamp/DigiCertTrustedG4TimeStampingRSA4096SHA2562025CA1.pem".to_string(),
                root: "https://knowledge.digicert.com/content/dam/kb/attachments/time-stamp/DigiCertTrustedRootG4.cer".to_string(),
            },
            path: CertificatePath {
                base: tsa_certs_dir.to_string_lossy().to_string(),
                chain_dir: "chain".to_string(),
                chain_filename: "digicert_tsa_chain.pem".to_string(),
            },
        })
    }
}

pub fn load_config_file(config_path: &PathBuf) -> AnyhowResult<TsaConfigFile> {
    if !config_path.exists() {
        return Err(anyhow::anyhow!("Configuration file not found: {}", config_path.display()));
    }
    
    let config_content = std::fs::read_to_string(config_path)
        .with_context(|| format!("Failed to read configuration file: {}", config_path.display()))?;
    
    let config: TsaConfigFile = toml::from_str(&config_content)
        .with_context(|| format!("Failed to parse configuration file: {}", config_path.display()))?;
    
    Ok(config)
}

pub fn save_config_file(config: &TsaConfigFile, config_path: &PathBuf) -> AnyhowResult<()> {
    let config_content = toml::to_string_pretty(config)
        .with_context(|| "Failed to serialize configuration")?;
    
    std::fs::write(config_path, config_content)
        .with_context(|| format!("Failed to write configuration file: {}", config_path.display()))?;
    
    Ok(())
}

pub fn find_tsa_cert_from_config() -> Option<PathBuf> {
    // Try to load configuration from default location ($HOME/.config/stamp/stamp.conf)
    if let Ok(default_config_path) = get_config_file_path() {
        if let Ok(config) = load_config_file(&default_config_path) {
            let cert_path = PathBuf::from(&config.path.base)
                .join(&config.path.chain_dir)
                .join(&config.path.chain_filename);
            
            if cert_path.exists() {
                return Some(cert_path);
            }
        }
    }
    
    // Fallback: try local config.toml for backwards compatibility
    let local_config_path = PathBuf::from("config.toml");
    if let Ok(config) = load_config_file(&local_config_path) {
        let cert_path = PathBuf::from(&config.path.base)
            .join(&config.path.chain_dir)
            .join(&config.path.chain_filename);
        
        if cert_path.exists() {
            return Some(cert_path);
        }
    }
    
    None
}

pub fn find_default_tsa_cert() -> Option<PathBuf> {
    // First, try to find certificate from configuration file
    if let Some(config_path) = find_tsa_cert_from_config() {
        return Some(config_path);
    }
    
    // Try the default stamp config directory
    if let Ok(tsa_certs_dir) = get_default_tsa_certs_dir() {
        let default_chain = tsa_certs_dir.join("chain").join("digicert_tsa_chain.pem");
        if default_chain.exists() {
            return Some(default_chain);
        }
    }
    
    // Fallback to common locations where tsa-setup might have placed certificates
    let mut common_locations = vec![
        // Current directory
        PathBuf::from("tsa_certs/chain/digicert_tsa_chain.pem"),
        PathBuf::from("chain/digicert_tsa_chain.pem"),
        PathBuf::from("digicert_tsa_chain.pem"),
    ];
    
    // Add home directory path if available
    if let Ok(home) = std::env::var("HOME") {
        common_locations.push(PathBuf::from(home).join("docs/chain/digicert_tsa_chain.pem"));
    }
    
    // Add work directory path if available
    if let Ok(workdir) = std::env::var("WORKDIR") {
        common_locations.push(PathBuf::from(workdir).join("chain/digicert_tsa_chain.pem"));
    }
    
    for location in common_locations {
        if location.exists() {
            return Some(location);
        }
    }
    
    None
}

pub fn set_config_value(key: &str, value: &str) -> AnyhowResult<()> {
    let config_path = get_config_file_path()?;
    
    // Ensure config directory exists
    if let Some(parent) = config_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    
    let mut config = if config_path.exists() {
        load_config_file(&config_path)?
    } else {
        TsaConfigFile::with_default_paths()?
    };
    
    // Parse the key and set the value
    match key {
        "tsa.url" => {
            validate_url(value)?;
            config.tsa.url = value.trim().to_string();
        }
        "certificates.sha256_responder" => {
            validate_url(value)?;
            config.certificates.sha256_responder = value.trim().to_string();
        }
        "certificates.sha384_responder" => {
            validate_url(value)?;
            config.certificates.sha384_responder = Some(value.trim().to_string());
        }
        "certificates.sha512_responder" => {
            validate_url(value)?;
            config.certificates.sha512_responder = Some(value.trim().to_string());
        }
        "certificates.intermediate" => {
            validate_url(value)?;
            config.certificates.intermediate = value.trim().to_string();
        }
        "certificates.root" => {
            validate_url(value)?;
            config.certificates.root = value.trim().to_string();
        }
        "path.base" => {
            config.path.base = validate_path_value(value)?;
        }
        "path.chain_dir" => {
            config.path.chain_dir = validate_path_value(value)?;
        }
        "path.chain_filename" => {
            config.path.chain_filename = validate_path_value(value)?;
        }
        _ => {
            return Err(anyhow::anyhow!("Unknown configuration key: {}", key));
        }
    }
    
    // Save the configuration
    save_config_file(&config, &config_path)?;
    info!("Configuration updated: {} = {}", key, value);
    Ok(())
}

pub fn get_config_value(key: &str) -> AnyhowResult<()> {
    let config_path = get_config_file_path()?;
    if !config_path.exists() {
        return Err(anyhow::anyhow!(
            "Configuration file not found: {}\nRun 'stamp init' to initialize stamp.",
            config_path.display()
        ));
    }
    
    let config = load_config_file(&config_path)?;
    
    let value = match key {
        "tsa.url" => config.tsa.url,
        "certificates.sha256_responder" => config.certificates.sha256_responder,
        "certificates.sha384_responder" => config.certificates.sha384_responder.unwrap_or_default(),
        "certificates.sha512_responder" => config.certificates.sha512_responder.unwrap_or_default(),
        "certificates.intermediate" => config.certificates.intermediate,
        "certificates.root" => config.certificates.root,
        "path.base" => config.path.base,
        "path.chain_dir" => config.path.chain_dir,
        "path.chain_filename" => config.path.chain_filename,
        _ => {
            return Err(anyhow::anyhow!("Unknown configuration key: {}", key));
        }
    };
    
    println!("{}", value);
    Ok(())
}

pub fn interactive_config_setup() -> AnyhowResult<()> {
    println!("=== TSA Configuration Setup ===");
    println!("This will guide you through setting up TSA certificate URLs.");
    println!("Press Enter to use default values (shown in brackets).");
    println!();
    
    // Show license notice and handle license commands
    loop {
        println!("stamp  Copyright (C) 2025 Dr. Samuel Louviot, Ph.D");
        println!("This program comes with ABSOLUTELY NO WARRANTY; for details type `show w'.");
        println!("This is free software, and you are welcome to redistribute it");
        println!("under certain conditions; type `show c' for details.");
        println!();
        print!("Press Enter to continue with setup, or type `show w' or `show c' for license details: ");
        io::stdout().flush()?;
        
        let mut input = String::new();
        io::stdin().read_line(&mut input)?;
        let input = input.trim();
        
        match input {
            "" => {
                // User pressed Enter, continue with setup
                break;
            }
            "show w" => {
                crate::utils::show_warranty();
                println!();
                continue;
            }
            "show c" => {
                crate::utils::show_copying();
                println!();
                continue;
            }
            _ => {
                println!("Invalid command. Please press Enter to continue, or type `show w` or `show c`.");
                continue;
            }
        }
    }
    
    let mut config = TsaConfigFile::default();
    
    // TSA Server configuration
    println!("--- TSA Server Configuration ---");
    
    let tsa_url = prompt_with_default("TSA URL", &config.tsa.url)?;
    config.tsa.url = tsa_url;
    
    println!();
    println!("--- Certificate URLs ---");
    println!("Enter the URLs for each certificate type:");
    
    let sha256_url = prompt_with_default("SHA256 Responder Certificate URL", &config.certificates.sha256_responder)?;
    config.certificates.sha256_responder = sha256_url;
    
    let sha384_url = prompt_with_default("SHA384 Responder Certificate URL (optional)", 
        &config.certificates.sha384_responder.as_deref().unwrap_or(""))?;
    if !sha384_url.is_empty() {
        config.certificates.sha384_responder = Some(sha384_url);
    } else {
        config.certificates.sha384_responder = None;
    }
    
    let sha512_url = prompt_with_default("SHA512 Responder Certificate URL (optional)", 
        &config.certificates.sha512_responder.as_deref().unwrap_or(""))?;
    if !sha512_url.is_empty() {
        config.certificates.sha512_responder = Some(sha512_url);
    } else {
        config.certificates.sha512_responder = None;
    }
    
    let intermediate_url = prompt_with_default("Intermediate Certificate URL", &config.certificates.intermediate)?;
    config.certificates.intermediate = intermediate_url;
    
    let root_url = prompt_with_default("Root Certificate URL", &config.certificates.root)?;
    config.certificates.root = root_url;
    
    println!();
    println!("--- Certificate Storage Configuration ---");
    println!("Configure where certificates will be stored:");
    
    // Use the default TSA certs directory as the default value
    let default_base = get_default_tsa_certs_dir()
        .map(|p| p.to_string_lossy().to_string())
        .unwrap_or_else(|_| config.path.base.clone());
    
    let base = prompt_with_default("Base certificate directory", &default_base)?;
    config.path.base = base;
    
    let chain_dir = prompt_with_default("Chain subdirectory name", &config.path.chain_dir)?;
    config.path.chain_dir = chain_dir;
    
    let chain_filename = prompt_with_default("Certificate chain filename", &config.path.chain_filename)?;
    config.path.chain_filename = chain_filename;
    
    println!();
    println!("Configuration completed!");
    
    // Save configuration to default location
    let config_path = get_config_file_path()?;
    
    // Ensure config directory exists
    if let Some(parent) = config_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    
    save_config_file(&config, &config_path)?;
    println!("Configuration saved to: {}", config_path.display());
    
    Ok(())
}

fn prompt_with_default(prompt: &str, default: &str) -> AnyhowResult<String> {
    print!("{} [{}]: ", prompt, default);
    io::stdout().flush()?;
    
    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    
    let input = input.trim();
    if input.is_empty() {
        Ok(default.to_string())
    } else {
        Ok(input.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_path_component_rejects_path_traversal() {
        assert!(validate_path_component("../etc/passwd").is_err());
        assert!(validate_path_component("../../etc").is_err());
        assert!(validate_path_component("path/../../etc").is_err());
        assert!(validate_path_component("..").is_err());
    }

    #[test]
    fn test_validate_path_component_rejects_absolute_paths() {
        assert!(validate_path_component("/etc/passwd").is_err());
        assert!(validate_path_component("/home/user").is_err());
        assert!(validate_path_component("/tmp/file").is_err());
    }

    #[test]
    fn test_validate_path_component_rejects_null_bytes() {
        assert!(validate_path_component("path\0with\0nulls").is_err());
        assert!(validate_path_component("\0").is_err());
    }

    #[test]
    fn test_validate_path_component_accepts_valid_paths() {
        assert!(validate_path_component("tsa_certs").is_ok());
        assert!(validate_path_component("chain").is_ok());
        assert!(validate_path_component("digicert_tsa_chain.pem").is_ok());
        assert!(validate_path_component("path/to/file").is_ok());
        assert!(validate_path_component("file-name_123").is_ok());
    }

    #[test]
    fn test_validate_path_value_rejects_empty() {
        assert!(validate_path_value("").is_err());
        assert!(validate_path_value("   ").is_err());
    }

    #[test]
    fn test_validate_path_value_accepts_valid_paths() {
        assert_eq!(validate_path_value("tsa_certs").unwrap(), "tsa_certs");
        assert_eq!(validate_path_value("  chain  ").unwrap(), "chain");
        assert_eq!(validate_path_value("file.pem").unwrap(), "file.pem");
    }

    #[test]
    fn test_validate_url_rejects_empty() {
        assert!(validate_url("").is_err());
        assert!(validate_url("   ").is_err());
    }

    #[test]
    fn test_validate_url_rejects_invalid_schemes() {
        assert!(validate_url("file:///etc/passwd").is_err());
        assert!(validate_url("javascript:alert(1)").is_err());
        assert!(validate_url("ftp://example.com").is_err());
        assert!(validate_url("gopher://example.com").is_err());
    }

    #[test]
    fn test_validate_url_accepts_http() {
        assert!(validate_url("http://example.com").is_ok());
        assert!(validate_url("http://timestamp.example.com").is_ok());
    }

    #[test]
    fn test_validate_url_accepts_https() {
        assert!(validate_url("https://example.com").is_ok());
        assert!(validate_url("https://timestamp.digicert.com").is_ok());
    }

    #[test]
    fn test_validate_url_rejects_localhost() {
        assert!(validate_url("http://localhost").is_err());
        assert!(validate_url("http://localhost:8080").is_err());
        assert!(validate_url("https://localhost").is_err());
        assert!(validate_url("http://127.0.0.1").is_err());
        assert!(validate_url("http://127.0.0.1:8080").is_err());
        assert!(validate_url("http://::1").is_err());
    }

    #[test]
    fn test_validate_url_rejects_private_ips() {
        // 10.0.0.0/8
        assert!(validate_url("http://10.0.0.1").is_err());
        assert!(validate_url("http://10.255.255.255").is_err());
        
        // 172.16.0.0/12
        assert!(validate_url("http://172.16.0.1").is_err());
        assert!(validate_url("http://172.31.255.255").is_err());
        
        // 192.168.0.0/16
        assert!(validate_url("http://192.168.0.1").is_err());
        assert!(validate_url("http://192.168.255.255").is_err());
        
        // Link-local 169.254.0.0/16
        assert!(validate_url("http://169.254.0.1").is_err());
        assert!(validate_url("http://169.254.255.255").is_err());
    }

    #[test]
    fn test_validate_url_accepts_public_ips() {
        // Public IPs should be allowed (though not recommended for TSA)
        assert!(validate_url("http://8.8.8.8").is_ok());
        assert!(validate_url("http://1.1.1.1").is_ok());
    }

    #[test]
    fn test_validate_url_accepts_valid_domains() {
        assert!(validate_url("https://timestamp.digicert.com").is_ok());
        assert!(validate_url("https://timestamp.globalsign.com").is_ok());
        assert!(validate_url("http://example.com").is_ok());
        assert!(validate_url("https://subdomain.example.com").is_ok());
    }

    #[test]
    fn test_validate_url_rejects_invalid_format() {
        assert!(validate_url("not-a-url").is_err());
        assert!(validate_url("://example.com").is_err());
        assert!(validate_url("http://").is_err());
    }

    #[test]
    fn test_set_config_value_validates_paths() {
        // This test would require mocking file system operations
        // For now, we test the validation functions directly
        assert!(validate_path_value("../../etc").is_err());
        assert!(validate_path_value("/absolute/path").is_err());
    }

    #[test]
    fn test_set_config_value_validates_urls() {
        // Test that URL validation is applied
        assert!(validate_url("http://127.0.0.1").is_err());
        assert!(validate_url("https://timestamp.digicert.com").is_ok());
    }
}
