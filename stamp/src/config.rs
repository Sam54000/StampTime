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
                url: "http://timestamp.digicert.com".to_string(),
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
    // Try to load configuration from default location
    let default_config_path = PathBuf::from("config.toml");
    if let Ok(config) = load_config_file(&default_config_path) {
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
    let config_path = PathBuf::from("config.toml");
    let mut config = if config_path.exists() {
        load_config_file(&config_path)?
    } else {
        TsaConfigFile::default()
    };
    
    // Parse the key and set the value
    match key {
        "tsa.url" => {
            config.tsa.url = value.to_string();
        }
        "certificates.sha256_responder" => {
            config.certificates.sha256_responder = value.to_string();
        }
        "certificates.sha384_responder" => {
            config.certificates.sha384_responder = Some(value.to_string());
        }
        "certificates.sha512_responder" => {
            config.certificates.sha512_responder = Some(value.to_string());
        }
        "certificates.intermediate" => {
            config.certificates.intermediate = value.to_string();
        }
        "certificates.root" => {
            config.certificates.root = value.to_string();
        }
        "path.base" => {
            config.path.base = value.to_string();
        }
        "path.chain_dir" => {
            config.path.chain_dir = value.to_string();
        }
        "path.chain_filename" => {
            config.path.chain_filename = value.to_string();
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
    let config_path = PathBuf::from("config.toml");
    if !config_path.exists() {
        return Err(anyhow::anyhow!("Configuration file not found: {}", config_path.display()));
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
    
    let base = prompt_with_default("Base certificate directory", &config.path.base)?;
    config.path.base = base;
    
    let chain_dir = prompt_with_default("Chain subdirectory name", &config.path.chain_dir)?;
    config.path.chain_dir = chain_dir;
    
    let chain_filename = prompt_with_default("Certificate chain filename", &config.path.chain_filename)?;
    config.path.chain_filename = chain_filename;
    
    println!();
    println!("Configuration completed!");
    
    // Save configuration
    let config_path = PathBuf::from("config.toml");
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
