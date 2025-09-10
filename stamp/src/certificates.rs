//! Certificate generation, PKCS#12, and certificate management
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
use tracing::info;
use crate::timestamp::{create_timestamp_query, send_timestamp_request};
use crate::utils::get_password_interactive;

pub fn download_rfc3161_certificates() -> AnyhowResult<()> {
    info!("Downloading RFC3161 certificates...");
    
    let config_path = PathBuf::from("config.toml");
    let config_file = if config_path.exists() {
        Some(crate::config::load_config_file(&config_path)?)
    } else {
        None
    };
    
    let workdir = if let Some(ref config) = config_file {
        PathBuf::from(&config.path.base)
    } else {
        std::env::var("WORKDIR")
            .map(PathBuf::from)
            .unwrap_or_else(|_| {
                std::env::var("HOME")
                    .map(|home| PathBuf::from(home).join("docs"))
                    .unwrap_or_else(|_| PathBuf::from("."))
            })
    };
    
    let tsa_dir = workdir.join("tsa");
    let chain_dir = if let Some(ref config) = config_file {
        PathBuf::from(&workdir).join(&config.path.chain_dir)
    } else {
        workdir.join("chain")
    };
    
    std::fs::create_dir_all(&tsa_dir)?;
    std::fs::create_dir_all(&chain_dir)?;
    
    let mut downloaded_certs = std::collections::HashMap::new();
    
    let certificates = if let Some(ref config_file) = config_file {
        let mut certs = vec![
            (
                "DigiCertSHA256RSA4096TimestampResponder20251.cer",
                config_file.certificates.sha256_responder.clone(),
                "responder"
            ),
            (
                "DigiCertTrustedG4TimeStampingRSA4096SHA2562025CA1.pem",
                config_file.certificates.intermediate.clone(),
                "intermediate"
            ),
            (
                "DigiCertTrustedRootG4.cer",
                config_file.certificates.root.clone(),
                "root"
            ),
        ];
        
        if let Some(ref sha384_url) = config_file.certificates.sha384_responder {
            certs.push((
                "DigiCertSHA384RSA4096TimestampResponder20251.cer",
                sha384_url.clone(),
                "responder_sha384"
            ));
        }
        
        if let Some(ref sha512_url) = config_file.certificates.sha512_responder {
            certs.push((
                "DigiCertSHA512RSA4096TimestampResponder20251.cer",
                sha512_url.clone(),
                "responder_sha512"
            ));
        }
        
        certs
    } else {
        vec![
            (
                "DigiCertSHA256RSA4096TimestampResponder20251.cer",
                "https://knowledge.digicert.com/content/dam/kb/attachments/time-stamp/DigiCertSHA256RSA4096TimestampResponder20251.cer".to_string(),
                "responder"
            ),
            (
                "DigiCertTrustedG4TimeStampingRSA4096SHA2562025CA1.pem",
                "https://knowledge.digicert.com/content/dam/kb/attachments/time-stamp/DigiCertTrustedG4TimeStampingRSA4096SHA2562025CA1.pem".to_string(),
                "intermediate"
            ),
            (
                "DigiCertTrustedRootG4.cer",
                "https://knowledge.digicert.com/content/dam/kb/attachments/time-stamp/DigiCertTrustedRootG4.cer".to_string(),
                "root"
            ),
        ]
    };
    
    for (filename, url, cert_type) in &certificates {
        let cert_path = chain_dir.join(filename);
        info!("Attempting to download {} certificate: {}", cert_type, filename);
        
        match download_certificate(url, &cert_path) {
            Ok(()) => {
                info!("Successfully downloaded: {}", filename);
                downloaded_certs.insert(*cert_type, cert_path);
            }
            Err(e) => {
                tracing::warn!("Failed to download {}: {}", filename, e);
                
                let existing_cert = std::path::Path::new(filename);
                if existing_cert.exists() {
                    info!("Using existing certificate: {}", filename);
                    std::fs::copy(existing_cert, &cert_path)?;
                    downloaded_certs.insert(*cert_type, cert_path);
                } else {
                    tracing::warn!("No existing certificate found for: {}", filename);
                }
            }
        }
    }
    
    let chain_filename = if let Some(ref config) = config_file {
        config.path.chain_filename.clone()
    } else {
        "digicert_tsa_chain.pem".to_string()
    };
    
    let chain_cert = chain_dir.join(&chain_filename);
    create_certificate_chain(&downloaded_certs, &chain_cert)?;
    
    info!("RFC3161 certificate download completed");
    info!("Certificate chain: {}", chain_cert.display());
    
    Ok(())
}

fn download_certificate(url: &str, output_path: &PathBuf) -> AnyhowResult<()> {
    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .user_agent("stamp/0.1.0")
        .build()?;
    
    let response = client.get(url).send()?;
    
    if !response.status().is_success() {
        return Err(anyhow::anyhow!("HTTP error: {}", response.status()));
    }
    
    let cert_data = response.bytes()?;
    std::fs::write(output_path, cert_data)?;
    
    Ok(())
}

fn create_certificate_chain(
    downloaded_certs: &std::collections::HashMap<&str, PathBuf>,
    chain_path: &PathBuf,
) -> AnyhowResult<()> {
    let mut chain_data = Vec::new();
    
    let cert_order = vec!["responder", "intermediate", "root"];
    
    for cert_type in cert_order {
        if let Some(cert_path) = downloaded_certs.get(cert_type) {
            if cert_path.exists() {
                let cert_content = std::fs::read(cert_path)?;
                chain_data.extend_from_slice(&cert_content);
                chain_data.push(b'\n');
            }
        }
    }
    
    if !chain_data.is_empty() {
        std::fs::write(chain_path, chain_data)?;
        info!("Created certificate chain: {}", chain_path.display());
    } else {
        return Err(anyhow::anyhow!("No certificates available to create chain"));
    }
    
    Ok(())
}

pub fn generate_pkcs12_certificate(
    common_name: String,
    days: u32,
    filename: String,
    key_size: u32,
    output_dir: Option<PathBuf>,
    tsa_url: Option<String>,
) -> AnyhowResult<()> {
    info!("Generating PKCS#12 certificate for: {}", common_name);
    
    println!("PKCS#12 certificate generation requires a password.");
    println!("The password will be used to protect the private key in the certificate file.");
    println!();
    
    let password = get_password_interactive()?;
    
    let workdir = std::env::var("WORKDIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            std::env::var("HOME")
                .map(|home| PathBuf::from(home).join("docs"))
                .unwrap_or_else(|_| PathBuf::from("."))
        });
    
    let output_dir = output_dir.unwrap_or_else(|| {
        workdir.join("keys").join(&common_name)
    });
    
    std::fs::create_dir_all(&output_dir)?;
    
    let p12_path = output_dir.join(&filename);
    let key_path = output_dir.join("private_key.pem");
    let cert_path = output_dir.join("cert.pem");
    let csr_path = output_dir.join("cert.csr");
    let tsq_path = output_dir.join(format!("{}.tsq", filename));
    let tsr_path = output_dir.join(format!("{}.tsr", filename));
    
    info!("Generating {} bit RSA private key", key_size);
    generate_private_key(&key_path, key_size)?;
    
    info!("Generating certificate signing request");
    generate_certificate_signing_request(&key_path, &csr_path, &common_name)?;
    
    info!("Generating self-signed certificate valid for {} days", days);
    generate_self_signed_certificate(&key_path, &cert_path, &common_name, days)?;
    
    info!("Creating PKCS#12 certificate file");
    create_pkcs12_file(&cert_path, &key_path, &p12_path, &password)?;
    
    let was_timestamped = if let Some(ref tsa_url) = tsa_url {
        info!("Timestamping certificate with TSA: {}", tsa_url);
        timestamp_certificate_file(&cert_path, &tsq_path, &tsr_path, tsa_url)?;
        true
    } else {
        std::fs::write(&tsq_path, b"# No TSA URL provided - certificate not timestamped\n")?;
        std::fs::write(&tsr_path, b"# No TSA URL provided - certificate not timestamped\n")?;
        false
    };
    
    info!("PKCS#12 certificate created successfully");
    info!("Private key: {}", key_path.display());
    info!("Certificate: {}", cert_path.display());
    info!("PKCS#12 file: {}", p12_path.display());
    if was_timestamped {
        info!("Timestamp query: {}", tsq_path.display());
        info!("Timestamp response: {}", tsr_path.display());
    }
    
    Ok(())
}

fn generate_private_key(key_path: &PathBuf, key_size: u32) -> AnyhowResult<()> {
    use std::process::Command;
    
    let output = Command::new("openssl")
        .args(&[
            "genrsa",
            "-out", key_path.to_str().unwrap(),
            &key_size.to_string()
        ])
        .output()
        .with_context(|| "Failed to execute openssl genrsa command")?;
    
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(anyhow::anyhow!("Failed to generate private key: {}", stderr));
    }
    
    info!("Private key generated: {}", key_path.display());
    Ok(())
}

fn generate_certificate_signing_request(
    key_path: &PathBuf, 
    csr_path: &PathBuf, 
    common_name: &str
) -> AnyhowResult<()> {
    use std::process::Command;
    
    let config_content = format!(
        "[req]\n\
        distinguished_name = req_distinguished_name\n\
        prompt = no\n\
        \n\
        [req_distinguished_name]\n\
        CN = {}\n",
        common_name
    );
    
    let mut temp_config = tempfile::NamedTempFile::new()
        .with_context(|| "Failed to create temporary config file")?;
    temp_config.write_all(config_content.as_bytes())
        .with_context(|| "Failed to write config content")?;
    temp_config.flush()
        .with_context(|| "Failed to flush config file")?;
    
    let output = Command::new("openssl")
        .args(&[
            "req",
            "-new",
            "-key", key_path.to_str().unwrap(),
            "-out", csr_path.to_str().unwrap(),
            "-config", temp_config.path().to_str().unwrap()
        ])
        .output()
        .with_context(|| "Failed to execute openssl req command")?;
    
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(anyhow::anyhow!("Failed to generate CSR: {}", stderr));
    }
    
    info!("Certificate signing request generated: {}", csr_path.display());
    Ok(())
}

fn generate_self_signed_certificate(
    key_path: &PathBuf,
    cert_path: &PathBuf,
    common_name: &str,
    days: u32
) -> AnyhowResult<()> {
    use std::process::Command;
    
    let config_content = format!(
        "[req]\n\
        distinguished_name = req_distinguished_name\n\
        prompt = no\n\
        \n\
        [req_distinguished_name]\n\
        CN = {}\n\
        \n\
        [v3_req]\n\
        basicConstraints = CA:FALSE\n\
        keyUsage = nonRepudiation, digitalSignature, keyEncipherment\n",
        common_name
    );
    
    let mut temp_config = tempfile::NamedTempFile::new()
        .with_context(|| "Failed to create temporary config file")?;
    temp_config.write_all(config_content.as_bytes())
        .with_context(|| "Failed to write config content")?;
    temp_config.flush()
        .with_context(|| "Failed to flush config file")?;
    
    let output = Command::new("openssl")
        .args(&[
            "req",
            "-x509",
            "-new",
            "-key", key_path.to_str().unwrap(),
            "-out", cert_path.to_str().unwrap(),
            "-days", &days.to_string(),
            "-config", temp_config.path().to_str().unwrap(),
            "-extensions", "v3_req"
        ])
        .output()
        .with_context(|| "Failed to execute openssl req command")?;
    
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(anyhow::anyhow!("Failed to generate self-signed certificate: {}", stderr));
    }
    
    info!("Self-signed certificate generated: {}", cert_path.display());
    Ok(())
}

fn create_pkcs12_file(
    cert_path: &PathBuf,
    key_path: &PathBuf,
    p12_path: &PathBuf,
    password: &str
) -> AnyhowResult<()> {
    use std::process::Command;
    
    let output = Command::new("openssl")
        .args(&[
            "pkcs12",
            "-export",
            "-out", p12_path.to_str().unwrap(),
            "-inkey", key_path.to_str().unwrap(),
            "-in", cert_path.to_str().unwrap(),
            "-passout", &format!("pass:{}", password)
        ])
        .output()
        .with_context(|| "Failed to execute openssl pkcs12 command")?;
    
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(anyhow::anyhow!("Failed to create PKCS#12 file: {}", stderr));
    }
    
    info!("PKCS#12 file created: {}", p12_path.display());
    Ok(())
}

fn timestamp_certificate_file(
    cert_path: &PathBuf,
    tsq_path: &PathBuf,
    tsr_path: &PathBuf,
    tsa_url: &str
) -> AnyhowResult<()> {
    let cert_data = std::fs::read(cert_path)
        .with_context(|| format!("Failed to read certificate file: {}", cert_path.display()))?;
    
    let tsq_data = create_timestamp_query(&cert_data)
        .with_context(|| "Failed to create timestamp query for certificate")?;
    
    std::fs::write(tsq_path, &tsq_data)
        .with_context(|| format!("Failed to write timestamp query: {}", tsq_path.display()))?;
    
    let tsr_data = send_timestamp_request(&tsq_data, tsa_url)
        .with_context(|| "Failed to send timestamp request for certificate")?;
    
    std::fs::write(tsr_path, &tsr_data)
        .with_context(|| format!("Failed to write timestamp response: {}", tsr_path.display()))?;
    
    info!("Certificate timestamped successfully");
    info!("Timestamp query: {}", tsq_path.display());
    info!("Timestamp response: {}", tsr_path.display());
    
    Ok(())
}
