//! StampTime - RFC3161 Timestamping Tool
//! 
//! A unified command-line tool for RFC3161 timestamping operations.
//! This tool provides configuration management, certificate generation, and timestamping capabilities.
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

mod config;
mod utils;
mod timestamp;
mod certificates;
mod cli;
mod blockchain;

use anyhow::Result as AnyhowResult;
use clap::Parser;
use tracing::info;
use cli::{Args, Commands, handle_config_command, handle_keygen_command, handle_cert_command, handle_verify_command, handle_inspect_command, handle_blockchain_command};
use utils::{init_logging, show_warranty, show_copying};

fn main() -> AnyhowResult<()> {
    let args = Args::parse();
    
    init_logging();
    
    if args.verbose {
        std::env::set_var("RUST_LOG", "debug");
    } else {
        std::env::set_var("RUST_LOG", "info");
    }
    
    info!("Starting StampTime RFC3161 timestamping tool");
    
    match args.command {
        Commands::Config { key, value } => {
            handle_config_command(key, value)?;
        }
        Commands::ShowWarranty => {
            show_warranty();
        }
        Commands::ShowCopying => {
            show_copying();
        }
        Commands::Keygen { keygen_type } => {
            handle_keygen_command(keygen_type)?;
        }
        Commands::Cert { 
            input, 
            output, 
            batch, 
            tsa_url, 
            tsa_cert, 
            no_verify, 
            recursive, 
            dry_run,
            re_timestamp,
            use_git,
            verbose,
            cleanup
        } => {
            handle_cert_command(input, output, batch, tsa_url, tsa_cert, no_verify, recursive, dry_run, re_timestamp, use_git, verbose, cleanup)?;
        }
        Commands::Verify { file, timestamp_file, query_file, tsa_cert, hash_only } => {
            handle_verify_command(file, timestamp_file, query_file, tsa_cert, hash_only)?;
        }
        Commands::Inspect { file } => {
            handle_inspect_command(file)?;
        }
        Commands::Blockchain { action } => {
            handle_blockchain_command(action)?;
        }
    }
    
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_timestamp_pdf() {
        let mut temp_file = NamedTempFile::new().unwrap();
        let pdf_data = b"%PDF-1.4\n%Test PDF content";
        temp_file.write_all(pdf_data).unwrap();
        
        let input_file = temp_file.path().to_path_buf();
        let _config = timestamp::TimestampConfig::new("http://timestamp.digicert.com".to_string());
        
        let pdf_data_read = std::fs::read(&input_file).unwrap();
        assert_eq!(pdf_data_read, pdf_data);
    }
}