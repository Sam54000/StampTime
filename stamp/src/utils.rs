//! Utility functions for StampTime
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

use anyhow::Result as AnyhowResult;
use std::io::{self, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

pub fn init_logging() {
    tracing_subscriber::fmt::init();
}

pub fn read_password(prompt: &str) -> AnyhowResult<String> {
    print!("{}", prompt);
    io::stdout().flush()?;
    
    #[cfg(unix)]
    {
        use std::process::Command;
        let _ = Command::new("stty").arg("-echo").output();
    }
    
    let mut password = String::new();
    io::stdin().read_line(&mut password)?;
    
    #[cfg(unix)]
    {
        use std::process::Command;
        let _ = Command::new("stty").arg("echo").output();
    }
    
    password.pop();
    
    Ok(password)
}

pub fn get_password_interactive() -> AnyhowResult<String> {
    let interrupted = Arc::new(AtomicBool::new(false));
    let interrupted_clone = interrupted.clone();
    
    #[cfg(unix)]
    {
        use std::sync::Once;
        static INIT: Once = Once::new();
        INIT.call_once(|| {
            let interrupted = interrupted_clone.clone();
            ctrlc::set_handler(move || {
                interrupted.store(true, Ordering::SeqCst);
                println!();
                eprintln!("Operation cancelled by user.");
                std::process::exit(130);
            }).expect("Error setting Ctrl+C handler");
        });
    }
    
    loop {
        if interrupted.load(Ordering::SeqCst) {
            return Err(anyhow::anyhow!("Operation cancelled by user"));
        }
        
        let password = read_password("Enter password: ")?;
        println!();
        
        if password.is_empty() {
            eprintln!("Password cannot be empty. Please try again.");
            continue;
        }
        
        if interrupted.load(Ordering::SeqCst) {
            return Err(anyhow::anyhow!("Operation cancelled by user"));
        }
        
        let confirm_password = read_password("Confirm password: ")?;
        println!();
        
        if password == confirm_password {
            return Ok(password);
        } else {
            eprintln!("Passwords do not match. Please try again.");
        }
    }
}

pub fn show_warranty() {
    println!("THERE IS NO WARRANTY FOR THE PROGRAM, TO THE EXTENT PERMITTED BY");
    println!("APPLICABLE LAW.  EXCEPT WHEN OTHERWISE STATED IN WRITING THE COPYRIGHT");
    println!("HOLDERS AND/OR OTHER PARTIES PROVIDE THE PROGRAM \"AS IS\" WITHOUT WARRANTY");
    println!("OF ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING, BUT NOT LIMITED TO,");
    println!("THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR");
    println!("PURPOSE.  THE ENTIRE RISK AS TO THE QUALITY AND PERFORMANCE OF THE");
    println!("PROGRAM IS WITH YOU.  SHOULD THE PROGRAM PROVE DEFECTIVE, YOU ASSUME THE");
    println!("COST OF ALL NECESSARY SERVICING, REPAIR OR CORRECTION.");
    println!();
    println!("For more details, see the GNU General Public License at:");
    println!("<https://www.gnu.org/licenses/>");
}

pub fn show_copying() {
    println!("This program is free software: you can redistribute it and/or modify");
    println!("it under the terms of the GNU General Public License as published by");
    println!("the Free Software Foundation, either version 3 of the License, or");
    println!("(at your option) any later version.");
    println!();
    println!("This program is distributed in the hope that it will be useful,");
    println!("but WITHOUT ANY WARRANTY; without even the implied warranty of");
    println!("MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the");
    println!("GNU General Public License for more details.");
    println!();
    println!("You should have received a copy of the GNU General Public License");
    println!("along with this program.  If not, see <https://www.gnu.org/licenses/>.");
    println!();
    println!("Contact: tech.swerve263@slmail.me");
}
