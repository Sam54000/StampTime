#!/bin/bash
# StampTime Installation Script
# 
# This script compiles and installs the unified StampTime tool to a specified location.
# It handles all dependencies, compilation, and installation steps.
#
# Copyright (C) 2025 Dr. Samuel Louviot, Ph.D
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.
#
# Contact: tech.swerve263@slmail.me
#
# Usage: ./install.sh [install_directory]
# Example: ./install.sh /usr/local/bin
# Example: ./install.sh ~/bin
# Example: ./install.sh (defaults to ~/.local/bin)

set -euo pipefail

# Colors for output
if tput colors &>/dev/null && [ "$(tput colors)" -ge 8 ]; then
    RED="$(tput setaf 1)"
    GREEN="$(tput setaf 2)"
    YELLOW="$(tput setaf 3)"
    BLUE="$(tput setaf 4)"
    CYAN="$(tput setaf 6)"
    NC="$(tput sgr0)"
else
    RED=""
    GREEN=""
    YELLOW=""
    BLUE=""
    CYAN=""
    NC=""
fi

# Function to print colored output
print_status() {
    local color=$1
    local message=$2
    echo -e "${color}${message}${NC}"
}

# Function to display license notice
display_license_notice() {
    echo ""
    print_status $CYAN "StampTime Installation Script  Copyright (C) 2025 Dr. Samuel Louviot, Ph.D"
    echo "This program comes with ABSOLUTELY NO WARRANTY; for details type 'show w'."
    echo "This is free software, and you are welcome to redistribute it"
    echo "under certain conditions; type 'show c' for details."
    echo ""
}

# Function to show warranty disclaimer
show_warranty() {
    echo ""
    echo "THERE IS NO WARRANTY FOR THE PROGRAM, TO THE EXTENT PERMITTED BY"
    echo "APPLICABLE LAW.  EXCEPT WHEN OTHERWISE STATED IN WRITING THE COPYRIGHT"
    echo "HOLDERS AND/OR OTHER PARTIES PROVIDE THE PROGRAM \"AS IS\" WITHOUT WARRANTY"
    echo "OF ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING, BUT NOT LIMITED TO,"
    echo "THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR"
    echo "PURPOSE.  THE ENTIRE RISK AS TO THE QUALITY AND PERFORMANCE OF THE"
    echo "PROGRAM IS WITH YOU.  SHOULD THE PROGRAM PROVE DEFECTIVE, YOU ASSUME THE"
    echo "COST OF ALL NECESSARY SERVICING, REPAIR OR CORRECTION."
    echo ""
    echo "For more details, see the GNU General Public License at:"
    echo "<https://www.gnu.org/licenses/>"
    echo ""
}

# Function to show copying conditions
show_copying() {
    echo ""
    echo "This program is free software: you can redistribute it and/or modify"
    echo "it under the terms of the GNU General Public License as published by"
    echo "the Free Software Foundation, either version 3 of the License, or"
    echo "(at your option) any later version."
    echo ""
    echo "This program is distributed in the hope that it will be useful,"
    echo "but WITHOUT ANY WARRANTY; without even the implied warranty of"
    echo "MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the"
    echo "GNU General Public License for more details."
    echo ""
    echo "You should have received a copy of the GNU General Public License"
    echo "along with this program.  If not, see <https://www.gnu.org/licenses/>."
    echo ""
    echo "Contact: tech.swerve263@slmail.me"
    echo ""
}

# Function to show usage
show_usage() {
    echo "Usage: $0 [install_directory]"
    echo ""
    echo "Arguments:"
    echo "  install_directory - Directory to install StampTime tool (optional)"
    echo "                     Defaults to ~/.local/bin if not specified"
    echo ""
    echo "Examples:"
    echo "  $0                    # Install to ~/.local/bin"
    echo "  $0 /usr/local/bin     # Install to /usr/local/bin (requires sudo)"
    echo "  $0 ~/bin              # Install to ~/bin"
    echo "  $0 /opt/stamptime/bin # Install to /opt/stamptime/bin"
    echo ""
    echo "License Commands:"
    echo "  $0 show w             # Show warranty information"
    echo "  $0 show c             # Show copying conditions"
    echo ""
    echo "This script will:"
    echo "  1. Check for required dependencies (Rust, OpenSSL, curl)"
    echo "  2. Compile the unified StampTime tool"
    echo "  3. Install the stamp binary to the specified directory"
    echo "  4. Test the installation and all subcommands"
}

# Check if help is requested
if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
    show_usage
    exit 0
fi

# Check if license commands are requested
if [[ "${1:-}" == "show" && "${2:-}" == "w" ]]; then
    show_warranty
    exit 0
fi

if [[ "${1:-}" == "show" && "${2:-}" == "c" ]]; then
    show_copying
    exit 0
fi

# Get installation directory
INSTALL_DIR="${1:-$HOME/.local/bin}"

# Expand tilde and resolve relative paths
INSTALL_DIR=$(realpath "$INSTALL_DIR")

print_status $BLUE "StampTime Installation Script"
echo "=================================="

# Display license notice
display_license_notice

print_status $YELLOW "Installation directory: $INSTALL_DIR"
echo ""

# Step 1: Check for required dependencies
print_status $YELLOW "Step 1: Checking dependencies..."

# Check for Rust
if command -v cargo >/dev/null 2>&1; then
    RUST_VERSION=$(cargo --version | awk '{print $2}')
    print_status $GREEN "[SUCCESS] Rust found: $RUST_VERSION"
else
    print_status $RED "[ERROR] Rust is not installed"
    echo ""
    echo "Please install Rust from: https://rustup.rs/"
    echo "Or run: curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh"
    exit 1
fi

# Check for OpenSSL
if command -v openssl >/dev/null 2>&1; then
    OPENSSL_VERSION=$(openssl version | awk '{print $2}')
    print_status $GREEN "[SUCCESS] OpenSSL found: $OPENSSL_VERSION"
else
    print_status $RED "[ERROR] OpenSSL is not installed"
    echo ""
    echo "Please install OpenSSL:"
    echo "  macOS: brew install openssl"
    echo "  Ubuntu/Debian: sudo apt-get install openssl"
    echo "  CentOS/RHEL: sudo yum install openssl"
    exit 1
fi

# Check for curl (used by stamp keygen rfc3161)
if command -v curl >/dev/null 2>&1; then
    CURL_VERSION=$(curl --version | head -1 | awk '{print $2}')
    print_status $GREEN "[SUCCESS] curl found: $CURL_VERSION"
else
    print_status $RED "[ERROR] curl is not installed"
    echo ""
    echo "Please install curl:"
    echo "  macOS: brew install curl"
    echo "  Ubuntu/Debian: sudo apt-get install curl"
    echo "  CentOS/RHEL: sudo yum install curl"
    exit 1
fi

echo ""

# Step 2: Create installation directory
print_status $YELLOW "Step 2: Creating installation directory..."
if [[ ! -d "$INSTALL_DIR" ]]; then
    if mkdir -p "$INSTALL_DIR"; then
        print_status $GREEN "[SUCCESS] Created directory: $INSTALL_DIR"
    else
        print_status $RED "[ERROR] Failed to create directory: $INSTALL_DIR"
        echo "You may need to run with sudo for system directories"
        exit 1
    fi
else
    print_status $GREEN "[SUCCESS] Directory exists: $INSTALL_DIR"
fi

echo ""

# Step 3: Clean and compile
print_status $YELLOW "Step 3: Compiling StampTime unified tool..."

# Clean previous builds
if [[ -d "target" ]]; then
    print_status $CYAN "[INFO] Cleaning previous builds..."
    cargo clean
fi

# Compile in release mode
print_status $CYAN "[INFO] Compiling in release mode..."
if cargo build --release; then
    print_status $GREEN "[SUCCESS] Compilation completed"
else
    print_status $RED "[ERROR] Compilation failed"
    exit 1
fi

echo ""

# Step 4: Install binaries
print_status $YELLOW "Step 4: Installing binaries..."

# Install the unified stamp tool
if [[ -f "target/release/stamp" ]]; then
    if cp "target/release/stamp" "$INSTALL_DIR/"; then
        chmod +x "$INSTALL_DIR/stamp"
        print_status $GREEN "[SUCCESS] Installed: stamp (unified tool)"
    else
        print_status $RED "[ERROR] Failed to install: stamp"
        echo "You may need to run with sudo for system directories"
        exit 1
    fi
else
    print_status $RED "[ERROR] Binary not found: target/release/stamp"
    exit 1
fi

echo ""

# Step 5: Verification functionality is now integrated into the unified tool
print_status $YELLOW "Step 5: Verification functionality integrated into stamp tool"
print_status $GREEN "[SUCCESS] Verification available via: stamp verify <file> <timestamp_file>"

echo ""

# Step 6: Add to PATH (if needed)
print_status $YELLOW "Step 6: Checking PATH configuration..."

# Check if install directory is in PATH
if [[ ":$PATH:" != *":$INSTALL_DIR:"* ]]; then
    print_status $YELLOW "[WARNING] $INSTALL_DIR is not in your PATH"
    echo ""
    echo "To use StampTime tools, you need to add $INSTALL_DIR to your PATH:"
    echo ""
    echo "For bash/zsh, add this to your ~/.bashrc or ~/.zshrc:"
    echo "  export PATH=\"\$PATH:$INSTALL_DIR\""
    echo ""
    echo "For fish shell, add this to your ~/.config/fish/config.fish:"
    echo "  set -gx PATH \$PATH $INSTALL_DIR"
    echo ""
    echo "Then restart your shell or run:"
    echo "  source ~/.bashrc  # or ~/.zshrc"
    echo ""
else
    print_status $GREEN "[SUCCESS] $INSTALL_DIR is already in your PATH"
fi

echo ""

# Step 7: Test installation
print_status $YELLOW "Step 7: Testing installation..."

# Test the unified stamp tool
if "$INSTALL_DIR/stamp" --help >/dev/null 2>&1; then
    print_status $GREEN "[SUCCESS] stamp is working"
else
    print_status $RED "[ERROR] stamp is not working"
    exit 1
fi

# Test subcommands
if "$INSTALL_DIR/stamp" config --help >/dev/null 2>&1; then
    print_status $GREEN "[SUCCESS] stamp config subcommand is working"
else
    print_status $RED "[ERROR] stamp config subcommand is not working"
    exit 1
fi

if "$INSTALL_DIR/stamp" keygen --help >/dev/null 2>&1; then
    print_status $GREEN "[SUCCESS] stamp keygen subcommand is working"
else
    print_status $RED "[ERROR] stamp keygen subcommand is not working"
    exit 1
fi

if "$INSTALL_DIR/stamp" cert --help >/dev/null 2>&1; then
    print_status $GREEN "[SUCCESS] stamp cert subcommand is working"
else
    print_status $RED "[ERROR] stamp cert subcommand is not working"
    exit 1
fi

# Test verify subcommand
if "$INSTALL_DIR/stamp" verify --help >/dev/null 2>&1; then
    print_status $GREEN "[SUCCESS] stamp verify subcommand is working"
else
    print_status $RED "[ERROR] stamp verify subcommand is not working"
    exit 1
fi

echo ""

# Final success message
print_status $GREEN "StampTime installation completed successfully"
echo ""
print_status $CYAN "Installed tools:"
echo "  • stamp              - Unified RFC3161 timestamping tool"
echo ""
print_status $CYAN "Usage examples:"
echo "  stamp config                          # Interactive configuration setup"
echo "  stamp keygen rfc3161                  # Download RFC3161 certificates"
echo "  stamp keygen pkcs12 'Name'  # Create PKCS#12 certificate (interactive password)"
echo "  stamp cert document.pdf               # Timestamp a single file"
echo "  stamp cert --batch ./docs --output ./timestamps  # Batch timestamping"
echo "  stamp verify document.pdf document.pdf.tsr  # Verify timestamp"
echo ""
print_status $CYAN "For detailed documentation, see:"
echo "  stamp --help                          # General help"
echo "  stamp config --help                   # Configuration help"
echo "  stamp keygen --help                   # Key generation help"
echo "  stamp cert --help                     # Timestamping help"
echo "  stamp verify --help                   # Verification help"
echo ""