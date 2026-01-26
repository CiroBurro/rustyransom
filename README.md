# RustyRansom - Proof of Concept
A sophisticated Proof of Concept (PoC) ransomware written in Rust, designed for educational and cybersecurity research purposes.
It demonstrates advanced cryptographic implementation and system-level programming techniques for high-performance and resilient file encryption.

## Key Features

### Advanced Cryptography (Hybrid Scheme)
- **Hybrid Encryption Architecture**: Utilizes a robust combination of asymmetric (PGP) and symmetric (AES-256) encryption.
  - **AES-256-GCM (Stream Mode)**: Used for file encryption. Ensures confidentiality and integrity (Authenticated Encryption).
  - **PGP/RSA**: Protects the randomly generated symmetric session key. Only the holder of the private key can decrypt the recovery file.
- **Secure Key Management**: Session keys are zeroed out in memory immediately after use (`zeroize` crate) to prevent cold-boot attacks or memory dumps.
- **Obfuscation**: The embedded public key is Gzip-compressed and Base64-encoded to hinder static analysis.

### High Performance & Reliability
- **Streaming Encryption**: Implements `AES-GCM` in stream mode with 4KB chunking. This allows encryption of arbitrarily large files (GBs/TBs) with minimal and constant RAM usage (preventing OOM crashes).
- **Parallel Processing**: leverages `Rayon` for multi-threaded filesystem traversal and encryption, maximizing CPU utilization.
- **Error Resilience**: Robust error handling ensures that locked or inaccessible files do not crash the payload, allowing the operation to continue uninterrupted.

### Cross-Platform Persistence
- **Linux**: Auto-installs as a user-level `systemd` service (`~/.config/systemd/user/`) for persistence across reboots without requiring root privileges.
- **Windows**: (Conditional Compilation) Modifies the Registry (`HKCU\Software\Microsoft\Windows\CurrentVersion\Run`) to execute on user login.

## Technical Architecture
- **Encryption Engine**: `aes-gcm` (Stream primitive with `EncryptorBE32` for nonce/counter management).
- **Concurrency**: `rayon` for parallel iterator bridges.
- **System Integration**: `dirs2` for path resolution, `winreg` (Windows) and standard I/O for system interactions.

## Structure
The project is modularized for maintainability:
- `src/main.rs`: Entry point and orchestration.
- `src/encryption.rs`: Core streaming encryption logic and nonce management.
- `src/persistence.rs`: OS-specific persistence mechanisms (Linux Systemd / Windows Registry).
- `src/recovery.rs`: PGP-based session key protection and recovery file generation.
- `dropper/`: Go-based cross-platform dropper with TUI and web server modes

## Dropper Architecture
The dropper is a separate [Go application](https://github.com/CiroBurro/SysGuard) that deploys the Rust ransomware payload:
- **Payload Encoding**: Rust binary is Gzip-compressed and Base64-encoded, then embedded in Go source
- **Platform-Specific Deployment**:
  - **Linux**: Decodes to `/usr/share/rustyransom` with 0755 permissions (no extension)
  - **Windows**: Decodes to `%PUBLIC%\rustyransom.exe`
- **Execution Modes**:
  - **TUI Mode** (default): Interactive terminal UI using charmbracelet/bubbletea
  - **Server Mode** (`-server`): Web server displaying system information
- **Asynchronous**: Dropper runs in background goroutine while UI distracts user

## Self-Protection Mechanisms
To prevent operational failures, the ransomware includes multiple self-protection layers:

### Extension Blacklist
Files with these extensions are NEVER encrypted:
- `.key` - Recovery key file
- `.ciro` - Already encrypted files
- `.exe`, `.dll`, `.sys` - Windows executables/libraries
- `.so`, `.ko` - Linux shared libraries/kernel modules

### Self-Executable Detection
Uses canonical path comparison to prevent encrypting the ransomware binary itself:
- Resolves symlinks and relative paths
- Compares against `env::current_exe()`
- Protects both `rustyransom` (Linux) and `rustyransom.exe` (Windows)

### No-Extension Protection
Files without extensions are automatically skipped (protects Linux binaries like `/bin/ls`, `./rustyransom`)

## Disclaimer
**DISCLAIMER: This software is for EDUCATIONAL PURPOSES ONLY.**
The author takes no responsibility for any misuse of this code. Writing malware for malicious intent is illegal and unethical. This tool is intended to help security researchers understand ransomware internals to build better defenses.
