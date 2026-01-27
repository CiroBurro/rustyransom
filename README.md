# RustyRansom - Proof of Concept
A sophisticated Proof of Concept (PoC) ransomware written in Rust, designed for educational and cybersecurity research purposes.
It demonstrates advanced cryptographic implementation and system-level programming techniques for high-performance and resilient file encryption.

## Key Features

### Advanced Cryptography (Hybrid Scheme)
- **Hybrid Encryption Architecture**: Utilizes a robust combination of asymmetric (OpenPGP) and symmetric (AES-256) encryption.
  - **AES-256-GCM (Stream Mode)**: Used for file encryption. Ensures confidentiality and integrity (Authenticated Encryption).
  - **OpenPGP**: Protects the randomly generated symmetric session key. Only the holder of the private key can decrypt the recovery file.
    - Supports both RSA and elliptic curve keys (Ed25519, Cv25519)
    - Uses `sequoia-openpgp` for modern OpenPGP implementation with `StandardPolicy` validation
- **Secure Key Management**: Session keys are zeroed out in memory immediately after use (`zeroize` crate) to prevent cold-boot attacks or memory dumps.
- **Obfuscation**: The embedded public key is Gzip-compressed and Base64-encoded to hinder static analysis.

### Multi-Session Recovery System
- **Progressive Key Management**: Each execution generates a unique recovery file with sequential indexing (`recovery_file_0.key`, `recovery_file_1.key`, etc.)
- **File-to-Key Mapping**: Encrypted files are tagged with their session key index (e.g., `document_0.txt.ciro`, `photo_1.jpg.ciro`)
- **Resumable Operations**: Marker file system prevents re-execution after encryption completes
- **No Key Overwriting**: Multiple sessions preserve all previous recovery keys, ensuring files from interrupted sessions remain recoverable

### High Performance & Reliability
- **Streaming Encryption**: Implements `AES-GCM` in stream mode with 4KB chunking. This allows encryption of arbitrarily large files (GBs/TBs) with minimal and constant RAM usage (preventing OOM crashes).
- **Parallel Processing**: leverages `Rayon` for multi-threaded filesystem traversal and encryption, maximizing CPU utilization.
- **Error Resilience**: Robust error handling ensures that locked or inaccessible files do not crash the payload, allowing the operation to continue uninterrupted.

### Cross-Platform Persistence
- **Linux**: Auto-installs as a user-level `systemd` service (`~/.config/systemd/user/`) for persistence across reboots without requiring root privileges.
- **Windows**: (Conditional Compilation) Modifies the Registry (`HKCU\Software\Microsoft\Windows\CurrentVersion\Run`) to execute on user login.

## Technical Architecture
- **Encryption Engine**: `aes-gcm` (Stream primitive with `EncryptorBE32` for 7-byte nonce + 4-byte counter management).
- **Concurrency**: `rayon` for parallel iterator bridges.
- **System Integration**: `dirs2` for path resolution, `winreg` (Windows) and standard I/O for system interactions.
- **Session Management**: Marker file system (`~/.local/share/marker`) prevents re-execution after completion.

## Structure
The project is modularized for maintainability:
- `src/main.rs`: Entry point and orchestration with multi-session recovery key management.
- `src/encryption.rs`: Core streaming encryption logic with 7-byte nonce management and file tagging.
- `src/persistence.rs`: OS-specific persistence mechanisms (Linux Systemd / Windows Registry).
- `src/recovery.rs`: OpenPGP-based session key protection and progressive recovery file generation using `sequoia-openpgp`.
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
- `.key` - Recovery key files
- `.ciro` - Already encrypted files
- `.exe`, `.dll`, `.sys` - Windows executables/libraries
- `.so`, `.ko` - Linux shared libraries/kernel modules
- `.service`, `.desktop` - Linux systemd/desktop files
- `.conf`, `.cfg`, `.ini` - Configuration files
- `.gpg` - GPG encrypted files

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
