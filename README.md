# RustyRansom - Proof of Concept
A sophisticated Proof of Concept (PoC) ransomware written in Rust, designed for educational and cybersecurity research purposes.
It demonstrates advanced cryptographic implementation and system-level programming techniques for high-performance and resilient file encryption.

## Key Features

### 🔒 Advanced Cryptography (Hybrid Scheme)
- **Hybrid Encryption Architecture**: Utilizes a robust combination of asymmetric (PGP) and symmetric (AES-256) encryption.
  - **AES-256-GCM (Stream Mode)**: Used for file encryption. Ensures confidentiality and integrity (Authenticated Encryption).
  - **PGP/RSA**: Protects the randomly generated symmetric session key. Only the holder of the private key can decrypt the recovery file.
- **Secure Key Management**: Session keys are zeroed out in memory immediately after use (`zeroize` crate) to prevent cold-boot attacks or memory dumps.
- **Obfuscation**: The embedded public key is Gzip-compressed and Base64-encoded to hinder static analysis.

### ⚡ High Performance & Reliability
- **Streaming Encryption**: Implements `AES-GCM` in stream mode with 4KB chunking. This allows encryption of arbitrarily large files (GBs/TBs) with minimal and constant RAM usage (preventing OOM crashes).
- **Parallel Processing**: leverages `Rayon` for multi-threaded filesystem traversal and encryption, maximizing CPU utilization.
- **Error Resilience**: Robust error handling ensures that locked or inaccessible files do not crash the payload, allowing the operation to continue uninterrupted.

### 💀 Cross-Platform Persistence
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

## Disclaimer
**DISCLAIMER: This software is for EDUCATIONAL PURPOSES ONLY.**
The author takes no responsibility for any misuse of this code. Writing malware for malicious intent is illegal and unethical. This tool is intended to help security researchers understand ransomware internals to build better defenses.