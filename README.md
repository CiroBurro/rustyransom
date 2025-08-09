# RustyRansom - Proof of Concept
A simple but efficient ransomware written in Rust
It searches for files recursively within the main user directories: desktop, documents, downloads and pictures.

## Features
- Encrypts files using AES-256 in GCM mode
- Parallel directory processing with Rayon multithreading
- File extension change to `.ciro`
- Recovery file is created in the data directory

## Warning
This project is a proof of concept and should not be used for malicious purposes.
