# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Comprehensive architectural diagrams to `README.md` using Mermaid.js.
- Detailed "Threat Model and Security Guarantees" section to `README.md`.
- Project "Roadmap" section to `README.md`.

### Changed
- **BREAKING CHANGE**: Completely restructured and consolidated `README.md` for clarity and accuracy. Removed significant duplicated content.
- Synchronized `PYPI_README.md` with the new, streamlined `README.md` content.
- Moved badges to the top of `README.md`.

## [0.1.0] - 2025-08-30

### Added
- **Post-quantum cryptography** support with Dilithium digital signatures
- **Dual USB token architecture** with split secret design
- **Memory protection** with secure allocation and automatic cleanup
- **Timing attack resistance** with constant-time operations
- **Real-time progress reporting** with ETA and bandwidth monitoring
- **Cross-platform USB detection** for Windows, Linux, and macOS
- **Atomic write operations** preventing data corruption
- **Comprehensive audit logging** with tamper-evident chains
- **Interactive CLI** with smart drive selection
- **Python API** for programmatic access
- **Extensive test suite** with security validation
- **Professional documentation** with usage examples

### Security Features
- AES-256-GCM authenticated encryption
- Argon2id key derivation function
- HMAC-SHA256 audit log chaining
- Memory locking (VirtualLock/mlock)
- Secure memory clearing
- Input validation and sanitization
- Path traversal protection
- Device binding and cloning detection

### Performance
- Optimized cryptographic operations
- Efficient USB device detection
- Progress reporting with minimal overhead
- Memory usage optimization

### Documentation
- Comprehensive README with examples
- API documentation with type hints
- Security model documentation
- Contributing guidelines
- Installation instructions for PyPI

[0.1.0]: https://github.com/Johnsonajibi/PostQuantum-DualUSB-Token-Library/releases/tag/v0.1.0
