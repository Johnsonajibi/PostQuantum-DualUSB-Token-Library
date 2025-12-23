# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.15.5] - 2025-10-26

### Changed
- Added comprehensive Release Notes section to README for better visibility on PyPI
- Embedded recent changelog entries (0.15.0-0.15.4) directly in README

### Notes
- Improves documentation accessibility by making changelog visible on PyPI page
- No functional code changes from 0.15.4

## [0.15.4] - 2025-10-26

### Changed
- Added prominent security notice to README warning users to upgrade from versions prior to 0.15.3
- Updated README with installation instructions and upgrade command
- Improved documentation clarity and removed marketing language

### Notes
- This is a documentation-only release to ensure PyPI page displays critical security information
- No functional code changes from 0.15.3

## [0.15.3] - 2025-10-26

### Security Fixes - CRITICAL UPDATE REQUIRED
- **CRITICAL**: Fixed signature verification bypass in PQCRYPTO backend where `verify()` always returned `True` regardless of signature validity
- **HIGH**: Fixed path traversal vulnerability in `InputValidator.validate_path()` that allowed access to system directories
- **MEDIUM**: Improved constant-time comparison implementation to prevent timing side-channel attacks
- **LOW**: Enhanced error messages to prevent information disclosure
- **LOW**: Strengthened password validation to detect weak patterns and excessive repeated characters

### Technical Details
- Signature verification now properly returns the boolean result from `pqcrypto.sign.verify()`
- Path validation includes URI scheme detection, network path blocking, and system directory protection
- Constant-time comparison uses consistent padding and bitwise operations to eliminate timing variations
- Error messages standardized to prevent sensitive information leakage
- Password validation includes repeated character detection and reasonable length limits

### Notes
- **This is a mandatory security update**. All users should upgrade immediately.
- All changes maintain backward compatibility while significantly improving security posture.
- Comprehensive security testing confirms all vulnerabilities are resolved.

## [0.15.2] - 2025-10-22

### Fixed
- Corrected documentation inconsistency in `generate_kem_keypair()` method - docstring now correctly states it returns `(secret_key, public_key)` tuple.
- Fixed all code examples throughout codebase (18 files) to use correct variable order matching the actual implementation.
- Updated usage examples in package documentation, README files, and test files for consistency.

### Notes
- This is a documentation-only patch release. No functional code changes. All tests passing.

## [0.15.1] - 2025-10-22

### Fixed
- PQCRYPTO backend detection updated to support standardized module names `pqcrypto.kem.ml_kem_1024` and `pqcrypto.sign.ml_dsa_65` with fallback to legacy `kyber1024`/`dilithium3`.
- Resolved OverflowError in side-channel dummy operations by masking to 256-bit width.
- Verified HybridCrypto PQC roundtrip and classical fallback via local tests.

### Notes
- This is a safe, backward-compatible patch release. Public APIs unchanged.

## [0.15.0] - 2024-01-XX

### Added
- **PQCRYPTO Backend Support**: Added priority support for `pqcrypto` library (pure Python, NIST-standard PQC algorithms)
  - Kyber1024 for key encapsulation (KEM)
  - Dilithium3 for digital signatures
  - Pure Python implementation, no compilation required
  - Cross-platform compatibility (Windows, Linux, macOS)
- Enhanced backend detection and fallback mechanism
- Improved installation script (`install_rust_pqc.py`) with PQCRYPTO priority
- Comprehensive backend testing and validation
- Better error handling for missing optional dependencies

### Changed
- Backend priority order: PQCRYPTO → CPP → Rust → OQS → Classical
- Updated dependencies: `pqcrypto>=0.3.4` now included as core dependency
- Improved backend initialization with better error messages
- Enhanced logging for backend selection process
- Package name standardized to `pqcdualusb` on PyPI

### Fixed
- Fixed `rust_pqc` version check bug (was checking for non-existent version 1.2.0)
- Corrected version attribute access in rust_pqc backend
- Fixed version string in `__init__.py` (was 0.1.0, now correctly shows 0.15.0)
- Improved backend availability checking

### Security
- All backends use NIST-standardized PQC algorithms (Kyber1024, Dilithium3)
- Power analysis attack countermeasures maintained across all backends
- Side-channel attack protection enhanced
- Constant-time operations where supported by backend

### Documentation
- Added comprehensive RELEASE_NOTES for v0.15.0
- Updated installation instructions for PQCRYPTO backend
- Added migration guide from version 0.14
- Documented backend selection and configuration

## [0.1.4] - 2025-10-18

### Changed
- Removed all emojis from documentation for professional, enterprise-grade appearance.
- Replaced emoji-based section markers with clean, professional text formatting.
- Improved documentation accessibility and compatibility with all text processors.

### Note
- This change aligns the package with professional security library standards and improves documentation accessibility for screen readers and corporate environments.

## [0.1.3] - 2025-10-18

### Fixed
- Fixed PyPI README display by using `PYPI_README.md` instead of `README.md` (PyPI doesn't support Mermaid diagrams).
- PyPI package page now shows properly formatted documentation without broken diagram syntax.

### Note
- The full documentation with interactive Mermaid diagrams is still available on [GitHub](https://github.com/Johnsonajibi/PostQuantum-DualUSB-Token-Library).

## [0.1.2] - 2025-10-18

### Changed
- Simplified `setup.py` to use all configuration from `pyproject.toml` (modern Python packaging best practice).
- Updated package metadata: author email, GitHub URLs to correct repository.
- Updated license format in `pyproject.toml` to comply with modern packaging standards.

### Added
- **Comprehensive architectural diagrams** using Mermaid:
  - High-level system architecture diagram
  - Component architecture with module relationships
  - Data flow sequence diagrams for all operations
  - Cryptographic pipeline visualization
  - File system layout diagram
  - Security threat model diagram
  - Detailed flowcharts for init, rotate, verify, restore, and PQC backend selection
- Enhanced documentation with visual guides in `README.md` and `ARCHITECTURE.md`.

### Fixed
- Corrected Mermaid diagram syntax errors (simplified nested subgraphs, fixed direction declarations).
- Improved diagram readability with better color contrast (dark text on light backgrounds).
- Fixed PyPI build configuration to remove deprecated license classifier format.
- Updated all documentation to reflect the current modular architecture (removed references to old `BackupManager` class).

## [0.1.1] - 2025-09-15

### Changed
- **BREAKING CHANGE**: Refactored the entire project from a single script into a modular, installable Python package named `pqcdualusb`.
- Replaced the high-level `BackupManager` class with a functional API (`init_dual_usb`, `rotate_token`, etc.) for more granular control.
- Migrated all cryptographic logic, PQC operations, device handling, and auditing into separate modules (`crypto.py`, `pqc.py`, `device.py`, `audit.py`).
- Updated the PQC backend logic to prioritize a high-performance Rust implementation and fall back to `python-oqs`.
- Replaced manual file operations with a dedicated `storage.py` module for managing state and orchestrating backups.

### Added
- Created a comprehensive test suite (`tests/test_all.py`) using `unittest` and `unittest.mock` to validate all core functionality.
- Implemented a `pyproject.toml` for modern, standardized package building and dependency management.
- Added a `build_rust_pqc.py` script to facilitate the compilation of the Rust backend.
- Created a `cli.py` as a reference implementation for using the library's functions.

### Fixed
- Corrected numerous `ImportError` and `AttributeError` issues that arose from the refactoring.
- Resolved a `TypeError` in `storage.py` where a `Path` object was incorrectly passed instead of `bytes`.
- Fixed a bug in `crypto.py` where `InvalidTag` exceptions were not being correctly propagated on passphrase mismatch.
- Patched tests to correctly mock file system interactions (`_is_removable_path`), allowing the test suite to run in any environment.

### Removed
- Removed the monolithic `dual_usb_backup.py` script, with all its logic now residing in the `pqcdualusb` package.

## [0.1.0] - 2025-08-30

### Added
- Initial release of the monolithic script version.
- **Post-quantum cryptography** support with Dilithium digital signatures.
- **Dual USB token architecture** with split secret design.
- **Memory protection** with secure allocation and automatic cleanup.
- **Timing attack resistance** with constant-time operations.
- **Cross-platform USB detection** for Windows, Linux, and macOS.
- **Atomic write operations** to prevent data corruption.
- **Comprehensive audit logging** with tamper-evident chains.
- **Interactive CLI** with smart drive selection.

[Unreleased]: https://github.com/Johnsonajibi/PostQuantum-DualUSB-Token-Library/compare/v0.1.4...HEAD
[0.1.4]: https://github.com/Johnsonajibi/PostQuantum-DualUSB-Token-Library/compare/v0.1.3...v0.1.4
[0.1.3]: https://github.com/Johnsonajibi/PostQuantum-DualUSB-Token-Library/compare/v0.1.2...v0.1.3
[0.1.2]: https://github.com/Johnsonajibi/PostQuantum-DualUSB-Token-Library/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/Johnsonajibi/PostQuantum-DualUSB-Token-Library/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/Johnsonajibi/PostQuantum-DualUSB-Token-Library/releases/tag/v0.1.0
