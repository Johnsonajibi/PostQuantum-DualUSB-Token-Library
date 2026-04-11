# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.5] - 2026-03-21

### Security (Critical)
- **Path traversal fixed** (`security.py`, `utils.py`): `InputValidator.validate_path()` now
  rejects URI schemes (`://`, `file:`), UNC/network paths (`\\\\`, `//`), explicit `..`
  traversal sequences, and access to system directories (`/etc/`, `C:\Windows\`, etc.).
  An optional `allowed_base` parameter enforces directory confinement.
- **Scrypt KDF strengthened** (`crypto.py`): Scrypt fallback work factor raised from
  `n=2**15` (32,768) to `n=2**18` (262,144) — 8x increase in GPU brute-force resistance.
- **Constant-time comparison** (`security.py`): `TimingAttackMitigation.constant_time_compare()`
  now delegates to `hmac.compare_digest()` (stdlib C implementation) eliminating the
  `zip()`-based early-termination risk present in the prior custom loop.
- **OverflowError in side-channel dummy ops fixed** (`crypto.py`): Added `& ((1 << 256) - 1)`
  bit-mask to the hash accumulator in `SideChannelProtection.dummy_operations()` to keep
  the integer within 256 bits and prevent `OverflowError` during extended operations.
- **Error message information disclosure fixed** (`crypto.py`): Decryption failure now
  raises `ValueError("Authentication failed")` instead of revealing whether the failure
  was due to a wrong key or data corruption.

### Security (Medium)
- **Audit HMAC key lazy-loaded** (`audit.py`): `AUDIT_KEY` is no longer a module-level
  global loaded at import time. A new `_get_audit_key()` function loads it on first use,
  reducing the window during which the key resides in memory.
- **Permission failures now logged** (`audit.py`, `security.py`): `chmod()` failures on
  the audit log and audit key files, and `VirtualLock`/`mlock` failures on secure memory,
  are now logged as warnings instead of being silently swallowed.
- **Bare `except` clauses removed** (`security.py`): Replaced bare `except:` in
  `secure_zero_memory()` and memory-lock helpers with `except (OSError, AttributeError, TypeError)`.

### Security (Low)
- **Log sanitizer hardened** (`crypto.py`): `_secure_log()` now uses a compiled regex
  (`re.sub`) to redact all occurrences of `password=`, `key=`, `token=`, etc. in a single
  pass, fixing the prior bug where only the first matching keyword was redacted.
- **Passphrase validation strengthened** (`security.py`, `utils.py`): Added maximum length
  cap (200 characters, DoS prevention) and repeated-character detection (>50% same char)
  to `InputValidator.validate_passphrase()` in both modules.
- **Backup restore schema validated** (`backup.py`): `restore_from_backup()` now calls
  `_validate_backup_schema()` before accessing nested keys, preventing unhandled `KeyError`
  on malformed or malicious backup files.

### Changed
- `cryptography` minimum version raised to `>=38.0.0` (aligns with current security support window).
- `tqdm` removed from core dependencies (was unused at the library level).
- Author email updated to `ajibijohnson@jtnetsolutions.com`.

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

[Unreleased]: https://github.com/Johnsonajibi/PostQuantum-DualUSB-Token-Library/compare/v0.1.5...HEAD
[0.1.5]: https://github.com/Johnsonajibi/PostQuantum-DualUSB-Token-Library/compare/v0.1.4...v0.1.5
[0.1.4]: https://github.com/Johnsonajibi/PostQuantum-DualUSB-Token-Library/compare/v0.1.3...v0.1.4
[0.1.3]: https://github.com/Johnsonajibi/PostQuantum-DualUSB-Token-Library/compare/v0.1.2...v0.1.3
[0.1.2]: https://github.com/Johnsonajibi/PostQuantum-DualUSB-Token-Library/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/Johnsonajibi/PostQuantum-DualUSB-Token-Library/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/Johnsonajibi/PostQuantum-DualUSB-Token-Library/releases/tag/v0.1.0
