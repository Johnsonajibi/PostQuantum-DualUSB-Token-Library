"""
Comprehensive test suite for PostQuantum DualUSB Token Library.

Tests cover:
- Core security functionality
- USB device detection
- Encryption/decryption operations
- Error handling
- Memory management
- Cross-platform compatibility
"""

import pytest
import tempfile
import secrets
import os
from pathlib import Path
import json

# Import the main library
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from pqcdualusb import (
    PostQuantumCrypto,
    HybridCrypto,
    UsbDriveDetector,
    SecurityConfig,
    SecureMemory,
    ProgressReporter,
    TimingAttackMitigation,
    AuditLogRotator,
)
from pqcdualusb.security import InputValidator
from pqcdualusb.storage import init_dual_usb, rotate_token, verify_dual_setup


class TestSecurityFeatures:
    """Test core security functionality."""

    def test_secure_memory_management(self):
        """Test memory protection features."""
        with SecureMemory(64) as buf:
            # __enter__ returns the raw bytearray directly
            assert isinstance(buf, bytearray)
            assert len(buf) == 64

            test_data = b"sensitive test data"
            buf[:len(test_data)] = test_data
            assert bytes(buf[:len(test_data)]) == test_data

        # Memory should be zeroed in place after context exit. `buf` still
        # refers to the same underlying bytearray object.
        assert buf == bytearray(64)

    def test_timing_attack_protection(self):
        """Test constant-time operations."""
        mitigation = TimingAttackMitigation()

        data1 = b"short"
        data2 = b"much longer test data string"

        assert mitigation.constant_time_compare(data1, data1) is True
        assert mitigation.constant_time_compare(data2, data2) is True
        assert mitigation.constant_time_compare(data1, data2) is False


class TestUSBOperations:
    """Test USB device detection and operations."""

    def test_usb_detection(self):
        """Test USB drive detection."""
        drives = UsbDriveDetector.get_removable_drives()

        # Should return a list (may be empty in test environment)
        assert isinstance(drives, list)

    def test_drive_validation(self):
        """Test USB drive validation logic."""
        # Test with temporary directory (simulating USB drive)
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            result = UsbDriveDetector.validate_removable_drive(temp_path)
            assert isinstance(result, dict)
            assert "valid" in result
            assert isinstance(result["valid"], bool)


class TestDualUSBSetup:
    """Test dual USB initialization and verification."""

    def test_dual_usb_init_with_temp_dirs(self, monkeypatch, mock_usb_drives, test_secret, test_passphrase):
        """Test dual USB setup with temporary directories."""
        primary, backup = mock_usb_drives

        # init_dual_usb requires the backup target to be on removable media;
        # bypass that hardware check for this unit test.
        monkeypatch.setattr("pqcdualusb.backup._is_removable_path", lambda path: True)

        result = init_dual_usb(
            token=test_secret,
            primary_mount=primary,
            backup_mount=backup,
            passphrase=test_passphrase,
        )

        assert isinstance(result, dict)
        assert Path(result["primary_token"]).exists()
        assert Path(result["backup_file"]).exists()

    def test_dual_setup_verification(self, monkeypatch, mock_usb_drives, test_secret, test_passphrase):
        """Test verification of dual USB setup."""
        primary, backup = mock_usb_drives

        monkeypatch.setattr("pqcdualusb.backup._is_removable_path", lambda path: True)

        result = init_dual_usb(
            token=test_secret,
            primary_mount=primary,
            backup_mount=backup,
            passphrase=test_passphrase,
        )

        is_valid = verify_dual_setup(
            primary_token_path=Path(result["primary_token"]),
            backup_file=Path(result["backup_file"]),
            passphrase=test_passphrase,
            enforce_device=False,
            enforce_rotation=False,
        )

        assert isinstance(is_valid, bool)
        assert is_valid is True


class TestAuditLogging:
    """Test audit log functionality."""

    def test_audit_log_rotation(self):
        """Test log rotation functionality."""
        with tempfile.TemporaryDirectory() as temp_dir:
            log_path = Path(temp_dir) / "test_audit.log"
            rotator = AuditLogRotator(log_path, max_size=1024, max_files=2)

            log_path.write_text("small entry\n")
            assert rotator.should_rotate() is False

            # Grow the file past max_size to trigger rotation
            with open(log_path, "ab") as f:
                f.write(b"x" * 2048)
            assert rotator.should_rotate() is True

            rotator.rotate()

            # The original file should be moved to the first rotated slot
            assert not log_path.exists()
            rotated = log_path.with_suffix(f"{log_path.suffix}.1")
            assert rotated.exists()


class TestProgressReporting:
    """Test progress reporting functionality."""

    def test_progress_reporter(self):
        """Test progress calculation and reporting."""
        # Use a no-op callback so this test doesn't print to stdout.
        reporter = ProgressReporter(total_bytes=1000, progress_callback=lambda msg: None)

        reporter.update(250)
        assert reporter.processed_bytes == 250
        assert (reporter.processed_bytes / reporter.total_bytes) * 100 == 25.0

        reporter.update(500)
        assert reporter.processed_bytes == 750
        assert (reporter.processed_bytes / reporter.total_bytes) * 100 == 75.0

        reporter.update(250)
        assert reporter.processed_bytes == 1000

        reporter.finish()
        assert reporter._finished is True


class TestErrorHandling:
    """Test error handling and edge cases."""

    def test_invalid_paths(self):
        """Test handling of invalid file paths."""
        token = secrets.token_bytes(32)

        # A path nested under a regular file can never be created as a
        # directory, so this deterministically exercises the failure path
        # regardless of platform or running-as-root permissions.
        with tempfile.NamedTemporaryFile() as tmp_file:
            invalid_path = Path(tmp_file.name) / "subdir"

            with pytest.raises(OSError):
                init_dual_usb(
                    token=token,
                    primary_mount=invalid_path,
                    backup_mount=invalid_path,
                    passphrase="test-passphrase-for-testing-123",
                )

    def test_empty_passphrase(self):
        """Test handling of empty or weak passphrases.

        init_dual_usb() itself does not validate the passphrase -- that is
        deliberately a CLI-layer concern (see cli.py, which calls
        InputValidator.validate_passphrase() before passing a passphrase
        down to the library). Test the invariant at the layer that actually
        owns it.
        """
        with pytest.raises(ValueError):
            InputValidator.validate_passphrase("")

        with pytest.raises(ValueError):
            InputValidator.validate_passphrase("too-short")  # below MINIMUM_PASSPHRASE_LENGTH

        # A sufficiently long, non-repetitive passphrase should pass through.
        passphrase = "a-sufficiently-long-passphrase-123"
        assert InputValidator.validate_passphrase(passphrase) == passphrase


if __name__ == "__main__":
    # Run tests if executed directly
    pytest.main([__file__, "-v"])
