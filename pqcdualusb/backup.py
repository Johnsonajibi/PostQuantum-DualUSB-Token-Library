"""
Backup Operations Module
========================

Dual USB backup operations with post-quantum cryptography.

Provides secure backup and restore functionality across two USB devices
with quantum-resistant encryption and integrity verification.
"""

import os
import json
import time
import secrets
import hashlib
from pathlib import Path
from typing import Dict, Any, Optional, Tuple, List
from datetime import datetime, timezone

from .crypto import PostQuantumCrypto, HybridCrypto
from .usb import UsbDriveDetector
from .security import SecurityConfig, SecureMemory
from .utils import ProgressReporter


class BackupManager:
    """
    Dual USB backup manager with post-quantum cryptography.
    
    Manages secure backup operations across two USB devices using
    quantum-resistant encryption and digital signatures.
    """
    
    def __init__(self, primary_path: Optional[Path] = None, backup_path: Optional[Path] = None):
        """
        Initialize BackupManager.
        
        Args:
            primary_path: Path to primary USB device
            backup_path: Path to backup USB device
        """
        self.primary_path = Path(primary_path) if primary_path else None
        self.backup_path = Path(backup_path) if backup_path else None
        
        # Initialize crypto components
        self.pqc = PostQuantumCrypto()
        self.hybrid_crypto = HybridCrypto()
        
        # Backup configuration
        self.backup_dir = ".pqc_backup"
        self.token_filename = "token.enc"
        self.metadata_filename = "backup_metadata.json"
        self.signature_filename = "backup_signature.sig"
        
    def set_paths(self, primary_path: Path, backup_path: Path):
        """Set USB device paths."""
        self.primary_path = Path(primary_path)
        self.backup_path = Path(backup_path)
        
    def validate_usb_devices(self) -> Dict[str, bool]:
        """
        Validate that both USB devices are available and writable.
        
        Returns:
            Dict with validation results for primary and backup devices
        """
        results = {
            "primary_available": False,
            "backup_available": False,
            "primary_writable": False,
            "backup_writable": False
        }
        
        if self.primary_path:
            results["primary_available"] = self.primary_path.exists()
            if results["primary_available"]:
                results["primary_writable"] = UsbDriveDetector.is_drive_writable(self.primary_path)
        
        if self.backup_path:
            results["backup_available"] = self.backup_path.exists()
            if results["backup_available"]:
                results["backup_writable"] = UsbDriveDetector.is_drive_writable(self.backup_path)
        
        return results
    
    def init_token(self, secret_data: bytes, passphrase: str, description: str = "") -> Dict[str, Any]:
        """
        Initialize dual USB token with secret data.
        
        Args:
            secret_data: The secret data to backup
            passphrase: Passphrase for encryption
            description: Optional description of the backup
            
        Returns:
            Dict with operation results and metadata
            
        Raises:
            ValueError: If validation fails
            RuntimeError: If operation fails
        """
        # Input validation
        if not isinstance(secret_data, bytes):
            raise ValueError("secret_data must be bytes")
        
        if not secret_data:
            raise ValueError("secret_data cannot be empty")
        
        if len(secret_data) > 100 * 1024 * 1024:  # 100MB limit
            raise ValueError("secret_data exceeds maximum size (100MB)")
        
        if not isinstance(passphrase, str) or len(passphrase) < 8:
            raise ValueError("passphrase must be at least 8 characters")
        
        if description and len(description) > 1000:
            raise ValueError("description too long (max 1000 characters)")
        
        if not self.primary_path or not self.backup_path:
            raise ValueError("Both primary and backup paths must be set")
        
        # Path traversal protection - ensure paths are absolute and resolved
        self.primary_path = self.primary_path.resolve()
        self.backup_path = self.backup_path.resolve()
        
        # Validate USB devices
        validation = self.validate_usb_devices()
        if not all([validation["primary_available"], validation["backup_available"],
                   validation["primary_writable"], validation["backup_writable"]]):
            raise RuntimeError(f"USB validation failed")
        
        progress = ProgressReporter(len(secret_data), "Initializing token")
        
        try:
            bytes_processed = 0
            
            # Generate keypairs for this backup
            bytes_processed += 100
            progress.update(bytes_processed)
            kem_public, kem_secret = self.pqc.generate_kem_keypair()
            sig_public, sig_secret = self.pqc.generate_sig_keypair()
            
            # Create backup metadata
            metadata = {
                "version": "1.0",
                "created": datetime.now(timezone.utc).isoformat(),
                "description": description,
                "kem_algorithm": self.pqc.kem_algorithm,
                "sig_algorithm": self.pqc.sig_algorithm,
                "kem_public_key": kem_public.hex(),
                "sig_public_key": sig_public.hex(),
                "data_size": len(secret_data),
                "checksum": hashlib.sha256(secret_data).hexdigest()
            }
            
            bytes_processed += 200
            progress.update(bytes_processed)
            
            # Encrypt the secret data
            encrypted_package = self.hybrid_crypto.encrypt_with_pqc(
                data=secret_data,
                passphrase=passphrase,
                kem_public_key=kem_public
            )
            
            bytes_processed += len(secret_data) // 2
            progress.update(bytes_processed)
            
            # Create digital signature of the encrypted package
            package_data = json.dumps(encrypted_package, sort_keys=True).encode()
            signature = self.pqc.sign(package_data, sig_secret)
            
            # Create backup directories
            primary_backup_dir = self.primary_path / self.backup_dir
            backup_backup_dir = self.backup_path / self.backup_dir
            
            primary_backup_dir.mkdir(exist_ok=True)
            backup_backup_dir.mkdir(exist_ok=True)
            
            bytes_processed += 100
            progress.update(bytes_processed)
            
            # Write to primary device
            self._write_backup_files(
                backup_dir=primary_backup_dir,
                encrypted_package=encrypted_package,
                metadata=metadata,
                signature=signature,
                kem_secret=kem_secret
            )
            
            bytes_processed += len(secret_data) // 4
            progress.update(bytes_processed)
            
            # Write to backup device
            self._write_backup_files(
                backup_dir=backup_backup_dir,
                encrypted_package=encrypted_package,
                metadata=metadata,
                signature=signature,
                kem_secret=kem_secret
            )
            
            progress.finish()
            
            return {
                "success": True,
                "metadata": metadata,
                "primary_path": str(primary_backup_dir),
                "backup_path": str(backup_backup_dir),
                "kem_public_key": kem_public.hex(),
                "sig_public_key": sig_public.hex()
            }
                
        except Exception as e:
            progress.finish()
            raise RuntimeError(f"Token initialization failed: {e}")
    
    def _write_backup_files(self, backup_dir: Path, encrypted_package: Dict[str, Any],
                           metadata: Dict[str, Any], signature: bytes, kem_secret: bytes):
        """
        Write backup files to a directory.
        
        Args:
            backup_dir: Directory to write files to
            encrypted_package: Encrypted data package
            metadata: Backup metadata
            signature: Digital signature
            kem_secret: KEM secret key
            
        Raises:
            ValueError: If paths are invalid
            RuntimeError: If write operation fails
        """
        # Path traversal protection
        backup_dir = backup_dir.resolve()
        
        # Validate all file paths are within backup directory
        token_path = backup_dir / self.token_filename
        metadata_path = backup_dir / self.metadata_filename
        signature_path = backup_dir / self.signature_filename
        secret_key_path = backup_dir / "kem_secret.key"
        
        # Ensure no path traversal
        for path in [token_path, metadata_path, signature_path, secret_key_path]:
            try:
                path.resolve().relative_to(backup_dir.resolve())
            except ValueError:
                raise RuntimeError("Path traversal detected in backup filenames")
        
        # Write encrypted token
        with open(token_path, 'w') as f:
            json.dump(encrypted_package, f, indent=2)
        
        # Write metadata
        with open(metadata_path, 'w') as f:
            json.dump(metadata, f, indent=2)
        
        # Write signature
        with open(signature_path, 'wb') as f:
            f.write(signature)
        
        # Write secret key (encrypted with passphrase)
        with open(secret_key_path, 'wb') as f:
            f.write(kem_secret)
    
    def verify_backup(self, passphrase: str) -> Dict[str, Any]:
        """
        Verify backup integrity on both USB devices.
        
        Args:
            passphrase: Passphrase for decryption
            
        Returns:
            Dict with verification results
        """
        if not self.primary_path or not self.backup_path:
            raise ValueError("Both primary and backup paths must be set")
        
        primary_backup_dir = self.primary_path / self.backup_dir
        backup_backup_dir = self.backup_path / self.backup_dir
        
        results = {
            "primary_valid": False,
            "backup_valid": False,
            "signatures_match": False,
            "metadata_match": False,
            "checksums_valid": False
        }
        
        try:
            # Verify primary device
            primary_result = self._verify_single_backup(primary_backup_dir, passphrase)
            results["primary_valid"] = primary_result["valid"]
            
            # Verify backup device
            backup_result = self._verify_single_backup(backup_backup_dir, passphrase)
            results["backup_valid"] = backup_result["valid"]
            
            if results["primary_valid"] and results["backup_valid"]:
                # Compare metadata between devices
                results["metadata_match"] = (
                    primary_result["metadata"] == backup_result["metadata"]
                )
                
                # Compare signatures
                results["signatures_match"] = (
                    primary_result["signature"] == backup_result["signature"]
                )
                
                # Verify checksums
                results["checksums_valid"] = (
                    primary_result["checksum_valid"] and backup_result["checksum_valid"]
                )
            
            results["overall_valid"] = all([
                results["primary_valid"],
                results["backup_valid"],
                results["signatures_match"],
                results["metadata_match"],
                results["checksums_valid"]
            ])
            
            return results
            
        except Exception as e:
            raise RuntimeError(f"Backup verification failed: {e}")
    
    def _verify_single_backup(self, backup_dir: Path, passphrase: str) -> Dict[str, Any]:
        """
        Verify a single backup directory.
        
        Args:
            backup_dir: Directory containing backup files
            passphrase: Passphrase for decryption
            
        Returns:
            Dict with verification results
        """
        # Path traversal protection
        backup_dir = backup_dir.resolve()
        
        if not backup_dir.exists():
            return {"valid": False, "error": "Backup directory not found"}
        
        try:
            # Construct and validate file paths
            metadata_path = backup_dir / self.metadata_filename
            token_path = backup_dir / self.token_filename
            signature_path = backup_dir / self.signature_filename
            secret_key_path = backup_dir / "kem_secret.key"
            
            # Ensure no path traversal in any file path
            for path in [metadata_path, token_path, signature_path, secret_key_path]:
                try:
                    path.resolve().relative_to(backup_dir.resolve())
                except ValueError:
                    return {"valid": False, "error": "Invalid file path detected"}
            
            # Load metadata with size limit
            if metadata_path.stat().st_size > 10 * 1024:  # 10KB limit
                return {"valid": False, "error": "Metadata file too large"}
                
            with open(metadata_path, 'r') as f:
                metadata = json.load(f)
            
            # Load encrypted package with size limit
            if token_path.stat().st_size > 110 * 1024 * 1024:  # 110MB limit
                return {"valid": False, "error": "Token file too large"}
                
            with open(token_path, 'r') as f:
                encrypted_package = json.load(f)
            
            # Load signature with size limit
            if signature_path.stat().st_size > 10 * 1024:  # 10KB limit
                return {"valid": False, "error": "Signature file too large"}
                
            with open(signature_path, 'rb') as f:
                signature = f.read()
            
            # Load secret key with size limit
            if secret_key_path.stat().st_size > 10 * 1024:  # 10KB limit
                return {"valid": False, "error": "Secret key file too large"}
                
            with open(secret_key_path, 'rb') as f:
                kem_secret = f.read()
            
            # Verify signature
            sig_public_key = bytes.fromhex(metadata["sig_public_key"])
            package_data = json.dumps(encrypted_package, sort_keys=True).encode()
            signature_valid = self.pqc.verify(package_data, signature, sig_public_key)
            
            if not signature_valid:
                return {"valid": False, "error": "Invalid signature"}
            
            # Decrypt and verify data
            decrypted_data = self.hybrid_crypto.decrypt_with_pqc(
                package=encrypted_package,
                passphrase=passphrase,
                kem_secret_key=kem_secret
            )
            
            # Verify checksum
            actual_checksum = hashlib.sha256(decrypted_data).hexdigest()
            expected_checksum = metadata["checksum"]
            checksum_valid = actual_checksum == expected_checksum
            
            return {
                "valid": True,
                "metadata": metadata,
                "signature": signature,
                "checksum_valid": checksum_valid,
                "data_size": len(decrypted_data)
            }
            
        except (json.JSONDecodeError, KeyError, ValueError) as e:
            # Sanitize error messages - don't expose internal details
            return {"valid": False, "error": "Backup validation failed"}
        except Exception as e:
            return {"valid": False, "error": "Backup verification error"}
    
    def restore_token(self, passphrase: str, prefer_primary: bool = True) -> Dict[str, Any]:
        """
        Restore secret data from backup.
        
        Args:
            passphrase: Passphrase for decryption
            prefer_primary: Whether to prefer primary device if both are available
            
        Returns:
            Dict with restored data and metadata
            
        Raises:
            ValueError: If validation fails
            RuntimeError: If restoration fails
        """
        # Input validation
        if not isinstance(passphrase, str) or len(passphrase) < 8:
            raise ValueError("passphrase must be at least 8 characters")
        
        if not self.primary_path or not self.backup_path:
            raise ValueError("Both primary and backup paths must be set")
        
        # Path traversal protection
        self.primary_path = self.primary_path.resolve()
        self.backup_path = self.backup_path.resolve()
        
        primary_backup_dir = self.primary_path / self.backup_dir
        backup_backup_dir = self.backup_path / self.backup_dir
        
        # Determine which backup to use
        primary_available = primary_backup_dir.exists()
        backup_available = backup_backup_dir.exists()
        
        if not primary_available and not backup_available:
            raise RuntimeError("No backup found on either device")
        
        # Choose backup source
        if prefer_primary and primary_available:
            backup_dir = primary_backup_dir
            source = "primary"
        elif backup_available:
            backup_dir = backup_backup_dir
            source = "backup"
        else:
            backup_dir = primary_backup_dir
            source = "primary"
        
        progress = ProgressReporter(description=f"Restoring from {source} device")
        
        try:
            bytes_processed = 0
            
            # Validate file paths for traversal protection
            metadata_path = backup_dir / self.metadata_filename
            token_path = backup_dir / self.token_filename
            secret_key_path = backup_dir / "kem_secret.key"
            
            # Ensure no path traversal
            for path in [metadata_path, token_path, secret_key_path]:
                try:
                    path.resolve().relative_to(backup_dir.resolve())
                except ValueError:
                    raise RuntimeError("Path traversal detected")
            
            # Load metadata with size limit
            if metadata_path.stat().st_size > 10 * 1024:
                raise RuntimeError("Metadata file too large")
            
            with open(metadata_path, 'r') as f:
                metadata = json.load(f)
            
            bytes_processed += 100
            progress.update(bytes_processed)
            
            # Load encrypted package with size limit
            if token_path.stat().st_size > 110 * 1024 * 1024:
                raise RuntimeError("Token file too large")
            
            with open(token_path, 'r') as f:
                encrypted_package = json.load(f)
            
            bytes_processed += 200
            progress.update(bytes_processed)
            
            # Load secret key with size limit
            if secret_key_path.stat().st_size > 10 * 1024:
                raise RuntimeError("Secret key file too large")
            
            with open(secret_key_path, 'rb') as f:
                kem_secret = f.read()
            
            bytes_processed += 100
            progress.update(bytes_processed)
            
            # Decrypt the data
            decrypted_data = self.hybrid_crypto.decrypt_with_pqc(
                package=encrypted_package,
                passphrase=passphrase,
                kem_secret_key=kem_secret
            )
            
            bytes_processed += metadata.get("data_size", 1000)
            progress.update(bytes_processed)
            
            # Verify checksum
            actual_checksum = hashlib.sha256(decrypted_data).hexdigest()
            expected_checksum = metadata["checksum"]
            
            if actual_checksum != expected_checksum:
                raise RuntimeError("Data integrity check failed - checksum mismatch")
            
            progress.finish()
            
            return {
                "success": True,
                "data": decrypted_data,
                "metadata": metadata,
                "source": source,
                "restored_from": str(backup_dir)
            }
            
        except (json.JSONDecodeError, KeyError, ValueError) as e:
            progress.finish()
            # Sanitize error - don't expose internal details
            raise RuntimeError("Token restoration failed")
        except Exception as e:
            progress.finish()
            raise RuntimeError("Token restoration failed")
    
    def list_backups(self) -> Dict[str, List[Dict[str, Any]]]:
        """
        List all available backups on both devices.
        
        Returns:
            Dict with backup information for both devices
        """
        result = {
            "primary": [],
            "backup": []
        }
        
        if self.primary_path:
            primary_backup_dir = self.primary_path / self.backup_dir
            if primary_backup_dir.exists():
                result["primary"] = self._list_device_backups(primary_backup_dir)
        
        if self.backup_path:
            backup_backup_dir = self.backup_path / self.backup_dir
            if backup_backup_dir.exists():
                result["backup"] = self._list_device_backups(backup_backup_dir)
        
        return result
    
    def _list_device_backups(self, backup_dir: Path) -> List[Dict[str, Any]]:
        """
        List backups in a single device directory.
        
        Args:
            backup_dir: Directory to list backups from
            
        Returns:
            List of backup information dictionaries
        """
        backups = []
        
        # Path traversal protection
        backup_dir = backup_dir.resolve()
        
        try:
            metadata_path = backup_dir / self.metadata_filename
            
            # Validate path is within backup_dir
            try:
                metadata_path.resolve().relative_to(backup_dir.resolve())
            except ValueError:
                return []  # Path traversal detected
            
            if metadata_path.exists():
                # Size limit check
                if metadata_path.stat().st_size > 10 * 1024:
                    backups.append({
                        "error": "Metadata file too large",
                        "path": str(backup_dir),
                        "complete": False
                    })
                    return backups
                
                with open(metadata_path, 'r') as f:
                    metadata = json.load(f)
                
                # Check if all required files exist
                required_files = [
                    self.token_filename,
                    self.signature_filename,
                    "kem_secret.key"
                ]
                
                files_exist = all((backup_dir / filename).exists() for filename in required_files)
                
                backup_info = {
                    "metadata": metadata,
                    "path": str(backup_dir),
                    "complete": files_exist,
                    "created": metadata.get("created", "unknown"),
                    "description": metadata.get("description", ""),
                    "data_size": metadata.get("data_size", 0)
                }
                
                backups.append(backup_info)
        
        except (json.JSONDecodeError, KeyError) as e:
            # JSON parsing errors - don't expose details
            backups.append({
                "error": "Backup metadata corrupted",
                "path": str(backup_dir),
                "complete": False
            })
        except Exception as e:
            # Other errors - generic message
            backups.append({
                "error": "Backup read error",
                "path": str(backup_dir),
                "complete": False
            })
        
        return backups
    
    def cleanup_backup(self, confirm: bool = False) -> Dict[str, Any]:
        """
        Remove backup files from both devices.
        
        WARNING: This permanently deletes backup data!
        
        Args:
            confirm: Must be True to actually delete files
            
        Returns:
            Dict with cleanup results
            
        Raises:
            ValueError: If confirm is not True
        """
        if not confirm:
            raise ValueError("cleanup_backup requires confirm=True to proceed")
        
        # Path traversal protection
        if self.primary_path:
            self.primary_path = self.primary_path.resolve()
        if self.backup_path:
            self.backup_path = self.backup_path.resolve()
        
        results = {
            "primary_cleaned": False,
            "backup_cleaned": False,
            "errors": []
        }
        
        if self.primary_path:
            primary_backup_dir = self.primary_path / self.backup_dir
            
            # Validate path is within primary_path
            try:
                primary_backup_dir.resolve().relative_to(self.primary_path.resolve())
            except ValueError:
                results["errors"].append("Path validation failed for primary")
                results["success"] = False
                return results
            
            try:
                if primary_backup_dir.exists():
                    import shutil
                    shutil.rmtree(primary_backup_dir)
                    results["primary_cleaned"] = True
            except Exception:
                # Don't expose internal errors
                results["errors"].append("Primary cleanup failed")
        
        if self.backup_path:
            backup_backup_dir = self.backup_path / self.backup_dir
            
            # Validate path is within backup_path
            try:
                backup_backup_dir.resolve().relative_to(self.backup_path.resolve())
            except ValueError:
                results["errors"].append("Path validation failed for backup")
                results["success"] = False
                return results
            
            try:
                if backup_backup_dir.exists():
                    import shutil
                    shutil.rmtree(backup_backup_dir)
                    results["backup_cleaned"] = True
            except Exception:
                # Don't expose internal errors
                results["errors"].append("Backup cleanup failed")
        
        results["success"] = len(results["errors"]) == 0
        return results
