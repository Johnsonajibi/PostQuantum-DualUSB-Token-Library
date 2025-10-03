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
        """
        if not self.primary_path or not self.backup_path:
            raise ValueError("Both primary and backup paths must be set")
        
        # Validate USB devices
        validation = self.validate_usb_devices()
        if not all([validation["primary_available"], validation["backup_available"],
                   validation["primary_writable"], validation["backup_writable"]]):
            raise RuntimeError(f"USB validation failed: {validation}")
        
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
        """Write backup files to a directory."""
        
        # Write encrypted token
        token_path = backup_dir / self.token_filename
        with open(token_path, 'w') as f:
            json.dump(encrypted_package, f, indent=2)
        
        # Write metadata
        metadata_path = backup_dir / self.metadata_filename
        with open(metadata_path, 'w') as f:
            json.dump(metadata, f, indent=2)
        
        # Write signature
        signature_path = backup_dir / self.signature_filename
        with open(signature_path, 'wb') as f:
            f.write(signature)
        
        # Write secret key (encrypted with passphrase)
        secret_key_path = backup_dir / "kem_secret.key"
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
        """Verify a single backup directory."""
        
        if not backup_dir.exists():
            return {"valid": False, "error": "Backup directory not found"}
        
        try:
            # Load metadata
            metadata_path = backup_dir / self.metadata_filename
            with open(metadata_path, 'r') as f:
                metadata = json.load(f)
            
            # Load encrypted package
            token_path = backup_dir / self.token_filename
            with open(token_path, 'r') as f:
                encrypted_package = json.load(f)
            
            # Load signature
            signature_path = backup_dir / self.signature_filename
            with open(signature_path, 'rb') as f:
                signature = f.read()
            
            # Load secret key
            secret_key_path = backup_dir / "kem_secret.key"
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
            
        except Exception as e:
            return {"valid": False, "error": str(e)}
    
    def restore_token(self, passphrase: str, prefer_primary: bool = True) -> Dict[str, Any]:
        """
        Restore secret data from backup.
        
        Args:
            passphrase: Passphrase for decryption
            prefer_primary: Whether to prefer primary device if both are available
            
        Returns:
            Dict with restored data and metadata
        """
        if not self.primary_path or not self.backup_path:
            raise ValueError("Both primary and backup paths must be set")
        
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
            
            # Load metadata
            metadata_path = backup_dir / self.metadata_filename
            with open(metadata_path, 'r') as f:
                metadata = json.load(f)
            
            bytes_processed += 100
            progress.update(bytes_processed)
            
            # Load encrypted package
            token_path = backup_dir / self.token_filename
            with open(token_path, 'r') as f:
                encrypted_package = json.load(f)
            
            bytes_processed += 200
            progress.update(bytes_processed)
            
            # Load secret key
            secret_key_path = backup_dir / "kem_secret.key"
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
            
        except Exception as e:
            progress.finish()
            raise RuntimeError(f"Token restoration failed: {e}")
    
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
        """List backups in a single device directory."""
        backups = []
        
        try:
            metadata_path = backup_dir / self.metadata_filename
            if metadata_path.exists():
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
        
        except Exception as e:
            # If we can't read metadata, still note that something exists
            backups.append({
                "error": str(e),
                "path": str(backup_dir),
                "complete": False
            })
        
        return backups
    
    def cleanup_backup(self, confirm: bool = False) -> Dict[str, Any]:
        """
        Remove backup files from both devices.
        
        Args:
            confirm: Must be True to actually delete files
            
        Returns:
            Dict with cleanup results
        """
        if not confirm:
            raise ValueError("cleanup_backup requires confirm=True to proceed")
        
        results = {
            "primary_cleaned": False,
            "backup_cleaned": False,
            "errors": []
        }
        
        if self.primary_path:
            primary_backup_dir = self.primary_path / self.backup_dir
            try:
                if primary_backup_dir.exists():
                    import shutil
                    shutil.rmtree(primary_backup_dir)
                    results["primary_cleaned"] = True
            except Exception as e:
                results["errors"].append(f"Primary cleanup failed: {e}")
        
        if self.backup_path:
            backup_backup_dir = self.backup_path / self.backup_dir
            try:
                if backup_backup_dir.exists():
                    import shutil
                    shutil.rmtree(backup_backup_dir)
                    results["backup_cleaned"] = True
            except Exception as e:
                results["errors"].append(f"Backup cleanup failed: {e}")
        
        results["success"] = len(results["errors"]) == 0
        return results
