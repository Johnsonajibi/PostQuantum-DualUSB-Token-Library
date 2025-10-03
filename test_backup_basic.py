#!/usr/bin/env python3
"""
Simple BackupManager Test
=========================

Basic test to verify BackupManager structure and USB operations work.
"""

import os
import sys
import tempfile
from pathlib import Path

# Add the current directory to Python path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

def test_backup_manager_basic():
    """Test basic BackupManager functionality without crypto operations."""
    print("=== Testing BackupManager Basic Functionality ===\n")
    
    try:
        from pqcdualusb import BackupManager, UsbDriveDetector
        
        # Create temporary directories to simulate USB drives
        with tempfile.TemporaryDirectory(prefix="primary_usb_") as primary_temp:
            with tempfile.TemporaryDirectory(prefix="backup_usb_") as backup_temp:
                
                primary_path = Path(primary_temp)
                backup_path = Path(backup_temp)
                
                print(f"Simulated USB drives:")
                print(f"  Primary: {primary_path}")
                print(f"  Backup:  {backup_path}")
                print()
                
                # Initialize BackupManager
                backup_manager = BackupManager(primary_path, backup_path)
                print(f"✅ BackupManager initialized successfully")
                print(f"   Primary path: {backup_manager.primary_path}")
                print(f"   Backup path: {backup_manager.backup_path}")
                print()
                
                # Test USB validation
                validation = backup_manager.validate_usb_devices()
                print(f"USB Validation Results:")
                for key, value in validation.items():
                    status = "✅" if value else "❌"
                    print(f"   {key}: {status} {value}")
                
                if all([validation["primary_available"], validation["backup_available"],
                       validation["primary_writable"], validation["backup_writable"]]):
                    print("✅ All USB validation checks passed")
                else:
                    print("❌ USB validation failed")
                    return False
                print()
                
                # Test directory creation
                backup_dir = backup_manager.backup_dir
                primary_backup_dir = primary_path / backup_dir
                backup_backup_dir = backup_path / backup_dir
                
                primary_backup_dir.mkdir(exist_ok=True)
                backup_backup_dir.mkdir(exist_ok=True)
                
                print(f"Backup directories created:")
                print(f"   Primary: {primary_backup_dir} (exists: {primary_backup_dir.exists()})")
                print(f"   Backup:  {backup_backup_dir} (exists: {backup_backup_dir.exists()})")
                print()
                
                # Test file operations
                test_file = primary_backup_dir / "test.txt"
                test_content = "This is a test file"
                
                with open(test_file, 'w') as f:
                    f.write(test_content)
                
                if test_file.exists():
                    with open(test_file, 'r') as f:
                        read_content = f.read()
                    
                    if read_content == test_content:
                        print("✅ File operations working correctly")
                    else:
                        print("❌ File content mismatch")
                        return False
                else:
                    print("❌ Test file was not created")
                    return False
                print()
                
                # Test list_backups (should be empty initially)
                backups = backup_manager.list_backups()
                print(f"Listed backups:")
                print(f"   Primary device: {len(backups['primary'])} backups")
                print(f"   Backup device: {len(backups['backup'])} backups")
                print("✅ list_backups() method working")
                print()
                
                print("🎉 All basic BackupManager tests passed!")
                return True
                
    except Exception as e:
        print(f"❌ Test failed with error: {e}")
        import traceback
        traceback.print_exc()
        return False

def test_crypto_components():
    """Test individual crypto components to identify issues."""
    print("=== Testing Individual Crypto Components ===\n")
    
    try:
        from pqcdualusb import PostQuantumCrypto, HybridCrypto
        
        print("1. Testing PostQuantumCrypto initialization...")
        crypto = PostQuantumCrypto()
        print(f"   ✅ PostQuantumCrypto initialized with backend: {crypto.backend}")
        print()
        
        print("2. Testing key generation...")
        try:
            kem_public, kem_secret = crypto.generate_kem_keypair()
            print(f"   ✅ KEM keypair generated: pub={len(kem_public)}, sec={len(kem_secret)}")
        except Exception as e:
            print(f"   ❌ KEM keypair generation failed: {e}")
            return False
        
        try:
            sig_public, sig_secret = crypto.generate_sig_keypair()
            print(f"   ✅ Signature keypair generated: pub={len(sig_public)}, sec={len(sig_secret)}")
        except Exception as e:
            print(f"   ❌ Signature keypair generation failed: {e}")
            return False
        print()
        
        print("3. Testing HybridCrypto...")
        hybrid = HybridCrypto()
        print(f"   ✅ HybridCrypto initialized")
        
        # Test without PQC (just passphrase-based encryption)
        test_data = b"Test data for encryption"
        passphrase = "test_passphrase"
        
        try:
            encrypted_package = hybrid.encrypt_with_pqc(
                data=test_data,
                passphrase=passphrase,
                kem_public_key=None  # No PQC, just passphrase
            )
            print(f"   ✅ Hybrid encryption (passphrase-only) successful")
            
            decrypted_data = hybrid.decrypt_with_pqc(
                package=encrypted_package,
                passphrase=passphrase,
                kem_secret_key=None
            )
            
            if decrypted_data == test_data:
                print(f"   ✅ Hybrid decryption successful - data matches")
            else:
                print(f"   ❌ Decrypted data doesn't match original")
                return False
                
        except Exception as e:
            print(f"   ❌ Hybrid crypto test failed: {e}")
            return False
        print()
        
        print("🎉 Individual crypto components working!")
        return True
        
    except Exception as e:
        print(f"❌ Crypto test failed: {e}")
        return False

def main():
    """Run all tests."""
    print("BackupManager Implementation Test (Basic)")
    print("=" * 50)
    
    # Test basic functionality
    basic_test_passed = test_backup_manager_basic()
    
    # Test crypto components individually
    crypto_test_passed = test_crypto_components()
    
    print("\n" + "=" * 50)
    print("FINAL RESULTS:")
    print(f"Basic BackupManager Tests: {'PASSED' if basic_test_passed else 'FAILED'}")
    print(f"Crypto Component Tests: {'PASSED' if crypto_test_passed else 'FAILED'}")
    
    if basic_test_passed and crypto_test_passed:
        print("\n🎉 All tests passed! BackupManager structure is working.")
        print("ℹ️  Note: Full crypto integration may need Rust PQC backend fixes.")
        return 0
    else:
        print("\n❌ Some tests failed. Please check the output above.")
        return 1

if __name__ == "__main__":
    exit(main())
