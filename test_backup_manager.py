#!/usr/bin/env python3
"""
BackupManager Test and Demo
===========================

Test script to verify the BackupManager functionality with real operations.
"""

import os
import sys
import tempfile
from pathlib import Path

# Add the current directory to Python path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

def test_backup_manager():
    """Test BackupManager with temporary directories simulating USB drives."""
    print("=== Testing BackupManager Implementation ===\n")
    
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
                
                # Test 1: Validate USB devices
                print("1. Validating USB devices...")
                validation = backup_manager.validate_usb_devices()
                print(f"   Validation results: {validation}")
                
                if not all([validation["primary_available"], validation["backup_available"],
                          validation["primary_writable"], validation["backup_writable"]]):
                    print("   ❌ USB validation failed")
                    return False
                
                print("   ✅ USB devices validated successfully")
                print()
                
                # Test 2: Initialize token with secret data
                print("2. Initializing token with secret data...")
                secret_data = b"This is highly sensitive secret data that needs quantum-safe protection!"
                passphrase = "test_passphrase_with_good_entropy_123"
                description = "Test backup for verification"
                
                init_result = backup_manager.init_token(
                    secret_data=secret_data,
                    passphrase=passphrase,
                    description=description
                )
                
                if init_result["success"]:
                    print("   ✅ Token initialization successful")
                    print(f"   Primary backup: {init_result['primary_path']}")
                    print(f"   Backup location: {init_result['backup_path']}")
                    print(f"   KEM public key: {init_result['kem_public_key'][:32]}...")
                    print(f"   Signature public key: {init_result['sig_public_key'][:32]}...")
                else:
                    print("   ❌ Token initialization failed")
                    return False
                print()
                
                # Test 3: List backups
                print("3. Listing available backups...")
                backups = backup_manager.list_backups()
                
                print(f"   Primary device backups: {len(backups['primary'])}")
                print(f"   Backup device backups: {len(backups['backup'])}")
                
                if backups['primary'] and backups['backup']:
                    primary_backup = backups['primary'][0]
                    backup_backup = backups['backup'][0]
                    print(f"   Primary backup complete: {primary_backup['complete']}")
                    print(f"   Backup backup complete: {backup_backup['complete']}")
                    print(f"   Data size: {primary_backup['data_size']} bytes")
                    print("   ✅ Backups listed successfully")
                else:
                    print("   ❌ No backups found")
                    return False
                print()
                
                # Test 4: Verify backup integrity
                print("4. Verifying backup integrity...")
                verification = backup_manager.verify_backup(passphrase)
                
                print(f"   Primary valid: {verification['primary_valid']}")
                print(f"   Backup valid: {verification['backup_valid']}")
                print(f"   Signatures match: {verification['signatures_match']}")
                print(f"   Metadata match: {verification['metadata_match']}")
                print(f"   Checksums valid: {verification['checksums_valid']}")
                print(f"   Overall valid: {verification['overall_valid']}")
                
                if verification['overall_valid']:
                    print("   ✅ Backup verification successful")
                else:
                    print("   ❌ Backup verification failed")
                    return False
                print()
                
                # Test 5: Restore token from backup
                print("5. Restoring token from backup...")
                restore_result = backup_manager.restore_token(passphrase, prefer_primary=True)
                
                if restore_result["success"]:
                    restored_data = restore_result["data"]
                    metadata = restore_result["metadata"]
                    
                    print(f"   ✅ Token restoration successful")
                    print(f"   Restored from: {restore_result['source']} device")
                    print(f"   Data size: {len(restored_data)} bytes")
                    print(f"   Created: {metadata['created']}")
                    print(f"   Description: {metadata['description']}")
                    
                    # Verify restored data matches original
                    if restored_data == secret_data:
                        print("   ✅ Restored data matches original")
                    else:
                        print("   ❌ Restored data does not match original")
                        return False
                else:
                    print("   ❌ Token restoration failed")
                    return False
                print()
                
                # Test 6: Test restore from backup device
                print("6. Testing restore from backup device...")
                restore_result_backup = backup_manager.restore_token(passphrase, prefer_primary=False)
                
                if restore_result_backup["success"]:
                    print(f"   ✅ Backup device restoration successful")
                    print(f"   Restored from: {restore_result_backup['source']} device")
                    
                    # Verify data matches
                    if restore_result_backup["data"] == secret_data:
                        print("   ✅ Backup device data matches original")
                    else:
                        print("   ❌ Backup device data does not match")
                        return False
                else:
                    print("   ❌ Backup device restoration failed")
                    return False
                print()
                
                print("🎉 All BackupManager tests passed successfully!")
                print("✅ BackupManager implementation is working correctly")
                return True
                
    except Exception as e:
        print(f"❌ Test failed with error: {e}")
        import traceback
        traceback.print_exc()
        return False

def test_real_usb_detection():
    """Test with real USB drive detection if available."""
    print("\n=== Testing Real USB Drive Detection ===\n")
    
    try:
        from pqcdualusb import UsbDriveDetector
        
        drives = UsbDriveDetector.get_removable_drives()
        print(f"Found {len(drives)} removable drives:")
        
        for i, drive in enumerate(drives):
            print(f"  {i+1}. {drive}")
            try:
                info = UsbDriveDetector.get_drive_info(drive)
                writable = UsbDriveDetector.is_drive_writable(drive)
                
                print(f"     Total space: {info['total_space'] // 1024 // 1024} MB")
                print(f"     Free space: {info['free_space'] // 1024 // 1024} MB")
                print(f"     Writable: {'Yes' if writable else 'No'}")
            except Exception as e:
                print(f"     Error getting info: {e}")
            print()
        
        if len(drives) >= 2:
            print("✅ Multiple USB drives detected - suitable for dual backup")
        elif len(drives) == 1:
            print("⚠️  Only one USB drive detected - dual backup requires two drives")
        else:
            print("ℹ️  No USB drives detected - tests ran with simulated directories")
        
        return True
        
    except Exception as e:
        print(f"❌ USB detection test failed: {e}")
        return False

def main():
    """Run all tests."""
    print("BackupManager Implementation Test")
    print("=" * 50)
    
    # Test BackupManager functionality
    backup_test_passed = test_backup_manager()
    
    # Test real USB detection
    usb_test_passed = test_real_usb_detection()
    
    print("\n" + "=" * 50)
    print("FINAL RESULTS:")
    print(f"BackupManager Tests: {'PASSED' if backup_test_passed else 'FAILED'}")
    print(f"USB Detection Tests: {'PASSED' if usb_test_passed else 'FAILED'}")
    
    if backup_test_passed and usb_test_passed:
        print("\n🎉 All tests passed! BackupManager is fully functional.")
        return 0
    else:
        print("\n❌ Some tests failed. Please check the output above.")
        return 1

if __name__ == "__main__":
    exit(main())
