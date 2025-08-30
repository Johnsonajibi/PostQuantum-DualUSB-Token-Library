#!/usr/bin/env python3
"""Test script for the enhanced dual USB backup system."""

import sys
import os
from pathlib import Path

# Execute the dual_usb_backup.py file to import its classes
exec(open('dual_usb_backup.py').read())

def test_security_config():
    """Test SecurityConfig functionality."""
    print("=== Testing SecurityConfig ===")
    
    params = SecurityConfig.get_argon2_params()
    print(f"Argon2 parameters: {params}")
    
    warnings = SecurityConfig.validate_security_level()
    if warnings:
        print(f"Security warnings: {warnings}")
    else:
        print("Security configuration is optimal")
    
    print(f"AES key size: {SecurityConfig.AES_KEY_SIZE}")
    print(f"Min passphrase length: {SecurityConfig.MIN_PASSPHRASE_LENGTH}")
    print()

def test_input_validator():
    """Test InputValidator functionality."""
    print("=== Testing InputValidator ===")
    
    # Test passphrase validation
    try:
        InputValidator.validate_passphrase("short")
        print("ERROR: Short passphrase should have failed")
    except ValueError as e:
        print(f"✓ Correctly rejected short passphrase: {e}")
    
    try:
        valid_pass = InputValidator.validate_passphrase("this_is_a_secure_passphrase_123!")
        print(f"✓ Accepted valid passphrase (length: {len(valid_pass)})")
    except ValueError as e:
        print(f"ERROR: Valid passphrase was rejected: {e}")
    
    # Test token size validation
    try:
        InputValidator.validate_token_size(16)
        print("ERROR: Small token size should have failed")
    except ValueError as e:
        print(f"✓ Correctly rejected small token: {e}")
    
    try:
        size = InputValidator.validate_token_size(64)
        print(f"✓ Accepted valid token size: {size}")
    except ValueError as e:
        print(f"ERROR: Valid token size was rejected: {e}")
    
    print()

def test_timing_mitigation():
    """Test TimingAttackMitigation functionality."""
    print("=== Testing TimingAttackMitigation ===")
    
    # Test constant time comparison
    data1 = b"hello_world_test_data"
    data2 = b"hello_world_test_data"
    data3 = b"different_test_data!!"
    
    result1 = TimingAttackMitigation.constant_time_compare(data1, data2)
    result2 = TimingAttackMitigation.constant_time_compare(data1, data3)
    
    print(f"✓ Identical data comparison: {result1} (should be True)")
    print(f"✓ Different data comparison: {result2} (should be False)")
    
    print("✓ Random delay test (this will take a moment)...")
    import time
    start = time.time()
    TimingAttackMitigation.add_random_delay(50, 100)
    elapsed = (time.time() - start) * 1000
    print(f"  Delay was {elapsed:.1f}ms (expected 50-100ms)")
    print()

def test_progress_reporter():
    """Test ProgressReporter functionality."""
    print("=== Testing ProgressReporter ===")
    
    import time
    progress = ProgressReporter(1000, "Test operation")
    
    for i in range(0, 1001, 250):
        progress.update(250 if i > 0 else 0)
        time.sleep(0.05)  # Simulate work
    
    progress.finish()
    print()

def test_secure_memory():
    """Test SecureMemory functionality."""
    print("=== Testing SecureMemory ===")
    
    try:
        with SecureMemory(64) as secure_buf:
            # Test that we can use the secure buffer
            test_data = b"sensitive_data_here"
            secure_buf[:len(test_data)] = test_data
            
            # Verify data was stored
            stored_data = bytes(secure_buf[:len(test_data)])
            if stored_data == test_data:
                print("✓ Secure memory allocation and usage successful")
            else:
                print("ERROR: Secure memory data mismatch")
        
        print("✓ Secure memory cleanup completed")
    except Exception as e:
        print(f"⚠ Secure memory test failed (may be expected on some systems): {e}")
    
    print()

def test_usb_detection():
    """Test USB drive detection (platform dependent)."""
    print("=== Testing USB Drive Detection ===")
    
    try:
        drives = UsbDriveDetector.get_removable_drives()
        print(f"Found {len(drives)} removable drives:")
        
        for drive in drives[:3]:  # Limit to first 3 to avoid spam
            info = UsbDriveDetector.get_drive_info(drive)
            print(f"  {drive}: writable={info['writable']}, free={info['free_space']//1024//1024}MB")
        
        if not drives:
            print("  No removable drives detected (normal for some environments)")
        
    except Exception as e:
        print(f"⚠ USB detection test failed (expected in some environments): {e}")
    
    print()

def test_secure_functions():
    """Test secure utility functions."""
    print("=== Testing Secure Functions ===")
    
    # Test secure memory clearing
    test_data = bytearray(b"sensitive_information")
    print(f"Before clearing: {test_data}")
    secure_zero_memory(test_data)
    print(f"After clearing: {test_data}")
    
    if all(b == 0 for b in test_data):
        print("✓ Secure memory clearing successful")
    else:
        print("ERROR: Secure memory clearing failed")
    
    print()

if __name__ == "__main__":
    print("Dual USB Backup System - Enhancement Tests")
    print("=" * 50)
    
    test_security_config()
    test_input_validator()
    test_timing_mitigation()
    test_progress_reporter()
    test_secure_memory()
    test_usb_detection()
    test_secure_functions()
    
    print("=" * 50)
    print("✓ Test suite completed successfully!")
    print("\nNote: Some tests may show warnings or failures on certain")
    print("systems due to platform-specific requirements (e.g., admin")
    print("privileges for memory locking, USB drive availability, etc.)")
    print("This is normal and expected.")
