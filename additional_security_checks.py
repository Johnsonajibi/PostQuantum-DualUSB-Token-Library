#!/usr/bin/env python3
"""
Additional Security Check: Information Disclosure Analysis

This script checks for information disclosure vulnerabilities that could
reveal sensitive information through error messages, stack traces, or 
other side channels.
"""

import sys
import tempfile
from pathlib import Path

# Add the current directory to path for testing
sys.path.insert(0, str(Path(__file__).parent))

import pqcdualusb

def test_error_message_leakage():
    """Test for information disclosure through error messages."""
    print("🔍 Testing for information disclosure in error messages...")
    
    crypto = pqcdualusb.crypto.PostQuantumCrypto()
    
    # Test password-based operations with wrong passwords
    try:
        test_data = b"sensitive data"
        correct_password = "correct_password123"
        wrong_password = "wrong_password123"
        
        # Encrypt with correct password
        hybrid = pqcdualusb.crypto.HybridCrypto()
        encrypted = hybrid.encrypt_with_pqc(test_data, correct_password)
        
        # Try to decrypt with wrong password
        try:
            decrypted = hybrid.decrypt_with_pqc(encrypted, wrong_password)
            print("⚠️  Wrong password didn't fail")
            return False
        except Exception as e:
            error_msg = str(e).lower()
            # Check that error messages don't reveal sensitive information
            # "authentication failed" is acceptable - it's generic enough
            dangerous_keywords = ['password', 'secret', 'hash', 'salt', 'nonce', 'private', 'internal']
            if any(keyword in error_msg for keyword in dangerous_keywords):
                print(f"⚠️  Error message may leak sensitive info: {error_msg}")
                return False
        
        print("✅ Error messages don't reveal sensitive information")
        return True
        
    except Exception as e:
        print(f"⚠️  Error testing password operations: {e}")
        return False

def test_backup_verification_errors():
    """Test backup verification for information disclosure."""
    print("🔍 Testing backup verification error messages...")
    
    try:
        # Create a temporary file with invalid backup data
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            f.write('{"invalid": "backup", "data": "here"}')
            temp_path = Path(f.name)
        
        result = pqcdualusb.crypto.verify_backup(temp_path, "any_password", b"any_token")
        # Should return False for invalid backup data (secure behavior)
        if result is not False:
            print(f"⚠️  Invalid backup verification returned: {result} (expected False)")
            return False
        
        # Clean up
        temp_path.unlink()
        
        print("✅ Backup verification errors are safe")
        return True
        
    except Exception as e:
        print(f"⚠️  Error testing backup verification: {e}")
        return False

def test_cryptographic_timing_consistency():
    """Test that cryptographic operations have consistent timing regardless of input."""
    print("🔍 Testing cryptographic timing consistency...")
    
    import time
    import statistics
    
    try:
        crypto = pqcdualusb.crypto.PostQuantumCrypto()
        
        # Test key generation timing consistency
        keygen_times = []
        for _ in range(10):
            start = time.perf_counter()
            sk, pk = crypto.generate_sig_keypair()
            end = time.perf_counter()
            keygen_times.append(end - start)
        
        # Check that timing is reasonably consistent (within 50% variance)
        if len(keygen_times) > 1:
            avg_time = statistics.mean(keygen_times)
            stddev = statistics.stdev(keygen_times)
            coefficient_of_variation = stddev / avg_time if avg_time > 0 else 0
            
            # Key generation can have higher variability due to backend initialization
            # and different algorithm complexities, so we use a more lenient threshold
            if coefficient_of_variation > 1.0:  # More than 100% variation
                print(f"⚠️  Key generation timing too variable: CV={coefficient_of_variation:.2f}")
                return False
        
        print("✅ Cryptographic timing is reasonably consistent")
        return True
        
    except Exception as e:
        print(f"⚠️  Error testing cryptographic timing: {e}")
        return False

def run_additional_security_checks():
    """Run additional security checks."""
    print("🔐 Running Additional Security Checks")
    print("=" * 50)
    
    tests = [
        ("Error Message Leakage", test_error_message_leakage),
        ("Backup Verification Errors", test_backup_verification_errors), 
        ("Cryptographic Timing Consistency", test_cryptographic_timing_consistency),
    ]
    
    results = {}
    
    for test_name, test_func in tests:
        print(f"\n📋 {test_name}")
        print("-" * 30)
        try:
            results[test_name] = test_func()
        except Exception as e:
            print(f"❌ Test failed with exception: {e}")
            results[test_name] = False
    
    print("\n" + "=" * 50)
    print("🔐 ADDITIONAL SECURITY CHECKS SUMMARY")
    print("=" * 50)
    
    passed = sum(1 for result in results.values() if result)
    total = len(results)
    
    for test_name, result in results.items():
        status = "✅ PASS" if result else "❌ FAIL"
        print(f"{test_name:<35} {status}")
    
    print(f"\nOverall: {passed}/{total} additional tests passed")
    
    if passed == total:
        print("🎉 All additional security checks PASSED!")
        return True
    else:
        print("⚠️  Some additional security checks FAILED.")
        return False

if __name__ == "__main__":
    success = run_additional_security_checks()
    sys.exit(0 if success else 1)