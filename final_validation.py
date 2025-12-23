#!/usr/bin/env python3
"""
Final comprehensive validation of pqcdualusb library for bugs and vulnerabilities.
"""
import sys

def test_imports():
    """Test all critical imports work."""
    print("=" * 60)
    print("TESTING IMPORTS")
    print("=" * 60)
    try:
        from pqcdualusb import (
            PostQuantumCrypto, HybridCrypto, PqcBackend,
            UsbDriveDetector, SecurityConfig, SecureMemory,
            TimingAttackMitigation, ProgressReporter,
            InputValidator, AuditLogRotator
        )
        print("✅ All imports successful")
        print(f"   - Version: {__import__('pqcdualusb').__version__}")
        return True
    except Exception as e:
        print(f"❌ Import failed: {e}")
        return False

def test_crypto_operations():
    """Test basic crypto operations."""
    print("\n" + "=" * 60)
    print("TESTING CRYPTO OPERATIONS")
    print("=" * 60)
    try:
        from pqcdualusb import PostQuantumCrypto
        crypto = PostQuantumCrypto()
        
        # Test KEM
        sk, pk = crypto.generate_kem_keypair()
        print(f"✅ KEM keypair: {len(sk)}+{len(pk)} bytes")
        
        ct, ss1 = crypto.kem_encapsulate(pk)
        ss2 = crypto.kem_decapsulate(ct, sk)
        assert ss1 == ss2, "Shared secrets don't match!"
        print(f"✅ KEM encap/decap: {len(ct)} byte ciphertext")
        
        # Test signatures
        sk_sig, pk_sig = crypto.generate_sig_keypair()
        message = b"Test message for signing"
        signature = crypto.sign(message, sk_sig)
        assert crypto.verify(message, signature, pk_sig), "Signature verification failed!"
        print(f"✅ Signing: {len(signature)} byte signature")
        
        return True
    except Exception as e:
        print(f"❌ Crypto test failed: {e}")
        import traceback
        traceback.print_exc()
        return False

def test_security_features():
    """Test security features."""
    print("\n" + "=" * 60)
    print("TESTING SECURITY FEATURES")
    print("=" * 60)
    try:
        from pqcdualusb.security import SecureMemory, TimingAttackMitigation, secure_zero_memory
        from pqcdualusb.utils import InputValidator
        
        # Test SecureMemory
        with SecureMemory(256) as buf:
            buf[:10] = b"sensitive!"
        print("✅ SecureMemory context manager works")
        
        # Test secure_zero_memory
        data = bytearray(b"secret_data")
        secure_zero_memory(data)
        assert data == bytearray(len(data)), "Memory not zeroed!"
        print("✅ secure_zero_memory works")
        
        # Test constant-time comparison
        tam = TimingAttackMitigation()
        assert tam.constant_time_compare(b"abc", b"abc"), "Should be equal"
        assert not tam.constant_time_compare(b"abc", b"def"), "Should not be equal"
        print("✅ Constant-time comparison works")
        
        # Test input validation
        validator = InputValidator()
        try:
            validator.validate_path("../etc/passwd")
            print("❌ Path traversal not blocked!")
            return False
        except ValueError:
            print("✅ Path traversal protection works")
        
        # Test password validation using InputValidator
        validator = InputValidator()
        try:
            validator.validate_passphrase("weak")
            print("❌ Weak password not rejected!")
            return False
        except ValueError:
            pass
        
        try:
            validator.validate_passphrase("a" * 300)
            print("❌ Too long password not rejected!")
            return False
        except ValueError:
            pass
        
        print("✅ Password validation works")
        
        return True
    except Exception as e:
        print(f"❌ Security test failed: {e}")
        import traceback
        traceback.print_exc()
        return False

def test_no_dangerous_patterns():
    """Check for dangerous code patterns."""
    print("\n" + "=" * 60)
    print("CHECKING FOR DANGEROUS PATTERNS")
    print("=" * 60)
    import os
    from pathlib import Path
    
    dangerous_patterns = {
        'eval(': 0,
        'exec(': 0,
        'shell=True': 0,
        '__import__': 0,  # Will have some legitimate uses
        'pickle.load': 0,
    }
    
    pqcdualusb_dir = Path(__file__).parent / 'pqcdualusb'
    for pyfile in pqcdualusb_dir.glob('*.py'):
        if '- Copy' in str(pyfile):
            continue
        content = pyfile.read_text(errors='ignore')
        for pattern in dangerous_patterns:
            dangerous_patterns[pattern] += content.count(pattern)
    
    print(f"   eval(): {dangerous_patterns['eval(']} occurrences")
    print(f"   exec(): {dangerous_patterns['exec(']} occurrences")
    print(f"   shell=True: {dangerous_patterns['shell=True']} occurrences")
    print(f"   __import__: {dangerous_patterns['__import__']} occurrences (some OK for dynamic imports)")
    print(f"   pickle.load: {dangerous_patterns['pickle.load']} occurrences")
    
    if dangerous_patterns['eval('] > 0 or dangerous_patterns['exec('] > 0 or dangerous_patterns['shell=True'] > 0 or dangerous_patterns['pickle.load'] > 0:
        print("⚠️  Found potentially dangerous patterns!")
        return False
    else:
        print("✅ No dangerous patterns found")
        return True

def main():
    print("\n")
    print("╔" + "=" * 58 + "╗")
    print("║" + " " * 10 + "FINAL VALIDATION TEST SUITE" + " " * 20 + "║")
    print("╚" + "=" * 58 + "╝")
    
    results = []
    results.append(("Imports", test_imports()))
    results.append(("Crypto Operations", test_crypto_operations()))
    results.append(("Security Features", test_security_features()))
    results.append(("Code Patterns", test_no_dangerous_patterns()))
    
    print("\n" + "=" * 60)
    print("FINAL SUMMARY")
    print("=" * 60)
    
    for name, result in results:
        status = "✅ PASS" if result else "❌ FAIL"
        print(f"{name:.<40} {status}")
    
    all_passed = all(result for _, result in results)
    
    if all_passed:
        print("\n🎉 ALL TESTS PASSED - NO BUGS OR VULNERABILITIES DETECTED! 🎉")
        return 0
    else:
        print("\n⚠️  SOME TESTS FAILED - REVIEW REQUIRED")
        return 1

if __name__ == "__main__":
    sys.exit(main())
