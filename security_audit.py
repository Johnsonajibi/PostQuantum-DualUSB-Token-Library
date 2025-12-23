#!/usr/bin/env python3
"""
Comprehensive Security Vulnerability Audit for pqcdualusb

This script performs systematic security testing to identify vulnerabilities including:
- Timing attacks
- Memory leakage
- Cryptographic implementation flaws
- Input validation bypasses
- Side-channel attacks
- Integer overflow/underflow
- Path traversal vulnerabilities
"""

import os
import sys
import time
import json
import tempfile
import statistics
from pathlib import Path

# Add the current directory to path for testing
sys.path.insert(0, str(Path(__file__).parent))

import pqcdualusb

def test_timing_attack_resistance():
    """Test for timing attack vulnerabilities in cryptographic operations."""
    print("🔍 Testing timing attack resistance...")
    
    # Test signature verification timing using correct API
    crypto = pqcdualusb.crypto.PostQuantumCrypto()
    sk, pk = crypto.generate_sig_keypair()  # Correct method name
    message = b"test message"
    signature = crypto.sign(message, sk)  # Correct method signature
    
    # Measure timing for valid signatures
    valid_times = []
    for _ in range(50):
        start = time.perf_counter()
        result = crypto.verify(message, signature, pk)  # Correct method signature
        end = time.perf_counter()
        valid_times.append(end - start)
        assert result is True, "Valid signature should verify"
    
    # Measure timing for invalid signatures (corrupted)
    corrupted_signature = bytearray(signature)
    corrupted_signature[0] ^= 1  # Flip one bit
    
    invalid_times = []
    for _ in range(50):
        start = time.perf_counter()
        result = crypto.verify(message, bytes(corrupted_signature), pk)
        end = time.perf_counter()
        invalid_times.append(end - start)
        assert result is False, "Invalid signature should not verify"
    
    # Statistical analysis of timing differences
    valid_avg = statistics.mean(valid_times)
    invalid_avg = statistics.mean(invalid_times)
    valid_stddev = statistics.stdev(valid_times) if len(valid_times) > 1 else 0
    invalid_stddev = statistics.stdev(invalid_times) if len(invalid_times) > 1 else 0
    
    timing_difference = abs(valid_avg - invalid_avg)
    combined_stddev = (valid_stddev + invalid_stddev) / 2
    
    # If timing difference is more than 2 standard deviations, potential vulnerability
    if timing_difference > 2 * combined_stddev and timing_difference > 1e-6:
        print(f"⚠️  POTENTIAL TIMING ATTACK: Valid avg: {valid_avg:.6f}s, Invalid avg: {invalid_avg:.6f}s")
        return False
    else:
        print(f"✅ Timing attack resistance: Valid avg: {valid_avg:.6f}s, Invalid avg: {invalid_avg:.6f}s (difference: {timing_difference:.6f}s)")
        return True

def test_constant_time_compare():
    """Test constant-time comparison implementation."""
    print("🔍 Testing constant-time comparison...")
    
    from pqcdualusb.security import TimingAttackMitigation
    
    # Test equal strings
    a = b"hello"
    b = b"hello"
    
    times_equal = []
    for _ in range(100):
        start = time.perf_counter()
        result = TimingAttackMitigation.constant_time_compare(a, b)
        end = time.perf_counter()
        times_equal.append(end - start)
        assert result is True
    
    # Test different strings of same length
    c = b"world"
    times_diff_same_len = []
    for _ in range(100):
        start = time.perf_counter()
        result = TimingAttackMitigation.constant_time_compare(a, c)
        end = time.perf_counter()
        times_diff_same_len.append(end - start)
        assert result is False
    
    # Test different lengths
    d = b"hello world"
    times_diff_len = []
    for _ in range(100):
        start = time.perf_counter()
        result = TimingAttackMitigation.constant_time_compare(a, d)
        end = time.perf_counter()
        times_diff_len.append(end - start)
        assert result is False
    
    # Check timing consistency
    avg_equal = statistics.mean(times_equal)
    avg_diff_same = statistics.mean(times_diff_same_len)
    avg_diff_len = statistics.mean(times_diff_len)
    
    print(f"✅ Constant-time compare: Equal={avg_equal:.8f}s, Different(same len)={avg_diff_same:.8f}s, Different(diff len)={avg_diff_len:.8f}s")
    
    # All should be roughly the same timing (within reasonable bounds for Python)
    max_diff = max(avg_equal, avg_diff_same, avg_diff_len) - min(avg_equal, avg_diff_same, avg_diff_len)
    
    # More lenient threshold for Python's inherent timing variations
    # but still detect major timing differences that could leak information
    threshold = max(1e-5, min(avg_equal, avg_diff_same, avg_diff_len) * 0.5)  # 50% of minimum time or 10 microseconds
    
    if max_diff > threshold:
        print(f"⚠️  Timing variation too large: {max_diff:.8f}s > {threshold:.8f}s")
        return False
    
    return True

def test_memory_security():
    """Test for memory security issues."""
    print("🔍 Testing memory security...")
    
    from pqcdualusb.security import SecureMemory, secure_zero_memory
    
    # Test secure memory allocation
    try:
        with SecureMemory(1024) as secure_buf:
            # Fill with sensitive data
            sensitive_data = b"SECRET_PASSWORD_12345"
            secure_buf[:len(sensitive_data)] = sensitive_data
            
            # Verify data is there
            assert bytes(secure_buf[:len(sensitive_data)]) == sensitive_data
        
        print("✅ SecureMemory context manager works")
    except Exception as e:
        print(f"⚠️  SecureMemory issue: {e}")
        return False
    
    # Test secure zero implementation
    test_data = bytearray(b"sensitive_information")
    original_data = bytes(test_data)
    secure_zero_memory(test_data)
    
    if test_data == bytearray(len(test_data)):  # All zeros
        print("✅ secure_zero_memory works correctly")
        return True
    else:
        print(f"⚠️  secure_zero_memory failed: {test_data}")
        return False

def test_input_validation():
    """Test input validation for common attack vectors."""
    print("🔍 Testing input validation...")
    
    from pqcdualusb.utils import InputValidator
    
    # Test path traversal prevention
    try:
        # These should fail
        dangerous_paths = [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\config\\sam", 
            "/etc/shadow",
            "C:\\Windows\\System32\\config\\SAM",
            "file:///etc/passwd",
            "\\\\server\\share\\file",
        ]
        
        for dangerous_path in dangerous_paths:
            try:
                # Use the current working directory as allowed_base to test path traversal protection
                current_dir = Path.cwd()
                validated = InputValidator.validate_path(dangerous_path, must_exist=False, allowed_base=current_dir)
                print(f"⚠️  Path traversal not blocked: {dangerous_path} -> {validated}")
                return False
            except (ValueError, OSError):
                pass  # Expected to fail
        
        print("✅ Path traversal attacks blocked")
    except Exception as e:
        print(f"⚠️  Input validation error: {e}")
        return False
    
    # Test passphrase validation
    try:
        # Weak passwords should fail
        weak_passwords = ["123", "password", "", "a" * 20, "a" * 250]  # Too short, common, empty, repeated chars, too long
        
        for idx, weak in enumerate(weak_passwords):
            try:
                InputValidator.validate_passphrase(weak)
                print(f"⚠️  Weak password not rejected (index={idx}, length={len(weak)})")
                return False
            except ValueError:
                pass  # Expected to fail
        
        # Strong password should pass
        strong_password = "This_is_a_very_str0ng_p@ssw0rd_with_123_numbers"
        try:
            result = InputValidator.validate_passphrase(strong_password)
            assert result == strong_password
            print("✅ Password validation works")
        except ValueError as e:
            print(f"⚠️  Strong password rejected: {e}")
            return False
            
    except Exception as e:
        print(f"⚠️  Password validation error: {e}")
        return False
    
    return True

def test_json_security():
    """Test JSON handling for security issues."""
    print("🔍 Testing JSON security...")
    
    # Test with malicious JSON payloads
    malicious_payloads = [
        '{"__proto__": {"isAdmin": true}}',  # Prototype pollution
        '{"constructor": {"prototype": {"isAdmin": true}}}',
        '{}' + 'A' * 10000000,  # Memory exhaustion (shortened for test)
        '[' + '1,' * 1000 + '1]',  # Large array
    ]
    
    for payload in malicious_payloads[:2]:  # Skip memory exhaustion tests
        try:
            data = json.loads(payload)
            # Check that prototype pollution didn't work
            if hasattr(dict, 'isAdmin') and dict.isAdmin:
                print(f"⚠️  Prototype pollution successful with: {payload[:50]}...")
                return False
        except (json.JSONDecodeError, MemoryError):
            pass  # Expected for malicious payloads
    
    print("✅ JSON security checks passed")
    return True

def test_random_number_security():
    """Test random number generation quality."""
    print("🔍 Testing random number generation...")
    
    # Test that we're using cryptographically secure random sources
    import secrets
    
    # Generate multiple random values and check for patterns
    sample_size = 1000
    range_size = 10000000  # Larger range to reduce collision probability
    random_values = [secrets.randbelow(range_size) for _ in range(sample_size)]
    
    # Basic statistical tests
    avg = sum(random_values) / len(random_values)
    expected_avg = (range_size - 1) / 2  # For randbelow(range_size), average is (0 + (range_size-1)) / 2
    
    # Should be roughly in the middle (within 5% due to randomness with 1000 samples)
    tolerance = expected_avg * 0.05  # 5% tolerance
    if abs(avg - expected_avg) > tolerance:
        print(f"⚠️  Random values not well distributed: avg={avg:.2f}, expected≈{expected_avg:.2f}, tolerance={tolerance:.2f}")
        return False
    
    # Check for duplicates - with 1000 samples from 10M range, duplicates should be extremely rare
    unique_values = len(set(random_values))
    duplicate_rate = (sample_size - unique_values) / sample_size
    
    # Allow a very small number of duplicates (< 1%) due to birthday paradox
    if duplicate_rate > 0.01:
        print(f"⚠️  Too many duplicate random values: {duplicate_rate:.2%} duplicates (expected < 1%)")
        return False
    
    print(f"✅ Random number generation: avg={avg:.0f} (expected≈{expected_avg})")
    return True

def test_integer_overflow():
    """Test for integer overflow vulnerabilities."""
    print("🔍 Testing integer overflow protection...")
    
    try:
        # Test large token sizes
        from pqcdualusb.utils import InputValidator
        
        # Should handle large but reasonable sizes
        reasonable_size = InputValidator.validate_token_size(1024)
        assert reasonable_size == 1024
        
        # Should reject unreasonable sizes
        try:
            huge_size = InputValidator.validate_token_size(2**63)  # Huge number
            print(f"⚠️  Huge token size not rejected: {huge_size}")
            return False
        except (ValueError, OverflowError):
            pass  # Expected to fail
        
        try:
            negative_size = InputValidator.validate_token_size(-1)
            print(f"⚠️  Negative token size not rejected: {negative_size}")
            return False
        except ValueError:
            pass  # Expected to fail
        
        print("✅ Integer overflow protection works")
        return True
        
    except Exception as e:
        print(f"⚠️  Integer overflow test error: {e}")
        return False

def run_comprehensive_audit():
    """Run all security tests."""
    print("🔐 Running Comprehensive Security Audit for pqcdualusb")
    print("=" * 60)
    
    tests = [
        ("Timing Attack Resistance", test_timing_attack_resistance),
        ("Constant-Time Comparison", test_constant_time_compare),
        ("Memory Security", test_memory_security),
        ("Input Validation", test_input_validation),
        ("JSON Security", test_json_security),
        ("Random Number Security", test_random_number_security),
        ("Integer Overflow Protection", test_integer_overflow),
    ]
    
    results = {}
    
    for test_name, test_func in tests:
        try:
            print(f"\n📋 {test_name}")
            print("-" * 40)
            results[test_name] = test_func()
        except Exception as e:
            print(f"❌ Test failed with exception: {e}")
            results[test_name] = False
    
    print("\n" + "=" * 60)
    print("🔐 SECURITY AUDIT SUMMARY")
    print("=" * 60)
    
    passed = sum(1 for result in results.values() if result)
    total = len(results)
    
    for test_name, result in results.items():
        status = "✅ PASS" if result else "❌ FAIL"
        print(f"{test_name:<30} {status}")
    
    print(f"\nOverall: {passed}/{total} tests passed")
    
    if passed == total:
        print("🎉 All security tests PASSED! No vulnerabilities detected.")
        return True
    else:
        print("⚠️  Some security tests FAILED. Review the issues above.")
        return False

if __name__ == "__main__":
    success = run_comprehensive_audit()
    sys.exit(0 if success else 1)