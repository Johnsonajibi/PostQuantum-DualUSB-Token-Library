#!/usr/bin/env python3
"""
Test script to validate the signature verification bug fix.
This tests that signature verification correctly rejects invalid signatures.
"""

import sys
sys.path.insert(0, '.')
from pqcdualusb import PostQuantumCrypto

def test_signature_verification():
    """Test that signature verification works correctly after the bug fix."""
    print("=== Testing Signature Verification Bug Fix ===\n")
    
    # Initialize crypto
    crypto = PostQuantumCrypto()
    print(f"✓ Using backend: {crypto.backend}")
    
    # Generate signature keypair
    sig_secret, sig_public = crypto.generate_sig_keypair()
    print(f"✓ Generated signature keypair - secret: {len(sig_secret)} bytes, public: {len(sig_public)} bytes")
    
    # Test messages
    original_message = b"This is the original message to be signed"
    tampered_message = b"This is a TAMPERED message - should fail verification"
    
    # Create signature for original message
    signature = crypto.sign(original_message, sig_secret)
    print(f"✓ Created signature: {len(signature)} bytes")
    
    # Test 1: Verify correct message (should pass)
    is_valid_correct = crypto.verify(original_message, signature, sig_public)
    print(f"✓ Original message verification: {is_valid_correct} (should be True)")
    
    # Test 2: Verify tampered message with same signature (should fail)
    is_valid_tampered = crypto.verify(tampered_message, signature, sig_public)
    print(f"✓ Tampered message verification: {is_valid_tampered} (should be False)")
    
    # Test 3: Verify with wrong public key (should fail)
    wrong_secret, wrong_public = crypto.generate_sig_keypair()
    is_valid_wrong_key = crypto.verify(original_message, signature, wrong_public)
    print(f"✓ Wrong public key verification: {is_valid_wrong_key} (should be False)")
    
    # Test 4: Verify with corrupted signature (should fail)
    corrupted_sig = bytearray(signature)
    corrupted_sig[0] ^= 0xFF  # Flip bits in first byte
    corrupted_sig = bytes(corrupted_sig)
    is_valid_corrupted = crypto.verify(original_message, corrupted_sig, sig_public)
    print(f"✓ Corrupted signature verification: {is_valid_corrupted} (should be False)")
    
    # Summary
    all_tests_passed = (
        is_valid_correct == True and 
        is_valid_tampered == False and 
        is_valid_wrong_key == False and 
        is_valid_corrupted == False
    )
    
    print(f"\n=== Test Results ===")
    print(f"Valid signature accepted: {'✓' if is_valid_correct else '✗'}")
    print(f"Tampered message rejected: {'✓' if not is_valid_tampered else '✗'}")
    print(f"Wrong key rejected: {'✓' if not is_valid_wrong_key else '✗'}")
    print(f"Corrupted signature rejected: {'✓' if not is_valid_corrupted else '✗'}")
    print(f"\n🎉 All signature tests passed!" if all_tests_passed else "❌ Some signature tests failed!")
    
    return all_tests_passed

if __name__ == "__main__":
    success = test_signature_verification()
    sys.exit(0 if success else 1)