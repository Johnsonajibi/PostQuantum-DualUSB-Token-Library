#!/usr/bin/env python3
"""
Targeted test for backup verification vulnerability
"""

import sys
import tempfile
import json
from pathlib import Path

# Add the current directory to path for testing
sys.path.insert(0, str(Path(__file__).parent))

import pqcdualusb

def test_backup_vulnerability():
    """Test specific backup verification vulnerability."""
    
    test_cases = [
        ('{"invalid": "backup"}', "Missing required fields"),
        ('{"meta": {}}', "Missing aead field"),
        ('{"meta": {}, "aead": {}}', "Missing kdf field"),
        ('{"meta": {"sha3": "invalid_hex"}, "aead": {"nonce": "123", "ct": "456"}, "kdf": {"salt": "789"}}', "Invalid hex data"),
        ('not valid json', "Invalid JSON"),
        ('', "Empty file"),
    ]
    
    for test_data, description in test_cases:
        print(f"Testing: {description}")
        
        # Create temporary file
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            f.write(test_data)
            temp_path = Path(f.name)
        
        try:
            result = pqcdualusb.crypto.verify_backup(temp_path, "test_password", b"test_token")
            print(f"  Result: {result} (should be False or raise exception)")
        except Exception as e:
            print(f"  Exception: {type(e).__name__}: {e}")
            
        # Clean up
        temp_path.unlink()
        print()

if __name__ == "__main__":
    test_backup_vulnerability()