# PQC Dual USB Backup - Library Summary

## 📦 What Is This?

**This is a Python library** for quantum-resistant cryptography and secure USB backup operations. Import it into your applications for future-proof data protection.

## 🎯 Quick Start

### Installation

```bash
# Option 1: From PyPI (when published)
pip install pqcdualusb

# Option 2: From source
cd Dual_USB_Backup
pip install -e .

# Option 3: Add to requirements.txt
pqcdualusb>=0.1.0
```

### Basic Usage

```python
from pqcdualusb import PostQuantumCrypto, PqcBackend

# Initialize with fallback (works everywhere)
pqc = PostQuantumCrypto(allow_fallback=True)

# Check which backend is active
if pqc.backend == PqcBackend.OQS:
    print("✅ Using quantum-safe crypto (Kyber1024 + Dilithium3)")
elif pqc.backend == PqcBackend.CLASSICAL:
    print("⚠️  Using classical crypto (RSA-4096, secure until ~2035)")

# Generate quantum-safe keys
secret_key, public_key = pqc.generate_kem_keypair()

# Encapsulate shared secret
ciphertext, shared_secret = pqc.kem_encapsulate(public_key)

# Decapsulate shared secret
recovered_secret = pqc.kem_decapsulate(secret_key, ciphertext)

# Sign data
sig_secret, sig_public = pqc.generate_sig_keypair()
signature = pqc.sign(b"Important data", sig_secret)

# Verify signature
is_valid = pqc.verify(b"Important data", signature, sig_public)
```

## 🛡️ Security Backends

The library automatically selects the best available backend:

### On Windows (Native)
- ⚠️ **Classical RSA-4096** (secure for now, not quantum-resistant)
- Use `allow_fallback=True` for convenience
- Suitable for data with <10 year lifetime

### On Windows (WSL2) - Recommended
- ✅ **OQS (liboqs)** - REAL quantum-safe crypto
- Kyber1024 + Dilithium3 (ML-DSA-65)
- Protected against quantum computers
- 15-minute setup (see FAST_TRACK_REAL_PQC.md)

### On Linux/macOS
- ✅ **OQS (liboqs)** - Native quantum-safe support
- Install liboqs system library
- Best performance and security

## 📚 Complete Documentation

| Document | Purpose |
|----------|---------|
| **USAGE_AS_LIBRARY.md** | **← START HERE** - Integration guide with examples |
| **LIBRARY_README.md** | Complete API reference and features |
| **FAST_TRACK_REAL_PQC.md** | Setup quantum-safe crypto in 15 minutes |
| **README.md** | Main project documentation |
| **example_library_usage.py** | Working code examples |

## 🔧 API Overview

### Core Classes

```python
from pqcdualusb import (
    PostQuantumCrypto,   # Low-level PQC operations
    HybridCrypto,        # High-level encryption (PQC + AES-256)
    BackupManager,       # Dual USB backup management
    UsbDriveDetector,    # Cross-platform USB detection
    SecurityConfig,      # Security configuration
    PqcBackend,          # Backend enum (OQS, RUST, CPP, CLASSICAL)
)
```

### Main Operations

| Operation | Method | Description |
|-----------|--------|-------------|
| **KEM Keygen** | `generate_kem_keypair()` | Generate Kyber1024 keypair |
| **Encapsulate** | `kem_encapsulate(pk)` | Create shared secret + ciphertext |
| **Decapsulate** | `kem_decapsulate(sk, ct)` | Recover shared secret |
| **Sign Keygen** | `generate_sig_keypair()` | Generate Dilithium3 keypair |
| **Sign** | `sign(msg, sk)` | Create digital signature |
| **Verify** | `verify(msg, sig, pk)` | Verify signature |

### High-Level Encryption

```python
from pqcdualusb import HybridCrypto

crypto = HybridCrypto()

# Encrypt with PQC + AES-256-GCM
encrypted_data, metadata = crypto.encrypt_file(
    b"sensitive data",
    password="strong_password"
)

# Decrypt
decrypted_data = crypto.decrypt_file(
    encrypted_data,
    password="strong_password",
    metadata=metadata
)
```

## 🎨 Real-World Integration Examples

### 1. Password Manager

```python
from pqcdualusb import HybridCrypto
import json

class PasswordManager:
    def __init__(self):
        self.crypto = HybridCrypto()
    
    def save(self, passwords: dict, master_password: str, file: str):
        data = json.dumps(passwords).encode()
        encrypted, metadata = self.crypto.encrypt_file(data, master_password)
        
        with open(file, 'wb') as f:
            f.write(encrypted)
        with open(f"{file}.meta", 'w') as f:
            json.dump(metadata, f)
    
    def load(self, master_password: str, file: str) -> dict:
        with open(file, 'rb') as f:
            encrypted = f.read()
        with open(f"{file}.meta") as f:
            metadata = json.load(f)
        
        decrypted = self.crypto.decrypt_file(encrypted, master_password, metadata)
        return json.loads(decrypted)

# Usage
pm = PasswordManager()
pm.save({"email": "pass123", "bank": "pass456"}, "master", "passwords.enc")
passwords = pm.load("master", "passwords.enc")
```

### 2. Secure API Signatures

```python
from pqcdualusb import PostQuantumCrypto
import hashlib

class SecureAPI:
    def __init__(self):
        self.pqc = PostQuantumCrypto(allow_fallback=True)
        self.sig_secret, self.sig_public = self.pqc.generate_sig_keypair()
    
    def sign_request(self, data: bytes) -> tuple[bytes, bytes]:
        """Sign request with quantum-safe signature."""
        request_hash = hashlib.sha3_256(data).digest()
        signature = self.pqc.sign(request_hash, self.sig_secret)
        return data, signature
    
    def verify_request(self, data: bytes, signature: bytes) -> bool:
        """Verify request signature."""
        request_hash = hashlib.sha3_256(data).digest()
        return self.pqc.verify(request_hash, signature, self.sig_public)

# Usage
api = SecureAPI()
data, sig = api.sign_request(b"GET /api/resource")
is_valid = api.verify_request(data, sig)  # True
```

### 3. Backup Application

```python
from pqcdualusb import BackupManager, UsbDriveDetector

class MyBackupApp:
    def __init__(self):
        self.backup_mgr = BackupManager()
    
    def backup(self, source_dir: str):
        """Perform quantum-safe backup to USB drives."""
        drives = UsbDriveDetector.get_removable_drives()
        
        if len(drives) < 2:
            raise ValueError("Need 2 USB drives for dual backup")
        
        destinations = [d['mount_point'] for d in drives[:2]]
        self.backup_mgr.create_backup(source_dir, destinations)
        print("✅ Quantum-safe backup complete!")

# Usage
app = MyBackupApp()
app.backup("/path/to/important/data")
```

## ⚠️ Important Notes

### Windows Users

When you import the library on Windows, you may see warnings about OQS not being available:

```
liboqs not found, installing it in C:\Users\...
Error installing liboqs.
RuntimeError: No oqs shared libraries found
```

**This is normal and expected!** The library will automatically fall back to classical RSA-4096 cryptography, which is:
- ✅ Secure for current threats (quantum computers don't exist yet)
- ✅ Works out of the box on Windows
- ✅ Suitable for data with <10 year lifetime
- ⚠️ NOT quantum-resistant (will be vulnerable ~2035+)

**For quantum-safe crypto on Windows:**
1. Install WSL2: `wsl --install`
2. Follow FAST_TRACK_REAL_PQC.md (15 minutes)
3. Run your application in WSL2

### Linux/macOS Users

Install liboqs system library for quantum-safe crypto:

```bash
sudo apt install -y build-essential cmake ninja-build libssl-dev

# Build liboqs
cd /tmp
git clone --depth 1 https://github.com/open-quantum-safe/liboqs.git
cd liboqs && mkdir build && cd build
cmake -GNinja -DCMAKE_INSTALL_PREFIX=/usr/local -DBUILD_SHARED_LIBS=ON ..
ninja && sudo ninja install && sudo ldconfig

# Install Python bindings
pip install liboqs-python cryptography
```

## 🔍 Backend Detection

```python
from pqcdualusb import PostQuantumCrypto, PqcBackend

# Strict mode: Require quantum-safe backend
try:
    pqc = PostQuantumCrypto(allow_fallback=False)
    print("✅ Quantum-safe backend available!")
except RuntimeError:
    print("❌ No PQC backend available")
    print("Use allow_fallback=True for classical crypto")

# Permissive mode: Allow classical fallback
pqc = PostQuantumCrypto(allow_fallback=True)

if pqc.backend == PqcBackend.OQS:
    print("Using OQS: Kyber1024 + Dilithium3")
elif pqc.backend == PqcBackend.RUST:
    print("Using Rust: Native performance")
elif pqc.backend == PqcBackend.CLASSICAL:
    print("Using Classical: RSA-4096 (fallback)")
```

## 📊 Key Size Comparison

| Algorithm | Public Key | Secret Key | Ciphertext/Signature |
|-----------|-----------|------------|---------------------|
| **Kyber1024** | 1,568 B | 3,168 B | 1,568 B |
| **Dilithium3** | 1,952 B | 4,032 B | ~3,309 B |
| **RSA-4096** | ~800 B | ~3,272 B | 512 B |

You can verify which algorithm is active by checking key sizes:

```python
pqc = PostQuantumCrypto(allow_fallback=True)
_, public_key = pqc.generate_kem_keypair()

if len(public_key) == 1568:
    print("✅ Real Kyber1024! (Quantum-safe)")
elif len(public_key) < 1000:
    print("⚠️  Classical RSA (Fallback)")
```

## 🧪 Testing Your Integration

```python
import unittest
from pqcdualusb import PostQuantumCrypto

class TestMyIntegration(unittest.TestCase):
    def setUp(self):
        self.pqc = PostQuantumCrypto(allow_fallback=True)
    
    def test_kem(self):
        sk, pk = self.pqc.generate_kem_keypair()
        ct, ss1 = self.pqc.kem_encapsulate(pk)
        ss2 = self.pqc.kem_decapsulate(sk, ct)
        self.assertEqual(ss1, ss2)
    
    def test_signatures(self):
        sk, pk = self.pqc.generate_sig_keypair()
        sig = self.pqc.sign(b"test", sk)
        self.assertTrue(self.pqc.verify(b"test", sig, pk))
```

## 🐛 Troubleshooting

### "ModuleNotFoundError: No module named 'pqcdualusb'"

```bash
# Solution 1: Install in development mode
cd Dual_USB_Backup
pip install -e .

# Solution 2: Add to PYTHONPATH
export PYTHONPATH="${PYTHONPATH}:/path/to/Dual_USB_Backup"

# Solution 3: Install from PyPI (when published)
pip install pqcdualusb
```

### "RuntimeError: No post-quantum library available"

This happens when `allow_fallback=False` but no quantum-safe backend is available.

**Solutions:**
- Use `allow_fallback=True` for classical crypto
- Or install liboqs (see FAST_TRACK_REAL_PQC.md)
- Or use WSL2 on Windows

### OQS Warnings on Windows

The warnings about "liboqs not found" are normal on Windows. The library automatically falls back to classical crypto. You can:
- Ignore the warnings (classical crypto works fine)
- Or use WSL2 for quantum-safe crypto

## 📖 Further Reading

- **USAGE_AS_LIBRARY.md** - Detailed integration guide
- **FAST_TRACK_REAL_PQC.md** - Get quantum-safe crypto in 15 minutes
- **ARCHITECTURE.md** - System design and components
- **SECURITY.md** - Threat model and security considerations

## 🎯 When to Use Quantum-Safe vs Classical

✅ **Use Quantum-Safe (OQS backend) when:**
- Data must remain secure for 10+ years
- Protecting against "harvest now, decrypt later" attacks
- Compliance requires quantum resistance
- Running on Linux or WSL2

✅ **Classical fallback (RSA-4096) is fine when:**
- Data lifetime < 10 years
- Running on Windows (for convenience)
- Quantum computers don't exist yet (expected ~2035-2040)
- Performance is critical

## 🚀 Next Steps

1. **Read USAGE_AS_LIBRARY.md** for detailed examples
2. **Install the library**: `pip install -e .`
3. **Import in your app**: `from pqcdualusb import PostQuantumCrypto`
4. **Test with**: `python example_library_usage.py`
5. **For quantum-safe**: Follow FAST_TRACK_REAL_PQC.md

---

**Your applications are now ready for the quantum future! 🛡️🔐**
