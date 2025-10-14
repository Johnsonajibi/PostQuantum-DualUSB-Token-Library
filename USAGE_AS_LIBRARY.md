# Using PQC Dual USB Backup as a Library

## 🎯 Overview

This is a **library package** designed to be imported into other Python applications. It provides quantum-resistant cryptography and secure USB backup operations.

## 📦 Installation Options

### For Application Developers

```bash
# Option 1: Install from PyPI (when published)
pip install pqcdualusb

# Option 2: Install from local source
cd /path/to/Dual_USB_Backup
pip install -e .

# Option 3: Add as dependency in requirements.txt
pqcdualusb>=0.1.0
```

### For Quantum-Safe Crypto (Recommended)

```bash
# Windows: Use WSL2
wsl --install
# Then follow Linux instructions below

# Linux/WSL2: Install liboqs
sudo apt update
sudo apt install -y build-essential cmake ninja-build libssl-dev python3-pip python3-venv

# Build liboqs from source
cd /tmp
git clone --depth 1 https://github.com/open-quantum-safe/liboqs.git
cd liboqs && mkdir build && cd build
cmake -GNinja -DCMAKE_INSTALL_PREFIX=/usr/local -DBUILD_SHARED_LIBS=ON ..
ninja && sudo ninja install && sudo ldconfig

# Install Python dependencies
pip install pqcdualusb liboqs-python cryptography
```

## 🚀 Quick Start

### Import the Library

```python
# Import main classes
from pqcdualusb import PostQuantumCrypto, HybridCrypto, BackupManager, PqcBackend

# Or import specific modules
from pqcdualusb.crypto import PostQuantumCrypto
from pqcdualusb.usb import UsbDriveDetector
from pqcdualusb.security import SecurityConfig, SecureMemory
from pqcdualusb.utils import ProgressReporter, InputValidator
```

### Basic Usage Examples

#### 1. Post-Quantum Key Generation

```python
from pqcdualusb import PostQuantumCrypto

# Initialize with automatic backend selection
pqc = PostQuantumCrypto(allow_fallback=True)

# Check which backend is active
print(f"Using backend: {pqc.backend}")  
# Output: PqcBackend.OQS (quantum-safe!) or PqcBackend.CLASSICAL (fallback)

# Generate quantum-safe keypair
secret_key, public_key = pqc.generate_kem_keypair()
print(f"Public key size: {len(public_key)} bytes")
# Kyber1024: 1,568 bytes (quantum-safe)
# RSA-4096:    800 bytes (classical fallback)
```

#### 2. Quantum-Safe Key Encapsulation

```python
from pqcdualusb import PostQuantumCrypto

pqc = PostQuantumCrypto(allow_fallback=True)

# Generate keys
secret_key, public_key = pqc.generate_kem_keypair()

# Encapsulate: Creates ciphertext and shared secret
ciphertext, shared_secret = pqc.kem_encapsulate(public_key)

# Decapsulate: Recover shared secret
recovered_secret = pqc.kem_decapsulate(secret_key, ciphertext)

assert shared_secret == recovered_secret  # ✅ Secrets match!
```

#### 3. Quantum-Safe Digital Signatures

```python
from pqcdualusb import PostQuantumCrypto

pqc = PostQuantumCrypto(allow_fallback=True)

# Generate signature keypair
sig_secret, sig_public = pqc.generate_sig_keypair()

# Sign data
message = b"Important document contents"
signature = pqc.sign(message, sig_secret)

# Verify signature
is_valid = pqc.verify(message, signature, sig_public)
print(f"Signature valid: {is_valid}")  # ✅ True
```

#### 4. High-Level Hybrid Encryption

```python
from pqcdualusb import HybridCrypto

crypto = HybridCrypto()

# Encrypt with quantum-safe KEM + AES-256-GCM
data = b"Sensitive application data"
password = "strong_user_password"

encrypted_data, metadata = crypto.encrypt_file(data, password)

# Decrypt
decrypted_data = crypto.decrypt_file(encrypted_data, password, metadata)

assert data == decrypted_data  # ✅ Data recovered!
```

#### 5. USB Drive Detection

```python
from pqcdualusb import UsbDriveDetector

# Detect removable USB drives
drives = UsbDriveDetector.get_removable_drives()

for drive in drives:
    print(f"Drive: {drive['mount_point']}")
    print(f"  Size: {drive['size_gb']:.2f} GB")
    print(f"  Free: {drive['free_gb']:.2f} GB")
    print(f"  Type: {drive['fs_type']}")
```

#### 6. Backend Detection and Fallback

```python
from pqcdualusb import PostQuantumCrypto, PqcBackend

# Strict mode: Require quantum-safe backend
try:
    pqc_strict = PostQuantumCrypto(allow_fallback=False)
    print("✅ Quantum-safe backend available!")
    print(f"Using: {pqc_strict.backend}")
except RuntimeError as e:
    print(f"❌ No PQC backend available: {e}")
    print("Tip: Install liboqs-python or use WSL2")

# Permissive mode: Allow classical fallback
pqc_permissive = PostQuantumCrypto(allow_fallback=True)

if pqc_permissive.backend == PqcBackend.OQS:
    print("✅ Using REAL quantum-safe OQS backend")
elif pqc_permissive.backend == PqcBackend.CLASSICAL:
    print("⚠️  Using classical RSA-4096 fallback (secure for now)")
```

## 🔧 Integration Patterns

### Pattern 1: Application with Quantum-Safe Storage

```python
from pqcdualusb import PostQuantumCrypto, HybridCrypto
import json

class SecureDataStore:
    def __init__(self):
        self.crypto = HybridCrypto()
        
    def save_secure(self, data: dict, password: str, filepath: str):
        """Save data with quantum-safe encryption."""
        json_data = json.dumps(data).encode()
        encrypted, metadata = self.crypto.encrypt_file(json_data, password)
        
        # Save encrypted data and metadata
        with open(filepath, 'wb') as f:
            f.write(encrypted)
        with open(f"{filepath}.meta", 'w') as f:
            json.dump(metadata, f)
            
    def load_secure(self, password: str, filepath: str) -> dict:
        """Load data with quantum-safe decryption."""
        with open(filepath, 'rb') as f:
            encrypted = f.read()
        with open(f"{filepath}.meta", 'r') as f:
            metadata = json.load(f)
            
        decrypted = self.crypto.decrypt_file(encrypted, password, metadata)
        return json.loads(decrypted)

# Usage
store = SecureDataStore()
store.save_secure({"secret": "value"}, "password123", "data.enc")
data = store.load_secure("password123", "data.enc")
```

### Pattern 2: API with Quantum-Safe Signatures

```python
from pqcdualusb import PostQuantumCrypto
import hashlib

class SecureAPI:
    def __init__(self):
        self.pqc = PostQuantumCrypto(allow_fallback=True)
        self.sig_secret, self.sig_public = self.pqc.generate_sig_keypair()
        
    def sign_request(self, request_data: bytes) -> tuple[bytes, bytes]:
        """Sign API request with quantum-safe signature."""
        # Hash the request
        request_hash = hashlib.sha3_256(request_data).digest()
        
        # Sign with Dilithium3 (quantum-safe)
        signature = self.pqc.sign(request_hash, self.sig_secret)
        
        return request_data, signature
        
    def verify_request(self, request_data: bytes, signature: bytes) -> bool:
        """Verify API request signature."""
        request_hash = hashlib.sha3_256(request_data).digest()
        return self.pqc.verify(request_hash, signature, self.sig_public)

# Usage
api = SecureAPI()
data, sig = api.sign_request(b"GET /api/resource")
is_valid = api.verify_request(data, sig)
```

### Pattern 3: Backup Manager Integration

```python
from pqcdualusb import BackupManager, UsbDriveDetector, SecurityConfig

class MyBackupApp:
    def __init__(self):
        self.backup_mgr = BackupManager()
        
    def perform_backup(self, source_dir: str):
        """Perform quantum-safe backup to USB drives."""
        # Find USB drives
        drives = UsbDriveDetector.get_removable_drives()
        
        if len(drives) < 2:
            raise ValueError("Need at least 2 USB drives for dual backup")
            
        # Perform backup with quantum-safe encryption
        destinations = [d['mount_point'] for d in drives[:2]]
        self.backup_mgr.create_backup(source_dir, destinations)
        
        print("✅ Quantum-safe backup complete!")

# Usage
app = MyBackupApp()
app.perform_backup("/path/to/important/data")
```

## 🛡️ Security Considerations

### Backend Selection Priority

The library automatically selects the best available backend:

1. **C++ (cpp_pqc)** - Fastest, requires compiled extension
2. **Rust (rust_pqc)** - Native speed, requires Rust toolchain
3. **OQS (liboqs-python)** - Pure Python, requires liboqs system library ✅ **WORKING**
4. **Classical (cryptography)** - RSA-4096 fallback, always available

### When to Use Quantum-Safe vs Classical

✅ **Use Quantum-Safe (PqcBackend.OQS) when:**
- Data must remain secure for 10+ years
- Protecting against "harvest now, decrypt later" attacks
- Compliance requires quantum resistance
- You have WSL2/Linux environment with liboqs installed

✅ **Classical fallback (RSA-4096) is fine when:**
- Data lifetime < 10 years  
- Running on Windows without WSL2 (for convenience)
- Quantum computers don't yet exist (expected ~2035-2040)
- Performance is critical

### Key Size Comparison

```python
from pqcdualusb import PostQuantumCrypto, PqcBackend

# Quantum-safe (OQS backend)
pqc_oqs = PostQuantumCrypto(allow_fallback=True)  # Will use OQS if available

if pqc_oqs.backend == PqcBackend.OQS:
    sk, pk = pqc_oqs.generate_kem_keypair()
    print(f"Kyber1024 public key: {len(pk)} bytes")  # 1,568 bytes
    
    sig_sk, sig_pk = pqc_oqs.generate_sig_keypair()
    print(f"Dilithium3 public key: {len(sig_pk)} bytes")  # 1,952 bytes

# Classical fallback
pqc_classical = PostQuantumCrypto(allow_fallback=True)
if pqc_classical.backend == PqcBackend.CLASSICAL:
    sk, pk = pqc_classical.generate_kem_keypair()
    print(f"RSA-4096 public key: {len(pk)} bytes")  # ~800 bytes
```

## 🧪 Testing Your Integration

```python
import unittest
from pqcdualusb import PostQuantumCrypto, PqcBackend

class TestMyIntegration(unittest.TestCase):
    def setUp(self):
        self.pqc = PostQuantumCrypto(allow_fallback=True)
        
    def test_backend_available(self):
        """Ensure some backend is available."""
        self.assertIsNotNone(self.pqc.backend)
        
    def test_key_generation(self):
        """Test KEM keypair generation."""
        sk, pk = self.pqc.generate_kem_keypair()
        self.assertIsNotNone(sk)
        self.assertIsNotNone(pk)
        self.assertGreater(len(pk), 0)
        
    def test_encapsulation_decapsulation(self):
        """Test KEM encapsulation/decapsulation."""
        sk, pk = self.pqc.generate_kem_keypair()
        ct, ss1 = self.pqc.kem_encapsulate(pk)
        ss2 = self.pqc.kem_decapsulate(sk, ct)
        self.assertEqual(ss1, ss2)
        
    def test_sign_verify(self):
        """Test signature creation and verification."""
        sk, pk = self.pqc.generate_sig_keypair()
        msg = b"Test message"
        sig = self.pqc.sign(msg, sk)
        self.assertTrue(self.pqc.verify(msg, sig, pk))

if __name__ == '__main__':
    unittest.main()
```

## 📊 Performance Characteristics

### Operation Timings (Approximate)

| Operation | OQS Backend | Classical |
|-----------|-------------|-----------|
| KEM Keygen | 2-3 ms | 1-2 ms |
| Encapsulate | 2-3 ms | 1-2 ms |
| Decapsulate | 3-5 ms | 1-2 ms |
| Sign | 3-5 ms | 2-3 ms |
| Verify | 2-3 ms | 1-2 ms |

### Memory Usage

| Algorithm | Public Key | Secret Key | Ciphertext/Sig |
|-----------|-----------|------------|----------------|
| Kyber1024 | 1,568 B | 3,168 B | 1,568 B |
| Dilithium3 | 1,952 B | 4,032 B | ~3,309 B |
| RSA-4096 | ~800 B | ~3,272 B | 512 B |

## 🐛 Troubleshooting

### "No post-quantum library available"

```python
# Check what backends are available
from pqcdualusb.crypto import get_available_backends

backends = get_available_backends()
print("Available backends:", backends)

# If empty and you want quantum-safe:
# 1. On Windows: Use WSL2
# 2. On Linux: Install liboqs (see Installation section)
# 3. Or use allow_fallback=True for classical crypto
```

### Import Errors

```bash
# Verify installation
python -c "import pqcdualusb; print('✅ Import OK')"

# Check specific modules
python -c "from pqcdualusb import PostQuantumCrypto; print('✅ PQC OK')"
```

### Backend Not Loading

```python
from pqcdualusb import PostQuantumCrypto, PqcBackend

pqc = PostQuantumCrypto(allow_fallback=True)

if pqc.backend == PqcBackend.CLASSICAL:
    print("⚠️  Using classical fallback")
    print("Tip: For quantum-safe crypto:")
    print("  1. Windows: wsl --install, then install liboqs in WSL2")
    print("  2. Linux: sudo apt install build-essential cmake ninja-build")
    print("  3. Build liboqs from source (see FAST_TRACK_REAL_PQC.md)")
```

## 📚 Complete API Reference

See `LIBRARY_README.md` for complete API documentation including:
- All class methods and parameters
- Security configuration options
- Utility functions
- Error handling

## 🔗 Additional Resources

- **Quick Setup Guide**: `FAST_TRACK_REAL_PQC.md` - Get quantum-safe crypto working in 15 minutes
- **Architecture**: `ARCHITECTURE.md` - System design and component interactions
- **Security**: `SECURITY.md` - Threat model and security considerations
- **Contributing**: `CONTRIBUTING.md` - How to contribute to the library

## 🎯 Real-World Example

```python
"""
Example: Password manager using quantum-safe encryption
"""
from pqcdualusb import HybridCrypto, PostQuantumCrypto, PqcBackend
import json
from pathlib import Path

class QuantumSafePasswordManager:
    def __init__(self, storage_path: str):
        self.storage = Path(storage_path)
        self.crypto = HybridCrypto()
        self.pqc = PostQuantumCrypto(allow_fallback=True)
        
        # Display security status
        if self.pqc.backend == PqcBackend.OQS:
            print("🛡️  Quantum-safe encryption active (Kyber1024 + Dilithium3)")
        else:
            print("🔒 Classical encryption active (RSA-4096, secure until ~2035)")
            
    def save_passwords(self, passwords: dict, master_password: str):
        """Save passwords with quantum-safe encryption."""
        data = json.dumps(passwords).encode()
        encrypted, metadata = self.crypto.encrypt_file(data, master_password)
        
        # Save encrypted data
        self.storage.write_bytes(encrypted)
        (self.storage.parent / f"{self.storage.name}.meta").write_text(
            json.dumps(metadata)
        )
        
    def load_passwords(self, master_password: str) -> dict:
        """Load passwords with quantum-safe decryption."""
        encrypted = self.storage.read_bytes()
        metadata = json.loads(
            (self.storage.parent / f"{self.storage.name}.meta").read_text()
        )
        
        decrypted = self.crypto.decrypt_file(encrypted, master_password, metadata)
        return json.loads(decrypted)

# Usage
pm = QuantumSafePasswordManager("passwords.enc")

# Save passwords
passwords = {
    "email": "strong_password_123",
    "bank": "another_strong_password"
}
pm.save_passwords(passwords, "master_password")

# Load passwords
loaded = pm.load_passwords("master_password")
print(f"Email password: {loaded['email']}")
```

---

**Your applications are now quantum-safe! 🛡️🔐**
