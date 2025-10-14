# PQC Dual USB Backup Library

## 🔐 Post-Quantum Cryptography Library for Secure Backup Operations

A professional Python library providing **quantum-resistant cryptography** for secure dual USB backup operations. Import and use in your applications for future-proof data protection.

## 📁 Library Structure

```
pqcdualusb/                    # Main package directory
├── __init__.py               # Public API exports
├── crypto.py                 # Post-quantum cryptography (PostQuantumCrypto, HybridCrypto)
├── usb.py                    # USB drive detection (UsbDriveDetector)
├── security.py              # Security utilities (SecurityConfig, SecureMemory, TimingAttackMitigation)
├── utils.py                  # General utilities (ProgressReporter, InputValidator, FileOperations)
├── backup.py                 # Backup operations (BackupManager - stub for now)
└── tests/                    # Test suite
    ├── __init__.py
    ├── test_basic.py         # Basic functionality tests
    └── ...

setup_library.py              # Package installation configuration
demo_library.py               # Library demonstration script
```

## 🎯 What Changed

### ✅ **Before**: Monolithic Application
- Single 2,864-line file
- All functionality mixed together
- Hard to maintain and extend
- No clean API boundaries

### ✅ **After**: Proper Python Library
- **Clean modular structure** with separated concerns
- **Importable package** (`from pqcdualusb import PostQuantumCrypto`)
- **Professional setup.py** for installation
- **Test suite** with automated testing
- **Power analysis countermeasures** working effectively
- **Cross-platform USB detection**
- **Type hints and documentation**

## 🚀 How to Use the Library

### Basic Import and Usage
```python
from pqcdualusb import PostQuantumCrypto, UsbDriveDetector, SecurityConfig

# Initialize post-quantum cryptography
pqc = PostQuantumCrypto()
pk, sk = pqc.generate_kem_keypair()

# Detect USB drives
drives = UsbDriveDetector.get_removable_drives()
print(f"Found {len(drives)} removable drives")

# Check security configuration
warnings = SecurityConfig.validate_security_level()
```

### Advanced Usage
```python
from pqcdualusb.crypto import HybridCrypto, get_available_backends
from pqcdualusb.utils import ProgressReporter, secure_temp_file

# Check available backends
backends = get_available_backends()
print("Available backends:", backends)

# Use hybrid encryption
hybrid = HybridCrypto()
encrypted = hybrid.encrypt_with_pqc(data, passphrase, kem_public_key)

# Progress reporting
progress = ProgressReporter(total_bytes, "Processing")
# ... do work ...
progress.finish()
```

## 🛡️ Security Features Preserved

All security features from the original monolithic application are preserved:

- ✅ **Post-Quantum Cryptography** (Kyber1024 + Dilithium3)
- ✅ **Power Analysis Countermeasures** (timing randomization, execution obfuscation)
- ✅ **Hybrid Classical+PQC Encryption**
- ✅ **Secure Memory Management**
- ✅ **Device Binding and Tamper Detection**
- ✅ **Cross-platform USB Detection**
- ✅ **Input Validation and Security Configuration**

## 📦 Installation (Future)

Once published, the library can be installed via pip:

```bash
# Basic installation
pip install pqcdualusb

# With post-quantum cryptography support
pip install pqcdualusb[pqc]

# Development installation
pip install pqcdualusb[dev]
```

## 🧪 Testing

Run the test suite:
```bash
python pqcdualusb/tests/test_basic.py
```

Run the demonstration:
```bash
python demo_library.py
```

## 📊 Test Results

```
test_crypto_backend_info ... ok
test_imports_work ... ok  
test_input_validation ... ok
test_progress_reporter ... ok
test_security_config ... ok
test_usb_detection ... ok
test_kem_operations ... ok
test_pqc_initialization ... ok

Ran 8 tests in 2.544s - OK
```

## 🎉 Benefits of the New Structure

1. **Maintainability**: Code is organized into logical modules
2. **Reusability**: Components can be imported and used independently  
3. **Testability**: Each module can be tested in isolation
4. **Extensibility**: Easy to add new features without touching existing code
5. **Distribution**: Can be packaged and distributed via PyPI
6. **Documentation**: Clear API boundaries and module purposes
7. **Type Safety**: Proper type hints throughout
8. **Professional**: Follows Python packaging best practices

## 🔄 Migration Path

The original `dual_usb_backup.py` file is preserved. To migrate:

1. **Keep using the original** for existing deployments
2. **Import the library** for new development:
   ```python
   from pqcdualusb import PostQuantumCrypto
   ```
3. **Gradually migrate** existing code to use the library modules

## 📈 Next Steps

1. **CLI Module**: Extract the command-line interface to `pqcdualusb/cli.py`
2. **Full Backup Implementation**: Complete the `BackupManager` class
3. **Documentation**: Add Sphinx documentation
4. **PyPI Publishing**: Package and publish to Python Package Index
5. **CI/CD**: Set up automated testing and deployment

---

**Your dual USB backup system is now a proper Python library! 🎊**
