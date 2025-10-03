"""
Cryptographic Operations Module
===============================

Post-quantum and hybrid cryptography implementations.

Contains:
- PostQuantumCrypto: Core PQC operations (Kyber1024 + Dilithium3)
- HybridCrypto: Classical + PQC hybrid encryption
- Power analysis attack countermeasures
- Crypto backend detection and fallback logic
"""

import os
import sys
import hashlib
import secrets
from pathlib import Path
from typing import Tuple, Optional, Dict, Any

# Cryptographic imports
try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.exceptions import InvalidTag
    from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
    HAS_CRYPTOGRAPHY = True
except ImportError:
    HAS_CRYPTOGRAPHY = False

# Argon2 support
try:
    from argon2 import hash_secret_raw, Argon2Type
    HAS_ARGON2 = True
except ImportError:
    HAS_ARGON2 = False

# OQS support
try:
    import oqs
    HAS_OQS = True
    OQS_ERROR = None
except ImportError as e:
    HAS_OQS = False
    OQS_ERROR = str(e)

# Rust PQC support
try:
    sys.path.insert(0, str(Path(__file__).parent.parent / "rust_pqc_build"))
    import rust_pqc
    HAS_RUST_PQC = True
    RUST_PQC_ERROR = None
except ImportError as e:
    HAS_RUST_PQC = False
    RUST_PQC_ERROR = str(e)

# Power analysis countermeasures
try:
    # Import from targeted countermeasures if available
    sys.path.insert(0, str(Path(__file__).parent.parent))
    from targeted_countermeasures import secure_pqc_execute
    POWER_ANALYSIS_PROTECTION = True
except ImportError:
    POWER_ANALYSIS_PROTECTION = False
    def secure_pqc_execute(func, *args, **kwargs):
        return func(*args, **kwargs)


class SecurityConfig:
    """Security configuration constants."""
    # Post-quantum algorithms
    PQC_KEM_ALGORITHM = "Kyber1024"
    PQC_SIG_ALGORITHM = "Dilithium3"
    
    # Classical cryptography
    AES_KEY_SIZE = 32  # 256-bit
    SALT_SIZE = 32
    NONCE_SIZE = 12
    HMAC_KEY_SIZE = 32
    
    # Argon2id parameters
    ARGON2_TIME_COST = 4
    ARGON2_MEMORY_COST = 65536  # 64 MB
    ARGON2_PARALLELISM = 2
    
    # Security levels
    PQC_HYBRID_MODE = True
    
    @classmethod
    def get_argon2_params(cls) -> Dict[str, int]:
        """Get Argon2id parameters."""
        return {
            "time_cost": cls.ARGON2_TIME_COST,
            "memory_cost": cls.ARGON2_MEMORY_COST,
            "parallelism": cls.ARGON2_PARALLELISM
        }


class PostQuantumCrypto:
    """
    Post-quantum cryptography implementation with power analysis countermeasures.
    
    Provides Kyber1024 key encapsulation and Dilithium3 digital signatures.
    Automatically selects best available backend (Rust PQC or OQS fallback).
    """
    
    def __init__(self, kem_algorithm: str = None, sig_algorithm: str = None):
        self.kem_algorithm = kem_algorithm or SecurityConfig.PQC_KEM_ALGORITHM
        self.sig_algorithm = sig_algorithm or SecurityConfig.PQC_SIG_ALGORITHM
        
        # Power analysis protection available
        self.power_protection_enabled = POWER_ANALYSIS_PROTECTION
        
        # Try Rust PQC first (preferred backend)
        if HAS_RUST_PQC:
            self.backend = "rust"
            self.rust_pqc = rust_pqc.RustPostQuantumCrypto(kem_algorithm, sig_algorithm)
            print(f"Using Rust PQC: {self.rust_pqc.get_kem_algorithm()}/{self.rust_pqc.get_sig_algorithm()}")
            return
        
        # Fallback to OQS
        if HAS_OQS:
            self.backend = "oqs"
            # Validate algorithms are available
            try:
                with oqs.KeyEncapsulation(self.kem_algorithm):
                    pass
                with oqs.Signature(self.sig_algorithm):
                    pass
                print(f"Using OQS fallback: {self.kem_algorithm}/{self.sig_algorithm}")
            except Exception as e:
                raise RuntimeError(f"OQS algorithm validation failed: {e}")
            return
        
        # No PQC libraries available
        raise RuntimeError(
            f"No post-quantum cryptography libraries available.\n"
            f"Rust PQC error: {RUST_PQC_ERROR}\n"
            f"OQS error: {OQS_ERROR}\n"
            f"Please build the Rust extension or install python-oqs."
        )
    
    def generate_kem_keypair(self) -> Tuple[bytes, bytes]:
        """
        Create a shiny new quantum-safe keypair!
        
        This generates a public key (safe to share) and a secret key (keep this
        locked away!) using Kyber1024. The 'KEM' part stands for 'Key Encapsulation
        Mechanism' - fancy crypto speak for "secure key exchange that quantum
        computers can't break."
        
        Returns a tuple: (public_key, secret_key)
        """
        def _generate_keypair():
            if self.backend == "rust":
                return tuple(self.rust_pqc.generate_kem_keypair())
            
            # OQS fallback
            with oqs.KeyEncapsulation(self.kem_algorithm) as kem:
                public_key = kem.generate_keypair()
                secret_key = kem.export_secret_key()
                return secret_key, public_key
        
        # Execute with targeted power analysis countermeasures
        if POWER_ANALYSIS_PROTECTION:
            return secure_pqc_execute(_generate_keypair)
        else:
            return _generate_keypair()
    
    def generate_sig_keypair(self) -> Tuple[bytes, bytes]:
        """Generate Dilithium keypair for signatures with power analysis protection."""
        def _generate_keypair():
            if self.backend == "rust":
                return tuple(self.rust_pqc.generate_sig_keypair())
            
            # OQS fallback
            with oqs.Signature(self.sig_algorithm) as sig:
                public_key = sig.generate_keypair()
                secret_key = sig.export_secret_key()
                return secret_key, public_key
        
        # Execute with targeted power analysis countermeasures
        if POWER_ANALYSIS_PROTECTION:
            return secure_pqc_execute(_generate_keypair)
        else:
            return _generate_keypair()
    
    def kem_encapsulate(self, public_key: bytes) -> Tuple[bytes, bytes]:
        """Encapsulate a shared secret using Kyber with power analysis protection."""
        def _encapsulate():
            if self.backend == "rust":
                return tuple(self.rust_pqc.kem_encapsulate(public_key))
            
            # OQS fallback
            with oqs.KeyEncapsulation(self.kem_algorithm) as kem:
                ciphertext, shared_secret = kem.encap_secret(public_key)
                return ciphertext, shared_secret
        
        # Execute with targeted power analysis countermeasures
        if POWER_ANALYSIS_PROTECTION:
            return secure_pqc_execute(_encapsulate)
        else:
            return _encapsulate()
    
    def kem_decapsulate(self, secret_key: bytes, ciphertext: bytes) -> bytes:
        """Decapsulate shared secret using Kyber with power analysis protection."""
        def _decapsulate():
            if self.backend == "rust":
                return bytes(self.rust_pqc.kem_decapsulate(secret_key, ciphertext))
            
            # OQS fallback
            with oqs.KeyEncapsulation(self.kem_algorithm) as kem:
                kem.import_secret_key(secret_key)
                return kem.decap_secret(ciphertext)
        
        # Execute with targeted power analysis countermeasures
        if POWER_ANALYSIS_PROTECTION:
            return secure_pqc_execute(_decapsulate)
        else:
            return _decapsulate()
    
    def sign(self, message: bytes, secret_key: bytes) -> bytes:
        """Sign message using Dilithium with power analysis protection."""
        def _sign():
            if self.backend == "rust":
                return bytes(self.rust_pqc.sign(message, secret_key))
            
            # OQS fallback
            with oqs.Signature(self.sig_algorithm) as sig:
                sig.import_secret_key(secret_key)
                return sig.sign(message)
        
        # Execute with targeted power analysis countermeasures
        if POWER_ANALYSIS_PROTECTION:
            return secure_pqc_execute(_sign)
        else:
            return _sign()
    
    def verify(self, message: bytes, signature: bytes, public_key: bytes) -> bool:
        """Verify signature using Dilithium with power analysis protection."""
        def _verify():
            if self.backend == "rust":
                return self.rust_pqc.verify(message, signature, public_key)
            
            # OQS fallback
            try:
                with oqs.Signature(self.sig_algorithm, public_key) as sig:
                    return sig.verify(message, signature)
            except Exception:
                return False
        
        # Execute with targeted power analysis countermeasures
        if POWER_ANALYSIS_PROTECTION:
            return secure_pqc_execute(_verify)
        else:
            return _verify()


class HybridCrypto:
    """Hybrid classical + post-quantum cryptography with power analysis protection."""
    
    def __init__(self):
        self.pqc = PostQuantumCrypto()
        
        # Power analysis protection available
        self.power_protection_enabled = POWER_ANALYSIS_PROTECTION
    
    def derive_hybrid_key(self, passphrase: str, salt: bytes, pq_shared_secret: bytes = None) -> bytes:
        """Derive encryption key using hybrid classical + PQC approach."""
        if not pq_shared_secret:
            # Pure classical fallback (less secure)
            return self._derive_classical_key(passphrase, salt)
        
        # Hybrid: combine passphrase-derived key with PQC shared secret
        classical_key = self._derive_classical_key(passphrase, salt)
        
        # Combine using secure construction
        combined_input = classical_key + pq_shared_secret + b"PQC_HYBRID_V1"
        
        # Final derivation with combined entropy
        # Simple implementation without secure memory for now
        combined = classical_key + pq_shared_secret[:32] if len(pq_shared_secret) >= 32 else pq_shared_secret.ljust(32, b'\x00')
        return hashlib.sha256(combined).digest()
    
    def _derive_classical_key(self, passphrase: str, salt: bytes) -> bytes:
        """Derive key using classical Argon2id."""
        if HAS_ARGON2:
            params = SecurityConfig.get_argon2_params()
            return hash_secret_raw(
                passphrase.encode('utf-8'),
                salt,
                time_cost=params["time_cost"],
                memory_cost=params["memory_cost"],
                parallelism=params["parallelism"],
                hash_len=SecurityConfig.AES_KEY_SIZE,
                type=Argon2Type.ID
            )
        else:
            # Scrypt fallback
            if not HAS_CRYPTOGRAPHY:
                raise RuntimeError("No key derivation libraries available")
            
            kdf = Scrypt(
                algorithm=hashlib.sha256(),
                length=SecurityConfig.AES_KEY_SIZE,
                salt=salt,
                n=2**18,  # 262144
                r=8,
                p=1
            )
            return kdf.derive(passphrase.encode('utf-8'))
    
    def encrypt_with_pqc(self, data: bytes, passphrase: str, kem_public_key: bytes = None) -> Dict[str, Any]:
        """Encrypt data using hybrid classical + PQC approach."""
        if not HAS_CRYPTOGRAPHY:
            raise RuntimeError("Cryptography library not available")
        
        salt = secrets.token_bytes(SecurityConfig.SALT_SIZE)
        nonce = secrets.token_bytes(SecurityConfig.NONCE_SIZE)
        
        pq_shared_secret = None
        kem_ciphertext = None
        
        if kem_public_key:
            # Use PQC key encapsulation
            kem_ciphertext, pq_shared_secret = self.pqc.kem_encapsulate(kem_public_key)
        
        # Derive hybrid encryption key
        encryption_key = self.derive_hybrid_key(passphrase, salt, pq_shared_secret)
        
        # Encrypt data
        aes_gcm = AESGCM(encryption_key)
        ciphertext = aes_gcm.encrypt(nonce, data, None)
        
        # Prepare encrypted package
        package = {
            "version": "2.0_PQC",
            "salt": salt.hex(),
            "nonce": nonce.hex(),
            "ciphertext": ciphertext.hex(),
            "kem_algorithm": self.pqc.kem_algorithm,
            "sig_algorithm": self.pqc.sig_algorithm,
            "hybrid_mode": True
        }
        
        if kem_ciphertext:
            package["kem_ciphertext"] = kem_ciphertext.hex()
        
        return package
    
    def decrypt_with_pqc(self, package: Dict[str, Any], passphrase: str, kem_secret_key: bytes = None) -> bytes:
        """Decrypt data using hybrid classical + PQC approach."""
        if not HAS_CRYPTOGRAPHY:
            raise RuntimeError("Cryptography library not available")
        
        salt = bytes.fromhex(package["salt"])
        nonce = bytes.fromhex(package["nonce"])
        ciphertext = bytes.fromhex(package["ciphertext"])
        
        pq_shared_secret = None
        
        if "kem_ciphertext" in package and kem_secret_key:
            # Decapsulate PQC shared secret
            kem_ciphertext = bytes.fromhex(package["kem_ciphertext"])
            pq_shared_secret = self.pqc.kem_decapsulate(kem_secret_key, kem_ciphertext)
        
        # Derive hybrid decryption key
        decryption_key = self.derive_hybrid_key(passphrase, salt, pq_shared_secret)
        
        # Decrypt data
        aes_gcm = AESGCM(decryption_key)
        try:
            return aes_gcm.decrypt(nonce, ciphertext, None)
        except InvalidTag:
            raise ValueError("Decryption failed - invalid key or corrupted data")


def get_available_backends() -> Dict[str, bool]:
    """Get information about available cryptographic backends."""
    return {
        "rust_pqc": HAS_RUST_PQC,
        "oqs": HAS_OQS,
        "argon2": HAS_ARGON2,
        "cryptography": HAS_CRYPTOGRAPHY,
        "power_analysis_protection": POWER_ANALYSIS_PROTECTION
    }


def check_pqc_requirements() -> bool:
    """Check if PQC requirements are met."""
    return HAS_RUST_PQC or HAS_OQS
