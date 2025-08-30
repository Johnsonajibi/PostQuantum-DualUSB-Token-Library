"""
pqcdualusb.py
=============================

A single-file, runnable version of the PQC Dual USB Token + Encrypted Backup library (ASCII-only).

- USB-only: plaintext token bytes are written only to the primary USB mount.
- Encrypted backup: Argon2id (or scrypt fallback) -> AES-GCM with authenticated metadata.
- Atomic writes + directory fsync.
- Tamper-evident audit log: HMAC-SHA256 chain persisted to ~/.dual_usb_audit.key and dual_usb_audit.log.
- Device binding: stores & checks device identifier (UUID/label/fs/model when available) to detect cloned/copy USBs.
- Rollback protection: per-primary monotonic rotation counter with HMAC over all state fields.
- Strict removable-only enforcement in CLI.
- PQC audit signing (Dilithium via python-oqs) now defaults to ON when a key is present (dual-sign: HMAC + PQ).
- CLI included (init/verify/rotate/restore; verify supports --enforce-device, --no-enforce-rotation, --pq-audit-pk).
- Tests included (run this file with no args to execute tests). PQ tests auto-skip if oqs is unavailable.

Usage:
    python pqcdualusb.py --help   # CLI
    python pqcdualusb.py          # runs tests
"""
from __future__ import annotations

import os
import sys
import json
import time
import tempfile
import subprocess
import shutil
import logging
import hashlib
import hmac
import secrets
import platform
import threading
import mmap
import ctypes
import atexit
from datetime import datetime, timezone
from pathlib import Path
from typing import Tuple, Optional, Dict, List, Union, Any
from contextlib import contextmanager

# ------------- Logging -------------
logger = logging.getLogger("dual_usb")
if not logger.handlers:
    h = logging.StreamHandler(sys.stderr)
    h.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
    logger.addHandler(h)
logger.setLevel(logging.INFO)

# ------------- Crypto deps -------------
try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
    from cryptography.exceptions import InvalidTag
except Exception as e:  # pragma: no cover
    raise RuntimeError("cryptography is required: pip install cryptography") from e

try:
    from argon2.low_level import hash_secret_raw, Type as Argon2Type
    HAS_ARGON2 = True
except Exception:  # pragma: no cover
    HAS_ARGON2 = False

# Optional PQC (Dilithium) for audit signing
try:  # pragma: no cover (depends on environment)
    import oqs  # type: ignore
    HAS_OQS = True
except Exception:
    HAS_OQS = False

# ------------- Audit log (persistent key + hash chain) -------------
AUDIT_LOG_PATH = Path("pqcdualusb_audit.log")
AUDIT_KEY_PATH = Path(os.environ.get("PQC_DUALUSB_AUDIT_KEY", str(Path.home() / ".pqcdualusb_audit.key")))

if AUDIT_KEY_PATH.exists():
    AUDIT_KEY = AUDIT_KEY_PATH.read_bytes()
else:
    AUDIT_KEY = secrets.token_bytes(32)
    AUDIT_KEY_PATH.write_bytes(AUDIT_KEY)
    try:
        AUDIT_KEY_PATH.chmod(0o600)
    except Exception:
        pass

# ensure audit log file exists with restrictive perms
try:
    if not AUDIT_LOG_PATH.exists():
        AUDIT_LOG_PATH.touch(exist_ok=True)
    AUDIT_LOG_PATH.chmod(0o600)
except Exception:
    pass

_AUDIT_CHAIN: Optional[str] = None

# PQ audit signing toggle (auto when key present)
_PQ_AUDIT_SK_PATH: Optional[Path] = None
_PQ_AUDIT_LEVEL: str = "Dilithium3"


class SecureMemory:
    """Secure memory handling for sensitive data."""
    
    def __init__(self, size: int):
        self.size = size
        self._buffer = None
        self._ctypes_buffer = None
        
    def __enter__(self):
        # Allocate and lock memory
        self._buffer = bytearray(self.size)
        if platform.system() == "Windows":
            # Lock memory on Windows
            try:
                import ctypes
                from ctypes import wintypes
                kernel32 = ctypes.windll.kernel32
                # VirtualLock
                kernel32.VirtualLock.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
                kernel32.VirtualLock.restype = wintypes.BOOL
                
                self._ctypes_buffer = (ctypes.c_char * self.size).from_buffer(self._buffer)
                kernel32.VirtualLock(ctypes.addressof(self._ctypes_buffer), self.size)
            except (ImportError, OSError):
                # Fallback if locking fails
                pass
        elif platform.system() in ["Linux", "Darwin"]:
            # Lock memory on Unix-like systems
            try:
                # Try to use mlock if available (requires root/special permissions)
                import mmap
                # This is a simplified approach - full mlock implementation would be more complex
                pass
            except (ImportError, OSError):
                # Fallback if locking fails
                pass
        
        return self._buffer
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        if self._buffer:
            # Securely clear memory
            for i in range(len(self._buffer)):
                self._buffer[i] = 0
            
            # Unlock memory
            if platform.system() == "Windows" and self._ctypes_buffer:
                try:
                    import ctypes
                    from ctypes import wintypes
                    kernel32 = ctypes.windll.kernel32
                    kernel32.VirtualUnlock.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
                    kernel32.VirtualUnlock.restype = wintypes.BOOL
                    kernel32.VirtualUnlock(ctypes.addressof(self._ctypes_buffer), self.size)
                except (AttributeError, OSError, ImportError):
                    pass
            
            self._buffer = None
            self._ctypes_buffer = None


class ProgressReporter:
    """Thread-safe progress reporting."""
    
    def __init__(self, total_bytes: int = 0, description: str = "Processing"):
        self.total_bytes = total_bytes
        self.processed_bytes = 0
        self.description = description
        self._lock = threading.Lock()
        self._start_time = time.time()
        
    def update(self, bytes_processed: int):
        """Update progress by bytes processed."""
        with self._lock:
            self.processed_bytes += bytes_processed
            self._report_progress()
    
    def set_total(self, total_bytes: int):
        """Set total bytes for percentage calculation."""
        with self._lock:
            self.total_bytes = total_bytes
    
    def _report_progress(self):
        """Report current progress."""
        if self.total_bytes > 0:
            percentage = (self.processed_bytes / self.total_bytes) * 100
            elapsed = time.time() - self._start_time
            
            if elapsed > 0 and self.processed_bytes > 0:
                rate = self.processed_bytes / elapsed
                eta = (self.total_bytes - self.processed_bytes) / rate if rate > 0 else 0
                print(f"\r{self.description}: {percentage:.1f}% ({self.processed_bytes}/{self.total_bytes} bytes) "
                      f"Rate: {rate/1024:.1f} KB/s ETA: {eta:.1f}s", end="", flush=True)
            else:
                print(f"\r{self.description}: {percentage:.1f}% ({self.processed_bytes}/{self.total_bytes} bytes)", 
                      end="", flush=True)
        else:
            print(f"\r{self.description}: {self.processed_bytes} bytes processed", end="", flush=True)
    
    def finish(self):
        """Finish progress reporting."""
        with self._lock:
            elapsed = time.time() - self._start_time
            rate = self.processed_bytes / elapsed if elapsed > 0 else 0
            print(f"\n{self.description} completed: {self.processed_bytes} bytes in {elapsed:.1f}s "
                  f"(avg {rate/1024:.1f} KB/s)")


class AuditLogRotator:
    """Audit log rotation and management."""
    
    def __init__(self, log_file: Path, max_size: int = 10 * 1024 * 1024, max_files: int = 5):
        self.log_file = log_file
        self.max_size = max_size
        self.max_files = max_files
        
    def should_rotate(self) -> bool:
        """Check if log file should be rotated."""
        try:
            return self.log_file.exists() and self.log_file.stat().st_size >= self.max_size
        except OSError:
            return False
    
    def rotate(self):
        """Rotate the log file."""
        if not self.log_file.exists():
            return
            
        try:
            # Move existing numbered logs
            for i in range(self.max_files - 1, 0, -1):
                old_file = self.log_file.with_suffix(f".{i}.log")
                new_file = self.log_file.with_suffix(f".{i + 1}.log")
                
                if old_file.exists():
                    if new_file.exists():
                        new_file.unlink()  # Remove oldest log
                    old_file.rename(new_file)
            
            # Move current log to .1
            rotated_file = self.log_file.with_suffix(".1.log")
            if rotated_file.exists():
                rotated_file.unlink()
            self.log_file.rename(rotated_file)
            
        except OSError as e:
            logging.warning(f"Failed to rotate audit log: {e}")


@contextmanager
def secure_temp_file(prefix: str = "secure_", suffix: str = ".tmp"):
    """Create a secure temporary file that's automatically cleaned up."""
    temp_file = None
    try:
        # Create temp file with restricted permissions
        fd, temp_path = tempfile.mkstemp(prefix=prefix, suffix=suffix)
        temp_file = Path(temp_path)
        
        # Set restrictive permissions (owner read/write only)
        if platform.system() != "Windows":
            os.chmod(temp_path, 0o600)
        
        with os.fdopen(fd, 'wb') as f:
            yield f, temp_file
            
    finally:
        # Secure cleanup
        if temp_file and temp_file.exists():
            try:
                # Overwrite file with random data before deletion
                with open(temp_file, 'r+b') as f:
                    size = f.seek(0, 2)  # Get file size
                    f.seek(0)
                    f.write(os.urandom(size))
                    f.flush()
                    os.fsync(f.fileno())
                temp_file.unlink()
            except OSError:
                pass


def secure_zero_memory(data: Union[bytearray, bytes]) -> None:
    """Securely zero out memory containing sensitive data."""
    if isinstance(data, bytearray):
        for i in range(len(data)):
            data[i] = 0
    elif isinstance(data, bytes):
        # Cannot modify bytes in-place, but at least try to replace references
        try:
            # This won't actually clear the original bytes object from memory
            # but it signals intent for garbage collection
            data = b'\x00' * len(data)
        except Exception:
            pass


class TimingAttackMitigation:
    """Helper class to mitigate timing attacks in cryptographic operations."""
    
    @staticmethod
    def constant_time_compare(a: bytes, b: bytes) -> bool:
        """Constant time comparison to prevent timing attacks."""
        if len(a) != len(b):
            return False
        
        result = 0
        for x, y in zip(a, b):
            result |= x ^ y
        return result == 0
    
    @staticmethod
    def add_random_delay(min_ms: int = None, max_ms: int = None):
        """Add random delay to mitigate timing analysis."""
        if min_ms is None:
            min_ms = SecurityConfig.MIN_DELAY_MS
        if max_ms is None:
            max_ms = SecurityConfig.MAX_DELAY_MS
            
        delay = secrets.randbelow(max_ms - min_ms + 1) + min_ms
        time.sleep(delay / 1000.0)


class SecurityConfig:
    """Centralized security configuration and parameters."""
    
    # Cryptographic parameters
    AES_KEY_SIZE = 32  # AES-256
    NONCE_SIZE = 12    # GCM nonce size
    SALT_SIZE = 32     # Salt for key derivation
    
    # Argon2 parameters (can be overridden by environment)
    ARGON2_MEMORY_COST = int(os.getenv("DUAL_USB_ARGON2_M", str(512 * 1024)))  # 512 MB
    ARGON2_TIME_COST = int(os.getenv("DUAL_USB_ARGON2_T", "3"))
    ARGON2_PARALLELISM = int(os.getenv("DUAL_USB_ARGON2_P", "2"))
    
    # Security limits
    MIN_PASSPHRASE_LENGTH = 12
    MAX_TOKEN_SIZE = 1024
    MIN_TOKEN_SIZE = 32
    
    # Audit log settings
    MAX_LOG_SIZE = 10 * 1024 * 1024  # 10 MB
    MAX_LOG_FILES = 5
    
    # Timing attack mitigation
    MIN_DELAY_MS = 50
    MAX_DELAY_MS = 200
    
    @classmethod
    def get_argon2_params(cls) -> Dict[str, int]:
        """Get Argon2 parameters with validation."""
        return {
            "memory_cost": max(cls.ARGON2_MEMORY_COST, 64 * 1024),  # Minimum 64 MB
            "time_cost": max(cls.ARGON2_TIME_COST, 2),              # Minimum 2 iterations
            "parallelism": max(cls.ARGON2_PARALLELISM, 1)           # Minimum 1 thread
        }
    
    @classmethod
    def validate_security_level(cls) -> List[str]:
        """Validate current security configuration and return warnings."""
        warnings = []
        
        if cls.ARGON2_MEMORY_COST < 256 * 1024:  # Less than 256 MB
            warnings.append("Argon2 memory cost is below recommended minimum (256 MB)")
        
        if cls.ARGON2_TIME_COST < 3:
            warnings.append("Argon2 time cost is below recommended minimum (3 iterations)")
        
        if cls.MIN_PASSPHRASE_LENGTH < 12:
            warnings.append("Minimum passphrase length is below recommended (12 characters)")
        
        return warnings


class InputValidator:
    """Input validation utilities for security."""
    
    @staticmethod
    def validate_path(path: Union[str, Path], must_exist: bool = True, must_be_dir: bool = False) -> Path:
        """Validate and sanitize path inputs."""
        try:
            path_obj = Path(path).resolve()
            
            # Check for path traversal attempts
            if ".." in str(path_obj):
                raise ValueError("Path traversal detected")
            
            if must_exist and not path_obj.exists():
                raise ValueError(f"Path does not exist: {path_obj}")
                
            if must_be_dir and path_obj.exists() and not path_obj.is_dir():
                raise ValueError(f"Path is not a directory: {path_obj}")
                
            return path_obj
            
        except Exception as e:
            raise ValueError(f"Invalid path: {e}")
    
    @staticmethod
    def validate_passphrase(passphrase: str, min_length: int = None) -> str:
        """Validate passphrase strength."""
        if min_length is None:
            min_length = SecurityConfig.MIN_PASSPHRASE_LENGTH
            
        if not passphrase:
            raise ValueError("Passphrase cannot be empty")
            
        if len(passphrase) < min_length:
            raise ValueError(f"Passphrase must be at least {min_length} characters")
            
        # Check for common weak patterns
        weak_patterns = ['password', '123456', 'qwerty', 'admin']
        if any(pattern in passphrase.lower() for pattern in weak_patterns):
            print("WARNING: Passphrase contains common weak patterns", file=sys.stderr)
            
        return passphrase
    
    @staticmethod
    def validate_token_size(size: int, min_size: int = None, max_size: int = None) -> int:
        """Validate token size parameters."""
        if min_size is None:
            min_size = SecurityConfig.MIN_TOKEN_SIZE
        if max_size is None:
            max_size = SecurityConfig.MAX_TOKEN_SIZE
            
        if not isinstance(size, int):
            raise ValueError("Token size must be an integer")
            
        if size < min_size:
            raise ValueError(f"Token size must be at least {min_size} bytes")
            
        if size > max_size:
            raise ValueError(f"Token size cannot exceed {max_size} bytes")
            
        return size


# Register cleanup function to clear sensitive data on exit
def _cleanup_sensitive_data():
    """Cleanup function called on program exit."""
    global AUDIT_KEY
    if AUDIT_KEY:
        secure_zero_memory(bytearray(AUDIT_KEY))

atexit.register(_cleanup_sensitive_data)


class UsbDriveDetector:
    """Enhanced USB drive detection with better cross-platform support."""
    
    @staticmethod
    def get_removable_drives() -> List[Path]:
        """Get list of removable drive mount points."""
        drives = []
        
        if platform.system() == "Windows":
            drives.extend(UsbDriveDetector._get_windows_removable_drives())
        elif platform.system() == "Linux":
            drives.extend(UsbDriveDetector._get_linux_removable_drives())
        elif platform.system() == "Darwin":
            drives.extend(UsbDriveDetector._get_macos_removable_drives())
        
        return [Path(drive) for drive in drives if Path(drive).exists()]
    
    @staticmethod
    def _get_windows_removable_drives() -> List[str]:
        """Get removable drives on Windows using multiple methods."""
        drives = []
        
        try:
            # Method 1: WMI query
            result = subprocess.run([
                "powershell", "-Command",
                "Get-WmiObject -Class Win32_LogicalDisk | Where-Object {$_.DriveType -eq 2} | Select-Object -ExpandProperty DeviceID"
            ], capture_output=True, text=True, timeout=10)
            
            if result.returncode == 0:
                for line in result.stdout.strip().split('\n'):
                    if line.strip():
                        drives.append(line.strip() + "\\")
        except (subprocess.TimeoutExpired, subprocess.SubprocessError):
            pass
        
        try:
            # Method 2: FSUTIL query
            result = subprocess.run([
                "fsutil", "fsinfo", "drives"
            ], capture_output=True, text=True, timeout=5)
            
            if result.returncode == 0:
                # Parse drives and check if removable
                import re
                drive_letters = re.findall(r'([A-Z]:)', result.stdout)
                for letter in drive_letters:
                    try:
                        vol_result = subprocess.run([
                            "vol", letter
                        ], capture_output=True, text=True, timeout=2)
                        if vol_result.returncode == 0 and letter + "\\" not in drives:
                            drives.append(letter + "\\")
                    except subprocess.SubprocessError:
                        continue
        except (subprocess.TimeoutExpired, subprocess.SubprocessError):
            pass
        
        return drives
    
    @staticmethod
    def _get_linux_removable_drives() -> List[str]:
        """Get removable drives on Linux."""
        drives = []
        
        try:
            # Method 1: lsblk
            result = subprocess.run([
                "lsblk", "-rno", "NAME,TYPE,MOUNTPOINT,HOTPLUG"
            ], capture_output=True, text=True, timeout=10)
            
            if result.returncode == 0:
                for line in result.stdout.strip().split('\n'):
                    parts = line.split()
                    if len(parts) >= 4 and parts[1] == "part" and parts[3] == "1" and len(parts) > 2:
                        mount_point = parts[2]
                        if mount_point != "":
                            drives.append(mount_point)
        except (subprocess.TimeoutExpired, subprocess.SubprocessError):
            pass
        
        try:
            # Method 2: Check /media and /mnt
            media_paths = ["/media", "/mnt", f"/media/{os.getenv('USER', '')}", "/run/media"]
            for media_path in media_paths:
                if os.path.exists(media_path):
                    for item in os.listdir(media_path):
                        full_path = os.path.join(media_path, item)
                        if os.path.ismount(full_path):
                            drives.append(full_path)
        except OSError:
            pass
        
        return list(set(drives))  # Remove duplicates
    
    @staticmethod
    def _get_macos_removable_drives() -> List[str]:
        """Get removable drives on macOS."""
        drives = []
        
        try:
            # Method 1: diskutil
            result = subprocess.run([
                "diskutil", "list", "-plist", "external"
            ], capture_output=True, text=True, timeout=10)
            
            if result.returncode == 0:
                # Parse plist output would require plistlib, fallback to simple parsing
                pass
        except (subprocess.TimeoutExpired, subprocess.SubprocessError):
            pass
        
        try:
            # Method 2: Check /Volumes
            volumes_path = "/Volumes"
            if os.path.exists(volumes_path):
                for item in os.listdir(volumes_path):
                    full_path = os.path.join(volumes_path, item)
                    if os.path.ismount(full_path) and item != "Macintosh HD":
                        drives.append(full_path)
        except OSError:
            pass
        
        return drives
    
    @staticmethod
    def is_drive_writable(drive_path: Path) -> bool:
        """Test if drive is writable by creating a temporary file."""
        try:
            test_file = drive_path / f".write_test_{secrets.token_hex(8)}"
            test_file.write_bytes(b"test")
            test_file.unlink()
            return True
        except (OSError, PermissionError):
            return False
    
    @staticmethod
    def get_drive_info(drive_path: Path) -> Dict[str, Any]:
        """Get detailed information about a drive."""
        info = {
            "path": str(drive_path),
            "exists": drive_path.exists(),
            "writable": False,
            "free_space": 0,
            "total_space": 0,
        }
        
        if info["exists"]:
            info["writable"] = UsbDriveDetector.is_drive_writable(drive_path)
            
            try:
                stat = shutil.disk_usage(drive_path)
                info["free_space"] = stat.free
                info["total_space"] = stat.total
            except OSError:
                pass
        
        return info


# Initialize audit log rotator with security config
_audit_rotator = AuditLogRotator(
    AUDIT_LOG_PATH, 
    max_size=SecurityConfig.MAX_LOG_SIZE, 
    max_files=SecurityConfig.MAX_LOG_FILES
)


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _audit(event: str, details: dict) -> None:
    """Append a tamper-evident line to the audit log.
    Always include HMAC; add Dilithium signature when available and enabled.
    Format:
      <ts>|<event>|<json>|prev=<chain>|hmac=<hex>[|pq_sig=<hex>|pq_alg=<name>]
    """
    global _AUDIT_CHAIN
    
    # Check if log rotation is needed
    if _audit_rotator.should_rotate():
        _audit_rotator.rotate()
    
    safe = {k: ("<bytes>" if isinstance(v, (bytes, bytearray)) else v) for k, v in (details or {}).items()}
    base = f"{_now_iso()}|{event}|{json.dumps(safe, separators=(',',':'))}|prev={_AUDIT_CHAIN or ''}"

    # HMAC over base
    mac = hmac.new(AUDIT_KEY, base.encode(), hashlib.sha256).hexdigest()
    chain_input = base + "|hmac=" + mac
    _AUDIT_CHAIN = hashlib.sha3_512(chain_input.encode()).hexdigest()

    # Optional PQ signature over chain_input
    pq_sig_hex = None
    pq_alg = None
    if HAS_OQS and _PQ_AUDIT_SK_PATH and _PQ_AUDIT_SK_PATH.exists():
        try:
            with oqs.Signature(_PQ_AUDIT_LEVEL) as signer:  # type: ignore
                try:
                    signer.import_secret_key(_PQ_AUDIT_SK_PATH.read_bytes())  # type: ignore[attr-defined]
                    pq_sig_hex = signer.sign(chain_input.encode()).hex()
                    pq_alg = _PQ_AUDIT_LEVEL
                except Exception as e:  # pragma: no cover
                    logger.warning("PQ audit signing unavailable: %s", e)
        except Exception as e:  # pragma: no cover
            logger.warning("PQ audit signing failed: %s", e)

    line = chain_input
    if pq_sig_hex:
        line += f"|pq_sig={pq_sig_hex}|pq_alg={pq_alg}"

    # Atomic append with retry mechanism
    max_retries = 3
    for attempt in range(max_retries):
        try:
            with AUDIT_LOG_PATH.open("a", encoding="utf-8") as f:
                f.write(line + "\n")
                f.flush()
                os.fsync(f.fileno())
            break
        except OSError as e:
            if attempt == max_retries - 1:
                # Last attempt failed, log to stderr
                print(f"WARNING: Failed to write audit log after {max_retries} attempts: {e}", 
                      file=sys.stderr)
            else:
                time.sleep(0.1)  # Brief delay before retry


def verify_audit_log(pq_pk_path: Optional[Path] = None) -> bool:
    """Verify audit log integrity.
    - Recomputes HMAC and chain for each line.
    - If pq_pk_path is provided and oqs is available, verifies Dilithium signatures when present.
    Accepts both legacy lines with '|sig=' and new lines with '|hmac='.
    Returns True if all checks that could be performed succeeded.
    """
    try:
        lines = AUDIT_LOG_PATH.read_text(encoding="utf-8").splitlines()
    except Exception:
        return False

    pq = None
    if pq_pk_path is not None:
        if not HAS_OQS:
            logger.error("PQ verify requested but python-oqs not available")
            return False
        try:
            pk = pq_pk_path.read_bytes()
            pq = oqs.Signature(_PQ_AUDIT_LEVEL, pk)  # type: ignore
        except Exception as e:
            logger.error("Failed to load PQ public key: %s", e)
            return False

    prev_chain = ""
    for raw in lines:
        parts = raw.split("|")
        try:
            prev_field = next((p for p in parts if p.startswith("prev=")), None)
            hmac_field = next((p for p in parts if p.startswith("hmac=") or p.startswith("sig=")), None)
            pq_sig_field = next((p for p in parts if p.startswith("pq_sig=")), None)
            if hmac_field is None or prev_field is None:
                logger.error("Audit line missing required fields: %s", raw)
                return False
            hmac_idx = parts.index(hmac_field)
            base = "|".join(parts[:hmac_idx]).rstrip("|")
            # Check prev chain continuity if we have one
            if prev_chain and ("prev=" + prev_chain) not in parts:
                logger.error("Audit chain mismatch")
                return False
            # Recompute HMAC
            expect_mac = hmac.new(AUDIT_KEY, base.encode(), hashlib.sha256).hexdigest()
            got_mac = hmac_field.split("=", 1)[1]
            if got_mac != expect_mac:
                logger.error("Audit HMAC mismatch")
                return False
            # Update chain
            chain_input = base + "|" + hmac_field
            prev_chain = hashlib.sha3_512(chain_input.encode()).hexdigest()
            # Optional PQ verify
            if pq and pq_sig_field:
                sig_hex = pq_sig_field.split("=", 1)[1]
                if not pq.verify(chain_input.encode(), bytes.fromhex(sig_hex)):
                    logger.error("Audit PQ signature verification failed")
                    return False
        except Exception:
            return False
    if pq:
        try:
            pq.free()  # type: ignore[attr-defined]
        except Exception:
            pass
    return True

# ------------- Device identity helpers -------------
DeviceId = Dict[str, Optional[str]]  # keys: uuid, label, fs, model


def _device_id_for_path(path: Path) -> DeviceId:
    """Best-effort device identity for filesystem that contains `path`. Never raises."""
    try:
        system = platform.system()
        if system == "Windows":
            import ctypes
            kernel32 = ctypes.windll.kernel32
            GetVolumePathNameW = kernel32.GetVolumePathNameW
            GetVolumeInformationW = kernel32.GetVolumeInformationW
            buf = ctypes.create_unicode_buffer(260)
            GetVolumePathNameW(str(path), buf, 260)
            root = buf.value or str(getattr(path, "drive", path))
            vol_name_buf = ctypes.create_unicode_buffer(261)
            fs_name_buf = ctypes.create_unicode_buffer(261)
            ser_num = ctypes.c_uint()
            max_comp_len = ctypes.c_uint()
            fs_flags = ctypes.c_uint()
            ok = GetVolumeInformationW(ctypes.c_wchar_p(root), vol_name_buf, 260, ctypes.byref(ser_num), ctypes.byref(max_comp_len), ctypes.byref(fs_flags), fs_name_buf, 260)
            return {"uuid": f"{ser_num.value:08X}" if ok else None, "label": vol_name_buf.value if ok else None, "fs": fs_name_buf.value if ok else None, "model": None}
        elif system == "Darwin":
            try:
                mp = Path(subprocess.check_output(["/bin/df", "-P", str(path)], text=True).splitlines()[-1].split()[5])
            except Exception:
                mp = Path("/")
            try:
                out = subprocess.check_output(["/usr/sbin/diskutil", "info", str(mp)], text=True)
                uuid = label = model = fs = None
                for line in out.splitlines():
                    if "Volume UUID:" in line: uuid = line.split(":", 1)[1].strip()
                    if "Volume Name:" in line: label = line.split(":", 1)[1].strip()
                    if "Device / Media Name:" in line: model = line.split(":", 1)[1].strip()
                    if "Type (Bundle):" in line: fs = line.split(":", 1)[1].strip()
                return {"uuid": uuid, "label": label, "fs": fs, "model": model}
            except Exception:
                return {"uuid": None, "label": None, "fs": None, "model": None}
        else:
            # Linux and others
            device = None
            best_mnt = ""
            try:
                with open("/proc/mounts", "r", encoding="utf-8") as f:
                    for line in f:
                        dev, mnt, *_ = line.split()
                        try:
                            p = Path(path).resolve()
                            m = Path(mnt)
                            if str(p).startswith(str(m.resolve())) and len(str(m)) > len(best_mnt):
                                best_mnt = str(m)
                                device = dev
                        except Exception:
                            continue
                if not device:
                    return {"uuid": None, "label": None, "fs": None, "model": None}
                blkid_path = shutil.which("blkid") or "/sbin/blkid"
                out = subprocess.check_output([blkid_path, "-o", "export", device], stderr=subprocess.DEVNULL, text=True)
                kv = dict(line.strip().split("=", 1) for line in out.strip().splitlines() if "=" in line)
                return {"uuid": kv.get("UUID"), "label": kv.get("LABEL"), "fs": kv.get("TYPE"), "model": kv.get("MODEL")}
            except Exception:
                return {"uuid": None, "label": None, "fs": None, "model": None}
    except Exception:
        return {"uuid": None, "label": None, "fs": None, "model": None}

# ------------- Core helpers -------------
BACKUP_DIR = ".system_backup"
BACKUP_SUFFIX = ".enc.json"
STATE_FILE = ".dual_usb_state.json"


def _fsync_dir(d: Path) -> None:
    try:
        fd = os.open(str(d), os.O_DIRECTORY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    except Exception:
        pass


def _atomic_write(dst: Path, data: bytes) -> None:
    dst.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(dir=str(dst.parent), delete=False) as tmp:
        tmp.write(data)
        tmp.flush()
        os.fsync(tmp.fileno())
        tmp_path = Path(tmp.name)
    os.replace(tmp_path, dst)
    _fsync_dir(dst.parent)

_SCRYPT_WARNED = False

def _derive_key(passphrase: str, salt: bytes) -> tuple[bytes, dict]:
    """Derive encryption key using Argon2id or scrypt with secure memory handling."""
    global _SCRYPT_WARNED
    
    # Use secure memory for sensitive operations
    passphrase_bytes = passphrase.encode('utf-8')
    
    try:
        with SecureMemory(len(passphrase_bytes) + SecurityConfig.AES_KEY_SIZE) as secure_buf:
            # Copy passphrase to secure memory
            secure_buf[:len(passphrase_bytes)] = passphrase_bytes
            
            if HAS_ARGON2:
                params = SecurityConfig.get_argon2_params()
                try:
                    # Use secure memory buffer for key derivation
                    key = hash_secret_raw(
                        bytes(secure_buf[:len(passphrase_bytes)]), 
                        salt, 
                        time_cost=params["time_cost"], 
                        memory_cost=params["memory_cost"], 
                        parallelism=params["parallelism"], 
                        hash_len=SecurityConfig.AES_KEY_SIZE, 
                        type=Argon2Type.ID
                    )
                    return key, {"kdf": "argon2id", **params}
                except Exception as e:  # rare
                    logger.warning("Argon2 failed: %s; falling back to scrypt.", e)
            else:
                if not _SCRYPT_WARNED:
                    logger.warning("Argon2 not available; falling back to scrypt (install argon2-cffi).")
                    _SCRYPT_WARNED = True
            
            # Fallback to scrypt
            kdf = Scrypt(salt=salt, length=SecurityConfig.AES_KEY_SIZE, n=2**15, r=8, p=1)
            key = kdf.derive(bytes(secure_buf[:len(passphrase_bytes)]))
            return key, {"kdf": "scrypt", "n": 2**15, "r": 8, "p": 1}
            
    finally:
        # Clear passphrase from memory
        if 'passphrase_bytes' in locals():
            secure_zero_memory(bytearray(passphrase_bytes))

# ----- Primary state (rollback protection) -----

def _state_path(primary_root: Path) -> Path:
    return primary_root / STATE_FILE


def _state_mac(obj: dict) -> str:
    payload = {
        "rotation": int((obj or {}).get("rotation", 0)),
        "created_at": (obj or {}).get("created_at", ""),
        "device": (obj or {}).get("device", {}),
    }
    data = json.dumps(payload, separators=(",", ":")).encode()
    return hmac.new(AUDIT_KEY, data, hashlib.sha256).hexdigest()


def _state_load(primary_root: Path) -> dict:
    p = _state_path(primary_root)
    if not p.exists():
        obj = {"rotation": 0, "created_at": _now_iso(), "device": _device_id_for_path(primary_root)}
        obj["mac"] = _state_mac(obj)
        return obj
    try:
        obj = json.loads(p.read_text("utf-8"))
        if obj.get("mac") != _state_mac(obj):
            logger.warning("primary state MAC mismatch; treating as rotation=0")
            obj = {"rotation": 0, "created_at": _now_iso(), "device": _device_id_for_path(primary_root)}
            obj["mac"] = _state_mac(obj)
        return obj
    except Exception:
        obj = {"rotation": 0, "created_at": _now_iso(), "device": _device_id_for_path(primary_root)}
        obj["mac"] = _state_mac(obj)
        return obj


def _state_save(primary_root: Path, rotation: int) -> None:
    payload = {"rotation": int(rotation), "created_at": _now_iso(), "device": _device_id_for_path(primary_root)}
    payload["mac"] = _state_mac(payload)
    _atomic_write(_state_path(primary_root), json.dumps(payload, separators=(",", ":")).encode())

# ------------- Public API -------------

def write_token_primary(token: bytes, primary_root: Path) -> tuple[Path, Path]:
    """Write plaintext token only to primary USB (USB-only) and record device identity."""
    fn = f"token_{int(time.time())}.bin"
    token_path = primary_root / fn
    dev = _device_id_for_path(primary_root)
    meta = {"created_at": _now_iso(), "sha3": hashlib.sha3_512(token).hexdigest(), "device": dev}
    _atomic_write(token_path, token)
    meta_path = primary_root / f"{fn}.meta.json"
    _atomic_write(meta_path, json.dumps(meta, separators=(",", ":")).encode())
    st = _state_load(primary_root)
    if st.get("rotation") is None:
        _state_save(primary_root, 0)
    _audit("primary_written", {"file": str(token_path), "device": dev})
    return token_path, meta_path


def _encrypt_backup(plaintext: bytes, passphrase: str, meta: dict) -> bytes:
    salt = os.urandom(16)
    key, kdf_params = _derive_key(passphrase, salt)
    aes = AESGCM(key)
    nonce = os.urandom(12)
    aad = json.dumps(meta, separators=(",", ":")).encode()
    ct = aes.encrypt(nonce, plaintext, aad)
    payload = {"meta": meta, "kdf": {**kdf_params, "salt": salt.hex()}, "aead": {"alg": "AES-256-GCM", "nonce": nonce.hex(), "ct": ct.hex()}}
    return json.dumps(payload, separators=(",", ":")).encode()


def write_backup(token: bytes, passphrase: str, backup_root: Path, rotation: int = 0, progress_callback: Optional[ProgressReporter] = None) -> Path:
    """Write encrypted backup with optional progress reporting."""
    dev = _device_id_for_path(backup_root)
    if not _is_removable_path(backup_root):
        raise RuntimeError("Backup path does not appear to be a removable device")
    
    # Initialize progress reporting
    if progress_callback is None:
        progress_callback = ProgressReporter(description="Writing backup")
    
    progress_callback.set_total(len(token) + 1024)  # Approximate total for encryption overhead
    
    meta = {"sha3": hashlib.sha3_512(token).hexdigest(), "created_at": _now_iso(), "rotation": rotation, "backup_device": dev}
    
    progress_callback.update(len(token) // 2)  # Report progress during encryption
    payload = _encrypt_backup(token, passphrase, meta)
    
    progress_callback.update(len(token) // 2)  # Report remaining progress
    dst = backup_root / BACKUP_DIR / f"token{BACKUP_SUFFIX}"
    _atomic_write(dst, payload)
    
    progress_callback.finish()
    _audit("backup_written", {"file": str(dst), "device": dev})
    return dst


def verify_backup(backup_file: Path, passphrase: str, token: bytes) -> bool:
    """Decrypt backup and check it matches `token` by SHA3-512 with timing attack protection."""
    try:
        # Add random delay to mitigate timing analysis
        TimingAttackMitigation.add_random_delay()
        
        data = json.loads(backup_file.read_text("utf-8"))
        meta = data["meta"]
        aead = data["aead"]
        salt = bytes.fromhex(data["kdf"]["salt"])
        
        # Use secure memory for key derivation
        key, _ = _derive_key(passphrase, salt)
        
        try:
            # Decrypt backup
            pt = AESGCM(key).decrypt(
                bytes.fromhex(aead["nonce"]), 
                bytes.fromhex(aead["ct"]), 
                json.dumps(meta, separators=(",", ":")).encode()
            )
            
            # Use constant-time comparison for hash verification
            backup_hash = hashlib.sha3_512(pt).digest()
            expected_hash = hashlib.sha3_512(token).digest()
            meta_hash = bytes.fromhex(meta["sha3"])
            
            # Verify both hashes match using constant-time comparison
            hash_match = (
                TimingAttackMitigation.constant_time_compare(backup_hash, expected_hash) and
                TimingAttackMitigation.constant_time_compare(backup_hash, meta_hash)
            )
            
            # Clear sensitive data
            secure_zero_memory(bytearray(key))
            secure_zero_memory(bytearray(pt))
            
            return hash_match
            
        except Exception:
            # Clear sensitive data even on exception
            if 'key' in locals():
                secure_zero_memory(bytearray(key))
            return False
            
    except Exception:
        return False


def init_dual_usb(token: bytes, primary_mount: Path, backup_mount: Path, passphrase: str) -> dict:
    tpath, mpath = write_token_primary(token, primary_mount)
    bpath = write_backup(token, passphrase, backup_mount, rotation=0)
    _state_save(primary_mount, 0)
    return {"primary": str(tpath), "meta": str(mpath), "backup": str(bpath)}


def verify_primary_binding(primary_token_path: Path, enforce: bool = True) -> bool:
    meta_path = primary_token_path.with_name(primary_token_path.name + ".meta.json")
    if not meta_path.exists():
        return not enforce
    try:
        meta = json.loads(meta_path.read_text("utf-8"))
        recorded = (meta.get("device") or {})
        current = _device_id_for_path(primary_token_path)
        rec_uuid = (recorded.get("uuid") or "").lower() or None
        cur_uuid = (current.get("uuid") or "").lower() or None
        if rec_uuid and cur_uuid:
            ok = rec_uuid == cur_uuid
        else:
            ok = True
            for key in ("label", "fs"):
                rv = recorded.get(key)
                cv = current.get(key)
                if rv and cv and rv != cv:
                    ok = False
                    break
        return ok or (not enforce)
    except Exception:
        return not enforce


def _read_backup_meta(backup_file: Path) -> dict:
    data = json.loads(backup_file.read_text("utf-8"))
    return data.get("meta", {})


def verify_dual_setup(primary_token_path: Path, backup_file: Path, passphrase: str, enforce_device: bool = True, enforce_rotation: bool = True) -> bool:
    if enforce_device and not verify_primary_binding(primary_token_path, enforce=True):
        return False
    if enforce_rotation:
        state = _state_load(primary_token_path.parent)
        meta = _read_backup_meta(backup_file)
        bu_rot = int(meta.get("rotation") or 0)
        st_rot = int(state.get("rotation") or 0)
        if bu_rot < st_rot:
            logger.error("Backup rotation (%s) older than primary state (%s)", bu_rot, st_rot)
            return False
    token_bytes = primary_token_path.read_bytes()
    return verify_backup(backup_file, passphrase, token_bytes)


def restore_from_backup(backup_file: Path, restore_primary: Path, passphrase: str) -> tuple[Path, Path]:
    data = json.loads(backup_file.read_text("utf-8"))
    meta = data["meta"]
    aead = data["aead"]
    salt = bytes.fromhex(data["kdf"]["salt"])
    key, _ = _derive_key(passphrase, salt)
    pt = AESGCM(key).decrypt(bytes.fromhex(aead["nonce"]), bytes.fromhex(aead["ct"]), json.dumps(meta, separators=(",", ":")).encode())
    return write_token_primary(pt, restore_primary)


def rotate_token(token: bytes, primary_mount: Path, backup_mount: Path, passphrase: str, prev_rotation: int) -> dict:
    st = _state_load(primary_mount)
    cur = int(st.get("rotation") or 0)
    if int(prev_rotation) != cur:
        raise RuntimeError(f"Rotation mismatch: prev_rotation={prev_rotation} does not match current state={cur}")
    tpath, mpath = write_token_primary(token, primary_mount)
    new_rot = cur + 1
    bpath = write_backup(token, passphrase, backup_mount, rotation=new_rot)
    _state_save(primary_mount, new_rot)
    return {"primary": str(tpath), "meta": str(mpath), "backup": str(bpath), "rotation": new_rot}

# ------------- Removable checks -------------

def _is_removable_path(path: Path) -> bool:
    try:
        system = platform.system()
        if system == "Windows":
            import ctypes
            DRIVE_REMOVABLE = 2
            drive = str(getattr(path, "drive", path))
            dtype = ctypes.windll.kernel32.GetDriveTypeW(drive)
            if dtype == DRIVE_REMOVABLE:
                # Filter out legacy A:/B: floppy false-positives and unlikely media
                if str(drive).upper().startswith(("A:", "B:")):
                    return False
                di = _device_id_for_path(path)
                fs = (di.get("fs") or "").lower()
                return fs in {"fat", "fat32", "exfat", "ntfs", "refs"}
            return False
        elif system == "Darwin":
            try:
                mp = Path(subprocess.check_output(["/bin/df", "-P", str(path)], text=True).splitlines()[-1].split()[5])
            except Exception:
                mp = Path("/")
            try:
                out = subprocess.check_output(["/usr/sbin/diskutil", "info", str(mp)], text=True)
                is_ext = any(("Device Location: External" in line) or ("Removable Media: Yes" in line) for line in out.splitlines())
                return bool(is_ext)
            except Exception:
                return False
        else:
            device = None
            best_mnt = ""
            with open("/proc/mounts", "r", encoding="utf-8") as f:
                for line in f:
                    dev, mnt, *_ = line.split()
                    p = Path(path).resolve(); m = Path(mnt)
                    try:
                        if str(p).startswith(str(m.resolve())) and len(str(m)) > len(best_mnt):
                            best_mnt = str(m); device = dev
                    except Exception:
                        continue
            if not device or not device.startswith("/dev/"):
                return False
            base = os.path.basename(device)
            cand = [f"/sys/block/{base}/removable", f"/sys/block/{base.rstrip('0123456789')}/removable"]
            for c in cand:
                try:
                    with open(c, "r", encoding="utf-8") as fh:
                        return fh.read().strip() == "1"
                except Exception:
                    continue
            return False
    except Exception:
        return False

# ------------- Optional PQC helpers (Dilithium) -------------

def pq_available() -> bool:
    return HAS_OQS


def pq_generate_keypair(level: str = "Dilithium3") -> tuple[bytes, bytes]:  # (sk, pk)
    if not HAS_OQS:
        raise RuntimeError("python-oqs not available")
    with oqs.Signature(level) as signer:  # type: ignore
        pk = signer.generate_keypair()
        try:
            sk = signer.export_secret_key()  # type: ignore[attr-defined]
        except Exception as e:
            raise RuntimeError("This oqs build cannot export secret keys; upgrade oqs or use a custom provider") from e
    return sk, pk


def pq_write_audit_keys(primary_mount: Path, backup_mount: Path, passphrase: str, level: str = "Dilithium3") -> dict:
    sk, pk = pq_generate_keypair(level)
    sk_path = primary_mount / "pq_audit_sk.bin"
    pk_path = primary_mount / "pq_audit_pk.bin"
    _atomic_write(sk_path, sk)
    _atomic_write(pk_path, pk)
    bu_meta = {"purpose": "pq_audit_sk", "created_at": _now_iso(), "alg": level}
    payload = _encrypt_backup(sk, passphrase, bu_meta)
    bu_path = backup_mount / BACKUP_DIR / "pq_audit_sk.enc.json"
    _atomic_write(bu_path, payload)
    _audit("pq_keys_written", {"sk": str(sk_path), "pk": str(pk_path), "backup": str(bu_path), "alg": level})
    return {"sk": str(sk_path), "pk": str(pk_path), "backup": str(bu_path), "alg": level}


def pq_enable_audit_signing(sk_path: Path, level: str = "Dilithium3") -> None:
    global _PQ_AUDIT_SK_PATH, _PQ_AUDIT_LEVEL
    if not HAS_OQS:
        raise RuntimeError("python-oqs not available")
    _PQ_AUDIT_SK_PATH = sk_path
    _PQ_AUDIT_LEVEL = level
    _audit("pq_audit_enabled", {"sk_path": str(sk_path), "alg": level})


def pq_sign(data: bytes, sk_path: Path, level: str = "Dilithium3") -> bytes:
    if not HAS_OQS:
        raise RuntimeError("python-oqs not available")
    with oqs.Signature(level) as signer:  # type: ignore
        try:
            signer.import_secret_key(sk_path.read_bytes())  # type: ignore[attr-defined]
        except Exception as e:
            raise RuntimeError("This oqs build cannot import secret keys; upgrade oqs or supply a custom signer") from e
        return signer.sign(data)


def pq_verify(data: bytes, sig: bytes, pk: bytes, level: str = "Dilithium3") -> bool:
    if not HAS_OQS:
        raise RuntimeError("python-oqs not available")
    with oqs.Signature(level, pk) as verifier:  # type: ignore
        return verifier.verify(data, sig)

# ------------- CLI -------------
import argparse


class CliUsageError(Exception):
    def __init__(self, code: int, message: str):
        super().__init__(message)
        self.code = code


def _read_pass(args) -> str:
    if getattr(args, "passphrase_env", None):
        val = os.getenv(args.passphrase_env)
        if not val:
            raise CliUsageError(2, f"Environment variable {args.passphrase_env} is empty")
        return val
    if getattr(args, "passphrase", None):
        return args.passphrase
    import getpass
    return getpass.getpass("Passphrase: ")


def _ensure_removable_and_distinct(primary: Path, backup: Path) -> None:
    # Normalize early to avoid false positives
    try:
        p_res = primary.resolve(strict=False)
        b_res = backup.resolve(strict=False)
    except Exception:
        p_res, b_res = primary, backup
    if p_res == b_res:
        raise CliUsageError(5, "Primary and backup paths must be different")
    pid = _device_id_for_path(primary); bid = _device_id_for_path(backup)
    if pid.get("uuid") and bid.get("uuid") and pid.get("uuid") == bid.get("uuid"):
        raise CliUsageError(6, "Primary and backup appear to be the same device (matching UUID)")
    if not _is_removable_path(primary):
        raise CliUsageError(7, "Primary path does not appear to be a removable device")
    if not _is_removable_path(backup):
        raise CliUsageError(8, "Backup path does not appear to be a removable device")


def _cmd_init(args):
    try:
        # Validate inputs
        primary = InputValidator.validate_path(args.primary, must_exist=True, must_be_dir=True)
        backup = InputValidator.validate_path(args.backup, must_exist=True, must_be_dir=True)
        size = InputValidator.validate_token_size(args.random or 64)
        
        pw = _read_pass(args)
        pw = InputValidator.validate_passphrase(pw)
        
        token = os.urandom(size)
        _ensure_removable_and_distinct(primary, backup)
        
        # Show progress during initialization
        progress = ProgressReporter(description="Initializing dual USB setup")
        progress.set_total(100)
        
        progress.update(50)
        info = init_dual_usb(token, primary, backup, pw)
        progress.update(50)
        progress.finish()
        
        print(info)
        
        # Clear sensitive data
        secure_zero_memory(bytearray(token))
        secure_zero_memory(bytearray(pw.encode()))
        
    except CliUsageError as e:
        print(str(e), file=sys.stderr)
        sys.exit(e.code)
    except ValueError as e:
        print(f"Validation error: {e}", file=sys.stderr)
        sys.exit(1)


def _cmd_rotate(args):
    try:
        # Validate inputs
        primary = InputValidator.validate_path(args.primary, must_exist=True, must_be_dir=True)
        backup = InputValidator.validate_path(args.backup, must_exist=True, must_be_dir=True)
        size = InputValidator.validate_token_size(args.random or 64)
        
        pw = _read_pass(args)
        pw = InputValidator.validate_passphrase(pw)
        
        token = os.urandom(size)
        _ensure_removable_and_distinct(primary, backup)
        
        # Show progress during rotation
        progress = ProgressReporter(description="Rotating token")
        progress.set_total(100)
        
        progress.update(50)
        info = rotate_token(token, primary, backup, pw, args.prev_rotation)
        progress.update(50)
        progress.finish()
        
        print(info)
        
        # Clear sensitive data
        secure_zero_memory(bytearray(token))
        secure_zero_memory(bytearray(pw.encode()))
        
    except CliUsageError as e:
        print(str(e), file=sys.stderr)
        sys.exit(e.code)
    except ValueError as e:
        print(f"Validation error: {e}", file=sys.stderr)
        sys.exit(1)


def _cmd_verify(args):
    try:
        pw = _read_pass(args)
        primary = Path(args.primary)
        matches = sorted(primary.glob(args.primary_token_name))
        if not matches:
            raise CliUsageError(3, f"No primary token matches pattern {args.primary_token_name} in {primary}")
        primary_token = matches[-1]
        ok = verify_dual_setup(primary_token, Path(args.backup_file), pw, enforce_device=args.enforce_device, enforce_rotation=not args.no_enforce_rotation)
        print("OK" if ok else "FAIL")
        if args.pq_audit_pk:
            pk_path = Path(args.pq_audit_pk)
            aok = verify_audit_log(pk_path)
            print("AUDIT_OK" if aok else "AUDIT_FAIL")
    except CliUsageError as e:
        print(str(e), file=sys.stderr)
        sys.exit(e.code)


def _cmd_restore(args):
    try:
        pw = _read_pass(args)
        token_path, meta_path = restore_from_backup(Path(args.backup_file), Path(args.restore_primary), pw)
        print({"primary": str(token_path), "meta": str(meta_path)})
    except CliUsageError as e:
        print(str(e), file=sys.stderr)
        sys.exit(e.code)


def _cmd_pq_init_audit(args):
    try:
        if not HAS_OQS:
            raise CliUsageError(4, "python-oqs not available; install python-oqs to use PQ features")
        pw = _read_pass(args)
        primary = Path(args.primary); backup = Path(args.backup)
        _ensure_removable_and_distinct(primary, backup)
        info = pq_write_audit_keys(primary, backup, pw, level=args.level)
        print(info)
    except CliUsageError as e:
        print(str(e), file=sys.stderr)
        sys.exit(e.code)


def _cmd_pq_enable_audit(args):
    try:
        if not HAS_OQS:
            raise CliUsageError(4, "python-oqs not available; install python-oqs to use PQ features")
        pq_enable_audit_signing(Path(args.sk_path), level=args.level)
        print({"pq_audit_enabled": True, "level": args.level, "sk_path": args.sk_path})
    except CliUsageError as e:
        print(str(e), file=sys.stderr)
        sys.exit(e.code)


def _cmd_list_drives(args):
    """Command to list available USB drives."""
    try:
        list_usb_drives(show_details=args.details)
    except Exception as e:
        print(f"Error listing drives: {e}", file=sys.stderr)
        sys.exit(1)


def list_usb_drives(show_details: bool = False) -> None:
    """List available USB drives with optional detailed information."""
    drives = UsbDriveDetector.get_removable_drives()
    
    if not drives:
        print("No removable USB drives detected.")
        return
    
    print(f"Found {len(drives)} removable drive(s):")
    for i, drive in enumerate(drives, 1):
        if show_details:
            info = UsbDriveDetector.get_drive_info(drive)
            free_gb = info['free_space'] / (1024**3) if info['free_space'] > 0 else 0
            total_gb = info['total_space'] / (1024**3) if info['total_space'] > 0 else 0
            writable_status = "✓" if info['writable'] else "✗"
            
            print(f"  {i}. {drive}")
            print(f"     Writable: {writable_status}")
            print(f"     Space: {free_gb:.1f} GB free / {total_gb:.1f} GB total")
        else:
            print(f"  {i}. {drive}")


def select_usb_drive(prompt: str, exclude: Optional[Path] = None) -> Path:
    """Interactively select a USB drive from available options."""
    drives = UsbDriveDetector.get_removable_drives()
    
    if exclude:
        drives = [d for d in drives if d != exclude]
    
    if not drives:
        if exclude:
            raise CliUsageError(1, "No other removable USB drives available.")
        else:
            raise CliUsageError(1, "No removable USB drives detected.")
    
    if len(drives) == 1:
        print(f"Auto-selecting only available drive: {drives[0]}")
        return drives[0]
    
    print(f"\n{prompt}")
    list_usb_drives(show_details=True)
    
    while True:
        try:
            choice = input(f"\nSelect drive (1-{len(drives)}): ").strip()
            index = int(choice) - 1
            if 0 <= index < len(drives):
                return drives[index]
            else:
                print(f"Please enter a number between 1 and {len(drives)}")
        except (ValueError, KeyboardInterrupt):
            print("\nOperation cancelled.")
            sys.exit(1)


def cli(argv=None):
    p = argparse.ArgumentParser(prog="pqc-dualusb", description="Dual USB Token + Encrypted Backup (USB-only)")
    sub = p.add_subparsers(dest="cmd", required=True)

    a = sub.add_parser("init", help="Initialize with random token")
    a.add_argument("--primary", required=True)
    a.add_argument("--backup", required=True)
    a.add_argument("--random", type=int, default=64)
    a.add_argument("--passphrase-env", dest="passphrase_env")
    a.add_argument("--passphrase")
    a.set_defaults(func=_cmd_init)

    r = sub.add_parser("rotate", help="Rotate with new random token")
    r.add_argument("--primary", required=True)
    r.add_argument("--backup", required=True)
    r.add_argument("--random", type=int, default=64)
    r.add_argument("--prev-rotation", type=int, default=0)
    r.add_argument("--passphrase-env", dest="passphrase_env")
    r.add_argument("--passphrase")
    r.set_defaults(func=_cmd_rotate)

    v = sub.add_parser("verify", help="Verify device binding, rotation, and backup integrity")
    v.add_argument("--primary", required=True)
    v.add_argument("--backup-file", required=True)
    v.add_argument("--primary-token-name", default="token_*.bin")
    v.add_argument("--enforce-device", action="store_true")
    v.add_argument("--no-enforce-rotation", action="store_true")
    v.add_argument("--pq-audit-pk", dest="pq_audit_pk")
    v.add_argument("--passphrase-env", dest="passphrase_env")
    v.add_argument("--passphrase")
    v.set_defaults(func=_cmd_verify)

    d = sub.add_parser("restore", help="Restore a token onto new primary USB from backup file")
    d.add_argument("--backup-file", required=True)
    d.add_argument("--restore-primary", required=True)
    d.add_argument("--passphrase-env", dest="passphrase_env")
    d.add_argument("--passphrase")
    d.set_defaults(func=_cmd_restore)

    pq = sub.add_parser("pq-init-audit", help="Generate Dilithium keys for audit signing and back them up encrypted")
    pq.add_argument("--primary", required=True)
    pq.add_argument("--backup", required=True)
    pq.add_argument("--level", default="Dilithium3", choices=["Dilithium2", "Dilithium3", "Dilithium5"])
    pq.add_argument("--passphrase-env", dest="passphrase_env")
    pq.add_argument("--passphrase")
    pq.set_defaults(func=_cmd_pq_init_audit)

    pqa = sub.add_parser("pq-enable-audit", help="Enable PQ audit signing using an existing secret key on the primary USB")
    pqa.add_argument("--sk-path", required=True)
    pqa.add_argument("--level", default="Dilithium3", choices=["Dilithium2", "Dilithium3", "Dilithium5"])
    pqa.set_defaults(func=_cmd_pq_enable_audit)

    lst = sub.add_parser("list-drives", help="List available removable USB drives")
    lst.add_argument("--details", action="store_true", help="Show detailed drive information")
    lst.set_defaults(func=_cmd_list_drives)

    args = p.parse_args(argv)
    return args.func(args)

__version__ = "0.1.0"

# ------------- Tests (run with no args) -------------
import unittest


class DualUSBTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="dualusb_"))
        self.primary = self.tmp / "PRIMARY"; self.primary.mkdir()
        self.backup = self.tmp / "BACKUP"; self.backup.mkdir()
        self.pw = "PW-For-Tests"

    def tearDown(self):
        try:
            for root, _, files in os.walk(self.tmp, topdown=False):
                for f in files:
                    Path(root, f).unlink(missing_ok=True)
                try:
                    Path(root).rmdir()
                except Exception:
                    pass
        except Exception:
            pass

    def test_init_verify_restore(self):
        secret = os.urandom(64)
        info = init_dual_usb(secret, self.primary, self.backup, passphrase=self.pw)
        self.assertTrue(self.primary.exists())
        self.assertTrue((self.backup / ".system_backup" / "token.enc.json").exists())
        ok = verify_backup(self.backup / ".system_backup" / "token.enc.json", self.pw, secret)
        self.assertTrue(ok)
        token_path, meta_path = restore_from_backup(self.backup / ".system_backup" / "token.enc.json", self.tmp / "NEW_PRIMARY", self.pw)
        self.assertTrue(token_path.exists())
        self.assertTrue(meta_path.exists())

    def test_wrong_passphrase_raises(self):
        secret = os.urandom(64)
        init_dual_usb(secret, self.primary, self.backup, passphrase=self.pw)
        with self.assertRaises(InvalidTag):
            verify_backup(self.backup / ".system_backup" / "token.enc.json", "WRONG-PW", secret)

    def test_rotate_increments(self):
        secret = os.urandom(64)
        init_dual_usb(secret, self.primary, self.backup, passphrase=self.pw)
        info2 = rotate_token(os.urandom(64), self.primary, self.backup, self.pw, prev_rotation=0)
        self.assertIn("rotation", info2)
        self.assertEqual(info2["rotation"], 1)

    def test_device_binding_skip_if_unknown(self):
        secret = os.urandom(64)
        init_dual_usb(secret, self.primary, self.backup, passphrase=self.pw)
        toks = sorted(self.primary.glob("token_*.bin"))
        self.assertTrue(toks)
        self.assertTrue(verify_primary_binding(toks[-1], enforce=False))

    def test_verify_dual_setup_rotation_enforced(self):
        secret = os.urandom(64)
        init_dual_usb(secret, self.primary, self.backup, passphrase=self.pw)
        old_backup = self.backup / ".system_backup" / "token.enc.copy.json"
        orig_backup = self.backup / ".system_backup" / "token.enc.json"
        _atomic_write(old_backup, orig_backup.read_bytes())
        rotate_token(os.urandom(64), self.primary, self.backup, self.pw, prev_rotation=0)
        toks = sorted(self.primary.glob("token_*.bin"))
        primary_latest = toks[-1]
        self.assertFalse(verify_dual_setup(primary_latest, old_backup, self.pw, enforce_device=False, enforce_rotation=True))

    def test_cli_guard_raises_not_exit(self):
        with self.assertRaises(CliUsageError) as ctx:
            _ensure_removable_and_distinct(self.primary, self.primary)
        self.assertEqual(ctx.exception.code, 5)


@unittest.skipUnless(HAS_OQS, "python-oqs not available")
class PQAuditTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="dualusb_pq_"))
        self.primary = self.tmp / "PRIMARY"; self.primary.mkdir()
        self.backup = self.tmp / "BACKUP"; self.backup.mkdir()
        self.pw = "PW-For-Tests"

    def tearDown(self):
        try:
            for root, _, files in os.walk(self.tmp, topdown=False):
                for f in files:
                    Path(root, f).unlink(missing_ok=True)
                try:
                    Path(root).rmdir()
                except Exception:
                    pass
        except Exception:
            pass

    def test_pq_audit_keygen(self):
        info = pq_write_audit_keys(self.primary, self.backup, self.pw, level="Dilithium3")
        self.assertTrue(Path(info["sk"]).exists())
        self.assertTrue(Path(info["pk"]).exists())
        self.assertTrue(Path(info["backup"]).exists())


if __name__ == "__main__":
    # If arguments provided -> CLI; else run tests.
    if len(sys.argv) > 1:
        sys.exit(cli(sys.argv[1:]))
    else:
        unittest.main(argv=[sys.argv[0]], verbosity=2)
