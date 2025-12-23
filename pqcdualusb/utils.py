"""
Utility Functions and Helper Classes
====================================

Common utility functions and classes used across the pqcdualusb library.

Components:
- ProgressReporter: Thread-safe progress tracking with ETA calculations
- AuditLogRotator: Log file rotation and management
- File operations: Secure temporary file creation and management
- Input validation: Password strength validation and input sanitization

These utilities provide foundational functionality for the main library components.
"""

import os
import sys
import time
import tempfile
import threading
import shutil
import logging
from pathlib import Path
from typing import Union, Optional, Any, Generator, ContextManager, Callable
from contextlib import contextmanager

# Configure secure logging
logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())


class ProgressReporter:
    """
    Progress tracking for long-running operations.
    
    Provides progress updates and statistics for operations that process data.
    Calculates throughput, ETA, and percentage completion.
    Thread-safe implementation for concurrent operations.
    
    For library usage, set progress_callback to receive updates instead of console output.
    """
    
    def __init__(self, total_bytes: int = 0, description: str = "Processing", 
                 progress_callback: Optional[Callable[[str], None]] = None):
        self.total_bytes = total_bytes
        self.processed_bytes = 0
        self.description = description
        self.start_time = time.time()
        self.last_report_time = 0
        self.lock = threading.Lock()
        self._finished = False
        self.progress_callback = progress_callback
        
        # Print initial status only if callback not provided (CLI mode)
        self._report_progress()
    
    def update(self, bytes_processed: int):
        """Update progress with new bytes processed."""
        with self.lock:
            self.processed_bytes += bytes_processed
            
            # Rate limit progress reports to avoid spam
            current_time = time.time()
            if current_time - self.last_report_time >= 0.1:  # Report max every 100ms
                self._report_progress()
                self.last_report_time = current_time
    
    def set_total(self, total_bytes: int):
        """Update the total bytes expected."""
        with self.lock:
            self.total_bytes = total_bytes
            self._report_progress()
    
    def _report_progress(self):
        """Internal method to report current progress."""
        if self._finished:
            return
        
        if self.total_bytes > 0:
            percentage = min(100, (self.processed_bytes / self.total_bytes) * 100)
            
            # Calculate speed
            elapsed = time.time() - self.start_time
            if elapsed > 0:
                speed = self.processed_bytes / elapsed
                speed_str = self._format_bytes(speed) + "/s"
            else:
                speed = 0
                speed_str = "calculating..."
            
            # Calculate ETA
            if speed > 0 and self.processed_bytes < self.total_bytes:
                remaining_bytes = self.total_bytes - self.processed_bytes
                eta_seconds = remaining_bytes / speed
                eta_str = self._format_time(eta_seconds)
            else:
                eta_str = "unknown"
            
            processed_str = self._format_bytes(self.processed_bytes)
            total_str = self._format_bytes(self.total_bytes)
            
            progress_msg = (f"\r{self.description}: {percentage:5.1f}% ({processed_str}/{total_str}) "
                           f"Speed: {speed_str} ETA: {eta_str}")
            
            if self.progress_callback:
                self.progress_callback(progress_msg)
            else:
                # Only print to console if no callback (CLI mode)
                print(progress_msg, end="", flush=True)
                
            logger.debug(f"Progress: {percentage:.1f}% ({processed_str}/{total_str})")
        else:
            # Indeterminate progress
            processed_str = self._format_bytes(self.processed_bytes)
            elapsed_str = self._format_time(time.time() - self.start_time)
            progress_msg = f"\r{self.description}: {processed_str} processed in {elapsed_str}"
            
            if self.progress_callback:
                self.progress_callback(progress_msg)
            else:
                print(progress_msg, end="", flush=True)
                
            logger.debug(f"Progress: {processed_str} in {elapsed_str}")
    
    def finish(self):
        """Mark progress as finished and print final status."""
        with self.lock:
            if self._finished:
                return
            
            self._finished = True
            elapsed = time.time() - self.start_time
            processed_str = self._format_bytes(self.processed_bytes)
            elapsed_str = self._format_time(elapsed)
            
            if elapsed > 0:
                avg_speed = self.processed_bytes / elapsed
                speed_str = self._format_bytes(avg_speed) + "/s"
                final_msg = (f"\r{self.description}: Complete! {processed_str} in {elapsed_str} "
                           f"(avg {speed_str})                    ")
            else:
                final_msg = f"\r{self.description}: Complete! {processed_str}                    "
            
            if self.progress_callback:
                self.progress_callback(final_msg)
            else:
                print(final_msg)
                
            logger.info(f"Operation complete: {processed_str} in {elapsed_str}")
    
    @staticmethod
    def _format_bytes(bytes_count: float) -> str:
        """Format byte count in human-readable format."""
        if bytes_count == 0:
            return "0 B"
        
        units = ['B', 'KB', 'MB', 'GB', 'TB']
        unit_index = 0
        size = float(bytes_count)
        
        while size >= 1024 and unit_index < len(units) - 1:
            size /= 1024
            unit_index += 1
        
        if unit_index == 0:
            return f"{int(size)} {units[unit_index]}"
        else:
            return f"{size:.1f} {units[unit_index]}"
    
    @staticmethod
    def _format_time(seconds: float) -> str:
        """Format time duration in human-readable format."""
        if seconds < 60:
            return f"{seconds:.1f}s"
        elif seconds < 3600:
            minutes = int(seconds // 60)
            secs = int(seconds % 60)
            return f"{minutes}m {secs}s"
        else:
            hours = int(seconds // 3600)
            minutes = int((seconds % 3600) // 60)
            return f"{hours}h {minutes}m"


class AuditLogRotator:
    """Log file rotation management with size-based rotation."""
    
    def __init__(self, log_file: Path, max_size: int = 10 * 1024 * 1024, max_files: int = 5):
        self.log_file = Path(log_file)
        self.max_size = max_size
        self.max_files = max_files
        self.lock = threading.Lock()
    
    def should_rotate(self) -> bool:
        """Check if log rotation is needed."""
        try:
            if not self.log_file.exists():
                return False
            return self.log_file.stat().st_size >= self.max_size
        except OSError:
            return False
    
    def rotate(self):
        """Perform log rotation."""
        with self.lock:
            if not self.log_file.exists():
                return
            
            try:
                # Shift existing rotated files
                for i in range(self.max_files - 1, 0, -1):
                    old_file = self.log_file.with_suffix(f"{self.log_file.suffix}.{i}")
                    new_file = self.log_file.with_suffix(f"{self.log_file.suffix}.{i + 1}")
                    
                    if old_file.exists():
                        if new_file.exists():
                            new_file.unlink()
                        old_file.rename(new_file)
                
                # Move current log to .1
                rotated_file = self.log_file.with_suffix(f"{self.log_file.suffix}.1")
                if rotated_file.exists():
                    rotated_file.unlink()
                
                self.log_file.rename(rotated_file)
                
                # Clean up old files beyond max_files
                for i in range(self.max_files + 1, self.max_files + 10):
                    old_file = self.log_file.with_suffix(f"{self.log_file.suffix}.{i}")
                    if old_file.exists():
                        old_file.unlink()
                    else:
                        break
                
                logger.info(f"Log rotated: {self.log_file} -> {rotated_file}")
                
            except OSError as e:
                logger.error(f"Log rotation failed: {e}")


@contextmanager
def secure_temp_file(prefix: str = "secure_", suffix: str = ".tmp") -> Generator[Path, None, None]:
    """
    Create a secure temporary file with restricted permissions.
    
    The file is automatically deleted when the context exits.
    
    Args:
        prefix: Filename prefix
        suffix: Filename suffix
        
    Yields:
        Path to the temporary file
    """
    fd = None
    temp_path = None
    
    try:
        # Create temporary file with secure permissions (600)
        fd, temp_name = tempfile.mkstemp(prefix=prefix, suffix=suffix)
        temp_path = Path(temp_name)
        
        # Set restrictive permissions (owner read/write only)
        os.chmod(temp_path, 0o600)
        
        # Close the file descriptor, caller will open as needed
        os.close(fd)
        fd = None
        
        yield temp_path
        
    finally:
        # Clean up
        if fd is not None:
            try:
                os.close(fd)
            except OSError:
                pass
        
        if temp_path and temp_path.exists():
            try:
                temp_path.unlink()
            except OSError:
                pass


@contextmanager
def secure_temp_dir(prefix: str = "secure_") -> Generator[Path, None, None]:
    """
    Create a secure temporary directory with restricted permissions.
    
    The directory and all contents are automatically deleted when the context exits.
    
    Args:
        prefix: Directory name prefix
        
    Yields:
        Path to the temporary directory
    """
    temp_dir = None
    
    try:
        # Create temporary directory
        temp_name = tempfile.mkdtemp(prefix=prefix)
        temp_dir = Path(temp_name)
        
        # Set restrictive permissions (700)
        os.chmod(temp_dir, 0o700)
        
        yield temp_dir
        
    finally:
        # Clean up
        if temp_dir and temp_dir.exists():
            try:
                shutil.rmtree(temp_dir)
            except OSError:
                pass


def cleanup_sensitive_data():
    """
    Perform cleanup of any sensitive data in memory.
    
    This is a best-effort cleanup that should be called at program exit.
    """
    import gc
    
    # Force garbage collection
    for _ in range(3):
        gc.collect()


class FileOperations:
    """Utility class for secure file operations."""
    
    @staticmethod
    def atomic_write(file_path: Path, data: bytes, mode: int = 0o600):
        """
        Atomically write data to a file.
        
        Uses a temporary file and rename to ensure atomic operation.
        
        Args:
            file_path: Target file path
            data: Data to write
            mode: File permissions (default: owner read/write only)
        """
        temp_path = None
        
        try:
            # Create temporary file in same directory
            with secure_temp_file(
                prefix=f".tmp_{file_path.name}_",
                suffix=".tmp"
            ) as temp_path:
                # Write data to temporary file
                temp_path.write_bytes(data)
                
                # Set correct permissions
                os.chmod(temp_path, mode)
                
                # Atomic rename
                temp_path.rename(file_path)
                temp_path = None  # Prevent cleanup
                
        except Exception:
            # Clean up temp file if rename failed
            if temp_path and temp_path.exists():
                try:
                    temp_path.unlink()
                except OSError:
                    pass
            raise
    
    @staticmethod
    def secure_delete(file_path: Path, passes: int = 3):
        """
        Securely delete a file by overwriting with random data.
        
        Args:
            file_path: File to delete
            passes: Number of overwrite passes
        """
        if not file_path.exists():
            return
        
        try:
            file_size = file_path.stat().st_size
            
            # Overwrite with random data
            with file_path.open('r+b') as f:
                for _ in range(passes):
                    f.seek(0)
                    # Write random data in chunks
                    remaining = file_size
                    while remaining > 0:
                        chunk_size = min(8192, remaining)
                        random_data = os.urandom(chunk_size)
                        f.write(random_data)
                        remaining -= chunk_size
                    f.flush()
                    os.fsync(f.fileno())
            
            # Finally delete the file
            file_path.unlink()
            
        except OSError:
            # If secure deletion fails, try regular deletion
            try:
                file_path.unlink()
            except OSError:
                pass


class InputValidator:
    """Enhanced input validation utilities."""
    
    @staticmethod
    def validate_path(path: Union[str, Path], must_exist: bool = True, must_be_dir: bool = False, allowed_base: Union[str, Path, None] = None) -> Path:
        """
        Validate and normalize a file system path with security checks.
        
        Args:
            path: Path to validate
            must_exist: Whether the path must exist
            must_be_dir: Whether the path must be a directory
            allowed_base: Optional base directory to restrict access to (prevents path traversal)
            
        Returns:
            Validated Path object
            
        Raises:
            ValueError: If validation fails or path traversal is detected
        """
        if not path:
            raise ValueError("Path cannot be empty")
        
        # Convert to string for security checks
        path_str = str(path)
        
        # Check for URI schemes (should be rejected)
        if '://' in path_str or path_str.startswith('file:'):
            raise ValueError(f"URI schemes not allowed in file paths: {path_str}")
        
        # Check for UNC paths and network shares
        if path_str.startswith('\\\\') or path_str.startswith('//'):
            raise ValueError(f"Network paths not allowed: {path_str}")
        
        # Check for obvious path traversal attempts
        dangerous_patterns = ['../', '..\\', '/../', '\\..\\', '/..', '\\..', '..']
        if any(pattern in path_str for pattern in dangerous_patterns):
            raise ValueError(f"Path traversal detected in path: {path_str}")
        
        # Check for absolute paths to sensitive system directories
        sensitive_dirs = ['/etc/', '/bin/', '/sbin/', '/usr/bin/', '/usr/sbin/', 
                         'C:\\Windows\\', 'C:\\Program Files\\', '/System/', '/Applications/',
                         '/etc', '/bin', '/sbin', '/usr/bin', '/usr/sbin', 
                         'C:\\Windows', 'C:\\Program Files', '/System', '/Applications']
        path_lower = path_str.lower()
        if any(path_lower.startswith(sensitive.lower()) for sensitive in sensitive_dirs):
            raise ValueError(f"Access to system directory not allowed: {path_str}")
        
        try:
            path_obj = Path(path).resolve()
        except (OSError, ValueError) as e:
            raise ValueError(f"Invalid path: {path_str}: {e}")
        
        # If allowed_base is specified, ensure path is within it
        if allowed_base is not None:
            try:
                allowed_base_resolved = Path(allowed_base).resolve()
                # Check if the resolved path is within the allowed base
                try:
                    path_obj.relative_to(allowed_base_resolved)
                except ValueError:
                    raise ValueError(f"Path outside allowed directory: {path_obj} not in {allowed_base_resolved}")
            except (OSError, ValueError) as e:
                raise ValueError(f"Invalid allowed_base path: {allowed_base}: {e}")
        
        if must_exist and not path_obj.exists():
            raise ValueError(f"Path does not exist: {path_obj}")
        
        if must_be_dir and path_obj.exists() and not path_obj.is_dir():
            raise ValueError(f"Path is not a directory: {path_obj}")
        
        return path_obj
    
    @staticmethod
    def validate_passphrase(passphrase: str, min_length: int = 12) -> str:
        """
        Validate passphrase strength.
        
        Args:
            passphrase: Passphrase to validate
            min_length: Minimum required length
            
        Returns:
            Validated passphrase
            
        Raises:
            ValueError: If validation fails
        """
        if not passphrase:
            raise ValueError("Passphrase cannot be empty")
        
        if len(passphrase) < min_length:
            raise ValueError(f"Passphrase must be at least {min_length} characters")
        
        # Check for common weak patterns
        weak_patterns = ['password', '123456', 'qwerty', 'admin', 'letmein']
        if passphrase.lower() in weak_patterns:
            raise ValueError("Passphrase is too common - use a stronger passphrase")
        
        # Check for repeated characters (more than 50% of the password)
        if len(passphrase) > 0:
            most_frequent_char = max(set(passphrase), key=passphrase.count)
            if passphrase.count(most_frequent_char) > len(passphrase) * 0.5:
                raise ValueError("Passphrase has too many repeated characters")
        
        # Check for overly long passphrases (potential DoS)
        max_reasonable_length = 200
        if len(passphrase) > max_reasonable_length:
            raise ValueError(f"Passphrase too long (max {max_reasonable_length} characters)")
        
        return passphrase
    
    @staticmethod
    def validate_token_size(size: int, min_size: int = 32, max_size: int = 1024) -> int:
        """
        Validate token size.
        
        Args:
            size: Token size in bytes
            min_size: Minimum allowed size
            max_size: Maximum allowed size
            
        Returns:
            Validated size
            
        Raises:
            ValueError: If validation fails
        """
        if size < min_size:
            raise ValueError(f"Token size must be at least {min_size} bytes")
        
        if size > max_size:
            raise ValueError(f"Token size cannot exceed {max_size} bytes")
        
        return size


def get_system_info() -> dict:
    """Get system information for debugging and compatibility."""
    import platform
    
    return {
        "platform": platform.system(),
        "platform_release": platform.release(),
        "platform_version": platform.version(),
        "architecture": platform.architecture(),
        "python_version": platform.python_version(),
        "temp_dir": str(Path(tempfile.gettempdir()))
    }
