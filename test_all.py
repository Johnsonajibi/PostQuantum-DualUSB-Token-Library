"""
Unit tests for the PQC Dual USB Backup library.
"""
import os
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch, MagicMock

# Add project root to path to allow direct imports
import sys
sys.path.insert(0, str(Path(__file__).parent.parent))

from pqcdualusb.storage import init_dual_usb, rotate_token, verify_primary_binding, verify_dual_setup
from pqcdualusb.crypto import verify_backup
from pqcdualusb.backup import restore_from_backup
from pqcdualusb.exceptions import CliUsageError
from pqcdualusb.cli import _ensure_removable_and_distinct
from pqcdualusb.pqc import pq_write_audit_keys, HAS_OQS

# Since we are running tests from a different structure,
# we need to handle potential InvalidTag import from cryptography
try:
    from cryptography.exceptions import InvalidTag
except ImportError:
    # Mock it if cryptography is not installed, though it's a core dep
    class InvalidTag(Exception):
        pass


@patch('pqcdualusb.backup._is_removable_path', return_value=True)
@patch('pqcdualusb.device._is_removable_path', return_value=True)
class DualUSBTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="dualusb_"))
        self.primary = self.tmp / "PRIMARY"; self.primary.mkdir()
        self.backup = self.tmp / "BACKUP"; self.backup.mkdir()
        self.pw = "PW-For-Tests"

    def tearDown(self):
        try:
            shutil.rmtree(self.tmp)
        except Exception:
            pass

    def test_init_verify_restore(self, mock_dev_removable, mock_backup_removable):
        secret = os.urandom(64)
        info = init_dual_usb(secret, self.primary, self.backup, passphrase=self.pw)
        self.assertTrue(self.primary.exists())
        self.assertTrue((self.backup / ".system_backup" / "token.enc.json").exists())
        ok = verify_backup(self.backup / ".system_backup" / "token.enc.json", self.pw, secret)
        self.assertTrue(ok)
        token_path, meta_path = restore_from_backup(self.backup / ".system_backup" / "token.enc.json", self.tmp / "NEW_PRIMARY", self.pw)
        self.assertTrue(token_path.exists())
        self.assertTrue(meta_path.exists())

    def test_wrong_passphrase_raises(self, mock_dev_removable, mock_backup_removable):
        secret = os.urandom(64)
        init_dual_usb(secret, self.primary, self.backup, passphrase=self.pw)
        with self.assertRaises(InvalidTag):
            verify_backup(self.backup / ".system_backup" / "token.enc.json", "WRONG-PW", secret)

    @patch('pqcdualusb.storage._state_load', return_value={'rotation': 0})
    def test_rotate_increments(self, mock_state_load, mock_dev_removable, mock_backup_removable):
        secret = os.urandom(64)
        init_dual_usb(secret, self.primary, self.backup, passphrase=self.pw)
        info2 = rotate_token(os.urandom(64), self.primary, self.backup, self.pw, prev_rotation=0)
        self.assertIn("rotation", info2)
        self.assertEqual(info2["rotation"], 1)

    def test_device_binding_skip_if_unknown(self, mock_dev_removable, mock_backup_removable):
        secret = os.urandom(64)
        init_dual_usb(secret, self.primary, self.backup, passphrase=self.pw)
        toks = sorted(self.primary.glob("token_*.bin"))
        self.assertTrue(toks)
        self.assertTrue(verify_primary_binding(toks[-1], enforce=False))

    def test_verify_dual_setup_rotation_enforced(self, mock_dev_removable, mock_backup_removable):
        secret = os.urandom(64)
        init_dual_usb(secret, self.primary, self.backup, passphrase=self.pw)
        old_backup = self.backup / ".system_backup" / "token.enc.copy.json"
        orig_backup = self.backup / ".system_backup" / "token.enc.json"
        
        # Simulate an old backup
        from pqcdualusb.storage import _atomic_write
        _atomic_write(old_backup, orig_backup.read_bytes())
        
        with patch('pqcdualusb.storage._state_load', return_value={'rotation': 0}):
            rotate_token(os.urandom(64), self.primary, self.backup, self.pw, prev_rotation=0)
        
        toks = sorted(self.primary.glob("token_*.bin"))
        primary_latest = toks[-1]

        with patch('pqcdualusb.storage._state_load', return_value={'rotation': 1}):
            self.assertFalse(verify_dual_setup(primary_latest, old_backup, self.pw, enforce_device=False, enforce_rotation=True))

    @patch('pqcdualusb.cli._is_removable_path')
    @patch('pqcdualusb.device._device_id_for_path')
    def test_cli_guard_raises_not_exit(self, mock_device_id, mock_cli_removable, mock_dev_removable, mock_backup_removable):
        # Test for distinct paths
        mock_cli_removable.return_value = True
        with self.assertRaises(CliUsageError) as ctx:
            _ensure_removable_and_distinct(self.primary, self.primary)
        self.assertEqual(ctx.exception.code, 5)

        # Test for non-removable
        mock_cli_removable.return_value = False
        with self.assertRaises(CliUsageError) as ctx:
            _ensure_removable_and_distinct(self.primary, self.backup)
        self.assertEqual(ctx.exception.code, 7)
        
        # Test for same device UUID
        mock_cli_removable.return_value = True
        mock_device_id.side_effect = [{'uuid': 'SAME-UUID'}, {'uuid': 'SAME-UUID'}]
        with self.assertRaises(CliUsageError) as ctx:
            _ensure_removable_and_distinct(self.primary, self.backup)
        self.assertEqual(ctx.exception.code, 6)


@unittest.skipUnless(HAS_OQS, "python-oqs not available")
@patch('pqcdualusb.backup._is_removable_path', return_value=True)
@patch('pqcdualusb.device._is_removable_path', return_value=True)
class PQAuditTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="dualusb_pq_"))
        self.primary = self.tmp / "PRIMARY"; self.primary.mkdir()
        self.backup = self.tmp / "BACKUP"; self.backup.mkdir()
        self.pw = "PW-For-Tests"

    def tearDown(self):
        try:
            shutil.rmtree(self.tmp)
        except Exception:
            pass

    @patch('pqcdualusb.pqc.pq_generate_keypair', return_value=(b'public_key', b'secret_key'))
    def test_pq_audit_keygen(self, mock_pq_gen, mock_dev_removable, mock_backup_removable):
        info = pq_write_audit_keys(self.primary, self.backup, self.pw, level="Dilithium3")
        self.assertTrue(Path(info["sk"]).exists())
        self.assertTrue(Path(info["pk"]).exists())
        self.assertTrue(Path(info["backup"]).exists())

if __name__ == "__main__":
    unittest.main()
