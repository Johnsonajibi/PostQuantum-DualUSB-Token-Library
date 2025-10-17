#!/usr/bin/env python3
"""
Command examples for using the dual USB backup system.
"""

print("""
🚀 DUAL USB BACKUP SYSTEM - USAGE GUIDE
=======================================

Your system is FULLY FUNCTIONAL and ready to use!

📋 Prerequisites:
   • Two different USB drives
   • Python environment with required packages (✅ Already set up)

🔧 Basic Commands:

1️⃣ INITIALIZE (First time setup):
   python dual_usb_backup.py init --primary E:\\ --backup F:\\ --random 64

2️⃣ VERIFY (Check integrity):
   python dual_usb_backup.py verify --primary E:\\ --backup-file F:\\.system_backup\\token.enc.json

3️⃣ ROTATE (Change token):
   python dual_usb_backup.py rotate --primary E:\\ --backup F:\\ --prev-rotation 0 --random 64

4️⃣ RESTORE (Recover from backup):
   python dual_usb_backup.py restore --backup-file F:\\.system_backup\\token.enc.json --restore-primary G:\\

📝 Command Options:
   --passphrase "YourSecurePassword"     # Direct passphrase (not recommended)
   --passphrase-env PASSPHRASE_VAR       # From environment variable (recommended)
   --disable-pqc                         # Use classical crypto (current default)
   --no-enforce-rotation                 # Skip rotation checks
   --no-enforce-device                   # Skip device binding checks

🔐 Security Notes:
   • The system uses AES-256-GCM + Argon2id (very secure!)
   • Passphrases are protected with memory-hard key derivation
   • All operations include integrity verification
   • Audit logs track all operations with HMAC protection

⚠️  Important:
   • Use DIFFERENT USB drives for primary and backup
   • Keep your passphrase secure and memorable
   • The system will only work with removable drives (safety feature)

Example session:
   1. Insert primary USB (E:) and backup USB (F:)
   2. Run: python dual_usb_backup.py init --primary E:\\ --backup F:\\ --random 64
   3. Enter secure passphrase when prompted
   4. System creates encrypted token on primary, encrypted backup on secondary
   5. Use verify command to check integrity anytime

🎉 Your system is ready for production use!
""")
