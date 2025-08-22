"""
Dual-USB Hardware Backup Module
This library helps you keep your secrets safe by storing your authentication token and encrypted backups on two separate USB drives. That way, if someone gets one drive, they still can't get everything!

What does it do?

How do you use it?

No cloud stuff, just good old hardware security.
"""
import os
import shutil
import platform
import logging

# Setup basic logging
logging.basicConfig(filename='dual_usb_backup.log', level=logging.INFO, format='%(asctime)s %(levelname)s:%(message)s')

def list_removable_drives():
    """
    Look for USB drives plugged into your computer.
    Returns a list of drive paths you can use.
    """
    drives = []
    if platform.system() == "Windows":
        import string
        from ctypes import windll
        bitmask = windll.kernel32.GetLogicalDrives()
        for letter in string.ascii_uppercase:
            if bitmask & 1:
                drive = f"{letter}:\\"
                if os.path.exists(drive):
                    try:
                        drive_type = windll.kernel32.GetDriveTypeW(f"{letter}:\\")
                        if drive_type == 2:  # DRIVE_REMOVABLE
                            drives.append(drive)
                    except Exception:
                        continue
            bitmask >>= 1
    else:
        # Linux/Mac: look for /media, /mnt, /Volumes
        for mount in ["/media", "/mnt", "/Volumes"]:
            if os.path.exists(mount):
                for d in os.listdir(mount):
                    path = os.path.join(mount, d)
                    if os.path.ismount(path):
                        drives.append(path)
    return drives

def select_dual_usb(drives):
    """
    Prompt user to select two USB drives: one for your token, one for your backups.
    Returns (auth_token_drive, vault_backup_drive).
    If you don't have at least two, it lets you know.
    """
    if len(drives) < 2:
        raise RuntimeError("At least two USB drives required for dual-USB backup.")
    print("Available USB drives:")
    for idx, drive in enumerate(drives):
        print(f"{idx + 1}: {drive}")
    try:
        auth_idx = int(input("Select USB drive for authentication token (number): ")) - 1
        vault_idx = int(input("Select USB drive for vault backup (number): ")) - 1
        if auth_idx == vault_idx:
            raise ValueError("You must select two different drives.")
        auth_token_drive = drives[auth_idx]
        vault_backup_drive = drives[vault_idx]
        logging.info(f"User selected {auth_token_drive} for token and {vault_backup_drive} for backup.")
        return auth_token_drive, vault_backup_drive
    except Exception as e:
        logging.error(f"Drive selection error: {e}")
        raise RuntimeError("Invalid drive selection.") from e

def backup_token(auth_token_path, auth_token_drive):
    """
    Copy your authentication token file to the chosen USB drive.
    Returns the path where it was saved.
    """
    dest = os.path.join(auth_token_drive, os.path.basename(auth_token_path))
    try:
        shutil.copy2(auth_token_path, dest)
        logging.info(f"Token backed up to {dest}")
        return dest
    except Exception as e:
        logging.error(f"Failed to backup token: {e}")
        raise

def backup_vault_files(vault_file_paths, vault_backup_drive):
    """
    Copy your encrypted vault files to the backup USB drive.
    Returns a list of where each file was saved.
    """
    secure_backup_folder = os.path.join(vault_backup_drive, ".system_backup")
    try:
        os.makedirs(secure_backup_folder, exist_ok=True)
    except Exception as e:
        logging.error(f"Failed to create backup folder: {e}")
        raise
    backed_up = []
    for vault_file_path in vault_file_paths:
        if os.path.exists(vault_file_path):
            dest = os.path.join(secure_backup_folder, os.path.basename(vault_file_path))
            try:
                shutil.copy2(vault_file_path, dest)
                logging.info(f"Vault file backed up to {dest}")
                backed_up.append(dest)
            except Exception as e:
                logging.error(f"Failed to backup vault file {vault_file_path}: {e}")
        else:
            logging.warning(f"Vault file not found: {vault_file_path}")
    return backed_up

def dual_usb_backup_workflow(auth_token_path, vault_file_paths):
    """
    The easy way: finds your USBs, puts your token on one, and your backups on another.
    Returns a dictionary with all the details.
    """
    drives = list_removable_drives()
    auth_token_drive, vault_backup_drive = select_dual_usb(drives)
    token_path = backup_token(auth_token_path, auth_token_drive)
    backup_paths = backup_vault_files(vault_file_paths, vault_backup_drive)
    return {
        "auth_token_drive": auth_token_drive,
        "vault_backup_drive": vault_backup_drive,
        "token_path": token_path,
        "backup_paths": backup_paths
    }

# Example usage (to be called from main script):
# result = dual_usb_backup_workflow("quantum_token", ["vault_data.cache", "auth_hash.cache", ...])
# print(result)