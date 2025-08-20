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
    Pick two USB drives: one for your token, one for your backups.
    Returns (auth_token_drive, vault_backup_drive).
    If you don't have at least two, it lets you know.
    """
    if len(drives) < 2:
        raise RuntimeError("At least two USB drives required for dual-USB backup.")
    # For demo, just pick first two
    return drives[0], drives[1]

def backup_token(auth_token_path, auth_token_drive):
    """
    Copy your authentication token file to the chosen USB drive.
    Returns the path where it was saved.
    """
    dest = os.path.join(auth_token_drive, os.path.basename(auth_token_path))
    shutil.copy2(auth_token_path, dest)
    return dest

def backup_vault_files(vault_file_paths, vault_backup_drive):
    """
    Copy your encrypted vault files to the backup USB drive.
    Returns a list of where each file was saved.
    """
    secure_backup_folder = os.path.join(vault_backup_drive, ".system_backup")
    os.makedirs(secure_backup_folder, exist_ok=True)
    backed_up = []
    for vault_file_path in vault_file_paths:
        if os.path.exists(vault_file_path):
            dest = os.path.join(secure_backup_folder, os.path.basename(vault_file_path))
            shutil.copy2(vault_file_path, dest)
            backed_up.append(dest)
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