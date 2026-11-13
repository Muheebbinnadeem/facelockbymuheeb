#!/usr/bin/env python3
"""
Session screensaver watcher that automatically re-locks any unlocked Folder Vaults
when the user locks their Kali Linux screen (xfce4-screensaver, light-locker, gnome-screensaver).
"""

import subprocess
import sys
import time

from facelock.config import ConfigManager, detect_active_username
from facelock.core.folder_lock import FolderVaultManager


def is_screen_locked() -> bool:
    commands = [
        ["xfce4-screensaver-command", "--query"],
        ["light-locker-command", "--query"],
        ["gnome-screensaver-command", "--query"],
    ]
    for cmd in commands:
        try:
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=1.5, check=False)
            if res.returncode == 0 and "is active" in (res.stdout or "").lower():
                return True
        except Exception:
            continue
    return False


def main() -> int:
    user = detect_active_username()
    vault_mgr = FolderVaultManager()
    was_locked = False

    while True:
        try:
            cfg = ConfigManager().data
            if cfg.get("security", {}).get("auto_lock_vaults_on_screensaver", True):
                currently_locked = is_screen_locked()
                if currently_locked and not was_locked:
                    vault_mgr.lock_all_unlocked(owner=user)
                was_locked = currently_locked
        except Exception:
            pass
        time.sleep(4.0)


if __name__ == "__main__":
    sys.exit(main())
