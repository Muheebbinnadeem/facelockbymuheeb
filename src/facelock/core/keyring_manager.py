"""
Keyring & KWallet Auto-Unlock Manager for biometric logins.

When logging into LightDM/GDM via Face Lock or Fingerprint (without typing a
Linux password into PAM), PAM_AUTHTOK is empty. If ~/.local/share/keyrings/login.keyring
is encrypted with the account password, GNOME Keyring (and/or KWallet) prompts
"Enter password to unlock your login keyring" right after desktop startup.

This module detects that condition and converts the login keyring to
passwordless auto-unlock (preserving all saved browser/Wi-Fi/app secrets),
and disables KWallet's startup nag on XFCE.
"""

import os
import pwd
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Tuple

from facelock.core.password_engine import verify_system_password


@dataclass
class KeyringStatus:
    gnome_keyring_exists: bool = False
    gnome_keyring_encrypted: bool = False
    kwallet_may_prompt: bool = False
    summary: str = "No startup keyring prompt detected"

    @property
    def needs_fix(self) -> bool:
        return self.gnome_keyring_encrypted or self.kwallet_may_prompt


def _user_home(username: str) -> Path:
    try:
        return Path(pwd.getpwnam(username).pw_dir)
    except KeyError:
        return Path.home()


def _is_binary_encrypted_keyring(keyring_path: Path) -> bool:
    """
    GNOME Keyring stores password-protected keyrings with the binary header
    'GnomeKeyring\\n\\r\\0\\n', whereas passwordless auto-unlock keyrings are
    stored as plain INI text starting with '[keyring]'.
    """
    if not keyring_path.is_file():
        return False
    try:
        header = keyring_path.read_bytes()[:16]
        return header.startswith(b"GnomeKeyring")
    except Exception:
        return False


def get_keyring_status(username: str) -> KeyringStatus:
    home = _user_home(username)
    login_kr = home / ".local" / "share" / "keyrings" / "login.keyring"
    kwalletrc = home / ".config" / "kwalletrc"
    kwallet_file = home / ".local" / "share" / "kwalletd" / "kdewallet.kwl"

    st = KeyringStatus()
    st.gnome_keyring_exists = login_kr.is_file()
    st.gnome_keyring_encrypted = _is_binary_encrypted_keyring(login_kr)

    # Check if KWallet is enabled or could prompt on login
    kwallet_disabled = False
    if kwalletrc.is_file():
        try:
            txt = kwalletrc.read_text(encoding="utf-8", errors="ignore").lower()
            if "enabled=false" in txt:
                kwallet_disabled = True
        except Exception:
            pass

    if not kwallet_disabled and (kwallet_file.is_file() or shutil.which("kwalletd6") or shutil.which("kwalletd5")):
        # Only flag if kwalletrc hasn't disabled it AND a wallet exists
        if kwallet_file.is_file():
            st.kwallet_may_prompt = True

    if st.gnome_keyring_encrypted and st.kwallet_may_prompt:
        st.summary = "Startup Keyring & KWallet prompts active after biometric login"
    elif st.gnome_keyring_encrypted:
        st.summary = "Login Keyring asks for password after Face/Fingerprint startup"
    elif st.kwallet_may_prompt:
        st.summary = "KWallet may ask for password on startup"
    else:
        st.summary = "Auto-unlock active (no startup keyring password prompt)"

    return st


def disable_kwallet_prompt(username: str) -> Tuple[bool, str]:
    """Disable KWallet startup nag on XFCE/Kali while preserving any existing wallet."""
    home = _user_home(username)
    cfg_dir = home / ".config"
    kwalletrc = cfg_dir / "kwalletrc"
    try:
        cfg_dir.mkdir(parents=True, exist_ok=True)
        if kwalletrc.is_file():
            backup = cfg_dir / "kwalletrc.facelock.bak"
            if not backup.is_file():
                shutil.copy2(kwalletrc, backup)
            lines = kwalletrc.read_text(encoding="utf-8", errors="ignore").splitlines()
            out_lines = []
            in_wallet = False
            saw_wallet = False
            saw_enabled = False
            saw_first = False
            for line in lines:
                s = line.strip()
                if s.startswith("["):
                    if in_wallet:
                        if not saw_enabled:
                            out_lines.append("Enabled=false")
                        if not saw_first:
                            out_lines.append("First Use=false")
                    in_wallet = s.lower() == "[wallet]"
                    if in_wallet:
                        saw_wallet = True
                    out_lines.append(line)
                elif in_wallet and s.lower().startswith("enabled="):
                    out_lines.append("Enabled=false")
                    saw_enabled = True
                elif in_wallet and s.lower().startswith("first use="):
                    out_lines.append("First Use=false")
                    saw_first = True
                else:
                    out_lines.append(line)
            if in_wallet:
                if not saw_enabled:
                    out_lines.append("Enabled=false")
                if not saw_first:
                    out_lines.append("First Use=false")
            if not saw_wallet:
                out_lines.extend(["", "[Wallet]", "Enabled=false", "First Use=false"])
            kwalletrc.write_text("\n".join(out_lines) + "\n", encoding="utf-8")
        else:
            kwalletrc.write_text("[Wallet]\nEnabled=false\nFirst Use=false\n", encoding="utf-8")

        try:
            pw = pwd.getpwnam(username)
            os.chown(cfg_dir, pw.pw_uid, pw.pw_gid)
            os.chown(kwalletrc, pw.pw_uid, pw.pw_gid)
        except Exception:
            pass
        return True, "KWallet startup prompt disabled"
    except Exception as exc:
        return False, f"Could not update kwalletrc: {exc}"


def initialize_fresh_keyring_if_missing(username: str) -> Tuple[bool, str]:
    """
    On fresh Kali installations where ~/.local/share/keyrings/login.keyring does not
    exist yet, pre-create a passwordless auto-unlock login keyring and disable KWallet
    nag so the user NEVER sees a startup keyring prompt after biometric login.
    """
    home = _user_home(username)
    kr_dir = home / ".local" / "share" / "keyrings"
    login_kr = kr_dir / "login.keyring"
    default_file = kr_dir / "default"

    disable_kwallet_prompt(username)

    if login_kr.is_file():
        return True, "Existing login.keyring preserved"

    try:
        kr_dir.mkdir(parents=True, exist_ok=True)
        os.chmod(kr_dir, 0o700)
        login_kr.write_text(
            "[keyring]\ndisplay-name=Login\nctime=0\nmtime=0\nlock-on-idle=false\nlock-after=false\n",
            encoding="utf-8",
        )
        os.chmod(login_kr, 0o600)
        default_file.write_text("login", encoding="utf-8")
        os.chmod(default_file, 0o600)

        try:
            pw = pwd.getpwnam(username)
            os.chown(home / ".local", pw.pw_uid, pw.pw_gid)
            os.chown(home / ".local" / "share", pw.pw_uid, pw.pw_gid)
            os.chown(kr_dir, pw.pw_uid, pw.pw_gid)
            os.chown(login_kr, pw.pw_uid, pw.pw_gid)
            os.chown(default_file, pw.pw_uid, pw.pw_gid)
        except Exception:
            pass
        return True, "Initialized passwordless Login keyring"
    except Exception as exc:
        return False, f"Failed to initialize keyring: {exc}"


def enable_auto_unlock_keyring(username: str, password: str) -> Tuple[bool, str]:
    """
    Verify the user's Linux password, then convert GNOME Keyring's 'login'
    collection to passwordless auto-unlock via D-Bus Secret Service API so all
    existing saved passwords stay intact and the startup keyring prompt disappears.
    """
    disable_kwallet_prompt(username)

    home = _user_home(username)
    login_kr = home / ".local" / "share" / "keyrings" / "login.keyring"
    if not login_kr.is_file():
        return initialize_fresh_keyring_if_missing(username)

    if not _is_binary_encrypted_keyring(login_kr):
        return True, "Startup keyring auto-unlock is already enabled!"

    if not password:
        return False, "Enter your Kali password once to unlock and remove the startup keyring prompt."

    ok_pw, pw_msg = verify_system_password(username, password)
    if not ok_pw:
        return False, pw_msg

    # Use GNOME Secret Service D-Bus API inside the user's session
    try:
        import dbus

        bus = dbus.SessionBus()
        obj = bus.get_object("org.freedesktop.secrets", "/org/freedesktop/secrets")
        svc = dbus.Interface(obj, "org.freedesktop.Secret.Service")
        _, session_path = svc.OpenSession("plain", dbus.String("", variant_level=1))

        # Ensure the login collection is unlocked first using the verified password
        login_coll = dbus.ObjectPath("/org/freedesktop/secrets/collection/login")
        old_secret = (
            dbus.ObjectPath(str(session_path)),
            dbus.ByteArray(b""),
            dbus.ByteArray(password.encode("utf-8")),
            dbus.String("text/plain"),
        )
        new_empty_secret = (
            dbus.ObjectPath(str(session_path)),
            dbus.ByteArray(b""),
            dbus.ByteArray(b""),
            dbus.String("text/plain"),
        )

        # Unlock first if locked
        cobj = bus.get_object("org.freedesktop.secrets", str(login_coll))
        cprops = dbus.Interface(cobj, "org.freedesktop.DBus.Properties")
        if bool(cprops.Get("org.freedesktop.Secret.Collection", "Locked")):
            # Try UnlockWithMasterPassword if available
            guilt = dbus.Interface(
                obj, "org.gnome.keyring.InternalUnsupportedGuiltRiddenInterface"
            )
            guilt.UnlockWithMasterPassword(login_coll, old_secret)

        guilt = dbus.Interface(
            obj, "org.gnome.keyring.InternalUnsupportedGuiltRiddenInterface"
        )
        guilt.ChangeWithMasterPassword(login_coll, old_secret, new_empty_secret)

        # Stop running kwalletd if active so it stays silent
        subprocess.run(["pkill", "-u", username, "kwalletd6"], check=False)
        subprocess.run(["pkill", "-u", username, "kwalletd5"], check=False)

        return True, "Startup Keyring Lock disabled! All saved passwords preserved."
    except Exception as exc:
        return False, f"Keyring update failed: {exc}"
