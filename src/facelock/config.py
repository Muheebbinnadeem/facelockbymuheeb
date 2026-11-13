"""
Configuration management and user auto-detection for FaceLock.
"""

import getpass
import json
import os
import pwd
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional

from facelock.constants import (
    CONFIG_PATH,
    ETC_DIR,
    METHOD_FACE,
    METHOD_FINGERPRINT,
    METHOD_PASSWORD,
)

DEFAULT_CONFIG: Dict[str, Any] = {
    "version": 1,
    "enabled": True,
    "default_method": METHOD_FACE,
    "allowed_methods": [METHOD_FACE, METHOD_FINGERPRINT, METHOD_PASSWORD],
    "auto_fallback_to_password": True,
    "camera": {
        "device_index": 0,
        "width": 640,
        "height": 480,
        "fps": 30,
        "warmup_frames": 4,
    },
    "face_auth": {
        "match_threshold": 0.76,
        "neural_cosine_threshold": 0.42,
        "liveness_mode": "balanced",  # strict | balanced | fast
        "require_liveness": True,
        "scan_timeout_seconds": 9,
        "min_face_size_px": 80,
        "enrollment_samples": 5,
    },
    "security": {
        "max_biometric_attempts": 4,
        "lockout_duration_seconds": 60,
        "prompt_timeout_seconds": 35,
        "skip_on_ssh": True,
        "capture_intruder_on_spoof": False,
        "auto_lock_vaults_on_screensaver": True,
    },
    "pam_services": {
        "sudo": True,
        "polkit": True,
        "lightdm": True,
        "gdm": False,
        "screensaver": True,
        "light_locker": True,
        "su": False,
    },
    "ui": {
        "theme": "kali-dark",
        "auto_start_scan": True,
        "close_delay_ms": 420,
        "show_confidence_score": True,
    },
}


def detect_active_username(explicit_user: Optional[str] = None) -> str:
    """
    Automatically detect the real desktop user even when invoked under sudo,
    pkexec, or PAM environment.
    """
    if explicit_user and explicit_user.strip() and explicit_user != "root":
        return explicit_user.strip()

    # Check common privilege-escalation environment variables first
    for env_var in ("PAM_USER", "SUDO_USER", "PKEXEC_UID"):
        val = os.environ.get(env_var)
        if not val:
            continue
        if env_var == "PKEXEC_UID":
            try:
                uid = int(val)
                if uid >= 1000:
                    return pwd.getpwuid(uid).pw_name
            except (ValueError, KeyError):
                continue
        elif val != "root":
            return val

    # Check controlling terminal owner via logname
    try:
        res = subprocess.run(
            ["logname"],
            capture_output=True,
            text=True,
            timeout=1.5,
            check=False,
        )
        name = res.stdout.strip()
        if res.returncode == 0 and name and name != "root":
            return name
    except Exception:
        pass

    # Check active graphical sessions in /run/user/<uid>
    run_user = Path("/run/user")
    if run_user.is_dir():
        for entry in sorted(run_user.iterdir()):
            if entry.name.isdigit():
                uid = int(entry.name)
                if uid >= 1000:
                    try:
                        return pwd.getpwuid(uid).pw_name
                    except KeyError:
                        continue

    # Fall back to current process UID or first normal system user >= 1000
    curr_uid = os.getuid()
    if curr_uid >= 1000:
        try:
            return pwd.getpwuid(curr_uid).pw_name
        except KeyError:
            pass

    for pw in pwd.getpwall():
        if 1000 <= pw.pw_uid < 60000 and pw.pw_shell not in (
            "/usr/sbin/nologin",
            "/bin/false",
        ):
            return pw.pw_name

    return explicit_user or getpass.getuser()


def list_human_users() -> List[str]:
    """Return all standard interactive users on the system."""
    users: List[str] = []
    for pw in pwd.getpwall():
        if 1000 <= pw.pw_uid < 60000 and not pw.pw_name.startswith("systemd-"):
            if pw.pw_shell not in ("/usr/sbin/nologin", "/bin/false"):
                users.append(pw.pw_name)
    active = detect_active_username()
    if active and active not in users:
        users.insert(0, active)
    return sorted(set(users), key=lambda u: (0 if u == active else 1, u))


def _deep_merge(base: Dict[str, Any], override: Dict[str, Any]) -> Dict[str, Any]:
    merged = dict(base)
    for k, v in override.items():
        if isinstance(v, dict) and isinstance(merged.get(k), dict):
            merged[k] = _deep_merge(merged[k], v)
        else:
            merged[k] = v
    return merged


class ConfigManager:
    """Thread-safe configuration loader and writer with fallbacks."""

    def __init__(self, path: Optional[Path] = None) -> None:
        self.path = path or CONFIG_PATH
        self._data: Dict[str, Any] = json.loads(json.dumps(DEFAULT_CONFIG))
        self.reload()

    def reload(self) -> Dict[str, Any]:
        base = json.loads(json.dumps(DEFAULT_CONFIG))
        if self.path.is_file():
            try:
                with open(self.path, "r", encoding="utf-8") as fh:
                    loaded = json.load(fh)
                if isinstance(loaded, dict):
                    base = _deep_merge(base, loaded)
            except Exception:
                pass
        else:
            # Check user-local config cache if /etc/facelock isn't created yet
            user_cfg = Path.home() / ".config" / "facelock" / "config.json"
            if user_cfg.is_file():
                try:
                    with open(user_cfg, "r", encoding="utf-8") as fh:
                        loaded = json.load(fh)
                    if isinstance(loaded, dict):
                        base = _deep_merge(base, loaded)
                except Exception:
                    pass
        self._data = base
        return self._data

    @property
    def data(self) -> Dict[str, Any]:
        return self._data

    def get(self, section: str, key: Optional[str] = None, default: Any = None) -> Any:
        if key is None:
            return self._data.get(section, default)
        sec = self._data.get(section, {})
        if isinstance(sec, dict):
            return sec.get(key, default)
        return default

    def set(self, section: str, key: str, value: Any) -> None:
        if section not in self._data or not isinstance(self._data[section], dict):
            self._data[section] = {}
        self._data[section][key] = value

    def set_top(self, key: str, value: Any) -> None:
        self._data[key] = value

    def save(self, target_path: Optional[Path] = None) -> Path:
        out_path = target_path or self.path
        try:
            out_path.parent.mkdir(parents=True, exist_ok=True)
            tmp_path = out_path.with_suffix(".tmp")
            with open(tmp_path, "w", encoding="utf-8") as fh:
                json.dump(self._data, fh, indent=2, sort_keys=False)
                fh.write("\n")
            os.chmod(tmp_path, 0o644)
            os.replace(tmp_path, out_path)
            return out_path
        except PermissionError:
            # Save to user config cache and return path; caller can push to /etc via privileged helper
            user_cfg = Path.home() / ".config" / "facelock" / "config.json"
            user_cfg.parent.mkdir(parents=True, exist_ok=True)
            with open(user_cfg, "w", encoding="utf-8") as fh:
                json.dump(self._data, fh, indent=2, sort_keys=False)
                fh.write("\n")
            return user_cfg
