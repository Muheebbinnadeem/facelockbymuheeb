"""
Automatic PAM backend configurator for Kali Linux / Debian.

Safely backs up /etc/pam.d/* files and manages non-locking PAM authentication
rules so FaceLock works across sudo, LightDM, GDM, Polkit (pkexec), lock screens,
and su without risking system lockout.
"""

import datetime
import os
import shutil
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from facelock.constants import (
    BACKUP_DIR,
    INSTALL_LIB_DIR,
    PAM_D_DIR,
    PAM_MARKER_TAG,
    PAM_MODULE_DIRS,
    PAM_TARGETS,
)


def find_pam_security_dir() -> Path:
    """Locate the platform's active PAM module directory."""
    for candidate in PAM_MODULE_DIRS:
        if candidate.is_dir() and (candidate / "pam_unix.so").is_file():
            return candidate
    for candidate in PAM_MODULE_DIRS:
        if candidate.is_dir():
            return candidate
    return Path("/lib/x86_64-linux-gnu/security")


def build_pam_rule_line(use_native_module: Optional[bool] = None) -> str:
    """
    Construct the non-locking PAM authentication line.
    Uses [success=done new_authtok_reqd=done ignore=ignore default=ignore] so:
      - If FaceLock succeeds (Face, Fingerprint, or Password in UI), PAM completes immediately.
      - If the user closes/skips the dialog or no camera/GUI is available, PAM cleanly falls
        through to standard pam_unix.so password authentication (zero lockout risk).
    """
    sec_dir = find_pam_security_dir()
    native_so = sec_dir / "pam_facelock.so"

    if use_native_module is None:
        use_native_module = native_so.is_file()

    if use_native_module:
        return (
            "auth [success=done new_authtok_reqd=done ignore=ignore default=ignore] "
            f"pam_facelock.so {PAM_MARKER_TAG}"
        )

    helper_bin = INSTALL_LIB_DIR / "facelock-pam-helper"
    return (
        "auth [success=done new_authtok_reqd=done ignore=ignore default=ignore] "
        f"pam_exec.so quiet stdout {helper_bin} {PAM_MARKER_TAG}"
    )


class PamManager:
    """Inspect, backup, enable, disable, and restore PAM service files."""

    def __init__(
        self,
        pam_d_dir: Optional[Path] = None,
        backup_dir: Optional[Path] = None,
    ) -> None:
        self.pam_d_dir = pam_d_dir or PAM_D_DIR
        self.backup_dir = backup_dir or (BACKUP_DIR / "pam.d")

    def get_service_status(self) -> Dict[str, Dict[str, Any]]:
        """
        Inspect all known PAM targets and return whether each file exists and has FaceLock enabled.
        """
        status: Dict[str, Dict[str, Any]] = {}
        for key, info in PAM_TARGETS.items():
            pam_file = self.pam_d_dir / info["file"]
            exists = pam_file.is_file()
            enabled = False
            if exists:
                try:
                    content = pam_file.read_text(encoding="utf-8", errors="ignore")
                    enabled = PAM_MARKER_TAG in content or "pam_facelock.so" in content
                except Exception:
                    pass
            status[key] = {
                "key": key,
                "file": info["file"],
                "path": str(pam_file),
                "label": info["label"],
                "description": info["description"],
                "installed_on_system": exists,
                "enabled": enabled,
            }
        return status

    def _ensure_backup(self, pam_file: Path) -> Optional[Path]:
        if not pam_file.is_file():
            return None
        self.backup_dir.mkdir(parents=True, exist_ok=True)
        orig_backup = self.backup_dir / f"{pam_file.name}.original"
        if not orig_backup.is_file():
            shutil.copy2(pam_file, orig_backup)
        ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        snap = self.backup_dir / f"{pam_file.name}.{ts}.bak"
        shutil.copy2(pam_file, snap)
        return orig_backup

    def set_service_enabled(
        self,
        target_key: str,
        enable: bool,
        use_native_module: Optional[bool] = None,
    ) -> Tuple[bool, str]:
        """
        Enable or disable FaceLock in a specific /etc/pam.d/<service> file atomically.
        """
        if target_key not in PAM_TARGETS:
            return False, f"Unknown PAM service target: {target_key}"

        info = PAM_TARGETS[target_key]
        pam_file = self.pam_d_dir / info["file"]
        if not pam_file.is_file():
            return False, f"PAM service file {pam_file} is not installed on this system"

        try:
            self._ensure_backup(pam_file)
            lines = pam_file.read_text(encoding="utf-8").splitlines()
            # Filter out any existing FaceLock lines first
            cleaned = [
                line
                for line in lines
                if PAM_MARKER_TAG not in line and "pam_facelock.so" not in line and "facelock-pam-helper" not in line
            ]

            if enable:
                rule_line = build_pam_rule_line(use_native_module=use_native_module)
                insert_idx = 0
                for idx, line in enumerate(cleaned):
                    stripped = line.strip()
                    if stripped.startswith("#%PAM") or stripped.startswith("#"):
                        insert_idx = idx + 1
                    else:
                        break
                cleaned.insert(insert_idx, rule_line)

            new_content = "\n".join(cleaned) + "\n"
            tmp_file = pam_file.with_suffix(".facelock.tmp")
            tmp_file.write_text(new_content, encoding="utf-8")
            os.chmod(tmp_file, 0o644)
            os.replace(tmp_file, pam_file)

            action = "Enabled" if enable else "Disabled"
            return True, f"{action} FaceLock for {info['label']} ({pam_file})"
        except PermissionError:
            return False, f"Root privileges required to update {pam_file}"
        except Exception as exc:
            return False, f"Failed to update {pam_file}: {exc}"

    def apply_service_map(
        self,
        service_map: Dict[str, bool],
        use_native_module: Optional[bool] = None,
    ) -> List[Tuple[str, bool, str]]:
        """
        Apply a dictionary of {target_key: bool} across all installed PAM files.
        """
        results: List[Tuple[str, bool, str]] = []
        for key, desired in service_map.items():
            if key not in PAM_TARGETS:
                continue
            pam_file = self.pam_d_dir / PAM_TARGETS[key]["file"]
            if not pam_file.is_file():
                continue
            ok, msg = self.set_service_enabled(
                key, bool(desired), use_native_module=use_native_module
            )
            results.append((key, ok, msg))
        return results

    def disable_all(self) -> List[Tuple[str, bool, str]]:
        results: List[Tuple[str, bool, str]] = []
        for key in PAM_TARGETS:
            pam_file = self.pam_d_dir / PAM_TARGETS[key]["file"]
            if pam_file.is_file():
                ok, msg = self.set_service_enabled(key, False)
                results.append((key, ok, msg))
        return results

    def restore_originals(self) -> Tuple[bool, str]:
        """
        Emergency rollback: restore original backups from /var/backups/facelock/pam.d/*.original
        and strip any remaining FaceLock lines.
        """
        restored: List[str] = []
        try:
            if self.backup_dir.is_dir():
                for orig in sorted(self.backup_dir.glob("*.original")):
                    service_name = orig.name[: -len(".original")]
                    dest = self.pam_d_dir / service_name
                    shutil.copy2(orig, dest)
                    os.chmod(dest, 0o644)
                    restored.append(service_name)
            # Also ensure no marker remains in any target file
            self.disable_all()
            return True, f"Restored PAM configuration ({', '.join(restored) if restored else 'cleaned all markers'})"
        except Exception as exc:
            return False, f"Failed to restore PAM backups: {exc}"
