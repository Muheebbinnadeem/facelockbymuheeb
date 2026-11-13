"""
Cryptographic Folder Lock & Vault Manager.

Locks any directory with AES-256-GCM chunked stream encryption and places a
Windows Hello Guard launcher inside the locked folder so opening or unlocking
it triggers the FaceLock 3-method prompt (Face / Fingerprint / Password).
"""

import datetime
import hashlib
import json
import os
import shutil
import subprocess
import tarfile
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from facelock.constants import VAULT_REGISTRY_PATH, VAULTS_DIR
from facelock.core.crypto import decrypt_file_stream, encrypt_file_stream

GUARD_METADATA_FILE = ".facelock_vault.json"


class FolderVaultManager:
    """Manage AES-256-GCM encrypted folder vaults and guard launchers."""

    def __init__(
        self,
        vaults_dir: Optional[Path] = None,
        registry_path: Optional[Path] = None,
        master_key: Optional[bytes] = None,
    ) -> None:
        self.vaults_dir = vaults_dir or self._resolve_vaults_dir()
        self.registry_path = registry_path or self._resolve_registry_path()
        self.master_key = master_key

    def _resolve_vaults_dir(self) -> Path:
        try:
            VAULTS_DIR.mkdir(parents=True, exist_ok=True)
            test = VAULTS_DIR / ".wtest"
            test.touch()
            test.unlink()
            return VAULTS_DIR
        except PermissionError:
            user_dir = Path.home() / ".local" / "share" / "facelock" / "vaults"
            user_dir.mkdir(parents=True, exist_ok=True)
            return user_dir

    def _resolve_registry_path(self) -> Path:
        if self.vaults_dir == VAULTS_DIR:
            return VAULT_REGISTRY_PATH
        return self.vaults_dir.parent / "vaults.json"

    def _resolve_master_key(self) -> Optional[bytes]:
        if self.master_key is not None:
            return self.master_key
        if self.vaults_dir != VAULTS_DIR:
            key_file = self.vaults_dir.parent / "user_vault.key"
            from facelock.core.crypto import ensure_master_key

            return ensure_master_key(key_file)
        return None

    def _load_registry(self) -> Dict[str, Dict[str, Any]]:
        if not self.registry_path.is_file():
            return {}
        try:
            with open(self.registry_path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
            if isinstance(data, dict):
                return data
        except Exception:
            pass
        return {}

    def _save_registry(self, reg: Dict[str, Dict[str, Any]]) -> None:
        self.registry_path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.registry_path.with_suffix(".tmp")
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(reg, fh, indent=2)
            fh.write("\n")
        os.replace(tmp, self.registry_path)

    @staticmethod
    def compute_vault_id(folder_path: Path) -> str:
        canonical = str(folder_path.expanduser().resolve())
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:16]

    def list_vaults(self, owner: Optional[str] = None) -> List[Dict[str, Any]]:
        reg = self._load_registry()
        items = list(reg.values())
        if owner:
            items = [v for v in items if v.get("owner") in (owner, None, "")]
        items.sort(key=lambda v: v.get("folder_path", ""))
        return items

    def is_folder_locked(self, folder_path: Path) -> bool:
        target = folder_path.expanduser().resolve()
        if (target / GUARD_METADATA_FILE).is_file():
            return True
        vid = self.compute_vault_id(target)
        reg = self._load_registry()
        entry = reg.get(vid)
        return bool(entry and entry.get("status") == "LOCKED")

    def lock_folder(
        self,
        folder_path: Path,
        owner: str,
    ) -> Tuple[bool, str]:
        """
        Encrypt all contents of folder_path into an AES-256-GCM vault container and
        replace the contents with a clickable Windows Hello unlock launcher.
        """
        target = folder_path.expanduser().resolve()
        if not target.exists() or not target.is_dir():
            return False, f"Folder does not exist: {target}"

        if target in (Path("/"), Path("/home"), Path.home(), Path("/etc"), Path("/usr"), Path("/var")):
            return False, f"Refusing to lock critical system/home root directory: {target}"

        if (target / GUARD_METADATA_FILE).is_file():
            return False, f"Folder is already locked: {target.name}"

        vid = self.compute_vault_id(target)
        self.vaults_dir.mkdir(parents=True, exist_ok=True)
        archive_path = self.vaults_dir / f"{vid}.flvault"

        # Count items before locking
        entries = [p for p in target.iterdir()]

        try:
            with tempfile.NamedTemporaryFile(suffix=".tar.gz", delete=False) as tmp_tar:
                tmp_tar_path = Path(tmp_tar.name)

            try:
                with tarfile.open(tmp_tar_path, "w:gz") as tar:
                    for item in entries:
                        tar.add(str(item), arcname=item.name)

                encrypt_file_stream(
                    tmp_tar_path,
                    archive_path,
                    vault_id=vid,
                    master_key=self._resolve_master_key(),
                )
            finally:
                if tmp_tar_path.exists():
                    tmp_tar_path.unlink()

            # Verify archive exists and is non-empty before removing plaintext files
            if not archive_path.is_file() or archive_path.stat().st_size < 16:
                return False, "Vault encryption verification failed; original files untouched"

            for item in entries:
                if item.is_dir() and not item.is_symlink():
                    shutil.rmtree(item)
                else:
                    item.unlink()

            now = datetime.datetime.now(datetime.timezone.utc).astimezone().strftime("%Y-%m-%d %H:%M:%S %z")
            meta = {
                "vault_id": vid,
                "folder_path": str(target),
                "folder_name": target.name,
                "owner": owner,
                "status": "LOCKED",
                "locked_at": now,
                "item_count": len(entries),
                "archive_path": str(archive_path),
            }

            guard_file = target / GUARD_METADATA_FILE
            guard_file.write_text(json.dumps(meta, indent=2) + "\n", encoding="utf-8")

            # Create clickable Desktop launcher inside the locked folder
            launcher = target / f"Unlock-{target.name}.desktop"
            launcher_content = (
                "[Desktop Entry]\n"
                "Version=1.0\n"
                "Type=Application\n"
                f"Name=Unlock {target.name} (FaceLock)\n"
                "Comment=Authenticate with Face, Fingerprint, or Password to unlock this folder\n"
                f"Exec=facelock-cli folder unlock \"{target}\" --open\n"
                "Icon=changes-prevent\n"
                "Terminal=false\n"
                "Categories=Security;Utility;\n"
            )
            launcher.write_text(launcher_content, encoding="utf-8")
            os.chmod(launcher, 0o755)

            readme_notice = target / "LOCKED_BY_FACELOCK.txt"
            readme_notice.write_text(
                f"This folder ({target.name}) is encrypted and locked with FaceLock (AES-256-GCM).\n\n"
                f"To unlock using Face Recognition, Fingerprint, or System Password:\n"
                f"  1. Double-click 'Unlock-{target.name}.desktop', OR\n"
                f"  2. Open FaceLock Control Center -> Folder Lock -> Unlock, OR\n"
                f"  3. Run: facelock-cli folder unlock \"{target}\"\n",
                encoding="utf-8",
            )

            reg = self._load_registry()
            reg[vid] = meta
            self._save_registry(reg)
            return True, f"Locked and encrypted '{target.name}' ({len(entries)} items)"
        except Exception as exc:
            return False, f"Failed to lock folder: {exc}"

    def unlock_folder(
        self,
        folder_path: Path,
        open_in_file_manager: bool = False,
    ) -> Tuple[bool, str]:
        """
        Decrypt and restore a locked folder's contents in-place after authentication.
        """
        target = folder_path.expanduser().resolve()
        vid = self.compute_vault_id(target)
        reg = self._load_registry()
        meta = reg.get(vid, {})

        guard_file = target / GUARD_METADATA_FILE
        if guard_file.is_file() and not meta:
            try:
                meta = json.loads(guard_file.read_text(encoding="utf-8"))
            except Exception:
                pass

        archive_path = Path(meta.get("archive_path", str(self.vaults_dir / f"{vid}.flvault")))
        if not archive_path.is_file():
            return False, f"Encrypted vault archive not found for {target.name}"

        try:
            with tempfile.NamedTemporaryFile(suffix=".tar.gz", delete=False) as tmp_tar:
                tmp_tar_path = Path(tmp_tar.name)

            try:
                decrypt_file_stream(
                    archive_path,
                    tmp_tar_path,
                    vault_id=vid,
                    master_key=self._resolve_master_key(),
                )

                target.mkdir(parents=True, exist_ok=True)
                # Remove guard files before extracting original contents
                for gname in (
                    GUARD_METADATA_FILE,
                    f"Unlock-{target.name}.desktop",
                    "LOCKED_BY_FACELOCK.txt",
                ):
                    gp = target / gname
                    if gp.is_file():
                        gp.unlink()

                with tarfile.open(tmp_tar_path, "r:gz") as tar:
                    # Safe extraction check against path traversal
                    for member in tar.getmembers():
                        member_dest = (target / member.name).resolve()
                        if not str(member_dest).startswith(str(target)):
                            raise ValueError(f"Unsafe path in archive: {member.name}")
                    tar.extractall(path=str(target))
            finally:
                if tmp_tar_path.exists():
                    tmp_tar_path.unlink()

            archive_path.unlink(missing_ok=True)
            if vid in reg:
                reg[vid]["status"] = "UNLOCKED"
                reg[vid]["unlocked_at"] = (
                    datetime.datetime.now(datetime.timezone.utc).astimezone().strftime("%Y-%m-%d %H:%M:%S %z")
                )
                self._save_registry(reg)

            if open_in_file_manager and os.environ.get("DISPLAY"):
                try:
                    subprocess.Popen(
                        ["xdg-open", str(target)],
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                    )
                except Exception:
                    pass

            return True, f"Unlocked '{target.name}' successfully"
        except Exception as exc:
            return False, f"Failed to unlock folder: {exc}"

    def remove_from_registry(self, folder_path: Path) -> Tuple[bool, str]:
        target = folder_path.expanduser().resolve()
        if self.is_folder_locked(target):
            return False, "Unlock the folder before removing it from FaceLock vault list"
        vid = self.compute_vault_id(target)
        reg = self._load_registry()
        if vid in reg:
            del reg[vid]
            self._save_registry(reg)
        return True, f"Removed '{target.name}' from vault list"

    def lock_all_unlocked(self, owner: str) -> List[Tuple[str, bool, str]]:
        """Re-lock all registered folders that are currently in UNLOCKED state."""
        results: List[Tuple[str, bool, str]] = []
        for entry in self.list_vaults(owner=owner):
            if entry.get("status") == "UNLOCKED":
                fpath = Path(entry["folder_path"])
                if fpath.is_dir():
                    ok, msg = self.lock_folder(fpath, owner=entry.get("owner", owner))
                    results.append((str(fpath), ok, msg))
        return results
