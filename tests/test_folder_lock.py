import tempfile
import unittest
from pathlib import Path

from facelock.core.crypto import ensure_master_key
from facelock.core.folder_lock import GUARD_METADATA_FILE, FolderVaultManager


class TestFolderVaultManager(unittest.TestCase):
    def test_lock_and_unlock_folder_roundtrip(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            mk = ensure_master_key(base / "master.key")
            vaults_dir = base / "vaults"
            reg_path = base / "vaults.json"

            mgr = FolderVaultManager(vaults_dir=vaults_dir, registry_path=reg_path, master_key=mk)

            secret_dir = base / "ProjectNotes"
            secret_dir.mkdir()
            (secret_dir / "credentials.txt").write_text("root_token=kali-2026-secret\n", encoding="utf-8")
            sub = secret_dir / "scans"
            sub.mkdir()
            (sub / "nmap.xml").write_text("<nmaprun>host up</nmaprun>", encoding="utf-8")

            ok, msg = mgr.lock_folder(secret_dir, owner="muheeb")
            self.assertTrue(ok, msg)
            self.assertTrue(mgr.is_folder_locked(secret_dir))
            self.assertTrue((secret_dir / GUARD_METADATA_FILE).is_file())
            self.assertFalse((secret_dir / "credentials.txt").exists())

            # Unlock and verify all files and subdirectories are restored bit-for-bit
            ok_un, msg_un = mgr.unlock_folder(secret_dir, open_in_file_manager=False)
            self.assertTrue(ok_un, msg_un)
            self.assertFalse(mgr.is_folder_locked(secret_dir))
            self.assertEqual(
                (secret_dir / "credentials.txt").read_text(encoding="utf-8"),
                "root_token=kali-2026-secret\n",
            )
            self.assertEqual(
                (secret_dir / "scans" / "nmap.xml").read_text(encoding="utf-8"),
                "<nmaprun>host up</nmaprun>",
            )


if __name__ == "__main__":
    unittest.main()
