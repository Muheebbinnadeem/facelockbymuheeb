import tempfile
import unittest
from pathlib import Path

from facelock.constants import PAM_MARKER_TAG
from facelock.core.pam_manager import PamManager


class TestPamManager(unittest.TestCase):
    def test_enable_disable_and_emergency_restore(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            pam_d = base / "pam.d"
            backups = base / "backups"
            pam_d.mkdir()

            sudo_file = pam_d / "sudo"
            original_content = "#%PAM-1.0\n@include common-auth\n@include common-account\n"
            sudo_file.write_text(original_content, encoding="utf-8")

            mgr = PamManager(pam_d_dir=pam_d, backup_dir=backups)

            # Enable sudo hook
            ok, msg = mgr.set_service_enabled("sudo", True, use_native_module=True)
            self.assertTrue(ok, msg)
            updated = sudo_file.read_text(encoding="utf-8")
            self.assertIn("pam_facelock.so", updated)
            self.assertIn(PAM_MARKER_TAG, updated)
            self.assertTrue(mgr.get_service_status()["sudo"]["enabled"])

            # Disable sudo hook
            ok_dis, _ = mgr.set_service_enabled("sudo", False)
            self.assertTrue(ok_dis)
            self.assertNotIn("pam_facelock.so", sudo_file.read_text(encoding="utf-8"))
            self.assertFalse(mgr.get_service_status()["sudo"]["enabled"])

            # Re-enable then test emergency restore
            mgr.set_service_enabled("sudo", True, use_native_module=True)
            ok_res, _ = mgr.restore_originals()
            self.assertTrue(ok_res)
            self.assertEqual(sudo_file.read_text(encoding="utf-8"), original_content)


if __name__ == "__main__":
    unittest.main()
