import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from facelock.core.fingerprint_engine import FingerprintEngine
from facelock.core.keyring_manager import (
    _is_binary_encrypted_keyring,
    disable_kwallet_prompt,
    get_keyring_status,
    initialize_fresh_keyring_if_missing,
)


class TestKeyringAndFingerprint(unittest.TestCase):
    def test_keyring_fresh_init_and_binary_detection(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            fake_home = Path(tmp)
            with patch("facelock.core.keyring_manager._user_home", return_value=fake_home):
                ok, _ = initialize_fresh_keyring_if_missing("testuser")
                self.assertTrue(ok)
                login_kr = fake_home / ".local" / "share" / "keyrings" / "login.keyring"
                self.assertTrue(login_kr.is_file())
                self.assertFalse(_is_binary_encrypted_keyring(login_kr))

                kwalletrc = fake_home / ".config" / "kwalletrc"
                self.assertTrue(kwalletrc.is_file())
                self.assertIn("Enabled=false", kwalletrc.read_text(encoding="utf-8"))

                st = get_keyring_status("testuser")
                self.assertFalse(st.needs_fix)

                # Simulate password-encrypted binary GNOME keyring
                login_kr.write_bytes(b"GnomeKeyring\n\r\0\nENCRYPTED_DATA")
                self.assertTrue(_is_binary_encrypted_keyring(login_kr))
                st_enc = get_keyring_status("testuser")
                self.assertTrue(st_enc.needs_fix)
                self.assertTrue(st_enc.gnome_keyring_encrypted)

    def test_disable_kwallet_preserves_existing_sections(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            fake_home = Path(tmp)
            cfg_dir = fake_home / ".config"
            cfg_dir.mkdir(parents=True)
            (cfg_dir / "kwalletrc").write_text("[Auto Allow]\nkdewallet=Brave\n[Wallet]\nEnabled=true\n", encoding="utf-8")

            with patch("facelock.core.keyring_manager._user_home", return_value=fake_home):
                ok, _ = disable_kwallet_prompt("testuser")
                self.assertTrue(ok)
                txt = (cfg_dir / "kwalletrc").read_text(encoding="utf-8")
                self.assertIn("[Auto Allow]", txt)
                self.assertIn("Enabled=false", txt)
                self.assertIn("First Use=false", txt)

    def test_fingerprint_engine_excludes_touchscreens_and_touchpads(self) -> None:
        eng = FingerprintEngine()
        sensors = eng.detect_usb_sensors()
        for s in sensors:
            self.assertNotIn("04F3:2856", s)
            self.assertNotIn("06CB:CD97", s)


if __name__ == "__main__":
    unittest.main()
