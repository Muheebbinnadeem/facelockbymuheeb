import tempfile
import unittest
from pathlib import Path

from facelock.core.crypto import (
    decrypt_file_stream,
    decrypt_json_payload,
    encrypt_file_stream,
    encrypt_json_payload,
    ensure_master_key,
    get_face_profile_metadata,
    load_encrypted_face_profile,
    save_encrypted_face_profile,
)


class TestCryptoEngine(unittest.TestCase):
    def test_master_key_and_json_encryption(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            key_path = Path(tmp) / "master.key"
            mk = ensure_master_key(key_path)
            self.assertEqual(len(mk), 32)
            self.assertEqual(mk, ensure_master_key(key_path))

            payload = {"username": "muheeb", "samples": [{"spatial": [0.1, 0.2, 0.7]}]}
            env = encrypt_json_payload(payload, purpose="face-profile", context="muheeb", master_key=mk)
            dec = decrypt_json_payload(env, purpose="face-profile", context="muheeb", master_key=mk)
            self.assertEqual(dec, payload)

            # Tamper check
            tampered = dict(env)
            tampered["hmac"] = "0" * 64
            with self.assertRaises(ValueError):
                decrypt_json_payload(tampered, purpose="face-profile", context="muheeb", master_key=mk)

    def test_face_profile_storage_and_stream_vault(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            mk = ensure_master_key(base / "master.key")
            enc_dir = base / "encodings"

            profile = {
                "username": "muheeb",
                "enrolled_at": "2026-11-13 14:00:00 +0500",
                "engine": "spatial-lbp-hog-dct",
                "samples": [{"spatial": [0.25, 0.5, 0.75]}],
            }
            save_encrypted_face_profile("muheeb", profile, encodings_dir=enc_dir, master_key=mk)
            meta = get_face_profile_metadata("muheeb", encodings_dir=enc_dir)
            self.assertIsNotNone(meta)
            self.assertEqual(meta["username"], "muheeb")
            self.assertEqual(meta["sample_count"], 1)

            loaded = load_encrypted_face_profile("muheeb", encodings_dir=enc_dir, master_key=mk)
            self.assertEqual(loaded, profile)

            # File stream encryption
            plain_src = base / "secret.bin"
            enc_dst = base / "secret.flvault"
            plain_out = base / "restored.bin"
            raw_data = b"Kali Linux Folder Vault Test Payload " * 4096
            plain_src.write_bytes(raw_data)

            encrypt_file_stream(plain_src, enc_dst, vault_id="v123", master_key=mk)
            self.assertTrue(enc_dst.is_file())
            self.assertNotEqual(enc_dst.read_bytes(), raw_data)

            decrypt_file_stream(enc_dst, plain_out, vault_id="v123", master_key=mk)
            self.assertEqual(plain_out.read_bytes(), raw_data)


if __name__ == "__main__":
    unittest.main()
