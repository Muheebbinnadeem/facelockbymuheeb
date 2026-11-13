import tempfile
import unittest
from pathlib import Path

from facelock.core.rate_limiter import BiometricRateLimiter


class TestBiometricRateLimiter(unittest.TestCase):
    def test_lockout_after_max_failures_and_reset(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            rl = BiometricRateLimiter(max_attempts=3, lockout_seconds=30, state_dir=Path(tmp))

            allowed, rem, _ = rl.check_biometric_allowed("muheeb")
            self.assertTrue(allowed)
            self.assertEqual(rem, 3)

            locked, rem, _ = rl.record_biometric_failure("muheeb")
            self.assertFalse(locked)
            self.assertEqual(rem, 2)

            locked, rem, _ = rl.record_biometric_failure("muheeb")
            self.assertFalse(locked)
            self.assertEqual(rem, 1)

            locked, rem, lock_sec = rl.record_biometric_failure("muheeb")
            self.assertTrue(locked)
            self.assertEqual(rem, 0)
            self.assertEqual(lock_sec, 30)

            allowed_after, _, _ = rl.check_biometric_allowed("muheeb")
            self.assertFalse(allowed_after)

            # Password verification resets lockout immediately
            rl.reset("muheeb")
            allowed_reset, rem_reset, _ = rl.check_biometric_allowed("muheeb")
            self.assertTrue(allowed_reset)
            self.assertEqual(rem_reset, 3)


if __name__ == "__main__":
    unittest.main()
