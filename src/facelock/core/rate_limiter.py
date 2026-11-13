"""
Biometric rate limiting and temporary lockout enforcement.

After N consecutive failed biometric attempts (Face or Fingerprint), biometric
authentication is locked out for a configurable duration and the user is required
to authenticate using their original Linux system password. Successful password
authentication resets the lockout counter immediately.
"""

import json
import os
import time
from pathlib import Path
from typing import Dict, Optional, Tuple

from facelock.constants import STATE_DIR


class BiometricRateLimiter:
    """Per-user failure counter and lockout timer."""

    def __init__(
        self,
        max_attempts: int = 4,
        lockout_seconds: int = 60,
        state_dir: Optional[Path] = None,
    ) -> None:
        self.max_attempts = max(1, int(max_attempts))
        self.lockout_seconds = max(5, int(lockout_seconds))
        self.state_dir = state_dir or STATE_DIR

    def _state_file(self, username: str) -> Path:
        safe = "".join(c for c in username if c.isalnum() or c in ("_", "-", "."))
        try:
            self.state_dir.mkdir(parents=True, exist_ok=True)
            return self.state_dir / f"ratelimit_{safe}.json"
        except PermissionError:
            fb = Path("/tmp") / f"facelock_rl_{os.getuid()}_{safe}.json"
            return fb

    def _load(self, username: str) -> Dict[str, float]:
        path = self._state_file(username)
        if not path.is_file():
            return {"failures": 0, "locked_until": 0.0, "last_failure": 0.0}
        try:
            with open(path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
            return {
                "failures": int(data.get("failures", 0)),
                "locked_until": float(data.get("locked_until", 0.0)),
                "last_failure": float(data.get("last_failure", 0.0)),
            }
        except Exception:
            return {"failures": 0, "locked_until": 0.0, "last_failure": 0.0}

    def _save(self, username: str, state: Dict[str, float]) -> None:
        path = self._state_file(username)
        try:
            tmp = path.with_suffix(".tmp")
            with open(tmp, "w", encoding="utf-8") as fh:
                json.dump(state, fh)
            os.replace(tmp, path)
        except Exception:
            pass

    def check_biometric_allowed(self, username: str) -> Tuple[bool, int, int]:
        """
        Check if biometric authentication is currently allowed for username.
        Returns (allowed, remaining_attempts, lockout_remaining_seconds).
        """
        state = self._load(username)
        now = time.time()
        locked_until = state["locked_until"]

        if locked_until > now:
            remaining_sec = int(round(locked_until - now))
            return False, 0, max(1, remaining_sec)

        # If a previous lockout expired, reset failures
        if locked_until > 0 and now >= locked_until:
            self.reset(username)
            return True, self.max_attempts, 0

        failures = int(state["failures"])
        remaining_attempts = max(0, self.max_attempts - failures)
        if remaining_attempts == 0:
            return False, 0, self.lockout_seconds

        return True, remaining_attempts, 0

    def record_biometric_failure(self, username: str) -> Tuple[bool, int, int]:
        """
        Increment biometric failure count and trigger lockout if threshold reached.
        Returns (now_locked_out, remaining_attempts, lockout_seconds).
        """
        state = self._load(username)
        now = time.time()

        # Reset stale failures older than 10 minutes
        if state["last_failure"] > 0 and (now - state["last_failure"]) > 600:
            state["failures"] = 0

        state["failures"] = int(state["failures"]) + 1
        state["last_failure"] = now

        if state["failures"] >= self.max_attempts:
            state["locked_until"] = now + self.lockout_seconds
            self._save(username, state)
            return True, 0, self.lockout_seconds

        self._save(username, state)
        remaining = max(0, self.max_attempts - int(state["failures"]))
        return False, remaining, 0

    def reset(self, username: str) -> None:
        """Reset failures on successful authentication."""
        path = self._state_file(username)
        try:
            if path.is_file():
                path.unlink()
        except Exception:
            self._save(username, {"failures": 0, "locked_until": 0.0, "last_failure": 0.0})
