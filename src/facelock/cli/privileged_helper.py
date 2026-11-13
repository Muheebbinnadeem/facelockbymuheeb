"""
Privileged backend helper invoked by the Frontend Control Center or installer.
"""

import json
import os
import sys
from pathlib import Path
from typing import Any, Dict, Tuple

from facelock.config import ConfigManager
from facelock.constants import (
    CONFIG_PATH,
    ENCODINGS_DIR,
    ETC_DIR,
    MASTER_KEY_PATH,
    STATE_DIR,
    VAR_LIB_DIR,
    VAR_LOG_DIR,
    VAULTS_DIR,
)
from facelock.core.crypto import ensure_master_key
from facelock.core.face_engine import FaceBiometricEngine
from facelock.core.pam_manager import PamManager


def _init_system_directories() -> None:
    for d, mode in (
        (ETC_DIR, 0o755),
        (ENCODINGS_DIR, 0o1777),
        (VAR_LIB_DIR, 0o755),
        (VAULTS_DIR, 0o1777),
        (STATE_DIR, 0o1777),
        (VAR_LOG_DIR, 0o1777),
    ):
        try:
            d.mkdir(parents=True, exist_ok=True)
            os.chmod(d, mode)
        except Exception:
            pass
    ensure_master_key()
    try:
        if MASTER_KEY_PATH.is_file():
            os.chmod(MASTER_KEY_PATH, 0o644)
    except Exception:
        pass


def execute_privileged_payload(action: str, payload: Dict[str, Any]) -> Tuple[bool, str]:
    try:
        _init_system_directories()

        if action == "save_face_enrollment":
            username = str(payload["username"])
            samples = payload["samples"]
            engine = FaceBiometricEngine()
            out_path = engine.save_user_enrollment(username, samples)
            return True, f"Encrypted face profile saved to {out_path}"

        if action == "delete_face_enrollment":
            username = "".join(
                c for c in str(payload.get("username", "")) if c.isalnum() or c in ("_", "-", ".")
            )
            enc_file = ENCODINGS_DIR / f"{username}.enc"
            if enc_file.is_file():
                enc_file.unlink()
                return True, f"Deleted face profile for '{username}'"
            return True, f"No face profile existed for '{username}'"

        if action == "auto_configure_backend":
            cfg_data = payload.get("config")
            if isinstance(cfg_data, dict):
                cfg_mgr = ConfigManager(CONFIG_PATH)
                cfg_mgr._data = cfg_data
                cfg_mgr.save(CONFIG_PATH)

            pam_services = payload.get("pam_services", {})
            pam_mgr = PamManager()
            results = pam_mgr.apply_service_map(pam_services)
            enabled_cnt = sum(1 for k, ok, _ in results if ok and pam_services.get(k))
            return True, f"Backend configured: {enabled_cnt} PAM service(s) active and synced"

        if action == "restore_pam":
            pam_mgr = PamManager()
            return pam_mgr.restore_originals()

        return False, f"Unknown privileged action: {action}"
    except PermissionError as exc:
        return False, f"Root permission required: {exc}"
    except Exception as exc:
        return False, f"Backend error: {exc}"


def main() -> int:
    if len(sys.argv) < 2:
        print("Usage: facelock-privileged <payload.json>", file=sys.stderr)
        return 1

    json_file = Path(sys.argv[1])
    if not json_file.is_file():
        print(f"Payload file not found: {json_file}", file=sys.stderr)
        return 1

    try:
        req = json.loads(json_file.read_text(encoding="utf-8"))
        action = str(req.get("action", ""))
        payload = req.get("payload", {})
    except Exception as exc:
        print(f"Invalid payload JSON: {exc}", file=sys.stderr)
        return 1

    ok, msg = execute_privileged_payload(action, payload)
    if ok:
        print(msg)
        return 0
    print(msg, file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
