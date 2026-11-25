"""
Unified CLI and GUI launcher for FaceLock (`facelock-cli` & `facelock-gui`).
"""

import argparse
import getpass
import json
import sys
from pathlib import Path
from typing import List, Optional

from facelock.config import ConfigManager, detect_active_username
from facelock.core.audit import read_recent_events
from facelock.core.face_engine import FaceBiometricEngine, enumerate_cameras
from facelock.core.fingerprint_engine import FingerprintEngine
from facelock.core.folder_lock import FolderVaultManager
from facelock.core.keyring_manager import enable_auto_unlock_keyring, get_keyring_status
from facelock.core.pam_manager import PamManager
from facelock.ui.prompt_window import launch_authentication_prompt


def cmd_status(user: str) -> int:
    cfg = ConfigManager().data
    face_eng = FaceBiometricEngine(cfg)
    fp_eng = FingerprintEngine()
    pam_mgr = PamManager()
    vault_mgr = FolderVaultManager()

    fp_st = fp_eng.get_status(user)
    kr_st = get_keyring_status(user)
    pam_st = pam_mgr.get_service_status()
    vaults = vault_mgr.list_vaults(owner=user)

    summary = {
        "active_user": user,
        "face_enrolled": face_eng.is_user_enrolled(user),
        "neural_onnx_ready": face_eng.has_neural_models,
        "cameras_detected": enumerate_cameras(),
        "fingerprint": {
            "fprintd_installed": fp_st.fprintd_installed,
            "fprintd_driver_active": fp_st.fprintd_driver_active,
            "device_present": fp_st.device_present,
            "device_name": fp_st.device_name,
            "enrolled_fingers": fp_st.enrolled_fingers,
            "usb_sensors": fp_st.usb_sensors,
        },
        "keyring": {
            "needs_fix": kr_st.needs_fix,
            "gnome_keyring_encrypted": kr_st.gnome_keyring_encrypted,
            "kwallet_may_prompt": kr_st.kwallet_may_prompt,
            "summary": kr_st.summary,
        },
        "pam_services": {k: v["enabled"] for k, v in pam_st.items() if v["installed_on_system"]},
        "protected_folders": len(vaults),
    }
    print(json.dumps(summary, indent=2))
    return 0


def cmd_folder(args: argparse.Namespace, user: str) -> int:
    vault_mgr = FolderVaultManager()
    if args.folder_action == "list":
        for v in vault_mgr.list_vaults(owner=user):
            print(f"[{v.get('status')}] {v.get('folder_path')} ({v.get('item_count')} items)")
        return 0

    if args.folder_action == "lock-all":
        res = vault_mgr.lock_all_unlocked(owner=user)
        for path_str, ok, msg in res:
            print(f"{'OK' if ok else 'ERR'}: {path_str} -> {msg}")
        return 0

    if not args.path:
        print("Error: folder path required", file=sys.stderr)
        return 1

    target = Path(args.path).expanduser().resolve()

    if args.folder_action == "toggle":
        if vault_mgr.is_folder_locked(target):
            args.folder_action = "unlock"
        else:
            args.folder_action = "lock"

    if args.folder_action == "lock":
        ok, msg = vault_mgr.lock_folder(target, owner=user)
        print(msg)
        return 0 if ok else 1

    if args.folder_action == "unlock":
        if not args.no_prompt:
            rc = launch_authentication_prompt(
                username=user,
                service="folder-vault",
                title_override=f"Unlock Folder: {target.name}",
            )
            if rc != 0:
                print("Authentication cancelled or failed.", file=sys.stderr)
                return 1
        ok, msg = vault_mgr.unlock_folder(target, open_in_file_manager=args.open)
        print(msg)
        return 0 if ok else 1

    return 1


def cmd_pam(args: argparse.Namespace) -> int:
    pam_mgr = PamManager()
    if args.pam_action == "status":
        for k, info in pam_mgr.get_service_status().items():
            state = "ENABLED" if info["enabled"] else "disabled"
            inst = "" if info["installed_on_system"] else " (not installed)"
            print(f"{k:14s} [{state:8s}] {info['path']}{inst}")
        return 0
    if args.pam_action == "enable-defaults":
        cfg = ConfigManager().data
        res = pam_mgr.apply_service_map(cfg.get("pam_services", {}))
        for _, ok, msg in res:
            print(f"{'OK' if ok else 'ERR'}: {msg}")
        return 0
    if args.pam_action == "restore":
        ok, msg = pam_mgr.restore_originals()
        print(msg)
        return 0 if ok else 1
    return 1


def cmd_keyring(args: argparse.Namespace, user: str) -> int:
    if args.keyring_action == "status":
        st = get_keyring_status(user)
        print(json.dumps({
            "needs_fix": st.needs_fix,
            "gnome_keyring_encrypted": st.gnome_keyring_encrypted,
            "kwallet_may_prompt": st.kwallet_may_prompt,
            "summary": st.summary,
        }, indent=2))
        return 0
    if args.keyring_action == "fix":
        pw = getpass.getpass(f"Enter Kali password for '{user}' once (to disable startup keyring lock): ")
        ok, msg = enable_auto_unlock_keyring(user, pw)
        print(msg)
        return 0 if ok else 1
    return 1


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="facelock-cli",
        description="FaceLock (Windows Hello for Kali Linux) Biometric & PAM Security Suite",
    )
    parser.add_argument("--user", default=None, help="Target username (auto-detected if omitted)")
    sub = parser.add_subparsers(dest="command")

    p_gui = sub.add_parser("gui", help="Launch the FaceLock Sign-in Options GUI")
    p_gui.add_argument("--user", default=None, help="Target username")

    p_status = sub.add_parser("status", help="Show biometric hardware, enrollment, keyring, and PAM status")
    p_status.add_argument("--user", default=None, help="Target username")

    p_prompt = sub.add_parser("prompt", help="Launch the Windows Hello 3-method authentication prompt")
    p_prompt.add_argument("--user", default=None, help="Target username")
    p_prompt.add_argument("--service", default="sudo", help="Service name displayed in header")
    p_prompt.add_argument("--method", choices=["face", "fingerprint", "password"], default=None)

    p_folder = sub.add_parser("folder", help="Lock or unlock AES-256-GCM protected folder vaults")
    p_folder.add_argument("--user", default=None, help="Target username")
    p_folder.add_argument("folder_action", choices=["lock", "unlock", "toggle", "list", "lock-all"])
    p_folder.add_argument("path", nargs="?", default=None, help="Folder path to lock or unlock")
    p_folder.add_argument("--open", action="store_true", help="Open folder in file manager after unlock")
    p_folder.add_argument("--no-prompt", action="store_true", help="Skip prompt (for internal tests)")

    p_pam = sub.add_parser("pam", help="Inspect, enable, or restore PAM service configurations")
    p_pam.add_argument("pam_action", choices=["status", "enable-defaults", "restore"])

    p_kr = sub.add_parser("keyring", help="Inspect or disable startup login keyring password prompt")
    p_kr.add_argument("--user", default=None, help="Target username")
    p_kr.add_argument("keyring_action", choices=["status", "fix"])

    sub.add_parser("audit-log", help="Display recent authentication audit events")

    args = parser.parse_args(argv)
    user = args.user or detect_active_username()

    if args.command in (None, "gui"):
        from facelock.ui.control_center import launch_control_center

        return launch_control_center()

    if args.command == "status":
        return cmd_status(user)

    if args.command == "prompt":
        return launch_authentication_prompt(
            username=user,
            service=args.service,
            initial_method=args.method,
        )

    if args.command == "folder":
        return cmd_folder(args, user)

    if args.command == "pam":
        return cmd_pam(args)

    if args.command == "keyring":
        return cmd_keyring(args, user)

    if args.command == "audit-log":
        for ev in read_recent_events(limit=40):
            print(
                f"{ev.get('timestamp')} | {ev.get('status'):7s} | user={ev.get('username')} "
                f"service={ev.get('service')} method={ev.get('method')} ({ev.get('reason', '')})"
            )
        return 0

    return 0


if __name__ == "__main__":
    sys.exit(main())
