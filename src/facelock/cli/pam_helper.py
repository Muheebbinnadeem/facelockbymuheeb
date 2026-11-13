"""
PAM Helper executable invoked by pam_facelock.so (or pam_exec.so).

Discovers the active local X11/Wayland graphical session environment
(DISPLAY, XAUTHORITY, XDG_RUNTIME_DIR, DBUS_SESSION_BUS_ADDRESS) even when
called from a stripped root PAM context (sudo, polkit-1, lightdm, screensaver)
and launches the Windows Hello 3-Method Authentication Prompt.
"""

import argparse
import os
import pwd
import sys
from pathlib import Path
from typing import Dict, Optional

from facelock.config import ConfigManager, detect_active_username
from facelock.ui.prompt_window import launch_authentication_prompt


def discover_graphical_session_env(target_user: str) -> Dict[str, str]:
    """
    Resolve DISPLAY, XAUTHORITY, WAYLAND_DISPLAY, and XDG_RUNTIME_DIR for the
    active desktop user so the GTK3 Windows Hello prompt can render over X11/Wayland
    when invoked by PAM (sudo / polkit-1 / screensaver).
    """
    env_updates: Dict[str, str] = {}

    # Identify candidate desktop user (non-root user running X11/Wayland)
    desktop_user = target_user
    if desktop_user == "root":
        desktop_user = detect_active_username()

    try:
        pw = pwd.getpwnam(desktop_user)
        uid = pw.pw_uid
        home = Path(pw.pw_dir)
    except KeyError:
        uid = -1
        home = Path("/root")

    # 1. Inspect /run/user/<uid>
    if uid >= 1000:
        runtime_dir = Path(f"/run/user/{uid}")
        if runtime_dir.is_dir():
            env_updates.setdefault("XDG_RUNTIME_DIR", str(runtime_dir))
            bus_sock = runtime_dir / "bus"
            if bus_sock.exists():
                env_updates.setdefault("DBUS_SESSION_BUS_ADDRESS", f"unix:path={bus_sock}")
            for wl in runtime_dir.glob("wayland-*"):
                if not wl.name.endswith(".lock"):
                    env_updates.setdefault("WAYLAND_DISPLAY", wl.name)
                    break
            for gdm_auth in (runtime_dir / "gdm" / "Xauthority", runtime_dir / "Xauthority"):
                if gdm_auth.is_file():
                    env_updates.setdefault("XAUTHORITY", str(gdm_auth))

    # 2. Check home .Xauthority
    xauth = home / ".Xauthority"
    if xauth.is_file():
        env_updates.setdefault("XAUTHORITY", str(xauth))

    # 3. Check /tmp/.X11-unix/X* sockets for active X11 display
    if not os.environ.get("DISPLAY"):
        x11_dir = Path("/tmp/.X11-unix")
        if x11_dir.is_dir():
            for sock in sorted(x11_dir.glob("X*")):
                disp_num = sock.name[1:]
                if disp_num.isdigit():
                    env_updates.setdefault("DISPLAY", f":{disp_num}")
                    break

    # 4. Scan /proc/<pid>/environ of the desktop user's session process for exact DISPLAY & XAUTHORITY
    if uid >= 1000 and (not os.environ.get("DISPLAY") or not os.environ.get("XAUTHORITY")):
        proc_root = Path("/proc")
        for proc_entry in proc_root.iterdir():
            if not proc_entry.name.isdigit():
                continue
            try:
                if proc_entry.stat().st_uid != uid:
                    continue
                raw_env = (proc_entry / "environ").read_bytes()
                if b"DISPLAY=" not in raw_env:
                    continue
                for item in raw_env.split(b"\x00"):
                    if item.startswith(b"DISPLAY="):
                        env_updates.setdefault("DISPLAY", item.split(b"=", 1)[1].decode("utf-8", "ignore"))
                    elif item.startswith(b"XAUTHORITY="):
                        env_updates.setdefault(
                            "XAUTHORITY", item.split(b"=", 1)[1].decode("utf-8", "ignore")
                        )
                    elif item.startswith(b"WAYLAND_DISPLAY="):
                        env_updates.setdefault(
                            "WAYLAND_DISPLAY", item.split(b"=", 1)[1].decode("utf-8", "ignore")
                        )
                if "DISPLAY" in env_updates and "XAUTHORITY" in env_updates:
                    break
            except Exception:
                continue

    return env_updates


def main(argv: Optional[list] = None) -> int:
    parser = argparse.ArgumentParser(description="FaceLock PAM Authentication Helper")
    parser.add_argument("--user", default=None, help="Target PAM username")
    parser.add_argument("--service", default=None, help="PAM service name (sudo, lightdm, polkit-1)")
    args = parser.parse_args(argv)

    cfg = ConfigManager().data
    if not cfg.get("enabled", True):
        return 2  # PAM_IGNORE

    # Skip on remote SSH sessions if configured
    if cfg.get("security", {}).get("skip_on_ssh", True):
        if os.environ.get("SSH_CLIENT") or os.environ.get("SSH_TTY") or os.environ.get("PAM_RHOST"):
            return 2

    pam_user = args.user or os.environ.get("PAM_USER") or detect_active_username()
    pam_service = args.service or os.environ.get("PAM_SERVICE") or "sudo"

    # When sudo is called without changing user or authenticating as the caller,
    # ensure we verify the human account (or the target user if enrolled)
    auth_user = pam_user
    if auth_user == "root":
        sudo_user = os.environ.get("SUDO_USER")
        if sudo_user and sudo_user != "root":
            auth_user = sudo_user
        else:
            auth_user = detect_active_username()

    # Inject active graphical session display variables if missing
    for k, v in discover_graphical_session_env(auth_user).items():
        if not os.environ.get(k) and v:
            os.environ[k] = v

    return launch_authentication_prompt(username=auth_user, service=pam_service)


if __name__ == "__main__":
    sys.exit(main())
