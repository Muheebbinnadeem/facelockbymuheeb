"""
Fingerprint authentication and enrollment engine via fprintd (D-Bus & CLI)
plus USB biometric hardware discovery for Kali Linux.
"""

import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Dict, List, Optional, Tuple

KNOWN_FINGERPRINT_USB_VENDORS: Dict[str, str] = {
    "06cb": "Synaptics",
    "27c6": "Goodix",
    "04f3": "Elan Microelectronics",
    "138a": "Validity Sensors",
    "147e": "Upek / AuthenTec",
    "08ff": "AuthenTec",
    "2808": "FocalTech",
    "1c7a": "LighTuning Technology",
    "0483": "STMicroelectronics Sensor",
    "2541": "Chipsailing",
}

FINGER_NAMES: List[Tuple[str, str]] = [
    ("right-index-finger", "Right Index Finger"),
    ("right-thumb", "Right Thumb"),
    ("right-middle-finger", "Right Middle Finger"),
    ("left-index-finger", "Left Index Finger"),
    ("left-thumb", "Left Thumb"),
    ("left-middle-finger", "Left Middle Finger"),
]


@dataclass
class FingerprintStatus:
    fprintd_installed: bool = False
    device_present: bool = False
    device_name: str = "No fingerprint reader detected"
    usb_sensors: List[str] = field(default_factory=list)
    enrolled_fingers: List[str] = field(default_factory=list)

    @property
    def is_ready_for_auth(self) -> bool:
        return self.fprintd_installed and self.device_present and len(self.enrolled_fingers) > 0


class FingerprintEngine:
    """Manage fingerprint discovery, enrollment, and verification on Linux."""

    def detect_usb_sensors(self) -> List[str]:
        sensors: List[str] = []
        sys_usb = Path("/sys/bus/usb/devices")
        if sys_usb.is_dir():
            for dev in sorted(sys_usb.iterdir()):
                vid_file = dev / "idVendor"
                pid_file = dev / "idProduct"
                prod_file = dev / "product"
                if not (vid_file.is_file() and pid_file.is_file()):
                    continue
                try:
                    vid = vid_file.read_text(encoding="utf-8").strip().lower()
                    pid = pid_file.read_text(encoding="utf-8").strip().lower()
                    prod = (
                        prod_file.read_text(encoding="utf-8").strip()
                        if prod_file.is_file()
                        else ""
                    )
                    if vid in KNOWN_FINGERPRINT_USB_VENDORS or "finger" in prod.lower() or "biometric" in prod.lower():
                        vendor_label = KNOWN_FINGERPRINT_USB_VENDORS.get(vid, "USB Biometric")
                        desc = f"{vendor_label} ({vid}:{pid})"
                        if prod:
                            desc = f"{prod} [{vid}:{pid}]"
                        sensors.append(desc)
                except Exception:
                    continue
        return sensors

    def get_status(self, username: str) -> FingerprintStatus:
        status = FingerprintStatus()
        status.usb_sensors = self.detect_usb_sensors()
        status.fprintd_installed = shutil.which("fprintd-list") is not None

        # 1. Try D-Bus net.reactivated.Fprint first
        try:
            import dbus

            bus = dbus.SystemBus()
            mgr_obj = bus.get_object("net.reactivated.Fprint", "/net/reactivated/Fprint/Manager")
            mgr = dbus.Interface(mgr_obj, "net.reactivated.Fprint.Manager")
            devices = mgr.GetDevices()
            if devices:
                status.fprintd_installed = True
                status.device_present = True
                dev_obj = bus.get_object("net.reactivated.Fprint", str(devices[0]))
                props = dbus.Interface(dev_obj, "org.freedesktop.DBus.Properties")
                status.device_name = str(props.Get("net.reactivated.Fprint.Device", "name"))
                dev_iface = dbus.Interface(dev_obj, "net.reactivated.Fprint.Device")
                enrolled = dev_iface.ListEnrolledFingers(username)
                status.enrolled_fingers = [str(f) for f in enrolled]
                return status
        except Exception:
            pass

        # 2. Fallback to fprintd-list CLI
        if status.fprintd_installed:
            try:
                res = subprocess.run(
                    ["fprintd-list", username],
                    capture_output=True,
                    text=True,
                    timeout=3.0,
                    check=False,
                )
                out = (res.stdout or "") + "\n" + (res.stderr or "")
                if "No devices available" not in out and res.returncode == 0:
                    for line in out.splitlines():
                        s = line.strip()
                        if s.startswith("Fingerprints for user"):
                            status.device_present = True
                            if " on " in s:
                                status.device_name = s.split(" on ", 1)[1].rstrip(":")
                        elif s.startswith("- #") or s.startswith("- "):
                            for fid, _ in FINGER_NAMES:
                                if fid in s:
                                    status.enrolled_fingers.append(fid)
            except Exception:
                pass

        if not status.device_present and status.usb_sensors:
            status.device_name = f"Detected USB sensor: {status.usb_sensors[0]} (driver/fprintd check needed)"

        return status

    def verify(
        self,
        username: str,
        status_cb: Optional[Callable[[str], None]] = None,
        timeout_sec: int = 15,
    ) -> Tuple[bool, str]:
        """
        Verify a user's fingerprint using fprintd.
        Returns (authenticated, message).
        """
        st = self.get_status(username)
        if not st.fprintd_installed:
            return False, "fprintd is not installed (run: sudo apt install fprintd libpam-fprintd)"
        if not st.device_present:
            return False, "No compatible fingerprint sensor detected on this machine"
        if not st.enrolled_fingers:
            return False, f"No fingerprints enrolled for '{username}' — enroll one in Control Center"

        if status_cb:
            status_cb(f"Touch or swipe {st.device_name}...")

        try:
            proc = subprocess.Popen(
                ["fprintd-verify", username],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
            )
            try:
                out, _ = proc.communicate(timeout=timeout_sec)
            except subprocess.TimeoutExpired:
                proc.kill()
                return False, "Fingerprint scan timed out"

            text = out or ""
            if "verify-match" in text:
                return True, "Fingerprint matched"
            if "verify-no-match" in text:
                return False, "Fingerprint did not match"
            return False, text.strip().splitlines()[-1] if text.strip() else "Fingerprint verification failed"
        except Exception as exc:
            return False, f"Fingerprint error: {exc}"

    def enroll(
        self,
        username: str,
        finger: str = "right-index-finger",
        status_cb: Optional[Callable[[str], None]] = None,
        timeout_sec: int = 45,
    ) -> Tuple[bool, str]:
        """
        Enroll a finger for username using fprintd-enroll.
        """
        if not shutil.which("fprintd-enroll"):
            return False, "fprintd-enroll not found (install package: fprintd)"

        if status_cb:
            status_cb(f"Touch the fingerprint sensor repeatedly to enroll ({finger})...")

        try:
            proc = subprocess.Popen(
                ["fprintd-enroll", "-f", finger, username],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
            )
            lines: List[str] = []
            start = subprocess.os.times().elapsed
            assert proc.stdout is not None
            for line in proc.stdout:
                clean = line.strip()
                if clean:
                    lines.append(clean)
                    if status_cb:
                        status_cb(clean)
                if "enroll-completed" in clean:
                    break
                if (subprocess.os.times().elapsed - start) > timeout_sec:
                    proc.kill()
                    return False, "Fingerprint enrollment timed out"

            proc.wait(timeout=5)
            joined = "\n".join(lines)
            if "enroll-completed" in joined:
                return True, f"Successfully enrolled {finger} for {username}"
            return False, lines[-1] if lines else "Enrollment failed or no sensor present"
        except Exception as exc:
            return False, f"Enrollment error: {exc}"

    def delete_enrolled(self, username: str) -> Tuple[bool, str]:
        if not shutil.which("fprintd-delete"):
            return False, "fprintd-delete not installed"
        try:
            res = subprocess.run(
                ["fprintd-delete", username],
                capture_output=True,
                text=True,
                timeout=6.0,
                check=False,
            )
            if res.returncode == 0:
                return True, f"Cleared enrolled fingerprints for {username}"
            return False, (res.stderr or res.stdout or "Failed to delete fingerprints").strip()
        except Exception as exc:
            return False, str(exc)
