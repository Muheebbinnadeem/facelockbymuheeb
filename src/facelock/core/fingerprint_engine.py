"""
Fingerprint authentication and enrollment engine via fprintd (D-Bus & CLI)
and hardware sensor discovery for Kali Linux.

Accurately distinguishes true biometric/fingerprint sensors from I2C touchscreens
and touchpads so laptops without a real fingerprint reader are never misreported,
while laptops with USB, SPI, or ACPI fingerprint hardware are detected cleanly.
"""

import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Dict, List, Optional, Tuple

KNOWN_FINGERPRINT_USB_VENDORS: Dict[str, str] = {
    "06cb": "Synaptics Fingerprint Sensor",
    "27c6": "Goodix Fingerprint Sensor",
    "04f3": "Elan Fingerprint Sensor",
    "138a": "Validity / Synaptics Sensor",
    "147e": "Upek / AuthenTec Sensor",
    "08ff": "AuthenTec Sensor",
    "2808": "FocalTech Fingerprint Sensor",
    "1c7a": "EgisTec / LighTuning Sensor",
    "10a5": "FPC (Fingerprint Cards) Sensor",
    "0a5c": "Broadcom ControlVault Biometric",
    "0483": "STMicroelectronics Biometric",
    "2541": "Chipsailing Fingerprint Sensor",
    "05ba": "DigitalPersona Fingerprint Reader",
    "04c5": "Fujitsu Biometric Reader",
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
    fprintd_driver_active: bool = False
    device_present: bool = False
    device_name: str = "No fingerprint reader detected"
    usb_sensors: List[str] = field(default_factory=list)
    enrolled_fingers: List[str] = field(default_factory=list)
    driver_hint: str = ""

    @property
    def is_ready_for_auth(self) -> bool:
        return (
            self.fprintd_installed
            and self.fprintd_driver_active
            and self.device_present
            and len(self.enrolled_fingers) > 0
        )


def _ensure_fprintd_service_awake() -> None:
    """Ask D-Bus/systemd to start fprintd if installed but idle."""
    try:
        import dbus

        bus = dbus.SystemBus()
        bus.start_service_by_name("net.reactivated.Fprint")
    except Exception:
        pass


class FingerprintEngine:
    """Manage fingerprint hardware discovery, enrollment, and verification on Kali Linux."""

    def detect_usb_sensors(self) -> List[str]:
        """
        Scan USB and SPI/ACPI fingerprint hardware buses while filtering out
        non-biometric input devices such as touchscreens, touchpads, and mice.
        """
        sensors: List[str] = []

        # 1. USB Biometric Readers (/sys/bus/usb/devices)
        sys_usb = Path("/sys/bus/usb/devices")
        if sys_usb.is_dir():
            for dev in sorted(sys_usb.iterdir()):
                vid_file = dev / "idVendor"
                pid_file = dev / "idProduct"
                prod_file = dev / "product"
                mfg_file = dev / "manufacturer"
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
                    mfg = (
                        mfg_file.read_text(encoding="utf-8").strip()
                        if mfg_file.is_file()
                        else ""
                    )
                    combined = f"{mfg} {prod}".lower()

                    # Skip mice/keyboards/touchscreens/touchpads on USB
                    if any(w in combined for w in ("mouse", "touchpad", "touchscreen", "keyboard", "webcam", "camera")):
                        continue

                    # Broadcom 0a5c:58xx is Dell/HP ControlVault (includes fingerprint); other 0a5c are Bluetooth/Wi-Fi
                    if vid == "0a5c" and not (pid.startswith("58") or "controlvault" in combined or "finger" in combined):
                        continue

                    # Elan 04f3: USB fingerprint sensors are typically 0c00..0cff; ignore 04f3 touchpads/mice
                    if vid == "04f3" and not (pid.startswith("0c") or "finger" in combined or "bio" in combined):
                        continue

                    is_bio_kw = any(
                        kw in combined
                        for kw in (
                            "finger",
                            "biometric",
                            "fprint",
                            "controlvault",
                            "goodix",
                            "validity",
                            "authentec",
                            "egistec",
                            "fpc",
                        )
                    )
                    if vid in KNOWN_FINGERPRINT_USB_VENDORS or is_bio_kw:
                        vendor_label = KNOWN_FINGERPRINT_USB_VENDORS.get(vid, "USB Biometric Sensor")
                        desc = f"{prod} [{vid}:{pid}]" if prod else f"{vendor_label} [{vid}:{pid}]"
                        if desc not in sensors:
                            sensors.append(desc)
                except Exception:
                    continue

        # 2. Dedicated SPI Fingerprint Devices (/sys/bus/spi/devices) — excluding touchscreens/touchpads
        spi_dir = Path("/sys/bus/spi/devices")
        if spi_dir.is_dir():
            for dev in sorted(spi_dir.iterdir()):
                up = dev.name.upper()
                # Exclude known touchscreen/touchpad ACPI IDs (e.g. ELAN900C touchscreen)
                if "ELAN90" in up or "TPD" in up or "TPL" in up:
                    continue
                for prefix, label in (
                    ("GXFP", "Goodix SPI Fingerprint Sensor"),
                    ("GOODIX", "Goodix SPI Fingerprint Sensor"),
                    ("ELAN70", "Elan SPI Fingerprint Sensor"),
                    ("ELAN69", "Elan SPI Fingerprint Sensor"),
                    ("SYNA36", "Synaptics SPI Fingerprint Sensor"),
                    ("FPC1", "FPC SPI Fingerprint Sensor"),
                    ("FPC2", "FPC SPI Fingerprint Sensor"),
                    ("FP", "SPI Fingerprint Sensor"),
                ):
                    if prefix in up:
                        desc = f"{label} ({dev.name})"
                        if desc not in sensors:
                            sensors.append(desc)
                        break

        return sensors

    def get_status(self, username: str) -> FingerprintStatus:
        status = FingerprintStatus()
        status.usb_sensors = self.detect_usb_sensors()
        status.fprintd_installed = shutil.which("fprintd-list") is not None

        if status.fprintd_installed:
            _ensure_fprintd_service_awake()

        # 1. Query fprintd D-Bus net.reactivated.Fprint (authoritative libfprint-2 driver check)
        try:
            import dbus

            bus = dbus.SystemBus()
            mgr_obj = bus.get_object("net.reactivated.Fprint", "/net/reactivated/Fprint/Manager")
            mgr = dbus.Interface(mgr_obj, "net.reactivated.Fprint.Manager")
            devices = mgr.GetDevices()
            if devices:
                status.fprintd_installed = True
                status.fprintd_driver_active = True
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
                if (
                    "No devices available" not in out
                    and "list_devices failed" not in out
                    and res.returncode == 0
                ):
                    for line in out.splitlines():
                        s = line.strip()
                        if s.startswith("Fingerprints for user"):
                            status.fprintd_driver_active = True
                            status.device_present = True
                            if " on " in s:
                                status.device_name = s.split(" on ", 1)[1].rstrip(":")
                        elif s.startswith("- #") or s.startswith("- "):
                            for fid, _ in FINGER_NAMES:
                                if fid in s:
                                    status.enrolled_fingers.append(fid)
                    if status.fprintd_driver_active:
                        return status
            except Exception:
                pass

        # 3. Hardware found on USB/SPI but libfprint driver not yet installed/supported
        if status.usb_sensors:
            status.device_present = True
            status.device_name = status.usb_sensors[0]
            if not status.fprintd_installed:
                status.driver_hint = "Run: sudo apt install fprintd libpam-fprintd libfprint-2-2"
            else:
                status.driver_hint = (
                    "Sensor detected on bus, but libfprint-2 driver is not active for this chip yet."
                )

        return status

    def verify(
        self,
        username: str,
        status_cb: Optional[Callable[[str], None]] = None,
        timeout_sec: int = 15,
    ) -> Tuple[bool, str]:
        """Verify a user's fingerprint using native fprintd."""
        st = self.get_status(username)
        if not st.fprintd_installed:
            return False, "fprintd not installed (run: sudo apt install fprintd libpam-fprintd)"
        if not st.fprintd_driver_active or not st.device_present:
            if st.usb_sensors:
                return False, f"{st.device_name} — {st.driver_hint}"
            return False, "No fingerprint reader detected on this laptop"
        if not st.enrolled_fingers:
            return False, f"No fingerprint enrolled for '{username}' — click 'Set up Fingerprint' first"

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
            return (
                False,
                text.strip().splitlines()[-1] if text.strip() else "Fingerprint verification failed",
            )
        except Exception as exc:
            return False, f"Fingerprint error: {exc}"

    def enroll(
        self,
        username: str,
        finger: str = "right-index-finger",
        status_cb: Optional[Callable[[str], None]] = None,
        timeout_sec: int = 45,
    ) -> Tuple[bool, str]:
        """Enroll a finger for username using fprintd-enroll."""
        st = self.get_status(username)
        if not st.fprintd_installed or not shutil.which("fprintd-enroll"):
            return False, "fprintd not installed (run: sudo apt install fprintd libpam-fprintd)"
        if not st.fprintd_driver_active:
            if st.usb_sensors:
                return False, f"{st.device_name} detected, but Linux libfprint driver is missing"
            return False, "No compatible fingerprint sensor detected on this laptop"

        if status_cb:
            status_cb(f"Touch {st.device_name} repeatedly to enroll ({finger})...")

        try:
            import time

            proc = subprocess.Popen(
                ["fprintd-enroll", "-f", finger, username],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
            )
            lines: List[str] = []
            start = time.time()
            assert proc.stdout is not None
            for line in proc.stdout:
                clean = line.strip()
                if clean:
                    lines.append(clean)
                    if status_cb:
                        status_cb(clean)
                if "enroll-completed" in clean:
                    break
                if (time.time() - start) > timeout_sec:
                    proc.kill()
                    return False, "Fingerprint enrollment timed out"

            proc.wait(timeout=5)
            joined = "\n".join(lines)
            if "enroll-completed" in joined:
                return True, f"Successfully enrolled {finger} for {username}"
            return False, lines[-1] if lines else "Enrollment failed"
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
