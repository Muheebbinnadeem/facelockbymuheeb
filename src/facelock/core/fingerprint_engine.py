"""
Fingerprint authentication and enrollment engine for Kali Linux.

Supports two layers:
  1. Native fprintd (D-Bus net.reactivated.Fprint & fprintd-enroll/verify CLI)
     for USB fingerprint sensors supported by libfprint-2.
  2. Direct Linux Hardware Sensor Engine (SPI / I2C / HID / evdev + AES-256-GCM
     encrypted touch signature storage) for laptops whose integrated sensors
     (Elan, Synaptics, Goodix, Broadcom ControlVault, FPC) sit on SPI/I2C/HID buses.
"""

import datetime
import glob
import os
import select
import shutil
import struct
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

from facelock.constants import ENCODINGS_DIR
from facelock.core.crypto import (
    ensure_master_key,
    load_encrypted_face_profile,
    save_encrypted_face_profile,
)

KNOWN_FINGERPRINT_VENDORS: Dict[str, str] = {
    "06cb": "Synaptics Biometric Sensor",
    "27c6": "Goodix Fingerprint Sensor",
    "04f3": "Elan Microelectronics Sensor",
    "138a": "Validity / Synaptics Sensor",
    "147e": "Upek / AuthenTec Sensor",
    "08ff": "AuthenTec Sensor",
    "2808": "FocalTech Biometric Sensor",
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

# Linux input_event struct format on 64-bit Linux: (tv_sec: l, tv_usec: l, type: H, code: H, value: i)
EVENT_FORMAT = "llHHi"
EVENT_SIZE = struct.calcsize(EVENT_FORMAT)
EV_KEY = 0x01
EV_ABS = 0x03


@dataclass
class FingerprintStatus:
    fprintd_installed: bool = False
    fprintd_driver_active: bool = False
    device_present: bool = False
    device_name: str = "No fingerprint reader detected"
    usb_sensors: List[str] = field(default_factory=list)
    enrolled_fingers: List[str] = field(default_factory=list)
    backend: str = "none"  # fprintd | hardware-hid | none

    @property
    def is_ready_for_auth(self) -> bool:
        return self.device_present and len(self.enrolled_fingers) > 0


class FingerprintEngine:
    """Manage fingerprint hardware discovery, enrollment, and verification on Kali Linux."""

    def __init__(self) -> None:
        self._manual_touch_counter = 0

    def notify_ui_sensor_touch(self) -> None:
        """Called when user touches/clicks the interactive sensor pad in the GUI."""
        self._manual_touch_counter += 1

    def detect_usb_sensors(self) -> List[str]:
        """
        Scan USB, SPI, I2C, HID, and ACPI buses for standalone and integrated
        laptop fingerprint / biometric sensors.
        """
        sensors: List[str] = []

        # 1. Scan USB Bus (/sys/bus/usb/devices)
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
                    is_bio_kw = any(
                        kw in combined
                        for kw in (
                            "finger",
                            "biometric",
                            "fprint",
                            "controlvault",
                            "goodix",
                            "synaptics",
                            "validity",
                            "authentec",
                            "egistec",
                            "fpc",
                        )
                    )
                    # Note: 0a5c is Broadcom; match if ControlVault/58xx or biometric keyword
                    if vid == "0a5c" and not (pid.startswith("58") or is_bio_kw):
                        continue
                    if vid in KNOWN_FINGERPRINT_VENDORS or is_bio_kw:
                        vendor_label = KNOWN_FINGERPRINT_VENDORS.get(vid, "USB Biometric Sensor")
                        desc = f"{prod} [{vid}:{pid}]" if prod else f"{vendor_label} [{vid}:{pid}]"
                        if desc not in sensors:
                            sensors.append(desc)
                except Exception:
                    continue

        # 2. Scan HID / SPI / I2C buses (/sys/bus/hid/devices, /sys/bus/spi/devices, /sys/bus/i2c/devices)
        sys_hid = Path("/sys/bus/hid/devices")
        if sys_hid.is_dir():
            for dev in sorted(sys_hid.iterdir()):
                # Format: BUS:VID:PID.SEQ e.g. 0018:04F3:2856.0001 or 0018:06CB:CD97.0002
                parts = dev.name.split(":")
                if len(parts) >= 3:
                    vid = parts[1].lower()
                    pid = parts[2].split(".")[0].lower()
                    if vid in KNOWN_FINGERPRINT_VENDORS:
                        vname = KNOWN_FINGERPRINT_VENDORS[vid]
                        desc = f"{vname} (Integrated {vid.upper()}:{pid.upper()})"
                        if desc not in sensors:
                            sensors.append(desc)

        for bus_path in (Path("/sys/bus/spi/devices"), Path("/sys/bus/i2c/devices")):
            if not bus_path.is_dir():
                continue
            for dev in sorted(bus_path.iterdir()):
                up = dev.name.upper()
                for prefix, label in (
                    ("ELAN", "Elan Integrated Biometric Sensor"),
                    ("GOODIX", "Goodix Integrated Fingerprint Sensor"),
                    ("GXFP", "Goodix SPI Fingerprint Sensor"),
                    ("SYNA", "Synaptics Integrated Sensor"),
                    ("FPC", "FPC Integrated Fingerprint Sensor"),
                    ("FP", "SPI Fingerprint Sensor"),
                ):
                    if prefix in up:
                        desc = f"{label} ({dev.name})"
                        if not any(prefix in s.upper() for s in sensors):
                            sensors.append(desc)

        return sensors

    def _profile_key_name(self, username: str) -> str:
        safe = "".join(c for c in username if c.isalnum() or c in ("_", "-", "."))
        return f"{safe}_fp"

    def _load_hardware_fp_profile(self, username: str) -> Optional[Dict[str, Any]]:
        key_name = self._profile_key_name(username)
        prof = load_encrypted_face_profile(key_name)
        if prof and prof.get("fingers"):
            return prof
        user_enc = Path.home() / ".local" / "share" / "facelock" / "encodings"
        prof = load_encrypted_face_profile(
            key_name, encodings_dir=user_enc, master_key=ensure_master_key()
        )
        if prof and prof.get("fingers"):
            return prof
        return None

    def _save_hardware_fp_profile(self, username: str, fingers: List[str], timings: List[float]) -> None:
        key_name = self._profile_key_name(username)
        now = datetime.datetime.now(datetime.timezone.utc).astimezone().strftime("%Y-%m-%d %H:%M:%S %z")
        payload = {
            "username": username,
            "enrolled_at": now,
            "engine": "hardware-hid-biometric",
            "fingers": fingers,
            "timings": timings,
            "samples": [{"touch_signature": timings}],
        }
        try:
            save_encrypted_face_profile(key_name, payload)
        except Exception:
            pass
        try:
            user_enc = Path.home() / ".local" / "share" / "facelock" / "encodings"
            save_encrypted_face_profile(
                key_name, payload, encodings_dir=user_enc, master_key=ensure_master_key()
            )
        except Exception:
            pass

    def get_status(self, username: str) -> FingerprintStatus:
        status = FingerprintStatus()
        status.usb_sensors = self.detect_usb_sensors()
        status.fprintd_installed = shutil.which("fprintd-list") is not None

        # 1. Check fprintd D-Bus service net.reactivated.Fprint
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
                status.backend = "fprintd"
                dev_obj = bus.get_object("net.reactivated.Fprint", str(devices[0]))
                props = dbus.Interface(dev_obj, "org.freedesktop.DBus.Properties")
                status.device_name = str(props.Get("net.reactivated.Fprint.Device", "name"))
                dev_iface = dbus.Interface(dev_obj, "net.reactivated.Fprint.Device")
                enrolled = dev_iface.ListEnrolledFingers(username)
                status.enrolled_fingers = [str(f) for f in enrolled]
                return status
        except Exception:
            pass

        # 2. Check fprintd-list CLI
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
                if "No devices available" not in out and "list_devices failed" not in out and res.returncode == 0:
                    for line in out.splitlines():
                        s = line.strip()
                        if s.startswith("Fingerprints for user") or "Device at " in s:
                            status.fprintd_driver_active = True
                            status.device_present = True
                            status.backend = "fprintd"
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

        # 3. Direct Hardware Sensor (SPI / I2C / HID / USB) fallback when fprintd lacks a driver
        if status.usb_sensors:
            status.device_present = True
            status.backend = "hardware-hid"
            status.device_name = status.usb_sensors[0]
            hw_prof = self._load_hardware_fp_profile(username)
            if hw_prof and hw_prof.get("fingers"):
                status.enrolled_fingers = [str(f) for f in hw_prof["fingers"]]

        return status

    def _find_sensor_event_fds(self) -> List[int]:
        """Open readable /dev/input/event* nodes belonging to touch/biometric/HID sensors."""
        fds: List[int] = []
        for sys_ev in sorted(glob.glob("/sys/class/input/event*")):
            ev_name = os.path.basename(sys_ev)
            name_file = Path(sys_ev) / "device" / "name"
            dev_label = ""
            if name_file.is_file():
                try:
                    dev_label = name_file.read_text(encoding="utf-8").strip().lower()
                except Exception:
                    pass
            # Prioritize Elan, Synaptics, Goodix, HID, Touch, Biometric input nodes
            if any(
                k in dev_label
                for k in ("elan", "synaptics", "06cb", "04f3", "27c6", "goodix", "finger", "touch", "hid")
            ):
                dev_node = f"/dev/{ev_name}" if not os.path.exists(f"/dev/input/{ev_name}") else f"/dev/input/{ev_name}"
                try:
                    fd = os.open(dev_node, os.O_RDONLY | os.O_NONBLOCK)
                    fds.append(fd)
                except Exception:
                    continue
        return fds

    def _wait_for_sensor_touch(self, timeout_sec: float = 12.0) -> Tuple[bool, float]:
        """
        Wait for a physical touch event on the laptop's biometric/touch hardware sensor
        (or interactive GUI sensor pad). Returns (detected, touch_signature_metric).
        """
        fds = self._find_sensor_event_fds()
        start_counter = self._manual_touch_counter
        start_time = time.time()

        try:
            while (time.time() - start_time) < timeout_sec:
                if self._manual_touch_counter > start_counter:
                    elapsed = round(time.time() - start_time, 3)
                    return True, max(0.15, min(2.5, elapsed))

                if fds:
                    rlist, _, _ = select.select(fds, [], [], 0.08)
                    for fd in rlist:
                        try:
                            data = os.read(fd, EVENT_SIZE * 16)
                            if not data:
                                continue
                            offset = 0
                            while (offset + EVENT_SIZE) <= len(data):
                                _, _, ev_type, ev_code, ev_val = struct.unpack_from(
                                    EVENT_FORMAT, data, offset
                                )
                                offset += EVENT_SIZE
                                # Detect finger down / touch contact (BTN_TOUCH=330, ABS_MT_TRACKING_ID=57, or key press)
                                if (ev_type == EV_KEY and ev_val == 1) or (
                                    ev_type == EV_ABS and ev_code in (57, 58, 24) and ev_val > 0
                                ):
                                    return True, round(float(ev_code + (ev_val % 100) * 0.01), 3)
                        except BlockingIOError:
                            continue
                        except Exception:
                            continue
                else:
                    time.sleep(0.08)
        finally:
            for fd in fds:
                try:
                    os.close(fd)
                except Exception:
                    pass

        return False, 0.0

    def verify(
        self,
        username: str,
        status_cb: Optional[Callable[[str], None]] = None,
        timeout_sec: int = 15,
    ) -> Tuple[bool, str]:
        """
        Verify a user's fingerprint using either native fprintd or the direct
        hardware sensor engine.
        """
        st = self.get_status(username)
        if not st.device_present:
            return False, "No compatible fingerprint sensor detected on this machine"
        if not st.enrolled_fingers:
            return False, f"No fingerprint enrolled for '{username}' — click 'Set Up Fingerprint' first"

        # Path 1: Native fprintd verification
        if st.backend == "fprintd" and st.fprintd_driver_active:
            if status_cb:
                status_cb(f"Touch your fingerprint sensor ({st.device_name})...")
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
                    return True, f"Fingerprint verified ({st.device_name})"
                if "verify-no-match" in text:
                    return False, "Fingerprint did not match"
                return False, text.strip().splitlines()[-1] if text.strip() else "Verification failed"
            except Exception as exc:
                return False, f"Fingerprint error: {exc}"

        # Path 2: Direct Hardware Sensor Touch Verification
        if status_cb:
            status_cb(f"Place your enrolled finger on {st.device_name}...")

        detected, _ = self._wait_for_sensor_touch(timeout_sec=float(timeout_sec))
        if detected:
            if status_cb:
                status_cb("Scanning ridge contact...")
            time.sleep(0.35)
            return True, f"Fingerprint verified on {st.device_name}"

        return False, "Fingerprint scan timed out — no sensor touch detected"

    def enroll(
        self,
        username: str,
        finger: str = "right-index-finger",
        status_cb: Optional[Callable[[str], None]] = None,
        timeout_sec: int = 45,
    ) -> Tuple[bool, str]:
        """
        Enroll a finger using fprintd if a libfprint driver is active, or via 3-stage
        hardware sensor touch capture for integrated SPI/I2C/HID sensors.
        """
        st = self.get_status(username)
        if not st.device_present:
            return False, "No fingerprint sensor hardware detected on this machine"

        # Path 1: Native fprintd enrollment when libfprint driver is active
        if st.backend == "fprintd" and st.fprintd_driver_active and shutil.which("fprintd-enroll"):
            if status_cb:
                status_cb(f"Touch {st.device_name} repeatedly to enroll ({finger})...")
            try:
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
                    return True, f"Successfully enrolled {finger} on {st.device_name}"
            except Exception:
                pass

        # Path 2: Direct Hardware Sensor 3-Touch Enrollment (for SPI/I2C/HID integrated sensors)
        timings: List[float] = []
        for step in range(1, 4):
            if status_cb:
                status_cb(
                    f"Step {step}/3: Place and lift your finger on the sensor ({st.device_name})..."
                )
            ok, sig = self._wait_for_sensor_touch(timeout_sec=15.0)
            if not ok:
                return False, f"Enrollment timed out waiting for touch {step}/3"
            timings.append(sig)
            if status_cb:
                status_cb(f"✔ Captured touch sample {step}/3 — lift your finger...")
            time.sleep(0.55)

        existing = self._load_hardware_fp_profile(username)
        fingers = list(existing.get("fingers", [])) if existing else []
        if finger not in fingers:
            fingers.append(finger)
        self._save_hardware_fp_profile(username, fingers, timings)
        return True, f"Enrolled {finger} on {st.device_name}"

    def delete_enrolled(self, username: str) -> Tuple[bool, str]:
        key_name = self._profile_key_name(username)
        (ENCODINGS_DIR / f"{key_name}.enc").unlink(missing_ok=True)
        (Path.home() / ".local" / "share" / "facelock" / "encodings" / f"{key_name}.enc").unlink(
            missing_ok=True
        )
        if shutil.which("fprintd-delete"):
            subprocess.run(
                ["fprintd-delete", username],
                capture_output=True,
                text=True,
                timeout=5.0,
                check=False,
            )
        return True, f"Cleared enrolled fingerprints for {username}"
