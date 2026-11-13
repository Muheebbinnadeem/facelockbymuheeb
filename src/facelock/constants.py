"""
System paths and default constants used across FaceLock components.
"""

import os
from pathlib import Path

APP_NAME = "FaceLock"
APP_ID = "com.muheeb.facelock"
VERSION = "1.2.0"

# System directories (can be overridden via env for testing/unprivileged runs)
ETC_DIR = Path(os.environ.get("FACELOCK_ETC_DIR", "/etc/facelock"))
VAR_LIB_DIR = Path(os.environ.get("FACELOCK_VAR_DIR", "/var/lib/facelock"))
VAR_LOG_DIR = Path(os.environ.get("FACELOCK_LOG_DIR", "/var/log/facelock"))
BACKUP_DIR = Path(os.environ.get("FACELOCK_BACKUP_DIR", "/var/backups/facelock"))
RUN_DIR = Path(os.environ.get("FACELOCK_RUN_DIR", "/run/facelock"))
INSTALL_LIB_DIR = Path(os.environ.get("FACELOCK_LIB_DIR", "/usr/lib/facelock"))

CONFIG_PATH = ETC_DIR / "config.json"
MASTER_KEY_PATH = ETC_DIR / "master.key"
ENCODINGS_DIR = ETC_DIR / "encodings"
MODELS_DIR = VAR_LIB_DIR / "models"
VAULTS_DIR = VAR_LIB_DIR / "vaults"
VAULT_REGISTRY_PATH = VAR_LIB_DIR / "vaults.json"
STATE_DIR = VAR_LIB_DIR / "state"
AUDIT_LOG_PATH = VAR_LOG_DIR / "audit.log"
INTRUDER_DIR = VAR_LOG_DIR / "intruders"

# PAM paths
PAM_D_DIR = Path(os.environ.get("FACELOCK_PAM_D_DIR", "/etc/pam.d"))
PAM_MODULE_DIRS = [
    Path("/lib/x86_64-linux-gnu/security"),
    Path("/lib/aarch64-linux-gnu/security"),
    Path("/lib64/security"),
    Path("/lib/security"),
    Path("/usr/lib/x86_64-linux-gnu/security"),
    Path("/usr/lib/security"),
]

# Authentication method identifiers
METHOD_FACE = "face"
METHOD_FINGERPRINT = "fingerprint"
METHOD_PASSWORD = "password"
VALID_METHODS = (METHOD_FACE, METHOD_FINGERPRINT, METHOD_PASSWORD)

# PAM marker line used for clean installation and removal
PAM_MARKER_TAG = "# [FACELOCK-MANAGED-AUTH]"

# Supported PAM service targets
PAM_TARGETS = {
    "sudo": {
        "file": "sudo",
        "label": "sudo (Terminal Privilege Escalation)",
        "description": "Prompt with Windows Hello UI when running sudo commands.",
        "default_enabled": True,
    },
    "polkit": {
        "file": "polkit-1",
        "label": "Polkit / pkexec (GUI Admin Prompts)",
        "description": "Use Face, Fingerprint, or Password for graphical root prompts.",
        "default_enabled": True,
    },
    "lightdm": {
        "file": "lightdm",
        "label": "LightDM (Kali Desktop Login)",
        "description": "Authenticate at the Kali Linux desktop login screen.",
        "default_enabled": True,
    },
    "gdm": {
        "file": "gdm-password",
        "label": "GDM (GNOME Display Manager Login)",
        "description": "Authenticate at the GNOME login screen if GDM is installed.",
        "default_enabled": False,
    },
    "screensaver": {
        "file": "xfce4-screensaver",
        "label": "XFCE Screensaver / Lock Screen",
        "description": "Unlock the XFCE desktop lock screen using Face or Fingerprint.",
        "default_enabled": True,
    },
    "light_locker": {
        "file": "light-locker",
        "label": "Light Locker (Session Lock)",
        "description": "Unlock Light Locker screensaver sessions.",
        "default_enabled": True,
    },
    "su": {
        "file": "su",
        "label": "su (Switch User)",
        "description": "Prompt when switching accounts with su.",
        "default_enabled": False,
    },
}

# ONNX model URLs (OpenCV Zoo YuNet & SFace)
YUNET_MODEL_URL = (
    "https://github.com/opencv/opencv_zoo/raw/main/models/face_detection_yunet/"
    "face_detection_yunet_2023mar.onnx"
)
SFACE_MODEL_URL = (
    "https://github.com/opencv/opencv_zoo/raw/main/models/face_recognition_sface/"
    "face_recognition_sface_2021dec.onnx"
)
