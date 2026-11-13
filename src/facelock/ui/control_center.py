"""
FaceLock Frontend Control Center GUI for Kali Linux.

Provides zero-CLI frontend setup for:
  - Auto-detected user account & system Password PAM verification status
  - Live Camera Face Lock Enrollment Wizard (5-pose guided capture + live test)
  - Fingerprint Hardware Detection, Enrollment & Verification (fprintd)
  - AES-256-GCM Encrypted Folder Lock & Vault Manager (gated by Windows Hello prompt)
  - Automatic One-Click Backend PAM Configurator (sudo, Polkit, LightDM, Lock Screen)
  - Security Policy Controls & Live Audit Log Viewer
"""

import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import cv2
import numpy as np

from facelock.config import ConfigManager, detect_active_username, list_human_users
from facelock.constants import (
    CONFIG_PATH,
    ENCODINGS_DIR,
    INSTALL_LIB_DIR,
    METHOD_FACE,
    METHOD_FINGERPRINT,
    METHOD_PASSWORD,
    PAM_TARGETS,
)
from facelock.core.audit import log_auth_event, read_recent_events
from facelock.core.crypto import get_face_profile_metadata, load_encrypted_face_profile
from facelock.core.face_engine import (
    FaceBiometricEngine,
    FaceDetectionResult,
    LivenessState,
    enumerate_cameras,
)
from facelock.core.fingerprint_engine import FINGER_NAMES, FingerprintEngine
from facelock.core.folder_lock import FolderVaultManager
from facelock.core.pam_manager import PamManager
from facelock.ui.prompt_window import launch_authentication_prompt

ENROLL_POSE_PROMPTS = [
    "Pose 1/5: Look straight at the camera",
    "Pose 2/5: Turn head slightly to the LEFT",
    "Pose 3/5: Turn head slightly to the RIGHT",
    "Pose 4/5: Tilt chin slightly UP/DOWN",
    "Pose 5/5: Look straight & blink naturally",
]


def run_privileged_action(action: str, payload: Dict[str, Any]) -> Tuple[bool, str]:
    """
    Execute a backend configuration task (saving /etc/facelock files or updating /etc/pam.d).
    If already running as root, executes directly in-process; otherwise elevates seamlessly
    using pkexec so the user never has to touch backend config files manually.
    """
    from facelock.cli.privileged_helper import execute_privileged_payload

    if os.geteuid() == 0:
        return execute_privileged_payload(action, payload)

    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False, encoding="utf-8") as tmp:
        json.dump({"action": action, "payload": payload}, tmp)
        tmp_path = Path(tmp.name)

    try:
        helper_bin = INSTALL_LIB_DIR / "facelock-privileged"
        repo_root = Path(__file__).resolve().parents[3]
        if helper_bin.is_file():
            cmd = ["pkexec", str(helper_bin), str(tmp_path)]
        else:
            cmd = [
                "pkexec",
                "env",
                f"PYTHONPATH={repo_root / 'src'}",
                sys.executable,
                "-m",
                "facelock.cli.privileged_helper",
                str(tmp_path),
            ]
        if not shutil.which("pkexec"):
            return execute_privileged_payload(action, payload)

        res = subprocess.run(cmd, capture_output=True, text=True, timeout=60, check=False)
        out = (res.stdout or "").strip()
        err = (res.stderr or "").strip()
        if res.returncode == 0:
            return True, out or "Backend updated successfully"
        return False, err or out or f"Privileged helper exited with code {res.returncode}"
    except Exception as exc:
        return False, f"Failed to run privileged helper: {exc}"
    finally:
        tmp_path.unlink(missing_ok=True)


class FaceLockControlCenter:
    """Main GTK3 Dashboard for FaceLock setup and management."""

    def __init__(self) -> None:
        import gi

        gi.require_version("Gtk", "3.0")
        from gi.repository import Gdk, GLib, Gtk

        self.Gtk = Gtk
        self.Gdk = Gdk
        self.GLib = GLib

        from facelock.ui.theme import apply_kali_theme, draw_circular_camera_hud

        apply_kali_theme()
        self._draw_camera_hud = draw_circular_camera_hud

        self.cfg_mgr = ConfigManager()
        self.cfg = self.cfg_mgr.data
        self.username = detect_active_username()
        self.face_engine = FaceBiometricEngine(self.cfg)
        self.fp_engine = FingerprintEngine()
        self.vault_mgr = FolderVaultManager()
        self.pam_mgr = PamManager()

        # Live camera state for Face Lock tab
        self._cap: Optional[cv2.VideoCapture] = None
        self._cam_timer_id: Optional[int] = None
        self._current_frame: Optional[np.ndarray] = None
        self._last_det: Optional[FaceDetectionResult] = None
        self._scan_phase = 0.0
        self._hud_state = "scanning"
        self._hud_confidence = 0.0
        self._cam_mode = "idle"  # idle | preview | enroll | test
        self._enroll_samples: List[Dict[str, List[float]]] = []
        self._enroll_last_capture = 0.0
        self._test_liveness = LivenessState()
        self._test_profile: Optional[Dict[str, Any]] = None

        self._build_ui()
        self._refresh_overview()

    def _build_ui(self) -> None:
        Gtk = self.Gtk
        self.win = Gtk.Window(title="FaceLock Control Center — Kali Hello Security")
        self.win.set_default_size(940, 650)
        self.win.set_position(Gtk.WindowPosition.CENTER)
        self.win.connect("destroy", self._on_destroy)

        root_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=0)
        self.win.add(root_box)

        # Top header bar
        header = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=14)
        header.set_margin_top(14)
        header.set_margin_bottom(12)
        header.set_margin_start(20)
        header.set_margin_end(20)

        title_col = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=2)
        t_lbl = Gtk.Label(label="Kali Hello  •  FaceLock Control Center")
        t_lbl.set_halign(Gtk.Align.START)
        t_lbl.get_style_context().add_class("title-label")
        s_lbl = Gtk.Label(
            label="Biometric Face Lock, Fingerprint & Password PAM Suite + Encrypted Folder Vaults"
        )
        s_lbl.set_halign(Gtk.Align.START)
        s_lbl.get_style_context().add_class("subtitle-label")
        title_col.pack_start(t_lbl, False, False, 0)
        title_col.pack_start(s_lbl, False, False, 0)
        header.pack_start(title_col, True, True, 0)

        # Auto-detected user selector in top right
        user_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        user_row.get_style_context().add_class("user-pill")
        u_lbl = Gtk.Label(label="Active Account:")
        self.user_combo = Gtk.ComboBoxText()
        users = list_human_users()
        for u in users:
            self.user_combo.append(u, f"{u} (Auto-Detected)" if u == self.username else u)
        self.user_combo.set_active_id(self.username)
        self.user_combo.connect("changed", self._on_user_changed)
        user_row.pack_start(u_lbl, False, False, 0)
        user_row.pack_start(self.user_combo, False, False, 0)
        header.pack_end(user_row, False, False, 0)

        root_box.pack_start(header, False, False, 0)
        root_box.pack_start(Gtk.Separator(orientation=Gtk.Orientation.HORIZONTAL), False, False, 0)

        # Main Notebook Tabs
        self.notebook = Gtk.Notebook()
        self.notebook.connect("switch-page", self._on_tab_switched)
        root_box.pack_start(self.notebook, True, True, 0)

        self.notebook.append_page(self._build_overview_tab(), Gtk.Label(label="1. Overview & Quick Setup"))
        self.notebook.append_page(self._build_face_tab(), Gtk.Label(label="2. Face Lock Setup"))
        self.notebook.append_page(self._build_fingerprint_tab(), Gtk.Label(label="3. Fingerprint Setup"))
        self.notebook.append_page(self._build_folder_vault_tab(), Gtk.Label(label="4. Folder Lock Vaults"))
        self.notebook.append_page(self._build_pam_security_tab(), Gtk.Label(label="5. Where to Use & PAM"))
        self.notebook.append_page(self._build_audit_tab(), Gtk.Label(label="6. Audit Log"))

        # Bottom global status bar
        status_bar = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
        status_bar.set_margin_top(8)
        status_bar.set_margin_bottom(10)
        status_bar.set_margin_start(20)
        status_bar.set_margin_end(20)
        self.footer_status = Gtk.Label(
            label=f"Ready — Active user '{self.username}' auto-configured."
        )
        self.footer_status.set_halign(Gtk.Align.START)
        self.footer_status.get_style_context().add_class("subtitle-label")
        status_bar.pack_start(self.footer_status, True, True, 0)
        root_box.pack_start(status_bar, False, False, 0)

        self.win.show_all()

    def _set_footer(self, text: str) -> None:
        self.footer_status.set_text(text)

    def _on_user_changed(self, combo: Any) -> None:
        uid = combo.get_active_id()
        if uid:
            self.username = uid
            self._refresh_overview()
            self._refresh_fingerprint_status()
            self._refresh_vault_list()
            self._set_footer(f"Switched active account to '{self.username}'")

    def _on_tab_switched(self, _nb: Any, _page: Any, page_num: int) -> None:
        if page_num != 1:
            self._stop_face_camera()
        if page_num == 0:
            self._refresh_overview()
        elif page_num == 2:
            self._refresh_fingerprint_status()
        elif page_num == 3:
            self._refresh_vault_list()
        elif page_num == 4:
            self._refresh_pam_toggles()
        elif page_num == 5:
            self._refresh_audit_log()

    # =========================================================================
    # TAB 1: Overview & One-Click Setup
    # =========================================================================
    def _build_overview_tab(self) -> Any:
        Gtk = self.Gtk
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=16)
        box.set_margin_top(20)
        box.set_margin_bottom(20)
        box.set_margin_start(24)
        box.set_margin_end(24)

        # Status Cards Grid (2x2)
        grid = Gtk.Grid()
        grid.set_column_spacing(16)
        grid.set_row_spacing(16)
        grid.set_column_homogeneous(True)

        self.card_face_val = Gtk.Label(label="Checking...")
        self.card_face_sub = Gtk.Label(label="")
        grid.attach(
            self._make_stat_card("FACE LOCK PROFILE", self.card_face_val, self.card_face_sub),
            0, 0, 1, 1,
        )

        self.card_fp_val = Gtk.Label(label="Checking...")
        self.card_fp_sub = Gtk.Label(label="")
        grid.attach(
            self._make_stat_card("FINGERPRINT SENSOR", self.card_fp_val, self.card_fp_sub),
            1, 0, 1, 1,
        )

        self.card_pw_val = Gtk.Label(label="Active (Linux PAM Shadow)")
        self.card_pw_sub = Gtk.Label(label=f"Uses original password of '{self.username}' automatically")
        grid.attach(
            self._make_stat_card("SYSTEM PASSWORD", self.card_pw_val, self.card_pw_sub),
            0, 1, 1, 1,
        )

        self.card_pam_val = Gtk.Label(label="Checking...")
        self.card_pam_sub = Gtk.Label(label="")
        grid.attach(
            self._make_stat_card("SYSTEM PAM INTEGRATION", self.card_pam_val, self.card_pam_sub),
            1, 1, 1, 1,
        )

        box.pack_start(grid, False, False, 0)

        # Quick Action Banner
        action_card = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        action_card.get_style_context().add_class("panel-card")

        act_title = Gtk.Label(label="Frontend One-Click Setup & Verification")
        act_title.set_halign(Gtk.Align.START)
        act_title.get_style_context().add_class("title-label")
        action_card.pack_start(act_title, False, False, 0)

        act_desc = Gtk.Label(
            label=(
                "No manual backend file editing required. Enroll your Face in Tab 2 (and Fingerprint in Tab 3 if "
                "your laptop has a reader), then click 'Auto-Configure Backend PAM' below to enable Kali Hello "
                "across sudo, desktop login, lock screen, and Polkit admin prompts."
            )
        )
        act_desc.set_halign(Gtk.Align.START)
        act_desc.set_line_wrap(True)
        act_desc.get_style_context().add_class("subtitle-label")
        action_card.pack_start(act_desc, False, False, 0)

        btn_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=12)

        btn_enroll_goto = Gtk.Button(label="1. Set Up Face Lock →")
        btn_enroll_goto.get_style_context().add_class("primary-btn")
        btn_enroll_goto.connect("clicked", lambda *_: self.notebook.set_current_page(1))
        btn_row.pack_start(btn_enroll_goto, False, False, 0)

        btn_auto_pam = Gtk.Button(label="2. Auto-Configure Backend PAM (One-Click)")
        btn_auto_pam.get_style_context().add_class("success-btn")
        btn_auto_pam.connect("clicked", self._on_one_click_backend_setup)
        btn_row.pack_start(btn_auto_pam, False, False, 0)

        btn_test_prompt = Gtk.Button(label="3. Test Windows Hello Prompt Live")
        btn_test_prompt.get_style_context().add_class("secondary-btn")
        btn_test_prompt.connect("clicked", self._on_test_windows_hello_prompt)
        btn_row.pack_start(btn_test_prompt, False, False, 0)

        action_card.pack_start(btn_row, False, False, 4)
        box.pack_start(action_card, False, False, 0)
        return box

    def _make_stat_card(self, title: str, val_lbl: Any, sub_lbl: Any) -> Any:
        Gtk = self.Gtk
        card = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6)
        card.get_style_context().add_class("panel-card")
        t = Gtk.Label(label=title)
        t.set_halign(Gtk.Align.START)
        t.get_style_context().add_class("stat-title")
        val_lbl.set_halign(Gtk.Align.START)
        val_lbl.get_style_context().add_class("stat-value")
        sub_lbl.set_halign(Gtk.Align.START)
        sub_lbl.set_line_wrap(True)
        sub_lbl.get_style_context().add_class("subtitle-label")
        card.pack_start(t, False, False, 0)
        card.pack_start(val_lbl, False, False, 0)
        card.pack_start(sub_lbl, False, False, 0)
        return card

    def _refresh_overview(self) -> None:
        meta = get_face_profile_metadata(self.username)
        if not meta:
            user_enc = Path.home() / ".local" / "share" / "facelock" / "encodings"
            meta = get_face_profile_metadata(self.username, encodings_dir=user_enc)

        if meta:
            samples = meta.get("sample_count", 5)
            eng = meta.get("engine", "hybrid")
            self.card_face_val.set_text(f"Enrolled ({samples} Poses)")
            self.card_face_sub.set_text(f"AES-256-GCM encrypted • Engine: {eng}")
        else:
            self.card_face_val.set_text("Not Enrolled Yet")
            self.card_face_sub.set_text("Open Tab 2 to scan your face with the camera")

        fp_st = self.fp_engine.get_status(self.username)
        if fp_st.is_ready_for_auth:
            self.card_fp_val.set_text(f"Ready ({len(fp_st.enrolled_fingers)} Finger(s))")
            self.card_fp_sub.set_text(fp_st.device_name)
        elif fp_st.device_present:
            self.card_fp_val.set_text("Sensor Detected (Not Enrolled)")
            self.card_fp_sub.set_text(f"{fp_st.device_name} — Enroll in Tab 3")
        else:
            self.card_fp_val.set_text("No Fingerprint Reader")
            self.card_fp_sub.set_text("Face Lock + System Password active")

        self.card_pw_val.set_text("Active (Original PAM Password)")
        self.card_pw_sub.set_text(f"Account '{self.username}' verified via Linux PAM / unix_chkpwd")

        pam_st = self.pam_mgr.get_service_status()
        enabled_list = [v["file"] for v in pam_st.values() if v["enabled"]]
        if enabled_list:
            self.card_pam_val.set_text(f"Active on {len(enabled_list)} Services")
            self.card_pam_sub.set_text("Enabled: " + ", ".join(enabled_list))
        else:
            self.card_pam_val.set_text("Not Hooked Into PAM Yet")
            self.card_pam_sub.set_text("Click 'Auto-Configure Backend PAM' below to enable system-wide")

    def _on_one_click_backend_setup(self, *_args: Any) -> None:
        self._set_footer("Configuring backend PAM services & encrypted storage directories...")
        desired_services = self.cfg.get("pam_services", {})
        ok, msg = run_privileged_action(
            "auto_configure_backend",
            {
                "username": self.username,
                "config": self.cfg,
                "pam_services": desired_services,
            },
        )
        self._refresh_overview()
        self._refresh_pam_toggles()
        self._set_footer(f"{'✔' if ok else '✘'} {msg}")

    def _on_test_windows_hello_prompt(self, *_args: Any) -> None:
        self._stop_face_camera()
        repo_root = Path(__file__).resolve().parents[3]
        env = os.environ.copy()
        env["PYTHONPATH"] = str(repo_root / "src")
        subprocess.Popen(
            [
                sys.executable,
                "-m",
                "facelock.cli.main",
                "prompt",
                "--user",
                self.username,
                "--service",
                "test",
            ],
            env=env,
        )
        self._set_footer("Launched live Windows Hello prompt window for testing.")

    # =========================================================================
    # TAB 2: Face Lock Enrollment & Live Test
    # =========================================================================
    def _build_face_tab(self) -> Any:
        Gtk = self.Gtk
        outer = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=20)
        outer.set_margin_top(18)
        outer.set_margin_bottom(18)
        outer.set_margin_start(22)
        outer.set_margin_end(22)

        # Left column: Live circular HUD camera preview
        left_card = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10)
        left_card.get_style_context().add_class("panel-card")

        self.face_drawing_area = Gtk.DrawingArea()
        self.face_drawing_area.set_size_request(280, 280)
        self.face_drawing_area.set_halign(Gtk.Align.CENTER)
        self.face_drawing_area.connect("draw", self._on_draw_face_preview)
        left_card.pack_start(self.face_drawing_area, False, False, 0)

        self.face_live_status = Gtk.Label(label="Click 'Start Camera Preview' or 'Enroll My Face'")
        self.face_live_status.set_line_wrap(True)
        self.face_live_status.set_justify(Gtk.Justification.CENTER)
        self.face_live_status.get_style_context().add_class("subtitle-label")
        left_card.pack_start(self.face_live_status, False, False, 0)

        self.enroll_progress = Gtk.ProgressBar()
        self.enroll_progress.set_show_text(True)
        self.enroll_progress.set_text("Enrollment Progress: 0 / 5 Poses")
        left_card.pack_start(self.enroll_progress, False, False, 0)

        outer.pack_start(left_card, False, False, 0)

        # Right column: Controls & Guided Wizard
        right_card = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        right_card.get_style_context().add_class("panel-card")

        r_title = Gtk.Label(label="Face Lock Biometric Enrollment")
        r_title.set_halign(Gtk.Align.START)
        r_title.get_style_context().add_class("title-label")
        right_card.pack_start(r_title, False, False, 0)

        r_desc = Gtk.Label(
            label=(
                "FaceLock captures 5 multi-angle facial templates with illumination normalization and "
                "3-layer anti-spoofing liveness checks. Raw images are never saved — only AES-256-GCM "
                "encrypted mathematical feature vectors are stored."
            )
        )
        r_desc.set_halign(Gtk.Align.START)
        r_desc.set_line_wrap(True)
        r_desc.get_style_context().add_class("subtitle-label")
        right_card.pack_start(r_desc, False, False, 0)

        # Camera device dropdown
        cam_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
        cam_lbl = Gtk.Label(label="Camera Device:")
        self.cam_combo = Gtk.ComboBoxText()
        cams = enumerate_cameras()
        if cams:
            for c in cams:
                self.cam_combo.append(str(c["index"]), f"{c['name']} ({c['path']})")
            self.cam_combo.set_active(0)
        else:
            self.cam_combo.append("0", "/dev/video0 (Default V4L2 Camera)")
            self.cam_combo.set_active(0)
        self.cam_combo.connect("changed", self._on_camera_device_changed)
        cam_row.pack_start(cam_lbl, False, False, 0)
        cam_row.pack_start(self.cam_combo, True, True, 0)
        right_card.pack_start(cam_row, False, False, 0)

        # Action buttons
        btn_enroll = Gtk.Button(label="Enroll / Update My Face (5-Pose Guided Scan)")
        btn_enroll.get_style_context().add_class("primary-btn")
        btn_enroll.connect("clicked", lambda *_: self._start_face_camera(mode="enroll"))
        right_card.pack_start(btn_enroll, False, False, 0)

        btn_test = Gtk.Button(label="Test Live Face Recognition & Liveness")
        btn_test.get_style_context().add_class("success-btn")
        btn_test.connect("clicked", lambda *_: self._start_face_camera(mode="test"))
        right_card.pack_start(btn_test, False, False, 0)

        row_sub_btns = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        btn_preview = Gtk.Button(label="Camera Preview Only")
        btn_preview.get_style_context().add_class("secondary-btn")
        btn_preview.connect("clicked", lambda *_: self._start_face_camera(mode="preview"))
        row_sub_btns.pack_start(btn_preview, True, True, 0)

        btn_stop = Gtk.Button(label="Stop Camera")
        btn_stop.get_style_context().add_class("secondary-btn")
        btn_stop.connect("clicked", lambda *_: self._stop_face_camera())
        row_sub_btns.pack_start(btn_stop, True, True, 0)

        btn_delete_face = Gtk.Button(label="Delete Face Profile")
        btn_delete_face.get_style_context().add_class("danger-btn")
        btn_delete_face.connect("clicked", self._on_delete_face_profile)
        row_sub_btns.pack_start(btn_delete_face, True, True, 0)
        right_card.pack_start(row_sub_btns, False, False, 0)

        right_card.pack_start(Gtk.Separator(orientation=Gtk.Orientation.HORIZONTAL), False, False, 4)

        # Neural ONNX Upgrade Section
        onnx_status = (
            "Neural ONNX Engine (YuNet + SFace): ACTIVE"
            if self.face_engine.has_neural_models
            else "Active Engine: Built-in Offline Spatial Descriptor (LBP+HOG+DCT)"
        )
        self.onnx_label = Gtk.Label(label=onnx_status)
        self.onnx_label.set_halign(Gtk.Align.START)
        self.onnx_label.get_style_context().add_class("subtitle-label")
        right_card.pack_start(self.onnx_label, False, False, 0)

        btn_onnx = Gtk.Button(label="Download High-Accuracy OpenCV Zoo Neural Models (YuNet + SFace)")
        btn_onnx.get_style_context().add_class("secondary-btn")
        btn_onnx.connect("clicked", self._on_download_onnx_models)
        right_card.pack_start(btn_onnx, False, False, 0)

        outer.pack_start(right_card, True, True, 0)
        return outer

    def _on_camera_device_changed(self, combo: Any) -> None:
        cid = combo.get_active_id()
        if cid is not None and cid.isdigit():
            self.cfg_mgr.set("camera", "device_index", int(cid))
            self.cfg_mgr.save()

    def _start_face_camera(self, mode: str = "preview") -> None:
        self._stop_face_camera()
        self._cam_mode = mode
        self._hud_state = "scanning"
        self._hud_confidence = 0.0

        if mode == "enroll":
            self._enroll_samples = []
            self._enroll_last_capture = time.time()
            self.enroll_progress.set_fraction(0.0)
            self.enroll_progress.set_text("0 / 5 Poses Captured")
        elif mode == "test":
            self._test_liveness = LivenessState()
            self._test_profile = load_encrypted_face_profile(self.username)
            if not self._test_profile:
                user_enc = Path.home() / ".local" / "share" / "facelock" / "encodings"
                user_key = Path.home() / ".local" / "share" / "facelock" / "user_master.key"
                if (user_enc / f"{self.username}.enc").is_file():
                    from facelock.core.crypto import ensure_master_key

                    self._test_profile = load_encrypted_face_profile(
                        self.username,
                        encodings_dir=user_enc,
                        master_key=ensure_master_key(user_key),
                    )
            if not self._test_profile:
                self.face_live_status.set_text(
                    f"No face profile enrolled for '{self.username}'. Click 'Enroll / Update My Face' first."
                )
                return

        cam_idx = int(self.cam_combo.get_active_id() or 0)
        cap = cv2.VideoCapture(cam_idx)
        if not cap.isOpened():
            self._hud_state = "error"
            self.face_live_status.set_text(f"Unable to open camera /dev/video{cam_idx}.")
            self.face_drawing_area.queue_draw()
            return

        cap.set(cv2.CAP_PROP_FRAME_WIDTH, 640)
        cap.set(cv2.CAP_PROP_FRAME_HEIGHT, 480)
        self._cap = cap
        self._cam_timer_id = self.GLib.timeout_add(45, self._on_face_tab_tick)

    def _on_face_tab_tick(self) -> bool:
        if self._cap is None:
            return False

        self._scan_phase += 0.15
        ok, frame = self._cap.read()
        if not ok or frame is None:
            return True

        self._current_frame = frame
        det = self.face_engine.detect_face(frame)
        self._last_det = det

        if self._cam_mode == "preview":
            self._hud_state = "matched" if (det.detected and det.quality_ok) else "scanning"
            self.face_live_status.set_text(
                f"{det.quality_message} (Brightness: {int(det.brightness)}, Sharpness: {int(det.sharpness)})"
            )

        elif self._cam_mode == "enroll":
            step_idx = len(self._enroll_samples)
            if step_idx < 5:
                prompt = ENROLL_POSE_PROMPTS[step_idx]
                now = time.time()
                if det.detected and det.quality_ok and (now - self._enroll_last_capture) >= 1.05:
                    emb = self.face_engine.extract_embedding(frame, det)
                    self._enroll_samples.append(emb)
                    self._enroll_last_capture = now
                    new_count = len(self._enroll_samples)
                    self.enroll_progress.set_fraction(new_count / 5.0)
                    self.enroll_progress.set_text(f"Captured {new_count} / 5 Poses")
                    self._hud_confidence = new_count / 5.0
                    if new_count == 5:
                        self._finish_face_enrollment()
                        return False
                else:
                    self.face_live_status.set_text(f"{prompt}\n({det.quality_message})")

        elif self._cam_mode == "test" and self._test_profile:
            verified, conf, live_sc, msg, _ = self.face_engine.verify_frame_for_user(
                self.username,
                frame,
                liveness_state=self._test_liveness,
                profile_cache=self._test_profile,
            )
            self._hud_confidence = conf
            self._hud_state = "matched" if verified else "scanning"
            self.face_live_status.set_text(
                f"{'✔ MATCHED' if verified else 'Scanning'}: {msg} | Liveness: {int(live_sc * 100)}%"
            )

        self.face_drawing_area.queue_draw()
        return True

    def _finish_face_enrollment(self) -> None:
        self._hud_state = "matched"
        self.face_drawing_area.queue_draw()
        self._stop_face_camera()

        # Save to /etc/facelock/encodings/<user>.enc via privileged action (and local cache)
        ok, msg = run_privileged_action(
            "save_face_enrollment",
            {
                "username": self.username,
                "samples": self._enroll_samples,
            },
        )
        if not ok:
            # Also save to user-local fallback so testing works even without root elevation
            from facelock.core.crypto import ensure_master_key

            user_enc = Path.home() / ".local" / "share" / "facelock" / "encodings"
            user_key = Path.home() / ".local" / "share" / "facelock" / "user_master.key"
            self.face_engine.save_user_enrollment(
                self.username,
                self._enroll_samples,
                encodings_dir=user_enc,
                master_key=ensure_master_key(user_key),
            )
            msg = f"Saved face profile locally for {self.username} ({msg})"

        self.face_live_status.set_text(f"✔ Enrollment complete for '{self.username}'! ({msg})")
        self._set_footer(f"✔ Enrolled 5-pose AES-256-GCM face profile for '{self.username}'.")
        self._refresh_overview()

    def _on_delete_face_profile(self, *_args: Any) -> None:
        self._stop_face_camera()
        ok, msg = run_privileged_action("delete_face_enrollment", {"username": self.username})
        user_enc = Path.home() / ".local" / "share" / "facelock" / "encodings" / f"{self.username}.enc"
        user_enc.unlink(missing_ok=True)
        self.face_live_status.set_text(msg)
        self._set_footer(msg)
        self._refresh_overview()

    def _on_download_onnx_models(self, *_args: Any) -> None:
        self.onnx_label.set_text("Downloading YuNet & SFace ONNX models from OpenCV Zoo...")

        def _worker() -> None:
            ok, msg = self.face_engine.download_onnx_models(
                progress_cb=lambda s, _: self.GLib.idle_add(self.onnx_label.set_text, s)
            )
            self.GLib.idle_add(self.onnx_label.set_text, f"{'✔' if ok else '✘'} {msg}")
            self.GLib.idle_add(self._set_footer, msg)

        threading.Thread(target=_worker, daemon=True).start()

    def _on_draw_face_preview(self, widget: Any, cr: Any) -> bool:
        w = widget.get_allocated_width()
        h = widget.get_allocated_height()
        bbox = self._last_det.bbox if (self._last_det and self._last_det.detected) else None
        self._draw_camera_hud(
            cr,
            w,
            h,
            self._current_frame,
            bbox,
            self._scan_phase,
            state=self._hud_state,
            confidence=self._hud_confidence,
        )
        return False

    def _stop_face_camera(self) -> None:
        if self._cam_timer_id is not None:
            try:
                self.GLib.source_remove(self._cam_timer_id)
            except Exception:
                pass
            self._cam_timer_id = None
        if self._cap is not None:
            try:
                self._cap.release()
            except Exception:
                pass
            self._cap = None
        self._cam_mode = "idle"

    # =========================================================================
    # TAB 3: Fingerprint Setup
    # =========================================================================
    def _build_fingerprint_tab(self) -> Any:
        Gtk = self.Gtk
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=16)
        box.set_margin_top(20)
        box.set_margin_bottom(20)
        box.set_margin_start(24)
        box.set_margin_end(24)

        card = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        card.get_style_context().add_class("panel-card")

        title = Gtk.Label(label="Fingerprint Reader Hardware & Enrollment (fprintd)")
        title.set_halign(Gtk.Align.START)
        title.get_style_context().add_class("title-label")
        card.pack_start(title, False, False, 0)

        self.fp_hw_label = Gtk.Label(label="Scanning for fingerprint hardware...")
        self.fp_hw_label.set_halign(Gtk.Align.START)
        self.fp_hw_label.set_line_wrap(True)
        self.fp_hw_label.get_style_context().add_class("stat-value")
        card.pack_start(self.fp_hw_label, False, False, 0)

        self.fp_enrolled_label = Gtk.Label(label="")
        self.fp_enrolled_label.set_halign(Gtk.Align.START)
        self.fp_enrolled_label.set_line_wrap(True)
        self.fp_enrolled_label.get_style_context().add_class("subtitle-label")
        card.pack_start(self.fp_enrolled_label, False, False, 0)

        # Finger selection combo
        f_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
        f_lbl = Gtk.Label(label="Finger to Enroll:")
        self.finger_combo = Gtk.ComboBoxText()
        for fid, flabel in FINGER_NAMES:
            self.finger_combo.append(fid, flabel)
        self.finger_combo.set_active(0)
        f_row.pack_start(f_lbl, False, False, 0)
        f_row.pack_start(self.finger_combo, False, False, 0)
        card.pack_start(f_row, False, False, 4)

        btn_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
        btn_enroll_fp = Gtk.Button(label="Enroll Selected Finger")
        btn_enroll_fp.get_style_context().add_class("primary-btn")
        btn_enroll_fp.connect("clicked", self._on_enroll_fingerprint)
        btn_row.pack_start(btn_enroll_fp, False, False, 0)

        btn_verify_fp = Gtk.Button(label="Test Fingerprint Verification")
        btn_verify_fp.get_style_context().add_class("success-btn")
        btn_verify_fp.connect("clicked", self._on_verify_fingerprint)
        btn_row.pack_start(btn_verify_fp, False, False, 0)

        btn_del_fp = Gtk.Button(label="Delete Enrolled Fingerprints")
        btn_del_fp.get_style_context().add_class("danger-btn")
        btn_del_fp.connect("clicked", self._on_delete_fingerprints)
        btn_row.pack_start(btn_del_fp, False, False, 0)

        btn_refresh_fp = Gtk.Button(label="Rescan Hardware")
        btn_refresh_fp.get_style_context().add_class("secondary-btn")
        btn_refresh_fp.connect("clicked", lambda *_: self._refresh_fingerprint_status())
        btn_row.pack_start(btn_refresh_fp, False, False, 0)

        card.pack_start(btn_row, False, False, 4)

        self.fp_action_status = Gtk.Label(
            label="If your machine has a supported fingerprint reader, enroll it here to unlock via the Fingerprint icon in Kali Hello."
        )
        self.fp_action_status.set_halign(Gtk.Align.START)
        self.fp_action_status.set_line_wrap(True)
        self.fp_action_status.get_style_context().add_class("subtitle-label")
        card.pack_start(self.fp_action_status, False, False, 4)

        box.pack_start(card, False, False, 0)
        self._refresh_fingerprint_status()
        return box

    def _refresh_fingerprint_status(self) -> None:
        st = self.fp_engine.get_status(self.username)
        if st.device_present:
            self.fp_hw_label.set_text(f"Sensor Ready: {st.device_name}")
        else:
            self.fp_hw_label.set_text(st.device_name)

        if st.enrolled_fingers:
            self.fp_enrolled_label.set_text(
                f"Enrolled fingers for '{self.username}': {', '.join(st.enrolled_fingers)}"
            )
        else:
            self.fp_enrolled_label.set_text(
                f"No fingerprints enrolled yet for '{self.username}'."
                + ("" if st.fprintd_installed else " (Package 'fprintd' can be installed via install.sh)")
            )

    def _on_enroll_fingerprint(self, *_args: Any) -> None:
        finger = self.finger_combo.get_active_id() or "right-index-finger"
        self.fp_action_status.set_text(f"Starting fingerprint enrollment for {finger}...")

        def _worker() -> None:
            ok, msg = self.fp_engine.enroll(
                self.username,
                finger=finger,
                status_cb=lambda s: self.GLib.idle_add(self.fp_action_status.set_text, s),
            )
            self.GLib.idle_add(self.fp_action_status.set_text, f"{'✔' if ok else '✘'} {msg}")
            self.GLib.idle_add(self._refresh_fingerprint_status)
            self.GLib.idle_add(self._refresh_overview)

        threading.Thread(target=_worker, daemon=True).start()

    def _on_verify_fingerprint(self, *_args: Any) -> None:
        self.fp_action_status.set_text("Touch your fingerprint sensor now...")

        def _worker() -> None:
            ok, msg = self.fp_engine.verify(
                self.username,
                status_cb=lambda s: self.GLib.idle_add(self.fp_action_status.set_text, s),
            )
            self.GLib.idle_add(self.fp_action_status.set_text, f"{'✔' if ok else '✘'} {msg}")

        threading.Thread(target=_worker, daemon=True).start()

    def _on_delete_fingerprints(self, *_args: Any) -> None:
        ok, msg = self.fp_engine.delete_enrolled(self.username)
        self.fp_action_status.set_text(f"{'✔' if ok else '✘'} {msg}")
        self._refresh_fingerprint_status()
        self._refresh_overview()

    # =========================================================================
    # TAB 4: Folder Lock (Encrypted Vaults)
    # =========================================================================
    def _build_folder_vault_tab(self) -> Any:
        Gtk = self.Gtk
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=14)
        box.set_margin_top(18)
        box.set_margin_bottom(18)
        box.set_margin_start(22)
        box.set_margin_end(22)

        card = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10)
        card.get_style_context().add_class("panel-card")

        title = Gtk.Label(label="AES-256-GCM Encrypted Folder Lock & Vaults")
        title.set_halign(Gtk.Align.START)
        title.get_style_context().add_class("title-label")
        card.pack_start(title, False, False, 0)

        desc = Gtk.Label(
            label=(
                "Lock any sensitive folder with AES-256-GCM encryption. When a folder is locked, its files are "
                "packed into an authenticated encrypted vault and replaced with a Kali Hello launcher. "
                "Unlocking requires passing the Windows Hello prompt (Face Lock, Fingerprint, or System Password)."
            )
        )
        desc.set_halign(Gtk.Align.START)
        desc.set_line_wrap(True)
        desc.get_style_context().add_class("subtitle-label")
        card.pack_start(desc, False, False, 0)

        btn_bar = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
        btn_add_lock = Gtk.Button(label="+ Select & Lock a Folder")
        btn_add_lock.get_style_context().add_class("primary-btn")
        btn_add_lock.connect("clicked", self._on_select_and_lock_folder)
        btn_bar.pack_start(btn_add_lock, False, False, 0)

        btn_unlock = Gtk.Button(label="Unlock Selected Folder (Kali Hello Prompt)")
        btn_unlock.get_style_context().add_class("success-btn")
        btn_unlock.connect("clicked", self._on_unlock_selected_vault)
        btn_bar.pack_start(btn_unlock, False, False, 0)

        btn_relock = Gtk.Button(label="Re-Lock Selected Folder")
        btn_relock.get_style_context().add_class("secondary-btn")
        btn_relock.connect("clicked", self._on_relock_selected_vault)
        btn_bar.pack_start(btn_relock, False, False, 0)

        btn_lock_all = Gtk.Button(label="Lock All Unlocked Vaults")
        btn_lock_all.get_style_context().add_class("danger-btn")
        btn_lock_all.connect("clicked", self._on_lock_all_vaults)
        btn_bar.pack_start(btn_lock_all, False, False, 0)

        card.pack_start(btn_bar, False, False, 4)

        # Vault list table (TreeView)
        self.vault_store = Gtk.ListStore(str, str, str, str)  # path, status, items, timestamp
        self.vault_tree = Gtk.TreeView(model=self.vault_store)
        for idx, col_title in enumerate(["Protected Folder Path", "Status", "Items", "Last Updated"]):
            renderer = Gtk.CellRendererText()
            col = Gtk.TreeViewColumn(col_title, renderer, text=idx)
            col.set_resizable(True)
            if idx == 0:
                col.set_expand(True)
            self.vault_tree.append_column(col)

        scroll = Gtk.ScrolledWindow()
        scroll.set_min_content_height(260)
        scroll.add(self.vault_tree)
        card.pack_start(scroll, True, True, 0)

        box.pack_start(card, True, True, 0)
        self._refresh_vault_list()
        return box

    def _refresh_vault_list(self) -> None:
        self.vault_store.clear()
        for v in self.vault_mgr.list_vaults(owner=self.username):
            self.vault_store.append(
                [
                    str(v.get("folder_path", "")),
                    str(v.get("status", "UNKNOWN")),
                    str(v.get("item_count", 0)),
                    str(v.get("locked_at", "")),
                ]
            )

    def _get_selected_vault_path(self) -> Optional[Path]:
        sel = self.vault_tree.get_selection()
        model, treeiter = sel.get_selected()
        if treeiter is not None:
            return Path(model[treeiter][0])
        return None

    def _on_select_and_lock_folder(self, *_args: Any) -> None:
        Gtk = self.Gtk
        dlg = Gtk.FileChooserDialog(
            title="Select Folder to Lock with FaceLock (AES-256-GCM)",
            parent=self.win,
            action=Gtk.FileChooserAction.SELECT_FOLDER,
        )
        dlg.add_buttons(
            Gtk.STOCK_CANCEL,
            Gtk.ResponseType.CANCEL,
            "Encrypt & Lock Folder",
            Gtk.ResponseType.OK,
        )
        resp = dlg.run()
        chosen = dlg.get_filename()
        dlg.destroy()

        if resp == Gtk.ResponseType.OK and chosen:
            ok, msg = self.vault_mgr.lock_folder(Path(chosen), owner=self.username)
            self._set_footer(f"{'✔' if ok else '✘'} {msg}")
            self._refresh_vault_list()

    def _on_unlock_selected_vault(self, *_args: Any) -> None:
        target = self._get_selected_vault_path()
        if target is None:
            self._set_footer("Select a locked folder from the list first.")
            return

        # Require Windows Hello authentication prompt before unlocking!
        rc = launch_authentication_prompt(
            username=self.username,
            service="folder-vault",
            title_override=f"Unlock Protected Folder: {target.name}",
        )
        if rc != 0:
            self._set_footer("Folder unlock cancelled — authentication not completed.")
            return

        ok, msg = self.vault_mgr.unlock_folder(target, open_in_file_manager=True)
        self._set_footer(f"{'✔' if ok else '✘'} {msg}")
        self._refresh_vault_list()

    def _on_relock_selected_vault(self, *_args: Any) -> None:
        target = self._get_selected_vault_path()
        if target is None:
            self._set_footer("Select an unlocked folder from the list first.")
            return
        ok, msg = self.vault_mgr.lock_folder(target, owner=self.username)
        self._set_footer(f"{'✔' if ok else '✘'} {msg}")
        self._refresh_vault_list()

    def _on_lock_all_vaults(self, *_args: Any) -> None:
        res = self.vault_mgr.lock_all_unlocked(owner=self.username)
        self._refresh_vault_list()
        self._set_footer(f"Re-locked {len(res)} unlocked folder vault(s).")

    # =========================================================================
    # TAB 5: Where to Use (PAM Targets & Security Settings)
    # =========================================================================
    def _build_pam_security_tab(self) -> Any:
        Gtk = self.Gtk
        outer = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=18)
        outer.set_margin_top(18)
        outer.set_margin_bottom(18)
        outer.set_margin_start(22)
        outer.set_margin_end(22)

        # Left panel: PAM Service Toggles
        pam_card = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10)
        pam_card.get_style_context().add_class("panel-card")

        p_title = Gtk.Label(label="Where to Use Kali Hello (PAM Hooks)")
        p_title.set_halign(Gtk.Align.START)
        p_title.get_style_context().add_class("title-label")
        pam_card.pack_start(p_title, False, False, 0)

        p_sub = Gtk.Label(
            label="Toggle where the Windows Hello Face/Fingerprint/Password prompt should appear:"
        )
        p_sub.set_halign(Gtk.Align.START)
        p_sub.set_line_wrap(True)
        p_sub.get_style_context().add_class("subtitle-label")
        pam_card.pack_start(p_sub, False, False, 0)

        self.pam_checkboxes: Dict[str, Any] = {}
        st_map = self.pam_mgr.get_service_status()
        for key, info in PAM_TARGETS.items():
            st = st_map.get(key, {})
            installed = st.get("installed_on_system", False)
            enabled = st.get("enabled", bool(self.cfg.get("pam_services", {}).get(key, False)))
            cb = Gtk.CheckButton(
                label=f"{info['label']} (/etc/pam.d/{info['file']})"
                + ("" if installed else " [not installed]")
            )
            cb.set_active(enabled and installed)
            cb.set_sensitive(installed)
            self.pam_checkboxes[key] = cb
            pam_card.pack_start(cb, False, False, 2)

        pam_btn_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
        btn_apply_pam = Gtk.Button(label="Apply & Sync PAM Backend")
        btn_apply_pam.get_style_context().add_class("primary-btn")
        btn_apply_pam.connect("clicked", self._on_apply_pam_and_security)
        pam_btn_row.pack_start(btn_apply_pam, False, False, 0)

        btn_restore_pam = Gtk.Button(label="Emergency Restore Default PAM")
        btn_restore_pam.get_style_context().add_class("danger-btn")
        btn_restore_pam.connect("clicked", self._on_emergency_restore_pam)
        pam_btn_row.pack_start(btn_restore_pam, False, False, 0)

        pam_card.pack_start(pam_btn_row, False, False, 8)
        outer.pack_start(pam_card, True, True, 0)

        # Right panel: Security & Liveness Policy
        sec_card = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10)
        sec_card.get_style_context().add_class("panel-card")

        s_title = Gtk.Label(label="Security & Anti-Spoofing Policy")
        s_title.set_halign(Gtk.Align.START)
        s_title.get_style_context().add_class("title-label")
        sec_card.pack_start(s_title, False, False, 0)

        # Default sign-in method dropdown
        dm_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
        dm_row.pack_start(Gtk.Label(label="Default Prompt Method:"), False, False, 0)
        self.default_method_combo = Gtk.ComboBoxText()
        self.default_method_combo.append(METHOD_FACE, "Face Lock (Kali Hello Camera)")
        self.default_method_combo.append(METHOD_FINGERPRINT, "Fingerprint Sensor (fprintd)")
        self.default_method_combo.append(METHOD_PASSWORD, "System Password (PAM)")
        self.default_method_combo.set_active_id(self.cfg.get("default_method", METHOD_FACE))
        dm_row.pack_start(self.default_method_combo, True, True, 0)
        sec_card.pack_start(dm_row, False, False, 0)

        # Liveness strictness dropdown
        lv_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
        lv_row.pack_start(Gtk.Label(label="Anti-Spoofing Liveness:"), False, False, 0)
        self.liveness_combo = Gtk.ComboBoxText()
        self.liveness_combo.append("strict", "Strict (Multi-frame motion + blink + texture)")
        self.liveness_combo.append("balanced", "Balanced (Recommended anti-photo check)")
        self.liveness_combo.append("fast", "Fast (Quick texture + landmark check)")
        self.liveness_combo.set_active_id(
            str(self.cfg.get("face_auth", {}).get("liveness_mode", "balanced"))
        )
        lv_row.pack_start(self.liveness_combo, True, True, 0)
        sec_card.pack_start(lv_row, False, False, 0)

        # Match confidence slider
        th_lbl = Gtk.Label(label="Face Match Strictness Threshold (0.65 - 0.90):")
        th_lbl.set_halign(Gtk.Align.START)
        sec_card.pack_start(th_lbl, False, False, 0)
        self.threshold_scale = Gtk.Scale.new_with_range(Gtk.Orientation.HORIZONTAL, 0.65, 0.90, 0.01)
        self.threshold_scale.set_value(
            float(self.cfg.get("face_auth", {}).get("match_threshold", 0.76))
        )
        sec_card.pack_start(self.threshold_scale, False, False, 0)

        # Max attempts before password lockout
        att_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
        att_row.pack_start(Gtk.Label(label="Max Failed Biometric Attempts:"), False, False, 0)
        self.max_attempts_spin = Gtk.SpinButton.new_with_range(2, 10, 1)
        self.max_attempts_spin.set_value(
            float(self.cfg.get("security", {}).get("max_biometric_attempts", 4))
        )
        att_row.pack_start(self.max_attempts_spin, False, False, 0)
        sec_card.pack_start(att_row, False, False, 0)

        self.ssh_skip_cb = Gtk.CheckButton(label="Bypass local biometrics on remote SSH sessions")
        self.ssh_skip_cb.set_active(bool(self.cfg.get("security", {}).get("skip_on_ssh", True)))
        sec_card.pack_start(self.ssh_skip_cb, False, False, 0)

        self.autolock_cb = Gtk.CheckButton(label="Auto-relock unlocked Folder Vaults on screen lock")
        self.autolock_cb.set_active(
            bool(self.cfg.get("security", {}).get("auto_lock_vaults_on_screensaver", True))
        )
        sec_card.pack_start(self.autolock_cb, False, False, 0)

        btn_save_sec = Gtk.Button(label="Save Security Policy")
        btn_save_sec.get_style_context().add_class("success-btn")
        btn_save_sec.connect("clicked", self._on_apply_pam_and_security)
        sec_card.pack_start(btn_save_sec, False, False, 6)

        outer.pack_start(sec_card, True, True, 0)
        return outer

    def _refresh_pam_toggles(self) -> None:
        st_map = self.pam_mgr.get_service_status()
        for key, cb in self.pam_checkboxes.items():
            st = st_map.get(key, {})
            if st.get("installed_on_system"):
                cb.set_active(bool(st.get("enabled")))

    def _on_apply_pam_and_security(self, *_args: Any) -> None:
        self.cfg_mgr.set_top("default_method", self.default_method_combo.get_active_id() or METHOD_FACE)
        self.cfg_mgr.set("face_auth", "liveness_mode", self.liveness_combo.get_active_id() or "balanced")
        self.cfg_mgr.set("face_auth", "match_threshold", round(self.threshold_scale.get_value(), 2))
        self.cfg_mgr.set("security", "max_biometric_attempts", int(self.max_attempts_spin.get_value()))
        self.cfg_mgr.set("security", "skip_on_ssh", bool(self.ssh_skip_cb.get_active()))
        self.cfg_mgr.set(
            "security", "auto_lock_vaults_on_screensaver", bool(self.autolock_cb.get_active())
        )

        pam_desired: Dict[str, bool] = {}
        for key, cb in self.pam_checkboxes.items():
            pam_desired[key] = bool(cb.get_active())
            self.cfg_mgr.set("pam_services", key, bool(cb.get_active()))

        self.cfg_mgr.save()
        ok, msg = run_privileged_action(
            "auto_configure_backend",
            {
                "username": self.username,
                "config": self.cfg_mgr.data,
                "pam_services": pam_desired,
            },
        )
        self._refresh_pam_toggles()
        self._refresh_overview()
        self._set_footer(f"{'✔' if ok else '✘'} {msg}")

    def _on_emergency_restore_pam(self, *_args: Any) -> None:
        ok, msg = run_privileged_action("restore_pam", {})
        self._refresh_pam_toggles()
        self._refresh_overview()
        self._set_footer(f"{'✔' if ok else '✘'} {msg}")

    # =========================================================================
    # TAB 6: Security Audit Log
    # =========================================================================
    def _build_audit_tab(self) -> Any:
        Gtk = self.Gtk
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        box.set_margin_top(18)
        box.set_margin_bottom(18)
        box.set_margin_start(22)
        box.set_margin_end(22)

        top = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
        lbl = Gtk.Label(label="Recent Authentication Events (/var/log/facelock/audit.log)")
        lbl.get_style_context().add_class("title-label")
        top.pack_start(lbl, False, False, 0)

        btn_ref = Gtk.Button(label="Refresh Audit Log")
        btn_ref.get_style_context().add_class("secondary-btn")
        btn_ref.connect("clicked", lambda *_: self._refresh_audit_log())
        top.pack_end(btn_ref, False, False, 0)
        box.pack_start(top, False, False, 0)

        self.audit_store = Gtk.ListStore(str, str, str, str, str, str)
        tree = Gtk.TreeView(model=self.audit_store)
        cols = ["Timestamp", "User", "Service", "Method", "Result", "Details / Scores"]
        for idx, ctitle in enumerate(cols):
            rend = Gtk.CellRendererText()
            col = Gtk.TreeViewColumn(ctitle, rend, text=idx)
            col.set_resizable(True)
            if idx == 5:
                col.set_expand(True)
            tree.append_column(col)

        scroll = Gtk.ScrolledWindow()
        scroll.set_min_content_height(380)
        scroll.add(tree)
        box.pack_start(scroll, True, True, 0)
        self._refresh_audit_log()
        return box

    def _refresh_audit_log(self) -> None:
        self.audit_store.clear()
        for ev in read_recent_events(limit=120):
            details = ev.get("reason", "")
            if "confidence" in ev:
                details += f" [match={int(float(ev['confidence']) * 100)}%]"
            if "liveness" in ev:
                details += f" [live={int(float(ev['liveness']) * 100)}%]"
            self.audit_store.append(
                [
                    str(ev.get("timestamp", "")),
                    str(ev.get("username", "")),
                    str(ev.get("service", "")),
                    str(ev.get("method", "")),
                    str(ev.get("status", "")),
                    details.strip(),
                ]
            )

    def _on_destroy(self, *_args: Any) -> None:
        self._stop_face_camera()
        if self.Gtk.main_level() > 0:
            self.Gtk.main_quit()

    def run(self) -> None:
        self.Gtk.main()


def launch_control_center() -> int:
    app = FaceLockControlCenter()
    app.run()
    return 0
