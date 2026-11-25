"""
Windows Hello Sign-in Options Control Center for Kali Linux — Made by Muheeb.

Clean, simple Windows 11 Sign-in Options interface:
  - Left Panel: Facial Recognition (Kali Hello) circular scanner + 1-click setup & popup test
  - Right Panel:
      * Fingerprint Recognition (auto-detected via fprintd)
      * System Password (auto-configured original Linux password)
      * Startup Keyring Lock Fix (eliminates post-login Keyring/KWallet password prompt)
      * Protected Folder Vaults (AES-256-GCM lock/unlock with Windows Hello prompt)
      * System PAM Protection Status (sudo, Login, Lock Screen, Polkit)
      * Author & Support footer (Muheeb Bin Nadeem)
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

from facelock.config import ConfigManager, detect_active_username
from facelock.constants import (
    ENCODINGS_DIR,
    INSTALL_LIB_DIR,
    METHOD_FACE,
    METHOD_FINGERPRINT,
    METHOD_PASSWORD,
)
from facelock.core.crypto import ensure_master_key, load_encrypted_face_profile
from facelock.core.face_engine import (
    FaceBiometricEngine,
    FaceDetectionResult,
    LivenessState,
    enumerate_cameras,
)
from facelock.core.fingerprint_engine import FingerprintEngine
from facelock.core.folder_lock import FolderVaultManager
from facelock.core.keyring_manager import enable_auto_unlock_keyring, get_keyring_status
from facelock.core.pam_manager import PamManager
from facelock.ui.prompt_window import launch_authentication_prompt


def run_privileged_action(action: str, payload: Dict[str, Any]) -> Tuple[bool, str]:
    """Run a backend action directly if permitted, or elevate via pkexec when needed."""
    from facelock.cli.privileged_helper import execute_privileged_payload

    if os.geteuid() == 0:
        return execute_privileged_payload(action, payload)

    if action in ("save_face_enrollment", "delete_face_enrollment"):
        ok, msg = execute_privileged_payload(action, payload)
        if ok:
            return ok, msg

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
            return True, out or "Updated successfully"
        return False, err or out or f"Exited with code {res.returncode}"
    except Exception as exc:
        return False, str(exc)
    finally:
        tmp_path.unlink(missing_ok=True)


class FaceLockControlCenter:
    """Windows 11 Sign-in Options style Control Center for Kali Linux."""

    def __init__(self) -> None:
        import gi

        gi.require_version("Gdk", "3.0")
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

        self._cap: Optional[cv2.VideoCapture] = None
        self._cam_timer_id: Optional[int] = None
        self._current_frame: Optional[np.ndarray] = None
        self._last_det: Optional[FaceDetectionResult] = None
        self._scan_phase = 0.0
        self._hud_state = "scanning"
        self._hud_confidence = 0.0
        self._cam_mode = "idle"  # idle | enroll | test
        self._enroll_samples: List[Dict[str, List[float]]] = []
        self._enroll_last_capture = 0.0
        self._test_liveness = LivenessState()
        self._test_profile: Optional[Dict[str, Any]] = None

        self._build_ui()
        self._refresh_all_statuses()

    def _build_ui(self) -> None:
        Gtk = self.Gtk
        self.win = Gtk.Window(title="Windows Hello • Kali Sign-in Options (Made by Muheeb)")
        self.win.set_default_size(940, 650)
        self.win.set_position(Gtk.WindowPosition.CENTER)
        self.win.connect("destroy", self._on_destroy)

        root = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=0)
        self.win.add(root)

        # --- Top Header ---
        top_bar = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=12)
        top_bar.set_margin_top(14)
        top_bar.set_margin_bottom(12)
        top_bar.set_margin_start(22)
        top_bar.set_margin_end(22)

        title_col = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=2)
        t_lbl = Gtk.Label(label=f"Accounts  ›  Sign-in options ({self.username})")
        t_lbl.set_halign(Gtk.Align.START)
        t_lbl.get_style_context().add_class("title-label")
        s_lbl = Gtk.Label(
            label="Windows Hello Face Lock, Fingerprint, Password, Startup Keyring Fix & Folder Vaults"
        )
        s_lbl.set_halign(Gtk.Align.START)
        s_lbl.get_style_context().add_class("subtitle-label")
        title_col.pack_start(t_lbl, False, False, 0)
        title_col.pack_start(s_lbl, False, False, 0)
        top_bar.pack_start(title_col, True, True, 0)

        self.system_badge = Gtk.Label(label="✔ HELLO ACTIVE")
        self.system_badge.get_style_context().add_class("header-badge")
        top_bar.pack_end(self.system_badge, False, False, 0)

        root.pack_start(top_bar, False, False, 0)
        root.pack_start(Gtk.Separator(orientation=Gtk.Orientation.HORIZONTAL), False, False, 0)

        # --- Two-Column Body ---
        body = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=16)
        body.set_margin_top(14)
        body.set_margin_bottom(10)
        body.set_margin_start(22)
        body.set_margin_end(22)
        root.pack_start(body, True, True, 0)

        # =====================================================================
        # LEFT COLUMN: Facial Recognition (Windows Hello Face)
        # =====================================================================
        left_card = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10)
        left_card.set_size_request(320, -1)
        left_card.get_style_context().add_class("panel-card")

        cam_header = Gtk.Label(label="Facial recognition (Kali Hello)")
        cam_header.get_style_context().add_class("section-title")
        left_card.pack_start(cam_header, False, False, 0)

        self.face_status_badge = Gtk.Label(label="Checking Face Profile...")
        self.face_status_badge.get_style_context().add_class("stat-value")
        left_card.pack_start(self.face_status_badge, False, False, 0)

        self.face_drawing_area = Gtk.DrawingArea()
        self.face_drawing_area.set_size_request(230, 230)
        self.face_drawing_area.set_halign(Gtk.Align.CENTER)
        self.face_drawing_area.connect("draw", self._on_draw_face_preview)
        left_card.pack_start(self.face_drawing_area, False, False, 2)

        self.face_live_status = Gtk.Label(
            label="Click 'Set up Face Lock' and look at the camera for 3 seconds."
        )
        self.face_live_status.set_line_wrap(True)
        self.face_live_status.set_justify(Gtk.Justification.CENTER)
        self.face_live_status.get_style_context().add_class("subtitle-label")
        left_card.pack_start(self.face_live_status, False, False, 0)

        self.enroll_progress = Gtk.ProgressBar()
        self.enroll_progress.set_show_text(True)
        self.enroll_progress.set_text("Ready")
        left_card.pack_start(self.enroll_progress, False, False, 0)

        self.btn_enroll_face = Gtk.Button(label="Set up Face Lock")
        self.btn_enroll_face.get_style_context().add_class("primary-btn")
        self.btn_enroll_face.connect("clicked", lambda *_: self._start_face_camera(mode="enroll"))
        left_card.pack_start(self.btn_enroll_face, False, False, 0)

        sub_face_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        btn_test_cam = Gtk.Button(label="Test Match")
        btn_test_cam.get_style_context().add_class("secondary-btn")
        btn_test_cam.connect("clicked", lambda *_: self._start_face_camera(mode="test"))
        sub_face_row.pack_start(btn_test_cam, True, True, 0)

        btn_del_face = Gtk.Button(label="Remove")
        btn_del_face.get_style_context().add_class("danger-btn")
        btn_del_face.connect("clicked", self._on_delete_face_profile)
        sub_face_row.pack_start(btn_del_face, False, False, 0)
        left_card.pack_start(sub_face_row, False, False, 0)

        left_card.pack_start(Gtk.Separator(orientation=Gtk.Orientation.HORIZONTAL), False, False, 4)

        btn_test_popup = Gtk.Button(label="★ Test Windows Hello Popup")
        btn_test_popup.get_style_context().add_class("success-btn")
        btn_test_popup.connect("clicked", self._on_test_windows_hello_prompt)
        left_card.pack_start(btn_test_popup, False, False, 0)

        body.pack_start(left_card, False, False, 0)

        # =====================================================================
        # RIGHT COLUMN: Ways to Sign In, Keyring Fix, Folder Lock, Support
        # =====================================================================
        right_col = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10)
        body.pack_start(right_col, True, True, 0)

        # --- Card 1: Ways to sign in (Windows 11 Settings style rows) ---
        methods_card = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        methods_card.get_style_context().add_class("panel-card")

        m_hdr_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        m_title = Gtk.Label(label="Ways to sign in")
        m_title.set_halign(Gtk.Align.START)
        m_title.get_style_context().add_class("section-title")
        m_hdr_row.pack_start(m_title, True, True, 0)

        def_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=6)
        def_lbl = Gtk.Label(label="Default method:")
        def_lbl.get_style_context().add_class("subtitle-label")
        self.default_combo = Gtk.ComboBoxText()
        self.default_combo.append(METHOD_FACE, "Face Lock")
        self.default_combo.append(METHOD_FINGERPRINT, "Fingerprint")
        self.default_combo.append(METHOD_PASSWORD, "Password")
        self.default_combo.set_active_id(self.cfg.get("default_method", METHOD_FACE))
        self.default_combo.connect("changed", self._on_default_method_changed)
        def_box.pack_start(def_lbl, False, False, 0)
        def_box.pack_start(self.default_combo, False, False, 0)
        m_hdr_row.pack_end(def_box, False, False, 0)
        methods_card.pack_start(m_hdr_row, False, False, 0)

        # Row A: Fingerprint
        fp_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
        fp_row.get_style_context().add_class("hello-row-card")
        fp_icon = Gtk.Image.new_from_icon_name("auth-fingerprint-symbolic", Gtk.IconSize.DND)
        fp_row.pack_start(fp_icon, False, False, 2)

        fp_info = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=2)
        fp_t = Gtk.Label(label="Fingerprint recognition (fprintd)")
        fp_t.set_halign(Gtk.Align.START)
        fp_t.get_style_context().add_class("stat-value")
        self.fp_status_lbl = Gtk.Label(label="Checking sensor...")
        self.fp_status_lbl.set_halign(Gtk.Align.START)
        self.fp_status_lbl.set_line_wrap(True)
        self.fp_status_lbl.get_style_context().add_class("subtitle-label")
        fp_info.pack_start(fp_t, False, False, 0)
        fp_info.pack_start(self.fp_status_lbl, False, False, 0)
        fp_row.pack_start(fp_info, True, True, 0)

        self.btn_fp_enroll = Gtk.Button(label="Set up")
        self.btn_fp_enroll.get_style_context().add_class("secondary-btn")
        self.btn_fp_enroll.set_valign(Gtk.Align.CENTER)
        self.btn_fp_enroll.connect("clicked", self._on_enroll_fingerprint)
        fp_row.pack_end(self.btn_fp_enroll, False, False, 0)
        methods_card.pack_start(fp_row, False, False, 0)

        # Row B: System Password
        pw_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
        pw_row.get_style_context().add_class("hello-row-card")
        pw_icon = Gtk.Image.new_from_icon_name("dialog-password-symbolic", Gtk.IconSize.DND)
        pw_row.pack_start(pw_icon, False, False, 2)
        pw_info = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=1)
        pw_t = Gtk.Label(label="Password (Original Linux Account)")
        pw_t.set_halign(Gtk.Align.START)
        pw_t.get_style_context().add_class("stat-value")
        pw_sub = Gtk.Label(label=f"✔ Ready — Uses '{self.username}' password automatically")
        pw_sub.set_halign(Gtk.Align.START)
        pw_sub.get_style_context().add_class("status-ok")
        pw_info.pack_start(pw_t, False, False, 0)
        pw_info.pack_start(pw_sub, False, False, 0)
        pw_row.pack_start(pw_info, True, True, 0)
        methods_card.pack_start(pw_row, False, False, 0)

        # Row C: Startup Keyring Lock Fix (stops post-login keyring prompt!)
        kr_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
        kr_row.get_style_context().add_class("hello-row-card")
        kr_icon = Gtk.Image.new_from_icon_name("changes-allow-symbolic", Gtk.IconSize.DND)
        kr_row.pack_start(kr_icon, False, False, 2)
        kr_info = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=2)
        kr_t = Gtk.Label(label="Startup Keyring Lock (No Prompt After Login)")
        kr_t.set_halign(Gtk.Align.START)
        kr_t.get_style_context().add_class("stat-value")
        self.kr_status_lbl = Gtk.Label(label="Checking login keyring...")
        self.kr_status_lbl.set_halign(Gtk.Align.START)
        self.kr_status_lbl.set_line_wrap(True)
        self.kr_status_lbl.get_style_context().add_class("subtitle-label")
        kr_info.pack_start(kr_t, False, False, 0)
        kr_info.pack_start(self.kr_status_lbl, False, False, 0)
        kr_row.pack_start(kr_info, True, True, 0)

        self.btn_fix_keyring = Gtk.Button(label="Fix Keyring Prompt")
        self.btn_fix_keyring.get_style_context().add_class("warn-btn")
        self.btn_fix_keyring.set_valign(Gtk.Align.CENTER)
        self.btn_fix_keyring.connect("clicked", self._on_fix_keyring_clicked)
        kr_row.pack_end(self.btn_fix_keyring, False, False, 0)
        methods_card.pack_start(kr_row, False, False, 0)

        right_col.pack_start(methods_card, False, False, 0)

        # --- Card 2: Folder Lock Vaults ---
        vault_card = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        vault_card.get_style_context().add_class("panel-card")

        v_top = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
        v_title = Gtk.Label(label="Protected Folder Vaults (AES-256-GCM)")
        v_title.set_halign(Gtk.Align.START)
        v_title.get_style_context().add_class("section-title")
        v_top.pack_start(v_title, True, True, 0)

        btn_lock_folder = Gtk.Button(label="+ Lock Folder")
        btn_lock_folder.get_style_context().add_class("primary-btn")
        btn_lock_folder.connect("clicked", self._on_select_and_lock_folder)
        v_top.pack_end(btn_lock_folder, False, False, 0)

        btn_unlock_folder = Gtk.Button(label="Unlock Selected")
        btn_unlock_folder.get_style_context().add_class("success-btn")
        btn_unlock_folder.connect("clicked", self._on_unlock_selected_vault)
        v_top.pack_end(btn_unlock_folder, False, False, 0)

        btn_relock_folder = Gtk.Button(label="Re-Lock")
        btn_relock_folder.get_style_context().add_class("secondary-btn")
        btn_relock_folder.connect("clicked", self._on_relock_selected_vault)
        v_top.pack_end(btn_relock_folder, False, False, 0)
        vault_card.pack_start(v_top, False, False, 0)

        self.vault_store = Gtk.ListStore(str, str, str)
        self.vault_tree = Gtk.TreeView(model=self.vault_store)
        for idx, col_title in enumerate(["Folder Path", "Status", "Items"]):
            renderer = Gtk.CellRendererText()
            col = Gtk.TreeViewColumn(col_title, renderer, text=idx)
            col.set_resizable(True)
            if idx == 0:
                col.set_expand(True)
            self.vault_tree.append_column(col)

        scroll = Gtk.ScrolledWindow()
        scroll.set_min_content_height(115)
        scroll.add(self.vault_tree)
        vault_card.pack_start(scroll, True, True, 0)
        right_col.pack_start(vault_card, True, True, 0)

        # --- Card 3: System PAM Status + Author / Support Strip ---
        sys_card = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=12)
        sys_card.get_style_context().add_class("panel-card")
        self.pam_summary_lbl = Gtk.Label(
            label="✔ Active for: sudo, Login, Lock Screen, Admin Prompts & Folders"
        )
        self.pam_summary_lbl.set_halign(Gtk.Align.START)
        self.pam_summary_lbl.set_line_wrap(True)
        self.pam_summary_lbl.get_style_context().add_class("status-ok")
        sys_card.pack_start(self.pam_summary_lbl, True, True, 0)

        self.btn_toggle_pam = Gtk.Button(label="Pause PAM")
        self.btn_toggle_pam.get_style_context().add_class("secondary-btn")
        self.btn_toggle_pam.connect("clicked", self._on_toggle_system_pam)
        sys_card.pack_end(self.btn_toggle_pam, False, False, 0)
        right_col.pack_start(sys_card, False, False, 0)

        # --- Bottom Status & Support Bar ---
        footer = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
        footer.set_margin_top(2)
        footer.set_margin_bottom(10)
        footer.set_margin_start(22)
        footer.set_margin_end(22)
        self.footer_status = Gtk.Label(
            label=f"Ready — Account '{self.username}' active."
        )
        self.footer_status.set_halign(Gtk.Align.START)
        self.footer_status.get_style_context().add_class("subtitle-label")
        footer.pack_start(self.footer_status, True, True, 0)

        support_lbl = Gtk.Label()
        support_lbl.set_markup(
            "<span size='small' foreground='#9ca3af'>Made by <b>Muheeb Bin Nadeem</b> • "
            "<a href='https://muheebbinnadeem.cv'>muheebbinnadeem.cv</a> • "
            "WhatsApp: <a href='https://wa.me/923074171882'>0307 4171882</a></span>"
        )
        footer.pack_end(support_lbl, False, False, 0)
        root.pack_start(footer, False, False, 0)

        self.win.show_all()

    def _set_footer(self, text: str) -> None:
        self.footer_status.set_text(text)

    def _refresh_all_statuses(self) -> None:
        # 1. Face status
        enrolled = self.face_engine.is_user_enrolled(self.username)
        if enrolled:
            self.face_status_badge.set_text("✔ Face Lock Ready")
            self.btn_enroll_face.set_label("Update Face Lock")
            self.enroll_progress.set_fraction(1.0)
            self.enroll_progress.set_text("Neural SFace Active")
        else:
            self.face_status_badge.set_text("Not set up")
            self.btn_enroll_face.set_label("Set up Face Lock")
            self.enroll_progress.set_fraction(0.0)
            self.enroll_progress.set_text("Ready to scan")

        # 2. Fingerprint status
        fp_st = self.fp_engine.get_status(self.username)
        if fp_st.is_ready_for_auth:
            self.fp_status_lbl.set_text(
                f"✔ Ready ({len(fp_st.enrolled_fingers)} finger enrolled on {fp_st.device_name})"
            )
            self.btn_fp_enroll.set_label("Add Finger")
            self.btn_fp_enroll.set_sensitive(True)
        elif fp_st.fprintd_driver_active and fp_st.device_present:
            self.fp_status_lbl.set_text(f"Sensor ready: {fp_st.device_name} — Click 'Set up'")
            self.btn_fp_enroll.set_label("Set up")
            self.btn_fp_enroll.set_sensitive(True)
        elif fp_st.usb_sensors:
            self.fp_status_lbl.set_text(f"{fp_st.device_name} ({fp_st.driver_hint})")
            self.btn_fp_enroll.set_label("Driver Needed")
            self.btn_fp_enroll.set_sensitive(False)
        else:
            self.fp_status_lbl.set_text(
                "No fingerprint reader on this device (Face Lock & Password active)"
            )
            self.btn_fp_enroll.set_label("Unavailable")
            self.btn_fp_enroll.set_sensitive(False)

        # 3. Keyring status
        kr_st = get_keyring_status(self.username)
        kr_ctx = self.kr_status_lbl.get_style_context()
        kr_ctx.remove_class("status-ok")
        kr_ctx.remove_class("status-warn")
        kr_ctx.remove_class("subtitle-label")
        if kr_st.needs_fix:
            kr_ctx.add_class("status-warn")
            self.kr_status_lbl.set_text(f"⚠ {kr_st.summary}")
            self.btn_fix_keyring.set_label("Fix Keyring Prompt")
            self.btn_fix_keyring.set_sensitive(True)
        else:
            kr_ctx.add_class("status-ok")
            self.kr_status_lbl.set_text(f"✔ {kr_st.summary}")
            self.btn_fix_keyring.set_label("Fixed")
            self.btn_fix_keyring.set_sensitive(False)

        # 4. Folder Vaults
        self.vault_store.clear()
        for v in self.vault_mgr.list_vaults(owner=self.username):
            self.vault_store.append(
                [
                    str(v.get("folder_path", "")),
                    str(v.get("status", "LOCKED")),
                    str(v.get("item_count", 0)),
                ]
            )

        # 5. PAM status
        pam_st = self.pam_mgr.get_service_status()
        enabled_list = [v["file"] for v in pam_st.values() if v["enabled"]]
        if enabled_list:
            self.system_badge.set_text("✔ HELLO ACTIVE")
            self.pam_summary_lbl.set_text(
                f"✔ Active on: {', '.join(enabled_list)} & Protected Folders"
            )
            self.btn_toggle_pam.set_label("Pause PAM")
        else:
            self.system_badge.set_text("PAUSED")
            self.pam_summary_lbl.set_text("PAM hooks paused — click 'Enable PAM' to activate")
            self.btn_toggle_pam.set_label("Enable PAM")

    # =========================================================================
    # Face Camera Setup & Test
    # =========================================================================
    def _start_face_camera(self, mode: str = "enroll") -> None:
        self._stop_face_camera()
        self._cam_mode = mode
        self._hud_state = "scanning"
        self._hud_confidence = 0.0

        if mode == "enroll":
            self._enroll_samples = []
            self._enroll_last_capture = time.time() - 0.3
            self.enroll_progress.set_fraction(0.0)
            self.enroll_progress.set_text("Scanning: 0%")
            self.face_live_status.set_text("Look straight at the camera...")
        elif mode == "test":
            self._test_liveness = LivenessState()
            self._test_profile = load_encrypted_face_profile(self.username)
            if not self._test_profile:
                self.face_live_status.set_text("Click 'Set up Face Lock' first.")
                return

        cams = enumerate_cameras()
        cam_idx = cams[0]["index"] if cams else int(self.cfg.get("camera", {}).get("device_index", 0))
        cap = cv2.VideoCapture(cam_idx)
        if not cap.isOpened():
            self._hud_state = "error"
            self.face_live_status.set_text(f"Camera /dev/video{cam_idx} could not be opened.")
            self.face_drawing_area.queue_draw()
            return

        cap.set(cv2.CAP_PROP_FRAME_WIDTH, 640)
        cap.set(cv2.CAP_PROP_FRAME_HEIGHT, 480)
        self._cap = cap
        self._cam_timer_id = self.GLib.timeout_add(45, self._on_face_tick)

    def _on_face_tick(self) -> bool:
        if self._cap is None:
            return False

        self._scan_phase += 0.16
        ok, frame = self._cap.read()
        if not ok or frame is None:
            return True

        self._current_frame = frame
        det = self.face_engine.detect_face(frame)
        self._last_det = det

        if self._cam_mode == "enroll":
            now = time.time()
            if det.detected and det.quality_ok and (now - self._enroll_last_capture) >= 0.45:
                emb = self.face_engine.extract_embedding(frame, det)
                self._enroll_samples.append(emb)
                self._enroll_last_capture = now
                cnt = len(self._enroll_samples)
                frac = min(1.0, cnt / 5.0)
                self._hud_confidence = frac
                self.enroll_progress.set_fraction(frac)
                self.enroll_progress.set_text(f"Scanning: {int(frac * 100)}%")
                self.face_live_status.set_text(f"Capturing face ({cnt}/5)... Keep still.")
                if cnt >= 5:
                    self._finish_face_enrollment()
                    return False
            elif not det.detected:
                self.face_live_status.set_text("Center your face inside the circle...")
            else:
                self.face_live_status.set_text(det.quality_message)

        elif self._cam_mode == "test" and self._test_profile:
            verified, conf, _live_sc, msg, _ = self.face_engine.verify_frame_for_user(
                self.username,
                frame,
                liveness_state=self._test_liveness,
                profile_cache=self._test_profile,
            )
            self._hud_confidence = conf
            self._hud_state = "matched" if verified else "scanning"
            self.face_live_status.set_text(
                f"{'✔ RECOGNIZED' if verified else 'Scanning'}: {msg}"
            )

        self.face_drawing_area.queue_draw()
        return True

    def _finish_face_enrollment(self) -> None:
        self._hud_state = "matched"
        self.face_drawing_area.queue_draw()
        self._stop_face_camera()

        try:
            self.face_engine.save_user_enrollment(self.username, self._enroll_samples)
        except Exception:
            run_privileged_action(
                "save_face_enrollment",
                {"username": self.username, "samples": self._enroll_samples},
            )

        try:
            user_enc = Path.home() / ".local" / "share" / "facelock" / "encodings"
            self.face_engine.save_user_enrollment(
                self.username,
                self._enroll_samples,
                encodings_dir=user_enc,
                master_key=ensure_master_key(),
            )
        except Exception:
            pass

        self.face_live_status.set_text(f"✔ Face Lock ready for '{self.username}'!")
        self._set_footer(f"✔ Face Lock saved for '{self.username}'.")
        self._refresh_all_statuses()

    def _on_delete_face_profile(self, *_args: Any) -> None:
        self._stop_face_camera()
        (ENCODINGS_DIR / f"{self.username}.enc").unlink(missing_ok=True)
        (Path.home() / ".local" / "share" / "facelock" / "encodings" / f"{self.username}.enc").unlink(
            missing_ok=True
        )
        self.face_live_status.set_text(f"Face profile removed for '{self.username}'.")
        self._refresh_all_statuses()

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
    # Keyring Fix Dialog (One-Time Password Confirm -> Permanent Auto-Unlock)
    # =========================================================================
    def _on_fix_keyring_clicked(self, *_args: Any) -> None:
        Gtk = self.Gtk
        dlg = Gtk.Dialog(
            title="Disable Startup Keyring Prompt",
            transient_for=self.win,
            flags=Gtk.DialogFlags.MODAL,
        )
        dlg.set_default_size(380, 160)
        box = dlg.get_content_area()
        box.set_spacing(10)
        box.set_margin_top(14)
        box.set_margin_bottom(10)
        box.set_margin_start(16)
        box.set_margin_end(16)

        lbl = Gtk.Label(
            label=(
                f"Enter your Kali password once for '{self.username}' to convert your Login Keyring "
                "to auto-unlock (preserves all saved browser/Wi-Fi passwords and stops startup prompts):"
            )
        )
        lbl.set_line_wrap(True)
        box.pack_start(lbl, False, False, 0)

        pw_entry = Gtk.Entry()
        pw_entry.set_visibility(False)
        pw_entry.set_placeholder_text("Your Kali Linux password...")
        pw_entry.connect("activate", lambda *_: dlg.response(Gtk.ResponseType.OK))
        box.pack_start(pw_entry, False, False, 0)

        dlg.add_button("Cancel", Gtk.ResponseType.CANCEL)
        ok_btn = dlg.add_button("Disable Keyring Prompt", Gtk.ResponseType.OK)
        ok_btn.get_style_context().add_class("primary-btn")
        dlg.show_all()

        resp = dlg.run()
        pw = pw_entry.get_text()
        dlg.destroy()

        if resp == Gtk.ResponseType.OK:
            ok, msg = enable_auto_unlock_keyring(self.username, pw)
            self._set_footer(f"{'✔' if ok else '✘'} {msg}")
            self._refresh_all_statuses()

    # =========================================================================
    # Fingerprint, Default Method, Folder Vaults & PAM Toggle
    # =========================================================================
    def _on_enroll_fingerprint(self, *_args: Any) -> None:
        st = self.fp_engine.get_status(self.username)
        if not st.fprintd_driver_active:
            self._set_footer("No supported fingerprint reader active in fprintd.")
            return

        self.fp_status_lbl.set_text("Touch your fingerprint sensor repeatedly...")

        def _worker() -> None:
            ok, msg = self.fp_engine.enroll(
                self.username,
                finger="right-index-finger",
                status_cb=lambda s: self.GLib.idle_add(self.fp_status_lbl.set_text, s),
            )
            self.GLib.idle_add(self.fp_status_lbl.set_text, f"{'✔' if ok else '✘'} {msg}")
            self.GLib.idle_add(self._refresh_all_statuses)

        threading.Thread(target=_worker, daemon=True).start()

    def _on_default_method_changed(self, combo: Any) -> None:
        mid = combo.get_active_id() or METHOD_FACE
        self.cfg_mgr.set_top("default_method", mid)
        self.cfg_mgr.save()
        self._set_footer(f"Default popup method set to: {mid}")

    def _get_selected_vault_path(self) -> Optional[Path]:
        sel = self.vault_tree.get_selection()
        model, treeiter = sel.get_selected()
        if treeiter is not None:
            return Path(model[treeiter][0])
        return None

    def _on_select_and_lock_folder(self, *_args: Any) -> None:
        Gtk = self.Gtk
        dlg = Gtk.FileChooserDialog(
            title="Select Folder to Lock with Windows Hello",
            parent=self.win,
            action=Gtk.FileChooserAction.SELECT_FOLDER,
        )
        dlg.add_buttons(
            Gtk.STOCK_CANCEL,
            Gtk.ResponseType.CANCEL,
            "Lock Folder",
            Gtk.ResponseType.OK,
        )
        resp = dlg.run()
        chosen = dlg.get_filename()
        dlg.destroy()

        if resp == Gtk.ResponseType.OK and chosen:
            ok, msg = self.vault_mgr.lock_folder(Path(chosen), owner=self.username)
            self._set_footer(f"{'✔' if ok else '✘'} {msg}")
            self._refresh_all_statuses()

    def _on_unlock_selected_vault(self, *_args: Any) -> None:
        target = self._get_selected_vault_path()
        if target is None:
            self._set_footer("Select a folder from the list first.")
            return

        self._stop_face_camera()
        rc = launch_authentication_prompt(
            username=self.username,
            service="folder-vault",
            title_override=f"Unlock Folder: {target.name}",
        )
        if rc != 0:
            self._set_footer("Unlock cancelled.")
            return

        ok, msg = self.vault_mgr.unlock_folder(target, open_in_file_manager=True)
        self._set_footer(f"{'✔' if ok else '✘'} {msg}")
        self._refresh_all_statuses()

    def _on_relock_selected_vault(self, *_args: Any) -> None:
        target = self._get_selected_vault_path()
        if target is None:
            self._set_footer("Select an unlocked folder first.")
            return
        ok, msg = self.vault_mgr.lock_folder(target, owner=self.username)
        self._set_footer(f"{'✔' if ok else '✘'} {msg}")
        self._refresh_all_statuses()

    def _on_toggle_system_pam(self, *_args: Any) -> None:
        pam_st = self.pam_mgr.get_service_status()
        any_enabled = any(v["enabled"] for v in pam_st.values())
        if any_enabled:
            ok, msg = run_privileged_action("restore_pam", {})
        else:
            ok, msg = run_privileged_action(
                "auto_configure_backend",
                {
                    "username": self.username,
                    "config": self.cfg_mgr.data,
                    "pam_services": self.cfg_mgr.data.get("pam_services", {}),
                },
            )
        self._refresh_all_statuses()
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
        self._set_footer("Opened Windows Hello Sign-In Popup.")

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
