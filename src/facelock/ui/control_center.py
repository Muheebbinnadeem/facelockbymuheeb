"""
FaceLock Frontend Control Center GUI for Kali Linux.

Designed like Windows 11 "Windows Hello Sign-in Options":
  - Single, easy-to-understand dashboard (zero manual backend steps)
  - Auto-detected username & original Kali Linux system password ready out of the box
  - One-click automatic 3-second Face Lock setup with live circular scanner ring
  - Auto-detected Fingerprint setup (if hardware is connected)
  - One-click Folder Lock & Unlock (protected by the Windows Hello popup)
  - System-wide protection (sudo, Login, Lock Screen, Polkit) automatically active
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
from facelock.core.crypto import (
    ensure_master_key,
    get_face_profile_metadata,
    load_encrypted_face_profile,
)
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


def run_privileged_action(action: str, payload: Dict[str, Any]) -> Tuple[bool, str]:
    """Run a backend action directly if permitted, or elevate via pkexec when needed."""
    from facelock.cli.privileged_helper import execute_privileged_payload

    if os.geteuid() == 0:
        return execute_privileged_payload(action, payload)

    # For saving or deleting face enrollment, try direct write first if /etc/facelock/encodings is writable
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
    """Simple, unified Windows Hello style Sign-in Options window for Kali Linux."""

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

        # Camera state
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
        self.win = Gtk.Window(title="Kali Hello — Sign-in Options & Folder Lock")
        self.win.set_default_size(920, 620)
        self.win.set_position(Gtk.WindowPosition.CENTER)
        self.win.connect("destroy", self._on_destroy)

        root = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=0)
        self.win.add(root)

        # --- Top Bar: Simple Windows Hello Greeting & Auto-Detected Account ---
        top_bar = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=12)
        top_bar.set_margin_top(14)
        top_bar.set_margin_bottom(12)
        top_bar.set_margin_start(22)
        top_bar.set_margin_end(22)

        title_col = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=2)
        t_lbl = Gtk.Label(label=f"Kali Hello  •  Sign-in Options ({self.username})")
        t_lbl.set_halign(Gtk.Align.START)
        t_lbl.get_style_context().add_class("title-label")
        s_lbl = Gtk.Label(
            label="Use Face Lock, Fingerprint, or your Kali Password for sudo, Login, Lock Screen & Folders"
        )
        s_lbl.set_halign(Gtk.Align.START)
        s_lbl.get_style_context().add_class("subtitle-label")
        title_col.pack_start(t_lbl, False, False, 0)
        title_col.pack_start(s_lbl, False, False, 0)
        top_bar.pack_start(title_col, True, True, 0)

        self.system_badge = Gtk.Label(label="✔ ACTIVE ON SYSTEM")
        self.system_badge.get_style_context().add_class("header-badge")
        top_bar.pack_end(self.system_badge, False, False, 0)

        root.pack_start(top_bar, False, False, 0)
        root.pack_start(Gtk.Separator(orientation=Gtk.Orientation.HORIZONTAL), False, False, 0)

        # --- Main Two-Column Body (Everything on ONE Simple Screen) ---
        body = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=18)
        body.set_margin_top(16)
        body.set_margin_bottom(12)
        body.set_margin_start(22)
        body.set_margin_end(22)
        root.pack_start(body, True, True, 0)

        # =====================================================================
        # LEFT COLUMN: Camera Ring + 1-Click Face Setup + Test Popup Button
        # =====================================================================
        left_card = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10)
        left_card.set_size_request(330, -1)
        left_card.get_style_context().add_class("panel-card")

        cam_header = Gtk.Label(label="1. Face Lock Scanner")
        cam_header.get_style_context().add_class("title-label")
        left_card.pack_start(cam_header, False, False, 0)

        self.face_status_badge = Gtk.Label(label="Checking Face Profile...")
        self.face_status_badge.get_style_context().add_class("stat-value")
        left_card.pack_start(self.face_status_badge, False, False, 0)

        self.face_drawing_area = Gtk.DrawingArea()
        self.face_drawing_area.set_size_request(240, 240)
        self.face_drawing_area.set_halign(Gtk.Align.CENTER)
        self.face_drawing_area.connect("draw", self._on_draw_face_preview)
        left_card.pack_start(self.face_drawing_area, False, False, 2)

        self.face_live_status = Gtk.Label(
            label="Click 'Set Up Face Lock' below and look at the camera for 3 seconds."
        )
        self.face_live_status.set_line_wrap(True)
        self.face_live_status.set_justify(Gtk.Justification.CENTER)
        self.face_live_status.get_style_context().add_class("subtitle-label")
        left_card.pack_start(self.face_live_status, False, False, 0)

        self.enroll_progress = Gtk.ProgressBar()
        self.enroll_progress.set_show_text(True)
        self.enroll_progress.set_text("Ready")
        left_card.pack_start(self.enroll_progress, False, False, 0)

        # Big 1-Click Enroll Button
        self.btn_enroll_face = Gtk.Button(label="Set Up Face Lock (Auto 3s Scan)")
        self.btn_enroll_face.get_style_context().add_class("primary-btn")
        self.btn_enroll_face.connect("clicked", lambda *_: self._start_face_camera(mode="enroll"))
        left_card.pack_start(self.btn_enroll_face, False, False, 0)

        sub_face_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        btn_test_cam = Gtk.Button(label="Test Camera Match")
        btn_test_cam.get_style_context().add_class("secondary-btn")
        btn_test_cam.connect("clicked", lambda *_: self._start_face_camera(mode="test"))
        sub_face_row.pack_start(btn_test_cam, True, True, 0)

        btn_del_face = Gtk.Button(label="Reset Face")
        btn_del_face.get_style_context().add_class("danger-btn")
        btn_del_face.connect("clicked", self._on_delete_face_profile)
        sub_face_row.pack_start(btn_del_face, False, False, 0)
        left_card.pack_start(sub_face_row, False, False, 0)

        left_card.pack_start(Gtk.Separator(orientation=Gtk.Orientation.HORIZONTAL), False, False, 4)

        # Big Test Windows Hello Popup Button
        btn_test_popup = Gtk.Button(label="★ Test Windows Hello Popup Now")
        btn_test_popup.get_style_context().add_class("success-btn")
        btn_test_popup.connect("clicked", self._on_test_windows_hello_prompt)
        left_card.pack_start(btn_test_popup, False, False, 0)

        body.pack_start(left_card, False, False, 0)

        # =====================================================================
        # RIGHT COLUMN: Fingerprint, Password & Folder Lock (All on One Screen)
        # =====================================================================
        right_col = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        body.pack_start(right_col, True, True, 0)

        # --- Card A: Fingerprint & System Password ---
        methods_card = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10)
        methods_card.get_style_context().add_class("panel-card")

        m_title = Gtk.Label(label="2. Fingerprint & Password Options")
        m_title.set_halign(Gtk.Align.START)
        m_title.get_style_context().add_class("title-label")
        methods_card.pack_start(m_title, False, False, 0)

        # Fingerprint Row
        fp_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
        fp_info_col = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=2)
        fp_hdr = Gtk.Label(label="Fingerprint Recognition (Windows Hello Fingerprint)")
        fp_hdr.set_halign(Gtk.Align.START)
        fp_hdr.get_style_context().add_class("stat-value")
        self.fp_status_lbl = Gtk.Label(label="Checking fingerprint sensor...")
        self.fp_status_lbl.set_halign(Gtk.Align.START)
        self.fp_status_lbl.set_line_wrap(True)
        self.fp_status_lbl.get_style_context().add_class("subtitle-label")
        fp_info_col.pack_start(fp_hdr, False, False, 0)
        fp_info_col.pack_start(self.fp_status_lbl, False, False, 0)
        fp_row.pack_start(fp_info_col, True, True, 0)

        self.btn_fp_enroll = Gtk.Button(label="Set Up Fingerprint")
        self.btn_fp_enroll.get_style_context().add_class("secondary-btn")
        self.btn_fp_enroll.set_valign(Gtk.Align.CENTER)
        self.btn_fp_enroll.connect("clicked", self._on_enroll_fingerprint)
        fp_row.pack_end(self.btn_fp_enroll, False, False, 0)
        methods_card.pack_start(fp_row, False, False, 0)

        methods_card.pack_start(Gtk.Separator(orientation=Gtk.Orientation.HORIZONTAL), False, False, 2)

        # Password & Default Method Row
        pw_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
        pw_lbl = Gtk.Label(
            label=f"✔ System Password: Uses original Kali password for '{self.username}' automatically"
        )
        pw_lbl.set_halign(Gtk.Align.START)
        pw_lbl.get_style_context().add_class("status-ok")
        pw_row.pack_start(pw_lbl, True, True, 0)

        def_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=6)
        def_box.pack_start(Gtk.Label(label="Default Popup Method:"), False, False, 0)
        self.default_combo = Gtk.ComboBoxText()
        self.default_combo.append(METHOD_FACE, "Face Lock")
        self.default_combo.append(METHOD_FINGERPRINT, "Fingerprint")
        self.default_combo.append(METHOD_PASSWORD, "Password")
        self.default_combo.set_active_id(self.cfg.get("default_method", METHOD_FACE))
        self.default_combo.connect("changed", self._on_default_method_changed)
        def_box.pack_start(self.default_combo, False, False, 0)
        pw_row.pack_end(def_box, False, False, 0)

        methods_card.pack_start(pw_row, False, False, 0)
        right_col.pack_start(methods_card, False, False, 0)

        # --- Card B: Folder Lock (Lock / Unlock Any Folder) ---
        vault_card = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10)
        vault_card.get_style_context().add_class("panel-card")

        v_top = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
        v_title = Gtk.Label(label="3. Folder Lock (Protect Any Folder with Kali Hello)")
        v_title.set_halign(Gtk.Align.START)
        v_title.get_style_context().add_class("title-label")
        v_top.pack_start(v_title, True, True, 0)
        vault_card.pack_start(v_top, False, False, 0)

        v_btn_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        btn_lock_folder = Gtk.Button(label="+ Select & Lock a Folder")
        btn_lock_folder.get_style_context().add_class("primary-btn")
        btn_lock_folder.connect("clicked", self._on_select_and_lock_folder)
        v_btn_row.pack_start(btn_lock_folder, False, False, 0)

        btn_unlock_folder = Gtk.Button(label="Unlock Selected Folder")
        btn_unlock_folder.get_style_context().add_class("success-btn")
        btn_unlock_folder.connect("clicked", self._on_unlock_selected_vault)
        v_btn_row.pack_start(btn_unlock_folder, False, False, 0)

        btn_relock_folder = Gtk.Button(label="Re-Lock Folder")
        btn_relock_folder.get_style_context().add_class("secondary-btn")
        btn_relock_folder.connect("clicked", self._on_relock_selected_vault)
        v_btn_row.pack_start(btn_relock_folder, False, False, 0)
        vault_card.pack_start(v_btn_row, False, False, 0)

        self.vault_store = Gtk.ListStore(str, str, str)  # path, status, items
        self.vault_tree = Gtk.TreeView(model=self.vault_store)
        for idx, col_title in enumerate(["Folder Path", "Status", "Items"]):
            renderer = Gtk.CellRendererText()
            col = Gtk.TreeViewColumn(col_title, renderer, text=idx)
            col.set_resizable(True)
            if idx == 0:
                col.set_expand(True)
            self.vault_tree.append_column(col)

        scroll = Gtk.ScrolledWindow()
        scroll.set_min_content_height(155)
        scroll.add(self.vault_tree)
        vault_card.pack_start(scroll, True, True, 0)
        right_col.pack_start(vault_card, True, True, 0)

        # --- Card C: Active Everywhere Status (sudo, Login, Lock Screen, Polkit) ---
        sys_card = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=12)
        sys_card.get_style_context().add_class("panel-card")

        self.pam_summary_lbl = Gtk.Label(
            label="✔ Active for: sudo, Desktop Login, Lock Screen, Admin Prompts & Folders"
        )
        self.pam_summary_lbl.set_halign(Gtk.Align.START)
        self.pam_summary_lbl.set_line_wrap(True)
        self.pam_summary_lbl.get_style_context().add_class("status-ok")
        sys_card.pack_start(self.pam_summary_lbl, True, True, 0)

        self.btn_toggle_pam = Gtk.Button(label="Disable PAM")
        self.btn_toggle_pam.get_style_context().add_class("secondary-btn")
        self.btn_toggle_pam.connect("clicked", self._on_toggle_system_pam)
        sys_card.pack_end(self.btn_toggle_pam, False, False, 0)

        right_col.pack_start(sys_card, False, False, 0)

        # --- Bottom Status Bar ---
        footer = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
        footer.set_margin_top(4)
        footer.set_margin_bottom(10)
        footer.set_margin_start(22)
        footer.set_margin_end(22)
        self.footer_status = Gtk.Label(
            label=f"Ready — Account '{self.username}' configured automatically."
        )
        self.footer_status.set_halign(Gtk.Align.START)
        self.footer_status.get_style_context().add_class("subtitle-label")
        footer.pack_start(self.footer_status, True, True, 0)
        root.pack_start(footer, False, False, 0)

        self.win.show_all()

    def _set_footer(self, text: str) -> None:
        self.footer_status.set_text(text)

    def _refresh_all_statuses(self) -> None:
        # 1. Face status (requires neural SFace enrollment)
        enrolled = self.face_engine.is_user_enrolled(self.username)

        if enrolled:
            self.face_status_badge.set_text("✔ Neural Face Lock Ready")
            self.btn_enroll_face.set_label("Update My Face (Auto 3s Scan)")
            self.enroll_progress.set_fraction(1.0)
            self.enroll_progress.set_text("Neural SFace Profile Active")
        else:
            self.face_status_badge.set_text("Face Not Set Up Yet")
            self.btn_enroll_face.set_label("Set Up Face Lock (Auto 3s Scan)")
            self.enroll_progress.set_fraction(0.0)
            self.enroll_progress.set_text("Click 'Set Up Face Lock' below")

        # 2. Fingerprint status
        fp_st = self.fp_engine.get_status(self.username)
        if fp_st.is_ready_for_auth:
            self.fp_status_lbl.set_text(
                f"✔ Ready ({len(fp_st.enrolled_fingers)} finger enrolled on {fp_st.device_name})"
            )
            self.btn_fp_enroll.set_label("Add Another Finger")
        elif fp_st.device_present:
            self.fp_status_lbl.set_text(f"Sensor found: {fp_st.device_name} — Click 'Set Up Fingerprint'")
            self.btn_fp_enroll.set_sensitive(True)
        else:
            self.fp_status_lbl.set_text(
                "No fingerprint sensor detected on this PC (Face Lock & System Password are active)"
            )

        # 3. Folder Vaults
        self.vault_store.clear()
        for v in self.vault_mgr.list_vaults(owner=self.username):
            self.vault_store.append(
                [
                    str(v.get("folder_path", "")),
                    str(v.get("status", "LOCKED")),
                    str(v.get("item_count", 0)),
                ]
            )

        # 4. PAM status
        pam_st = self.pam_mgr.get_service_status()
        enabled_list = [v["file"] for v in pam_st.values() if v["enabled"]]
        if enabled_list:
            self.system_badge.set_text("✔ KALI HELLO ACTIVE")
            self.pam_summary_lbl.set_text(
                f"✔ Active everywhere: {', '.join(enabled_list)} & Protected Folders"
            )
            self.btn_toggle_pam.set_label("Pause / Restore Default PAM")
        else:
            self.system_badge.set_text("PAUSED")
            self.pam_summary_lbl.set_text("PAM hooks currently paused — click 'Enable Kali Hello' to activate")
            self.btn_toggle_pam.set_label("Enable Kali Hello Everywhere")

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
            self.enroll_progress.set_text("Scanning Face: 0%")
            self.face_live_status.set_text("Look directly at the camera — scanning automatically...")
        elif mode == "test":
            self._test_liveness = LivenessState()
            self._test_profile = load_encrypted_face_profile(self.username)
            if not self._test_profile:
                self.face_live_status.set_text("Please click 'Set Up Face Lock' first.")
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
                self.enroll_progress.set_text(f"Scanning Face: {int(frac * 100)}%")
                self.face_live_status.set_text(f"Capturing face angles ({cnt}/5)... Hold steady.")
                if cnt >= 5:
                    self._finish_face_enrollment()
                    return False
            elif not det.detected:
                self.face_live_status.set_text("Position your face inside the circle...")
            else:
                self.face_live_status.set_text(det.quality_message)

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
                f"{'✔ RECOGNIZED' if verified else 'Scanning'}: {msg}"
            )

        self.face_drawing_area.queue_draw()
        return True

    def _finish_face_enrollment(self) -> None:
        self._hud_state = "matched"
        self.face_drawing_area.queue_draw()
        self._stop_face_camera()

        # Save to both /etc/facelock/encodings (for PAM root) and user cache
        saved_paths: List[str] = []
        try:
            p_sys = self.face_engine.save_user_enrollment(self.username, self._enroll_samples)
            saved_paths.append(str(p_sys))
        except Exception:
            ok, msg = run_privileged_action(
                "save_face_enrollment",
                {"username": self.username, "samples": self._enroll_samples},
            )
            if ok:
                saved_paths.append(msg)

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

        self.face_live_status.set_text(
            f"✔ Face Lock is now active for '{self.username}'! Click 'Test Windows Hello Popup Now' below."
        )
        self._set_footer(f"✔ Face Lock configured automatically for '{self.username}'.")
        self._refresh_all_statuses()

    def _on_delete_face_profile(self, *_args: Any) -> None:
        self._stop_face_camera()
        (ENCODINGS_DIR / f"{self.username}.enc").unlink(missing_ok=True)
        (Path.home() / ".local" / "share" / "facelock" / "encodings" / f"{self.username}.enc").unlink(
            missing_ok=True
        )
        self.face_live_status.set_text(f"Face profile reset for '{self.username}'.")
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
    # Fingerprint, Default Method, Folder Vaults & PAM Toggle
    # =========================================================================
    def _on_enroll_fingerprint(self, *_args: Any) -> None:
        st = self.fp_engine.get_status(self.username)
        if not st.device_present:
            self._set_footer("No fingerprint hardware sensor detected on this PC.")
            return

        self.fp_status_lbl.set_text("Touch your fingerprint sensor repeatedly to enroll...")

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
        self._set_footer(f"Default popup sign-in method set to: {mid}")

    def _get_selected_vault_path(self) -> Optional[Path]:
        sel = self.vault_tree.get_selection()
        model, treeiter = sel.get_selected()
        if treeiter is not None:
            return Path(model[treeiter][0])
        return None

    def _on_select_and_lock_folder(self, *_args: Any) -> None:
        Gtk = self.Gtk
        dlg = Gtk.FileChooserDialog(
            title="Choose a Folder to Lock with Kali Hello",
            parent=self.win,
            action=Gtk.FileChooserAction.SELECT_FOLDER,
        )
        dlg.add_buttons(
            Gtk.STOCK_CANCEL,
            Gtk.ResponseType.CANCEL,
            "Lock Folder Now",
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
            self._set_footer("Click on a folder in the list first, then click 'Unlock Selected Folder'.")
            return

        self._stop_face_camera()
        rc = launch_authentication_prompt(
            username=self.username,
            service="folder-vault",
            title_override=f"Unlock Folder: {target.name}",
        )
        if rc != 0:
            self._set_footer("Folder unlock cancelled.")
            return

        ok, msg = self.vault_mgr.unlock_folder(target, open_in_file_manager=True)
        self._set_footer(f"{'✔' if ok else '✘'} {msg}")
        self._refresh_all_statuses()

    def _on_relock_selected_vault(self, *_args: Any) -> None:
        target = self._get_selected_vault_path()
        if target is None:
            self._set_footer("Click on an unlocked folder in the list first.")
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
