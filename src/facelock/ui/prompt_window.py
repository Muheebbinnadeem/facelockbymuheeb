"""
Windows Hello-style Authentication Prompt Window for Kali Linux.

Supports instant switching between 3 authentication methods via BOTH:
  1. Clickable Method Icon Buttons (Face Lock | Fingerprint | System Password)
  2. A "Sign-in method" Dropdown Selector (Gtk.ComboBoxText)

Automatically detects the target username, enforces biometric rate-limiting,
verifies anti-spoofing liveness, and returns exit code 0 on verification.
"""

import getpass
import math
import os
import sys
import threading
import time
from typing import Any, Dict, Optional, Tuple

import cv2
import numpy as np

from facelock.config import ConfigManager, detect_active_username
from facelock.constants import (
    METHOD_FACE,
    METHOD_FINGERPRINT,
    METHOD_PASSWORD,
)
from facelock.core.audit import log_auth_event
from facelock.core.crypto import load_encrypted_face_profile
from facelock.core.face_engine import FaceBiometricEngine, FaceDetectionResult, LivenessState
from facelock.core.fingerprint_engine import FingerprintEngine
from facelock.core.password_engine import verify_system_password
from facelock.core.rate_limiter import BiometricRateLimiter

SERVICE_LABELS = {
    "sudo": "sudo — Terminal Privilege Escalation",
    "polkit-1": "Polkit — System Administrator Action",
    "polkit": "Polkit — System Administrator Action",
    "lightdm": "LightDM — Kali Desktop Session Login",
    "gdm-password": "GDM — Desktop Session Login",
    "xfce4-screensaver": "XFCE Lock Screen — Unlock Session",
    "light-locker": "Light Locker — Unlock Session",
    "su": "su — Switch User Account",
    "folder-vault": "Folder Vault — Unlock Encrypted Directory",
    "test": "Kali Hello — Live Verification Test",
}


class WindowsHelloPromptWindow:
    """
    GTK3 modal authentication prompt modeled after Windows Hello with Kali Dark styling.
    """

    def __init__(
        self,
        username: Optional[str] = None,
        service: str = "sudo",
        initial_method: Optional[str] = None,
        title_override: Optional[str] = None,
    ) -> None:
        import gi

        gi.require_version("Gdk", "3.0")
        gi.require_version("Gtk", "3.0")
        from gi.repository import Gdk, GLib, Gtk

        self.Gtk = Gtk
        self.Gdk = Gdk
        self.GLib = GLib

        from facelock.ui.theme import (
            apply_kali_theme,
            draw_circular_camera_hud,
            draw_fingerprint_radar,
        )

        apply_kali_theme()
        self._draw_camera_hud = draw_circular_camera_hud
        self._draw_fp_radar = draw_fingerprint_radar

        self.cfg_mgr = ConfigManager()
        self.cfg = self.cfg_mgr.data
        self.username = username or detect_active_username()
        self.service = service
        self.title_override = title_override

        self.face_engine = FaceBiometricEngine(self.cfg)
        self.fp_engine = FingerprintEngine()
        sec_cfg = self.cfg.get("security", {})
        self.rate_limiter = BiometricRateLimiter(
            max_attempts=int(sec_cfg.get("max_biometric_attempts", 4)),
            lockout_seconds=int(sec_cfg.get("lockout_duration_seconds", 60)),
        )

        self.authenticated = False
        self.auth_method_used = ""
        self.exit_code = 2  # Default to PAM_IGNORE / fallback if closed

        # Biometric runtime state
        self.active_method = initial_method or self._select_initial_method()
        self._syncing_selector = False
        self._cap: Optional[cv2.VideoCapture] = None
        self._current_frame: Optional[np.ndarray] = None
        self._last_det: Optional[FaceDetectionResult] = None
        self._liveness = LivenessState()
        self._face_profile: Optional[Dict[str, Any]] = None
        self._scan_phase = 0.0
        self._visual_state = "scanning"  # scanning | matched | error
        self._match_confidence = 0.0
        self._scan_start_time = time.time()
        self._scan_timeout = float(self.cfg.get("face_auth", {}).get("scan_timeout_seconds", 9))
        self._camera_timer_id: Optional[int] = None
        self._fp_thread: Optional[threading.Thread] = None
        self._fp_running = False

        self._load_user_profile()
        self._build_ui()

    def _load_user_profile(self) -> None:
        try:
            self._face_profile = load_encrypted_face_profile(self.username)
        except Exception:
            self._face_profile = None

    def _select_initial_method(self) -> str:
        allowed, _, _ = self.rate_limiter.check_biometric_allowed(self.username)
        if not allowed:
            return METHOD_PASSWORD

        preferred = self.cfg.get("default_method", METHOD_FACE)
        if preferred == METHOD_FACE and self.face_engine.is_user_enrolled(self.username):
            return METHOD_FACE
        if preferred == METHOD_FINGERPRINT and self.fp_engine.get_status(self.username).is_ready_for_auth:
            return METHOD_FINGERPRINT
        if self.face_engine.is_user_enrolled(self.username):
            return METHOD_FACE
        if self.fp_engine.get_status(self.username).is_ready_for_auth:
            return METHOD_FINGERPRINT
        return preferred if preferred in (METHOD_FACE, METHOD_FINGERPRINT, METHOD_PASSWORD) else METHOD_FACE

    def _build_ui(self) -> None:
        Gtk = self.Gtk
        Gdk = self.Gdk

        self.win = Gtk.Window(title="Windows Hello — Kali Security")
        self.win.set_default_size(420, 540)
        self.win.set_resizable(False)
        self.win.set_position(Gtk.WindowPosition.CENTER_ALWAYS)
        self.win.set_keep_above(True)
        self.win.set_type_hint(Gdk.WindowTypeHint.DIALOG)
        self.win.connect("destroy", self._on_destroy)
        self.win.connect("key-press-event", self._on_key_press)

        outer = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=11)
        outer.set_margin_top(16)
        outer.set_margin_bottom(16)
        outer.set_margin_start(18)
        outer.set_margin_end(18)
        outer.get_style_context().add_class("prompt-card")
        self.win.add(outer)

        # Top badge & service title
        badge_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL)
        badge_box.set_halign(Gtk.Align.CENTER)
        badge = Gtk.Label(label="WINDOWS HELLO  •  KALI SECURITY")
        badge.get_style_context().add_class("header-badge")
        badge_box.pack_start(badge, False, False, 0)
        outer.pack_start(badge_box, False, False, 0)

        srv_title = self.title_override or SERVICE_LABELS.get(
            self.service, f"Authentication Required ({self.service})"
        )
        title_lbl = Gtk.Label(label="Making sure it's you")
        title_lbl.get_style_context().add_class("title-label")
        outer.pack_start(title_lbl, False, False, 0)

        sub_lbl = Gtk.Label(label=srv_title)
        sub_lbl.get_style_context().add_class("subtitle-label")
        sub_lbl.set_line_wrap(True)
        outer.pack_start(sub_lbl, False, False, 0)

        # Auto-detected username card
        user_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        user_box.set_halign(Gtk.Align.CENTER)
        user_box.get_style_context().add_class("user-pill")
        user_icon = Gtk.Image.new_from_icon_name("avatar-default-symbolic", Gtk.IconSize.BUTTON)
        user_lbl = Gtk.Label(label=f"{self.username}")
        user_box.pack_start(user_icon, False, False, 0)
        user_box.pack_start(user_lbl, False, False, 0)
        outer.pack_start(user_box, False, False, 2)

        # Main Stack for the 3 Authentication Methods
        self.stack = Gtk.Stack()
        self.stack.set_transition_type(Gtk.StackTransitionType.CROSSFADE)
        self.stack.set_transition_duration(180)
        outer.pack_start(self.stack, True, True, 4)

        # --- View 1: Face Lock ---
        face_page = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        self.camera_area = Gtk.DrawingArea()
        self.camera_area.set_size_request(230, 230)
        self.camera_area.set_halign(Gtk.Align.CENTER)
        self.camera_area.connect("draw", self._on_draw_camera)
        face_page.pack_start(self.camera_area, False, False, 0)

        self.face_retry_btn = Gtk.Button(label="Scan Face Again")
        self.face_retry_btn.get_style_context().add_class("secondary-btn")
        self.face_retry_btn.set_halign(Gtk.Align.CENTER)
        self.face_retry_btn.connect("clicked", lambda *_: self._start_face_mode())
        face_page.pack_start(self.face_retry_btn, False, False, 0)
        self.stack.add_named(face_page, METHOD_FACE)

        # --- View 2: Fingerprint ---
        fp_page = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10)
        self.fp_area = Gtk.DrawingArea()
        self.fp_area.set_size_request(210, 210)
        self.fp_area.set_halign(Gtk.Align.CENTER)
        self.fp_area.connect("draw", self._on_draw_fingerprint)
        fp_page.pack_start(self.fp_area, False, False, 0)

        self.fp_retry_btn = Gtk.Button(label="Retry Fingerprint Scan")
        self.fp_retry_btn.get_style_context().add_class("secondary-btn")
        self.fp_retry_btn.set_halign(Gtk.Align.CENTER)
        self.fp_retry_btn.connect("clicked", lambda *_: self._start_fingerprint_mode())
        fp_page.pack_start(self.fp_retry_btn, False, False, 0)
        self.stack.add_named(fp_page, METHOD_FINGERPRINT)

        # --- View 3: System Password ---
        pw_page = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        pw_page.set_valign(Gtk.Align.CENTER)
        pw_page.set_margin_top(20)
        pw_page.set_margin_bottom(20)
        pw_page.set_margin_start(16)
        pw_page.set_margin_end(16)

        pw_icon = Gtk.Image.new_from_icon_name("dialog-password-symbolic", Gtk.IconSize.DIALOG)
        pw_page.pack_start(pw_icon, False, False, 0)

        pw_hint = Gtk.Label(
            label=f"Enter the original Kali Linux password for '{self.username}':"
        )
        pw_hint.get_style_context().add_class("subtitle-label")
        pw_page.pack_start(pw_hint, False, False, 0)

        pw_entry_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=6)
        self.pw_entry = Gtk.Entry()
        self.pw_entry.set_visibility(False)
        self.pw_entry.set_invisible_char("●")
        self.pw_entry.set_placeholder_text("System password...")
        self.pw_entry.connect("activate", self._on_verify_password)
        pw_entry_row.pack_start(self.pw_entry, True, True, 0)

        self.show_pw_toggle = Gtk.ToggleButton(label="Show")
        self.show_pw_toggle.get_style_context().add_class("secondary-btn")
        self.show_pw_toggle.connect(
            "toggled",
            lambda btn: self.pw_entry.set_visibility(btn.get_active()),
        )
        pw_entry_row.pack_start(self.show_pw_toggle, False, False, 0)
        pw_page.pack_start(pw_entry_row, False, False, 0)

        pw_submit_btn = Gtk.Button(label="Sign In with Password")
        pw_submit_btn.get_style_context().add_class("primary-btn")
        pw_submit_btn.connect("clicked", self._on_verify_password)
        pw_page.pack_start(pw_submit_btn, False, False, 0)
        self.stack.add_named(pw_page, METHOD_PASSWORD)

        # Live status feedback line
        self.status_label = Gtk.Label(label="Initializing Kali Hello...")
        self.status_label.set_line_wrap(True)
        self.status_label.set_justify(Gtk.Justification.CENTER)
        outer.pack_start(self.status_label, False, False, 2)

        # Separator
        outer.pack_start(Gtk.Separator(orientation=Gtk.Orientation.HORIZONTAL), False, False, 4)

        # --- Sign-in Options Switcher: BOTH 3 Clickable Icons AND Dropdown ---
        switcher_lbl = Gtk.Label(label="Sign-in options (switch method via icon or dropdown):")
        switcher_lbl.get_style_context().add_class("subtitle-label")
        outer.pack_start(switcher_lbl, False, False, 0)

        # 1. Three clickable icon buttons
        icon_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        icon_row.set_homogeneous(True)

        self.btn_face = self._create_method_button("camera-web-symbolic", "Face Lock", METHOD_FACE)
        self.btn_fp = self._create_method_button("auth-fingerprint-symbolic", "Fingerprint", METHOD_FINGERPRINT)
        self.btn_pw = self._create_method_button("dialog-password-symbolic", "Password", METHOD_PASSWORD)

        icon_row.pack_start(self.btn_face, True, True, 0)
        icon_row.pack_start(self.btn_fp, True, True, 0)
        icon_row.pack_start(self.btn_pw, True, True, 0)
        outer.pack_start(icon_row, False, False, 0)

        # 2. Dropdown selector (Gtk.ComboBoxText)
        dropdown_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        dd_lbl = Gtk.Label(label="Method:")
        dd_lbl.get_style_context().add_class("subtitle-label")
        self.method_combo = Gtk.ComboBoxText()
        self.method_combo.append(METHOD_FACE, "1. Face Recognition (Kali Hello Camera)")
        self.method_combo.append(METHOD_FINGERPRINT, "2. Fingerprint Sensor (fprintd Biometric)")
        self.method_combo.append(METHOD_PASSWORD, "3. System Password (Original Linux PAM)")
        self.method_combo.connect("changed", self._on_combo_changed)
        dropdown_row.pack_start(dd_lbl, False, False, 0)
        dropdown_row.pack_start(self.method_combo, True, True, 0)
        outer.pack_start(dropdown_row, False, False, 0)

        # Bottom Cancel / Terminal Fallback button
        bottom_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        cancel_btn = Gtk.Button(label="Cancel / Terminal Prompt")
        cancel_btn.get_style_context().add_class("secondary-btn")
        cancel_btn.connect("clicked", lambda *_: self._close_window(exit_code=2))
        bottom_row.pack_end(cancel_btn, False, False, 0)
        outer.pack_start(bottom_row, False, False, 2)

        self.win.show_all()
        self.win.present()
        self.switch_method(self.active_method)

    def _create_method_button(self, icon_name: str, text: str, method_id: str) -> Any:
        Gtk = self.Gtk
        btn = Gtk.Button()
        box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=6)
        box.set_halign(Gtk.Align.CENTER)
        icon = Gtk.Image.new_from_icon_name(icon_name, Gtk.IconSize.BUTTON)
        lbl = Gtk.Label(label=text)
        box.pack_start(icon, False, False, 0)
        box.pack_start(lbl, False, False, 0)
        btn.add(box)
        btn.connect("clicked", lambda *_: self.switch_method(method_id))
        return btn

    def _set_status(self, message: str, level: str = "info") -> None:
        ctx = self.status_label.get_style_context()
        for cls in ("status-ok", "status-warn", "status-err", "subtitle-label"):
            ctx.remove_class(cls)
        if level == "ok":
            ctx.add_class("status-ok")
        elif level == "warn":
            ctx.add_class("status-warn")
        elif level == "err":
            ctx.add_class("status-err")
        else:
            ctx.add_class("subtitle-label")
        self.status_label.set_text(message)

    def _on_combo_changed(self, combo: Any) -> None:
        if self._syncing_selector:
            return
        selected = combo.get_active_id()
        if selected and selected != self.active_method:
            self.switch_method(selected)

    def _update_selector_styles(self) -> None:
        self._syncing_selector = True
        try:
            self.method_combo.set_active_id(self.active_method)
            mapping = [
                (self.btn_face, METHOD_FACE),
                (self.btn_fp, METHOD_FINGERPRINT),
                (self.btn_pw, METHOD_PASSWORD),
            ]
            for btn, m_id in mapping:
                ctx = btn.get_style_context()
                ctx.remove_class("method-icon-btn")
                ctx.remove_class("method-icon-btn-active")
                if m_id == self.active_method:
                    ctx.add_class("method-icon-btn-active")
                else:
                    ctx.add_class("method-icon-btn")
        finally:
            self._syncing_selector = False

    def switch_method(self, method_id: str) -> None:
        """Switch between Face Lock, Fingerprint, and System Password."""
        self._stop_camera()
        self._fp_running = False

        # Check rate-limiter lockout if user tries a biometric method
        if method_id in (METHOD_FACE, METHOD_FINGERPRINT):
            allowed, rem, lock_sec = self.rate_limiter.check_biometric_allowed(self.username)
            if not allowed:
                self.active_method = METHOD_PASSWORD
                self._update_selector_styles()
                self.stack.set_visible_child_name(METHOD_PASSWORD)
                self._set_status(
                    f"Biometrics locked out for {lock_sec}s after failed attempts. Enter system password.",
                    level="err",
                )
                self.pw_entry.grab_focus()
                return

        self.active_method = method_id
        self._update_selector_styles()
        self.stack.set_visible_child_name(method_id)

        if method_id == METHOD_FACE:
            self._start_face_mode()
        elif method_id == METHOD_FINGERPRINT:
            self._start_fingerprint_mode()
        else:
            self._set_status("Enter your Linux system password and press Enter.", level="info")
            self.pw_entry.grab_focus()

    # --- Mode 1: Face Lock ---
    def _start_face_mode(self) -> None:
        self._stop_camera()
        self._load_user_profile()
        self._liveness = LivenessState()
        self._visual_state = "scanning"
        self._match_confidence = 0.0
        self._scan_start_time = time.time()

        if not self._face_profile or not self._face_profile.get("samples"):
            self._visual_state = "error"
            self._set_status(
                f"No face profile enrolled for '{self.username}'. Enroll in Control Center or switch to Password.",
                level="warn",
            )
            self.camera_area.queue_draw()
            return

        cam_idx = int(self.cfg.get("camera", {}).get("device_index", 0))
        cap = cv2.VideoCapture(cam_idx)
        if not cap.isOpened():
            self._visual_state = "error"
            self._set_status(
                f"Camera /dev/video{cam_idx} unavailable. Switch to Fingerprint or Password below.",
                level="warn",
            )
            self.camera_area.queue_draw()
            return

        cap.set(cv2.CAP_PROP_FRAME_WIDTH, float(self.cfg.get("camera", {}).get("width", 640)))
        cap.set(cv2.CAP_PROP_FRAME_HEIGHT, float(self.cfg.get("camera", {}).get("height", 480)))
        self._cap = cap
        self._set_status("Looking for you... Look at the camera.", level="info")
        self._camera_timer_id = self.GLib.timeout_add(45, self._on_camera_tick)

    def _on_camera_tick(self) -> bool:
        if self.active_method != METHOD_FACE or self._cap is None:
            return False

        self._scan_phase += 0.16
        elapsed = time.time() - self._scan_start_time
        if elapsed > self._scan_timeout:
            self._visual_state = "error"
            locked, rem, lock_sec = self.rate_limiter.record_biometric_failure(self.username)
            log_auth_event(
                self.username,
                self.service,
                METHOD_FACE,
                False,
                reason="Face scan timeout",
                confidence=self._match_confidence,
            )
            self._stop_camera()
            if locked:
                self.switch_method(METHOD_PASSWORD)
            else:
                self._set_status(
                    f"Face scan timed out ({rem} biometric attempts left). Click 'Scan Face Again' or switch method.",
                    level="warn",
                )
            self.camera_area.queue_draw()
            return False

        ok, frame = self._cap.read()
        if not ok or frame is None:
            self.camera_area.queue_draw()
            return True

        self._current_frame = frame
        verified, conf, live_score, msg, det = self.face_engine.verify_frame_for_user(
            self.username,
            frame,
            liveness_state=self._liveness,
            profile_cache=self._face_profile,
        )
        self._last_det = det
        self._match_confidence = conf

        if verified:
            self._visual_state = "matched"
            self._set_status(f"✔ {msg}", level="ok")
            self.camera_area.queue_draw()
            self._stop_camera()
            self.rate_limiter.reset(self.username)
            log_auth_event(
                self.username,
                self.service,
                METHOD_FACE,
                True,
                reason="Face + liveness verified",
                confidence=conf,
                liveness=live_score,
            )
            self._complete_authentication(METHOD_FACE)
            return False

        self._set_status(msg, level="info" if det.detected else "warn")
        self.camera_area.queue_draw()
        return True

    def _on_draw_camera(self, widget: Any, cr: Any) -> bool:
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
            state=self._visual_state,
            confidence=self._match_confidence,
        )
        return False

    def _stop_camera(self) -> None:
        if self._camera_timer_id is not None:
            try:
                self.GLib.source_remove(self._camera_timer_id)
            except Exception:
                pass
            self._camera_timer_id = None
        if self._cap is not None:
            try:
                self._cap.release()
            except Exception:
                pass
            self._cap = None

    # --- Mode 2: Fingerprint ---
    def _start_fingerprint_mode(self) -> None:
        self._visual_state = "scanning"
        self._fp_running = True
        self.GLib.timeout_add(50, self._on_fp_anim_tick)

        st = self.fp_engine.get_status(self.username)
        if not st.device_present:
            self._visual_state = "error"
            self._set_status(
                f"{st.device_name}. Switch to Face Lock or System Password below.",
                level="warn",
            )
            self.fp_area.queue_draw()
            return
        if not st.enrolled_fingers:
            self._visual_state = "error"
            self._set_status(
                f"Sensor '{st.device_name}' ready, but no fingerprint enrolled for '{self.username}'.",
                level="warn",
            )
            self.fp_area.queue_draw()
            return

        self._set_status(f"Touch fingerprint sensor ({st.device_name})...", level="info")

        def _worker() -> None:
            ok, msg = self.fp_engine.verify(
                self.username,
                status_cb=lambda s: self.GLib.idle_add(self._set_status, s, "info"),
            )
            if not self._fp_running or self.active_method != METHOD_FINGERPRINT:
                return
            self.GLib.idle_add(self._on_fingerprint_finished, ok, msg)

        self._fp_thread = threading.Thread(target=_worker, daemon=True)
        self._fp_thread.start()

    def _on_fp_anim_tick(self) -> bool:
        if self.active_method != METHOD_FINGERPRINT or not self._fp_running:
            return False
        self._scan_phase += 0.12
        self.fp_area.queue_draw()
        return True

    def _on_fingerprint_finished(self, ok: bool, msg: str) -> bool:
        self._fp_running = False
        if ok:
            self._visual_state = "matched"
            self.fp_area.queue_draw()
            self._set_status(f"✔ {msg}", level="ok")
            self.rate_limiter.reset(self.username)
            log_auth_event(self.username, self.service, METHOD_FINGERPRINT, True, reason=msg)
            self._complete_authentication(METHOD_FINGERPRINT)
        else:
            self._visual_state = "error"
            self.fp_area.queue_draw()
            locked, rem, _ = self.rate_limiter.record_biometric_failure(self.username)
            log_auth_event(self.username, self.service, METHOD_FINGERPRINT, False, reason=msg)
            if locked:
                self.switch_method(METHOD_PASSWORD)
            else:
                self._set_status(f"{msg} ({rem} attempts left)", level="err")
        return False

    def _on_draw_fingerprint(self, widget: Any, cr: Any) -> bool:
        w = widget.get_allocated_width()
        h = widget.get_allocated_height()
        self._draw_fp_radar(cr, w, h, self._scan_phase, state=self._visual_state)
        return False

    # --- Mode 3: System Password ---
    def _on_verify_password(self, *_args: Any) -> None:
        password = self.pw_entry.get_text()
        if not password:
            self._set_status("Please enter your system password.", level="warn")
            return

        self._set_status("Verifying system password...", level="info")
        ok, msg = verify_system_password(self.username, password)
        # Clear password buffer in entry immediately
        self.pw_entry.set_text("")

        if ok:
            self.rate_limiter.reset(self.username)
            log_auth_event(self.username, self.service, METHOD_PASSWORD, True, reason=msg)
            self._set_status(f"✔ {msg}", level="ok")
            self._complete_authentication(METHOD_PASSWORD)
        else:
            log_auth_event(self.username, self.service, METHOD_PASSWORD, False, reason=msg)
            self._set_status(f"✘ {msg}", level="err")
            self.pw_entry.grab_focus()

    def _complete_authentication(self, method: str) -> None:
        self.authenticated = True
        self.auth_method_used = method
        self.exit_code = 0
        delay_ms = int(self.cfg.get("ui", {}).get("close_delay_ms", 420))
        self.GLib.timeout_add(max(100, delay_ms), lambda: self._close_window(exit_code=0))

    def _on_key_press(self, _widget: Any, event: Any) -> bool:
        if event.keyval == self.Gdk.KEY_Escape:
            self._close_window(exit_code=2)
            return True
        return False

    def _close_window(self, exit_code: int) -> bool:
        self._stop_camera()
        self._fp_running = False
        self.exit_code = exit_code
        self.win.destroy()
        return False

    def _on_destroy(self, *_args: Any) -> None:
        self._stop_camera()
        self._fp_running = False
        if self.Gtk.main_level() > 0:
            self.Gtk.main_quit()

    def run(self) -> int:
        self.Gtk.main()
        return self.exit_code


def run_headless_tty_prompt(username: str, service: str) -> int:
    """
    Fallback interactive terminal prompt when no X11/Wayland GUI display is available.
    Lets the user pick [1] Face Lock, [2] Fingerprint, or [3] System Password.
    """
    if not sys.stdin.isatty():
        return 2

    cfg = ConfigManager().data
    face_engine = FaceBiometricEngine(cfg)
    fp_engine = FingerprintEngine()

    print(f"\n[Kali Hello Security] Authentication required for {username} ({service})")
    print("  [1] Face Lock (Camera)   [2] Fingerprint (fprintd)   [3] System Password")
    try:
        choice = input("Select method [1/2/3, Enter=default]: ").strip()
    except (EOFError, KeyboardInterrupt):
        return 2

    method = cfg.get("default_method", METHOD_FACE)
    if choice == "1":
        method = METHOD_FACE
    elif choice == "2":
        method = METHOD_FINGERPRINT
    elif choice == "3":
        method = METHOD_PASSWORD

    if method == METHOD_FACE:
        profile = load_encrypted_face_profile(username)
        if not profile:
            print("No face profile enrolled; falling back to password prompt.")
            return 2
        cam_idx = int(cfg.get("camera", {}).get("device_index", 0))
        cap = cv2.VideoCapture(cam_idx)
        if not cap.isOpened():
            return 2
        liveness = LivenessState()
        start = time.time()
        try:
            while (time.time() - start) < 8.0:
                ok, frame = cap.read()
                if not ok:
                    continue
                verified, conf, live, _, _ = face_engine.verify_frame_for_user(
                    username, frame, liveness_state=liveness, profile_cache=profile
                )
                if verified:
                    print(f"[Kali Hello] Face verified ({int(conf * 100)}%).")
                    log_auth_event(username, service, METHOD_FACE, True, confidence=conf, liveness=live)
                    return 0
        finally:
            cap.release()
        return 2

    if method == METHOD_FINGERPRINT:
        ok, msg = fp_engine.verify(username)
        print(f"[Kali Hello] {msg}")
        log_auth_event(username, service, METHOD_FINGERPRINT, ok, reason=msg)
        return 0 if ok else 2

    try:
        pw = getpass.getpass(f"[Kali Hello] Password for {username}: ")
    except (EOFError, KeyboardInterrupt):
        return 2
    ok, msg = verify_system_password(username, pw)
    log_auth_event(username, service, METHOD_PASSWORD, ok, reason=msg)
    return 0 if ok else 10


def launch_authentication_prompt(
    username: Optional[str] = None,
    service: str = "sudo",
    initial_method: Optional[str] = None,
    title_override: Optional[str] = None,
) -> int:
    """
    Launch the Windows Hello GTK3 prompt if a graphical session is active,
    otherwise fall back cleanly to TTY mode.
    """
    user = username or detect_active_username()
    if os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY"):
        try:
            app = WindowsHelloPromptWindow(
                username=user,
                service=service,
                initial_method=initial_method,
                title_override=title_override,
            )
            return app.run()
        except Exception:
            pass
    return run_headless_tty_prompt(user, service)
