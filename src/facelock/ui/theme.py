"""
Windows 11 / Windows Hello Fluent Dark GTK3 styling and Cairo biometric HUD rendering.
"""

import math
from typing import Optional, Tuple

import cairo
import cv2
import numpy as np

KALI_DARK_CSS = b"""
window, dialog, .facelock-window {
    background-color: #11141b;
    color: #f3f4f6;
    font-family: "Segoe UI Variable", "Segoe UI", "Cantarell", "Inter", sans-serif;
}

.prompt-card {
    background-color: #181c26;
    border: 1px solid #2b3242;
    border-radius: 14px;
    padding: 20px;
}

.header-badge {
    background-color: rgba(0, 120, 212, 0.16);
    color: #60a5fa;
    border: 1px solid rgba(56, 189, 248, 0.35);
    border-radius: 999px;
    padding: 4px 12px;
    font-size: 11px;
    font-weight: 700;
    letter-spacing: 0.6px;
}

.title-label {
    font-size: 19px;
    font-weight: 700;
    color: #f8fafc;
}

.section-title {
    font-size: 14px;
    font-weight: 700;
    color: #f1f5f9;
}

.subtitle-label {
    font-size: 12.5px;
    color: #9ca3af;
}

.user-pill {
    background-color: #202634;
    border: 1px solid #30394d;
    border-radius: 999px;
    padding: 6px 14px;
    color: #e5e7eb;
    font-weight: 600;
    font-size: 12.5px;
}

.status-ok {
    color: #34d399;
    font-weight: 600;
}

.status-warn {
    color: #fbbf24;
    font-weight: 600;
}

.status-err {
    color: #f87171;
    font-weight: 600;
}

.method-icon-btn {
    background-image: none;
    background-color: #1f2430;
    color: #9ca3af;
    border: 1px solid #2d3548;
    border-radius: 8px;
    padding: 9px 12px;
    font-weight: 600;
    font-size: 12px;
}

.method-icon-btn:hover {
    background-color: #282f3f;
    color: #ffffff;
    border-color: #60a5fa;
}

.method-icon-btn-active {
    background-image: none;
    background-color: rgba(0, 120, 212, 0.24);
    color: #60cdff;
    border: 1px solid #0078d4;
    border-radius: 8px;
    padding: 9px 12px;
    font-weight: 700;
    font-size: 12px;
}

.primary-btn {
    background-image: none;
    background-color: #0078d4;
    color: #ffffff;
    border: 1px solid #2b95e8;
    border-radius: 8px;
    padding: 9px 16px;
    font-weight: 600;
}

.primary-btn:hover {
    background-color: #1084dc;
}

.success-btn {
    background-image: none;
    background-color: #0f766e;
    color: #ffffff;
    border: 1px solid #14b8a6;
    border-radius: 8px;
    padding: 9px 16px;
    font-weight: 600;
}

.success-btn:hover {
    background-color: #0d9488;
}

.warn-btn {
    background-image: none;
    background-color: rgba(217, 119, 6, 0.22);
    color: #fcd34d;
    border: 1px solid #f59e0b;
    border-radius: 8px;
    padding: 7px 14px;
    font-weight: 600;
}

.danger-btn {
    background-image: none;
    background-color: rgba(220, 38, 38, 0.16);
    color: #fca5a5;
    border: 1px solid #ef4444;
    border-radius: 8px;
    padding: 8px 12px;
    font-weight: 600;
}

.secondary-btn {
    background-image: none;
    background-color: #232936;
    color: #d1d5db;
    border: 1px solid #353e52;
    border-radius: 8px;
    padding: 8px 12px;
    font-weight: 600;
}

.secondary-btn:hover {
    background-color: #2e3647;
    color: #ffffff;
}

.panel-card {
    background-color: #181c26;
    border: 1px solid #272e3d;
    border-radius: 10px;
    padding: 14px 16px;
}

.hello-row-card {
    background-color: #1d222e;
    border: 1px solid #2c3446;
    border-radius: 8px;
    padding: 10px 12px;
}

.stat-value {
    font-size: 14px;
    font-weight: 700;
    color: #60cdff;
}

.stat-title {
    font-size: 12px;
    color: #9ca3af;
}

entry, combobox button {
    background-image: none;
    background-color: #12151e;
    color: #f9fafb;
    border: 1px solid #374151;
    border-radius: 6px;
    padding: 7px 10px;
}

entry:focus {
    border-color: #0078d4;
}

treeview {
    background-color: #131720;
    color: #e5e7eb;
}

treeview:selected {
    background-color: #0078d4;
    color: #ffffff;
}
"""


def apply_kali_theme() -> None:
    """Register the Windows Hello Fluent Dark CSS stylesheet globally."""
    import gi

    gi.require_version("Gdk", "3.0")
    gi.require_version("Gtk", "3.0")
    from gi.repository import Gdk, Gtk

    screen = Gdk.Screen.get_default()
    if screen is None:
        return
    provider = Gtk.CssProvider()
    provider.load_from_data(KALI_DARK_CSS)
    Gtk.StyleContext.add_provider_for_screen(
        screen,
        provider,
        Gtk.STYLE_PROVIDER_PRIORITY_APPLICATION,
    )


def draw_circular_camera_hud(
    cr: cairo.Context,
    width: int,
    height: int,
    frame_bgr: Optional[np.ndarray],
    bbox: Optional[Tuple[int, int, int, int]],
    scan_phase: float,
    state: str = "scanning",  # scanning | matched | error
    confidence: float = 0.0,
) -> None:
    """
    Render a Windows Hello-style circular biometric camera lens with glowing
    reticle segments, subtle scan line, and face tracking frame.
    """
    if width < 60 or height < 60:
        return
    cx = width / 2.0
    cy = height / 2.0
    radius = max(20.0, min(width, height) / 2.0 - 14.0)

    # Clear background to match card surface
    cr.set_source_rgb(0.094, 0.110, 0.149)
    cr.paint()

    cr.save()
    cr.arc(cx, cy, radius, 0, 2 * math.pi)
    cr.clip()

    if frame_bgr is not None and frame_bgr.size > 0:
        mirrored = cv2.flip(frame_bgr, 1)
        fh, fw = mirrored.shape[:2]

        diam = int(radius * 2)
        side = min(fw, fh)
        sx = (fw - side) // 2
        sy = (fh - side) // 2
        square = mirrored[sy : sy + side, sx : sx + side]
        resized = cv2.resize(square, (diam, diam), interpolation=cv2.INTER_LINEAR)

        if bbox is not None:
            bx, by, bw, bh = bbox
            mx = fw - (bx + bw)
            scale = diam / float(side)
            rx = int((mx - sx) * scale)
            ry = int((by - sy) * scale)
            rw = int(bw * scale)
            rh = int(bh * scale)
            color = (120, 235, 90) if state == "matched" else (255, 205, 96)
            cv2.rectangle(resized, (rx, ry), (rx + rw, ry + rh), color, 2)

        bgra = cv2.cvtColor(resized, cv2.COLOR_BGR2BGRA)
        bgra = np.ascontiguousarray(bgra)
        surface = cairo.ImageSurface.create_for_data(
            bgra, cairo.FORMAT_ARGB32, diam, diam, diam * 4
        )
        cr.set_source_surface(surface, cx - radius, cy - radius)
        cr.paint()

        if state == "scanning":
            scan_y = (cy - radius) + ((math.sin(scan_phase) + 1.0) / 2.0) * (radius * 2.0)
            grad = cairo.LinearGradient(0, scan_y - 14, 0, scan_y + 14)
            grad.add_color_stop_rgba(0.0, 0.0, 0.47, 0.83, 0.0)
            grad.add_color_stop_rgba(0.5, 0.38, 0.80, 1.00, 0.42)
            grad.add_color_stop_rgba(1.0, 0.0, 0.47, 0.83, 0.0)
            cr.set_source(grad)
            cr.rectangle(cx - radius, scan_y - 14, radius * 2, 28)
            cr.fill()
    else:
        # Windows Hello idle smiling/eye glyph placeholder
        cr.set_source_rgb(0.071, 0.082, 0.118)
        cr.paint()
        cr.set_source_rgba(0.38, 0.80, 1.00, 0.85)
        cr.set_line_width(3.0)
        # Eyes
        cr.arc(cx - 24, cy - 12, 4.5, 0, 2 * math.pi)
        cr.fill()
        cr.arc(cx + 24, cy - 12, 4.5, 0, 2 * math.pi)
        cr.fill()
        # Nose bridge
        cr.move_to(cx, cy - 12)
        cr.line_to(cx, cy + 10)
        cr.line_to(cx - 6, cy + 12)
        cr.stroke()
        # Smile arc
        cr.arc(cx, cy + 8, 22, 0.2 * math.pi, 0.8 * math.pi)
        cr.stroke()

    cr.restore()

    if state == "matched":
        ring_color = (0.20, 0.83, 0.60)
    elif state == "error":
        ring_color = (0.97, 0.44, 0.44)
    else:
        ring_color = (0.38, 0.80, 1.00)

    cr.set_line_width(2.5)
    cr.set_source_rgba(ring_color[0], ring_color[1], ring_color[2], 0.30)
    cr.arc(cx, cy, radius + 3, 0, 2 * math.pi)
    cr.stroke()

    cr.set_line_width(4.0)
    cr.set_source_rgba(ring_color[0], ring_color[1], ring_color[2], 0.95)
    for i in range(3):
        base_angle = scan_phase * 0.85 + i * (2 * math.pi / 3.0)
        cr.arc(cx, cy, radius + 5, base_angle, base_angle + 0.85)
        cr.stroke()

    if confidence > 0.02:
        cr.set_line_width(3.0)
        cr.set_source_rgba(0.20, 0.83, 0.60, 0.90)
        cr.arc(cx, cy, radius - 3, -math.pi / 2, -math.pi / 2 + (2 * math.pi * min(1.0, confidence)))
        cr.stroke()


def draw_fingerprint_radar(
    cr: cairo.Context,
    width: int,
    height: int,
    pulse_phase: float,
    state: str = "scanning",
) -> None:
    """Render a Windows Hello-style concentric fingerprint scanner glyph."""
    if width < 60 or height < 60:
        return
    cx = width / 2.0
    cy = height / 2.0
    cr.set_source_rgb(0.094, 0.110, 0.149)
    cr.paint()

    if state == "matched":
        color = (0.20, 0.83, 0.60)
    elif state == "error":
        color = (0.97, 0.44, 0.44)
    else:
        color = (0.38, 0.80, 1.00)

    pulse_r = 24.0 + ((math.sin(pulse_phase * 2.0) + 1.0) / 2.0) * 56.0
    cr.set_source_rgba(color[0], color[1], color[2], 0.16)
    cr.arc(cx, cy, pulse_r, 0, 2 * math.pi)
    cr.fill()

    cr.set_line_width(3.0)
    for idx, r in enumerate([16, 26, 36, 46, 56, 66]):
        alpha = 0.92 - idx * 0.09
        cr.set_source_rgba(color[0], color[1], color[2], alpha)
        offset = math.sin(pulse_phase + idx * 0.55) * 0.16
        cr.arc(cx, cy + 5, r, math.pi * 0.85 + offset, math.pi * 2.15 + offset)
        cr.stroke()
        cr.arc(cx, cy + 5, r, math.pi * 0.25 - offset, math.pi * 0.65 - offset)
        cr.stroke()
