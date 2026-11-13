"""
Kali Dark / Windows Hello GTK3 CSS styling and custom Cairo visual rendering.
"""

import math
from typing import Optional, Tuple

import cairo
import cv2
import numpy as np

KALI_DARK_CSS = b"""
window, dialog, .facelock-window {
    background-color: #0b0f17;
    color: #e6edf3;
    font-family: "Cantarell", "Inter", "Segoe UI", sans-serif;
}

.prompt-card {
    background-color: #111827;
    border: 1px solid #1f2937;
    border-radius: 16px;
    padding: 20px;
}

.header-badge {
    background-color: rgba(0, 212, 255, 0.12);
    color: #38bdf8;
    border: 1px solid rgba(56, 189, 248, 0.35);
    border-radius: 999px;
    padding: 4px 12px;
    font-size: 11px;
    font-weight: 700;
    letter-spacing: 0.8px;
}

.title-label {
    font-size: 20px;
    font-weight: 700;
    color: #f8fafc;
}

.subtitle-label {
    font-size: 13px;
    color: #94a3b8;
}

.user-pill {
    background-color: #162032;
    border: 1px solid #26354d;
    border-radius: 10px;
    padding: 8px 14px;
    color: #e2e8f0;
    font-weight: 600;
}

.status-ok {
    color: #34d399;
    font-weight: 700;
}

.status-warn {
    color: #fbbf24;
    font-weight: 600;
}

.status-err {
    color: #f87171;
    font-weight: 700;
}

.method-icon-btn {
    background-image: none;
    background-color: #151e2e;
    color: #94a3b8;
    border: 1px solid #23314b;
    border-radius: 10px;
    padding: 9px 14px;
    font-weight: 600;
    font-size: 12px;
}

.method-icon-btn:hover {
    background-color: #1c283d;
    color: #f1f5f9;
    border-color: #38bdf8;
}

.method-icon-btn-active {
    background-image: none;
    background-color: rgba(14, 165, 233, 0.22);
    color: #38bdf8;
    border: 1px solid #0ea5e9;
    border-radius: 10px;
    padding: 9px 14px;
    font-weight: 700;
    font-size: 12px;
}

.primary-btn {
    background-image: none;
    background-color: #0284c7;
    color: #ffffff;
    border: 1px solid #38bdf8;
    border-radius: 9px;
    padding: 9px 16px;
    font-weight: 700;
}

.primary-btn:hover {
    background-color: #0369a1;
}

.success-btn {
    background-image: none;
    background-color: #059669;
    color: #ffffff;
    border: 1px solid #34d399;
    border-radius: 9px;
    padding: 9px 16px;
    font-weight: 700;
}

.danger-btn {
    background-image: none;
    background-color: rgba(220, 38, 38, 0.2);
    color: #fca5a5;
    border: 1px solid #ef4444;
    border-radius: 9px;
    padding: 8px 14px;
    font-weight: 600;
}

.secondary-btn {
    background-image: none;
    background-color: #1e293b;
    color: #cbd5e1;
    border: 1px solid #334155;
    border-radius: 9px;
    padding: 8px 14px;
    font-weight: 600;
}

.secondary-btn:hover {
    background-color: #334155;
    color: #ffffff;
}

.panel-card {
    background-color: #111827;
    border: 1px solid #1e293b;
    border-radius: 12px;
    padding: 16px;
}

.stat-value {
    font-size: 17px;
    font-weight: 700;
    color: #38bdf8;
}

.stat-title {
    font-size: 12px;
    color: #94a3b8;
}

entry, combobox button {
    background-image: none;
    background-color: #0f172a;
    color: #f8fafc;
    border: 1px solid #334155;
    border-radius: 8px;
    padding: 7px 11px;
}

entry:focus {
    border-color: #38bdf8;
}

notebook header {
    background-color: #0f172a;
    border-bottom: 1px solid #1e293b;
}

notebook tab {
    background-color: transparent;
    color: #94a3b8;
    padding: 10px 18px;
    font-weight: 600;
}

notebook tab:checked {
    color: #38bdf8;
    border-bottom: 2px solid #38bdf8;
}
"""


def apply_kali_theme() -> None:
    """Register the Kali Dark / Windows Hello CSS stylesheet globally on the default screen."""
    import gi

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
    Render a Windows Hello-style circular biometric camera viewfinder with glowing
    reticle arcs, sweeping laser scan line, and face detection bounding overlay.
    """
    cx = width / 2.0
    cy = height / 2.0
    radius = min(width, height) / 2.0 - 14.0

    # Background clear
    cr.set_source_rgb(0.067, 0.094, 0.153)
    cr.paint()

    # Clip camera feed to circular lens
    cr.save()
    cr.arc(cx, cy, radius, 0, 2 * math.pi)
    cr.clip()

    if frame_bgr is not None and frame_bgr.size > 0:
        # Mirror horizontally for natural selfie view
        mirrored = cv2.flip(frame_bgr, 1)
        fh, fw = mirrored.shape[:2]

        # Center-crop to square and resize to circle diameter
        diam = int(radius * 2)
        side = min(fw, fh)
        sx = (fw - side) // 2
        sy = (fh - side) // 2
        square = mirrored[sy : sy + side, sx : sx + side]
        resized = cv2.resize(square, (diam, diam), interpolation=cv2.INTER_LINEAR)

        # Draw subtle face targeting box inside lens if detected
        if bbox is not None:
            bx, by, bw, bh = bbox
            # Mirror X coordinate
            mx = fw - (bx + bw)
            scale = diam / float(side)
            rx = int((mx - sx) * scale)
            ry = int((by - sy) * scale)
            rw = int(bw * scale)
            rh = int(bh * scale)
            color = (120, 235, 60) if state == "matched" else (255, 200, 30)
            cv2.rectangle(resized, (rx, ry), (rx + rw, ry + rh), color, 2)

        # Convert BGR to Cairo ARGB32 (BGRA in little-endian memory)
        bgra = cv2.cvtColor(resized, cv2.COLOR_BGR2BGRA)
        bgra = np.ascontiguousarray(bgra)
        surface = cairo.ImageSurface.create_for_data(
            bgra, cairo.FORMAT_ARGB32, diam, diam, diam * 4
        )
        cr.set_source_surface(surface, cx - radius, cy - radius)
        cr.paint()

        # Subtle HUD scanline sweep when scanning
        if state == "scanning":
            scan_y = (cy - radius) + ((math.sin(scan_phase) + 1.0) / 2.0) * (radius * 2.0)
            grad = cairo.LinearGradient(0, scan_y - 16, 0, scan_y + 16)
            grad.add_color_stop_rgba(0.0, 0.0, 0.83, 1.0, 0.0)
            grad.add_color_stop_rgba(0.5, 0.22, 0.74, 0.98, 0.45)
            grad.add_color_stop_rgba(1.0, 0.0, 0.83, 1.0, 0.0)
            cr.set_source(grad)
            cr.rectangle(cx - radius, scan_y - 16, radius * 2, 32)
            cr.fill()
    else:
        # Placeholder dark lens when camera is warming up
        cr.set_source_rgb(0.04, 0.06, 0.11)
        cr.paint()
        cr.set_source_rgba(0.22, 0.74, 0.97, 0.5)
        cr.select_font_face("Sans", cairo.FONT_SLANT_NORMAL, cairo.FONT_WEIGHT_BOLD)
        cr.set_font_size(13)
        text = "INITIALIZING CAMERA..."
        ext = cr.text_extents(text)
        cr.move_to(cx - ext.width / 2, cy + ext.height / 2)
        cr.show_text(text)

    cr.restore()

    # Outer biometric scanner ring
    if state == "matched":
        ring_color = (0.20, 0.83, 0.60)  # Emerald green
    elif state == "error":
        ring_color = (0.97, 0.44, 0.44)  # Coral red
    else:
        ring_color = (0.22, 0.74, 0.97)  # Kali cyan-blue

    cr.set_line_width(3.0)
    cr.set_source_rgba(ring_color[0], ring_color[1], ring_color[2], 0.35)
    cr.arc(cx, cy, radius + 3, 0, 2 * math.pi)
    cr.stroke()

    # Rotating outer HUD segments
    cr.set_line_width(4.5)
    cr.set_source_rgba(ring_color[0], ring_color[1], ring_color[2], 0.95)
    for i in range(3):
        base_angle = scan_phase * 0.9 + i * (2 * math.pi / 3.0)
        cr.arc(cx, cy, radius + 5, base_angle, base_angle + 0.85)
        cr.stroke()

    # Inner confidence progress arc
    if confidence > 0.02:
        cr.set_line_width(3.0)
        cr.set_source_rgba(0.20, 0.83, 0.60, 0.85)
        cr.arc(cx, cy, radius - 3, -math.pi / 2, -math.pi / 2 + (2 * math.pi * min(1.0, confidence)))
        cr.stroke()


def draw_fingerprint_radar(
    cr: cairo.Context,
    width: int,
    height: int,
    pulse_phase: float,
    state: str = "scanning",
) -> None:
    """
    Render an animated fingerprint biometric scanner graphic with concentric ridges.
    """
    cx = width / 2.0
    cy = height / 2.0
    cr.set_source_rgb(0.067, 0.094, 0.153)
    cr.paint()

    if state == "matched":
        color = (0.20, 0.83, 0.60)
    elif state == "error":
        color = (0.97, 0.44, 0.44)
    else:
        color = (0.22, 0.74, 0.97)

    # Pulsing sonar halo
    pulse_r = 25.0 + ((math.sin(pulse_phase * 2.0) + 1.0) / 2.0) * 58.0
    cr.set_source_rgba(color[0], color[1], color[2], 0.18)
    cr.arc(cx, cy, pulse_r, 0, 2 * math.pi)
    cr.fill()

    # Concentric fingerprint ridge arcs
    cr.set_line_width(3.2)
    for idx, r in enumerate([16, 26, 36, 46, 56, 66]):
        alpha = 0.9 - idx * 0.09
        cr.set_source_rgba(color[0], color[1], color[2], alpha)
        offset = math.sin(pulse_phase + idx * 0.6) * 0.18
        cr.arc(cx, cy + 6, r, math.pi * 0.85 + offset, math.pi * 2.15 + offset)
        cr.stroke()
        cr.arc(cx, cy + 6, r, math.pi * 0.25 - offset, math.pi * 0.65 - offset)
        cr.stroke()
