"""
Face detection, anti-spoofing liveness analysis, and hybrid biometric feature
extraction (Neural ONNX YuNet/SFace + Offline Illumination-Normalized LBP/HOG/DCT).
"""

import datetime
import math
import os
import time
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

import cv2
import numpy as np

from facelock.constants import (
    ENCODINGS_DIR,
    INTRUDER_DIR,
    MODELS_DIR,
    SFACE_MODEL_URL,
    YUNET_MODEL_URL,
)
from facelock.core.crypto import (
    get_face_profile_metadata,
    load_encrypted_face_profile,
    save_encrypted_face_profile,
)

CASCADE_SEARCH_DIRS = [
    Path("/usr/share/opencv4/haarcascades"),
    Path("/usr/share/opencv4/lbpcascades"),
    Path("/usr/share/opencv/haarcascades"),
]
if hasattr(cv2, "data") and hasattr(cv2.data, "haarcascades"):
    CASCADE_SEARCH_DIRS.insert(0, Path(cv2.data.haarcascades))


@dataclass
class FaceDetectionResult:
    detected: bool
    bbox: Optional[Tuple[int, int, int, int]] = None  # (x, y, w, h)
    eyes: List[Tuple[int, int, int, int]] = field(default_factory=list)
    landmarks: Optional[np.ndarray] = None
    brightness: float = 0.0
    sharpness: float = 0.0
    quality_ok: bool = False
    quality_message: str = ""
    aligned_gray: Optional[np.ndarray] = None
    aligned_color: Optional[np.ndarray] = None


@dataclass
class LivenessState:
    frames_With_face: int = 0
    eye_states: List[int] = field(default_factory=list)
    center_positions: List[Tuple[float, float]] = field(default_factory=list)
    face_sizes: List[float] = field(default_factory=list)
    frame_diffs: List[float] = field(default_factory=list)
    sharpness_scores: List[float] = field(default_factory=list)
    parallax_ratios: List[float] = field(default_factory=list)
    prev_face_crop: Optional[np.ndarray] = None

    def update(self, frame_gray: np.ndarray, det: FaceDetectionResult) -> Tuple[bool, float, str]:
        """
        Update temporal liveness tracker and compute anti-spoofing confidence in [0.0, 1.0].
        Returns (passed, liveness_score, status_hint).
        """
        if not det.detected or det.bbox is None or det.aligned_gray is None:
            return False, 0.0, "Position your face inside the scanner ring"

        self.frames_With_face += 1
        x, y, w, h = det.bbox
        cx = x + w / 2.0
        cy = y + h / 2.0
        self.center_positions.append((cx, cy))
        self.face_sizes.append(float(w * h))
        self.eye_states.append(len(det.eyes))
        self.sharpness_scores.append(det.sharpness)

        crop = cv2.resize(det.aligned_gray, (96, 96))
        if self.prev_face_crop is not None:
            diff = float(np.mean(np.abs(crop.astype(np.float32) - self.prev_face_crop.astype(np.float32))))
            self.frame_diffs.append(diff)

            # Compare inner nose/eye core shift vs outer face boundary shift (3D parallax cue)
            inner_curr = crop[24:72, 24:72].astype(np.float32)
            inner_prev = self.prev_face_crop[24:72, 24:72].astype(np.float32)
            inner_diff = float(np.mean(np.abs(inner_curr - inner_prev))) + 1e-4
            outer_diff = max(diff, 1e-4)
            self.parallax_ratios.append(abs(inner_diff - outer_diff) / outer_diff)

        self.prev_face_crop = crop

        if self.frames_With_face < 3:
            return False, 0.25, "Hold steady — verifying depth & texture..."

        # 1. Texture & anti-screen glare score
        avg_sharp = float(np.mean(self.sharpness_scores[-6:]))
        texture_score = min(1.0, max(0.0, (avg_sharp - 18.0) / 85.0))

        # 2. Micro-movement / non-static frame check (rejects frozen images)
        recent_diffs = self.frame_diffs[-6:]
        avg_diff = float(np.mean(recent_diffs)) if recent_diffs else 0.0
        diff_std = float(np.std(recent_diffs)) if len(recent_diffs) >= 2 else 0.0
        if avg_diff < 0.35:
            motion_score = 0.1  # Suspiciously frozen frame
        elif 0.45 <= avg_diff <= 22.0:
            motion_score = min(1.0, 0.55 + diff_std * 0.25 + min(0.35, avg_diff / 18.0))
        else:
            motion_score = 0.4  # Excessive motion blur

        # 3. Eye landmark / blink modulation check
        eyes_detected_any = any(e >= 1 for e in self.eye_states[-8:])
        eyes_both = any(e >= 2 for e in self.eye_states[-8:])
        eye_variation = len(set(self.eye_states[-8:])) > 1
        eye_score = 0.45
        if eyes_both:
            eye_score = 0.85
        elif eyes_detected_any:
            eye_score = 0.70
        if eye_variation and eyes_detected_any:
            eye_score = 1.0  # Blink or natural eye state change observed

        # 4. 3D Parallax variance
        parallax_val = float(np.mean(self.parallax_ratios[-5:])) if self.parallax_ratios else 0.0
        parallax_score = min(1.0, max(0.2, parallax_val * 4.5))

        total_score = (
            0.30 * texture_score
            + 0.30 * motion_score
            + 0.25 * eye_score
            + 0.15 * parallax_score
        )
        total_score = round(min(1.0, max(0.0, total_score)), 4)

        if total_score >= 0.54:
            return True, total_score, "Liveness verified"
        return False, total_score, "Blink naturally or move head slightly"


def enumerate_cameras(max_index: int = 6) -> List[Dict[str, Any]]:
    """
    Discover available V4L2 video capture devices on Linux.
    """
    cameras: List[Dict[str, Any]] = []
    sys_video = Path("/sys/class/video4linux")
    if sys_video.is_dir():
        for entry in sorted(sys_video.iterdir()):
            if not entry.name.startswith("video"):
                continue
            idx_str = entry.name.replace("video", "")
            if not idx_str.isdigit():
                continue
            idx = int(idx_str)
            name_file = entry / "name"
            dev_name = f"Camera {idx}"
            if name_file.is_file():
                try:
                    dev_name = name_file.read_text(encoding="utf-8").strip()
                except Exception:
                    pass
            dev_path = f"/dev/video{idx}"
            if os.path.exists(dev_path):
                cameras.append({"index": idx, "name": dev_name, "path": dev_path})
    if not cameras:
        for idx in range(max_index):
            if os.path.exists(f"/dev/video{idx}"):
                cameras.append(
                    {"index": idx, "name": f"V4L2 Camera #{idx}", "path": f"/dev/video{idx}"}
                )
    return cameras


def _find_cascade(filenames: List[str]) -> Optional[Any]:
    if not hasattr(cv2, "CascadeClassifier"):
        return None
    for directory in CASCADE_SEARCH_DIRS:
        if not directory.is_dir():
            continue
        for fname in filenames:
            candidate = directory / fname
            if candidate.is_file():
                try:
                    clf = cv2.CascadeClassifier(str(candidate))
                    if not clf.empty():
                        return clf
                except Exception:
                    continue
    return None


def _detect_face_geometric_fallback(
    frame_bgr: np.ndarray,
    gray: np.ndarray,
    min_size: int = 80,
) -> Tuple[Optional[Tuple[int, int, int, int]], List[Tuple[int, int, int, int]]]:
    """
    OpenCV 5+ offline fallback face and eye-pair detector when neither YuNet ONNX
    nor legacy CascadeClassifier is available. Combines YCrCb skin-chrominance
    segmentation with central gradient energy and bilateral eye-valley detection.
    """
    h_img, w_img = gray.shape[:2]
    if h_img < min_size or w_img < min_size:
        return None, []

    bbox: Optional[Tuple[int, int, int, int]] = None

    # 1. YCrCb skin-chrominance mask for natural RGB camera frames
    ycrcb = cv2.cvtColor(frame_bgr, cv2.COLOR_BGR2YCrCb)
    skin_mask = cv2.inRange(ycrcb, np.array([35, 133, 77], dtype=np.uint8), np.array([255, 175, 129], dtype=np.uint8))
    kernel = cv2.getStructuringElement(cv2.MORPH_ELLIPSE, (9, 9))
    skin_mask = cv2.morphologyEx(skin_mask, cv2.MORPH_CLOSE, kernel, iterations=2)
    skin_mask = cv2.morphologyEx(skin_mask, cv2.MORPH_OPEN, kernel, iterations=1)

    contours, _ = cv2.findContours(skin_mask, cv2.RETR_EXTERNAL, cv2.CHAIN_APPROX_SIMPLE)
    best_area = 0.0
    for cnt in contours:
        x, y, w, h = cv2.boundingRect(cnt)
        if w < min_size or h < min_size:
            continue
        aspect = float(h) / max(float(w), 1.0)
        if 0.80 <= aspect <= 1.85:
            area = float(w * h)
            if area > best_area and area < (w_img * h_img * 0.88):
                best_area = area
                bbox = (x, y, w, h)

    # 2. Gradient-energy center window fallback (for monochrome / IR cameras)
    if bbox is None:
        gx = cv2.Sobel(gray, cv2.CV_32F, 1, 0, ksize=3)
        gy = cv2.Sobel(gray, cv2.CV_32F, 0, 1, ksize=3)
        grad_energy = float(np.mean(np.hypot(gx, gy)))
        if grad_energy > 8.5:
            side = int(min(w_img, h_img) * 0.56)
            if side >= min_size:
                cx, cy = w_img // 2, h_img // 2
                bbox = (cx - side // 2, cy - side // 2, side, side)

    if bbox is None:
        return None, []

    # Locate bilateral dark eye regions in upper-middle half of face box
    x, y, w, h = bbox
    eyes: List[Tuple[int, int, int, int]] = []
    upper = gray[y + int(h * 0.20) : y + int(h * 0.55), x + int(w * 0.12) : x + int(w * 0.88)]
    if upper.size > 0:
        uh, uw = upper.shape[:2]
        mid = uw // 2
        left_half = upper[:, :mid]
        right_half = upper[:, mid:]
        ew = max(14, w // 6)
        eh = max(10, h // 10)
        if left_half.size > 0 and float(np.std(left_half)) > 8.0:
            min_idx = np.unravel_index(int(np.argmin(left_half)), left_half.shape)
            ex = x + int(w * 0.12) + int(min_idx[1]) - ew // 2
            ey = y + int(h * 0.20) + int(min_idx[0]) - eh // 2
            eyes.append((max(x, ex), max(y, ey), ew, eh))
        if right_half.size > 0 and float(np.std(right_half)) > 8.0:
            min_idx = np.unravel_index(int(np.argmin(right_half)), right_half.shape)
            ex = x + int(w * 0.12) + mid + int(min_idx[1]) - ew // 2
            ey = y + int(h * 0.20) + int(min_idx[0]) - eh // 2
            eyes.append((max(x, ex), max(y, ey), ew, eh))

    return bbox, eyes


def _tan_triggs_normalization(gray: np.ndarray) -> np.ndarray:
    """
    Illumination normalization pipeline (Gamma -> Difference of Gaussians -> Contrast Equalization)
    so facial descriptors remain invariant under bright or dim room lighting.
    """
    img = np.power(gray.astype(np.float32) / 255.0, 0.2)
    g1 = cv2.GaussianBlur(img, (0, 0), 1.0)
    g2 = cv2.GaussianBlur(img, (0, 0), 2.0)
    dog = g1 - g2

    alpha = 0.1
    tau = 10.0
    denom = np.power(np.mean(np.power(np.abs(dog), alpha)), 1.0 / alpha) + 1e-6
    dog = dog / denom
    denom2 = np.power(np.mean(np.power(np.minimum(np.abs(dog), tau), alpha)), 1.0 / alpha) + 1e-6
    dog = dog / denom2
    dog = tau * np.tanh(dog / tau)

    norm = cv2.normalize(dog, None, 0, 255, cv2.NORM_MINMAX)
    return norm.astype(np.uint8)


def _compute_spatial_lbp_hog_dct_embedding(aligned_gray: np.ndarray) -> np.ndarray:
    """
    Extract a 512-D L2-normalized spatial facial descriptor combining:
    - 4x4 grid multi-radius LBP texture histograms
    - 4x4 grid oriented gradient histograms
    - 2D DCT structural low-frequency coefficients
    """
    face = cv2.resize(aligned_gray, (128, 128), interpolation=cv2.INTER_AREA)
    clahe = cv2.createCLAHE(clipLimit=2.2, tileGridSize=(8, 8))
    eq = clahe.apply(face)
    tt = _tan_triggs_normalization(eq)

    # Apply elliptical mask to remove background corners
    mask = np.zeros_like(tt)
    cv2.ellipse(mask, (64, 64), (54, 62), 0, 0, 360, 255, -1)
    masked = cv2.bitwise_and(tt, mask)

    # 1. vectorized 8-neighbor LBP on 128x128
    padded = np.pad(masked, 1, mode="edge").astype(np.int16)
    center = padded[1:-1, 1:-1]
    neighbors = [
        padded[0:-2, 0:-2],
        padded[0:-2, 1:-1],
        padded[0:-2, 2:],
        padded[1:-1, 2:],
        padded[2:, 2:],
        padded[2:, 1:-1],
        padded[2:, 0:-2],
        padded[1:-1, 0:-2],
    ]
    lbp = np.zeros_like(center, dtype=np.uint8)
    for bit, nb in enumerate(neighbors):
        lbp |= ((nb >= center).astype(np.uint8) << bit)

    # Compute 16-bin LBP histograms across 4x4 spatial grid (16 * 16 = 256 dims)
    lbp_feats: List[np.ndarray] = []
    step = 32
    for gy in range(4):
        for gx in range(4):
            cell = lbp[gy * step : (gy + 1) * step, gx * step : (gx + 1) * step]
            hist, _ = np.histogram(cell, bins=16, range=(0, 256))
            hist = hist.astype(np.float32)
            hist /= np.linalg.norm(hist) + 1e-6
            lbp_feats.append(hist)

    # 2. Oriented gradients across 4x4 spatial grid (16 cells * 12 angle bins = 192 dims)
    gx_arr = cv2.Sobel(masked, cv2.CV_32F, 1, 0, ksize=3)
    gy_arr = cv2.Sobel(masked, cv2.CV_32F, 0, 1, ksize=3)
    mag, ang = cv2.cartToPolar(gx_arr, gy_arr, angleInDegrees=True)
    ang = ang % 180.0
    hog_feats: List[np.ndarray] = []
    for gy in range(4):
        for gx in range(4):
            c_mag = mag[gy * step : (gy + 1) * step, gx * step : (gx + 1) * step].ravel()
            c_ang = ang[gy * step : (gy + 1) * step, gx * step : (gx + 1) * step].ravel()
            bins = np.clip((c_ang / 15.0).astype(np.int32), 0, 11)
            hist = np.bincount(bins, weights=c_mag, minlength=12).astype(np.float32)
            hist /= np.linalg.norm(hist) + 1e-6
            hog_feats.append(hist)

    # 3. 2D Discrete Cosine Transform low-frequency geometry (8x8 = 64 dims)
    dct_in = cv2.resize(eq, (64, 64)).astype(np.float32) / 255.0
    dct_full = cv2.dct(dct_in)
    dct_low = dct_full[:8, :8].ravel().copy()
    dct_low[0] = 0.0  # drop DC offset (average brightness)
    dct_low /= np.linalg.norm(dct_low) + 1e-6

    combined = np.concatenate(lbp_feats + hog_feats + [dct_low]).astype(np.float32)
    norm = np.linalg.norm(combined) + 1e-8
    return combined / norm


class FaceBiometricEngine:
    """
    Production biometric engine supporting both offline spatial descriptors and
    OpenCV Zoo YuNet/SFace neural ONNX models with multi-layer liveness verification.
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None) -> None:
        self.config = config or {}
        face_cfg = self.config.get("face_auth", {})
        self.match_threshold = float(face_cfg.get("match_threshold", 0.76))
        self.neural_threshold = float(face_cfg.get("neural_cosine_threshold", 0.42))
        self.liveness_mode = str(face_cfg.get("liveness_mode", "balanced"))
        self.require_liveness = bool(face_cfg.get("require_liveness", True))
        self.min_face_size = int(face_cfg.get("min_face_size_px", 80))

        self.face_cascade = _find_cascade(
            [
                "haarcascade_frontalface_alt2.xml",
                "haarcascade_frontalface_default.xml",
                "haarcascade_frontalface_alt.xml",
                "lbpcascade_frontalface_improved.xml",
            ]
        )
        self.eye_cascade = _find_cascade(
            [
                "haarcascade_eye_tree_eyeglasses.xml",
                "haarcascade_eye.xml",
                "haarcascade_lefteye_2splits.xml",
            ]
        )

        self.yunet_detector = None
        self.sface_recognizer = None
        self._init_onnx_models()

    def _model_paths(self) -> Tuple[Path, Path]:
        for base in (MODELS_DIR, Path.home() / ".local" / "share" / "facelock" / "models"):
            yunet = base / "face_detection_yunet_2023mar.onnx"
            sface = base / "face_recognition_sface_2021dec.onnx"
            if yunet.is_file() and sface.is_file():
                return yunet, sface
        return (
            MODELS_DIR / "face_detection_yunet_2023mar.onnx",
            MODELS_DIR / "face_recognition_sface_2021dec.onnx",
        )

    def _init_onnx_models(self) -> bool:
        yunet_path, sface_path = self._model_paths()
        if not (yunet_path.is_file() and sface_path.is_file()):
            return False
        if not (hasattr(cv2, "FaceDetectorYN") and hasattr(cv2, "FaceRecognizerSF")):
            return False
        try:
            self.yunet_detector = cv2.FaceDetectorYN.create(
                str(yunet_path), "", (320, 320), 0.75, 0.3, 5000
            )
            self.sface_recognizer = cv2.FaceRecognizerSF.create(str(sface_path), "")
            return True
        except Exception:
            self.yunet_detector = None
            self.sface_recognizer = None
            return False

    @property
    def has_neural_models(self) -> bool:
        return self.yunet_detector is not None and self.sface_recognizer is not None

    def download_onnx_models(
        self,
        progress_cb: Optional[Callable[[str, float], None]] = None,
    ) -> Tuple[bool, str]:
        """
        Download YuNet & SFace ONNX models from OpenCV Zoo for deep neural recognition.
        """
        target_dir = MODELS_DIR
        try:
            target_dir.mkdir(parents=True, exist_ok=True)
            test_file = target_dir / ".write_test"
            test_file.touch()
            test_file.unlink()
        except PermissionError:
            target_dir = Path.home() / ".local" / "share" / "facelock" / "models"
            target_dir.mkdir(parents=True, exist_ok=True)

        files = [
            ("YuNet Face Detector", YUNET_MODEL_URL, target_dir / "face_detection_yunet_2023mar.onnx"),
            ("SFace Neural Recognizer", SFACE_MODEL_URL, target_dir / "face_recognition_sface_2021dec.onnx"),
        ]
        try:
            for idx, (label, url, dest) in enumerate(files):
                if progress_cb:
                    progress_cb(f"Downloading {label}...", idx / len(files))
                req = urllib.request.Request(url, headers={"User-Agent": "FaceLock-Kali/1.2"})
                with urllib.request.urlopen(req, timeout=30) as resp:
                    data = resp.read()
                tmp = dest.with_suffix(".tmp")
                tmp.write_bytes(data)
                os.replace(tmp, dest)
            if progress_cb:
                progress_cb("Initializing neural engine...", 1.0)
            ok = self._init_onnx_models()
            if ok:
                return True, f"Neural ONNX models installed in {target_dir}"
            return False, "Models downloaded but OpenCV FaceRecognizerSF initialization failed"
        except Exception as exc:
            return False, f"Model download failed: {exc}"

    def detect_face(self, frame_bgr: np.ndarray) -> FaceDetectionResult:
        """
        Detect the primary face, eyes/landmarks, and image quality metrics from a BGR frame.
        """
        if frame_bgr is None or frame_bgr.size == 0:
            return FaceDetectionResult(detected=False, quality_message="No camera frame")

        gray = cv2.cvtColor(frame_bgr, cv2.COLOR_BGR2GRAY)
        h_img, w_img = gray.shape[:2]

        bbox: Optional[Tuple[int, int, int, int]] = None
        landmarks: Optional[np.ndarray] = None
        eyes: List[Tuple[int, int, int, int]] = []

        # 1. Try YuNet neural detector if loaded
        if self.yunet_detector is not None:
            try:
                self.yunet_detector.setInputSize((w_img, h_img))
                _, faces = self.yunet_detector.detect(frame_bgr)
                if faces is not None and len(faces) > 0:
                    # Pick largest face
                    best = max(faces, key=lambda f: float(f[2]) * float(f[3]))
                    x, y, w, h = int(max(0, best[0])), int(max(0, best[1])), int(best[2]), int(best[3])
                    if w >= self.min_face_size and h >= self.min_face_size:
                        bbox = (x, y, min(w, w_img - x), min(h, h_img - y))
                        landmarks = best
                        # Extract eye boxes from YuNet landmarks (right eye: [4,5], left eye: [6,7])
                        rx, ry = int(best[4]), int(best[5])
                        lx, ly = int(best[6]), int(best[7])
                        ew = max(16, w // 6)
                        eyes = [
                            (rx - ew // 2, ry - ew // 3, ew, ew // 2),
                            (lx - ew // 2, ly - ew // 3, ew, ew // 2),
                        ]
            except Exception:
                pass

        # 2. Fallback or supplement with Haar/LBP cascade (OpenCV 4.x)
        if bbox is None and self.face_cascade is not None:
            eq = cv2.equalizeHist(gray)
            detected = self.face_cascade.detectMultiScale(
                eq,
                scaleFactor=1.12,
                minNeighbors=5,
                minSize=(self.min_face_size, self.min_face_size),
            )
            if len(detected) > 0:
                best_rect = max(detected, key=lambda r: int(r[2]) * int(r[3]))
                x, y, w, h = [int(v) for v in best_rect]
                bbox = (x, y, w, h)

        # 3. Fallback to geometric skin/gradient + bilateral eye-valley detector (OpenCV 5+ offline)
        if bbox is None:
            bbox, fallback_eyes = _detect_face_geometric_fallback(
                frame_bgr, gray, min_size=self.min_face_size
            )
            if fallback_eyes and not eyes:
                eyes = fallback_eyes

        if bbox is None:
            return FaceDetectionResult(
                detected=False,
                quality_message="No face detected — look directly at the camera",
            )

        x, y, w, h = bbox
        face_gray = gray[y : y + h, x : x + w]
        face_color = frame_bgr[y : y + h, x : x + w]
        if face_gray.size == 0:
            return FaceDetectionResult(detected=False, quality_message="Face out of bounds")

        # Detect eyes in upper 65% of face if not already populated
        if self.eye_cascade is not None:
            upper_h = int(h * 0.65)
            upper_face = face_gray[:upper_h, :]
            raw_eyes = self.eye_cascade.detectMultiScale(
                upper_face,
                scaleFactor=1.1,
                minNeighbors=4,
                minSize=(max(16, w // 10), max(12, h // 12)),
            )
            if len(raw_eyes) > 0:
                eyes = [(x + int(ex), y + int(ey), int(ew), int(eh)) for (ex, ey, ew, eh) in raw_eyes[:2]]

        brightness = float(np.mean(face_gray))
        sharpness = float(cv2.Laplacian(face_gray, cv2.CV_64F).var())

        # Geometric eye alignment if 2 eyes are separated horizontally
        aligned_gray = face_gray.copy()
        aligned_color = face_color.copy()
        if len(eyes) >= 2:
            e1, e2 = sorted(eyes[:2], key=lambda e: e[0])
            p1 = (e1[0] + e1[2] / 2.0, e1[1] + e1[3] / 2.0)
            p2 = (e2[0] + e2[2] / 2.0, e2[1] + e2[3] / 2.0)
            dx = p2[0] - p1[0]
            dy = p2[1] - p1[1]
            if dx > w * 0.18:
                angle = math.degrees(math.atan2(dy, dx))
                if abs(angle) < 28.0:
                    center_pt = (w / 2.0, h / 2.0)
                    rot_mat = cv2.getRotationMatrix2D(center_pt, angle, 1.0)
                    aligned_gray = cv2.warpAffine(
                        face_gray, rot_mat, (w, h), flags=cv2.INTER_LINEAR, borderMode=cv2.BORDER_REPLICATE
                    )
                    aligned_color = cv2.warpAffine(
                        face_color, rot_mat, (w, h), flags=cv2.INTER_LINEAR, borderMode=cv2.BORDER_REPLICATE
                    )

        # Quality assessment
        if brightness < 32.0:
            q_ok = False
            q_msg = "Lighting too dark — increase screen or room brightness"
        elif brightness > 238.0:
            q_ok = False
            q_msg = "Face overexposed — reduce direct backlight"
        elif sharpness < 14.0:
            q_ok = False
            q_msg = "Image blurry — hold steady"
        else:
            q_ok = True
            q_msg = "Face locked in frame"

        return FaceDetectionResult(
            detected=True,
            bbox=bbox,
            eyes=eyes,
            landmarks=landmarks,
            brightness=brightness,
            sharpness=sharpness,
            quality_ok=q_ok,
            quality_message=q_msg,
            aligned_gray=aligned_gray,
            aligned_color=aligned_color,
        )

    def extract_embedding(self, frame_bgr: np.ndarray, det: FaceDetectionResult) -> Dict[str, List[float]]:
        """
        Compute both the 512-D spatial descriptor and (if available) 128-D SFace neural vector.
        """
        if not det.detected or det.aligned_gray is None:
            raise ValueError("Cannot extract embedding without a detected face")

        spatial_vec = _compute_spatial_lbp_hog_dct_embedding(det.aligned_gray)
        result: Dict[str, List[float]] = {
            "spatial": [round(float(v), 6) for v in spatial_vec.tolist()],
        }

        if self.sface_recognizer is not None and det.landmarks is not None:
            try:
                aligned_sface = self.sface_recognizer.alignCrop(frame_bgr, det.landmarks)
                feat = self.sface_recognizer.feature(aligned_sface).ravel()
                feat = feat / (np.linalg.norm(feat) + 1e-8)
                result["neural"] = [round(float(v), 6) for v in feat.tolist()]
            except Exception:
                pass

        return result

    def compare_embeddings(
        self,
        live_emb: Dict[str, List[float]],
        enrolled_samples: List[Dict[str, List[float]]],
    ) -> Tuple[bool, float]:
        """
        Compare a live embedding against enrolled multi-angle samples.
        Returns (matched, best_confidence_score).
        """
        if not enrolled_samples:
            return False, 0.0

        best_score = 0.0
        matched = False

        live_spatial = np.array(live_emb.get("spatial", []), dtype=np.float32)
        live_neural = np.array(live_emb.get("neural", []), dtype=np.float32)

        for sample in enrolled_samples:
            # 1. Check neural 128-D cosine similarity if both have neural embeddings
            s_neural = np.array(sample.get("neural", []), dtype=np.float32)
            if live_neural.size == 128 and s_neural.size == 128:
                cos_sim = float(np.dot(live_neural, s_neural))
                # Map SFace cosine similarity (threshold ~0.36-0.45) into [0, 1] confidence
                norm_conf = min(1.0, max(0.0, (cos_sim + 0.2) / 0.85))
                if cos_sim >= self.neural_threshold:
                    matched = True
                best_score = max(best_score, norm_conf)
                continue

            # 2. Spatial 512-D descriptor ensemble (Cosine + RBF Euclidean)
            s_spatial = np.array(sample.get("spatial", []), dtype=np.float32)
            if live_spatial.size > 0 and live_spatial.size == s_spatial.size:
                cos_sim = float(np.dot(live_spatial, s_spatial))
                l2_dist = float(np.linalg.norm(live_spatial - s_spatial))
                rbf_sim = math.exp(-0.75 * (l2_dist ** 2))
                score = 0.65 * max(0.0, cos_sim) + 0.35 * rbf_sim
                if score >= self.match_threshold:
                    matched = True
                best_score = max(best_score, score)

        return matched, round(float(best_score), 4)

    def is_user_enrolled(self, username: str, encodings_dir: Optional[Path] = None) -> bool:
        meta = get_face_profile_metadata(username, encodings_dir=encodings_dir)
        return meta is not None and int(meta.get("sample_count", 0)) > 0

    def save_user_enrollment(
        self,
        username: str,
        samples: List[Dict[str, List[float]]],
        encodings_dir: Optional[Path] = None,
        master_key: Optional[bytes] = None,
    ) -> Path:
        now = datetime.datetime.now(datetime.timezone.utc).astimezone().strftime("%Y-%m-%d %H:%M:%S %z")
        engine_type = "neural+spatial" if any("neural" in s for s in samples) else "spatial-lbp-hog-dct"
        payload = {
            "username": username,
            "enrolled_at": now,
            "engine": engine_type,
            "samples": samples,
        }
        return save_encrypted_face_profile(
            username,
            payload,
            encodings_dir=encodings_dir,
            master_key=master_key,
        )

    def verify_frame_for_user(
        self,
        username: str,
        frame_bgr: np.ndarray,
        liveness_state: Optional[LivenessState] = None,
        profile_cache: Optional[Dict[str, Any]] = None,
        encodings_dir: Optional[Path] = None,
        master_key: Optional[bytes] = None,
    ) -> Tuple[bool, float, float, str, FaceDetectionResult]:
        """
        Evaluate a single camera frame for user authentication.
        Returns (authenticated, match_confidence, liveness_score, status_text, detection).
        """
        det = self.detect_face(frame_bgr)
        if not det.detected:
            return False, 0.0, 0.0, det.quality_message, det

        profile = profile_cache or load_encrypted_face_profile(
            username, encodings_dir=encodings_dir, master_key=master_key
        )
        if not profile or not profile.get("samples"):
            return False, 0.0, 0.0, f"No face profile enrolled for '{username}'", det

        live_ok = True
        live_score = 1.0
        live_msg = "Liveness OK"
        if self.require_liveness and liveness_state is not None:
            gray = cv2.cvtColor(frame_bgr, cv2.COLOR_BGR2GRAY)
            live_ok, live_score, live_msg = liveness_state.update(gray, det)
            if self.liveness_mode == "strict" and live_score < 0.65:
                live_ok = False
            elif self.liveness_mode == "fast" and liveness_state.frames_With_face >= 2 and live_score >= 0.42:
                live_ok = True

        if not det.quality_ok:
            return False, 0.0, live_score, det.quality_message, det

        emb = self.extract_embedding(frame_bgr, det)
        matched, confidence = self.compare_embeddings(emb, profile["samples"])

        if matched and live_ok:
            return True, confidence, live_score, f"Verified {username} ({int(confidence * 100)}%)", det
        if matched and not live_ok:
            return False, confidence, live_score, f"Face matched — {live_msg}", det

        return (
            False,
            confidence,
            live_score,
            f"Scanning face... ({int(confidence * 100)}% match)",
            det,
        )

    def save_intruder_snapshot(self, frame_bgr: np.ndarray, username: str, reason: str) -> Optional[Path]:
        """Save an audit snapshot when spoofing or repeated failures occur (if enabled)."""
        try:
            INTRUDER_DIR.mkdir(parents=True, exist_ok=True)
            ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            out = INTRUDER_DIR / f"intruder_{username}_{ts}.jpg"
            annotated = frame_bgr.copy()
            cv2.putText(
                annotated,
                f"FACELOCK ALERT: {username} - {reason} ({ts})",
                (16, 28),
                cv2.FONT_HERSHEY_SIMPLEX,
                0.55,
                (0, 0, 255),
                2,
            )
            cv2.imwrite(str(out), annotated)
            os.chmod(out, 0o600)
            return out
        except Exception:
            return None
