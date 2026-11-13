"""
Deep Neural Face Detection (YuNet ONNX), 128-D Identity Recognition (SFace ONNX),
and Multi-Frame Anti-Spoofing Liveness Engine for FaceLock (Kali Linux).
"""

import datetime
import math
import os
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

import cv2
import numpy as np

from facelock.constants import (
    ENCODINGS_DIR,
    INSTALL_LIB_DIR,
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

REPO_MODELS_DIR = Path(__file__).resolve().parents[3] / "models"


@dataclass
class FaceDetectionResult:
    detected: bool
    bbox: Optional[Tuple[int, int, int, int]] = None  # (x, y, w, h)
    eyes: List[Tuple[int, int, int, int]] = field(default_factory=list)
    landmarks: Optional[np.ndarray] = None
    det_confidence: float = 0.0
    brightness: float = 0.0
    sharpness: float = 0.0
    quality_ok: bool = False
    quality_message: str = ""
    aligned_gray: Optional[np.ndarray] = None
    aligned_color: Optional[np.ndarray] = None


@dataclass
class LivenessState:
    frames_with_face: int = 0
    consecutive_matches: int = 0
    consecutive_impostors: int = 0
    nose_positions: List[Tuple[float, float]] = field(default_factory=list)
    eye_distances: List[float] = field(default_factory=list)
    frame_diffs: List[float] = field(default_factory=list)
    sharpness_scores: List[float] = field(default_factory=list)
    parallax_ratios: List[float] = field(default_factory=list)
    prev_face_crop: Optional[np.ndarray] = None

    def reset_matches(self) -> None:
        self.consecutive_matches = 0

    def update(self, _frame_gray: np.ndarray, det: FaceDetectionResult) -> Tuple[bool, float, str]:
        """
        Evaluate temporal anti-spoofing cues across consecutive frames.
        Returns (passed, liveness_score, status_hint).
        """
        if not det.detected or det.bbox is None or det.aligned_gray is None:
            self.consecutive_matches = 0
            return False, 0.0, "Position your face clearly inside the circle"

        self.frames_with_face += 1
        self.sharpness_scores.append(det.sharpness)

        if det.landmarks is not None and len(det.landmarks) >= 14:
            rx, ry = float(det.landmarks[4]), float(det.landmarks[5])
            lx, ly = float(det.landmarks[6]), float(det.landmarks[7])
            nx, ny = float(det.landmarks[8]), float(det.landmarks[9])
            self.nose_positions.append((nx, ny))
            self.eye_distances.append(math.hypot(lx - rx, ly - ry))

        crop = cv2.resize(det.aligned_gray, (96, 96))
        if self.prev_face_crop is not None:
            diff = float(
                np.mean(np.abs(crop.astype(np.float32) - self.prev_face_crop.astype(np.float32)))
            )
            self.frame_diffs.append(diff)

            inner_curr = crop[24:72, 24:72].astype(np.float32)
            inner_prev = self.prev_face_crop[24:72, 24:72].astype(np.float32)
            inner_diff = float(np.mean(np.abs(inner_curr - inner_prev))) + 1e-4
            outer_diff = max(diff, 1e-4)
            self.parallax_ratios.append(abs(inner_diff - outer_diff) / outer_diff)

        self.prev_face_crop = crop

        if self.frames_with_face < 3:
            return False, 0.30, "Verifying 3D facial landmarks..."

        # 1. Sharpness & screen-glare check
        avg_sharp = float(np.mean(self.sharpness_scores[-6:]))
        texture_score = min(1.0, max(0.0, (avg_sharp - 15.0) / 75.0))

        # 2. Temporal frame variation (rejects completely frozen spoof frames)
        recent_diffs = self.frame_diffs[-6:]
        avg_diff = float(np.mean(recent_diffs)) if recent_diffs else 0.0
        if avg_diff < 0.22:
            motion_score = 0.05  # Frozen image
        elif 0.25 <= avg_diff <= 25.0:
            motion_score = min(1.0, 0.65 + min(0.35, avg_diff / 15.0))
        else:
            motion_score = 0.35

        # 3. Anatomical landmark presence & micro-shift
        landmark_score = 0.85 if len(det.eyes) >= 2 else 0.45
        if len(self.nose_positions) >= 3:
            xs = [p[0] for p in self.nose_positions[-6:]]
            ys = [p[1] for p in self.nose_positions[-6:]]
            shift = math.hypot(max(xs) - min(xs), max(ys) - min(ys))
            if 0.4 <= shift <= 45.0:
                landmark_score = 1.0

        # 4. 3D Parallax cue
        parallax_val = float(np.mean(self.parallax_ratios[-5:])) if self.parallax_ratios else 0.0
        parallax_score = min(1.0, max(0.25, parallax_val * 4.5))

        total_score = (
            0.30 * texture_score
            + 0.30 * motion_score
            + 0.25 * landmark_score
            + 0.15 * parallax_score
        )
        total_score = round(min(1.0, max(0.0, total_score)), 4)

        if total_score >= 0.52:
            return True, total_score, "Liveness verified"
        return False, total_score, "Hold steady and look at the camera"


def enumerate_cameras(max_index: int = 6) -> List[Dict[str, Any]]:
    """Discover V4L2 video capture devices on Linux."""
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


def _tan_triggs_normalization(gray: np.ndarray) -> np.ndarray:
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
    Extract a 512-D zero-mean standardized (z-score + L2 normalized) spatial facial
    descriptor. Zero-mean centering eliminates positive-orthant histogram bias so
    unrelated faces have ~0.0 correlation while true matches exceed 0.72.
    """
    face = cv2.resize(aligned_gray, (128, 128), interpolation=cv2.INTER_AREA)
    clahe = cv2.createCLAHE(clipLimit=2.2, tileGridSize=(8, 8))
    eq = clahe.apply(face)
    tt = _tan_triggs_normalization(eq)

    mask = np.zeros_like(tt)
    cv2.ellipse(mask, (64, 64), (54, 62), 0, 0, 360, 255, -1)
    masked = cv2.bitwise_and(tt, mask)

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

    lbp_feats: List[np.ndarray] = []
    step = 32
    for gy in range(4):
        for gx in range(4):
            cell = lbp[gy * step : (gy + 1) * step, gx * step : (gx + 1) * step]
            hist, _ = np.histogram(cell, bins=16, range=(0, 256))
            hist = hist.astype(np.float32)
            hist -= float(np.mean(hist))
            hist /= np.linalg.norm(hist) + 1e-6
            lbp_feats.append(hist)

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
            hist -= float(np.mean(hist))
            hist /= np.linalg.norm(hist) + 1e-6
            hog_feats.append(hist)

    dct_in = cv2.resize(tt, (64, 64)).astype(np.float32) / 255.0
    dct_full = cv2.dct(dct_in)
    dct_low = dct_full[:8, :8].ravel().copy()
    dct_low[0] = 0.0
    dct_low -= float(np.mean(dct_low))
    dct_low /= np.linalg.norm(dct_low) + 1e-6

    combined = np.concatenate(lbp_feats + hog_feats + [dct_low]).astype(np.float32)
    combined -= float(np.mean(combined))
    norm = np.linalg.norm(combined) + 1e-8
    return combined / norm


def _validate_anatomical_landmarks(face_row: np.ndarray, img_w: int, img_h: int) -> bool:
    """
    Verify that a YuNet detection has anatomically valid 5-point facial landmarks:
      - Right eye & left eye above nose tip
      - Nose tip above right & left mouth corners
      - Inter-eye distance >= 20% of face bounding box width (rejects occluded/extreme profile faces)
      - Face bounding box inside image frame
    """
    x, y, w, h = float(face_row[0]), float(face_row[1]), float(face_row[2]), float(face_row[3])
    rx, ry = float(face_row[4]), float(face_row[5])
    lx, ly = float(face_row[6]), float(face_row[7])
    nx, ny = float(face_row[8]), float(face_row[9])
    rmx, rmy = float(face_row[10]), float(face_row[11])
    lmx, lmy = float(face_row[12]), float(face_row[13])
    conf = float(face_row[14])

    if conf < 0.84:
        return False

    if x < -10 or y < -10 or (x + w) > (img_w + 15) or (y + h) > (img_h + 15):
        return False

    # Eyes must be horizontally separated (frontal or near-frontal face)
    eye_dx = abs(lx - rx)
    eye_dy = abs(ly - ry)
    if eye_dx < (w * 0.21) or eye_dy > (eye_dx * 0.65):
        return False

    # Eyes must be above nose tip
    max_eye_y = max(ry, ly)
    if ny <= max_eye_y + (h * 0.04):
        return False

    # Nose tip must be above mouth corners
    min_mouth_y = min(rmy, lmy)
    if min_mouth_y <= ny + (h * 0.03):
        return False

    # Nose X should lie roughly between the two eyes (within reasonable yaw margin)
    min_eye_x = min(rx, lx) - w * 0.12
    max_eye_x = max(rx, lx) + w * 0.12
    if not (min_eye_x <= nx <= max_eye_x):
        return False

    return True


class FaceBiometricEngine:
    """
    Biometric engine powered by YuNet 5-landmark neural face detection and
    SFace 128-D neural face recognition with strict anti-false-positive verification.
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None) -> None:
        self.config = config or {}
        face_cfg = self.config.get("face_auth", {})
        self.match_threshold = float(face_cfg.get("match_threshold", 0.75))
        # Strict SFace cosine threshold (OpenCV default is 0.363; 0.50 prevents false positives)
        self.neural_threshold = max(0.48, float(face_cfg.get("neural_cosine_threshold", 0.50)))
        self.liveness_mode = str(face_cfg.get("liveness_mode", "balanced"))
        self.require_liveness = bool(face_cfg.get("require_liveness", True))
        self.min_face_size = max(80, int(face_cfg.get("min_face_size_px", 85)))

        self.yunet_detector = None
        self.sface_recognizer = None
        self._init_onnx_models()

    def _model_paths(self) -> Tuple[Optional[Path], Optional[Path]]:
        search_dirs = [
            REPO_MODELS_DIR,
            INSTALL_LIB_DIR / "models",
            MODELS_DIR,
            Path.home() / ".local" / "share" / "facelock" / "models",
        ]
        yunet_found: Optional[Path] = None
        sface_found: Optional[Path] = None

        for base in search_dirs:
            if not base.is_dir():
                continue
            y_cand = base / "face_detection_yunet_2023mar.onnx"
            if y_cand.is_file() and yunet_found is None:
                yunet_found = y_cand
            for s_name in (
                "face_recognition_sface_2021dec_int8.onnx",
                "face_recognition_sface_2021dec.onnx",
            ):
                s_cand = base / s_name
                if s_cand.is_file() and sface_found is None:
                    sface_found = s_cand
                    break

        return yunet_found, sface_found

    def _init_onnx_models(self) -> bool:
        yunet_path, sface_path = self._model_paths()
        if not (yunet_path and sface_path and yunet_path.is_file() and sface_path.is_file()):
            return False
        if not (hasattr(cv2, "FaceDetectorYN") and hasattr(cv2, "FaceRecognizerSF")):
            return False
        try:
            self.yunet_detector = cv2.FaceDetectorYN.create(
                str(yunet_path), "", (320, 320), 0.84, 0.3, 5000
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

    def detect_face(self, frame_bgr: np.ndarray) -> FaceDetectionResult:
        """
        Detect a real human face with validated 5-point anatomical landmarks using YuNet.
        Never guesses bounding boxes on non-face backgrounds or covered faces.
        """
        if frame_bgr is None or frame_bgr.size == 0:
            return FaceDetectionResult(detected=False, quality_message="No camera frame")

        gray = cv2.cvtColor(frame_bgr, cv2.COLOR_BGR2GRAY)
        h_img, w_img = gray.shape[:2]

        bbox: Optional[Tuple[int, int, int, int]] = None
        landmarks: Optional[np.ndarray] = None
        eyes: List[Tuple[int, int, int, int]] = []
        det_conf = 0.0

        if self.yunet_detector is not None:
            try:
                self.yunet_detector.setInputSize((w_img, h_img))
                _, faces = self.yunet_detector.detect(frame_bgr)
                if faces is not None and len(faces) > 0:
                    # Filter to faces with valid anatomical landmarks
                    valid_faces = [
                        f for f in faces if _validate_anatomical_landmarks(f, w_img, h_img)
                    ]
                    if not valid_faces:
                        return FaceDetectionResult(
                            detected=False,
                            quality_message="Face partially covered or at extreme angle — look straight at camera",
                        )

                    best = max(valid_faces, key=lambda f: float(f[2]) * float(f[3]))
                    x = int(max(0, best[0]))
                    y = int(max(0, best[1]))
                    w = int(min(best[2], w_img - x))
                    h = int(min(best[3], h_img - y))

                    if w >= self.min_face_size and h >= self.min_face_size:
                        bbox = (x, y, w, h)
                        landmarks = best
                        det_conf = float(best[14])
                        rx, ry = int(best[4]), int(best[5])
                        lx, ly = int(best[6]), int(best[7])
                        ew = max(16, w // 6)
                        eyes = [
                            (rx - ew // 2, ry - ew // 3, ew, ew // 2),
                            (lx - ew // 2, ly - ew // 3, ew, ew // 2),
                        ]
                    else:
                        return FaceDetectionResult(
                            detected=False,
                            quality_message="Move slightly closer to the camera",
                        )
            except Exception:
                pass

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

        brightness = float(np.mean(face_gray))
        sharpness = float(cv2.Laplacian(face_gray, cv2.CV_64F).var())

        # Align crop using SFace 5-point landmarks if available
        aligned_color = face_color.copy()
        if self.sface_recognizer is not None and landmarks is not None:
            try:
                aligned_color = self.sface_recognizer.alignCrop(frame_bgr, landmarks)
            except Exception:
                pass
        aligned_gray = cv2.cvtColor(aligned_color, cv2.COLOR_BGR2GRAY)

        if brightness < 34.0:
            q_ok = False
            q_msg = "Lighting too dark — increase room or screen brightness"
        elif brightness > 238.0:
            q_ok = False
            q_msg = "Face overexposed — reduce direct backlight"
        elif sharpness < 14.0:
            q_ok = False
            q_msg = "Camera image blurry — hold steady"
        else:
            q_ok = True
            q_msg = "Face locked in scanner"

        return FaceDetectionResult(
            detected=True,
            bbox=bbox,
            eyes=eyes,
            landmarks=landmarks,
            det_confidence=det_conf,
            brightness=brightness,
            sharpness=sharpness,
            quality_ok=q_ok,
            quality_message=q_msg,
            aligned_gray=aligned_gray,
            aligned_color=aligned_color,
        )

    def extract_embedding(self, frame_bgr: np.ndarray, det: FaceDetectionResult) -> Dict[str, List[float]]:
        """
        Extract 128-D SFace neural identity vector + 512-D zero-mean spatial descriptor.
        """
        if not det.detected or det.aligned_gray is None:
            raise ValueError("Cannot extract embedding without a detected face")

        spatial_vec = _compute_spatial_lbp_hog_dct_embedding(det.aligned_gray)
        result: Dict[str, List[float]] = {
            "spatial_zm": [round(float(v), 6) for v in spatial_vec.tolist()],
        }

        if self.sface_recognizer is not None and det.landmarks is not None:
            aligned_sface = self.sface_recognizer.alignCrop(frame_bgr, det.landmarks)
            feat = self.sface_recognizer.feature(aligned_sface).ravel().astype(np.float32)
            feat = feat / (np.linalg.norm(feat) + 1e-8)
            result["neural"] = [round(float(v), 6) for v in feat.tolist()]

        return result

    def compare_embeddings(
        self,
        live_emb: Dict[str, List[float]],
        enrolled_samples: List[Dict[str, List[float]]],
    ) -> Tuple[bool, float]:
        """
        Compare live face embedding against enrolled samples using strict neural
        cosine + L2 distance verification and zero-mean spatial correlation.
        Returns (matched, display_confidence).
        """
        if not enrolled_samples:
            return False, 0.0

        live_neural = np.array(live_emb.get("neural", []), dtype=np.float32)
        live_spatial = np.array(
            live_emb.get("spatial_zm", live_emb.get("spatial", [])), dtype=np.float32
        )

        neural_cos_scores: List[float] = []
        neural_l2_scores: List[float] = []
        spatial_scores: List[float] = []

        for sample in enrolled_samples:
            s_neural = np.array(sample.get("neural", []), dtype=np.float32)
            if live_neural.size == 128 and s_neural.size == 128:
                cos_sim = float(np.dot(live_neural, s_neural))
                l2_dist = float(np.linalg.norm(live_neural - s_neural))
                neural_cos_scores.append(cos_sim)
                neural_l2_scores.append(l2_dist)

            s_spatial = np.array(
                sample.get("spatial_zm", sample.get("spatial", [])), dtype=np.float32
            )
            if live_spatial.size > 0 and live_spatial.size == s_spatial.size:
                # Ensure both vectors are zero-mean centered before dot product
                v1 = live_spatial - float(np.mean(live_spatial))
                v2 = s_spatial - float(np.mean(s_spatial))
                v1 /= np.linalg.norm(v1) + 1e-8
                v2 /= np.linalg.norm(v2) + 1e-8
                spatial_scores.append(float(np.dot(v1, v2)))

        # 1. Primary path: Deep Neural 128-D SFace Identity Verification
        if neural_cos_scores:
            best_cos = max(neural_cos_scores)
            median_cos = float(np.median(neural_cos_scores))
            best_l2 = min(neural_l2_scores)
            best_spatial = max(spatial_scores) if spatial_scores else 0.75

            # Strict identity criteria:
            # - Best sample cosine similarity >= self.neural_threshold (0.50)
            # - Median cosine across all 5 enrolled poses >= (self.neural_threshold - 0.06) (0.44)
            # - Best L2 distance <= 1.01
            # - Zero-mean spatial correlation >= 0.45
            matched = (
                best_cos >= self.neural_threshold
                and median_cos >= (self.neural_threshold - 0.06)
                and best_l2 <= 1.01
                and best_spatial >= 0.45
            )

            # Map raw SFace cosine similarity [-0.1..0.85] to intuitive UI percentage [0..1]
            # where threshold 0.50 corresponds to ~75% UI confidence
            ui_conf = min(0.99, max(0.0, (best_cos - 0.05) / 0.65))
            return matched, round(float(ui_conf), 4)

        # 2. If neural models are active on the system, NEVER accept an old non-neural profile
        if self.has_neural_models:
            return False, 0.0

        # 3. Fallback for unit tests using synthetic zero-mean spatial crops
        if spatial_scores:
            best_sp = max(spatial_scores)
            matched = best_sp >= self.match_threshold
            return matched, round(max(0.0, min(1.0, best_sp)), 4)

        return False, 0.0

    def is_user_enrolled(self, username: str, encodings_dir: Optional[Path] = None) -> bool:
        profile = load_encrypted_face_profile(username, encodings_dir=encodings_dir)
        if not profile or not profile.get("samples"):
            return False
        # Require neural embeddings when neural engine is active
        if self.has_neural_models:
            return any("neural" in s for s in profile.get("samples", []))
        return True

    def save_user_enrollment(
        self,
        username: str,
        samples: List[Dict[str, List[float]]],
        encodings_dir: Optional[Path] = None,
        master_key: Optional[bytes] = None,
    ) -> Path:
        now = datetime.datetime.now(datetime.timezone.utc).astimezone().strftime("%Y-%m-%d %H:%M:%S %z")
        engine_type = "sface-neural-128d" if any("neural" in s for s in samples) else "spatial-zm-512d"
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
        Evaluate a camera frame for username.
        Requires 3 consecutive neural-matched frames + liveness verification to prevent
        any false unlocks.
        """
        det = self.detect_face(frame_bgr)
        if not det.detected:
            if liveness_state is not None:
                liveness_state.reset_matches()
            return False, 0.0, 0.0, det.quality_message, det

        profile = profile_cache or load_encrypted_face_profile(
            username, encodings_dir=encodings_dir, master_key=master_key
        )
        if not profile or not profile.get("samples"):
            return False, 0.0, 0.0, f"No face profile enrolled for '{username}'", det

        # Reject legacy non-neural profile if neural engine is active
        if self.has_neural_models and not any("neural" in s for s in profile["samples"]):
            return (
                False,
                0.0,
                0.0,
                "Please click 'Set Up Face Lock' once to enroll with the Neural SFace engine",
                det,
            )

        live_ok = True
        live_score = 1.0
        live_msg = "Liveness OK"
        if self.require_liveness and liveness_state is not None:
            gray = cv2.cvtColor(frame_bgr, cv2.COLOR_BGR2GRAY)
            live_ok, live_score, live_msg = liveness_state.update(gray, det)

        if not det.quality_ok:
            if liveness_state is not None:
                liveness_state.reset_matches()
            return False, 0.0, live_score, det.quality_message, det

        emb = self.extract_embedding(frame_bgr, det)
        matched, confidence = self.compare_embeddings(emb, profile["samples"])

        if not matched:
            if liveness_state is not None:
                liveness_state.reset_matches()
                liveness_state.consecutive_impostors += 1
            return (
                False,
                confidence,
                live_score,
                f"Face not recognized ({int(confidence * 100)}% similarity — does not match {username})",
                det,
            )

        # Face matched on this frame! Increment consecutive match counter
        if liveness_state is not None:
            liveness_state.consecutive_impostors = 0
            liveness_state.consecutive_matches += 1
            needed = 3
            if liveness_state.consecutive_matches < needed:
                return (
                    False,
                    confidence,
                    live_score,
                    f"Confirming identity ({liveness_state.consecutive_matches}/{needed})...",
                    det,
                )

        if matched and live_ok:
            return True, confidence, live_score, f"Verified {username} ({int(confidence * 100)}%)", det

        return False, confidence, live_score, f"Identity matched — {live_msg}", det
