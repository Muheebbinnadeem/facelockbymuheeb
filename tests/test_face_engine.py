import unittest
import cv2
import numpy as np

from facelock.core.face_engine import (
    FaceBiometricEngine,
    FaceDetectionResult,
    LivenessState,
    _compute_spatial_lbp_hog_dct_embedding,
)


class TestFaceBiometricEngine(unittest.TestCase):
    def _synthetic_face_crop(self, seed: int = 42, shift: int = 0) -> np.ndarray:
        rng = np.random.default_rng(seed)
        img = np.full((128, 128), 140, dtype=np.uint8)
        # Draw structured facial features (oval, eyes, nose bridge, mouth)
        cv2.ellipse(img, (64 + shift, 64), (46, 56), 0, 0, 360, 185, -1)
        cv2.circle(img, (44 + shift, 48), 9, 35, -1)
        cv2.circle(img, (84 + shift, 48), 9, 35, -1)
        cv2.line(img, (64 + shift, 48), (64 + shift, 78), 95, 4)
        cv2.ellipse(img, (64 + shift, 96), (18, 7), 0, 0, 180, 50, 3)
        noise = rng.integers(-6, 7, size=img.shape, dtype=np.int16)
        out = np.clip(img.astype(np.int16) + noise, 0, 255).astype(np.uint8)
        return out

    def test_spatial_embedding_self_vs_impostor(self) -> None:
        engine = FaceBiometricEngine()
        crop_a1 = self._synthetic_face_crop(seed=10, shift=0)
        crop_a2 = self._synthetic_face_crop(seed=11, shift=1)

        # Different structured face geometry for impostor
        impostor = np.full((128, 128), 110, dtype=np.uint8)
        cv2.rectangle(impostor, (20, 20), (108, 108), 210, -1)
        cv2.circle(impostor, (36, 62), 14, 15, -1)
        cv2.circle(impostor, (92, 62), 14, 15, -1)

        vec_a1 = _compute_spatial_lbp_hog_dct_embedding(crop_a1)
        vec_a2 = _compute_spatial_lbp_hog_dct_embedding(crop_a2)
        vec_imp = _compute_spatial_lbp_hog_dct_embedding(impostor)

        self.assertEqual(vec_a1.shape, (512,))
        matched_same, score_same = engine.compare_embeddings(
            {"spatial": vec_a2.tolist()},
            [{"spatial": vec_a1.tolist()}],
        )
        matched_imp, score_imp = engine.compare_embeddings(
            {"spatial": vec_imp.tolist()},
            [{"spatial": vec_a1.tolist()}],
        )
        self.assertTrue(matched_same)
        self.assertGreater(score_same, 0.85)
        self.assertGreater(score_same, score_imp)
        self.assertFalse(matched_imp)

    def test_liveness_tracker_progression(self) -> None:
        liveness = LivenessState()
        for step in range(5):
            crop = self._synthetic_face_crop(seed=20 + step, shift=step % 2)
            det = FaceDetectionResult(
                detected=True,
                bbox=(100 + step, 80, 128, 128),
                eyes=[(120, 110, 20, 12), (170, 110, 20, 12)] if step != 2 else [(120, 110, 20, 12)],
                brightness=145.0,
                sharpness=95.0,
                quality_ok=True,
                aligned_gray=crop,
            )
            passed, score, _ = liveness.update(crop, det)
        self.assertTrue(passed)
        self.assertGreaterEqual(score, 0.54)


if __name__ == "__main__":
    unittest.main()
