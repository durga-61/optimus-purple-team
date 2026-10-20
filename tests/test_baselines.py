"""Tests for the independent One-Class SVM and PCA anomaly baselines."""

import numpy as np
import pytest

from app.evaluation.baselines import (
    OneClassSVMDetector,
    PCADetector,
    evaluate_detector,
    fit_baseline_detectors,
    observation_matrix,
)
from app.evaluation.dataset import generate_attack_dataset, generate_normal_dataset


def _samples():
    normal = generate_normal_dataset(num_samples=60, seed=7)
    attacks = generate_attack_dataset(num_samples_per_class=5, seed=7, episode_length=5)
    return normal, attacks


class TestObservationMatrix:
    def test_extracts_shared_seven_features(self):
        normal, _ = _samples()
        matrix = observation_matrix(normal[:10])
        assert matrix.shape == (10, 7)
        assert np.isfinite(matrix).all()
        assert matrix[0, 2] == normal[0].observation.inventory

    def test_empty_input_returns_empty_matrix(self):
        matrix = observation_matrix([])
        assert matrix.shape == (0, 7)


class TestBaselineDetectors:
    def test_fit_requires_minimum_normal_samples(self):
        normal, _ = _samples()
        with pytest.raises(ValueError):
            OneClassSVMDetector().fit(normal[:5])
        with pytest.raises(ValueError):
            PCADetector().fit(normal[:5])

    def test_fit_rejects_labeled_attack_records(self):
        normal, attacks = _samples()
        with pytest.raises(ValueError):
            OneClassSVMDetector().fit(normal[:20] + attacks[:1])
        with pytest.raises(ValueError):
            PCADetector().fit(normal[:20] + attacks[:1])

    @pytest.mark.parametrize("detector_class", [OneClassSVMDetector, PCADetector])
    def test_detector_fit_calibrate_and_predict(self, detector_class):
        normal, attacks = _samples()
        detector = detector_class()
        with pytest.raises(RuntimeError):
            detector.score(normal[:1])
        with pytest.raises(RuntimeError):
            detector.predict(normal[:1])

        detector.fit(normal[:40])
        threshold = detector.calibrate(normal[40:50] + attacks[:10], max_fpr=0.001)

        assert detector.is_fitted is True
        assert detector.threshold == threshold
        assert np.isfinite(threshold)
        scores = detector.score(normal[50:] + attacks[10:])
        predictions = detector.predict(normal[50:] + attacks[10:])
        assert scores.shape[0] == len(normal[50:]) + len(attacks[10:])
        assert predictions.shape == scores.shape
        assert set(np.unique(predictions)).issubset({0, 1})

    def test_fit_baseline_detectors_calibrates_both(self):
        normal, attacks = _samples()
        detectors = fit_baseline_detectors(
            train_records=normal[:40],
            validation_records=normal[40:50] + attacks[:10],
            max_fpr=0.001,
        )
        assert set(detectors) == {"one_class_svm", "pca"}
        for detector in detectors.values():
            assert detector.is_fitted is True
            assert detector.threshold is not None


class TestBaselineEvaluation:
    def test_evaluate_detector_reports_metrics_and_per_class_recall(self):
        normal, attacks = _samples()
        detector = OneClassSVMDetector()
        detector.fit(normal[:40])
        detector.calibrate(normal[40:50] + attacks[:10], max_fpr=0.001)

        records = normal[50:] + attacks[10:]
        metrics = evaluate_detector(detector, records)

        assert metrics["detector"] == "one_class_svm"
        assert metrics["total_samples"] == len(records)
        assert 0.0 <= metrics["recall"] <= 1.0
        assert 0.0 <= metrics["false_positive_rate"] <= 1.0
        assert metrics["tp"] + metrics["fp"] + metrics["tn"] + metrics["fn"] == len(records)
        assert metrics["per_class_recall"]
        assert set(metrics["per_class_recall"]) == set(metrics["per_class_evasion"])
        assert np.isfinite(metrics["mean_normal_score"])
        assert np.isfinite(metrics["mean_attack_score"])

    def test_evaluate_detector_accepts_explicit_threshold(self):
        normal, attacks = _samples()
        detector = PCADetector()
        detector.fit(normal[:40])
        detector.calibrate(normal[40:50] + attacks[:10], max_fpr=0.001)

        impossible = evaluate_detector(detector, normal[50:] + attacks[10:], threshold=1e9)
        assert impossible["tp"] == 0
        assert impossible["fp"] == 0
        assert impossible["threshold"] == 1e9
