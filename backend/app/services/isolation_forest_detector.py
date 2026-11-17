"""Isolation Forest machine learning anomaly detection module for SentinelAgent.

Extracts numeric feature matrices from WindowFeatures, fits an IsolationForest
estimator on baseline normal data, calibrates anomaly thresholds on independent
normal calibration windows, and provides predict and evaluation interfaces.

Operates completely independently of the rule-based detection engine.
"""

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import math
from typing import Any, Optional, Sequence, Union

import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.metrics import (
    accuracy_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)

from app.services.feature_extractor import (
    FeatureExtractor,
    FeatureExtractorConfig,
    WindowFeatures,
    extract_window_features,
)
from app.services.rule_detector import RuleDetector, RuleDetectorConfig
from app.services.ssh_event_generator import (
    generate_brute_force_events,
    generate_failed_events,
    generate_normal_events,
    generate_suspicious_success_events,
)

# Stable, canonical feature ordering
FEATURE_NAMES: tuple[str, ...] = (
    "total_attempts",
    "failed_login_count",
    "successful_login_count",
    "distinct_usernames",
    "failure_ratio",
    "success_after_failures",
)

MODEL_VERSION: str = "isolation_forest_v1"
SCORE_INTERPRETATION: str = (
    "Scikit-learn decision_function score (normality score): lower values indicate higher abnormality. "
    "Negative values represent outliers relative to the estimator offset (-0.5). "
    "A window is flagged as anomalous (is_anomaly=True) when normality_score < calibrated_threshold. "
    "This raw score is an isolation normality score, not a probability or calibrated risk percentage."
)


@dataclass(frozen=True)
class IsolationForestConfig:
    """Typed configuration class for the Isolation Forest anomaly detector.

    Parameters:
    - n_estimators: Number of base isolation trees in the ensemble.
    - max_samples: Number of samples drawn to train each base tree.
    - contamination: Expected proportion of outliers in the data (default: 'auto').
    - max_features: Proportion of features drawn to train each tree.
    - random_state: Fixed random seed for deterministic reproducibility.
    - min_training_samples: Minimum number of normal windows required to fit the model.
    - default_target_fpr: Default target false positive rate for threshold calibration.
    """

    n_estimators: int = 100
    max_samples: Union[int, float, str] = "auto"
    contamination: Union[float, str] = "auto"
    max_features: float = 1.0
    random_state: Optional[int] = 42
    min_training_samples: int = 10
    default_target_fpr: float = 0.05

    def __post_init__(self) -> None:
        if not isinstance(self.n_estimators, int) or self.n_estimators <= 0:
            raise ValueError(f"n_estimators must be a positive integer, got {self.n_estimators}")

        if isinstance(self.max_samples, int):
            if self.max_samples <= 0:
                raise ValueError(f"max_samples as integer must be > 0, got {self.max_samples}")
        elif isinstance(self.max_samples, float):
            if not (0.0 < self.max_samples <= 1.0):
                raise ValueError(f"max_samples as float must be in (0.0, 1.0], got {self.max_samples}")
        elif self.max_samples != "auto":
            raise ValueError(f"max_samples must be int, float, or 'auto', got {self.max_samples}")

        if isinstance(self.contamination, float):
            if not (0.0 < self.contamination <= 0.5):
                raise ValueError(f"contamination as float must be in (0.0, 0.5], got {self.contamination}")
        elif self.contamination != "auto":
            raise ValueError(f"contamination must be float or 'auto', got {self.contamination}")

        if not isinstance(self.max_features, (int, float)) or not (0.0 < self.max_features <= 1.0):
            raise ValueError(f"max_features must be in (0.0, 1.0], got {self.max_features}")

        if not isinstance(self.min_training_samples, int) or self.min_training_samples < 2:
            raise ValueError(f"min_training_samples must be an integer >= 2, got {self.min_training_samples}")

        if not isinstance(self.default_target_fpr, float) or not (0.0 < self.default_target_fpr < 1.0):
            raise ValueError(f"default_target_fpr must be a float in (0.0, 1.0), got {self.default_target_fpr}")


@dataclass(frozen=True)
class MLDetectionResult:
    """Immutable result structure for Isolation Forest anomaly predictions."""

    source_ip: str
    window_start: datetime
    window_end: datetime
    is_anomaly: bool
    normality_score: float
    calibrated_threshold: float
    model_version: str
    features: WindowFeatures
    feature_summary: dict[str, float]
    score_interpretation: str = SCORE_INTERPRETATION

    def to_dict(self) -> dict[str, Any]:
        """Convert detection result to serializable dictionary."""
        return {
            "source_ip": self.source_ip,
            "window_start": self.window_start.isoformat(),
            "window_end": self.window_end.isoformat(),
            "is_anomaly": self.is_anomaly,
            "normality_score": round(self.normality_score, 6),
            "calibrated_threshold": round(self.calibrated_threshold, 6),
            "model_version": self.model_version,
            "features": self.features.to_dict(),
            "feature_summary": self.feature_summary,
            "score_interpretation": self.score_interpretation,
        }


def window_to_feature_vector(wf: WindowFeatures) -> np.ndarray:
    """Convert a WindowFeatures instance into a 1D numeric array of shape (6,).

    Validates numeric types, dimensions, and ensures no NaN or infinite values exist.
    Converts boolean success_after_failures to 0.0 or 1.0.
    """
    if wf is None or not isinstance(wf, WindowFeatures):
        raise ValueError(f"Expected WindowFeatures instance, got {type(wf).__name__}")

    raw_values = [
        float(wf.total_attempts),
        float(wf.failed_login_count),
        float(wf.successful_login_count),
        float(wf.distinct_usernames),
        float(wf.failure_ratio),
        1.0 if wf.success_after_failures else 0.0,
    ]

    for val, name in zip(raw_values, FEATURE_NAMES):
        if math.isnan(val):
            raise ValueError(f"Feature '{name}' contains NaN")
        if math.isinf(val):
            raise ValueError(f"Feature '{name}' contains infinite value")

    vec = np.array(raw_values, dtype=np.float64)
    if vec.shape != (6,):
        raise ValueError(f"Expected feature vector of length 6, got shape {vec.shape}")
    return vec


def windows_to_feature_matrix(windows: Sequence[WindowFeatures]) -> np.ndarray:
    """Convert a sequence of WindowFeatures into a 2D NumPy array of shape (N, 6)."""
    if not windows:
        return np.empty((0, 6), dtype=np.float64)

    rows = [window_to_feature_vector(w) for w in windows]
    matrix = np.vstack(rows)
    return matrix


class IsolationForestDetector:
    """Machine learning anomaly detector based on scikit-learn's IsolationForest."""

    def __init__(self, config: Optional[IsolationForestConfig] = None) -> None:
        self.config = config or IsolationForestConfig()
        self._model: Optional[IsolationForest] = None
        self._calibrated_threshold: Optional[float] = None
        self._is_trained: bool = False
        self._is_calibrated: bool = False

    @property
    def is_trained(self) -> bool:
        """Whether the model has been fitted."""
        return self._is_trained

    @property
    def is_calibrated(self) -> bool:
        """Whether the anomaly threshold has been calibrated."""
        return self._is_calibrated

    @property
    def calibrated_threshold(self) -> Optional[float]:
        """Currently active calibrated anomaly threshold."""
        return self._calibrated_threshold

    def train(self, normal_windows: Sequence[WindowFeatures]) -> None:
        """Train the Isolation Forest estimator on normal-activity baseline windows.

        Requirements:
        - Must contain at least config.min_training_samples normal windows.
        - Must contain only baseline normal data (no attack samples).
        """
        if len(normal_windows) < self.config.min_training_samples:
            raise ValueError(
                f"Insufficient training data: expected at least {self.config.min_training_samples} "
                f"windows, got {len(normal_windows)}."
            )

        X_train = windows_to_feature_matrix(normal_windows)

        model = IsolationForest(
            n_estimators=self.config.n_estimators,
            max_samples=self.config.max_samples,
            contamination=self.config.contamination,
            max_features=self.config.max_features,
            random_state=self.config.random_state,
        )
        model.fit(X_train)

        self._model = model
        self._is_trained = True
        # Default uncalibrated threshold matches model decision_function offset (0.0)
        self._calibrated_threshold = 0.0
        self._is_calibrated = False

    def calibrate(
        self,
        calibration_windows: Sequence[WindowFeatures],
        target_fpr: Optional[float] = None,
    ) -> float:
        """Calibrate the decision threshold using an independent held-out normal-only dataset.

        Calculates decision_function scores for the normal calibration samples and sets
        the threshold to the (target_fpr * 100)-th percentile. Samples with scores below
        this threshold will be classified as anomalous.

        Parameters:
        - calibration_windows: Normal-only windows that do not overlap with training data.
        - target_fpr: Target false positive rate (default: config.default_target_fpr).

        Returns:
        - calibrated_threshold: The computed numeric threshold.
        """
        if not self._is_trained or self._model is None:
            raise RuntimeError("Model must be trained before threshold calibration.")

        if not calibration_windows:
            raise ValueError("Calibration dataset cannot be empty.")

        fpr = target_fpr if target_fpr is not None else self.config.default_target_fpr
        if not (0.0 < fpr < 1.0):
            raise ValueError(f"target_fpr must be a float in (0.0, 1.0), got {fpr}")

        X_cal = windows_to_feature_matrix(calibration_windows)
        scores = self._model.decision_function(X_cal)

        # Percentile corresponding to target FPR on normal calibration data
        threshold = float(np.percentile(scores, fpr * 100))
        self._calibrated_threshold = threshold
        self._is_calibrated = True
        return threshold

    def predict_window(self, window: WindowFeatures) -> MLDetectionResult:
        """Generate anomaly prediction for a single WindowFeatures record."""
        if not self._is_trained or self._model is None:
            raise RuntimeError("Model must be trained before predicting.")

        x = window_to_feature_vector(window).reshape(1, -1)
        score = float(self._model.decision_function(x)[0])

        threshold = (
            self._calibrated_threshold
            if self._calibrated_threshold is not None
            else 0.0
        )
        is_anomaly = bool(score < threshold)

        feature_summary = {
            "total_attempts": float(window.total_attempts),
            "failed_login_count": float(window.failed_login_count),
            "successful_login_count": float(window.successful_login_count),
            "distinct_usernames": float(window.distinct_usernames),
            "failure_ratio": float(window.failure_ratio),
            "success_after_failures": 1.0 if window.success_after_failures else 0.0,
        }

        return MLDetectionResult(
            source_ip=window.source_ip,
            window_start=window.window_start,
            window_end=window.window_end,
            is_anomaly=is_anomaly,
            normality_score=score,
            calibrated_threshold=threshold,
            model_version=MODEL_VERSION,
            features=window,
            feature_summary=feature_summary,
        )

    def predict_windows(self, windows: Sequence[WindowFeatures]) -> list[MLDetectionResult]:
        """Generate anomaly predictions for a sequence of WindowFeatures records."""
        return [self.predict_window(w) for w in windows]


# ---------------------------------------------------------------------------
# Evaluation Helpers (Independent ML & Rule Evaluation)
# ---------------------------------------------------------------------------

def evaluate_ml_detector(
    detector: IsolationForestDetector,
    test_windows: Sequence[WindowFeatures],
    ground_truth_labels: Sequence[int],
) -> dict[str, Any]:
    """Evaluate IsolationForestDetector against held-out labelled test windows.

    Labels:
    - 0: Normal
    - 1: Anomalous / Suspicious
    """
    if len(test_windows) != len(ground_truth_labels):
        raise ValueError(
            f"test_windows ({len(test_windows)}) and ground_truth_labels "
            f"({len(ground_truth_labels)}) must have identical length."
        )

    if not test_windows:
        raise ValueError("test_windows cannot be empty for evaluation.")

    predictions = [int(r.is_anomaly) for r in detector.predict_windows(test_windows)]
    y_true = list(ground_truth_labels)

    acc = float(accuracy_score(y_true, predictions))
    prec = float(precision_score(y_true, predictions, zero_division=0.0))
    rec = float(recall_score(y_true, predictions, zero_division=0.0))
    f1 = float(f1_score(y_true, predictions, zero_division=0.0))

    cm = confusion_matrix(y_true, predictions, labels=[0, 1])
    tn, fp, fn, tp = (int(v) for v in cm.ravel())

    fpr = float(fp / (fp + tn)) if (fp + tn) > 0 else 0.0
    tpr = float(tp / (tp + fn)) if (tp + fn) > 0 else 0.0

    return {
        "model_type": "IsolationForest",
        "sample_count": len(test_windows),
        "accuracy": round(acc, 4),
        "precision": round(prec, 4),
        "recall": round(rec, 4),
        "f1_score": round(f1, 4),
        "false_positive_rate": round(fpr, 4),
        "true_positive_rate": round(tpr, 4),
        "confusion_matrix": {
            "true_negatives": tn,
            "false_positives": fp,
            "false_negatives": fn,
            "true_positives": tp,
        },
    }


def evaluate_rule_detector(
    detector: RuleDetector,
    test_windows: Sequence[WindowFeatures],
    ground_truth_labels: Sequence[int],
) -> dict[str, Any]:
    """Evaluate RuleDetector against the exact same held-out labelled test windows."""
    if len(test_windows) != len(ground_truth_labels):
        raise ValueError("test_windows and ground_truth_labels must match in length.")

    if not test_windows:
        raise ValueError("test_windows cannot be empty for evaluation.")

    results = detector.evaluate_windows(test_windows)
    predictions = [int(r.is_suspicious) for r in results]
    y_true = list(ground_truth_labels)

    acc = float(accuracy_score(y_true, predictions))
    prec = float(precision_score(y_true, predictions, zero_division=0.0))
    rec = float(recall_score(y_true, predictions, zero_division=0.0))
    f1 = float(f1_score(y_true, predictions, zero_division=0.0))

    cm = confusion_matrix(y_true, predictions, labels=[0, 1])
    tn, fp, fn, tp = (int(v) for v in cm.ravel())

    fpr = float(fp / (fp + tn)) if (fp + tn) > 0 else 0.0
    tpr = float(tp / (tp + fn)) if (tp + fn) > 0 else 0.0

    return {
        "model_type": "RuleDetector",
        "sample_count": len(test_windows),
        "accuracy": round(acc, 4),
        "precision": round(prec, 4),
        "recall": round(rec, 4),
        "f1_score": round(f1, 4),
        "false_positive_rate": round(fpr, 4),
        "true_positive_rate": round(tpr, 4),
        "confusion_matrix": {
            "true_negatives": tn,
            "false_positives": fp,
            "false_negatives": fn,
            "true_positives": tp,
        },
    }


def generate_synthetic_evaluation_datasets(
    *,
    base_time: Optional[datetime] = None,
    train_normal_event_count: int = 120,
    cal_normal_event_count: int = 60,
    test_normal_event_count: int = 60,
    train_seed: int = 1001,
    cal_seed: int = 2001,
    test_seed: int = 3001,
) -> tuple[list[WindowFeatures], list[WindowFeatures], list[WindowFeatures], list[int], list[str]]:
    """Build controlled, separated synthetic datasets for training, calibration, and evaluation.

    Guarantees:
    - Training, calibration, and test sets are generated with different seeds.
    - Non-overlapping time windows prevent temporal leakage.
    - Ground-truth labels are created strictly outside the feature vectors.

    Returns:
    (train_windows, cal_windows, test_windows, test_labels, test_scenarios)
    """
    t0 = base_time or datetime(2026, 11, 8, 6, 0, 0, tzinfo=timezone.utc)

    # 1. Training dataset: Normal activity only
    t_train = t0
    train_events = generate_normal_events(
        count=train_normal_event_count,
        base_timestamp=t_train,
        failure_rate=0.05,
        seed=train_seed,
    )
    train_windows = extract_window_features(train_events)

    # 2. Calibration dataset: Independent normal activity only (different seed, non-overlapping window)
    t_cal = t0 + timedelta(hours=2)
    cal_events = generate_normal_events(
        count=cal_normal_event_count,
        base_timestamp=t_cal,
        failure_rate=0.05,
        seed=cal_seed,
    )
    cal_windows = extract_window_features(cal_events)

    # 3. Held-out Evaluation dataset: Mixed normal and attack scenarios (different seed, non-overlapping window)
    t_test = t0 + timedelta(hours=4)

    test_windows: list[WindowFeatures] = []
    test_labels: list[int] = []
    test_scenarios: list[str] = []

    # Scenario A: Normal traffic (label 0)
    test_norm_events = generate_normal_events(
        count=test_normal_event_count,
        base_timestamp=t_test,
        failure_rate=0.05,
        seed=test_seed,
    )
    norm_w = extract_window_features(test_norm_events)
    test_windows.extend(norm_w)
    test_labels.extend([0] * len(norm_w))
    test_scenarios.extend(["normal"] * len(norm_w))

    # Scenario B: Brute-Force activity (label 1)
    test_bf_events = generate_brute_force_events(
        count=50,
        base_timestamp=t_test + timedelta(minutes=30),
        seed=test_seed + 1,
    )
    bf_w = extract_window_features(test_bf_events)
    test_windows.extend(bf_w)
    test_labels.extend([1] * len(bf_w))
    test_scenarios.extend(["brute_force"] * len(bf_w))

    # Scenario C: Suspicious Success after repeated failures (label 1)
    test_ss_events = generate_suspicious_success_events(
        failure_count=8,
        base_timestamp=t_test + timedelta(minutes=45),
        seed=test_seed + 2,
    )
    ss_w = extract_window_features(test_ss_events)
    test_windows.extend(ss_w)
    test_labels.extend([1] * len(ss_w))
    test_scenarios.extend(["suspicious_success"] * len(ss_w))

    # Scenario D: Repeated Failed Logins (label 1)
    test_rep_events = generate_failed_events(
        count=15,
        base_timestamp=t_test + timedelta(minutes=55),
        duration_seconds=50.0,
        seed=test_seed + 3,
    )
    rep_w = extract_window_features(test_rep_events)
    test_windows.extend(rep_w)
    test_labels.extend([1] * len(rep_w))
    test_scenarios.extend(["repeated_failures"] * len(rep_w))

    return train_windows, cal_windows, test_windows, test_labels, test_scenarios

