"""Automated tests for Isolation Forest machine learning anomaly detection (Task 5B).

Tests:
1. Valid model configuration.
2. Invalid configuration.
3. Feature-vector construction.
4. Boolean conversion.
5. Feature ordering.
6. Missing features.
7. NaN and infinity rejection.
8. Insufficient training data.
9. Successful model training.
10. Calibration using normal-only data.
11. Prevention of training/calibration overlap.
12. Successful prediction.
13. Deterministic results using random_state.
14. Normal activity classification.
15. Brute-force activity classification.
16. Suspicious successful-login evaluation.
17. Correct normality-score interpretation.
18. Evaluation metrics.
19. Confusion matrix.
20. Independent rule-based versus ML evaluation.
"""

from datetime import datetime, timedelta, timezone
import math
import pytest

from app.services.feature_extractor import WindowFeatures, extract_window_features
from app.services.isolation_forest_detector import (
    FEATURE_NAMES,
    IsolationForestConfig,
    IsolationForestDetector,
    MLDetectionResult,
    evaluate_ml_detector,
    evaluate_rule_detector,
    generate_synthetic_evaluation_datasets,
    window_to_feature_vector,
    windows_to_feature_matrix,
)
from app.services.rule_detector import RuleDetector
from app.services.ssh_event_generator import (
    generate_brute_force_events,
    generate_normal_events,
    generate_suspicious_success_events,
)


def make_mock_window(
    total_attempts: int = 2,
    failed_login_count: int = 0,
    successful_login_count: int = 2,
    distinct_usernames: int = 1,
    failure_ratio: float = 0.0,
    success_after_failures: bool = False,
    source_ip: str = "192.0.2.1",
    start_time: datetime = None,
) -> WindowFeatures:
    """Helper to build a single WindowFeatures record for unit testing."""
    st = start_time or datetime(2026, 11, 8, 10, 0, 0, tzinfo=timezone.utc)
    return WindowFeatures(
        source_ip=source_ip,
        window_start=st,
        window_end=st + timedelta(minutes=1),
        total_attempts=total_attempts,
        failed_login_count=failed_login_count,
        successful_login_count=successful_login_count,
        distinct_usernames=distinct_usernames,
        failure_ratio=failure_ratio,
        success_after_failures=success_after_failures,
        event_ids=(),
    )


# ---------------------------------------------------------------------------
# Test 1 & 2: Configuration Validation
# ---------------------------------------------------------------------------

def test_valid_model_configuration():
    """Test 1: Valid IsolationForestConfig initializes properly with defaults and custom values."""
    default_cfg = IsolationForestConfig()
    assert default_cfg.n_estimators == 100
    assert default_cfg.random_state == 42
    assert default_cfg.default_target_fpr == 0.05

    custom_cfg = IsolationForestConfig(
        n_estimators=50,
        max_samples=0.8,
        contamination=0.1,
        max_features=0.9,
        random_state=123,
        min_training_samples=15,
        default_target_fpr=0.03,
    )
    assert custom_cfg.n_estimators == 50
    assert custom_cfg.max_samples == 0.8
    assert custom_cfg.random_state == 123


def test_invalid_configuration():
    """Test 2: Invalid configuration arguments raise ValueError."""
    with pytest.raises(ValueError, match="n_estimators must be a positive integer"):
        IsolationForestConfig(n_estimators=0)

    with pytest.raises(ValueError, match="max_samples"):
        IsolationForestConfig(max_samples=-1)

    with pytest.raises(ValueError, match="contamination"):
        IsolationForestConfig(contamination=0.8)

    with pytest.raises(ValueError, match="max_features"):
        IsolationForestConfig(max_features=1.5)

    with pytest.raises(ValueError, match="min_training_samples"):
        IsolationForestConfig(min_training_samples=1)

    with pytest.raises(ValueError, match="default_target_fpr"):
        IsolationForestConfig(default_target_fpr=1.2)


# ---------------------------------------------------------------------------
# Test 3, 4, 5: Feature Vector Construction & Ordering
# ---------------------------------------------------------------------------

def test_feature_vector_construction():
    """Test 3: Converts WindowFeatures to a numeric NumPy array of shape (6,)."""
    wf = make_mock_window(
        total_attempts=10,
        failed_login_count=3,
        successful_login_count=7,
        distinct_usernames=2,
        failure_ratio=0.3,
        success_after_failures=False,
    )
    vec = window_to_feature_vector(wf)
    assert vec.shape == (6,)
    assert vec.dtype == float


def test_boolean_conversion():
    """Test 4: Converts success_after_failures boolean to 1.0 or 0.0."""
    wf_true = make_mock_window(success_after_failures=True)
    wf_false = make_mock_window(success_after_failures=False)

    vec_true = window_to_feature_vector(wf_true)
    vec_false = window_to_feature_vector(wf_false)

    assert vec_true[5] == 1.0
    assert vec_false[5] == 0.0


def test_feature_ordering():
    """Test 5: Vector columns match FEATURE_NAMES exactly."""
    wf = make_mock_window(
        total_attempts=12,
        failed_login_count=4,
        successful_login_count=8,
        distinct_usernames=3,
        failure_ratio=0.3333,
        success_after_failures=True,
    )
    vec = window_to_feature_vector(wf)

    assert vec[0] == 12.0   # total_attempts
    assert vec[1] == 4.0    # failed_login_count
    assert vec[2] == 8.0    # successful_login_count
    assert vec[3] == 3.0    # distinct_usernames
    assert vec[4] == 0.3333 # failure_ratio
    assert vec[5] == 1.0    # success_after_failures


# ---------------------------------------------------------------------------
# Test 6 & 7: Missing / NaN / Infinity Rejection
# ---------------------------------------------------------------------------

def test_missing_features():
    """Test 6: None or non-WindowFeatures input is rejected."""
    with pytest.raises(ValueError, match="Expected WindowFeatures instance"):
        window_to_feature_vector(None)

    with pytest.raises(ValueError, match="Expected WindowFeatures instance"):
        window_to_feature_vector({"total_attempts": 5})


def test_nan_and_infinity_rejection():
    """Test 7: Rejects NaN and infinite values in feature vector."""
    wf_nan = make_mock_window(failure_ratio=float("nan"))
    with pytest.raises(ValueError, match="contains NaN"):
        window_to_feature_vector(wf_nan)

    wf_inf = make_mock_window(failure_ratio=float("inf"))
    with pytest.raises(ValueError, match="contains infinite value"):
        window_to_feature_vector(wf_inf)


# ---------------------------------------------------------------------------
# Test 8 & 9: Training Validation & Execution
# ---------------------------------------------------------------------------

def test_insufficient_training_data():
    """Test 8: Training with fewer than min_training_samples raises ValueError."""
    detector = IsolationForestDetector(config=IsolationForestConfig(min_training_samples=10))
    sparse_windows = [make_mock_window() for _ in range(5)]

    with pytest.raises(ValueError, match="Insufficient training data"):
        detector.train(sparse_windows)


def test_successful_model_training():
    """Test 9: Successfully trains on sufficient normal baseline windows."""
    train_windows, _, _, _, _ = generate_synthetic_evaluation_datasets(
        train_normal_event_count=80,
        train_seed=101,
    )
    detector = IsolationForestDetector()
    assert detector.is_trained is False

    detector.train(train_windows)
    assert detector.is_trained is True
    assert detector._model is not None


# ---------------------------------------------------------------------------
# Test 10 & 11: Calibration & Prevention of Overlap
# ---------------------------------------------------------------------------

def test_calibration_using_normal_only_data():
    """Test 10: Calibrates anomaly threshold on held-out normal-only windows."""
    train_w, cal_w, _, _, _ = generate_synthetic_evaluation_datasets(
        train_normal_event_count=80,
        cal_normal_event_count=40,
        train_seed=201,
        cal_seed=202,
    )
    detector = IsolationForestDetector()
    detector.train(train_w)

    thresh = detector.calibrate(cal_w, target_fpr=0.05)
    assert detector.is_calibrated is True
    assert detector.calibrated_threshold == thresh
    assert isinstance(thresh, float)


def test_prevention_of_training_calibration_overlap():
    """Test 11: Calibration fails if model is un-trained; datasets are structurally disjoint."""
    train_w, cal_w, _, _, _ = generate_synthetic_evaluation_datasets(
        train_seed=301,
        cal_seed=302,
    )
    detector = IsolationForestDetector()

    # Calling calibrate on untrained detector must fail
    with pytest.raises(RuntimeError, match="Model must be trained before"):
        detector.calibrate(cal_w)

    # Empty calibration data must fail
    detector.train(train_w)
    with pytest.raises(ValueError, match="Calibration dataset cannot be empty"):
        detector.calibrate([])

    # Ensure windows do not overlap in timestamps
    train_times = {w.window_start for w in train_w}
    cal_times = {w.window_start for w in cal_w}
    assert train_times.isdisjoint(cal_times), "Training and calibration windows must not overlap!"


# ---------------------------------------------------------------------------
# Test 12 & 13: Prediction & Reproducibility
# ---------------------------------------------------------------------------

def test_successful_prediction():
    """Test 12: Generates structured MLDetectionResult for a feature window."""
    train_w, cal_w, test_w, _, _ = generate_synthetic_evaluation_datasets(train_seed=401, cal_seed=402, test_seed=403)
    detector = IsolationForestDetector()
    detector.train(train_w)
    detector.calibrate(cal_w)

    result = detector.predict_window(test_w[0])
    assert isinstance(result, MLDetectionResult)
    assert isinstance(result.is_anomaly, bool)
    assert isinstance(result.normality_score, float)
    assert result.source_ip == test_w[0].source_ip
    assert result.window_start == test_w[0].window_start
    assert "normality_score" in result.score_interpretation

    # Verify to_dict serialization
    d = result.to_dict()
    assert "is_anomaly" in d
    assert "feature_summary" in d


def test_deterministic_results_using_random_state():
    """Test 13: Models with identical random_state produce identical scores and thresholds."""
    train_w, cal_w, test_w, _, _ = generate_synthetic_evaluation_datasets(train_seed=501, cal_seed=502, test_seed=503)

    det1 = IsolationForestDetector(config=IsolationForestConfig(random_state=42))
    det1.train(train_w)
    det1.calibrate(cal_w)
    res1 = det1.predict_windows(test_w)

    det2 = IsolationForestDetector(config=IsolationForestConfig(random_state=42))
    det2.train(train_w)
    det2.calibrate(cal_w)
    res2 = det2.predict_windows(test_w)

    assert det1.calibrated_threshold == det2.calibrated_threshold
    for r1, r2 in zip(res1, res2):
        assert r1.normality_score == r2.normality_score
        assert r1.is_anomaly == r2.is_anomaly


# ---------------------------------------------------------------------------
# Test 14, 15, 16, 17: Scenario Classification & Score Interpretation
# ---------------------------------------------------------------------------

def test_normal_activity_classification():
    """Test 14: Normal activity windows have high normality scores and low anomaly rate."""
    train_w, cal_w, test_w, labels, scenarios = generate_synthetic_evaluation_datasets(
        train_seed=601,
        cal_seed=602,
        test_seed=603,
    )
    detector = IsolationForestDetector(config=IsolationForestConfig(random_state=42))
    detector.train(train_w)
    detector.calibrate(cal_w, target_fpr=0.05)

    normal_windows = [w for w, lab in zip(test_w, labels) if lab == 0]
    results = detector.predict_windows(normal_windows)

    anomalies = [r for r in results if r.is_anomaly]
    # On normal evaluation data, anomaly rate should be close to calibrated FPR (e.g. <= 10%)
    anomaly_rate = len(anomalies) / len(results)
    assert anomaly_rate <= 0.15, f"Expected low FPR on normal data, got {anomaly_rate:.2f}"


def test_brute_force_activity_classification():
    """Test 15: High-volume brute-force activity is detected as an anomaly."""
    train_w, cal_w, _, _, _ = generate_synthetic_evaluation_datasets(train_seed=701, cal_seed=702)
    detector = IsolationForestDetector()
    detector.train(train_w)
    detector.calibrate(cal_w)

    # Brute-force window: 50 failed attempts in 1 minute
    bf_events = generate_brute_force_events(count=50, seed=777)
    bf_windows = extract_window_features(bf_events)
    assert len(bf_windows) >= 1

    result = detector.predict_window(bf_windows[0])
    assert result.is_anomaly is True
    assert result.normality_score < result.calibrated_threshold


def test_suspicious_successful_login_evaluation():
    """Test 16: Suspicious success following repeated failures is detected as anomalous."""
    train_w, cal_w, _, _, _ = generate_synthetic_evaluation_datasets(train_seed=801, cal_seed=802)
    detector = IsolationForestDetector()
    detector.train(train_w)
    detector.calibrate(cal_w)

    ss_events = generate_suspicious_success_events(failure_count=8, seed=888)
    ss_windows = extract_window_features(ss_events)
    assert len(ss_windows) >= 1

    result = detector.predict_window(ss_windows[0])
    assert result.is_anomaly is True


def test_correct_normality_score_interpretation():
    """Test 17: Abnormal observations receive lower normality_score than baseline normal windows."""
    train_w, cal_w, _, _, _ = generate_synthetic_evaluation_datasets(train_seed=901, cal_seed=902)
    detector = IsolationForestDetector()
    detector.train(train_w)
    detector.calibrate(cal_w)

    # Typical normal window (1 success, 0 failures)
    norm_wf = make_mock_window(total_attempts=1, failed_login_count=0, successful_login_count=1)
    # Severe attack window (50 attempts, 50 failures)
    attack_wf = make_mock_window(total_attempts=50, failed_login_count=50, successful_login_count=0, failure_ratio=1.0)

    norm_res = detector.predict_window(norm_wf)
    attack_res = detector.predict_window(attack_wf)

    # Scikit-learn decision_function: lower score = more abnormal
    assert attack_res.normality_score < norm_res.normality_score


# ---------------------------------------------------------------------------
# Test 18, 19, 20: Metrics, Confusion Matrix, and Rule vs ML Independence
# ---------------------------------------------------------------------------

def test_evaluation_metrics():
    """Test 18: evaluate_ml_detector calculates precision, recall, f1, accuracy, fpr, tpr."""
    train_w, cal_w, test_w, labels, _ = generate_synthetic_evaluation_datasets(
        train_seed=1001,
        cal_seed=1002,
        test_seed=1003,
    )
    detector = IsolationForestDetector()
    detector.train(train_w)
    detector.calibrate(cal_w)

    metrics = evaluate_ml_detector(detector, test_w, labels)
    for field in ("accuracy", "precision", "recall", "f1_score", "false_positive_rate", "true_positive_rate"):
        assert field in metrics
        assert 0.0 <= metrics[field] <= 1.0


def test_confusion_matrix():
    """Test 19: Confusion matrix totals equal sample count."""
    train_w, cal_w, test_w, labels, _ = generate_synthetic_evaluation_datasets(
        train_seed=1101,
        cal_seed=1102,
        test_seed=1103,
    )
    detector = IsolationForestDetector()
    detector.train(train_w)
    detector.calibrate(cal_w)

    metrics = evaluate_ml_detector(detector, test_w, labels)
    cm = metrics["confusion_matrix"]

    total = cm["true_negatives"] + cm["false_positives"] + cm["false_negatives"] + cm["true_positives"]
    assert total == len(test_w)
    assert total == metrics["sample_count"]


def test_independent_rule_based_versus_ml_evaluation():
    """Test 20: ML and Rule detector evaluate independently on identical held-out test data."""
    train_w, cal_w, test_w, labels, _ = generate_synthetic_evaluation_datasets(
        train_seed=1201,
        cal_seed=1202,
        test_seed=1203,
    )

    # 1. Evaluate ML Detector
    ml_detector = IsolationForestDetector()
    ml_detector.train(train_w)
    ml_detector.calibrate(cal_w)
    ml_metrics = evaluate_ml_detector(ml_detector, test_w, labels)

    # 2. Evaluate Rule Detector
    rule_detector = RuleDetector()
    rule_metrics = evaluate_rule_detector(rule_detector, test_w, labels)

    # Ensure reports are completely distinct dictionaries and models run independently
    assert ml_metrics["model_type"] == "IsolationForest"
    assert rule_metrics["model_type"] == "RuleDetector"
    assert ml_metrics["sample_count"] == rule_metrics["sample_count"]


# ---------------------------------------------------------------------------
# Test 21, 22, 23, 24: Scoring Consistency, Threshold Usage & Interpretation
# ---------------------------------------------------------------------------

def test_calibration_and_prediction_use_same_scoring_method():
    """Test 21: Both calibration and prediction strictly use decision_function on the same scale."""
    train_w, cal_w, test_w, _, _ = generate_synthetic_evaluation_datasets(
        train_seed=1301,
        cal_seed=1302,
        test_seed=1303,
    )
    detector = IsolationForestDetector()
    detector.train(train_w)
    cal_thresh = detector.calibrate(cal_w, target_fpr=0.05)

    # 1. Verify calibration uses decision_function
    X_cal = windows_to_feature_matrix(cal_w)
    raw_cal_df = detector._model.decision_function(X_cal)
    raw_cal_ss = detector._model.score_samples(X_cal)
    offset = detector._model.offset_

    # In scikit-learn: decision_function(X) = score_samples(X) - offset_
    import numpy as np
    assert np.allclose(raw_cal_df, raw_cal_ss - offset), "decision_function must equal score_samples - offset_"

    # Calibration threshold must be an empirical percentile of decision_function scores
    expected_threshold = float(np.percentile(raw_cal_df, 5.0))
    assert math.isclose(cal_thresh, expected_threshold, rel_tol=1e-9)

    # 2. Verify prediction uses decision_function
    for w in test_w[:5]:
        res = detector.predict_window(w)
        x_vec = window_to_feature_vector(w).reshape(1, -1)
        expected_score = float(detector._model.decision_function(x_vec)[0])
        assert math.isclose(res.normality_score, expected_score, rel_tol=1e-9)
        # Verify score_interpretation accurately reflects non-probabilistic decision score
        assert "probability" in res.score_interpretation.lower()


def test_threshold_comparison_consistency():
    """Test 22: Classification is strictly consistent with (normality_score < calibrated_threshold)."""
    train_w, cal_w, test_w, _, _ = generate_synthetic_evaluation_datasets(
        train_seed=1401,
        cal_seed=1402,
        test_seed=1403,
    )
    detector = IsolationForestDetector()
    detector.train(train_w)
    detector.calibrate(cal_w, target_fpr=0.05)

    results = detector.predict_windows(test_w)
    for res in results:
        expected_is_anomaly = (res.normality_score < res.calibrated_threshold)
        assert res.is_anomaly == expected_is_anomaly, (
            f"Classification mismatch: score={res.normality_score}, "
            f"threshold={res.calibrated_threshold}, is_anomaly={res.is_anomaly}"
        )


def test_normal_and_anomalous_score_interpretations():
    """Test 23: Lower decision scores indicate more abnormal behavior across diverse attack vectors."""
    train_w, cal_w, _, _, _ = generate_synthetic_evaluation_datasets(
        train_seed=1501,
        cal_seed=1502,
    )
    detector = IsolationForestDetector()
    detector.train(train_w)
    detector.calibrate(cal_w)

    clean_normal = make_mock_window(total_attempts=1, failed_login_count=0, successful_login_count=1)
    moderate_failures = make_mock_window(total_attempts=6, failed_login_count=6, successful_login_count=0, failure_ratio=1.0)
    massive_brute_force = make_mock_window(total_attempts=60, failed_login_count=60, successful_login_count=0, failure_ratio=1.0)

    score_normal = detector.predict_window(clean_normal).normality_score
    score_mod = detector.predict_window(moderate_failures).normality_score
    score_massive = detector.predict_window(massive_brute_force).normality_score

    # Normality score hierarchy: clean normal > moderate failures > massive attack
    assert score_normal > score_mod, "Normal window must have higher normality score than failure burst"
    assert score_mod >= score_massive, "Massive brute-force must have lower or equal normality score than moderate failures"


def test_custom_calibration_threshold_actively_used_in_prediction():
    """Test 24: Threshold change actively changes prediction outcome without touching model weights."""
    train_w, cal_w, test_w, _, _ = generate_synthetic_evaluation_datasets(
        train_seed=1601,
        cal_seed=1602,
        test_seed=1603,
    )
    detector = IsolationForestDetector()
    detector.train(train_w)

    # Predict with uncalibrated default threshold (0.0)
    target_window = test_w[0]
    uncal_res = detector.predict_window(target_window)
    assert uncal_res.calibrated_threshold == 0.0

    # Score of target window
    score = uncal_res.normality_score

    # Force artificial threshold above the score -> must be flagged as anomaly
    detector._calibrated_threshold = score + 0.05
    res_high = detector.predict_window(target_window)
    assert res_high.is_anomaly is True
    assert res_high.calibrated_threshold == score + 0.05

    # Force artificial threshold below the score -> must NOT be flagged as anomaly
    detector._calibrated_threshold = score - 0.05
    res_low = detector.predict_window(target_window)
    assert res_low.is_anomaly is False
    assert res_low.calibrated_threshold == score - 0.05


