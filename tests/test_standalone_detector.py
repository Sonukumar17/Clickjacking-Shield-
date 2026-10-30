"""Tests for Standalone Clickjacking Detection Module"""

import pytest
from clickjacking_detection import ClickjackDetector, detect_clickjacking


class TestStandaloneDetector:
    def test_detector_xfo_evaluation(self):
        detector = ClickjackDetector()

        # DENY
        res = detector._evaluate_xfo("DENY")
        assert res["present"] is True
        assert res["status"] == "Protected (DENY)"

        # SAMEORIGIN
        res = detector._evaluate_xfo("SAMEORIGIN")
        assert res["present"] is True
        assert res["status"] == "Protected (SAMEORIGIN)"

        # Missing
        res = detector._evaluate_xfo(None)
        assert res["present"] is False
        assert res["status"] == "Missing"

        # Deprecated
        res = detector._evaluate_xfo("ALLOW-FROM https://trusted.com")
        assert "Deprecated" in res["status"]

    def test_detector_csp_evaluation(self):
        detector = ClickjackDetector()

        # frame-ancestors 'none'
        res = detector._evaluate_csp("frame-ancestors 'none';", None)
        assert res["present"] is True
        assert res["status"] == "Protected (none)"

        # frame-ancestors 'self'
        res = detector._evaluate_csp("frame-ancestors 'self';", None)
        assert res["present"] is True
        assert res["status"] == "Protected (self)"

        # Wildcard *
        res = detector._evaluate_csp("frame-ancestors *;", None)
        assert "Wildcard" in res["status"]

        # Missing
        res = detector._evaluate_csp(None, None)
        assert res["present"] is False
        assert res["status"] == "Missing"

    def test_synthesize_posture(self):
        detector = ClickjackDetector()

        xfo_prot = detector._evaluate_xfo("DENY")
        csp_prot = detector._evaluate_csp("frame-ancestors 'none';", None)
        posture, confidence, explanation, _ = detector._synthesize_posture(xfo_prot, csp_prot, 200)

        assert posture == "Protected"
        assert confidence == "High"

        xfo_miss = detector._evaluate_xfo(None)
        csp_miss = detector._evaluate_csp(None, None)
        posture_risk, _, _, _ = detector._synthesize_posture(xfo_miss, csp_miss, 200)

        assert posture_risk == "Potential Risk"
