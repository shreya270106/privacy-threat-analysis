import unittest

from threat_engine.detector import detect_attack
from threat_engine.metrics import evaluate_predictions


class TestThreatDetector(unittest.TestCase):

    def test_brute_force_detailed(self):
        log = {
            "source_type": "AUTH",
            "action": "LOGIN_ATTEMPT sudo/su",
            "result": "FAILED",
            "resource_details": {
                "attempt_count": 10
            }
        }

        self.assertEqual(
            detect_attack(log),
            "BRUTE_FORCE"
        )

    def test_brute_force_generalized_l2(self):
        log = {
            "source_type": "AUTH",
            "action": "AUTHENTICATION",
            "result": "FAILED",
            "resource_details": {
                "attempt_count": 10
            }
        }

        self.assertEqual(
            detect_attack(log),
            "BRUTE_FORCE"
        )

    def test_brute_force_generalized_l3(self):
        log = {
            "source_type": "AUTH",
            "action": "AUTHENTICATION",
            "result": "UNSUCCESSFUL",
            "resource_details": {
                "attempt_count": 10
            }
        }

        self.assertEqual(
            detect_attack(log),
            "BRUTE_FORCE"
        )

    def test_web_recon(self):
        log = {
            "source_type": "WEB_ACCESS",
            "action": "GET /etc/passwd HTTP/1.1",
            "result": "DENIED",
            "resource_details": {
                "user_agent": "sqlmap/1.6"
            }
        }

        self.assertEqual(
            detect_attack(log),
            "WEB_RECON"
        )

    def test_data_exfiltration(self):
        log = {
            "source_type": "FILE_DOWNLOAD",
            "action": "GET /api/v1/export_db",
            "result": "SUCCESS",
            "resource_details": {}
        }

        self.assertEqual(
            detect_attack(log),
            "DATA_EXFILTRATION"
        )

    def test_normal_event(self):
        log = {
            "source_type": "WEB_ACCESS",
            "action": "GET /index.html HTTP/1.1",
            "result": "SUCCESS",
            "resource_details": {}
        }

        self.assertEqual(
            detect_attack(log),
            "NONE"
        )

    def test_generalized_sensitive_resource(self):
        log = {
            "source_type": "FILE_DOWNLOAD",
            "action": "SENSITIVE_RESOURCE_ACCESS",
            "result": "SUCCESS",
            "resource_details": {}
        }

        self.assertEqual(
            detect_attack(log),
            "DATA_EXFILTRATION"
        )


class TestThreatMetrics(unittest.TestCase):

    def test_generalized_attack_labels(self):

        logs = [
            {"attack_type": "AUTH_ATTACK"},
            {"attack_type": "WEB_ATTACK"},
            {"attack_type": "DATA_ATTACK"},
            {"attack_type": "NONE"},
        ]

        predictions = [
            "BRUTE_FORCE",
            "WEB_RECON",
            "DATA_EXFILTRATION",
            "NONE",
        ]

        metrics = evaluate_predictions(
            logs,
            predictions
        )

        self.assertEqual(
            metrics["correct_predictions"],
            4
        )

        self.assertEqual(
            metrics["accuracy"],
            1.0
        )

        self.assertEqual(
            metrics["attack_detection_rate"],
            1.0
        )


if __name__ == "__main__":
    unittest.main()