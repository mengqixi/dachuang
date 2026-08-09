import os
import sys
import unittest
from unittest.mock import patch


sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))


from src.analysis.privacy_risk import (  # noqa: E402
    ANALYSIS_POLICY_VERSION,
    assess_privacy_exposure,
    build_dual_risk_summary,
    summarize_attack_risk,
)
import src.user_submission_manager as submission_module  # noqa: E402


class PrivacyExposurePolicyTests(unittest.TestCase):
    def test_sensitive_credentials_and_financial_fields_raise_privacy_risk(self):
        columns = [
            "username", "ip", "password", "phone", "bank_card", "income", "label",
        ]
        result = assess_privacy_exposure(
            columns,
            ["username", "password", "phone", "bank_card", "income"],
            {"rows": 1200, "columns": len(columns)},
        )

        self.assertEqual(result["policy_version"], ANALYSIS_POLICY_VERSION)
        self.assertIn(result["level"], {"high", "critical"})
        self.assertTrue(result["is_model_score"] is False)
        self.assertEqual(result["external_api_payload_policy"], "redacted_aggregates_only")
        category_keys = {item["key"] for item in result["categories"]}
        self.assertTrue({"credentials", "financial", "identity"}.issubset(category_keys))

    def test_common_login_identifiers_are_kept_separate_from_attack_score(self):
        privacy = assess_privacy_exposure(
            [
                "username", "ip_address", "device_type",
                "current_password_strength", "failed_attempts", "label",
            ],
            ["username"],
            {"rows": 20, "columns": 6},
        )
        attack = summarize_attack_risk(
            {"low": 18, "medium": 1, "high": 1, "critical": 0},
            0.24,
            20,
        )
        combined = build_dual_risk_summary(privacy, attack)

        self.assertTrue(combined["axes_are_independent"])
        category_keys = {item["key"] for item in privacy["categories"]}
        self.assertNotIn("credentials", category_keys)
        self.assertNotIn("contact", category_keys)
        self.assertIn("network_identifier", category_keys)
        self.assertEqual(combined["privacy_level"], privacy["level"])
        self.assertEqual(combined["attack_level"], attack["level"])
        self.assertIn(combined["recommended_route"], {
            "encrypted_archive", "encrypted_review_first", "local_feature_first",
        })

    def test_single_critical_sample_requires_review_even_when_aggregate_is_low(self):
        attack = summarize_attack_risk(
            {"low": 499, "medium": 0, "high": 0, "critical": 1},
            0.05,
            500,
        )
        combined = build_dual_risk_summary(
            {"level": "low"},
            attack,
        )

        self.assertEqual(attack["level"], "low")
        self.assertEqual(combined["attack_peak_level"], "critical")
        self.assertEqual(combined["overall_level"], "critical")
        self.assertEqual(combined["recommended_route"], "encrypted_review_first")

    def test_storage_guard_rejects_without_deleting_archives(self):
        with patch.object(submission_module, "ARCHIVE_QUOTA_BYTES", 100), patch.object(
            submission_module, "_archive_usage_bytes", return_value=90
        ):
            with self.assertRaises(submission_module.UploadValidationError):
                submission_module._validate_storage_capacity(20)

        class DiskUsage(object):
            free = 100

        with patch.object(submission_module, "ARCHIVE_QUOTA_BYTES", 10 ** 9), patch.object(
            submission_module, "MIN_FREE_DISK_BYTES", 90
        ), patch.object(submission_module, "_archive_usage_bytes", return_value=0), patch.object(
            submission_module.shutil, "disk_usage", return_value=DiskUsage()
        ):
            with self.assertRaises(submission_module.UploadValidationError):
                submission_module._validate_storage_capacity(20)


if __name__ == "__main__":
    unittest.main()
