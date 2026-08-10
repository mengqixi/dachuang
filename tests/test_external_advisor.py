import json
import os
import tempfile
import unittest
from unittest.mock import patch

from src.analysis.external_advisor import (
    ExternalAdvisorClient,
    ExternalAdvisorConfigError,
    ExternalAdvisorResponseError,
    ExternalAdvisorSettingsStore,
    build_ai_assisted_decisions,
    build_redacted_analysis_payload,
    build_redacted_training_comparison_payload,
    make_external_analysis_record,
    normalize_base_url,
)


def _settings(mode="chat_completions"):
    return {
        "enabled": True,
        "user_enabled": True,
        "base_url": "https://api.example.com/v1",
        "api_key": "unit-test-provider-key",
        "model": "gpt-5.6-sol",
        "mode": mode,
        "timeout_seconds": 15,
        "max_output_tokens": 800,
        "calls_per_hour": 20,
    }


def _advice(**overrides):
    value = {
        "summary": "本地模型与 AI 二次判定已完成。",
        "privacy_findings": ["仅使用脱敏统计。"],
        "attack_findings": ["存在需要复核的边界信号。"],
        "security_findings": [],
        "metric_findings": [],
        "data_quality_findings": [],
        "federated_tradeoffs": [],
        "recommended_actions": ["优先复核冲突项。"],
        "training_readiness": "review_first",
        "comparison_verdict": "not_comparable",
        "training_advice": "保留本地模型为主判定。",
        "comparison_advice": "指标口径一致后再比较。",
        "sample_reviews": [],
        "confidence_note": "仅作辅助判定。",
    }
    value.update(overrides)
    return value


class RedactedPayloadTests(unittest.TestCase):
    def test_frontend_uses_small_optional_controls_not_a_new_page(self):
        with open("index.html", "r", encoding="utf-8") as stream:
            html = stream.read()
        self.assertIn("AI 接口设置", html)
        self.assertIn("使用 AI 辅助判定", html)
        self.assertIn("AI 辅助选择模型", html)
        self.assertIn("同一共享留出集", html)
        self.assertIn("shared_holdout_validation", html)
        self.assertIn("epochs:20", html)
        self.assertIn('id="externalAiSettingsModal"', html)
        self.assertNotIn('id="pg-externalAi"', html)
        self.assertNotIn("隐私保护 90%", html)
        self.assertNotIn("metric.aggregation_method||'paillier'", html)
        self.assertNotIn("实验", html)
        self.assertIn("Paillier 安全聚合", html)
        self.assertIn("{id:'training',text:'训练中心'}", html)
        self.assertIn("requestedAppMode === 'admin'", html)
        self.assertNotIn("单机真实密态聚合", html)
        self.assertNotIn("单机无跨机构密钥隔离", html)
        self.assertNotIn("聚合与安全边界", html)
        self.assertNotIn("代码事实", html)

    def test_dataset_payload_excludes_identifiers_values_and_field_names(self):
        analysis = {
            "submission_id": "private-submission-id",
            "profile": {"rows": 2, "columns": 8, "missing_cells": 1, "missing_rate": 0.0625},
            "risk_summary": {"low": 1, "medium": 0, "high": 1, "critical": 0},
            "attack_types": {"疑似暴力破解": 1},
            "trigger_feature_stats": {"失败次数偏高": 1},
            "risk_score_distribution": {"0.65-0.85": 1},
            "privacy_risk": {
                "score": 0.7,
                "level": "high",
                "field_count": 2,
                "category_count": 1,
                "categories": [{
                    "key": "credentials",
                    "label": "凭据与密钥",
                    "field_count": 2,
                    "fields": ["raw_password", "private_token"],
                }],
            },
            "attack_risk": {"score": 0.8, "level": "high", "highest_sample_level": "high"},
            "dual_risk": {"privacy_level": "high", "attack_level": "high"},
            "analysis_trace": {
                "analysis_id": "private-analysis-id",
                "data_revision": "private-file-hash",
                "analyzed_rows": 2,
                "source_rows": 2,
                "source_rows_exact": True,
                "scope": "all_rows",
            },
            "risk_ranking": [{
                "id": 77,
                "username": "alice-private",
                "ip": "203.0.113.77",
                "risk_score": 0.82,
                "risk_level": "high",
                "confidence": 0.9,
                "attack_type": "疑似暴力破解",
                "trigger_features": ["失败次数偏高"],
                "dominant_factor": "失败登录次数",
                "score_breakdown": {
                    "model_score": 0.8,
                    "failed_attempts_score": 0.7,
                    "indicators": [{"value": "raw-secret-value"}],
                },
            }],
        }
        payload = build_redacted_analysis_payload(analysis)
        raw = json.dumps(payload, ensure_ascii=False)

        for forbidden in (
            "private-submission-id", "private-analysis-id", "private-file-hash",
            "alice-private", "203.0.113.77", "raw_password", "private_token",
            "raw-secret-value",
        ):
            self.assertNotIn(forbidden, raw)
        self.assertEqual(payload["payload_policy"], "redacted_aggregates_only")
        self.assertFalse(payload["evidence_boundaries"]["raw_rows_included"])
        self.assertEqual(payload["review_candidates"][0]["component_scores"]["model_score"], 0.8)
        self.assertNotIn("id", payload["review_candidates"][0])

    def test_training_payload_uses_aggregate_facts_and_marks_unfair_metric_scope(self):
        local = {
            "task_type": "local",
            "accuracy": 0.96,
            "samples": 100,
            "metadata": json.dumps({
                "dataset_source_id": "source-private",
                "dataset_revision": "revision-private",
                "preparation_id": "prep-private",
                "metric_scope": "train",
                "validation_available": False,
                "precision": 0.95,
                "recall": 0.94,
                "f1": 0.945,
            }),
        }
        federated = {
            "task_type": "federated",
            "accuracy": 0.91,
            "samples": 100,
            "metadata": json.dumps({
                "dataset_source_id": "source-private",
                "dataset_revision": "revision-private",
                "preparation_id": "prep-private",
                "metric_scope": "node_validation_weighted",
                "validation_available": True,
                "avg_accuracy": 0.91,
                "clients": [
                    {"name": "hospital", "samples": 50, "accuracy": 0.9, "loss": 0.2},
                    {"name": "bank", "samples": 50, "accuracy": 0.92, "loss": 0.18},
                ],
                "paillier": {
                    "paillier_enabled": True,
                    "display_only": True,
                    "timing_method": "parameter_count_estimate",
                    "actual_crypto_operations_performed": False,
                    "encryption_time_ms": 5.0,
                },
            }),
        }
        payload = build_redacted_training_comparison_payload(local, federated)
        raw = json.dumps(payload, ensure_ascii=False)

        self.assertNotIn("source-private", raw)
        self.assertNotIn("revision-private", raw)
        self.assertNotIn("prep-private", raw)
        self.assertNotIn("hospital", raw)
        self.assertNotIn("bank", raw)
        self.assertTrue(payload["comparison_fairness"]["same_dataset_revision"])
        self.assertFalse(payload["comparison_fairness"]["same_metric_scope"])
        self.assertFalse(payload["comparison_fairness"]["direct_accuracy_ranking_allowed"])
        self.assertEqual(
            payload["deterministic_differences"]["federated_minus_local_accuracy_percentage_points"],
            -5.0,
        )
        self.assertFalse(
            payload["security_architecture"]["federated_training"]["actual_weight_secure_aggregation"]
        )
        self.assertTrue(
            payload["security_architecture"]["federated_training"]["paillier_timings_are_estimates"]
        )
        self.assertFalse(
            payload["security_architecture"]["federated_training"]["actual_paillier_crypto_operations_performed"]
        )

    def test_training_payload_reports_actual_paillier_path_without_overstating_boundary(self):
        shared = {
            "dataset_source_id": "source-private",
            "dataset_revision": "revision-private",
            "preparation_id": "prep-private",
            "validation_id": "validation-private",
            "metric_scope": "shared_holdout_validation",
            "validation_available": True,
            "base_model_algorithm": "linear_logistic_binary_classifier",
            "optimizer": "batch_gradient_descent_l2",
            "epochs": 20,
        }
        centralized = {
            "task_type": "centralized",
            "accuracy": 0.9,
            "samples": 80,
            "metadata": json.dumps(shared),
        }
        federated = {
            "task_type": "federated",
            "accuracy": 0.9,
            "samples": 80,
            "metadata": json.dumps({
                **shared,
                "aggregation_method": "fedavg_paillier_secure",
                "secure_aggregation": True,
                "paillier": {
                    "paillier_enabled": True,
                    "secure_aggregation": True,
                    "display_only": False,
                    "timing_method": "measured_wall_clock",
                    "actual_crypto_operations_performed": True,
                    "key_size_bits": 2048,
                    "encrypted_parameter_count": 76,
                    "max_abs_weight_delta": 0.0000002,
                    "server_plaintext_node_updates_observable": True,
                    "cross_institution_key_isolation": False,
                    "trust_boundary": "single_host_logical_nodes",
                },
            }),
        }

        payload = build_redacted_training_comparison_payload(centralized, federated)
        security = payload["security_architecture"]["federated_training"]

        self.assertTrue(security["actual_weight_secure_aggregation"])
        self.assertTrue(security["actual_paillier_crypto_operations_performed"])
        self.assertTrue(security["paillier_replaces_actual_weight_path"])
        self.assertFalse(security["paillier_is_measurement_demo_layer"])
        self.assertFalse(security["cross_institution_key_isolation"])
        self.assertEqual(security["trust_boundary"], "single_host_logical_nodes")

    def test_training_payload_allows_limited_ranking_only_on_same_shared_holdout(self):
        shared = {
            "dataset_source_id": "source-private",
            "dataset_revision": "revision-private",
            "preparation_id": "prep-private",
            "validation_id": "validation-private",
            "metric_scope": "shared_holdout_validation",
            "metric_label": "同源共享留出集指标",
            "validation_available": True,
            "validation_samples": 20,
            "base_model_algorithm": "linear_logistic_binary_classifier",
            "optimizer": "batch_gradient_descent_l2",
            "epochs": 20,
        }
        local = {
            "task_type": "local",
            "accuracy": 0.9,
            "samples": 80,
            "metadata": json.dumps({**shared, "precision": 0.91, "recall": 0.89, "f1": 0.9}),
        }
        federated = {
            "task_type": "federated",
            "accuracy": 0.88,
            "samples": 80,
            "metadata": json.dumps({
                **shared,
                "avg_accuracy": 0.88,
                "precision": 0.89,
                "recall": 0.86,
                "f1": 0.875,
                "loss": 0.31,
                "clients": [{"name": "private-node", "samples": 80, "accuracy": 0.87, "loss": 0.4}],
            }),
        }

        payload = build_redacted_training_comparison_payload(local, federated)
        raw = json.dumps(payload, ensure_ascii=False)

        self.assertTrue(payload["comparison_fairness"]["same_validation_set"])
        self.assertTrue(payload["comparison_fairness"]["same_metric_scope"])
        self.assertTrue(payload["comparison_fairness"]["same_model_architecture"])
        self.assertTrue(payload["comparison_fairness"]["same_epoch_budget"])
        self.assertTrue(payload["comparison_fairness"]["direct_accuracy_ranking_allowed"])
        self.assertEqual(payload["local_training"]["data_summary"]["validation_samples"], 20)
        self.assertEqual(payload["federated_training"]["metrics"]["loss"], 0.31)
        self.assertFalse(payload["security_architecture"]["local_training"]["runtime_model_can_be_updated"])
        self.assertTrue(payload["security_architecture"]["local_training"]["runtime_detector_is_separate"])
        self.assertNotIn("validation-private", raw)
        self.assertNotIn("private-node", raw)

    def test_training_payload_preserves_shared_holdout_zero_accuracy(self):
        shared = {
            "dataset_source_id": "source-private",
            "dataset_revision": "revision-private",
            "preparation_id": "prep-private",
            "validation_id": "validation-private",
            "metric_scope": "shared_holdout_validation",
            "validation_available": True,
            "base_model_algorithm": "linear_logistic_binary_classifier",
            "optimizer": "batch_gradient_descent_l2",
            "epochs": 20,
        }
        centralized = {
            "task_type": "centralized",
            "accuracy": 0.5,
            "samples": 80,
            "metadata": json.dumps(shared),
        }
        federated = {
            "task_type": "federated",
            "accuracy": 0.0,
            "samples": 80,
            "metadata": json.dumps({
                **shared,
                "avg_accuracy": 0.0,
                "clients": [{"name": "private-node", "samples": 80, "accuracy": 0.9, "loss": 0.2}],
            }),
        }

        payload = build_redacted_training_comparison_payload(centralized, federated)

        self.assertEqual(payload["federated_training"]["metrics"]["accuracy"], 0.0)
        self.assertEqual(
            payload["deterministic_differences"]["federated_minus_local_accuracy_percentage_points"],
            -50.0,
        )


class SettingsStoreTests(unittest.TestCase):
    def test_key_is_encrypted_and_public_status_is_masked(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            settings_path = os.path.join(temp_dir, "settings.json")
            key_path = os.path.join(temp_dir, "settings.key")
            store = ExternalAdvisorSettingsStore(settings_path=settings_path, key_path=key_path)
            saved = store.save(_settings())

            with open(settings_path, "r", encoding="utf-8") as stream:
                stored_text = stream.read()
            self.assertNotIn("unit-test-provider-key", stored_text)
            self.assertEqual(saved["api_key"], "unit-test-provider-key")
            public = store.public_status(saved)
            self.assertNotIn("api_key", public)
            self.assertEqual(public["api_key_masked"], "****-key")

    def test_url_validation_rejects_plain_http_and_private_literal(self):
        with self.assertRaises(ExternalAdvisorConfigError):
            normalize_base_url("http://api.example.com/v1")
        with self.assertRaises(ExternalAdvisorConfigError):
            normalize_base_url("https://127.0.0.1/v1")
        self.assertEqual(
            normalize_base_url("https://api.example.com/v1/"),
            "https://api.example.com/v1",
        )


class ClientAndFusionTests(unittest.TestCase):
    def test_deterministic_boundaries_override_unsafe_provider_verdicts(self):
        training_payload = {
            "analysis_kind": "training_security_comparison",
            "payload_policy": "redacted_aggregates_only",
            "comparison_fairness": {"direct_accuracy_ranking_allowed": False},
        }
        training_record = make_external_analysis_record(
            training_payload,
            _settings(),
            {"advice": _advice(comparison_verdict="federated_preferred")},
        )
        self.assertEqual(training_record["advice"]["comparison_verdict"], "not_comparable")
        self.assertIn(
            "incomparable_metrics_cannot_select_a_preferred_model",
            training_record["boundary_guards"],
        )

        dataset_payload = {
            "analysis_kind": "dataset_security",
            "payload_policy": "redacted_aggregates_only",
            "privacy_risk": {"level": "high"},
            "attack_risk": {"level": "low", "highest_sample_level": "low"},
            "dual_risk": {"overall_level": "high"},
        }
        dataset_record = make_external_analysis_record(
            dataset_payload,
            _settings(),
            {"advice": _advice(training_readiness="ready")},
        )
        self.assertEqual(dataset_record["advice"]["training_readiness"], "review_first")
        self.assertIn(
            "high_local_risk_requires_review_before_training",
            dataset_record["boundary_guards"],
        )

    def test_chat_client_uses_explicit_store_false_and_parses_second_opinion(self):
        captured = {}

        def transport(url, body, headers, timeout):
            captured.update({
                "url": url,
                "body": json.loads(body.decode("utf-8")),
                "headers": headers,
                "timeout": timeout,
            })
            response = {
                "choices": [{"message": {"content": json.dumps(_advice(sample_reviews=[{
                    "rank": 1,
                    "assessment": "agree",
                    "ai_risk_level": "high",
                    "ai_confidence": 0.88,
                    "ai_attack_type": "疑似暴力破解",
                    "reason": "归一化信号与本地结果一致。",
                    "recommended_action": "继续优先复核。",
                }]), ensure_ascii=False)}}],
                "usage": {"prompt_tokens": 20, "completion_tokens": 30, "total_tokens": 50},
            }
            return 200, {"x-request-id": "request-unit-1"}, json.dumps(response, ensure_ascii=False).encode("utf-8")

        payload = build_redacted_analysis_payload({
            "profile": {"rows": 1, "columns": 3},
            "analysis_trace": {"analyzed_rows": 1, "source_rows": 1},
            "risk_ranking": [{"id": 1, "risk_score": 0.8, "risk_level": "high"}],
        })
        result = ExternalAdvisorClient(_settings(), transport=transport).analyze(payload)

        self.assertTrue(captured["url"].endswith("/chat/completions"))
        self.assertFalse(captured["body"]["store"])
        self.assertNotIn("unit-test-provider-key", json.dumps(captured["body"]))
        self.assertEqual(result["advice"]["sample_reviews"][0]["ai_confidence"], 0.88)
        self.assertEqual(result["usage"]["input_tokens"], 20)

    def test_responses_parser_supports_output_text_blocks(self):
        def transport(url, body, headers, timeout):
            response = {
                "output": [{
                    "type": "message",
                    "content": [{"type": "output_text", "text": json.dumps(_advice(), ensure_ascii=False)}],
                }],
            }
            return 200, {}, json.dumps(response, ensure_ascii=False).encode("utf-8")

        payload = build_redacted_analysis_payload({"analysis_trace": {"analyzed_rows": 1}})
        result = ExternalAdvisorClient(_settings("responses"), transport=transport).analyze(payload)
        self.assertEqual(result["advice"]["summary"], "本地模型与 AI 二次判定已完成。")

    def test_invalid_provider_text_is_rejected(self):
        def transport(url, body, headers, timeout):
            return 200, {}, json.dumps({"choices": [{"message": {"content": "not-json"}}]}).encode("utf-8")

        payload = build_redacted_analysis_payload({"analysis_trace": {"analyzed_rows": 1}})
        with self.assertRaises(ExternalAdvisorResponseError):
            ExternalAdvisorClient(_settings(), transport=transport).analyze(payload)

    def test_assisted_fusion_never_downgrades_local_high_and_can_escalate(self):
        analysis = {
            "risk_ranking": [
                {"id": 11, "risk_score": 0.82, "risk_level": "high"},
                {"id": 12, "risk_score": 0.48, "risk_level": "medium"},
            ],
        }
        advice = _advice(sample_reviews=[
            {
                "rank": 1,
                "assessment": "review",
                "ai_risk_level": "low",
                "ai_confidence": 0.9,
                "reason": "存在冲突。",
                "recommended_action": "人工复核。",
            },
            {
                "rank": 2,
                "assessment": "escalate",
                "ai_risk_level": "high",
                "ai_confidence": 0.8,
                "reason": "多个信号叠加。",
                "recommended_action": "提高复核优先级。",
            },
        ])
        result = build_ai_assisted_decisions(analysis, advice)

        self.assertEqual(result["items"][0]["combined_risk_level"], "high")
        self.assertEqual(result["items"][0]["decision_status"], "conflict_local_preserved")
        self.assertEqual(result["items"][1]["combined_risk_level"], "high")
        self.assertEqual(result["items"][1]["decision_status"], "ai_escalated_review")
        self.assertEqual(result["summary"]["ai_escalated"], 1)

    def test_duplicate_provider_ranks_do_not_duplicate_a_local_decision(self):
        analysis = {"risk_ranking": [{"id": 11, "risk_score": 0.82, "risk_level": "high"}]}
        repeated = {
            "rank": 1,
            "assessment": "agree",
            "ai_risk_level": "high",
            "ai_confidence": 0.9,
        }
        result = build_ai_assisted_decisions(
            analysis,
            _advice(sample_reviews=[repeated, dict(repeated)]),
        )

        self.assertEqual(len(result["items"]), 1)
        self.assertEqual(result["summary"]["reviewed"], 1)


class ExternalAdvisorApiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import app as app_module
        cls.app_module = app_module
        cls.client = app_module.app.test_client()

    def setUp(self):
        with self.app_module._external_analysis_rate_lock:
            self.app_module._external_analysis_call_times.clear()
        if self.app_module._external_analysis_operation_lock.locked():
            self.app_module._external_analysis_operation_lock.release()

    def test_health_reports_the_primary_runtime_model(self):
        runtime_status = {
            "ready": True,
            "is_ready": True,
            "model_version": "runtime-unit",
            "classifier_type": "LogisticRegression",
            "components": {
                "isolation_forest": True,
                "classifier": True,
                "numpy_lstm": True,
            },
        }
        with patch(
            "src.detection.ensemble_detector.ensemble_detector.status",
            return_value=runtime_status,
        ):
            response = self.client.get("/api/system/health")

        self.assertEqual(response.status_code, 200)
        data = response.get_json()["data"]
        self.assertTrue(data["detector_trained"])
        self.assertTrue(data["real_detector_trained"])
        self.assertEqual(data["local_model"]["version"], "runtime-unit")
        self.assertIn("NumPy LSTM", data["modules"]["detection"])

    def test_user_endpoint_is_explicit_and_returns_local_primary_fusion(self):
        analysis = {
            "total": 1,
            "profile": {"rows": 1, "columns": 4},
            "risk_summary": {"high": 1},
            "privacy_risk": {"score": 0.2, "level": "low"},
            "attack_risk": {"score": 0.8, "level": "high"},
            "dual_risk": {"privacy_level": "low", "attack_level": "high"},
            "analysis_trace": {
                "analysis_id": "analysis-unit",
                "analyzed_rows": 1,
                "source_rows": 1,
                "source_rows_exact": True,
            },
            "risk_ranking": [{
                "rank": 1,
                "id": 9,
                "risk_score": 0.8,
                "risk_level": "high",
                "trigger_features": ["失败次数偏高"],
            }],
        }
        submission = {"id": "sub-unit", "analysis": analysis, "external_analysis": {}}
        captured = {}

        class FakeClient:
            def analyze(self, payload):
                captured["payload"] = payload
                return {"advice": _advice(sample_reviews=[{
                    "rank": 1,
                    "assessment": "agree",
                    "ai_risk_level": "high",
                    "ai_confidence": 0.9,
                    "ai_attack_type": "疑似暴力破解",
                    "reason": "信号一致。",
                    "recommended_action": "优先复核。",
                }]), "usage": {"total_tokens": 12}}

        with patch.object(self.app_module._external_ai_settings_store, "get_effective", return_value=_settings()), \
             patch.object(self.app_module, "_create_external_advisor_client", return_value=FakeClient()), \
             patch.object(self.app_module.user_submission_manager, "get_submission", return_value=submission), \
             patch.object(self.app_module.user_submission_manager, "save_external_analysis", return_value=submission):
            response = self.client.post("/api/user/datasets/sub-unit/external-analysis", json={})

        body = json.loads(response.data)
        self.assertEqual(response.status_code, 200, body)
        self.assertEqual(body["data"]["decision_policy"], "local_primary_ai_may_only_confirm_or_escalate")
        self.assertEqual(body["data"]["assisted_decisions"][0]["sample_id"], 9)
        self.assertFalse(captured["payload"]["evidence_boundaries"]["raw_rows_included"])

    def test_admin_settings_endpoint_is_protected_and_never_returns_key(self):
        with self.client.session_transaction() as session:
            session.clear()
        unauthorized = self.client.get("/api/admin/external-ai/settings")
        self.assertEqual(unauthorized.status_code, 401)

        settings = _settings()
        settings.update({"configured": True, "ready": True, "source": "admin_ui"})
        with self.client.session_transaction() as session:
            session["admin_logged_in"] = True
            session["admin_username"] = "unit-admin"
        with patch.object(self.app_module._external_ai_settings_store, "get_effective", return_value=settings):
            response = self.client.get("/api/admin/external-ai/settings")
        body = json.loads(response.data)
        self.assertEqual(response.status_code, 200, body)
        self.assertNotIn("api_key", body["data"])
        self.assertEqual(body["data"]["api_key_masked"], "****-key")

    def test_admin_training_comparison_uses_matching_aggregate_tasks(self):
        local = {
            "task_type": "local",
            "accuracy": 0.9,
            "samples": 50,
            "metadata": json.dumps({
                "dataset_source_id": "source-1",
                "dataset_revision": "revision-1",
                "preparation_id": "prep-1",
                "metric_scope": "train",
                "validation_available": False,
            }),
        }
        federated = {
            "task_type": "federated",
            "accuracy": 0.88,
            "samples": 50,
            "metadata": json.dumps({
                "dataset_source_id": "source-1",
                "dataset_revision": "revision-1",
                "preparation_id": "prep-1",
                "metric_scope": "node_validation_weighted",
                "validation_available": True,
                "clients": [{"samples": 50, "accuracy": 0.88, "loss": 0.2}],
            }),
        }
        captured = {}

        class FakeClient:
            def analyze(self, payload):
                captured["payload"] = payload
                return {"advice": _advice(
                    comparison_verdict="not_comparable",
                    metric_findings=["指标口径不同，不能直接排名。"],
                )}

        with self.client.session_transaction() as session:
            session["admin_logged_in"] = True
            session["admin_username"] = "unit-admin"
        with patch.object(self.app_module._external_ai_settings_store, "get_effective", return_value=_settings()), \
             patch.object(self.app_module, "_latest_training_pair", return_value=(local, federated)), \
             patch.object(self.app_module, "_create_external_advisor_client", return_value=FakeClient()), \
             patch.object(self.app_module, "_load_training_ai_comparison_cache", return_value={}), \
             patch.object(self.app_module.db, "set_config") as save_config:
            response = self.client.post("/api/admin/training/external-comparison", json={})

        body = json.loads(response.data)
        self.assertEqual(response.status_code, 200, body)
        self.assertEqual(body["data"]["advice"]["comparison_verdict"], "not_comparable")
        self.assertFalse(captured["payload"]["comparison_fairness"]["direct_accuracy_ranking_allowed"])
        save_config.assert_called_once()


if __name__ == "__main__":
    unittest.main()
