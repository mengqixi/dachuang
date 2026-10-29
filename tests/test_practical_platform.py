import io
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import numpy as np

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
os.chdir(os.path.join(os.path.dirname(__file__), ".."))


class TestPracticalPlatformRoadmap(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import importlib
        import app as app_module
        from src.utils.data_storage import DataStorage

        submission_module = importlib.import_module("src.user_submission_manager")
        cls._temp_dir = tempfile.TemporaryDirectory()
        root = Path(cls._temp_dir.name)
        upload_dir = root / "uploads"
        upload_dir.mkdir(parents=True)
        user_root = root / "user_submissions"
        isolated_paths = {
            "DATA_ROOT": str(user_root),
            "TEMP_DIR": str(user_root / "plain_temp"),
            "ARCHIVE_DIR": str(user_root / "archive"),
            "REPORT_DIR": str(user_root / "reports"),
            "INDEX_FILE": str(user_root / "index.json"),
            "KEY_DIR": str(root / "keys"),
            "KEY_FILE": str(root / "keys" / "user_archive.key"),
        }
        cls._patchers = [
            patch.object(submission_module, name, value)
            for name, value in isolated_paths.items()
        ]
        cls._patchers.extend([
            patch.object(app_module, "db", DataStorage(str(root / "system.db"))),
            patch.dict(app_module.app.config, {"UPLOAD_FOLDER": str(upload_dir)}),
        ])
        for patcher in cls._patchers:
            patcher.start()
        cls.app_module = app_module
        cls.submission_module = submission_module
        cls.client = app_module.app.test_client()

    def _admin_client(self):
        client = self.app_module.app.test_client()
        with client.session_transaction() as session:
            session["admin_logged_in"] = True
            session["admin_username"] = "root"
        return client

    @classmethod
    def tearDownClass(cls):
        for patcher in reversed(cls._patchers):
            patcher.stop()
        cls._temp_dir.cleanup()

    def test_frontend_uses_risk_ranking_without_legacy_detail_copy(self):
        with open("index.html", "r", encoding="utf-8") as f:
            html = f.read()

        self.assertIn("上传数据", html)
        self.assertIn("风险检测", html)
        self.assertIn("分析报告", html)
        self.assertIn("需关注样本排名", html)
        self.assertIn("risk_ranking", html)
        self.assertNotIn("riskMoreButton", html)
        self.assertNotIn("riskRowsVisible", html)
        self.assertNotIn("showMoreRiskRows", html)
        self.assertIn("rows.map(riskRowHtml)", html)
        self.assertIn("dataProcessReadyTitle", html)
        self.assertIn("currentDatasetSourceId\n      ? currentDatasetSource.prepared_for_federated", html)
        self.assertIn(
            "updateDataProcessReadyState(currentNodeBundleReady,currentRuntimeMatchesPreparation)",
            html,
        )
        self.assertIn("指标可比 · 质量告警", html)
        self.assertIn("隐私暴露风险", html)
        self.assertIn("analyzeSubmission", html)
        self.assertNotIn("Top 20", html)
        self.assertNotIn("风险详情模块", html)
        self.assertNotIn("展开详情按钮", html)

    def test_training_approval_is_one_step_and_rejection_keeps_archive(self):
        upload = self.client.post('/api/user/datasets/upload',
            data={'file':(io.BytesIO(b'username,failed_attempts,label\nalice,3,1\n'),'approval.csv')},
            content_type='multipart/form-data').get_json()
        self.assertEqual(upload['code'],200,upload)
        pending=upload['data'];sid=pending['id']
        self.assertTrue(pending['encrypted'])
        self.assertFalse(pending['trainable'])
        self.assertEqual(pending['allowed_actions'],['mark_trainable','reject'])
        stored=lambda: next(x for x in self.submission_module._read_index()['submissions'] if x['id']==sid)
        original=stored()
        self.assertEqual(self.app_module.app.test_client().post(f'/api/admin/submissions/{sid}/mark-trainable').status_code,401)
        admin=self._admin_client()
        approved=admin.post(f'/api/admin/submissions/{sid}/mark-trainable').get_json()
        self.assertEqual(approved['code'],200,approved)
        self.assertTrue(approved['data']['trainable'])
        self.assertEqual(approved['data']['allowed_actions'],['reject'])
        self.assertEqual(approved['data']['training_runs'],0)
        self.assertEqual(len(stored()['review_history']),1)
        rejected=admin.post(f'/api/admin/submissions/{sid}/reject',json={}).get_json()
        self.assertEqual(rejected['code'],200,rejected)
        self.assertFalse(rejected['data']['trainable'])
        self.assertTrue(rejected['data']['encrypted'])
        self.assertEqual(rejected['data']['allowed_actions'],['mark_trainable'])
        after=stored()
        self.assertEqual(after['encrypted_path'],original['encrypted_path'])
        self.assertTrue(Path(after['encrypted_path']).is_file())
        restored=admin.post(f'/api/admin/submissions/{sid}/mark-trainable').get_json()
        self.assertTrue(restored['data']['trainable'])

    def test_legacy_archive_needs_only_training_approval(self):
        summary=self.app_module.user_submission_manager.public_summary({
            'id':'legacy','review_status':'已归档','trainable':False,'row_count':1})
        self.assertEqual(summary['allowed_actions'],['mark_trainable','reject'])
        with open('index.html',encoding='utf-8') as stream:
            html=stream.read()
        self.assertNotIn('archiveSubmission(',html)
        self.assertIn('>允许训练</button>',html)

    def test_score_explanation_uses_original_model_signal_for_both_fusion_paths(self):
        module = self.submission_module
        for row, model_score, expected in [
            ({}, 0.9, 0.765),
            ({"failed_attempts":20,"request_frequency":200,"response_time":3,"unusual_hour":1}, 0.2, 0.66),
            ({"failed_attempts":200,"request_frequency":2000,"response_time_ms":30000}, 0.0, 0.53),
        ]:
            with self.subTest(row=row):
                final = module._fusion_score(row, {"risk_score":model_score})
                self.assertEqual(final, expected)
                b = module._risk_breakdown(row, {"risk_score":final,"raw_model_score":model_score})
                self.assertEqual(b["model_score"], model_score)
                self.assertEqual(b["final_score"], expected)
                self.assertEqual(module._clip_score(max(b["weighted_score"], b["model_floor"])), expected)

    def test_user_analysis_returns_unified_risk_schema_and_sorted_ranking(self):
        rows = [
            "username,ip,device_type,browser,os,login_success,failed_attempts,request_frequency,response_time,session_duration,unusual_hour,password_strength,label",
            "alice,192.168.1.10,desktop,Chrome,Windows,1,0,5,0.20,300,0,5,0",
            "bob,8.8.8.8,desktop,Edge,Windows,0,8,140,1.60,30,1,1,1",
            "carl,203.0.113.8,mobile,Safari,iOS,0,5,90,1.10,45,1,2,1",
        ]
        payload = "\n".join(rows).encode("utf-8")
        upload = self.client.post(
            "/api/user/datasets/upload",
            data={"file": (io.BytesIO(payload), "roadmap_login_security.csv")},
            content_type="multipart/form-data",
        )
        upload_data = json.loads(upload.data)
        self.assertEqual(upload_data["code"], 200, upload_data)
        submission_id = upload_data["data"]["id"]
        stored_submission = next(
            item for item in self.submission_module._read_index()["submissions"]
            if item.get("id") == submission_id
        )
        self.assertIn(self._temp_dir.name, stored_submission["encrypted_path"])

        analyze = self.client.post(
            f"/api/user/datasets/{submission_id}/analyze",
            json={"limit": 2},
        )
        analyze_data = json.loads(analyze.data)
        self.assertEqual(analyze_data["code"], 200, analyze_data)
        data = analyze_data["data"]

        self.assertEqual(data["risk_ranking_order"], "risk_score_desc")
        self.assertLessEqual(len(data["risk_ranking"]), 100)
        scores = [float(item["risk_score"]) for item in data["risk_ranking"]]
        self.assertEqual(scores, sorted(scores, reverse=True))

        required = {
            "is_risk",
            "risk_score",
            "risk_level",
            "attack_type",
            "confidence",
            "action_suggestion",
            "detection_time_ms",
            "trigger_features",
            "score_breakdown",
            "reason",
            "suggestion",
            "source_dataset",
            "model_version",
        }
        self.assertTrue(data["detections"], "analysis should include detections")
        for detection in data["detections"]:
            self.assertTrue(required.issubset(detection.keys()), detection)
            self.assertIsInstance(detection["score_breakdown"], dict)
            parts = detection["score_breakdown"]
            self.assertEqual(parts["calculation_version"], "fusion-score-explanation-v1")
            self.assertEqual(parts["model_score"], self.submission_module._clip_score(detection["raw_model_score"]))
            expected = self.submission_module._clip_score(max(parts["weighted_score"], parts["model_floor"]))
            self.assertEqual(expected, detection["risk_score"])

        self.assertIn("risk_score_distribution", data)
        self.assertIn("trigger_feature_stats", data)
        self.assertIn("detection_pipeline", data)
        self.assertIn("privacy_risk", data)
        self.assertIn("attack_risk", data)
        self.assertIn("dual_risk", data)
        self.assertIn("analysis_trace", data)
        self.assertEqual(data["analysis_trace"]["api_version"], "v1")
        self.assertFalse(data["analysis_trace"]["cache_reused"])
        self.assertEqual(data["analysis_trace"]["source_rows"], 3)
        self.assertTrue(data["analysis_trace"]["source_rows_exact"])
        self.assertEqual(data["analysis_trace"]["analyzed_rows"], 2)
        self.assertEqual(data["analysis_trace"]["scope"], "first_limit_rows")
        self.assertEqual(data["privacy_risk"]["external_api_payload_policy"], "redacted_aggregates_only")

        cached = self.client.post(
            f"/api/user/datasets/{submission_id}/analyze",
            json={"limit": 2},
        )
        cached_data = json.loads(cached.data)
        self.assertEqual(cached_data["code"], 200, cached_data)
        self.assertTrue(cached_data["data"]["analysis_trace"]["cache_reused"])

        with self.client.session_transaction() as sess:
            sess.pop("admin_logged_in", None)
            sess.pop("admin_username", None)
        unauthorized = self.client.post(
            f"/api/admin/submissions/{submission_id}/analyze",
            json={"limit": 100},
        )
        self.assertEqual(unauthorized.status_code, 401)

        with self.client.session_transaction() as sess:
            sess["admin_logged_in"] = True
            sess["admin_username"] = "test-admin"
        admin_analysis = self.client.post(
            f"/api/admin/submissions/{submission_id}/analyze",
            json={"limit": 100},
        )
        admin_data = json.loads(admin_analysis.data)
        self.assertEqual(admin_data["code"], 200, admin_data)
        self.assertIn("privacy_risk", admin_data["data"])
        self.assertEqual(admin_data["data"]["analysis_trace"]["scope"], "all_rows")

        detail = self.client.get(f"/api/admin/submissions/{submission_id}")
        detail_data = json.loads(detail.data)
        self.assertEqual(detail_data["code"], 200, detail_data)
        self.assertEqual(detail_data["data"]["row_count"], 3)
        self.assertTrue(detail_data["data"]["row_count_exact"])
        self.assertEqual(detail_data["data"]["analysis"]["analysis_trace"]["source_rows"], 3)

        report = self.client.get(f"/api/user/reports/{submission_id}")
        report_data = json.loads(report.data)
        self.assertEqual(report_data["code"], 200, report_data)
        self.assertIn("隐私暴露", report_data["data"]["report_markdown"])

    def test_private_submission_is_bound_to_uploading_browser_session(self):
        owner = self.app_module.app.test_client()
        outsider = self.app_module.app.test_client()
        payload = b"username,failed_attempts,label\nalice,0,0\n"
        upload = owner.post(
            "/api/user/datasets/upload",
            data={"file": (io.BytesIO(payload), "nested\\private.csv")},
            content_type="multipart/form-data",
        )
        upload_data = upload.get_json()
        self.assertEqual(upload.status_code, 200, upload_data)
        submission_id = upload_data["data"]["id"]

        # The owner reaches the resource lookup; a different browser session
        # is rejected before the existence or state of that record is exposed.
        self.assertEqual(owner.get(f"/api/user/reports/{submission_id}").status_code, 200)
        self.assertEqual(
            outsider.post(f"/api/user/datasets/{submission_id}/analyze", json={}).status_code,
            403,
        )
        self.assertEqual(
            outsider.post(f"/api/user/datasets/{submission_id}/external-analysis", json={}).status_code,
            403,
        )
        self.assertEqual(outsider.get(f"/api/user/reports/{submission_id}").status_code, 403)

    def test_privacy_cipher_preview_is_full_but_strictly_bounded(self):
        class FakePaillier:
            def encrypt(self, value):
                return int("9" * 96) + int(value)

        with patch.object(self.app_module, "get_paillier", return_value=FakePaillier()):
            response = self.app_module.app.test_client().post(
                "/api/generate_privacy_dataset",
                json={"n_records": 5000},
            )
        body = response.get_json()
        self.assertEqual(response.status_code, 200, body)
        data = body["data"]
        self.assertEqual(data["requested_records"], 5000)
        self.assertEqual(data["n_records"], self.app_module.PRIVACY_PREVIEW_MAX_ROWS)
        self.assertTrue(data["preview_only"])
        self.assertLessEqual(len(data["encrypted"]), self.app_module.PRIVACY_PREVIEW_MAX_ROWS)
        self.assertGreater(len(data["encrypted"][0]["phone_encrypted"]), 40)

        invalid_body = self.app_module.app.test_client().post(
            "/api/generate_privacy_dataset",
            json=[{"n_records": 20}],
        )
        self.assertEqual(invalid_body.status_code, 400)

    def test_dataset_detection_rejects_invalid_pagination_without_500(self):
        with patch.object(self.app_module, "_processed_dataset_ready", return_value=True):
            invalid = self._admin_client().post(
                "/api/ensemble/detect_from_dataset",
                json={"limit": "many", "offset": -1, "seed": -3},
            )
        self.assertEqual(invalid.status_code, 400, invalid.get_json())

    def test_dataset_detection_requires_model_from_current_preparation(self):
        fake_x = np.zeros((2, 18), dtype=np.float64)
        fake_y = np.array([0, 1], dtype=np.int32)
        fake_meta = {"preparation_id": "prep-current", "source": "test.csv"}

        with (
            patch.object(self.app_module, "_processed_dataset_ready", return_value=True),
            patch.object(self.app_module, "_load_prepared_arrays", return_value=(fake_x, fake_y, fake_meta)),
            patch.object(self.app_module, "_ensure_runtime_ensemble_ready", return_value=True),
            patch(
                "src.detection.ensemble_detector.ensemble_detector.status",
                return_value={
                    "ready": True,
                    "version": "model-old",
                    "training_context": {"preparation_id": "prep-old"},
                },
            ),
        ):
            response = self._admin_client().post(
                "/api/ensemble/detect_from_dataset",
                json={"limit": 2, "offset": 0},
            )

        self.assertEqual(response.status_code, 409, response.get_json())
        self.assertEqual(response.get_json()["data"]["preparation_id"], "prep-current")

    def test_legacy_write_and_heavy_routes_require_admin_session(self):
        guest = self.app_module.app.test_client()
        for path in (
            "/upload",
            "/api/generate_dataset",
            "/api/save_sample",
            "/api/compare_encryption",
            "/api/detection/analyze",
            "/api/detection/real",
            "/api/ensemble/detect",
            "/api/ensemble/detect_from_dataset",
        ):
            with self.subTest(path=path):
                response = guest.post(path, json={})
                self.assertEqual(response.status_code, 401, response.get_json())


if __name__ == "__main__":
    unittest.main()
