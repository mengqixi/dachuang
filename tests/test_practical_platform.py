import io
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
os.chdir(os.path.join(os.path.dirname(__file__), ".."))


class TestPracticalPlatformRoadmap(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from app import app
        cls.client = app.test_client()

    def test_frontend_uses_risk_ranking_without_legacy_detail_copy(self):
        with open("index.html", "r", encoding="utf-8") as f:
            html = f.read()

        self.assertIn("上传数据", html)
        self.assertIn("风险检测", html)
        self.assertIn("分析报告", html)
        self.assertIn("风险排名", html)
        self.assertIn("风险排名摘要", html)
        self.assertIn("隐私暴露风险", html)
        self.assertIn("analyzeSubmission", html)
        self.assertNotIn("Top 20", html)
        self.assertNotIn("风险详情模块", html)
        self.assertNotIn("展开详情按钮", html)

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


if __name__ == "__main__":
    unittest.main()
