"""Performance contracts: bounded reads, cache safety, no duplicate persistence."""
import gzip
import io
import json
import os
import tempfile
import unittest
from unittest.mock import patch

import numpy as np
import tests.test_practical_platform as fixture_module


class SubmissionReadCacheTests(unittest.TestCase):
    def setUp(self):
        import src.user_submission_manager as u
        self.u = u
        self.temp = tempfile.TemporaryDirectory()
        self.path = os.path.join(self.temp.name, "index.json")
        self.patches = [patch.object(u, "INDEX_FILE", self.path), patch.object(u, "_ensure_dirs", lambda: None)]
        for p in self.patches:
            p.start()
        self.addCleanup(self.temp.cleanup)
        for p in self.patches:
            self.addCleanup(p.stop)
        u._SUBMISSION_READ_CACHE.clear()
        self.data = {"submissions": [{"id": "a", "status": "pending", "analysis": {"detections": [{"id": 1}]}}]}
        u._write_index(self.data)

    def test_cache_reads_only_once_and_results_are_detached(self):
        with patch.object(self.u, "_read_index", wraps=self.u._read_index) as read:
            first = self.u._read_submission_record("a")
            first["analysis"]["detections"][0]["id"] = 999
            second = self.u._read_submission_record("a")
            self.assertEqual(second["analysis"]["detections"][0]["id"], 1)
            self.assertEqual(read.call_count, 1)

    def test_write_and_external_atomic_replacement_invalidate_cache(self):
        self.u._read_submission_record("a")
        self.data["submissions"][0]["status"] = "rejected"
        self.u._write_index(self.data)
        self.assertEqual(self.u._read_submission_record("a")["status"], "rejected")
        prior = os.stat(self.path)
        other = self.path + ".new"
        self.data["submissions"][0]["status"] = "approved"
        with open(other, "w", encoding="utf-8") as f:
            json.dump(self.data, f)
        os.utime(other, ns=(prior.st_atime_ns, prior.st_mtime_ns))
        os.replace(other, self.path)
        self.assertEqual(self.u._read_submission_record("a")["status"], "approved")

    def test_large_results_are_not_retained_and_compact_json_is_lossless(self):
        rows = [{"id": i, "score": .7} for i in range(1201)]
        self.data["submissions"][0]["analysis"]["detections"] = rows
        self.u._write_index(self.data)
        self.assertLess(os.path.getsize(self.path), len(json.dumps(self.data, indent=2).encode("utf-8")))
        with patch.object(self.u, "_read_index", wraps=self.u._read_index) as read:
            self.assertEqual(len(self.u._read_submission_record("a")["analysis"]["detections"]), 1201)
            self.u._read_submission_record("a")
            self.assertEqual(read.call_count, 2)


class DetectionEndpointPerformanceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fixture = fixture_module.TestPracticalPlatformRoadmap
        cls.fixture.setUpClass()
        cls.a = cls.fixture.app_module

    @classmethod
    def tearDownClass(cls):
        cls.fixture.tearDownClass()

    def test_cached_detection_skips_writes_and_gzip_keeps_exact_evidence(self):
        client = self.a.app.test_client()
        csv = "username,ip,failed_attempts,request_frequency,label\n" + "\n".join(
            "demo%s,198.51.100.%s,%s,%s,%s" % (i, i + 1, i % 10, 50 + i, i % 2) for i in range(50))
        uploaded = client.post("/api/user/datasets/upload", data={"file": (io.BytesIO(csv.encode()), "speed.csv")}, content_type="multipart/form-data").get_json()
        sid = uploaded["data"]["id"]

        class Detector:
            calls = 0
            def status(self): return {"version": "speed-test"}
            def is_ready(self): return True
            def predict(self, x):
                self.calls += 1
                return np.ones(len(x)), np.full(len(x), .6), np.full(len(x), 2)

        from src.detection import ensemble_detector as detector_module
        detector = Detector()
        url = "/api/user/datasets/%s/analyze" % sid
        with patch.object(self.a, "_ensure_runtime_ensemble_ready", return_value=True), patch.object(detector_module, "ensemble_detector", detector), \
                patch.object(self.a.db, "upsert_user_submission", wraps=self.a.db.upsert_user_submission) as upsert, \
                patch.object(self.a.db, "save_analysis_report_record", wraps=self.a.db.save_analysis_report_record) as save:
            first = client.post(url, json={"limit": 1000}).get_json()["data"]
            compressed = client.post(url, json={"limit": 1000}, headers={"Accept-Encoding": "gzip"})
            self.assertEqual(compressed.headers.get("Content-Encoding"), "gzip")
            second = json.loads(gzip.decompress(compressed.data).decode("utf-8"))["data"]
            self.assertEqual(first["total"], second["total"])
            self.assertEqual(first["risk_summary"], second["risk_summary"])
            self.assertEqual(first["detections"], second["detections"])
            self.assertEqual(first["analysis_trace"]["analysis_id"], second["analysis_trace"]["analysis_id"])
            self.assertTrue(second["analysis_trace"]["cache_reused"])
            self.assertLess(len(compressed.data), len(json.dumps(second).encode("utf-8")) / 3)
            refused = client.post(url, json={"limit": 1000}, headers={"Accept-Encoding": "gzip;q=0"})
            self.assertIsNone(refused.headers.get("Content-Encoding"))
            self.assertEqual(detector.calls, 1)
            self.assertEqual(upsert.call_count, 1)
            self.assertEqual(save.call_count, 1)
        outsider = self.a.app.test_client().post(url, json={})
        self.assertEqual(outsider.status_code, 403)
