import io
import unittest
from unittest.mock import patch

import numpy as np
import tests.test_practical_platform as fixture_module
from tests.test_external_advisor import _advice, _settings


class SubmissionAiPreservationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fixture = fixture_module.TestPracticalPlatformRoadmap
        cls.fixture.setUpClass()
        cls.a, cls.u = cls.fixture.app_module, cls.fixture.submission_module

    @classmethod
    def tearDownClass(cls):
        cls.fixture.tearDownClass()

    def setUp(self):
        self.client = self.a.app.test_client()
        with self.a._external_analysis_rate_lock:
            self.a._external_analysis_call_times.clear()
        csv = "ip,failed_attempts,request_frequency,label\n" + "\n".join(
            "198.51.100.%s,8,140,%s" % (i+1, i % 2) for i in range(30))
        response = self.client.post('/api/user/datasets/upload', data={
            'file': (io.BytesIO(csv.encode()), 'preserve.csv')}, content_type='multipart/form-data')
        self.sid = response.get_json()['data']['id']
        class Detector:
            version = 'preserve-model'
            calls = 0
            def status(self): return {'version': self.version}
            def is_ready(self): return True
            def predict(self, X):
                self.calls += 1
                return np.ones(len(X)), np.full(len(X), .8), np.full(len(X), 2)
        self.detector = Detector()
        self.first = self.a.user_submission_manager.analyze(self.sid, detector=self.detector, limit=1000)
        self.provider_calls = []
        calls = self.provider_calls
        class Provider:
            def analyze(self, payload):
                calls.append(payload)
                return {'advice': _advice(summary='已经保存的 AI 结论')}
        with patch.object(self.a._external_ai_settings_store, 'get_effective', return_value=_settings()), \
             patch.object(self.a, '_create_external_advisor_client', return_value=Provider()):
            result = self.client.post('/api/user/datasets/%s/external-analysis' % self.sid, json={})
        self.assertEqual(result.status_code, 200, result.get_json())
        self.saved = result.get_json()['data']

    def test_admin_smaller_ceiling_reuses_user_full_scope_and_ai(self):
        from src.detection import ensemble_detector as detector_module
        admin = self.fixture()._admin_client()
        with patch.object(self.a, '_ensure_runtime_ensemble_ready', return_value=True), \
             patch.object(detector_module, 'ensemble_detector', self.detector), \
             patch.object(self.a, '_create_external_advisor_client') as provider:
            response = admin.post('/api/admin/submissions/%s/analyze' % self.sid, json={'limit': 500})
            self.assertEqual(response.status_code, 200)
            self.assertTrue(response.get_json()['data']['analysis_trace']['cache_reused'])
            detail = admin.get('/api/admin/submissions/%s' % self.sid).get_json()['data']
            self.assertEqual(detail['external_analysis']['advice'], self.saved['advice'])
            self.assertEqual(detail['analysis']['analysis_trace']['analysis_id'], self.first['analysis_trace']['analysis_id'])
            provider.assert_not_called()
        self.assertEqual(self.detector.calls, 1)
        self.assertEqual(len(self.provider_calls), 1)

    def test_force_identical_evidence_retains_ai_but_changed_model_is_history_only(self):
        second = self.a.user_submission_manager.analyze(self.sid, detector=self.detector, limit=500, force=True)
        self.assertNotEqual(second['analysis_trace']['analysis_id'], self.first['analysis_trace']['analysis_id'])
        current = self.a.user_submission_manager.get_submission(self.sid)
        self.assertEqual(current['external_analysis']['advice'], self.saved['advice'])
        self.assertEqual(current['external_analysis']['analysis_id'], second['analysis_trace']['analysis_id'])
        self.detector.version = 'new-model'
        self.a.user_submission_manager.analyze(self.sid, detector=self.detector, limit=500)
        current = self.a.user_submission_manager.get_submission(self.sid)
        self.assertEqual(current['external_analysis'], {})
        self.assertGreater(current['ai_history_count'], 0)
        raw = self.u._read_submission_record(self.sid)
        self.assertTrue(raw['external_analysis'])
        history = self.a.user_submission_manager.get_external_analysis_history(self.sid)
        self.assertEqual(history['records'][0]['result']['advice'], self.saved['advice'])
        url = '/api/admin/submissions/%s/ai-history' % self.sid
        self.assertEqual(self.a.app.test_client().get(url).status_code, 401)
        self.assertEqual(self.fixture()._admin_client().get(url).get_json()['data']['total'], 1)

    def test_larger_actual_scope_does_not_reuse_ai_for_other_rows(self):
        # The current 30-row upload is reused only when the actual row set matches.
        result = self.a.user_submission_manager.analyze(self.sid, detector=self.detector, limit=10)
        self.assertEqual(result['total'], 10)
        self.assertEqual(self.a.user_submission_manager.get_submission(self.sid)['external_analysis'], {})
        self.assertEqual(self.a.user_submission_manager.get_external_analysis_history(self.sid)['total'], 1)

    def test_legacy_requested_limit_key_is_migrated_without_losing_ai(self):
        item = self.u._read_submission_record(self.sid)
        item['analysis']['analysis_trace']['cache_key'] = self.u._analysis_cache_key(item, 1000, self.detector.version, normalize_scope=False)
        self.u._update_submission(self.sid, {'analysis': item['analysis']})
        result = self.a.user_submission_manager.analyze(self.sid, detector=self.detector, limit=500)
        self.assertTrue(result['analysis_trace']['cache_reused'])
        self.assertEqual(self.detector.calls, 1)
        self.assertTrue(self.a.user_submission_manager.get_submission(self.sid)['external_analysis'])

    def test_source_label_statistics_are_ground_truth_not_model_predictions(self):
        source = next(s for s in self.a.user_submission_manager.list_dataset_sources()
                      if s['submission_id'] == self.sid)
        self.assertEqual(source['label_distribution'], {'0': 15, '1': 15})
        self.assertEqual(source['scanned_rows'], 30)
        self.assertEqual(source['label_statistics_status'], 'complete')
        self.assertEqual(self.first['risk_summary']['high'], 30)
        pool = self.a._build_user_submission_pool_source([
            dict(source, trainable=True),
            dict(source, id='pending', trainable=True, label_distribution={}, scanned_rows=0,
                 label_statistics_status='pending')])
        self.assertEqual(pool['samples'], 60)
        self.assertEqual(pool['scanned_rows'], 30)
        self.assertEqual(pool['label_distribution'], {'0': 15, '1': 15})
        self.assertEqual(pool['label_statistics_status'], 'partial')

    def test_legacy_label_backfill_keeps_analysis_id_and_ai(self):
        self.u._update_submission(self.sid, {'label_statistics': {}})
        result = self.a.user_submission_manager.analyze(self.sid, detector=self.detector, limit=500)
        self.assertTrue(result['label_statistics_updated'])
        self.assertEqual(self.detector.calls, 1)
        self.assertEqual(result['analysis_trace']['analysis_id'], self.first['analysis_trace']['analysis_id'])
        self.assertEqual(self.a.user_submission_manager.get_submission(self.sid)['external_analysis']['advice'], self.saved['advice'])
        self.assertEqual(self.u._read_submission_record(self.sid)['label_statistics']['distribution'], {'0': 15, '1': 15})

    def test_missing_and_non_numeric_labels(self):
        stats = self.u._label_statistics([
            {'\ufeff Label ': 'BENIGN'}, {'\ufeff Label ': 'Brute Force'},
            {'\ufeff Label ': ''}, {'\ufeff Label ': None}], ['\ufeff Label '])
        self.assertEqual(stats['distribution'], {'0': 1, '1': 1})
        self.assertEqual(stats['unlabeled_rows'], 2)
        unlabeled = self.u._label_statistics([{'risk_score': .99}], ['risk_score'])
        self.assertEqual(unlabeled['distribution'], {})
        self.assertEqual(unlabeled['status'], 'unlabeled')
