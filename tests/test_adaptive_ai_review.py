import io
import json
import unittest
from unittest.mock import patch

import numpy as np

import tests.test_practical_platform as fixture_module
from tests.test_external_advisor import _settings, _advice
from src.analysis.external_advisor import plan_adaptive_review, ExternalAdvisorProviderError


class AdaptivePolicyTests(unittest.TestCase):
    def test_legacy_paid_results_are_reused_only_for_matching_provider_and_evidence(self):
        from src.analysis.external_advisor import canonical_fingerprint, build_redacted_analysis_payload, reusable_review_record
        settings=_settings()
        analysis={'total':1,'risk_ranking':[{'id':1,'risk_score':.7,'risk_level':'high'}]}
        old_prompt='privacy-advisor-zh-v5-complete-json'
        fingerprint=canonical_fingerprint({'base_url':settings['base_url'],'model':settings['model'],
                                           'mode':settings['mode'],'prompt_version':old_prompt})
        record={'prompt_version':old_prompt,'settings_fingerprint':fingerprint,'model':settings['model'],'mode':settings['mode'],
                'input_fingerprint':canonical_fingerprint({'payload':build_redacted_analysis_payload(analysis),'settings_fingerprint':fingerprint})}
        self.assertTrue(reusable_review_record(analysis,record,settings))
        self.assertFalse(reusable_review_record(analysis,record,dict(settings,base_url='https://other.example/v1')))

    def test_local_explanations_describe_observations_and_actions_match_signals(self):
        from src.user_submission_manager import _clean_reason_for_detection, _clean_suggestion_for_detection
        det={'risk_level':'high','risk_score':.75}
        brute={'failed_attempts':8,'request_frequency':142,'unusual_hour':1}
        reason=_clean_reason_for_detection(det,brute)
        self.assertIn('8次',reason)
        self.assertIn('142',reason)
        self.assertNotIn('阈值',reason)
        self.assertNotIn('高区间',reason)
        slow={'response_time_ms':1800}
        self.assertIn('1.8s',_clean_reason_for_detection(det,slow))
        self.assertIn('拥堵',_clean_suggestion_for_detection(det,slow))
        self.assertNotEqual(_clean_suggestion_for_detection(det,brute),_clean_suggestion_for_detection(det,slow))

    def test_scope_prefers_all_then_medium_high_then_high(self):
        def analysis(high, medium, low):
            levels = ['high']*high + ['medium']*medium + ['low']*low
            rows = [{'id':i+1, 'risk_level':level, 'risk_score':.7 if level=='high' else .4}
                    for i,level in enumerate(levels)]
            return {'total':len(rows),'detections':rows,'risk_ranking':rows[:high+medium]}
        for counts, expected, size in [((5,3,2),'all_samples',10), ((5,10,85),'medium_high',15),
                                       ((19,50,150),'high',19), ((0,0,100),'overview',0)]:
            with self.subTest(counts=counts):
                result = plan_adaptive_review(analysis(*counts),4096)
                self.assertEqual(result['scope'],expected)
                self.assertEqual(len(result['rows']),size)


class AdaptiveEndpointTests(unittest.TestCase):
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

    def prepare(self, count):
        csv = 'username,ip,failed_attempts,request_frequency,label\n' + '\n'.join(
            'demo%d,198.51.100.%d,9,120,%d' % (i,i+1,i%2) for i in range(count))
        uploaded = self.client.post('/api/user/datasets/upload', data={'file':(io.BytesIO(csv.encode()),'adaptive.csv')},content_type='multipart/form-data').get_json()
        sid = uploaded['data']['id']
        class Detector:
            def status(self): return {'version':'adaptive-unit'}
            def is_ready(self): return True
            def predict(self,X): return np.ones(len(X)),np.full(len(X),.9),np.full(len(X),2)
        self.a.user_submission_manager.analyze(sid,detector=Detector(),limit=500)
        return sid

    def provider(self, fail_second=False, omit_first=0):
        class Provider:
            def __init__(self): self.calls=[]
            def analyze(self,payload):
                self.calls.append(payload)
                if fail_second and len(self.calls)==2:
                    raise ExternalAdvisorProviderError('unit outage',status_code=500)
                candidates=payload['review_candidates']
                if len(self.calls)==1 and omit_first: candidates=candidates[:-omit_first]
                reviews=[{'rank':r['rank'],'assessment':'agree','ai_risk_level':r['local_risk_level'],
                          'ai_confidence':.8,'reason':'失败与频率信号叠加','recommended_action':'核对来源是否为授权任务'}
                         for r in candidates]
                return {'advice':_advice(sample_reviews=reviews),'usage':{'total_tokens':10}}
        return Provider()

    def invoke(self,sid):
        return self.client.post('/api/user/datasets/'+sid+'/external-analysis',json={'adaptive_review':True})

    def run_with(self,provider):
        settings=_settings();settings['max_output_tokens']=4096
        return (
            patch.object(self.a._external_ai_settings_store,'get_effective',return_value=settings),
            patch.object(self.a,'_create_external_advisor_client',return_value=provider))

    def test_single_request_reviews_more_than_twelve_without_sending_ips(self):
        sid=self.prepare(20);provider=self.provider();settings,client=self.run_with(provider)
        with settings,client:
            response=self.invoke(sid)
        self.assertEqual(response.status_code,200,response.get_json())
        result=response.get_json()['data']
        self.assertEqual(result['review_scope']['scope'],'all_samples')
        self.assertEqual(result['review_scope']['reviewed'],20)
        self.assertTrue(result['review_scope']['complete'])
        self.assertEqual(len(provider.calls),1)
        self.assertNotIn('198.51.100.',json.dumps(provider.calls))
        self.assertNotIn('demo',json.dumps(provider.calls))
        self.assertTrue(all(d['ip'] for d in result['assisted_decisions']))
        report=self.a.user_submission_manager.get_report(sid)
        self.assertIn('198.51.100.',report['report_markdown'])
        self.assertIn('AI 建议',report['report_markdown'])

    def test_failure_preserves_partial_and_resume_does_not_repeat_paid_work(self):
        sid=self.prepare(26);provider=self.provider(fail_second=True);settings,client=self.run_with(provider)
        with settings,client:
            first=self.invoke(sid).get_json()['data']
            self.assertFalse(first['review_scope']['complete'])
            self.assertEqual(self.invoke(sid).status_code,502)
        saved=self.a.user_submission_manager.get_report(sid)['external_analysis']
        self.assertEqual(saved['review_scope']['reviewed'],first['review_scope']['reviewed'])
        resumed=self.provider();settings,client=self.run_with(resumed)
        with settings,client:
            last=self.invoke(sid).get_json()['data']
            cached=self.invoke(sid).get_json()['data']
        self.assertEqual(last['review_scope']['reviewed'],26)
        self.assertTrue(last['review_scope']['complete'])
        self.assertTrue(cached['cache_reused'])
        self.assertEqual(len(resumed.calls),1)
        self.assertEqual(len(resumed.calls[0]['review_candidates']),26-first['review_scope']['reviewed'])
        self.assertEqual({d['sample_id'] for d in last['assisted_decisions']},set(range(1,27)))

    def test_missing_rows_are_saved_as_partial_not_falsely_marked_complete(self):
        sid=self.prepare(20);provider=self.provider(omit_first=3);settings,client=self.run_with(provider)
        with settings,client:
            partial=self.invoke(sid).get_json()['data']
            complete=self.invoke(sid).get_json()['data']
        self.assertEqual(partial['review_scope']['reviewed'],17)
        self.assertFalse(partial['review_scope']['complete'])
        self.assertEqual(len(provider.calls[1]['review_candidates']),3)
        self.assertTrue(complete['review_scope']['complete'])

    def test_cache_only_never_calls_provider(self):
        sid=self.prepare(20);provider=self.provider();settings,client=self.run_with(provider)
        with settings,client:
            response=self.client.post('/api/user/datasets/'+sid+'/external-analysis',json={'adaptive_review':True,'cache_only':True})
        self.assertEqual(response.status_code,200)
        self.assertFalse(response.get_json()['data']['review_scope']['complete'])
        self.assertEqual(provider.calls,[])


if __name__=='__main__': unittest.main()
