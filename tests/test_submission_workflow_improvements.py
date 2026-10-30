import io
import unittest
from unittest.mock import patch
import tests.test_practical_platform as fixture_module


class SubmissionWorkflowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fixture=fixture_module.TestPracticalPlatformRoadmap
        cls.fixture.setUpClass()
        cls.a,cls.u=cls.fixture.app_module,cls.fixture.submission_module

    @classmethod
    def tearDownClass(cls):
        cls.fixture.tearDownClass()

    def upload(self,tag,n=20,approve=True,content=None):
        client=self.a.app.test_client()
        csv=content or 'username,ip,failed_attempts,request_frequency,label\n'+'\n'.join('%s%s,198.51.100.%s,%s,%s,%s'%(tag,i,i+1,i%7,20+i,i%2) for i in range(n))
        response=client.post('/api/user/datasets/upload',data={'file':(io.BytesIO(csv.encode()),tag+'.csv')},content_type='multipart/form-data').get_json()
        item=response['data']
        if approve:self.a.user_submission_manager.set_status(item['id'],review_status='可训练',trainable=True)
        return item

    def admin(self):
        return self.fixture()._admin_client()

    def test_selection_requires_admin_approval_and_preserves_upload_metadata(self):
        a,b=self.upload('select-one'),self.upload('select-two',22)
        ids=[a['id'],b['id']]
        self.assertEqual(self.a.app.test_client().post('/api/admin/datasets/selections',json={'submission_ids':ids}).status_code,401)
        created=self.admin().post('/api/admin/datasets/selections',json={'submission_ids':ids})
        self.assertEqual(created.status_code,200)
        selection=created.get_json()['data']
        self.assertEqual(set(selection['submission_ids']),set(ids))
        repeated=self.admin().post('/api/admin/datasets/selections',json={'submission_ids':ids[::-1]}).get_json()['data']
        self.assertEqual(selection['id'],repeated['id'])
        sources=self.a.user_submission_manager.list_dataset_sources()
        source=next(x for x in sources if x['submission_id']==a['id'])
        self.assertEqual(source['filename'],'select-one.csv');self.assertTrue(source['upload_time'])
        pending=self.upload('pending-selection',approve=False)
        refused=self.admin().post('/api/admin/datasets/selections',json={'submission_ids':[a['id'],pending['id']]})
        self.assertEqual(refused.status_code,400)

    def test_selected_loader_never_adds_unselected_or_revoked_submissions(self):
        a,b=self.upload('only-a'),self.upload('only-b',22)
        other=self.upload('not-selected',24)
        chosen=[a['id'],b['id']]
        spec=self.a.user_submission_manager.create_training_selection(chosen)
        user_sources=self.a.user_submission_manager.list_dataset_sources()
        source=self.a._build_user_submission_pool_source([x for x in user_sources if x['submission_id'] in chosen])
        source.update(id=spec['id'],selection=True)
        with patch.object(self.a,'_list_dataset_sources_cached',return_value=[source]),patch.object(self.a,'_preparation_matches',return_value=False):
            x,y,meta=self.a._load_training_dataset_source(spec['id'],limit=50)
            self.assertEqual(len(x),42)
            self.assertEqual({s['id'] for s in meta['sources']},set(chosen))
            self.assertNotIn(other['id'],[s['id'] for s in meta['sources']])
            self.a.user_submission_manager.set_status(b['id'],review_status='已拒绝',trainable=False)
            with self.assertRaises(self.u.SubmissionStatusError):
                self.a._load_training_dataset_source(spec['id'],limit=50)

    def test_identical_content_is_not_added_twice_and_every_source_gets_budget(self):
        content='username,failed_attempts,label\nshared,4,1\n'
        a,b=self.upload('duplicate-a',content=content),self.upload('duplicate-b',content=content)
        with self.assertRaises(self.u.SubmissionStatusError):
            self.a.user_submission_manager.create_training_selection([a['id'],b['id']])
        c,d=self.upload('budget-a',40),self.upload('budget-b',40)
        x,y,meta=self.a.user_submission_manager.load_trainable_features(ids=[c['id'],d['id']],limit=20,require_all=True)
        self.assertEqual(len(x),20);self.assertEqual([s['samples'] for s in meta['sources']],[10,10])
