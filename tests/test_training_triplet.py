"""Three real training paths on isolated arrays/SQLite; no provider or cloud calls."""
import copy
import json
import os
from unittest.mock import Mock

import numpy as np
import pytest

import app as a
from src.encryption.paillier import Paillier
from src.federated.aggregator import FedAvgServer
from src.utils.data_storage import DataStorage


@pytest.fixture
def triplet(tmp_path, monkeypatch):
    import src.federated.aggregator as aggregator
    import src.preprocess.federated_splitter as splitter
    rng = np.random.default_rng(62)
    X = rng.random((200, 18))
    y = (X[:, 0] + .5 * X[:, 1] > .75).astype(np.int32)
    train_x, train_y, val_x, val_y = X[:160], y[:160], X[160:], y[160:]
    nodes = []
    for name, indices in zip(splitter.NODE_NAMES, np.array_split(np.arange(160), 4)):
        folder = tmp_path / name
        folder.mkdir()
        np.save(str(folder / 'X.npy'), train_x[indices])
        np.save(str(folder / 'y.npy'), train_y[indices])
        nodes.append({'name': name, 'samples': len(indices), 'ready': True})
    meta = dict(dataset_source_id='qa-source', dataset_revision='qa-data', preparation_id='qa-prep',
                validation_id='qa-val', uses_prepared_data=True, uses_shared_validation=True,
                validation_available=True, validation_label_distribution={'0': int(sum(val_y == 0)), '1': int(sum(val_y == 1))},
                validation_split_version=a.SHARED_VALIDATION_SPLIT_VERSION,
                preprocessing_version=a.FEATURE_NORMALIZATION_VERSION,
                federated_split_version=a.FEDERATED_SPLIT_VERSION, prepared_bundle_version=a.PREPARED_BUNDLE_VERSION,
                nodes=nodes, source_samples=200, prepared_samples=160, sources=[])
    key = Paillier(key_size=int(os.environ.get('DACHUANG_TEST_PAILLIER_BITS', '128')))
    key.generate_keys()  # small test key by default; production path is unchanged (>=2048).
    monkeypatch.setitem(a.app.config, 'TESTING', True)
    monkeypatch.setattr(a, 'db', DataStorage(str(tmp_path / 'qa.db')))
    monkeypatch.setattr(a, '_load_processed_metadata', lambda: copy.deepcopy(meta))
    monkeypatch.setattr(a, '_load_training_dataset_source', lambda *args, **kwargs: (train_x, train_y, copy.deepcopy(meta)))
    monkeypatch.setattr(a, '_load_prepared_validation_arrays', lambda: (val_x, val_y, copy.deepcopy(meta)))
    monkeypatch.setattr(a, '_federated_files_ready', lambda: True)
    monkeypatch.setattr(a, 'get_secure_aggregation_paillier', lambda: key)
    monkeypatch.setattr(a, 'save_training_record', lambda record: None)
    monkeypatch.setattr(a, 'get_training_records', lambda **kwargs: [])
    monkeypatch.setattr(a.user_submission_manager, 'mark_used_for_training', lambda *args, **kwargs: [])
    monkeypatch.setattr(splitter, 'FEDERATED_DIR', str(tmp_path))
    monkeypatch.setattr(aggregator, 'fedavg_server', FedAvgServer())
    client = a.app.test_client()
    with client.session_transaction() as session:
        session['admin_logged_in'] = True
    return client, meta


def run_triplet(client):
    return client.post('/api/admin/training/comparison', json={
        'dataset_source_id': 'qa-source', 'expected_preparation_id': 'qa-prep', 'epochs': 3})


def test_runtime_refuses_changed_preparation_before_fitting(triplet, monkeypatch):
    from src.detection.ensemble_detector import ensemble_detector
    client, _ = triplet
    fit = Mock(side_effect=AssertionError('must not train changed data'))
    monkeypatch.setattr(ensemble_detector, 'fit', fit)
    response = client.post('/api/admin/training/local', json={
        'dataset_source_id': 'qa-source', 'expected_preparation_id': 'old-prep'})
    assert response.status_code == 409, response.get_json()
    fit.assert_not_called()
    assert not a.db.get_training_tasks()


def test_inventory_reports_real_classifier_and_distinguishes_serving_role(monkeypatch):
    from src.detection.ensemble_detector import ensemble_detector
    monkeypatch.setattr(ensemble_detector, 'status', lambda: {
        'ready': True, 'version': 'active', 'classifier_type': 'logistic_regression',
        'components': {'isolation_forest': True, 'classifier': True, 'numpy_lstm': False}})
    inventory = a._model_inventory()
    runtime = inventory['runtime_detector']
    assert runtime['name'] == 'IF + 逻辑回归 融合检测模型'
    assert runtime['serving_impact'] == 'active_user_detector'
    for key in ('centralized_comparison', 'federated_training', 'paillier'):
        assert inventory[key]['serving_impact'] == 'comparison_only'


def test_three_paths_are_independently_saved_and_use_identical_scope(triplet):
    client, _ = triplet
    response = run_triplet(client)
    assert response.status_code == 200, response.get_json()
    data = response.get_json()['data']
    rows = data['results']
    assert set(rows) == {'centralized', 'federated', 'secure'}
    assert len(a.db.get_training_tasks()) == 3
    assert len({r['model_version'] for r in rows.values()}) == 3
    for row in rows.values():
        assert row['comparison_run_id'] == data['comparison_run_id']
        assert row['preparation_id'] == 'qa-prep'
        assert row['validation_id'] == 'qa-val'
        assert row['samples'] == 160
        assert row['validation_samples'] == 40
        assert row['effective_epochs'] == 3
        assert row['performance']['training_time_ms'] > 0
        matrix = row['confusion_matrix']
        assert set(matrix) == {'tp', 'tn', 'fp', 'fn'}
        assert sum(matrix.values()) == row['validation_samples']
        assert matrix['tn'] + matrix['fp'] == row['validation_label_distribution']['0']
        assert matrix['tp'] + matrix['fn'] == row['validation_label_distribution']['1']
        assert round((matrix['tp'] + matrix['tn']) / 40, 4) == row['accuracy']
    for saved in a.db.get_training_tasks():
        metadata = json.loads(saved['metadata'])
        assert (metadata.get('metadata') or metadata)['confusion_matrix'] is not None
    assert rows['federated']['round'] == rows['secure']['round'] == 1
    assert rows['federated']['continued_from_previous_round'] is False
    assert rows['secure']['continued_from_previous_round'] is False
    assert rows['secure']['paillier']['actual_crypto_operations_performed']
    assert rows['secure']['paillier']['max_abs_weight_delta'] < 1e-6
    assert rows['federated']['aggregation_method'] == 'plain'
    versions = {key: rows[k]['model_version'] for key, k in (
        ('local_version', 'centralized'), ('federated_version', 'federated'), ('secure_version', 'secure'))}
    with a.app.test_request_context('/'):
        resolved = a._requested_training_comparison(dict(versions, dataset_source_id='qa-source', preparation_id='qa-prep'))
        assert all(resolved)
        payload = a._training_comparison_payload(*resolved)
        assert payload['comparison_mode'] == 'three_way'
        assert payload['comparison_fairness']['direct_accuracy_ranking_allowed']
        assert payload['comparison_fairness']['direct_performance_ranking_allowed']
        assert 'qa-source' not in json.dumps(payload)
        assert payload['secure_federated_training']['aggregation']['actual_crypto_operations_performed']
        assert not a._requested_training_comparison(dict(versions, secure_version='other'))[0]


def test_queue_executes_the_whole_comparison_as_one_job(triplet, monkeypatch):
    client, _ = triplet
    monkeypatch.setitem(a.app.config, 'TESTING', False)
    monkeypatch.setattr(a, '_ensure_training_worker', lambda: None)
    response = run_triplet(client)
    assert response.status_code == 202
    same = run_triplet(client)
    assert same.get_json()['data']['id'] == response.get_json()['data']['id']
    job = a.db.claim_next_training_job('qa-worker')
    assert job['task_type'] == 'comparison'
    a._execute_training_job(job)
    saved = a.db.get_training_job(job['id'])
    assert saved['status'] == 'completed'
    assert len(saved['result']['data']['results']) == 3


def test_changed_revision_stops_without_mixing_results(triplet, monkeypatch):
    client, meta = triplet
    original = a._admin_training_centralized_locked
    def switch_after_centralized():
        result = original()
        meta['preparation_id'] = 'new-preparation'
        return result
    monkeypatch.setattr(a, '_admin_training_centralized_locked', switch_after_centralized)
    response = run_triplet(client)
    assert response.status_code == 409
    assert response.get_json()['data']['failed_variant'] == 'federated'
    assert len(a.db.get_training_tasks()) == 1


def test_secure_failure_keeps_two_completed_records(triplet, monkeypatch):
    client, _ = triplet
    monkeypatch.setattr(a, 'get_secure_aggregation_paillier', lambda: None)
    response = run_triplet(client)
    assert response.status_code == 503
    assert set(response.get_json()['data']['results']) == {'centralized', 'federated'}
    assert len(a.db.get_training_tasks()) == 2


def test_revision_and_auth_guard(triplet):
    client, _ = triplet
    assert a.app.test_client().post('/api/admin/training/comparison', json={}).status_code == 401
    assert client.post('/api/admin/training/comparison', json={'dataset_source_id': 'qa-source', 'expected_preparation_id': 'old'}).status_code == 409
    assert client.post('/api/admin/training/comparison', json={'epochs': 'invalid'}).status_code == 400
    assert not a.db.get_training_tasks()


def test_identical_metrics_do_not_deduplicate_different_variants():
    rows = [dict(task_type='federated', samples=160, accuracy=.75, timestamp='2026-10-30 13:00:00',
                 metadata=json.dumps({'model_version': version})) for version in ['plain-v1', 'secure-v1']]
    assert len(a._merge_training_tasks(rows, [], 20)) == 2


def test_three_way_ai_is_saved_and_bound_to_all_three_versions(triplet, monkeypatch):
    from tests.test_external_advisor import _settings, _advice
    client, _ = triplet
    data = run_triplet(client).get_json()['data']['results']
    params = dict(dataset_source_id='qa-source', preparation_id='qa-prep',
                  local_version=data['centralized']['model_version'],
                  federated_version=data['federated']['model_version'], secure_version=data['secure']['model_version'])
    provider = Mock()
    provider.analyze.return_value = {'advice': _advice(summary='三路结果的保存解读')}
    monkeypatch.setattr(a._external_ai_settings_store, 'get_effective', lambda **kwargs: _settings())
    monkeypatch.setattr(a, '_reserve_external_ai_call', lambda *args: (True, 0, 19))
    monkeypatch.setattr(a, '_create_external_advisor_client', lambda settings: provider)
    response = client.post('/api/admin/training/external-comparison', json=params)
    assert response.status_code == 200, response.get_json()
    assert provider.analyze.call_args[0][0]['comparison_mode'] == 'three_way'
    assert response.get_json()['data']['comparison_context']['secure_version'] == params['secure_version']
    restored = client.get('/api/admin/training/external-comparison', query_string=params)
    assert restored.get_json()['data']['advice']['summary'] == '三路结果的保存解读'
    assert client.post('/api/admin/training/external-comparison', json=params).status_code == 200
    assert provider.analyze.call_count == 1
    assert client.post('/api/admin/training/external-comparison', json=dict(params, secure_version='other')).status_code == 409
    assert provider.analyze.call_count == 1
