"""Isolated security and read-only behavior checks; no live data or paid calls."""
import hashlib
import importlib
import json
import os
import sqlite3
import sys
import threading
from datetime import datetime, timezone
from contextlib import closing
from pathlib import Path
from types import SimpleNamespace

import pytest
from flask import Flask

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from src.muse_readonly import PREFIX, RESOURCES, register_muse_readonly

TOKEN = 'muse-unit-test-only-' + 'x' * 43


@pytest.fixture
def platform(tmp_path, monkeypatch):
    submission_module = importlib.import_module('src.user_submission_manager')
    security_module = importlib.import_module('src.security.security_logger')
    index = tmp_path / 'index.json'
    source = {
        'id': 'sub-test', 'filename': 'security.csv', 'row_count': 200,
        'upload_time': '2026-10-29 10:00:00', 'review_status': '可训练', 'trainable': True,
        'risk_summary': {'high': 20, 'medium': 40, 'low': 140},
        'analysis': {'privacy_risk': {'level': 'medium', 'score': .52, 'method': 'rules'}},
        'masked_preview': [{'ip': '192.0.2.33', 'password': 'DO_NOT_EXPORT'}],
        'encrypted_path': '/root/private/secret.enc',
        'external_analysis': {'model': 'saved-model', 'generated_at': '2026-10-29',
                              'advice': {'summary': 'Review password=DO_NOT_EXPORT at 192.0.2.33'}},
    }
    index.write_text(json.dumps({'submissions': [source]}), encoding='utf-8')
    monkeypatch.setattr(submission_module, 'INDEX_FILE', str(index))
    events = tmp_path / 'events.log'
    events.write_text(json.dumps({'timestamp': datetime.now(timezone.utc).isoformat(),
                                 'risk_level': 'high', 'event_type': 'blocked',
                                 'ip': '192.0.2.33', 'message': 'DO_NOT_EXPORT'}) + '\n', encoding='utf-8')
    monkeypatch.setattr(security_module, 'SECURITY_EVENTS_LOG_PATH', str(events))
    prepared = tmp_path / 'prepared.json'
    prepared.write_text(json.dumps({'dataset_source_id': 'test-source', 'samples': 200,
                                    'training_samples': 160, 'validation_samples': 40,
                                    'path': '/root/private/data.npy'}), encoding='utf-8')
    database = tmp_path / 'system.db'
    with closing(sqlite3.connect(str(database))) as conn, conn:
        conn.executescript('''
            CREATE TABLE training_tasks (id INTEGER PRIMARY KEY, task_type TEXT, timestamp TEXT,
                status TEXT, accuracy REAL, samples INTEGER, metadata TEXT);
            CREATE TABLE training_jobs (id TEXT PRIMARY KEY, created_epoch REAL,
                task_type TEXT, status TEXT, created_at TEXT, updated_at TEXT, payload TEXT);
            CREATE TABLE model_versions (id INTEGER PRIMARY KEY, timestamp TEXT,
                version TEXT, model_type TEXT, samples INTEGER, accuracy REAL, metadata TEXT);
        ''')
        metrics = dict(metric_scope='shared_holdout_validation', preparation_id='p1', validation_id='v1',
                       base_model_algorithm='linear_logistic_binary_classifier', optimizer='balanced',
                       class_weighting='balanced_global', epochs=10, effective_epochs=10,
                       validation_samples=40, accuracy=.8, f1=.75)
        for idx, kind in enumerate(('centralized', 'federated'), 1):
            conn.execute('INSERT INTO training_tasks VALUES (?,?,?,?,?,?,?)',
                         (idx, kind, '2026-10-29', 'completed', .8, 160, json.dumps(metrics)))
        conn.execute("INSERT INTO training_jobs VALUES ('a-new',2,'federated','completed','','','DO_NOT_EXPORT')")
        conn.execute("INSERT INTO training_jobs VALUES ('z-old',1,'centralized','failed','','','DO_NOT_EXPORT')")
        conn.execute("INSERT INTO model_versions VALUES (1,'2026-10-29','m1','federated',160,.8,'DO_NOT_EXPORT')")

    app = Flask(__name__)
    app.secret_key = 'unit-test-only'
    app.config['MUSE_READONLY_AUDIT_PATH'] = str(tmp_path / 'logs' / 'muse.log')
    writes = []

    @app.route('/api/admin/train', methods=['GET', 'POST'])
    def forbidden_write():
        writes.append(True)
        return {'written': True}

    cache = {'time': 123, 'value': [{'id': 'public-1', 'name': 'Public dataset', 'source_type': 'UNSW-NB15',
                                   'samples': 500, 'source': '/root/private/data.csv'}]}
    namespace = dict(PROJECT_ROOT=str(tmp_path), PROCESSED_META_PATH=str(prepared),
                     db=SimpleNamespace(db_path=str(database)),
                     user_submission_manager=submission_module.user_submission_manager,
                     _dataset_sources_cache=cache, _dataset_sources_cache_lock=threading.Lock(),
                     _model_inventory=lambda: {'runtime_detector': {'ready': True, 'version': 'serving-v2',
                        'name': 'Detector', 'files': {'private': '/root/private/model'}, 'training_context': {'samples': 160}}})
    register_muse_readonly(app, namespace)
    monkeypatch.setenv('MUSE_READONLY_ENABLED', 'true')
    monkeypatch.setenv('MUSE_READONLY_TOKEN', TOKEN)
    yield SimpleNamespace(app=app, client=app.test_client(), index=index, db=database,
                          prepared=prepared, events=events, namespace=namespace, writes=writes)
    logger = app.extensions['muse_readonly']['audit_logger']
    for handler in logger.handlers[:]:
        handler.close()
        logger.removeHandler(handler)


def query(platform, resource, **kwargs):
    return platform.client.get(PREFIX + resource, headers={'Authorization': 'Bearer ' + TOKEN}, **kwargs)


def test_disabled_and_credentials(platform, monkeypatch):
    monkeypatch.setenv('MUSE_READONLY_ENABLED', 'false')
    assert query(platform, 'overview').status_code == 503
    monkeypatch.setenv('MUSE_READONLY_ENABLED', 'true')
    assert platform.client.get(PREFIX + 'overview').status_code == 401
    assert platform.client.get(PREFIX + 'overview', headers={'Authorization': 'Bearer wrong'}).status_code == 401
    monkeypatch.setenv('MUSE_READONLY_TOKEN', 'short')
    assert query(platform, 'overview').status_code == 503


def test_public_http_cannot_spoof_https(platform):
    assert query(platform, 'overview', environ_overrides={'REMOTE_ADDR': '198.51.100.7', 'HTTP_X_FORWARDED_PROTO': 'https'}).status_code == 403
    assert query(platform, 'overview', base_url='https://example.test', environ_overrides={'REMOTE_ADDR': '198.51.100.7'}).status_code == 200


@pytest.mark.parametrize('method', ['POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'])
def test_writes_denied(platform, method):
    response = platform.client.open(PREFIX + 'overview', method=method, headers={'Authorization': 'Bearer ' + TOKEN})
    assert response.status_code == 405


def test_admin_cookie_cannot_expand_token_scope(platform):
    with platform.client.session_transaction() as session:
        session['admin_logged_in'] = True
    for method in ('GET', 'POST'):
        response = platform.client.open('/api/admin/train', method=method, headers={'Authorization': 'Bearer ' + TOKEN})
        assert response.status_code == 403
        assert response.headers['Cache-Control'] == 'no-store'
    assert platform.writes == []
    assert query(platform, 'unknown').status_code == 404


@pytest.mark.parametrize('resource', RESOURCES)
def test_snapshots_are_bounded_and_do_not_export_secrets(platform, resource):
    protected = [platform.index, platform.db, platform.prepared, platform.events]
    before = [hashlib.sha256(p.read_bytes()).hexdigest() for p in protected]
    response = query(platform, resource)
    assert response.status_code == 200, response.json
    assert response.json['meta']['read_only'] is True
    assert response.headers['Cache-Control'] == 'no-store'
    for secret in ('DO_NOT_EXPORT', '192.0.2.33', '/root/private', TOKEN, 'masked_preview', 'encrypted_path'):
        assert secret not in response.get_data(as_text=True)
    assert before == [hashlib.sha256(p.read_bytes()).hexdigest() for p in protected]
    assert query(platform, resource + '?limit=0').status_code == 400
    assert query(platform, resource + '?limit=2&limit=1').status_code == 400
    assert query(platform, resource + '?path=/etc/passwd').status_code == 400


def test_overview_and_dataset_pool_not_double_counted(platform):
    data = query(platform, 'overview').json['data']
    assert data['submission_count'] == 1 and data['risk_counts']['high'] == 20
    data = query(platform, 'datasets').json['data']
    assert data['total'] == 3
    assert data['approved_unique_samples'] == 200
    assert data['prepared_source']['training_samples'] == 160
    platform.namespace['_dataset_sources_cache']['value'] = None
    response = query(platform, 'datasets').json
    assert response['meta']['warnings']
    assert platform.namespace['_dataset_sources_cache']['value'] is None


def test_training_fairness_and_job_order(platform):
    data = query(platform, 'training').json['data']
    assert data['latest_pair_directly_comparable'] is True
    assert data['jobs'][0]['id'] == 'a-new'
    assert data['jobs'][0]['task_type'] == 'federated'
    with closing(sqlite3.connect(str(platform.db))) as conn, conn:
        meta = json.loads(conn.execute('SELECT metadata FROM training_tasks WHERE id=2').fetchone()[0])
        meta['effective_epochs'] = 20
        conn.execute('UPDATE training_tasks SET metadata=? WHERE id=2', (json.dumps(meta),))
    assert query(platform, 'training').json['data']['latest_pair_directly_comparable'] is False


def test_runtime_model_is_separate(platform):
    data = query(platform, 'models').json['data']
    assert data['serving_detector']['version'] == 'serving-v2'
    assert data['items'][0]['version'] == 'm1'


def test_audit_parameters_and_rate_limit(platform):
    assert query(platform, 'audit?hours=invalid').status_code == 400
    assert query(platform, 'audit?hours=169').status_code == 400
    platform.app.extensions['muse_readonly']['calls'].clear()
    for _ in range(30):
        assert query(platform, 'overview').status_code == 200
    response = query(platform, 'overview')
    assert response.status_code == 429
    assert response.headers['Retry-After'] == '60'
    log = Path(platform.app.config['MUSE_READONLY_AUDIT_PATH']).read_text(encoding='utf-8')
    assert TOKEN not in log and '192.0.2.33' not in log and 'DO_NOT_EXPORT' not in log


def test_missing_index_does_not_repair(platform):
    platform.index.unlink()
    assert query(platform, 'overview').status_code == 503
    assert not platform.index.exists()


def test_missing_database_does_not_create(platform):
    platform.db.unlink()
    assert query(platform, 'training').status_code == 503
    assert not platform.db.exists()


def test_head_supported(platform):
    response = platform.client.head(PREFIX + 'overview', headers={'Authorization': 'Bearer ' + TOKEN})
    assert response.status_code == 200 and response.data == b''


def test_real_app_has_early_guard_and_no_admin_bypass(platform, monkeypatch):
    application = importlib.import_module('app')
    client = application.app.test_client()
    monkeypatch.setitem(application.app.config, 'MUSE_READONLY_AUDIT_PATH',
                        platform.app.config['MUSE_READONLY_AUDIT_PATH'])
    assert client.get(PREFIX + 'overview', headers={'Authorization': 'Bearer ' + TOKEN}).status_code == 200
    assert client.get('/api/admin/datasets/sources', headers={'Authorization': 'Bearer ' + TOKEN}).status_code == 403
    assert client.get('/api/admin/datasets/sources').status_code == 401
