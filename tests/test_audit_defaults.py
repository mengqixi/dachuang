import json

import pytest


@pytest.fixture
def audit_client(tmp_path, monkeypatch):
    import app as a
    import src.security.security_logger as logger
    path = tmp_path / 'audit.log'
    rows = [dict(event_type='site_visit' if i < 3 else 'blocked_request',
                 timestamp='2026-10-30T12:00:%02d' % i,
                 risk_level=level, trace_id=str(i), ip='198.51.100.1', path='/example')
            for i, level in enumerate(['info', 'low', 'high', 'low', 'medium', 'high', 'critical'])]
    path.write_text('\n'.join(json.dumps(row) for row in rows), encoding='utf-8')
    monkeypatch.setattr(logger, 'SECURITY_EVENTS_LOG_PATH', str(path))
    monkeypatch.setitem(a.app.config, 'TESTING', True)
    client = a.app.test_client()
    with client.session_transaction() as session:
        session['admin_logged_in'] = True
    return client, path


def test_events_default_to_attention_and_filter_before_paging(audit_client):
    client, path = audit_client
    original = path.read_bytes()
    result = client.get('/api/admin/audit/events?limit=2').get_json()['data']
    assert result['total'] == 3
    assert result['events'][0]['timestamp'] == '2026-10-30T12:00:06'
    assert [row['risk_level'] for row in result['events']] == ['critical', 'high']
    assert result['has_more']
    result = client.get('/api/admin/audit/events?limit=2&offset=2').get_json()['data']
    assert [row['risk_level'] for row in result['events']] == ['medium']
    assert path.read_bytes() == original


def test_visits_default_to_all_levels_and_all_events_are_still_available(audit_client):
    client, _ = audit_client
    visits = client.get('/api/admin/audit/events?event_type=site_visit').get_json()['data']
    assert visits['total'] == 3
    assert all(row['timestamp'].startswith('2026-10-30T12:00:') for row in visits['events'])
    assert {row['risk_level'] for row in visits['events']} == {'info', 'low', 'high'}
    events = client.get('/api/admin/audit/events?risk_level=').get_json()['data']
    assert events['total'] == 4
    assert all(row['event_type'] != 'site_visit' for row in events['events'])
    assert client.get('/api/admin/audit/events?risk_level=low').get_json()['data']['total'] == 1


def test_audit_requires_admin(audit_client):
    client, _ = audit_client
    with client.session_transaction() as session:
        session.clear()
    assert client.get('/api/admin/audit/events').status_code == 401
