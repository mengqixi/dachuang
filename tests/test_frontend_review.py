import app as a


def test_confusion_counts_are_actual_predictions():
    result = a.binary_classification_metrics([0, 0, 1, 1, 1], [0, 1, 1, 0, 1])
    assert result['confusion_matrix'] == {'tp': 2, 'tn': 1, 'fp': 1, 'fn': 1}
    assert result['accuracy'] == .6
    assert a.binary_classification_metrics([], [])['confusion_matrix'] is None


def test_submission_pagination_preserves_global_summary(monkeypatch):
    items = [dict(id='row-%s' % n, risk_summary={'high': 1}, trainable=False) for n in range(45)]
    monkeypatch.setattr(a, '_list_admin_submissions_cached', lambda **kwargs: items)
    monkeypatch.setattr(a, '_admin_submission_summary', lambda rows: {'total': len(rows), 'high': len(rows)})
    client = a.app.test_client()
    assert client.get('/api/admin/submissions?offset=20').status_code == 401
    with client.session_transaction() as session:
        session['admin_logged_in'] = True
    for offset, count in [(0, 20), (20, 20), (40, 5), (100, 0)]:
        response = client.get('/api/admin/submissions?limit=20&offset=%s' % offset)
        assert response.status_code == 200
        data = response.get_json()['data']
        assert data['submissions'] == items[offset:offset+20]
        assert len(data['submissions']) == count
        assert data['summary']['total'] == data['total'] == 45
        assert data['has_more'] == (offset+20 < 45)
    assert client.get('/api/admin/submissions?offset=bad').status_code == 400
    assert client.get('/api/admin/submissions?limit=bad').status_code == 400
