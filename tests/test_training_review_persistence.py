import json
import tempfile
from pathlib import Path
from unittest.mock import patch

import numpy as np
import pytest

import app as a
from src.analysis.external_advisor import (
    ExternalAdvisorProviderError, build_redacted_training_comparison_payload,
    external_cache_key,
)
from src.utils.data_storage import DataStorage
from src.preprocess.feature_engineering import (
    FEATURE_NAMES, FEATURE_DEFAULT_VALUES, extract_features_structured,
    infer_label, inspect_csv, load_security_csv,
)


def pair(version="1"):
    meta = {"dataset_source_id": "source", "dataset_revision": "data-1",
            "preparation_id": "prep", "validation_id": "val", "epochs": 20}
    return tuple({"id": kind + version, "task_type": kind, "accuracy": .8,
                  "samples": 100, "metadata": json.dumps(dict(meta, model_version=kind + version))}
                 for kind in ("centralized", "federated"))


def test_tracking_version_exposes_recorded_time_consistently():
    for task in (
        {"task_type": "federated", "created_at": "2026-10-30 20:38:39"},
        {"task_type": "runtime", "timestamp": "2026-10-30 20:38:39"},
        {"task_type": "centralized", "metadata": json.dumps({"timestamp": "2026-10-30 20:38:39"})},
    ):
        version = a._training_task_to_tracking_version(task)
        assert version['timestamp'] == version['created_at'] == '2026-10-30 20:38:39'
    assert a._training_task_to_tracking_version({'model_version': 'fed20261030203839'})['timestamp'] == ''


@pytest.fixture
def isolated_review(tmp_path):
    client = a.app.test_client()
    with client.session_transaction() as session:
        session["admin_logged_in"] = True
    settings = {"base_url": "https://example.invalid/v1", "model": "test-model",
                "mode": "chat_completions", "calls_per_hour": 20}
    with patch.object(a, "db", DataStorage(str(tmp_path / "system.db"))), \
         patch.object(a._external_ai_settings_store, "get_effective", return_value=settings), \
         patch.object(a, "_reserve_external_ai_call", return_value=(True, 0, 19)) as reserve, \
         patch.object(a, "_create_external_advisor_client") as provider:
        provider.return_value.analyze.return_value = {"advice": {"summary": "已核对本次训练结果"}}
        yield client, settings, provider, reserve


def test_training_ai_saved_restore_and_version_isolation(isolated_review):
    client, _, provider, reserve = isolated_review
    with patch.object(a, "_latest_training_pair", return_value=pair()):
        response = client.post("/api/admin/training/external-comparison", json={})
        assert response.status_code == 200
        first = response.get_json()["data"]
        assert first["comparison_id"]
        # A new HTTP client (page/session refresh) reads the persisted DB record.
        restored = client.get("/api/admin/training/external-comparison").get_json()["data"]
        assert restored["advice"] == first["advice"]
        assert restored["generated_at"] == first["generated_at"]
        assert restored["cache_reused"] is True
        assert client.post("/api/admin/training/external-comparison", json={}).get_json()["data"]["cache_reused"]
        assert not client.get("/api/admin/training/external-comparison?local_version=wrong").get_json()["data"]
        assert client.post("/api/admin/training/external-comparison", json={"local_version": "wrong"}).status_code == 409
    assert provider.return_value.analyze.call_count == reserve.call_count == 1
    with patch.object(a, "_latest_training_pair", return_value=pair("2")):
        assert not client.get("/api/admin/training/external-comparison").get_json()["data"]
        assert client.post("/api/admin/training/external-comparison", json={}).status_code == 200
    with patch.object(a, "_latest_training_pair", return_value=pair()):
        assert client.get("/api/admin/training/external-comparison").get_json()["data"]["comparison_id"] == first["comparison_id"]
        provider.return_value.analyze.side_effect = ExternalAdvisorProviderError("unavailable")
        assert client.post("/api/admin/training/external-comparison", json={"force": True}).status_code >= 400
        assert client.get("/api/admin/training/external-comparison").get_json()["data"]["generated_at"] == first["generated_at"]
    assert a.app.test_client().get("/api/admin/training/external-comparison").status_code == 401


def test_legacy_cache_is_preserved_after_new_records(isolated_review):
    client, settings, provider, reserve = isolated_review
    payload = build_redacted_training_comparison_payload(*pair())
    legacy = {"input_fingerprint": external_cache_key(payload, settings),
              "advice": {"summary": "旧版本已存解读"}, "generated_at": "old"}
    a.db.set_config(a.TRAINING_AI_COMPARISON_CACHE_KEY, json.dumps(legacy))
    with patch.object(a, "_latest_training_pair", return_value=pair()):
        assert not client.get("/api/admin/training/external-comparison").get_json()["data"]
        history = client.get("/api/admin/training/external-comparison?history=1").get_json()["data"]["records"]
        assert history[0]["version_binding"] == "unrecorded"
    # Different metrics to ensure legacy input does not match, then restore old.
    changed = pair("2")
    changed[0]["accuracy"] = .7
    with patch.object(a, "_latest_training_pair", return_value=changed):
        client.post("/api/admin/training/external-comparison", json={})
    with patch.object(a, "_latest_training_pair", return_value=pair()):
        history = client.get("/api/admin/training/external-comparison?history=1").get_json()["data"]["records"]
        assert any(item["generated_at"] == "old" for item in history)
        assert not client.get("/api/admin/training/external-comparison").get_json()["data"]
    assert provider.return_value.analyze.call_count == reserve.call_count == 1


def test_cic_headers_labels_and_units_are_not_defaults(tmp_path):
    csv = tmp_path / "cic.csv"
    csv.write_text("\ufeff Flow Duration,Flow Pkts/s,Flow IAT Mean,TotLen Fwd Pkts,Pkt Len Var, Label\n"
                   "2000000,120,50000,500,36,Benign\n"
                   "3000000,200,80000,700,49,Brute Force\n", encoding="utf-8")
    X, y, _ = load_security_csv(str(csv))
    assert y.tolist() == [0, 1]
    assert X[0, FEATURE_NAMES.index("connection_duration")] == 2
    assert X[0, FEATURE_NAMES.index("packet_interarrival")] == pytest.approx(.05)
    assert X[0, FEATURE_NAMES.index("request_frequency")] == 120
    assert X[0, FEATURE_NAMES.index("response_time")] == FEATURE_DEFAULT_VALUES[FEATURE_NAMES.index("response_time")]
    assert inspect_csv(str(csv))["label_column"] == " Label"
    assert inspect_csv(str(csv))["features"] == 5
    assert infer_label({" LABEL ": "BENIGN"}) == 0
    assert infer_label({"Label": "DoS"}) == 1
    np.testing.assert_array_equal(extract_features_structured({"request_frequency": 12, "label": 0}),
                                  extract_features_structured({"request_frequency": 12, "label": 1}))


def test_invalid_csv_never_overwrites_prepared_arrays(tmp_path):
    csv = tmp_path / "cic.csv"
    for rows, reason in [(["1,2,Benign"] * 30, "正常和攻击"),
                         (["1,2,Benign", "1,2,DoS"] * 15, "特征全部相同")]:
        csv.write_text("Flow Duration,Flow Pkts/s,Label\n" + "\n".join(rows), encoding="utf-8")
        with a.app.test_request_context(), \
             patch.object(a, "_preparation_matches", return_value=False), \
             patch.object(a, "_incremental_submission_change", return_value=None), \
             patch.object(a, "_save_shared_training_partitions") as save:
            response = a._prepare_dataset_source_for_federated({"id": "cic", "path": str(csv), "samples": 30}, limit=30)
            body = response.get_json()
            assert body["code"] == 400, body
            assert reason in body["msg"]
            save.assert_not_called()
    assert a._comparison_preparation_error(np.arange(540).reshape(30, 18), np.array([0, 1] * 15)) is None
