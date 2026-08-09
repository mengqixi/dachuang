import json
import os
import builtins
from contextlib import ExitStack
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import numpy as np


class FeatureTransformTests(unittest.TestCase):
    def test_fixed_normalization_is_batch_independent(self):
        from src.preprocess.feature_engineering import (
            FEATURE_MAX_VALUES,
            FEATURE_MIN_VALUES,
            normalize_security_features,
        )

        row = FEATURE_MIN_VALUES + 0.4 * (FEATURE_MAX_VALUES - FEATURE_MIN_VALUES)
        alone = normalize_security_features(row.reshape(1, -1))[0]
        in_batch = normalize_security_features(
            np.vstack([row, FEATURE_MIN_VALUES, FEATURE_MAX_VALUES])
        )[0]

        np.testing.assert_allclose(alone, in_batch)
        self.assertGreater(float(np.sum(alone)), 0.0)

    def test_response_time_ms_is_converted_to_seconds(self):
        from src.preprocess.feature_engineering import FEATURE_NAMES, extract_features_structured

        features = extract_features_structured({"response_time_ms": 250})
        self.assertAlmostEqual(features[FEATURE_NAMES.index("response_time")], 0.25)

    def test_csv_inspection_counts_rows_and_invalidates_by_file_revision(self):
        from src.preprocess.feature_engineering import inspect_csv

        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "security.csv"
            source.write_text(
                "request_frequency,response_time,label\n"
                "10,0.2,0\n"
                "120,1.3,1",
                encoding="utf-8",
            )
            first = inspect_csv(str(source))
            self.assertEqual(first["samples"], 2)
            self.assertEqual(first["features"], 2)
            self.assertEqual(first["label_column"], "label")

            with source.open("a", encoding="utf-8") as stream:
                stream.write("\n80,0.8,1\n")
            second = inspect_csv(str(source))
            self.assertEqual(second["samples"], 3)
            self.assertEqual(second["row_count_method"], "physical_lines")


class IsolationForestScoringTests(unittest.TestCase):
    def test_score_does_not_depend_on_other_request_rows(self):
        from sklearn.ensemble import IsolationForest
        from src.detection.scoring import calibrate_isolation_forest, isolation_forest_risk_score

        rng = np.random.default_rng(42)
        training = rng.normal(size=(200, 4))
        model = IsolationForest(contamination=0.1, random_state=42).fit(training)
        calibrate_isolation_forest(model, training)
        sample = training[0]

        alone = isolation_forest_risk_score(model, sample.reshape(1, -1))[0]
        in_batch = isolation_forest_risk_score(
            model,
            np.vstack([sample, np.full((20, 4), 50.0)]),
        )[0]
        self.assertAlmostEqual(float(alone), float(in_batch), places=12)


class FedAvgContextTests(unittest.TestCase):
    def test_weighting_and_context_reset(self):
        from src.federated.aggregator import FedAvgServer

        server = FedAvgServer()
        self.assertTrue(server.ensure_context("prep-a"))
        result = server.aggregate([
            {"weights": np.array([0.0, 0.0]), "samples": 1, "accuracy": 0.0, "loss": 1.0},
            {"weights": np.array([10.0, 10.0]), "samples": 3, "accuracy": 1.0, "loss": 0.0},
        ])
        np.testing.assert_allclose(result, np.array([7.5, 7.5]))
        self.assertEqual(server.get_history()[0]["accuracy"], 0.75)
        self.assertFalse(server.ensure_context("prep-a"))
        self.assertEqual(server.round, 1)

        self.assertTrue(server.ensure_context("prep-b"))
        self.assertEqual(server.round, 0)
        self.assertIsNone(server.global_weights)
        self.assertEqual(server.get_history(), [])


class OptimizationFallbackTests(unittest.TestCase):
    def test_environment_runs_without_gym_packages(self):
        source_path = Path(__file__).parents[1] / "src" / "optimization" / "environment.py"
        source = source_path.read_text(encoding="utf-8")
        real_import = builtins.__import__

        def import_without_gym(name, *args, **kwargs):
            if name in {"gym", "gymnasium"}:
                raise ImportError("blocked for fallback test")
            return real_import(name, *args, **kwargs)

        namespace = {"__name__": "optimization_environment_fallback_test"}
        with patch.object(builtins, "__import__", side_effect=import_without_gym):
            exec(compile(source, str(source_path), "exec"), namespace)

        environment = namespace["EncryptionEnv"]()
        state, info = environment.reset(seed=42)
        action = environment.action_space.sample()
        next_state, reward, terminated, truncated, details = environment.step(action)
        self.assertEqual(state.shape, (4,))
        self.assertEqual(next_state.shape, (4,))
        self.assertIsInstance(reward, float)
        self.assertIsInstance(terminated, bool)
        self.assertIsInstance(truncated, bool)
        self.assertIn("key_length", details)


class SubmissionArchiveTests(unittest.TestCase):
    def test_new_submission_keeps_only_encrypted_durable_copy(self):
        import src.user_submission_manager as module

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            data_root = root / "submissions"
            temp_dir = data_root / "plain_temp"
            archive_dir = data_root / "archive"
            report_dir = data_root / "reports"
            key_dir = root / "keys"
            paths = {
                "DATA_ROOT": str(data_root),
                "TEMP_DIR": str(temp_dir),
                "ARCHIVE_DIR": str(archive_dir),
                "REPORT_DIR": str(report_dir),
                "INDEX_FILE": str(data_root / "index.json"),
                "KEY_DIR": str(key_dir),
                "KEY_FILE": str(key_dir / "archive.key"),
            }
            source = root / "input.csv"
            source.write_text(
                "username,password,failed_attempts,request_frequency,response_time,label\n"
                "alice,secret123,0,5,0.2,0\n"
                "bob,password,8,140,1.6,1\n",
                encoding="utf-8",
            )

            with ExitStack() as stack:
                for name, value in paths.items():
                    stack.enter_context(patch.object(module, name, value))
                manager = module.UserSubmissionManager()
                summary = manager.create_submission(str(source), "input.csv")

                self.assertTrue(summary["encrypted"])
                self.assertEqual(list(temp_dir.glob("*")), [])
                index = json.loads((data_root / "index.json").read_text(encoding="utf-8"))
                raw_item = index["submissions"][0]
                self.assertIsNone(raw_item["plain_temp_path"])
                self.assertTrue(Path(raw_item["encrypted_path"]).exists())

                rows, _ = manager._load_plain_rows(raw_item)
                self.assertEqual(len(rows), 2)
                self.assertNotIn("password", rows[0])
                self.assertEqual(list(temp_dir.glob("*")), [])

                manager.set_status(
                    summary["id"],
                    review_status=module.REVIEW_STATUS["trainable"],
                    trainable=True,
                )
                X, y, metadata = manager.load_trainable_features(ids=[summary["id"]])
                self.assertEqual(X.shape, (2, 18))
                np.testing.assert_array_equal(y, np.array([0, 1]))
                self.assertEqual(metadata["source_count"], 1)
                self.assertEqual(list(temp_dir.glob("*")), [])


class HttpBoundaryTests(unittest.TestCase):
    def setUp(self):
        from app import app

        app.config.update(TESTING=True)
        self.client = app.test_client()

    def test_management_legacy_route_requires_admin_session(self):
        response = self.client.get("/api/optimization/status")
        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.get_json()["code"], 401)

    def test_blank_admin_password_cannot_enable_remote_default_login(self):
        with patch.dict(
            os.environ,
            {"ADMIN_PASSWORD": "", "ALLOW_DEFAULT_ADMIN": "false"},
            clear=False,
        ):
            response = self.client.post(
                "/api/admin/login",
                json={"username": "root", "password": "root"},
                base_url="http://example.test:5001",
            )
        self.assertEqual(response.status_code, 503)

    def test_untrusted_origin_does_not_receive_cors_wildcard(self):
        with patch.dict(os.environ, {"CORS_ALLOWED_ORIGINS": ""}, clear=False):
            response = self.client.get(
                "/api/system/health",
                headers={"Origin": "https://evil.example"},
            )
        self.assertNotIn("Access-Control-Allow-Origin", response.headers)


class PreparedMetadataTests(unittest.TestCase):
    def test_existing_metadata_file_is_loaded(self):
        import app as app_module

        with tempfile.TemporaryDirectory() as tmp:
            metadata_path = Path(tmp) / "metadata.json"
            metadata_path.write_text('{"preparation_id":"prep-test"}', encoding="utf-8")
            with patch.object(app_module, "PROCESSED_META_PATH", str(metadata_path)):
                self.assertEqual(
                    app_module._load_processed_metadata(),
                    {"preparation_id": "prep-test"},
                )

    def test_processed_arrays_with_stale_preprocessing_are_not_ready(self):
        import app as app_module

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            x_path = root / "X.npy"
            y_path = root / "y.npy"
            metadata_path = root / "metadata.json"
            np.save(x_path, np.zeros((2, 18), dtype=float))
            np.save(y_path, np.zeros(2, dtype=int))
            metadata_path.write_text(
                json.dumps({"preprocessing_version": "legacy-minmax-v0"}),
                encoding="utf-8",
            )
            with (
                patch.object(app_module, "PROCESSED_X_PATH", str(x_path)),
                patch.object(app_module, "PROCESSED_Y_PATH", str(y_path)),
                patch.object(app_module, "PROCESSED_META_PATH", str(metadata_path)),
            ):
                self.assertFalse(app_module._processed_dataset_ready())
                metadata_path.write_text(
                    json.dumps({"preprocessing_version": app_module.FEATURE_NORMALIZATION_VERSION}),
                    encoding="utf-8",
                )
                self.assertTrue(app_module._processed_dataset_ready())


class DatasetSourcesApiTests(unittest.TestCase):
    def test_response_identifies_current_prepared_source(self):
        import app as app_module

        app_module.app.config.update(TESTING=True)
        client = app_module.app.test_client()
        with client.session_transaction() as admin_session:
            admin_session["admin_logged_in"] = True

        source = {"id": "source-a", "name": "A", "prepared_for_federated": True}
        metadata = {"dataset_source_id": "source-a", "preparation_id": "prep-a"}
        with (
            patch.object(app_module, "_list_dataset_sources_cached", return_value=[source]),
            patch.object(app_module, "_load_processed_metadata", return_value=metadata),
            patch.object(app_module, "_source_prepared_for_federated", return_value=True),
            patch.object(app_module, "_federated_files_ready", return_value=True),
            patch.object(app_module, "_model_inventory", return_value={}),
        ):
            response = client.get("/api/admin/datasets/sources")
            try:
                payload = response.get_json()["data"]
                self.assertEqual(payload["current_source_id"], "source-a")
                self.assertEqual(payload["current_source"]["id"], "source-a")
                self.assertTrue(payload["ready_for_federated"])
            finally:
                response.close()


class TrainingSourceBoundaryTests(unittest.TestCase):
    def setUp(self):
        import app as app_module

        self.app_module = app_module
        app_module.app.config.update(TESTING=True)
        self.client = app_module.app.test_client()
        with self.client.session_transaction() as admin_session:
            admin_session["admin_logged_in"] = True

    def test_explicit_missing_source_does_not_fall_back_to_another_source(self):
        with patch.object(self.app_module, "_list_dataset_sources_cached", return_value=[{"id": "source-a"}]):
            X, y, metadata = self.app_module._load_training_dataset_source("missing-source")
        self.assertEqual(len(X), 0)
        self.assertEqual(len(y), 0)
        self.assertTrue(metadata["source_not_found"])
        self.assertEqual(metadata["dataset_source_id"], "missing-source")

    def test_federated_training_rejects_unprepared_source(self):
        X = np.zeros((20, 18), dtype=float)
        y = np.array([0, 1] * 10, dtype=int)
        metadata = {
            "dataset_source_id": "source-a",
            "uses_prepared_data": False,
            "preparation_id": None,
        }
        with (
            patch.object(self.app_module, "_load_training_dataset_source", return_value=(X, y, metadata)),
            patch.object(self.app_module, "_load_processed_metadata", return_value={}),
            patch.object(self.app_module, "_federated_files_ready", return_value=True),
        ):
            response = self.client.post(
                "/api/admin/training/federated",
                json={"dataset_source_id": "source-a", "epochs": 1},
            )
            try:
                self.assertEqual(response.status_code, 409)
                self.assertEqual(response.get_json()["code"], 409)
            finally:
                response.close()


if __name__ == "__main__":
    unittest.main()
