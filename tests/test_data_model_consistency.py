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
        self.assertTrue(server.ensure_context("prep-a", force_reset=True))
        self.assertEqual(server.round, 0)
        self.assertIsNone(server.global_weights)

        self.assertTrue(server.ensure_context("prep-b"))
        self.assertEqual(server.round, 0)
        self.assertIsNone(server.global_weights)
        self.assertEqual(server.get_history(), [])

    def test_paillier_secure_aggregation_matches_plain_weighted_average(self):
        from src.encryption.paillier import Paillier
        from src.federated.aggregator import FedAvgServer

        paillier = Paillier(key_size=128)
        paillier.generate_keys()
        results = [
            {
                "name": "node-a",
                "weights": np.array([-1.25, 0.5, -0.125]),
                "samples": 2,
                "accuracy": 0.5,
                "loss": 0.8,
            },
            {
                "name": "node-b",
                "weights": np.array([2.0, -0.25, 0.875]),
                "samples": 6,
                "accuracy": 0.9,
                "loss": 0.2,
            },
        ]
        expected = np.average(
            np.asarray([result["weights"] for result in results]),
            axis=0,
            weights=np.asarray([result["samples"] for result in results]),
        )

        server = FedAvgServer()
        server.ensure_context("secure-prep")
        aggregated, crypto = server.aggregate_paillier(results, paillier)

        np.testing.assert_allclose(aggregated, expected, atol=1e-6)
        self.assertTrue(crypto["secure_aggregation"])
        self.assertTrue(crypto["actual_crypto_operations_performed"])
        self.assertFalse(crypto["display_only"])
        self.assertFalse(crypto["individual_updates_decrypted"])
        self.assertEqual(crypto["encrypted_parameter_count"], 6)
        self.assertLessEqual(crypto["max_abs_weight_delta"], 1e-6)
        self.assertEqual(server.get_history()[0]["aggregation_method"], "fedavg_paillier_secure")


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
            train_x_path = root / "X_train.npy"
            train_y_path = root / "y_train.npy"
            validation_x_path = root / "X_validation.npy"
            validation_y_path = root / "y_validation.npy"
            metadata_path = root / "metadata.json"
            np.save(x_path, np.zeros((2, 18), dtype=float))
            np.save(y_path, np.zeros(2, dtype=int))
            np.save(train_x_path, np.zeros((2, 18), dtype=float))
            np.save(train_y_path, np.zeros(2, dtype=int))
            np.save(validation_x_path, np.empty((0, 18), dtype=float))
            np.save(validation_y_path, np.empty(0, dtype=int))
            metadata_path.write_text(
                json.dumps({"preprocessing_version": "legacy-minmax-v0"}),
                encoding="utf-8",
            )
            with (
                patch.object(app_module, "PROCESSED_X_PATH", str(x_path)),
                patch.object(app_module, "PROCESSED_Y_PATH", str(y_path)),
                patch.object(app_module, "PROCESSED_TRAIN_X_PATH", str(train_x_path)),
                patch.object(app_module, "PROCESSED_TRAIN_Y_PATH", str(train_y_path)),
                patch.object(app_module, "PROCESSED_VALIDATION_X_PATH", str(validation_x_path)),
                patch.object(app_module, "PROCESSED_VALIDATION_Y_PATH", str(validation_y_path)),
                patch.object(app_module, "PROCESSED_META_PATH", str(metadata_path)),
            ):
                self.assertFalse(app_module._processed_dataset_ready())
                metadata_path.write_text(
                    json.dumps({"preprocessing_version": app_module.FEATURE_NORMALIZATION_VERSION}),
                    encoding="utf-8",
                )
                self.assertFalse(app_module._processed_dataset_ready())
                metadata_path.write_text(
                    json.dumps({
                        "preprocessing_version": app_module.FEATURE_NORMALIZATION_VERSION,
                        "validation_split_version": app_module.SHARED_VALIDATION_SPLIT_VERSION,
                    }),
                    encoding="utf-8",
                )
                self.assertTrue(app_module._processed_dataset_ready())


class SharedValidationTests(unittest.TestCase):
    def test_stratified_holdout_is_deterministic_balanced_and_disjoint(self):
        import app as app_module

        X = np.zeros((100, 18), dtype=float)
        X[:, 0] = np.arange(100)
        y = np.array([0] * 60 + [1] * 40, dtype=int)

        first = app_module._stratified_holdout_split(X, y, seed=123)
        second = app_module._stratified_holdout_split(X, y, seed=123)
        X_train, y_train, X_validation, y_validation = first

        self.assertEqual(len(X_train), 80)
        self.assertEqual(len(X_validation), 20)
        self.assertEqual(set(np.unique(y_train)), {0, 1})
        self.assertEqual(set(np.unique(y_validation)), {0, 1})
        self.assertFalse(set(X_train[:, 0]).intersection(set(X_validation[:, 0])))
        for left, right in zip(first, second):
            np.testing.assert_array_equal(left, right)

    def test_preparation_persists_train_holdout_and_train_only_nodes(self):
        import app as app_module
        import src.preprocess.federated_splitter as splitter_module

        X = np.zeros((100, 18), dtype=float)
        X[:, 0] = np.arange(100)
        y = np.array([0] * 60 + [1] * 40, dtype=int)
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            processed = root / "processed"
            federated = root / "federated"
            paths = {
                "PROCESSED_DATA_DIR": processed,
                "PROCESSED_X_PATH": processed / "X_processed.npy",
                "PROCESSED_Y_PATH": processed / "y_processed.npy",
                "PROCESSED_TRAIN_X_PATH": processed / "X_train.npy",
                "PROCESSED_TRAIN_Y_PATH": processed / "y_train.npy",
                "PROCESSED_VALIDATION_X_PATH": processed / "X_validation.npy",
                "PROCESSED_VALIDATION_Y_PATH": processed / "y_validation.npy",
            }
            with ExitStack() as stack:
                for name, value in paths.items():
                    stack.enter_context(patch.object(app_module, name, str(value)))
                stack.enter_context(patch.object(splitter_module, "FEDERATED_DIR", str(federated)))
                result = app_module._save_shared_training_partitions(X, y, 123, "prep-a")

            self.assertEqual(result["training_samples"], 80)
            self.assertEqual(result["validation_samples"], 20)
            self.assertTrue(result["validation_available"])
            self.assertEqual(sum(count for _, count in result["nodes"]), 80)
            self.assertEqual(len(np.load(paths["PROCESSED_X_PATH"])), 100)
            self.assertEqual(len(np.load(paths["PROCESSED_TRAIN_X_PATH"])), 80)
            self.assertEqual(len(np.load(paths["PROCESSED_VALIDATION_X_PATH"])), 20)
            node_rows = sum(
                len(np.load(federated / name / "X.npy"))
                for name in splitter_module.NODE_NAMES
            )
            self.assertEqual(node_rows, 80)

    def test_small_imbalanced_source_does_not_claim_holdout(self):
        import app as app_module

        X = np.zeros((20, 18), dtype=float)
        y = np.array([0] * 19 + [1], dtype=int)
        X_train, y_train, X_validation, y_validation = app_module._stratified_holdout_split(X, y)

        self.assertEqual(len(X_train), 20)
        self.assertEqual(len(y_train), 20)
        self.assertEqual(len(X_validation), 0)
        self.assertEqual(len(y_validation), 0)

    def test_federated_client_uses_full_node_partition_when_shared_holdout_exists(self):
        from src.federated.client import FederatedClient

        client = FederatedClient("node-a", "unused")
        client.X = np.vstack([np.zeros((10, 18)), np.ones((10, 18))])
        client.y = np.array([0] * 10 + [1] * 10, dtype=int)
        client._loaded = True
        with patch.object(
            client,
            "_split_train_validation",
            side_effect=AssertionError("internal validation must not run"),
        ):
            result = client.train_local(epochs=1, use_internal_validation=False)

        self.assertEqual(result["samples"], 20)
        self.assertEqual(result["metric_scope"], "node_training_diagnostic")
        self.assertEqual(result["metric_label"], "节点训练诊断指标")

    def test_local_training_uses_prepared_shared_holdout_metrics(self):
        import app as app_module
        from src.detection.ensemble_detector import ensemble_detector

        app_module.app.config.update(TESTING=True)
        client = app_module.app.test_client()
        with client.session_transaction() as admin_session:
            admin_session["admin_logged_in"] = True

        X_train = np.zeros((40, 18), dtype=float)
        y_train = np.array([0, 1] * 20, dtype=int)
        X_validation = np.ones((10, 18), dtype=float)
        y_validation = np.array([0, 1] * 5, dtype=int)
        metadata = {
            "dataset_source_id": "source-a",
            "dataset_revision": "revision-a",
            "preparation_id": "prep-a",
            "validation_id": "val-a",
            "validation_split_version": app_module.SHARED_VALIDATION_SPLIT_VERSION,
            "preprocessing_version": app_module.FEATURE_NORMALIZATION_VERSION,
            "validation_available": True,
            "uses_shared_validation": True,
            "validation_samples": 10,
            "uses_prepared_data": True,
            "training_source": "managed_dataset_source",
            "dataset_name": "A",
            "source_type": "local_generated",
            "source_samples": 50,
            "source_count": 1,
            "sources": [],
            "label_distribution": {"0": 20, "1": 20},
        }
        train_scores = np.where(y_train > 0, 0.9, 0.1)
        validation_scores = np.where(y_validation > 0, 0.9, 0.1)

        with (
            patch.object(app_module, "_load_training_dataset_source", return_value=(X_train, y_train, metadata)),
            patch.object(
                app_module,
                "_load_prepared_validation_arrays",
                return_value=(X_validation, y_validation, metadata),
            ),
            patch.object(ensemble_detector, "fit", return_value={"accuracy": 1.0}),
            patch.object(
                ensemble_detector,
                "predict",
                side_effect=[
                    (y_train.copy(), train_scores, np.zeros(len(y_train), dtype=int)),
                    (y_validation.copy(), validation_scores, np.zeros(len(y_validation), dtype=int)),
                ],
            ),
            patch.object(app_module, "save_training_record"),
            patch.object(app_module.user_submission_manager, "mark_used_for_training", return_value=[]),
            patch.object(app_module.db, "save_training_task_record"),
            patch.object(app_module.db, "save_model_version_record"),
        ):
            response = client.post(
                "/api/admin/training/local",
                json={"dataset_source_id": "source-a", "limit": 50},
            )
        try:
            payload = response.get_json()
            self.assertEqual(response.status_code, 200, payload)
            data = payload["data"]
            self.assertEqual(data["task_type"], "runtime")
            self.assertEqual(data["comparison_role"], "user_facing_runtime_detector")
            self.assertEqual(data["metric_scope"], "shared_holdout_validation")
            self.assertEqual(data["metric_label"], "同源共享留出集指标")
            self.assertEqual(data["validation_id"], "val-a")
            self.assertEqual(data["validation_samples"], 10)
            self.assertEqual(data["samples"], 40)
            self.assertEqual(data["source_samples"], 50)
            self.assertEqual(data["accuracy"], 1.0)
            self.assertTrue(data["uses_shared_validation"])
        finally:
            response.close()

    def test_centralized_baseline_is_linear_comparison_task_not_runtime_update(self):
        import app as app_module

        app_module.app.config.update(TESTING=True)
        client = app_module.app.test_client()
        with client.session_transaction() as admin_session:
            admin_session["admin_logged_in"] = True

        y_train = np.array([0, 1] * 20, dtype=int)
        X_train = np.zeros((40, 18), dtype=float)
        X_train[:, 0] = np.where(y_train > 0, 1.0, -1.0)
        y_validation = np.array([0, 1] * 5, dtype=int)
        X_validation = np.zeros((10, 18), dtype=float)
        X_validation[:, 0] = np.where(y_validation > 0, 1.0, -1.0)
        metadata = {
            "dataset_source_id": "source-a",
            "dataset_revision": "abcdef123456",
            "preparation_id": "prep-a",
            "validation_id": "val-a",
            "validation_split_version": app_module.SHARED_VALIDATION_SPLIT_VERSION,
            "preprocessing_version": app_module.FEATURE_NORMALIZATION_VERSION,
            "validation_available": True,
            "validation_samples": 10,
            "validation_label_distribution": {"0": 5, "1": 5},
            "uses_shared_validation": True,
            "uses_prepared_data": True,
            "training_source": "managed_dataset_source",
            "dataset_name": "A",
            "source_type": "local_generated",
            "source_samples": 50,
            "source_count": 1,
            "sources": [],
            "label_distribution": {"0": 20, "1": 20},
        }

        with (
            patch.object(app_module, "_load_training_dataset_source", return_value=(X_train, y_train, metadata)),
            patch.object(
                app_module,
                "_load_prepared_validation_arrays",
                return_value=(X_validation, y_validation, metadata),
            ),
            patch.object(app_module, "save_training_record"),
            patch.object(app_module.user_submission_manager, "mark_used_for_training", return_value=[]),
            patch.object(app_module.db, "save_training_task_record"),
            patch.object(app_module.db, "save_model_version_record"),
        ):
            response = client.post(
                "/api/admin/training/centralized",
                json={"dataset_source_id": "source-a", "epochs": 1},
            )
        try:
            payload = response.get_json()
            self.assertEqual(response.status_code, 200, payload)
            data = payload["data"]
            self.assertEqual(data["task_type"], "centralized")
            self.assertEqual(data["model_type"], "centralized_linear_baseline")
            self.assertEqual(data["comparison_role"], "ordinary_centralized_baseline")
            self.assertEqual(data["algorithm"], "linear_logistic_gradient_descent")
            self.assertEqual(data["metric_scope"], "shared_holdout_validation")
            self.assertFalse(data["runtime_model_updated"])
            self.assertEqual(data["accuracy"], 1.0)
        finally:
            response.close()

    def test_federated_training_evaluates_global_weights_on_same_holdout(self):
        import app as app_module
        import src.federated.aggregator as aggregator_module
        import src.federated.client as client_module

        app_module.app.config.update(TESTING=True)
        client = app_module.app.test_client()
        with client.session_transaction() as admin_session:
            admin_session["admin_logged_in"] = True

        X_train = np.zeros((40, 18), dtype=float)
        y_train = np.array([0, 1] * 20, dtype=int)
        X_validation = np.zeros((10, 18), dtype=float)
        y_validation = np.array([0, 1] * 5, dtype=int)
        X_validation[:, 0] = y_validation
        weights = np.zeros(19, dtype=float)
        weights[0] = 10.0
        weights[-1] = -5.0
        nodes = [
            {"name": name, "samples": 10, "ready": True}
            for name in ("hospital", "bank", "insurance", "government")
        ]
        metadata = {
            "dataset_source_id": "source-a",
            "dataset_revision": "revision-a",
            "preparation_id": "prep-a",
            "validation_id": "val-a",
            "validation_split_version": app_module.SHARED_VALIDATION_SPLIT_VERSION,
            "preprocessing_version": app_module.FEATURE_NORMALIZATION_VERSION,
            "validation_available": True,
            "validation_samples": 10,
            "validation_label_distribution": {"0": 5, "1": 5},
            "uses_shared_validation": True,
            "uses_prepared_data": True,
            "prepared_samples": 40,
            "training_source": "managed_dataset_source",
            "dataset_name": "A",
            "source_type": "local_generated",
            "source_samples": 50,
            "source_count": 1,
            "sources": [],
            "label_distribution": {"0": 20, "1": 20},
            "nodes": nodes,
        }
        internal_validation_flags = []

        class FakeClient:
            def __init__(self, name, _data_dir):
                self.name = name

            def load_data(self):
                return True

            def train_local(self, global_weights=None, epochs=1, use_internal_validation=True):
                self.use_internal_validation = use_internal_validation
                internal_validation_flags.append(use_internal_validation)
                return {
                    "name": self.name,
                    "weights": weights.copy(),
                    "samples": 10,
                    "accuracy": 0.5,
                    "loss": 0.69,
                    "metric_scope": "node_training_diagnostic",
                    "metric_label": "节点训练诊断指标",
                }

        class FakeServer:
            def __init__(self):
                self.global_weights = None
                self.round = 0

            def ensure_context(self, _context_id, force_reset=False):
                self.force_reset = force_reset
                return True

            def aggregate(self, _results):
                self.global_weights = weights.copy()
                self.round = 1
                return self.global_weights.copy()

            def aggregate_paillier(self, _results, key):
                self.secure_key = key
                self.global_weights = weights.copy()
                self.round = 1
                return self.global_weights.copy(), {
                    "paillier_enabled": True,
                    "secure_aggregation": True,
                    "secure_aggregation_requested": True,
                    "display_only": False,
                    "timing_method": "measured_wall_clock",
                    "actual_crypto_operations_performed": True,
                    "aggregation_method": "fedavg_paillier_secure",
                    "key_size_bits": 2048,
                    "encryption_time_ms": 10.0,
                    "aggregation_time_ms": 2.0,
                    "decryption_time_ms": 3.0,
                    "individual_updates_decrypted": False,
                    "server_plaintext_node_updates_observable": True,
                    "cross_institution_key_isolation": False,
                    "trust_boundary": "single_host_logical_nodes",
                }

            def get_history(self):
                return [{"round": 1, "accuracy": 0.5, "loss": 0.69, "samples": 40}]

        fake_server = FakeServer()
        secure_key = object()
        with (
            patch.object(app_module, "_load_training_dataset_source", return_value=(X_train, y_train, metadata)),
            patch.object(app_module, "_load_processed_metadata", return_value=metadata),
            patch.object(app_module, "_federated_files_ready", return_value=True),
            patch.object(
                app_module,
                "_load_prepared_validation_arrays",
                return_value=(X_validation, y_validation, metadata),
            ),
            patch.object(client_module, "FederatedClient", FakeClient),
            patch.object(aggregator_module, "fedavg_server", fake_server),
            patch.object(app_module, "get_secure_aggregation_paillier", return_value=secure_key),
            patch.object(app_module, "save_training_record"),
            patch.object(app_module.user_submission_manager, "mark_used_for_training", return_value=[]),
            patch.object(app_module.db, "save_training_task_record"),
            patch.object(app_module.db, "save_model_version_record"),
        ):
            plain_response = client.post(
                "/api/admin/training/federated",
                json={"dataset_source_id": "source-a", "epochs": 1},
            )
            secure_response = client.post(
                "/api/admin/training/federated",
                json={
                    "dataset_source_id": "source-a",
                    "epochs": 1,
                    "aggregation_method": "paillier",
                },
            )
        try:
            payload = plain_response.get_json()
            self.assertEqual(plain_response.status_code, 200, payload)
            data = payload["data"]
            self.assertEqual(data["metric_scope"], "shared_holdout_validation")
            self.assertEqual(data["validation_id"], "val-a")
            self.assertEqual(data["validation_samples"], 10)
            self.assertEqual(data["accuracy"], 1.0)
            self.assertEqual(data["avg_accuracy"], 1.0)
            self.assertEqual(data["node_validation_accuracy"], 0.5)
            self.assertTrue(data["uses_shared_validation"])
            self.assertEqual(internal_validation_flags, [False] * 8)
            self.assertTrue(fake_server.force_reset)
            self.assertEqual(data["effective_epochs"], 1)
            self.assertEqual(data["aggregation_method"], "plain")
            self.assertFalse(data["secure_aggregation"])

            secure_payload = secure_response.get_json()
            self.assertEqual(secure_response.status_code, 200, secure_payload)
            secure_data = secure_payload["data"]
            self.assertEqual(secure_data["aggregation_method"], "fedavg_paillier_secure")
            self.assertTrue(secure_data["secure_aggregation"])
            self.assertTrue(secure_data["paillier"]["actual_crypto_operations_performed"])
            self.assertFalse(secure_data["paillier"]["individual_updates_decrypted"])
            self.assertIs(fake_server.secure_key, secure_key)
        finally:
            plain_response.close()
            secure_response.close()

    def test_training_pair_ignores_runtime_ensemble_and_selects_centralized_baseline(self):
        import app as app_module

        shared = {
            "dataset_source_id": "source-a",
            "preparation_id": "prep-a",
            "dataset_revision": "revision-a",
        }
        tasks = [
            {
                "id": "runtime-task",
                "task_type": "runtime",
                "status": "completed",
                "timestamp": "2026-08-09 20:00:03",
                "metadata": json.dumps({**shared, "task_type": "runtime"}),
            },
            {
                "id": "central-task",
                "task_type": "centralized",
                "status": "completed",
                "timestamp": "2026-08-09 20:00:02",
                "metadata": json.dumps({**shared, "task_type": "centralized"}),
            },
            {
                "id": "fed-task",
                "task_type": "federated",
                "status": "completed",
                "timestamp": "2026-08-09 20:00:01",
                "metadata": json.dumps({**shared, "task_type": "federated"}),
            },
        ]
        with (
            patch.object(app_module.db, "get_training_tasks", return_value=tasks),
            patch.object(app_module, "get_training_records", return_value=[]),
        ):
            centralized, federated = app_module._latest_training_pair("source-a", "prep-a")

        self.assertEqual(centralized["id"], "central-task")
        self.assertEqual(federated["id"], "fed-task")


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
