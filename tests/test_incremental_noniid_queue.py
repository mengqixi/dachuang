import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

import numpy as np


class NonIidSplitTests(unittest.TestCase):
    def test_business_split_is_deterministic_complete_and_heterogeneous(self):
        from src.preprocess.federated_splitter import (
            FEDERATED_SPLIT_VERSION,
            split_federated,
            summarize_federated_split,
        )

        rng = np.random.RandomState(7)
        X = rng.random_sample((400, 18))
        X[:, 0] = np.arange(400)
        y = np.array([0] * 240 + [1] * 160, dtype=np.int32)
        first = split_federated(X, y, seed=123)
        second = split_federated(X, y, seed=123)

        self.assertEqual(sum(len(node_x) for node_x, _ in first), len(X))
        merged_ids = np.concatenate([node_x[:, 0] for node_x, _ in first])
        np.testing.assert_array_equal(np.sort(merged_ids), np.arange(400))
        for (left_x, left_y), (right_x, right_y) in zip(first, second):
            np.testing.assert_array_equal(left_x, right_x)
            np.testing.assert_array_equal(left_y, right_y)

        summary = summarize_federated_split(X, y, first)
        attack_rates = [item["attack_rate"] for item in summary["nodes"]]
        self.assertEqual(summary["version"], FEDERATED_SPLIT_VERSION)
        self.assertGreater(max(attack_rates) - min(attack_rates), 0.20)
        self.assertTrue(all(0 <= item["quality_score"] <= 100 for item in summary["nodes"]))
        self.assertTrue(all(item["quality_score"] >= 80 for item in summary["nodes"]))


class DriftTests(unittest.TestCase):
    def test_drift_policy_distinguishes_stable_and_shifted_batches(self):
        from src.preprocess.data_drift import calculate_data_drift

        rng = np.random.RandomState(11)
        reference = rng.normal(0.3, 0.05, (500, 18))
        stable = rng.normal(0.3, 0.05, (150, 18))
        shifted = rng.normal(0.8, 0.04, (150, 18))
        reference_y = np.array([0] * 350 + [1] * 150)
        stable_y = np.array([0] * 105 + [1] * 45)
        shifted_y = np.array([0] * 30 + [1] * 120)

        stable_result = calculate_data_drift(reference, reference_y, stable, stable_y)
        shifted_result = calculate_data_drift(reference, reference_y, shifted, shifted_y)
        self.assertTrue(stable_result["available"])
        self.assertEqual(stable_result["level"], "low")
        self.assertEqual(shifted_result["level"], "high")
        self.assertGreater(shifted_result["mean_feature_psi"], stable_result["mean_feature_psi"])


class TrainingQueueStorageTests(unittest.TestCase):
    def test_queue_deduplicates_payload_and_enforces_capacity_atomically(self):
        from src.utils.data_storage import DataStorage

        with tempfile.TemporaryDirectory() as tmp:
            storage = DataStorage(str(Path(tmp) / "queue.db"))
            first = storage.enqueue_training_job("runtime", {"limit": 100}, max_pending=2)
            duplicate = storage.enqueue_training_job("runtime", {"limit": 100}, max_pending=2)
            second = storage.enqueue_training_job("federated", {"epochs": 1}, max_pending=2)

            self.assertEqual(duplicate["id"], first["id"])
            self.assertTrue(duplicate["reused"])
            self.assertNotEqual(second["id"], first["id"])
            with self.assertRaises(RuntimeError):
                storage.enqueue_training_job("centralized", {"epochs": 1}, max_pending=2)

    def test_sqlite_queue_claims_only_one_live_job(self):
        from src.utils.data_storage import DataStorage

        with tempfile.TemporaryDirectory() as tmp:
            storage = DataStorage(str(Path(tmp) / "queue.db"))
            first = storage.enqueue_training_job("runtime", {"limit": 100})
            second = storage.enqueue_training_job("federated", {"epochs": 1})

            claimed_first = storage.claim_next_training_job("worker-a", lease_seconds=600)
            self.assertEqual(claimed_first["id"], first["id"])
            self.assertEqual(claimed_first["status"], "running")
            self.assertEqual(storage.claim_next_training_job("worker-b", lease_seconds=600), {})

            storage.finish_training_job(first["id"], {"code": 200, "data": {"accuracy": 0.9}})
            claimed_second = storage.claim_next_training_job("worker-b", lease_seconds=600)
            self.assertEqual(claimed_second["id"], second["id"])
            self.assertEqual(storage.requeue_interrupted_training_jobs(), 1)
            recovered = storage.claim_next_training_job("worker-c", lease_seconds=600)
            self.assertEqual(recovered["id"], second["id"])
            storage.fail_training_job(second["id"], "invalid source")

            self.assertEqual(storage.get_training_job(first["id"])["status"], "completed")
            self.assertEqual(storage.get_training_job(second["id"])["status"], "failed")
            self.assertFalse(storage.has_pending_training_jobs())


class BackgroundWorkerLifecycleTests(unittest.TestCase):
    def test_existing_training_worker_is_woken_for_new_job(self):
        import app as app_module

        original_thread = app_module._training_worker_thread
        existing_thread = Mock()
        existing_thread.is_alive.return_value = True
        app_module._training_worker_wakeup.clear()
        app_module._training_worker_thread = existing_thread
        try:
            app_module._ensure_training_worker()
            self.assertTrue(app_module._training_worker_wakeup.is_set())
        finally:
            app_module._training_worker_thread = original_thread
            app_module._training_worker_wakeup.clear()

    def test_status_collector_starts_only_one_live_thread(self):
        from src.utils.data_storage import DataStorage

        with tempfile.TemporaryDirectory() as tmp:
            storage = DataStorage(str(Path(tmp) / "collector.db"))
            with patch("src.utils.data_storage.threading.Thread") as thread_class:
                thread_handle = thread_class.return_value
                thread_handle.is_alive.return_value = True
                self.assertTrue(storage.start_collector(lambda: {}, interval=60))
                self.assertFalse(storage.start_collector(lambda: {"cpu_usage": 1}, interval=60))
                thread_class.assert_called_once()
                thread_handle.start.assert_called_once()


class IncrementalPreparationTests(unittest.TestCase):
    def test_user_pool_change_loads_only_new_submission_ids(self):
        import app as app_module

        source = {
            "id": "user-submission-pool",
            "source_type": "user_submission_pool",
            "name": "用户可训练数据池",
            "samples": 60,
            "submission_ids": ["old-a", "old-b", "new-c"],
        }
        previous = {
            "dataset_source_id": source["id"],
            "samples": 40,
            "training_samples": 32,
            "validation_samples": 8,
            "validation_id": "val-frozen",
            "validation_split_version": app_module.SHARED_VALIDATION_SPLIT_VERSION,
            "preprocessing_version": app_module.FEATURE_NORMALIZATION_VERSION,
            "federated_split_version": app_module.FEDERATED_SPLIT_VERSION,
            "prepared_bundle_version": app_module.PREPARED_BUNDLE_VERSION,
            "process_limit": 100,
            "submission_ids": ["old-a", "old-b"],
        }
        new_x = np.zeros((20, 18), dtype=float)
        new_y = np.array([0, 1] * 10, dtype=int)
        partition = {
            "samples": 60,
            "training_samples": 52,
            "validation_samples": 8,
            "label_counts": {"0": 30, "1": 30},
            "training_label_counts": {"0": 26, "1": 26},
            "validation_label_counts": {"0": 4, "1": 4},
            "federated_split": {"heterogeneity_level": "medium"},
            "drift": {"available": True, "level": "low"},
            "node_details": [{"name": name, "samples": 13, "ready": True} for name in ("hospital", "bank", "insurance", "government")],
            "added_samples": 20,
            "previous_samples": 40,
        }
        loaded_meta = {"sources": [{"id": "new-c", "samples": 20}]}
        with app_module.app.test_request_context("/prepare", method="POST", json={}):
            with (
                patch.object(app_module, "_preparation_matches", return_value=False),
                patch.object(app_module, "_incremental_submission_change", return_value={
                    "metadata": previous,
                    "previous_ids": ["old-a", "old-b"],
                    "current_ids": ["old-a", "old-b", "new-c"],
                    "new_ids": ["new-c"],
                }),
                patch.object(app_module.user_submission_manager, "load_trainable_features", return_value=(new_x, new_y, loaded_meta)) as loader,
                patch.object(app_module, "_append_incremental_training_partitions", return_value=partition),
                patch.object(app_module, "atomic_write_json") as writer,
                patch.object(app_module, "_clear_dataset_sources_cache"),
            ):
                response = app_module._prepare_dataset_source_for_federated_locked(
                    source,
                    source_id=source["id"],
                    limit=100,
                )

        payload = response.get_json()
        self.assertEqual(payload["data"]["process_mode"], "incremental_append")
        self.assertEqual(payload["data"]["added_samples"], 20)
        self.assertEqual(payload["data"]["validation_id"], "val-frozen")
        loader.assert_called_once_with(ids=["new-c"], limit=60)
        written_metadata = writer.call_args.args[1]
        self.assertEqual(written_metadata["source_submission_ids"], ["old-a", "old-b", "new-c"])


class TrainingQueueApiTests(unittest.TestCase):
    def test_production_training_request_is_enqueued(self):
        import app as app_module

        client = app_module.app.test_client()
        with client.session_transaction() as admin_session:
            admin_session["admin_logged_in"] = True
        queued = {
            "id": "train-queued",
            "task_type": "runtime",
            "status": "queued",
            "created_at": "2026-08-12 12:00:00",
            "result": {},
        }
        previous_testing = app_module.app.config.get("TESTING")
        app_module.app.config["TESTING"] = False
        try:
            with (
                patch.object(app_module.db, "get_training_jobs", return_value=[]),
                patch.object(app_module.db, "enqueue_training_job", return_value=queued) as enqueue,
                patch.object(app_module, "_ensure_training_worker"),
                patch.object(app_module, "_admin_training_local_locked", side_effect=AssertionError("must not run inline")),
            ):
                response = client.post(
                    "/api/admin/training/local",
                    json={"dataset_source_id": "source-a", "limit": 100},
                )
        finally:
            app_module.app.config["TESTING"] = previous_testing

        self.assertEqual(response.status_code, 202)
        self.assertEqual(response.get_json()["data"]["status"], "queued")
        enqueue.assert_called_once()

    def test_worker_persists_completed_handler_output(self):
        import app as app_module
        from src.utils.data_storage import DataStorage

        with tempfile.TemporaryDirectory() as tmp:
            storage = DataStorage(str(Path(tmp) / "worker.db"))
            queued = storage.enqueue_training_job("runtime", {"limit": 100})
            job = storage.claim_next_training_job("worker-test", lease_seconds=600)
            with app_module.app.app_context():
                with (
                    patch.object(app_module, "db", storage),
                    patch.object(
                        app_module,
                        "_admin_training_local_locked",
                        return_value=app_module.jsonify(app_module.api_response(
                            msg="完成",
                            data={"model_version": "v-test", "accuracy": 0.95},
                        )),
                    ),
                ):
                    app_module._execute_training_job(job)

            completed = storage.get_training_job(queued["id"])
            self.assertEqual(completed["status"], "completed")
            self.assertEqual(completed["result"]["data"]["model_version"], "v-test")


if __name__ == "__main__":
    unittest.main()
