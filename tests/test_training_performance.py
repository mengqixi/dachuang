import unittest
import json
from unittest.mock import patch

import numpy as np

from src.federated.performance import benchmark_linear_inference, training_performance


class TrainingPerformanceTests(unittest.TestCase):
    def test_actual_inference_is_bounded_and_does_not_mutate_input(self):
        X = np.ones((2000, 18))
        weights = np.arange(19, dtype=float)
        original = weights.copy()
        result = benchmark_linear_inference(X, weights)
        self.assertEqual(result['inference_batch_samples'], 1024)
        self.assertEqual(result['inference_repeats'], 7)
        self.assertGreater(result['inference_batch_ms'], 0)
        self.assertAlmostEqual(result['inference_samples_per_second'],
                               1024 * 1000 / result['inference_batch_ms'])
        np.testing.assert_array_equal(weights, original)
        np.testing.assert_array_equal(X, np.ones((2000, 18)))

    def test_invalid_input_does_not_invent_inference_timing(self):
        self.assertEqual(benchmark_linear_inference(np.empty((0, 18)), np.zeros(19)), {})
        self.assertEqual(benchmark_linear_inference(np.ones((2, 18)), np.zeros(2)), {})

    def test_median_measurement_excludes_warmup(self):
        times = []
        for value in [1, 2, 3, 4, 5, 6, 100]:
            times.extend([0.0, value / 1000])
        with patch('src.federated.performance.time.perf_counter', side_effect=times):
            result = benchmark_linear_inference(np.ones((10, 18)), np.zeros(19))
        self.assertAlmostEqual(result['inference_batch_ms'], 4.0)

    def test_training_clock_excludes_benchmark_and_retains_stage_times(self):
        with patch('src.federated.performance.time.perf_counter', return_value=12), \
             patch('src.federated.performance.benchmark_linear_inference', return_value={}):
            result = training_performance(10, 1000, 300, [], [], aggregation_time_ms=100)
        self.assertEqual(result['training_time_ms'], 2000)
        self.assertEqual(result['training_samples_per_second'], 500)
        self.assertEqual(result['model_compute_time_ms'], 300)
        self.assertEqual(result['aggregation_time_ms'], 100)
        self.assertNotIn('inference_batch_ms', result)

    def test_ai_performance_context_is_redacted_and_comparability_is_guarded(self):
        from src.analysis.external_advisor import build_redacted_training_comparison_payload
        performance = dict(timing_version='v1', environment_id='PRIVATE_HOST_ID',
                           execution_mode='single_host_sequential', training_time_ms=100,
                           inference_batch_ms=1, inference_batch_samples=20,
                           inference_repeats=7, inference_warmup=1)
        shared = dict(dataset_source_id='s', dataset_revision='r', preparation_id='p',
                      validation_id='v', metric_scope='shared_holdout_validation',
                      validation_available=True, base_model_algorithm='linear', optimizer='batch',
                      samples=80, epochs=20, performance=performance)
        payload = build_redacted_training_comparison_payload(shared, shared)
        self.assertTrue(payload['comparison_fairness']['direct_performance_ranking_allowed'])
        self.assertNotIn('PRIVATE_HOST_ID', json.dumps(payload))
        self.assertEqual(payload['local_training']['performance']['training_time_ms'], 100)
        changed = dict(shared, performance=dict(performance, environment_id='another'))
        self.assertFalse(build_redacted_training_comparison_payload(shared, changed)[
            'comparison_fairness']['direct_performance_ranking_allowed'])
        missing = dict(shared, performance={})
        self.assertFalse(build_redacted_training_comparison_payload(missing, missing)[
            'comparison_fairness']['direct_performance_ranking_allowed'])
