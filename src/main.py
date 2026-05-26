import argparse
import logging
import yaml
import sys
import os

from src.encryption.paillier import Paillier, EncryptedGradientAggregator
from src.detection.feature_extractor import FeatureExtractor
from src.detection.attack_detector import HybridAttackDetector
from src.optimization.rl_optimizer import AdaptiveEncryptionManager
from src.federated.fate_client import FATEClient, FederatedTrainingManager
from src.federated.pipeline_manager import FederatedPipelineManager

def setup_logging():
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        handlers=[
            logging.StreamHandler(sys.stdout),
            logging.FileHandler("logs/app.log")
        ]
    )

def load_config(config_path: str = "config/config.yaml") -> dict:
    with open(config_path, 'r') as f:
        return yaml.safe_load(f)

def main():
    parser = argparse.ArgumentParser(description="Crypto Attack Detection System")
    parser.add_argument("--config", default="config/config.yaml", help="Path to config file")
    parser.add_argument("--mode", default="detect", choices=["detect", "train", "optimize", "federated"])
    args = parser.parse_args()

    setup_logging()
    logger = logging.getLogger(__name__)

    config = load_config(args.config)
    logger.info(f"Loaded configuration from {args.config}")

    if args.mode == "detect":
        run_detection(config)
    elif args.mode == "train":
        run_training(config)
    elif args.mode == "optimize":
        run_optimization(config)
    elif args.mode == "federated":
        run_federated(config)

def run_detection(config: dict):
    logger = logging.getLogger(__name__)
    logger.info("Running attack detection mode")

    detector = HybridAttackDetector(feature_dim=config['detection']['feature_dim'])
    
    feature_extractor = FeatureExtractor()
    
    sample_log = {
        'key_generation_time': 0.12,
        'ciphertext': 'encrypted_data_here',
        'hash_collisions': 0,
        'request_frequency': 100.0,
        'response_time': 0.05,
        'payload_size': 1024,
        'connection_duration': 10.5,
        'packet_interarrival': 0.01,
        'failed_attempts': 0,
        'session_duration': 300.0,
        'request_size_variance': 100.0,
        'encryption_rounds': 1,
        'decryption_success_rate': 1.0,
        'memory_usage': 0.3,
        'cpu_usage': 0.2,
        'network_latency': 0.01,
        'protocol_violations': 0,
        'anomaly_score': 0.1
    }
    
    features = feature_extractor.extract_features(sample_log)
    features = feature_extractor.normalize_features(features)
    
    prediction, _, _ = detector.predict(features.reshape(1, -1))
    logger.info(f"Attack detection result: {'Attack detected' if prediction[0] == 1 else 'Normal traffic'}")

def run_training(config: dict):
    logger = logging.getLogger(__name__)
    logger.info("Running training mode")

    detector = HybridAttackDetector(
        feature_dim=config['detection']['feature_dim'],
        lstm_hidden_dim=config['detection']['lstm']['hidden_units']
    )

    logger.info("Training Isolation Forest...")
    X_train = np.random.randn(1000, config['detection']['feature_dim'])
    detector.fit_isolation_forest(X_train)

    logger.info("Training LSTM model...")
    X_seq_train = np.random.randn(500, 10, config['detection']['feature_dim'])
    y_train = np.random.randint(0, 2, 500)
    
    history = detector.fit_lstm(
        X_seq_train, 
        y_train,
        epochs=config['detection']['lstm']['epochs'],
        batch_size=config['detection']['lstm']['batch_size']
    )
    
    logger.info(f"Training completed. Final accuracy: {history['accuracy'][-1]:.4f}")

def run_optimization(config: dict):
    logger = logging.getLogger(__name__)
    logger.info("Running optimization mode")

    optimizer = AdaptiveEncryptionManager()
    optimizer.train_agent(episodes=config['optimization']['q_learning']['episodes'])

    test_anomaly_scores = [0.1, 0.3, 0.6, 0.9]
    for score in test_anomaly_scores:
        result = optimizer.update(score, False, {})
        logger.info(f"Anomaly score: {score:.2f} -> Config: {result}")

def run_federated(config: dict):
    logger = logging.getLogger(__name__)
    logger.info("Running federated learning mode")

    fate_client = FATEClient(
        host=config['fate']['host'],
        port=config['fate']['port']
    )

    pipeline_manager = FederatedPipelineManager()
    
    pipeline = pipeline_manager.create_attack_detection_pipeline(
        data_path="/app/data/training_data.csv",
        party_id="0"
    )
    
    pipeline_manager.generate_fate_config(pipeline, "/tmp/fate_config.json")
    logger.info("Generated FATE configuration")

    training_manager = FederatedTrainingManager(fate_client)
    
    try:
        result = training_manager.run_federated_training(
            dsl_config=pipeline,
            runtime_config={"job_type": "train"}
        )
        logger.info(f"Submitted federated training job: {result}")
    except Exception as e:
        logger.error(f"Failed to submit federated job: {e}")

if __name__ == "__main__":
    import numpy as np
    main()