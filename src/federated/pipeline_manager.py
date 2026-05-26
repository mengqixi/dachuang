import json
from typing import Dict, List, Any

class PipelineBuilder:
    def __init__(self):
        self.pipeline = {
            "components": [],
            "data_connections": [],
            "model_connections": []
        }

    def add_data_source(self, name: str, path: str, party_id: str = "0") -> None:
        component = {
            "name": name,
            "type": "DataReader",
            "party_id": party_id,
            "params": {
                "path": path,
                "format": "csv",
                "delimiter": ","
            }
        }
        self.pipeline["components"].append(component)

    def add_feature_engineering(self, name: str, input_component: str, 
                               operations: List[Dict]) -> None:
        component = {
            "name": name,
            "type": "FeatureEngineering",
            "input": input_component,
            "params": {
                "operations": operations
            }
        }
        self.pipeline["components"].append(component)
        
        self.pipeline["data_connections"].append({
            "from": input_component,
            "to": name
        })

    def add_encryption(self, name: str, input_component: str, 
                       algorithm: str = "paillier") -> None:
        component = {
            "name": name,
            "type": "Encryption",
            "input": input_component,
            "params": {
                "algorithm": algorithm,
                "key_size": 2048
            }
        }
        self.pipeline["components"].append(component)
        
        self.pipeline["data_connections"].append({
            "from": input_component,
            "to": name
        })

    def add_model_training(self, name: str, input_component: str, 
                          model_type: str = "logistic_regression",
                          params: Dict = None) -> None:
        component = {
            "name": name,
            "type": "ModelTraining",
            "input": input_component,
            "params": params or {}
        }
        component["params"]["model_type"] = model_type
        
        self.pipeline["components"].append(component)
        
        self.pipeline["data_connections"].append({
            "from": input_component,
            "to": name
        })

    def add_model_evaluation(self, name: str, model_component: str, 
                             data_component: str) -> None:
        component = {
            "name": name,
            "type": "ModelEvaluation",
            "params": {
                "metrics": ["accuracy", "precision", "recall", "f1"]
            }
        }
        self.pipeline["components"].append(component)
        
        self.pipeline["model_connections"].append({
            "from": model_component,
            "to": name
        })
        self.pipeline["data_connections"].append({
            "from": data_component,
            "to": name
        })

    def build(self) -> Dict:
        return self.pipeline

    def save(self, path: str) -> None:
        with open(path, 'w') as f:
            json.dump(self.pipeline, f, indent=2)

class FederatedPipelineManager:
    def __init__(self):
        self.builder = PipelineBuilder()
        self.config = {}

    def create_attack_detection_pipeline(self, data_path: str, party_id: str = "0") -> Dict:
        self.builder.add_data_source("raw_data", data_path, party_id)
        
        self.builder.add_feature_engineering("feature_processing", "raw_data", [
            {"operation": "normalize", "columns": "all"},
            {"operation": "feature_selection", "method": "mutual_info"},
            {"operation": "dimension_reduction", "method": "pca", "components": 18}
        ])
        
        self.builder.add_encryption("encrypted_features", "feature_processing", "paillier")
        
        self.builder.add_model_training("attack_detector", "encrypted_features", 
                                       model_type="hybrid_isolation_lstm",
                                       params={
                                           "n_estimators": 100,
                                           "lstm_hidden_units": 128,
                                           "epochs": 50
                                       })
        
        self.builder.add_model_evaluation("model_eval", "attack_detector", "raw_data")
        
        return self.builder.build()

    def create_secure_aggregation_pipeline(self, parties: List[str]) -> Dict:
        pipeline = {
            "parties": parties,
            "protocol": "aby3",
            "aggregation_method": "secure_sum",
            "components": []
        }
        
        for party in parties:
            component = {
                "party_id": party,
                "type": "SecureAggregator",
                "params": {
                    "threshold": 0.001,
                    "max_iterations": 100
                }
            }
            pipeline["components"].append(component)
        
        return pipeline

    def generate_fate_config(self, pipeline: Dict, output_path: str) -> None:
        fate_config = {
            "dsl_version": "2.0",
            "initiator": {"party_id": "0", "role": "guest"},
            "roles": {
                "guest": ["0"],
                "host": ["1", "2"]
            },
            "component_parameters": {},
            "algorithm_parameters": {}
        }
        
        for component in pipeline.get("components", []):
            fate_config["component_parameters"][component["name"]] = component.get("params", {})
        
        with open(output_path, 'w') as f:
            json.dump(fate_config, f, indent=2)