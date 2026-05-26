import json
import requests
from typing import Dict, List, Any
import os

class FATEClient:
    def __init__(self, host: str = "localhost", port: int = 9380):
        self.host = host
        self.port = port
        self.base_url = f"http://{host}:{port}"

    def upload_data(self, file_path: str, namespace: str, table_name: str) -> Dict:
        url = f"{self.base_url}/v1/fate/job/upload"
        data = {
            "file": open(file_path, "rb"),
            "namespace": namespace,
            "table_name": table_name
        }
        response = requests.post(url, files=data)
        return response.json()

    def submit_job(self, dsl_path: str, conf_path: str) -> Dict:
        url = f"{self.base_url}/v1/fate/job/submit"
        
        with open(dsl_path, 'r') as f:
            dsl = json.load(f)
        
        with open(conf_path, 'r') as f:
            conf = json.load(f)
        
        data = {
            "dsl": dsl,
            "conf": conf
        }
        
        response = requests.post(url, json=data)
        return response.json()

    def query_job(self, job_id: str) -> Dict:
        url = f"{self.base_url}/v1/fate/job/{job_id}"
        response = requests.get(url)
        return response.json()

    def download_model(self, job_id: str, output_path: str) -> bool:
        url = f"{self.base_url}/v1/fate/model/{job_id}/download"
        response = requests.get(url)
        
        if response.status_code == 200:
            with open(output_path, 'wb') as f:
                f.write(response.content)
            return True
        return False

    def list_jobs(self, limit: int = 10) -> List[Dict]:
        url = f"{self.base_url}/v1/fate/job/list?limit={limit}"
        response = requests.get(url)
        return response.json()

    def create_session(self, session_id: str) -> Dict:
        url = f"{self.base_url}/v1/fate/session/{session_id}"
        response = requests.post(url)
        return response.json()

    def destroy_session(self, session_id: str) -> Dict:
        url = f"{self.base_url}/v1/fate/session/{session_id}"
        response = requests.delete(url)
        return response.json()

class FederatedTrainingManager:
    def __init__(self, fate_client: FATEClient):
        self.fate_client = fate_client
        self.current_job_id = None

    def prepare_data(self, local_data_path: str, party_id: str = "0") -> Dict:
        namespace = f"party_{party_id}"
        table_name = "encrypted_training_data"
        
        result = self.fate_client.upload_data(local_data_path, namespace, table_name)
        return result

    def run_federated_training(self, dsl_config: Dict, runtime_config: Dict) -> Dict:
        dsl_path = "/tmp/training_dsl.json"
        conf_path = "/tmp/training_conf.json"
        
        with open(dsl_path, 'w') as f:
            json.dump(dsl_config, f, indent=2)
        
        with open(conf_path, 'w') as f:
            json.dump(runtime_config, f, indent=2)
        
        result = self.fate_client.submit_job(dsl_path, conf_path)
        self.current_job_id = result.get('jobId')
        
        return result

    def monitor_training(self, job_id: str = None) -> Dict:
        if job_id is None:
            job_id = self.current_job_id
        
        if job_id is None:
            return {"error": "No active job"}
        
        return self.fate_client.query_job(job_id)

    def get_model(self, output_path: str, job_id: str = None) -> bool:
        if job_id is None:
            job_id = self.current_job_id
        
        if job_id is None:
            return False
        
        return self.fate_client.download_model(job_id, output_path)

class SecureAggregationClient:
    def __init__(self, party_id: str, fate_client: FATEClient):
        self.party_id = party_id
        self.fate_client = fate_client
        self.aggregation_results = []

    def send_local_gradient(self, gradient: List[float], task_id: str) -> Dict:
        url = f"{self.fate_client.base_url}/v1/fate/secure_aggregation/{task_id}/gradient"
        
        data = {
            "party_id": self.party_id,
            "gradient": gradient,
            "timestamp": "2024-01-01T00:00:00Z"
        }
        
        response = requests.post(url, json=data)
        return response.json()

    def receive_aggregated_gradient(self, task_id: str) -> List[float]:
        url = f"{self.fate_client.base_url}/v1/fate/secure_aggregation/{task_id}/result"
        response = requests.get(url)
        result = response.json()
        return result.get('aggregated_gradient', [])

    def participate_in_aggregation(self, local_gradient: List[float], task_id: str) -> List[float]:
        self.send_local_gradient(local_gradient, task_id)
        aggregated = self.receive_aggregated_gradient(task_id)
        self.aggregation_results.append(aggregated)
        return aggregated