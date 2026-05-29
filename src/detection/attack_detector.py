import numpy as np

try:
    import torch
    import torch.nn as nn
    import torch.optim as optim
    TORCH_AVAILABLE = True
except ImportError:
    TORCH_AVAILABLE = False

from sklearn.ensemble import IsolationForest
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
from typing import Tuple, List, Dict, Any


class DummyModule:
    """当PyTorch不可用时使用的虚拟模块"""
    def __init__(self, *args, **kwargs): pass
    def __call__(self, *args, **kwargs): return self
    def __getattr__(self, name): return self
    def forward(self, x): return x


class LSTMDetector:  # 不再继承nn.Module
    def __init__(self, input_dim: int, hidden_dim: int = 128, num_layers: int = 2, dropout: float = 0.3):
        self.input_dim = input_dim
        self.hidden_dim = hidden_dim
        self.num_layers = num_layers
        self.dropout = dropout
        self._torch_available = TORCH_AVAILABLE

        if TORCH_AVAILABLE:
            self._build_model()
        else:
            self.model = None
            print("INFO: LSTMDetector running in fallback mode (PyTorch not available)")

    def _build_model(self):
        class _LSTM(nn.Module):
            def __init__(self, input_dim, hidden_dim, num_layers, dropout):
                super().__init__()
                self.lstm = nn.LSTM(input_dim, hidden_dim, num_layers, batch_first=True, dropout=dropout)
                self.fc = nn.Sequential(
                    nn.Linear(hidden_dim, 64), nn.ReLU(), nn.Dropout(dropout),
                    nn.Linear(64, 1), nn.Sigmoid()
                )
            def forward(self, x):
                _, (h_n, _) = self.lstm(x)
                return self.fc(h_n[-1])

        self.model = _LSTM(self.input_dim, self.hidden_dim, self.num_layers, self.dropout)

    def forward(self, x):
        if self.model is not None:
            return self.model(x)
        return x

    def parameters(self):
        if self.model is not None:
            return self.model.parameters()
        return []

    def train(self, mode=True):
        if self.model is not None:
            self.model.train(mode)

    def eval(self):
        if self.model is not None:
            self.model.eval()

    def state_dict(self):
        if self.model is not None:
            return self.model.state_dict()
        return {}

    def load_state_dict(self, state):
        if self.model is not None:
            self.model.load_state_dict(state)

    def to(self, device):
        if self.model is not None:
            return self.model.to(device)
        return self


class IsolationForestDetector:
    def __init__(self, n_estimators: int = 100, contamination: float = 0.1):
        self.model = IsolationForest(n_estimators=n_estimators, contamination=contamination, random_state=42)

    def fit(self, X: np.ndarray) -> None:
        self.model.fit(X)

    def predict(self, X: np.ndarray) -> np.ndarray:
        predictions = self.model.predict(X)
        return np.where(predictions == -1, 1, 0)

    def predict_proba(self, X: np.ndarray) -> np.ndarray:
        scores = self.model.decision_function(X)
        prob = 1 - (scores - scores.min()) / (scores.max() - scores.min() + 1e-8)
        return prob


class HybridAttackDetector:
    def __init__(self, feature_dim: int = 18, lstm_hidden_dim: int = 128):
        self.isolation_forest = IsolationForestDetector()
        self.lstm = LSTMDetector(input_dim=feature_dim, hidden_dim=lstm_hidden_dim)
        if TORCH_AVAILABLE:
            self.device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
            self.lstm.to(self.device)
        else:
            self.device = None
        self.scaler = None

    def fit_isolation_forest(self, X: np.ndarray) -> None:
        self.isolation_forest.fit(X)

    def fit_lstm(self, X_seq: np.ndarray, y: np.ndarray,
                 epochs: int = 50, batch_size: int = 64, lr: float = 0.001) -> Dict:
        if not TORCH_AVAILABLE:
            return {'loss': [], 'accuracy': []}

        X_tensor = torch.tensor(X_seq, dtype=torch.float32).to(self.device)
        y_tensor = torch.tensor(y, dtype=torch.float32).to(self.device)

        criterion = nn.BCELoss()
        optimizer = optim.Adam(self.lstm.parameters(), lr=lr)

        history = {'loss': [], 'accuracy': []}

        for epoch in range(epochs):
            self.lstm.train()
            permutation = torch.randperm(X_tensor.size(0))

            epoch_loss = 0.0
            epoch_correct = 0
            epoch_total = 0

            for i in range(0, X_tensor.size(0), batch_size):
                indices = permutation[i:i+batch_size]
                batch_x, batch_y = X_tensor[indices], y_tensor[indices]

                optimizer.zero_grad()
                outputs = self.lstm.forward(batch_x).squeeze()
                loss = criterion(outputs, batch_y)
                loss.backward()
                optimizer.step()

                epoch_loss += loss.item() * batch_x.size(0)
                predictions = (outputs > 0.5).float()
                epoch_correct += (predictions == batch_y).sum().item()
                epoch_total += batch_y.size(0)

            epoch_loss /= epoch_total
            epoch_acc = epoch_correct / epoch_total
            history['loss'].append(epoch_loss)
            history['accuracy'].append(epoch_acc)

        return history

    def predict(self, X: np.ndarray, X_seq: np.ndarray = None) -> Tuple[np.ndarray, np.ndarray, np.ndarray]:
        if_preds = self.isolation_forest.predict(X)

        lstm_preds = np.zeros(len(if_preds))
        if X_seq is not None and self.device is not None:
            self.lstm.eval()
            with torch.no_grad():
                X_tensor = torch.tensor(X_seq, dtype=torch.float32).to(self.device)
                lstm_preds = self.lstm.forward(X_tensor).cpu().numpy().squeeze()
                lstm_preds = (lstm_preds > 0.5).astype(int)

        combined_preds = np.logical_or(if_preds, lstm_preds).astype(int)
        return combined_preds, if_preds, lstm_preds

    def predict_proba(self, X: np.ndarray, X_seq: np.ndarray = None) -> np.ndarray:
        if_probs = self.isolation_forest.predict_proba(X)

        lstm_probs = np.zeros(len(if_probs))
        if X_seq is not None and self.device is not None:
            self.lstm.eval()
            with torch.no_grad():
                X_tensor = torch.tensor(X_seq, dtype=torch.float32).to(self.device)
                lstm_probs = self.lstm.forward(X_tensor).cpu().numpy().squeeze()

        combined_probs = (if_probs + lstm_probs) / 2
        return combined_probs

    def evaluate(self, X: np.ndarray, y: np.ndarray, X_seq: np.ndarray = None) -> Dict[str, float]:
        preds, _, _ = self.predict(X, X_seq)
        return {
            'accuracy': accuracy_score(y, preds),
            'precision': precision_score(y, preds),
            'recall': recall_score(y, preds),
            'f1': f1_score(y, preds),
        }

    def save(self, path: str) -> None:
        if TORCH_AVAILABLE:
            torch.save({'lstm_state_dict': self.lstm.state_dict(), 'scaler': self.scaler}, path)

    def load(self, path: str) -> None:
        if TORCH_AVAILABLE:
            checkpoint = torch.load(path, map_location=self.device)
            self.lstm.load_state_dict(checkpoint['lstm_state_dict'])
            self.scaler = checkpoint.get('scaler')
