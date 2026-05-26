import numpy as np
import torch
import torch.nn as nn
import torch.optim as optim
from sklearn.ensemble import IsolationForest
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
from typing import Tuple, List, Dict, Any

class IsolationForestDetector:
    def __init__(self, n_estimators: int = 100, contamination: float = 0.1):
        self.model = IsolationForest(
            n_estimators=n_estimators,
            contamination=contamination,
            random_state=42
        )

    def fit(self, X: np.ndarray) -> None:
        self.model.fit(X)

    def predict(self, X: np.ndarray) -> np.ndarray:
        predictions = self.model.predict(X)
        return np.where(predictions == -1, 1, 0)

    def predict_proba(self, X: np.ndarray) -> np.ndarray:
        scores = self.model.decision_function(X)
        prob = 1 - (scores - scores.min()) / (scores.max() - scores.min() + 1e-8)
        return prob

class LSTMDetector(nn.Module):
    def __init__(self, input_dim: int, hidden_dim: int = 128, num_layers: int = 2, dropout: float = 0.3):
        super(LSTMDetector, self).__init__()
        
        self.lstm = nn.LSTM(
            input_size=input_dim,
            hidden_size=hidden_dim,
            num_layers=num_layers,
            batch_first=True,
            dropout=dropout
        )
        
        self.fc = nn.Sequential(
            nn.Linear(hidden_dim, 64),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(64, 1),
            nn.Sigmoid()
        )

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        _, (h_n, _) = self.lstm(x)
        last_hidden = h_n[-1]
        output = self.fc(last_hidden)
        return output

class HybridAttackDetector:
    def __init__(self, feature_dim: int = 18, lstm_hidden_dim: int = 128):
        self.isolation_forest = IsolationForestDetector()
        self.lstm = LSTMDetector(input_dim=feature_dim, hidden_dim=lstm_hidden_dim)
        self.device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
        self.lstm.to(self.device)
        self.scaler = None

    def fit_isolation_forest(self, X: np.ndarray) -> None:
        self.isolation_forest.fit(X)

    def fit_lstm(self, X_seq: np.ndarray, y: np.ndarray, 
                 epochs: int = 50, batch_size: int = 64, lr: float = 0.001) -> Dict:
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
                outputs = self.lstm(batch_x).squeeze()
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
            
            if (epoch + 1) % 10 == 0:
                print(f"Epoch {epoch+1}/{epochs}, Loss: {epoch_loss:.4f}, Accuracy: {epoch_acc:.4f}")
        
        return history

    def predict(self, X: np.ndarray, X_seq: np.ndarray = None) -> Tuple[np.ndarray, np.ndarray]:
        if_preds = self.isolation_forest.predict(X)
        
        if X_seq is not None:
            self.lstm.eval()
            with torch.no_grad():
                X_tensor = torch.tensor(X_seq, dtype=torch.float32).to(self.device)
                lstm_preds = self.lstm(X_tensor).cpu().numpy().squeeze()
                lstm_preds = (lstm_preds > 0.5).astype(int)
        else:
            lstm_preds = np.zeros(len(if_preds))
        
        combined_preds = np.logical_or(if_preds, lstm_preds).astype(int)
        return combined_preds, if_preds, lstm_preds

    def predict_proba(self, X: np.ndarray, X_seq: np.ndarray = None) -> np.ndarray:
        if_probs = self.isolation_forest.predict_proba(X)
        
        if X_seq is not None:
            self.lstm.eval()
            with torch.no_grad():
                X_tensor = torch.tensor(X_seq, dtype=torch.float32).to(self.device)
                lstm_probs = self.lstm(X_tensor).cpu().numpy().squeeze()
        else:
            lstm_probs = np.zeros(len(if_probs))
        
        combined_probs = (if_probs + lstm_probs) / 2
        return combined_probs

    def evaluate(self, X: np.ndarray, y: np.ndarray, 
                 X_seq: np.ndarray = None) -> Dict[str, float]:
        preds, _, _ = self.predict(X, X_seq)
        
        return {
            'accuracy': accuracy_score(y, preds),
            'precision': precision_score(y, preds),
            'recall': recall_score(y, preds),
            'f1': f1_score(y, preds)
        }

    def save(self, path: str) -> None:
        torch.save({
            'lstm_state_dict': self.lstm.state_dict(),
            'scaler': self.scaler
        }, path)

    def load(self, path: str) -> None:
        checkpoint = torch.load(path, map_location=self.device)
        self.lstm.load_state_dict(checkpoint['lstm_state_dict'])
        self.scaler = checkpoint.get('scaler')