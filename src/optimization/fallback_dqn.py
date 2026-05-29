"""回退DQN实现（当Stable-Baselines3不可用时）

提供基于PyTorch的DQN训练和推理，与EncryptionEnv兼容。
训练后的模型保存在实例中，可重复用于预测。
"""

from typing import List, Tuple, Optional
import numpy as np
from loguru import logger

try:
    import torch
    import torch.nn as nn
    import torch.optim as optim
    import torch.nn.functional as F
    TORCH_AVAILABLE = True
except ImportError:
    TORCH_AVAILABLE = False


if TORCH_AVAILABLE:

    class DQNNetwork(nn.Module):
        """DQN神经网络"""

        def __init__(self, state_dim: int, action_dim: int):
            super().__init__()
            self.net = nn.Sequential(
                nn.Linear(state_dim, 128),
                nn.ReLU(),
                nn.Linear(128, 64),
                nn.ReLU(),
                nn.Linear(64, action_dim),
            )

        def forward(self, x: torch.Tensor) -> torch.Tensor:
            return self.net(x)


    class ReplayBuffer:
        """经验回放缓冲区"""

        def __init__(self, capacity: int = 50000):
            self.capacity = capacity
            self.buffer = []
            self.pos = 0

        def push(self, state, action, reward, next_state, terminated):
            if len(self.buffer) < self.capacity:
                self.buffer.append(None)
            self.buffer[self.pos] = (state, action, reward, next_state, terminated)
            self.pos = (self.pos + 1) % self.capacity

        def sample(self, batch_size: int) -> Tuple:
            indices = np.random.randint(0, len(self.buffer), size=batch_size)
            batch = [self.buffer[i] for i in indices]
            return (
                torch.FloatTensor(np.array([b[0] for b in batch])),
                torch.LongTensor(np.array([b[1] for b in batch])).unsqueeze(1),
                torch.FloatTensor(np.array([b[2] for b in batch])).unsqueeze(1),
                torch.FloatTensor(np.array([b[3] for b in batch])),
                torch.FloatTensor(np.array([b[4] for b in batch])).unsqueeze(1),
            )

        def __len__(self) -> int:
            return len(self.buffer)


    class FallbackDQN:
        """回退DQN训练器（实例化后可保留训练好的网络）

        用法:
            dqn = FallbackDQN(state_dim=4, action_dim=9)
            rewards = dqn.train(env, total_timesteps=10000)
            action, q_value = dqn.predict(state)
        """

        def __init__(self, state_dim: int, action_dim: int, device=None):
            self.state_dim = state_dim
            self.action_dim = action_dim
            self.device = device or torch.device("cuda" if torch.cuda.is_available() else "cpu")

            self.policy_net = DQNNetwork(state_dim, action_dim).to(self.device)
            self.target_net = DQNNetwork(state_dim, action_dim).to(self.device)
            self.target_net.load_state_dict(self.policy_net.state_dict())
            self.target_net.eval()
            self._trained = False

        def train(self, env, total_timesteps: int = 10000) -> List[float]:
            """训练DQN网络并存储权重到 self.policy_net

            Args:
                env: Gymnasium环境
                total_timesteps: 总训练步数

            Returns:
                每个episode的累计奖励列表
            """
            device = self.device
            policy_net = self.policy_net
            target_net = self.target_net

            optimizer = optim.Adam(policy_net.parameters(), lr=3e-4)
            buffer = ReplayBuffer(50000)

            batch_size = 64
            gamma = 0.99
            epsilon = 1.0
            epsilon_min = 0.05
            epsilon_decay = 0.995
            target_update = 500
            learning_starts = 1000

            state, _ = env.reset()
            episode_rewards = []
            episode_reward = 0.0

            for step in range(total_timesteps):
                # epsilon-greedy
                if np.random.random() < epsilon:
                    action = env.action_space.sample()
                else:
                    with torch.no_grad():
                        q_values = policy_net(torch.FloatTensor(state).unsqueeze(0).to(device))
                        action = q_values.argmax().item()

                next_state, reward, terminated, truncated, _ = env.step(action)
                done = terminated or truncated
                buffer.push(state, action, reward, next_state, done)
                episode_reward += reward

                state = next_state
                if done:
                    episode_rewards.append(episode_reward)
                    episode_reward = 0.0
                    state, _ = env.reset()

                # 训练步骤
                if len(buffer) >= learning_starts and step % 4 == 0:
                    states, actions, rewards_, next_states, dones = buffer.sample(batch_size)
                    states, actions = states.to(device), actions.to(device)
                    rewards_, dones = rewards_.to(device), dones.to(device)
                    next_states = next_states.to(device)

                    current_q = policy_net(states).gather(1, actions)
                    with torch.no_grad():
                        next_q = target_net(next_states).max(1, keepdim=True)[0]
                        target_q = rewards_ + gamma * next_q * (1 - dones)

                    loss = F.mse_loss(current_q, target_q)
                    optimizer.zero_grad()
                    loss.backward()
                    optimizer.step()

                # 更新target网络
                if step > 0 and step % target_update == 0:
                    target_net.load_state_dict(policy_net.state_dict())

                # 衰减epsilon
                epsilon = max(epsilon_min, epsilon * epsilon_decay)

            self._trained = True
            logger.info("回退DQN训练完成: %d步, %d episodes" % (total_timesteps, len(episode_rewards)))
            return episode_rewards if episode_rewards else [0.0]

        def predict(self, state: np.ndarray, deterministic: bool = True) -> Tuple[int, float]:
            """使用训练好的policy_net预测动作

            Args:
                state: 4维状态向量
                deterministic: 是否确定性预测

            Returns:
                (action, q_value)
            """
            if not self._trained:
                return 0, 0.0

            self.policy_net.eval()
            with torch.no_grad():
                q_values = self.policy_net(torch.FloatTensor(state).unsqueeze(0).to(self.device))
                if deterministic:
                    action = q_values.argmax().item()
                else:
                    probs = F.softmax(q_values, dim=1)
                    action = torch.multinomial(probs, 1).item()
                q_value = q_values.max().item()
            return action, q_value

        def is_trained(self) -> bool:
            return self._trained

else:
    # PyTorch不可用时的最小回退
    class FallbackDQN:
        def __init__(self, state_dim: int, action_dim: int, device=None):
            self.state_dim = state_dim
            self.action_dim = action_dim
            self._trained = False

        def train(self, env, total_timesteps: int = 10000) -> List[float]:
            logger.warning("PyTorch不可用，使用随机策略")
            self._trained = False
            return [0.0]

        def predict(self, state: np.ndarray, deterministic: bool = True) -> Tuple[int, float]:
            import random
            return random.randint(0, self.action_dim - 1), 0.0

        def is_trained(self) -> bool:
            return self._trained
