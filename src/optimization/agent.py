"""表格型Q-learning强化学习智能体

使用表格型Q-learning替代DQN进行加密参数自适应优化。
状态空间经离散化后映射为Q-table索引，内存占用<1MB。
"""

import os
import json
import random
from typing import Dict, List, Tuple, Any, Optional

import numpy as np
from loguru import logger

from src.optimization.environment import EncryptionEnv


class QLearningAgent:
    """表格型Q-learning智能体

    将连续4维状态离散化为108种组合，维护972条Q值表。
    支持训练、预测、保存、加载。

    属性:
        q_table: Q值表，形状 (n_states, n_actions)
        lr: 学习率
        gamma: 折扣因子
        epsilon: 当前探索率
        epsilon_min: 最小探索率
        epsilon_decay: 探索率衰减系数
        is_trained: 是否经过训练
    """

    # 状态离散化边界
    CPU_BINS = [0.3, 0.7]       # 低(<0.3) / 中(0.3-0.7) / 高(>0.7)
    MEM_BINS = [0.3, 0.7]
    ACC_BINS = [0.9, 0.95]      # 低(<0.9) / 中(0.9-0.95) / 高(>0.95)

    def __init__(
        self,
        learning_rate: float = 0.1,
        gamma: float = 0.9,
        epsilon_start: float = 0.3,
        epsilon_min: float = 0.01,
        epsilon_decay: float = 0.995,
    ):
        self.lr = learning_rate
        self.gamma = gamma
        self.epsilon = epsilon_start
        self.epsilon_min = epsilon_min
        self.epsilon_decay = epsilon_decay

        self.env = EncryptionEnv()
        self.n_actions = self.env.action_space.n
        # 108 states(4×3×3×3) × 9 actions
        self.n_states = 108
        self.q_table = np.zeros((self.n_states, self.n_actions), dtype=np.float32)
        self._trained = False
        self._train_step = 0
        logger.debug(
            "QLearningAgent 初始化: Q-table=%dx%d (%.1fKB)" %
            (self.n_states, self.n_actions, self.q_table.nbytes / 1024)
        )

    def _bin_index(self, value: float, bins: List[float]) -> int:
        """将连续值映射为离散bin索引"""
        if value <= bins[0]:
            return 0
        if value <= bins[1]:
            return 1
        return 2

    def discretize_state(self, state: np.ndarray) -> str:
        """将4维连续状态离散化为字符串key

        Args:
            state: [risk_level, cpu_usage, memory_usage, model_accuracy]

        Returns:
            e.g. "2_1_0_2"
        """
        risk_idx = int(np.clip(state[0], 0, 3))
        cpu_idx = self._bin_index(float(state[1]), self.CPU_BINS)
        mem_idx = self._bin_index(float(state[2]), self.MEM_BINS)
        acc_idx = self._bin_index(float(state[3]), self.ACC_BINS)
        return f"{risk_idx}_{cpu_idx}_{mem_idx}_{acc_idx}"

    def _state_to_idx(self, state_key: str) -> int:
        """将离散状态字符串映射为Q-table行索引 [0, 108)"""
        parts = [int(x) for x in state_key.split("_")]
        risk, cpu, mem, acc = parts
        return (risk * 3 * 3 * 3) + (cpu * 3 * 3) + (mem * 3) + acc

    def predict(self, state: np.ndarray, deterministic: bool = True) -> Tuple[int, float]:
        """根据状态选择最优动作

        Args:
            state: 4维状态向量
            deterministic: True=贪心, False=epsilon-greedy

        Returns:
            (action_idx, max_q_value)
        """
        state_key = self.discretize_state(state)
        s_idx = self._state_to_idx(state_key)

        if not deterministic and random.random() < self.epsilon:
            action = random.randint(0, self.n_actions - 1)
            q_val = self.q_table[s_idx, action]
        else:
            action = int(np.argmax(self.q_table[s_idx]))
            q_val = float(self.q_table[s_idx, action])

        return action, q_val

    def train(self, total_timesteps: int = 10000) -> List[float]:
        """训练Q-learning智能体

        通过与环境交互采集经验并更新Q-table。

        Args:
            total_timesteps: 总训练步数

        Returns:
            每个episode的累计奖励列表
        """
        logger.info("开始Q-learning训练: %d步" % total_timesteps)
        episode_rewards = []
        total_reward = 0.0
        episode = 0

        obs, _ = self.env.reset()
        state_key = self.discretize_state(obs)
        s_idx = self._state_to_idx(state_key)

        for step in range(total_timesteps):
            # epsilon-greedy 选择动作
            if random.random() < self.epsilon:
                action = self.env.action_space.sample()
            else:
                action = int(np.argmax(self.q_table[s_idx]))

            # 执行动作
            next_obs, reward, terminated, truncated, _ = self.env.step(action)
            next_key = self.discretize_state(next_obs)
            next_idx = self._state_to_idx(next_key)

            # Q-learning 更新公式
            best_next_q = float(np.max(self.q_table[next_idx]))
            current_q = float(self.q_table[s_idx, action])
            new_q = current_q + self.lr * (reward + self.gamma * best_next_q - current_q)
            self.q_table[s_idx, action] = new_q

            total_reward += reward
            self._train_step += 1

            # 转移到下一状态
            obs = next_obs
            s_idx = next_idx

            # 每500步衰减探索率
            if self._train_step % 500 == 0:
                self.epsilon = max(self.epsilon_min, self.epsilon * self.epsilon_decay)

            # episode结束
            if terminated or truncated:
                episode_rewards.append(total_reward)
                episode += 1
                if episode % 100 == 0:
                    avg = np.mean(episode_rewards[-100:]) if episode_rewards else 0
                    logger.info("Q-learning Episode %d: avg_reward=%.2f, eps=%.3f" %
                               (episode, avg, self.epsilon))
                obs, _ = self.env.reset()
                s_idx = self._state_to_idx(self.discretize_state(obs))
                total_reward = 0.0

        self._trained = True
        final_avg = np.mean(episode_rewards[-100:]) if len(episode_rewards) >= 100 else 0
        logger.info("Q-learning训练完成: %d episodes, avg_reward=%.2f" %
                   (episode, final_avg))
        return episode_rewards

    def decode_action(self, action: int) -> Tuple[int, int]:
        """将动作解码为(密钥长度, 加密轮数)"""
        return self.env._decode_action(action)

    def save(self, path: str) -> None:
        """保存Q-table到文件"""
        save_path = path + "_qtable.npz"
        np.savez_compressed(
            save_path,
            q_table=self.q_table,
            lr=self.lr,
            gamma=self.gamma,
            epsilon=self.epsilon,
            trained=self._trained,
        )
        logger.info("Q-table已保存: %s (%d entries)" % (save_path, self.q_table.size))

    def load(self, path: str) -> bool:
        """从文件加载Q-table"""
        load_path = path + "_qtable.npz"
        try:
            data = np.load(load_path, allow_pickle=False)
            self.q_table = data["q_table"]
            self.lr = float(data["lr"])
            self.gamma = float(data["gamma"])
            self.epsilon = float(data["epsilon"])
            self._trained = bool(data["trained"])
            logger.info("Q-table已加载: %s" % load_path)
            return True
        except Exception as e:
            logger.warning("加载Q-table失败: %s" % e)
            return False

    @property
    def is_trained(self) -> bool:
        return self._trained

    def get_q_table_stats(self) -> Dict[str, Any]:
        """获取Q-table统计信息"""
        nonzero = np.count_nonzero(self.q_table)
        return {
            "shape": list(self.q_table.shape),
            "nonzero_entries": int(nonzero),
            "memory_bytes": self.q_table.nbytes,
            "max_q": float(np.max(self.q_table)),
            "min_q": float(np.min(self.q_table)),
            "avg_q": float(np.mean(self.q_table)),
            "epsilon": round(self.epsilon, 4),
            "trained": self._trained,
        }
