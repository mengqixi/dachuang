# -*- coding: utf-8 -*-
"""表格型Q-learning强化学习智能体

使用表格型Q-learning进行加密参数自适应优化。
500离散状态(5×5×5×5) × 6动作，Q-table内存占用<20KB。
"""

import os
import random
from typing import Dict, List, Tuple, Any

import numpy as np
from loguru import logger

from src.optimization.environment import EncryptionEnv


class QLearningAgent:
    """表格型Q-learning智能体

    将连续4维状态离散化为500种组合，维护3000条Q值表。
    支持训练、预测、保存、加载。
    """

    # 5分箱边界（每个维度5档）
    BINS = [0.2, 0.4, 0.6, 0.8]  # 产生5个区间: [0,0.2), [0.2,0.4), [0.4,0.6), [0.6,0.8), [0.8,1.0]
    N_BINS = 5

    def __init__(self, lr: float = 0.1, gamma: float = 0.9, epsilon: float = 0.1):
        self.lr = lr
        self.gamma = gamma
        self.epsilon_init = epsilon
        self.epsilon = epsilon

        self.env = EncryptionEnv()
        self.n_actions = self.env.action_space.n
        # 500 states(5×5×5×4) × 6 actions = 3000 entries
        self.n_states = self.N_BINS * self.N_BINS * self.N_BINS * self.N_BINS
        self.q_table = np.zeros((self.n_states, self.n_actions), dtype=np.float32)
        self._trained = False
        self._train_step = 0
        logger.info(
            "QLearningAgent(500状态) 初始化: Q-table=%dx%d (%.1fKB)" %
            (self.n_states, self.n_actions, self.q_table.nbytes / 1024)
        )

    def _bin_index(self, value: float) -> int:
        """将连续值映射为5档索引"""
        if value <= 0.2:
            return 0
        if value <= 0.4:
            return 1
        if value <= 0.6:
            return 2
        if value <= 0.8:
            return 3
        return 4

    def discretize_state(self, state: np.ndarray) -> str:
        """将4维连续状态离散化为字符串key [0, 500)"""
        risk_idx = int(np.clip(state[0], 0, 3)) % 4  # 0-3
        cpu_idx = self._bin_index(float(state[1]))
        mem_idx = self._bin_index(float(state[2]))
        acc_idx = self._bin_index(float(state[3]))
        return "%d_%d_%d_%d" % (risk_idx, cpu_idx, mem_idx, acc_idx)

    def _state_to_idx(self, state_key: str) -> int:
        """状态key → Q-table行索引 [0, 500)"""
        parts = [int(x) for x in state_key.split("_")]
        risk, cpu, mem, acc = parts
        return (risk * 125) + (cpu * 25) + (mem * 5) + acc

    def predict(self, state: np.ndarray, deterministic: bool = True) -> Tuple[int, float]:
        """根据状态选择最优动作"""
        s_idx = self._state_to_idx(self.discretize_state(state))

        if not deterministic and random.random() < self.epsilon:
            action = random.randint(0, self.n_actions - 1)
            q_val = self.q_table[s_idx, action]
        else:
            action = int(np.argmax(self.q_table[s_idx]))
            q_val = float(self.q_table[s_idx, action])

        return action, q_val

    def train(self, total_timesteps: int = 50000) -> List[float]:
        """训练Q-learning智能体

        Args:
            total_timesteps: 总训练步数

        Returns:
            每个episode的累计奖励列表
        """
        logger.info("开始Q-learning训练: %d步, 500状态, 6动作" % total_timesteps)
        episode_rewards = []
        total_reward = 0.0
        episode = 0
        self.epsilon = self.epsilon_init

        obs = self.env.reset()
        s_idx = self._state_to_idx(self.discretize_state(obs))

        for step in range(total_timesteps):
            # epsilon衰减 (从0.1线性衰减到0.01)
            eps = max(0.01, self.epsilon_init * (1 - step / total_timesteps))

            if random.random() < eps:
                action = self.env.action_space.sample()
            else:
                action = int(np.argmax(self.q_table[s_idx]))

            # gym API: step返回 (obs, reward, done, info)
            next_obs, reward, done, _ = self.env.step(action)
            next_idx = self._state_to_idx(self.discretize_state(next_obs))

            # Q-learning更新
            best_next_q = float(np.max(self.q_table[next_idx]))
            current_q = float(self.q_table[s_idx, action])
            new_q = current_q + self.lr * (reward + self.gamma * best_next_q - current_q)
            self.q_table[s_idx, action] = new_q

            total_reward += reward
            self._train_step += 1
            obs = next_obs
            s_idx = next_idx

            if done:
                episode_rewards.append(total_reward)
                episode += 1
                if episode % 200 == 0 and episode > 0:
                    avg = np.mean(episode_rewards[-200:])
                    logger.info("Q-learning Episode %d: avg_reward=%.2f, eps=%.4f" %
                               (episode, avg, eps))
                obs = self.env.reset()
                s_idx = self._state_to_idx(self.discretize_state(obs))
                total_reward = 0.0

        self._trained = True
        final_avg = np.mean(episode_rewards[-200:]) if len(episode_rewards) >= 200 else \
                    np.mean(episode_rewards) if episode_rewards else 0
        logger.info("Q-learning训练完成: %d episodes, avg_reward=%.2f", episode, final_avg)
        return episode_rewards

    def decode_action(self, action: int) -> Tuple[int, int]:
        """将动作解码为(密钥长度, 加密轮数)"""
        return self.env._decode_action(action)

    def save(self, path: str) -> None:
        save_path = path + "_qtable.npz"
        np.savez_compressed(save_path, q_table=self.q_table, lr=self.lr,
                            gamma=self.gamma, epsilon=self.epsilon, trained=self._trained)
        logger.info("Q-table已保存: %s (%d entries)", save_path, self.q_table.size)

    def load(self, path: str) -> bool:
        load_path = path + "_qtable.npz"
        try:
            data = np.load(load_path, allow_pickle=False)
            self.q_table = data["q_table"]
            self.lr = float(data["lr"])
            self.gamma = float(data["gamma"])
            self.epsilon = float(data["epsilon"])
            self._trained = bool(data["trained"])
            logger.info("Q-table已加载: %s", load_path)
            return True
        except Exception as e:
            logger.warning("加载Q-table失败: %s", e)
            return False

    @property
    def is_trained(self) -> bool:
        return self._trained

    def get_q_table_stats(self) -> Dict[str, Any]:
        nonzero = np.count_nonzero(self.q_table)
        return {
            "shape": list(self.q_table.shape),
            "nonzero_entries": int(nonzero),
            "memory_bytes": self.q_table.nbytes,
            "max_q": float(np.max(self.q_table)),
            "epsilon": round(self.epsilon, 4),
            "trained": self._trained,
        }
