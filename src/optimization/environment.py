# -*- coding: utf-8 -*-
"""加密参数自适应优化 - 强化学习环境（gym版）

基于OpenAI Gym实现的加密参数调优环境。
状态空间: 攻击风险等级, CPU使用率, 内存使用率, 模型精度
动作空间: 6个离散动作（3密钥长度 × 2加密轮数）
奖励函数: 综合隐私保护强度、计算效率和模型精度
"""

from typing import Dict, List, Tuple, Any, Optional
import numpy as np
try:
    import gymnasium as gym
    from gymnasium import spaces
except ImportError:
    import gym
    from gym import spaces
from loguru import logger


class EncryptionEnv(gym.Env):
    """加密参数优化强化学习环境

    状态空间 (4维):
        - risk_level: 攻击风险等级 [0, 3]
        - cpu_usage: CPU使用率 [0, 1]
        - memory_usage: 内存使用率 [0, 1]
        - model_accuracy: 模型精度 [0, 1]

    动作空间 (6个离散动作):
        0: 1024bit/10轮
        1: 1024bit/12轮
        2: 2048bit/10轮
        3: 2048bit/12轮
        4: 4096bit/10轮
        5: 4096bit/12轮
    """

    RISK_LEVELS = ["low", "medium", "high", "critical"]
    KEY_LENGTHS = [1024, 2048, 4096]
    ROUNDS = [10, 12]

    def __init__(self):
        super().__init__()

        # 动作空间: 6种离散组合 (3密钥长度 × 2加密轮数)
        self.action_space = spaces.Discrete(len(self.KEY_LENGTHS) * len(self.ROUNDS))

        # 状态空间: 4维连续
        self.observation_space = spaces.Box(
            low=np.array([0.0, 0.0, 0.0, 0.0], dtype=np.float32),
            high=np.array([3.0, 1.0, 1.0, 1.0], dtype=np.float32),
            dtype=np.float32,
        )

        # 加密参数配置成本模型
        self._key_length_cost = {1024: 1.0, 2048: 2.5, 4096: 6.0}
        self._rounds_cost = {10: 1.0, 12: 1.2}

        # 攻击成功概率 (取决于密钥长度)
        self._attack_success_prob = {
            1024: {0: 0.01, 1: 0.05, 2: 0.15, 3: 0.35},
            2048: {0: 0.005, 1: 0.02, 2: 0.08, 3: 0.20},
            4096: {0: 0.001, 1: 0.005, 2: 0.02, 3: 0.08},
        }

        self.state = None
        self._steps = 0
        self._max_steps = 100
        self.np_random = np.random.RandomState()

        logger.debug("EncryptionEnv 初始化完成 (6动作)")

    def seed(self, seed=None):
        self.np_random = np.random.RandomState(seed)

    def _decode_action(self, action: int) -> Tuple[int, int]:
        """将离散动作解码为(密钥长度, 加密轮数)"""
        kl_idx = action // len(self.ROUNDS)
        r_idx = action % len(self.ROUNDS)
        return self.KEY_LENGTHS[kl_idx], self.ROUNDS[r_idx]

    @staticmethod
    def encode_action(key_length: int, rounds: int) -> int:
        """将(密钥长度, 加密轮数)编码为离散动作"""
        kl_idx = EncryptionEnv.KEY_LENGTHS.index(key_length)
        r_idx = EncryptionEnv.ROUNDS.index(rounds)
        return kl_idx * len(EncryptionEnv.ROUNDS) + r_idx

    def reset(self):
        """重置环境状态"""
        risk_level = self.np_random.randint(0, 4)
        cpu_usage = self.np_random.uniform(0.1, 0.9)
        memory_usage = self.np_random.uniform(0.1, 0.9)
        model_accuracy = self.np_random.uniform(0.85, 0.99)

        self.state = np.array(
            [float(risk_level), float(cpu_usage), float(memory_usage), float(model_accuracy)],
            dtype=np.float32,
        )
        self._steps = 0
        return self.state

    def step(self, action: int) -> Tuple[np.ndarray, float, bool, Dict]:
        """执行动作并返回新状态和奖励

        Returns:
            (next_state, reward, done, info)
        """
        assert self.state is not None

        key_length, rounds = self._decode_action(action)
        risk_level = int(self.state[0])
        cpu_usage = float(self.state[1])
        memory_usage = float(self.state[2])
        model_accuracy = float(self.state[3])

        # 计算性能开销
        time_cost = self._key_length_cost[key_length] * self._rounds_cost[rounds]
        memory_cost = (key_length / 2048) * (rounds / 12)
        efficiency_penalty = -(time_cost * 0.3 + memory_cost * 0.2)

        # 计算安全性收益
        attack_prob = self._attack_success_prob[key_length][risk_level]
        security_reward = (1.0 - attack_prob) * 5.0

        if risk_level >= 2 and key_length >= 2048:
            security_reward += 3.0

        # 计算精度影响
        accuracy_impact = 0.999 ** (key_length / 1024 + rounds / 10)
        accuracy_reward = (model_accuracy * accuracy_impact) * 2.0

        # 总奖励
        reward = security_reward + efficiency_penalty + accuracy_reward

        # 更新状态
        self._steps += 1
        new_risk_level = self._evolve_risk_level(risk_level, key_length, rounds)
        new_cpu = np.clip(cpu_usage + self.np_random.uniform(-0.05, 0.05), 0.05, 0.95)
        new_memory = np.clip(memory_usage + self.np_random.uniform(-0.03, 0.03), 0.05, 0.95)
        new_accuracy = np.clip(
            model_accuracy + self.np_random.uniform(-0.01, 0.01) * (1 - accuracy_impact),
            0.7, 0.99,
        )

        self.state = np.array(
            [float(new_risk_level), float(new_cpu), float(new_memory), float(new_accuracy)],
            dtype=np.float32,
        )

        # 终止条件
        truncated = self._steps >= self._max_steps
        attack_succeeded = self.np_random.random() < attack_prob * 0.3
        terminated = attack_succeeded and risk_level >= 2

        if terminated:
            reward -= 10.0  # 攻击成功惩罚

        info = {
            "key_length": key_length,
            "rounds": rounds,
            "risk_level": self.RISK_LEVELS[risk_level],
            "time_cost": float(time_cost),
            "attack_success_prob": float(attack_prob),
        }

        return self.state, float(reward), terminated or truncated, info

    def _evolve_risk_level(self, current_level: int, key_length: int, rounds: int) -> int:
        """风险等级动态演化"""
        protection = (key_length / 4096) * (rounds / 14)
        drift = self.np_random.uniform(-0.5, 0.5)
        new_level = current_level - protection * 0.5 + drift * 0.3
        return int(np.clip(np.round(new_level), 0, 3))

    def get_risk_level_name(self) -> str:
        """获取当前风险等级名称"""
        if self.state is None:
            return "unknown"
        return self.RISK_LEVELS[int(self.state[0])]

    def render(self, mode: str = "human"):
        pass
