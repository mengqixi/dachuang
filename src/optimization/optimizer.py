"""自适应优化器

实现"攻击感知-参数调优-反馈优化"闭环。
对接攻击检测模块获取实时风险等级，
调用DQN智能体动态调整加密参数，
反馈性能指标持续优化策略。
"""

import time
import json
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, asdict

import numpy as np
from loguru import logger

from src.optimization.environment import EncryptionEnv
from src.optimization.agent import DQNAgent, AgentConfig


@dataclass
class OptimizationRecord:
    """优化记录"""
    timestamp: float
    risk_level: str
    risk_score: float
    cpu_usage: float
    memory_usage: float
    model_accuracy: float
    key_length: int
    rounds: int
    reward: float
    performance_gain: float


class AdaptiveOptimizer:
    """自适应加密参数优化器

    实现攻击感知 → 参数调优 → 反馈优化的闭环流程。
    对接攻击检测模块获取实时风险等级，调用DQN智能体做出决策。

    属性:
        agent: DQN强化学习智能体
        env: 加密环境
        current_key_length: 当前密钥长度
        current_rounds: 当前加密轮数
        current_risk_level: 当前风险等级
        history: 优化历史记录
        performance_gain: 累计性能提升
        _baseline_cost: 静态加密基准成本
    """

    def __init__(self, agent_config: Optional[AgentConfig] = None):
        self.agent = DQNAgent(agent_config)
        self.env = EncryptionEnv()
        self.current_key_length: int = 2048
        self.current_rounds: int = 10
        self.current_risk_level: str = "low"
        self.history: List[OptimizationRecord] = []
        self.performance_gain: float = 0.0
        self._baseline_cost: float = self._calc_cost(2048, 10)
        self._last_update: float = time.time()
        logger.info("自适应优化器初始化完成")

    def update(
        self,
        anomaly_score: float,
        cpu_usage: float = 0.3,
        memory_usage: float = 0.4,
        model_accuracy: float = 0.95,
    ) -> Dict[str, Any]:
        """执行一次优化更新

        Args:
            anomaly_score: 攻击检测异常分数 [0, 1]
            cpu_usage: CPU使用率 [0, 1]
            memory_usage: 内存使用率 [0, 1]
            model_accuracy: 模型当前精度 [0, 1]

        Returns:
            优化结果字典
        """
        # 1. 计算风险等级
        risk_level = self._calc_risk_level(anomaly_score)
        self.current_risk_level = risk_level
        risk_level_idx = EncryptionEnv.RISK_LEVELS.index(risk_level)

        # 2. 构建状态
        state = np.array(
            [float(risk_level_idx), float(cpu_usage), float(memory_usage), float(model_accuracy)],
            dtype=np.float32,
        )

        # 3. DQN决策
        action, _ = self.agent.predict(state)
        key_length, rounds = self.env._decode_action(action)

        # 4. 计算性能增益（相对静态基线 2048/10）
        old_cost = self._calc_cost(self.current_key_length, self.current_rounds)
        new_cost = self._calc_cost(key_length, rounds)
        baseline_cost = self._calc_cost(2048, 10)
        changed = (key_length != self.current_key_length) or (rounds != self.current_rounds)

        if changed:
            gain = ((baseline_cost - new_cost) / baseline_cost) * 100
            self.performance_gain += gain
            logger.info(
                f"加密参数调整: {self.current_key_length}bit/{self.current_rounds}轮 → "
                f"{key_length}bit/{rounds}轮 (风险={risk_level}, 增益={gain:.1f}%)"
            )
        else:
            gain = 0.0

        self.current_key_length = key_length
        self.current_rounds = rounds

        # 5. 计算奖励
        reward = self._calc_reward(risk_level_idx, anomaly_score, key_length, rounds)

        # 6. 记录历史
        record = OptimizationRecord(
            timestamp=time.time(),
            risk_level=risk_level,
            risk_score=round(anomaly_score, 4),
            cpu_usage=round(cpu_usage, 4),
            memory_usage=round(memory_usage, 4),
            model_accuracy=round(model_accuracy, 4),
            key_length=key_length,
            rounds=rounds,
            reward=round(reward, 4),
            performance_gain=round(self.performance_gain, 2),
        )
        self.history.append(record)

        self._last_update = time.time()

        return {
            "action": "update" if changed else "maintain",
            "key_length": key_length,
            "rounds": rounds,
            "risk_level": risk_level,
            "reward": round(reward, 4),
            "performance_gain": round(self.performance_gain, 2),
            "reason": f"异常分数={anomaly_score:.2f}, 风险等级={risk_level}",
        }

    def get_current_config(self) -> Dict[str, int]:
        """获取当前加密配置"""
        return {
            "key_length": self.current_key_length,
            "rounds": self.current_rounds,
        }

    def get_history(self) -> List[Dict]:
        """获取优化历史"""
        return [asdict(r) for r in self.history[-200:]]  # 最多返回200条

    def train(self, episodes: int = 500) -> List[float]:
        """训练优化智能体

        Args:
            episodes: 训练episode数

        Returns:
            奖励历史
        """
        logger.info(f"开始训练优化智能体: {episodes} episodes")
        total_steps = episodes * 100  # 每个episode最多100步
        rewards = self.agent.train(total_timesteps=total_steps)
        logger.info(f"优化智能体训练完成: avg_reward={np.mean(rewards[-100:]):.2f}")
        return rewards

    def get_status(self) -> Dict[str, Any]:
        """获取优化器完整状态"""
        return {
            "current_key_length": self.current_key_length,
            "current_rounds": self.current_rounds,
            "risk_level": self.current_risk_level,
            "performance_gain": round(self.performance_gain, 2),
            "total_updates": len(self.history),
            "last_update": self._last_update,
            "agent_trained": self.agent.is_trained,
        }

    @staticmethod
    def _calc_risk_level(anomaly_score: float) -> str:
        """将异常分数映射为风险等级"""
        if anomaly_score < 0.2:
            return "low"
        elif anomaly_score < 0.5:
            return "medium"
        elif anomaly_score < 0.8:
            return "high"
        else:
            return "critical"

    @staticmethod
    def _calc_cost(key_length: int, rounds: int) -> float:
        """计算加密参数的成本"""
        kl_cost = {1024: 1.0, 2048: 2.5, 4096: 6.0}
        r_cost = {10: 1.0, 12: 1.2, 14: 1.5}
        return kl_cost.get(key_length, 2.5) * r_cost.get(rounds, 1.0)

    @staticmethod
    def _calc_reward(
        risk_level_idx: int, anomaly_score: float, key_length: int, rounds: int
    ) -> float:
        """计算动作的即时奖励"""
        # 安全性奖励
        protection = (key_length / 4096) * (rounds / 14)
        security = protection * (1.0 + risk_level_idx * 0.5)

        # 效率惩罚
        cost = AdaptiveOptimizer._calc_cost(key_length, rounds)
        efficiency = -cost * 0.1

        # 适应性奖励
        if risk_level_idx >= 2 and protection >= 0.7:
            adaptability = 2.0
        elif risk_level_idx <= 1 and protection <= 0.5:
            adaptability = 1.0
        else:
            adaptability = 0.0

        return security + efficiency + adaptability
