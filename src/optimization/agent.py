"""DQN强化学习智能体

使用Stable-Baselines3实现深度Q网络(DQN)智能体，
用于加密参数自适应优化决策。当SB3不可用时，使用回退PyTorch实现。
"""

import os
from typing import Dict, List, Tuple, Any, Optional
from dataclasses import dataclass, asdict

import numpy as np
from loguru import logger

from src.optimization.environment import EncryptionEnv


@dataclass
class AgentConfig:
    """智能体配置"""
    learning_rate: float = 3e-4
    buffer_size: int = 50000
    learning_starts: int = 1000
    batch_size: int = 64
    tau: float = 1.0
    gamma: float = 0.99
    train_freq: int = 4
    target_update_interval: int = 500
    exploration_fraction: float = 0.3
    exploration_initial_eps: float = 1.0
    exploration_final_eps: float = 0.05
    policy_kwargs: Dict = None
    seed: int = 42


class DQNAgent:
    """DQN强化学习智能体

    封装Stable-Baselines3的DQN算法，提供训练、推理、保存、加载接口。
    使用EncryptionEnv环境进行加密参数优化。
    当SB3不可用时自动使用回退PyTorch实现。

    属性:
        model: Stable-Baselines3 DQN模型（SB3模式）
        fallback_model: FallbackDQN实例（回退模式）
        env: EncryptionEnv环境实例
        config: 智能体配置
    """

    def __init__(self, config: Optional[AgentConfig] = None):
        self.config = config or AgentConfig()
        self.env = EncryptionEnv()
        self.model = None
        self.fallback_model = None
        self._trained = False
        self._sb3_mode = False
        logger.debug("DQNAgent 初始化完成")

    def train(self, total_timesteps: int = 10000) -> List[float]:
        """训练DQN智能体

        优先使用Stable-Baselines3，不可用时使用回退PyTorch实现。

        Args:
            total_timesteps: 总训练步数

        Returns:
            奖励历史列表
        """
        import importlib
        sb3_available = importlib.util.find_spec("stable_baselines3") is not None

        if sb3_available:
            return self._train_sb3(total_timesteps)
        else:
            return self._train_fallback(total_timesteps)

    def _train_sb3(self, total_timesteps: int) -> List[float]:
        """使用Stable-Baselines3训练"""
        from stable_baselines3 import DQN

        logger.info("使用Stable-Baselines3训练DQN: %d步" % total_timesteps)
        self.model = DQN(
            "MlpPolicy", self.env,
            learning_rate=self.config.learning_rate,
            buffer_size=self.config.buffer_size,
            learning_starts=self.config.learning_starts,
            batch_size=self.config.batch_size,
            tau=self.config.tau,
            gamma=self.config.gamma,
            train_freq=self.config.train_freq,
            target_update_interval=self.config.target_update_interval,
            exploration_fraction=self.config.exploration_fraction,
            exploration_initial_eps=self.config.exploration_initial_eps,
            exploration_final_eps=self.config.exploration_final_eps,
            policy_kwargs=self.config.policy_kwargs or dict(net_arch=[128, 64]),
            seed=self.config.seed,
            verbose=0,
        )
        self.model.learn(total_timesteps=total_timesteps, log_interval=0, progress_bar=False)
        rewards = self._collect_rewards()
        self._sb3_mode = True
        self._trained = True
        logger.info("SB3 DQN训练完成: %d步, 平均奖励=%.2f" % (total_timesteps, np.mean(rewards[-100:]) if len(rewards) >= 100 else 0))
        return rewards

    def _train_fallback(self, total_timesteps: int) -> List[float]:
        """使用回退PyTorch DQN训练，模型持久化存储在 self.fallback_model"""
        logger.info("使用回退DQN训练: %d步" % total_timesteps)
        from src.optimization.fallback_dqn import FallbackDQN

        state_dim = self.env.observation_space.shape[0]
        action_dim = self.env.action_space.n
        self.fallback_model = FallbackDQN(state_dim, action_dim)
        rewards = self.fallback_model.train(self.env, total_timesteps)
        self._sb3_mode = False
        self._trained = True
        logger.info("回退DQN训练完成: %d步" % total_timesteps)
        return rewards

    def _collect_rewards(self) -> List[float]:
        """收集训练过程中的奖励"""
        rewards = []
        obs, _ = self.env.reset()
        total_reward = 0.0
        for _ in range(1000):
            action, _ = self.model.predict(obs, deterministic=True)
            obs, reward, terminated, truncated, _ = self.env.step(int(action))
            total_reward += reward
            if terminated or truncated:
                rewards.append(total_reward)
                obs, _ = self.env.reset()
                total_reward = 0.0
        return rewards if rewards else [0.0]

    def predict(self, state: np.ndarray, deterministic: bool = True) -> Tuple[int, float]:
        """根据状态预测最优动作

        优先级: SB3模型 > 回退DQN > 启发式策略

        Args:
            state: 4维状态向量 [risk_level, cpu, memory, accuracy]
            deterministic: 是否确定性预测

        Returns:
            (action, q_value) 动作索引和Q值
        """
        if self._sb3_mode and self.model is not None:
            action, _ = self.model.predict(state, deterministic=deterministic)
            return int(action), 0.0

        if self.fallback_model is not None and self._trained and self.fallback_model.is_trained():
            return self.fallback_model.predict(state, deterministic)

        return self._heuristic_predict(state)

    def _heuristic_predict(self, state: np.ndarray) -> Tuple[int, float]:
        """启发式策略（模型未训练时的后备方案）"""
        risk_level = int(state[0])
        cpu_usage = float(state[1])

        if risk_level >= 2:  # 高/严重风险
            return EncryptionEnv.encode_action(4096, 14), 0.0
        elif risk_level == 1:  # 中风险
            return EncryptionEnv.encode_action(2048, 12), 0.0
        else:  # 低风险
            if cpu_usage > 0.7:
                return EncryptionEnv.encode_action(1024, 10), 0.0
            return EncryptionEnv.encode_action(2048, 10), 0.0

    def decode_action(self, action: int) -> Tuple[int, int]:
        """将动作解码为(密钥长度, 加密轮数)"""
        return self.env._decode_action(action)

    def save(self, path: str) -> None:
        """保存模型"""
        if self._sb3_mode and self.model is not None:
            self.model.save(path)
            logger.info("DQN模型已保存: %s" % path)
        elif self.fallback_model is not None:
            import joblib
            joblib.dump(self.fallback_model, path + "_fallback.pkl")
            logger.info("回退DQN模型已保存: %s" % path)

    def load(self, path: str) -> bool:
        """加载模型"""
        try:
            from stable_baselines3 import DQN
            self.model = DQN.load(path)
            self._sb3_mode = True
            self._trained = True
            logger.info("DQN模型已加载: %s" % path)
            return True
        except Exception:
            try:
                import joblib
                from src.optimization.fallback_dqn import FallbackDQN
                self.fallback_model = joblib.load(path + "_fallback.pkl")
                self._sb3_mode = False
                self._trained = True
                logger.info("回退DQN模型已加载: %s" % path)
                return True
            except Exception as e:
                logger.warning("加载DQN模型失败: %s" % e)
                return False

    @property
    def is_trained(self) -> bool:
        return self._trained
