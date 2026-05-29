# -*- coding: utf-8 -*-
"""自适应优化器

实现"攻击感知-参数调优-反馈优化"闭环。
支持平滑调整（限幅+冷却+阈值），防止频繁波动。
"""

import time
from typing import Dict, List, Any, Tuple
from dataclasses import dataclass, asdict

import numpy as np
from loguru import logger

from src.optimization.environment import EncryptionEnv
from src.optimization.agent import QLearningAgent


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
    old_key_length: int = 2048
    old_rounds: int = 10
    reason_detail: str = ""


_SMOOTH_KL_STEPS = {1024: 2048, 2048: 4096}
_SMOOTH_KL_REV = {4096: 2048, 2048: 1024}
COOLDOWN_SECONDS = 30
RISK_CHANGE_THRESHOLD = 0.2


class AdaptiveOptimizer:
    """自适应加密参数优化器（带平滑调整）"""

    def __init__(self):
        self.agent = QLearningAgent()
        self.current_key_length: int = 2048
        self.current_rounds: int = 10
        self.current_risk_level: str = "low"
        self.history: List[OptimizationRecord] = []
        self.performance_gain: float = 0.0
        self._baseline_cost: float = self._calc_cost(2048, 10)
        self._last_update: float = 0
        self._last_anomaly_score: float = 0.0
        self._total_cooldown_hits: int = 0
        # 累计节省时间（模拟）
        self._total_saved_time_sec: float = 0.0
        logger.info("自适应优化器初始化完成(平滑调整)")

    def _smooth_action(self, target_kl: int, target_r: int) -> Tuple[int, int]:
        """对目标动作进行平滑限幅，防止大幅跳变"""
        # 限制密钥长度每次最多±1档
        if target_kl > self.current_key_length:
            target_kl = _SMOOTH_KL_STEPS.get(self.current_key_length, target_kl)
        elif target_kl < self.current_key_length:
            target_kl = _SMOOTH_KL_REV.get(self.current_key_length, target_kl)

        # 限制加密轮数每次最多±2
        target_r = max(10, min(12, target_r))
        if target_r > self.current_rounds + 2:
            target_r = self.current_rounds + 2
        elif target_r < self.current_rounds - 2:
            target_r = self.current_rounds - 2

        return target_kl, target_r

    def update(
        self,
        anomaly_score: float,
        cpu_usage: float = 0.3,
        memory_usage: float = 0.4,
        model_accuracy: float = 0.95,
    ) -> Dict[str, Any]:
        """执行一次平滑优化更新"""
        now = time.time()

        # 冷却检查
        if now - self._last_update < COOLDOWN_SECONDS:
            self._total_cooldown_hits += 1
            return {
                "action": "cooldown",
                "key_length": self.current_key_length,
                "rounds": self.current_rounds,
                "risk_level": self.current_risk_level,
                "reward": 0,
                "performance_gain": round(self.performance_gain, 2),
                "reason": "冷却中(%.0fs)" % (COOLDOWN_SECONDS - (now - self._last_update)),
            }

        # 风险变化阈值检查
        risk_change = abs(anomaly_score - self._last_anomaly_score)
        self._last_anomaly_score = anomaly_score

        risk_level = self._calc_risk_level(anomaly_score)
        self.current_risk_level = risk_level
        risk_level_idx = EncryptionEnv.RISK_LEVELS.index(risk_level)

        state = np.array(
            [float(risk_level_idx), float(cpu_usage), float(memory_usage), float(model_accuracy)],
            dtype=np.float32,
        )

        action, _ = self.agent.predict(state)
        raw_kl, raw_r = self.agent.decode_action(action)

        # 平滑限幅
        key_length, rounds = self._smooth_action(raw_kl, raw_r)

        old_key_length = self.current_key_length
        old_rounds = self.current_rounds
        old_cost = self._calc_cost(old_key_length, old_rounds)
        new_cost = self._calc_cost(key_length, rounds)
        baseline_cost = self._calc_cost(2048, 10)
        changed = (key_length != old_key_length) or (rounds != old_rounds)

        should_adjust = changed and risk_change >= RISK_CHANGE_THRESHOLD

        if should_adjust:
            gain = ((baseline_cost - new_cost) / baseline_cost) * 100
            self.performance_gain += gain
            detail = "攻击风险从%.2f上升到%.2f，自动提升密钥长度至%dbits" % (
                self._last_anomaly_score - risk_change, anomaly_score, key_length) if risk_change > 0 else \
                     "风险等级变化为%s，调整加密参数" % risk_level
            self._total_saved_time_sec += abs(new_cost - old_cost) * 0.1
            logger.info("加密参数调整: %dbit/%d轮 → %dbit/%d轮 (风险=%s, 增益=%.1f%%, Δ风险=%.2f)",
                        old_key_length, old_rounds, key_length, rounds, risk_level, gain, risk_change)
        else:
            gain = 0.0
            if changed and risk_change < RISK_CHANGE_THRESHOLD:
                detail = "风险变化%.2f<阈值0.2，保持当前参数" % risk_change
            else:
                detail = "当前参数已最优"

        self.current_key_length = key_length
        self.current_rounds = rounds
        self._last_update = now

        reward = self._calc_reward(risk_level_idx, anomaly_score, key_length, rounds)

        record = OptimizationRecord(
            timestamp=now,
            risk_level=risk_level,
            risk_score=round(anomaly_score, 4),
            cpu_usage=round(cpu_usage, 4),
            memory_usage=round(memory_usage, 4),
            model_accuracy=round(model_accuracy, 4),
            key_length=key_length,
            rounds=rounds,
            reward=round(reward, 4),
            performance_gain=round(self.performance_gain, 2),
            old_key_length=old_key_length,
            old_rounds=old_rounds,
            reason_detail=detail,
        )
        self.history.append(record)

        return {
            "action": "update" if should_adjust else ("maintain" if not changed else "threshold_blocked"),
            "key_length": key_length,
            "rounds": rounds,
            "risk_level": risk_level,
            "reward": round(reward, 4),
            "performance_gain": round(self.performance_gain, 2),
            "old_key_length": old_key_length,
            "old_rounds": old_rounds,
            "change_detail": detail,
            "risk_change": round(risk_change, 3),
            "total_saved_time": round(self._total_saved_time_sec, 1),
            "reason": detail,
        }

    def get_current_config(self) -> Dict[str, int]:
        return {"key_length": self.current_key_length, "rounds": self.current_rounds}

    def get_history(self) -> List[Dict]:
        return [asdict(r) for r in self.history[-200:]]

    def train(self, episodes: int = 500) -> List[float]:
        logger.info("开始训练优化智能体: %d episodes", episodes)
        total_steps = episodes * 100
        rewards = self.agent.train(total_timesteps=total_steps)
        logger.info("优化智能体训练完成: avg_reward=%.2f", np.mean(rewards[-100:]) if rewards else 0)
        return rewards

    def get_status(self) -> Dict[str, Any]:
        return {
            "current_key_length": self.current_key_length,
            "current_rounds": self.current_rounds,
            "risk_level": self.current_risk_level,
            "performance_gain": round(self.performance_gain, 2),
            "total_updates": len(self.history),
            "last_update": self._last_update,
            "agent_trained": self.agent.is_trained,
            "total_saved_time": round(self._total_saved_time_sec, 1),
            "cooldown_hits": self._total_cooldown_hits,
        }

    def get_effect_comparison(self) -> Dict:
        """获取静态vs自适应效果对比"""
        if not self.history:
            return {"static_cost": "2.50", "adaptive_cost": "2.50",
                    "efficiency_gain": "0%", "total_saved": "0"}

        static_cost = self._calc_cost(2048, 10)
        avg_adaptive = np.mean([self._calc_cost(r.key_length, r.rounds) for r in self.history[-50:]])
        gain = ((static_cost - avg_adaptive) / static_cost) * 100 if static_cost > 0 else 0
        return {
            "static_cost": "%.2f" % static_cost,
            "adaptive_cost": "%.2f" % avg_adaptive,
            "efficiency_gain": "%.1f%%" % max(0, gain),
            "total_saved": "%.1f" % self._total_saved_time_sec,
        }

    @staticmethod
    def _calc_risk_level(anomaly_score: float) -> str:
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
        kl_cost = {1024: 1.0, 2048: 2.5, 4096: 6.0}
        r_cost = {10: 1.0, 12: 1.2}
        return kl_cost.get(key_length, 2.5) * r_cost.get(rounds, 1.0)

    @staticmethod
    def _calc_reward(risk_level_idx: int, anomaly_score: float, key_length: int, rounds: int) -> float:
        protection = (key_length / 4096) * (rounds / 14)
        security = protection * (1.0 + risk_level_idx * 0.5)
        cost = AdaptiveOptimizer._calc_cost(key_length, rounds)
        efficiency = -cost * 0.1
        if risk_level_idx >= 2 and protection >= 0.7:
            adaptability = 2.0
        elif risk_level_idx <= 1 and protection <= 0.5:
            adaptability = 1.0
        else:
            adaptability = 0.0
        return security + efficiency + adaptability
