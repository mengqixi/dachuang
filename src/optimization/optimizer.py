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
    security_strength: float = 70.0
    security_delta: float = 0.0
    cost_delta_percent: float = 0.0
    old_security_strength: float = 70.0
    old_key_length: int = 2048
    old_rounds: int = 10
    reason_detail: str = ""
    policy_source: str = "risk_rule_fallback"
    q_action: int = 0
    q_value: float = 0.0
    stage: str = "maintained"
    risk_change: float = 0.0
    recommended_key_length: int = 2048
    recommended_rounds: int = 10
    applied: bool = False
    reward_security: float = 0.0
    reward_efficiency: float = 0.0
    reward_adaptability: float = 0.0
    protection_score: float = 0.0
    estimated_attack_success_prob: float = 0.0
    efficiency_cost: float = 0.0


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
        self._last_signal: Dict[str, Any] = {
            "anomaly_score": 0.0,
            "cpu_usage": 0.3,
            "memory_usage": 0.4,
            "model_accuracy": 0.95,
        }
        self._last_decision: Dict[str, Any] = {}
        self._demo_index: int = 0
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
        target_r = max(10, min(14, target_r))
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
        force: bool = False,
    ) -> Dict[str, Any]:
        """Run one risk-driven parameter optimization step."""
        now = time.time()
        anomaly_score = max(0.0, min(1.0, float(anomaly_score)))
        previous_score = self._last_anomaly_score

        if not force and now - self._last_update < COOLDOWN_SECONDS:
            self._total_cooldown_hits += 1
            current_strength = self._calc_security_strength(self.current_key_length, self.current_rounds)
            current_cost = self._calc_cost(self.current_key_length, self.current_rounds)
            cooldown_remaining = max(0.0, COOLDOWN_SECONDS - (now - self._last_update))
            result = {
                "action": "cooldown",
                "key_length": self.current_key_length,
                "rounds": self.current_rounds,
                "recommended_key_length": self.current_key_length,
                "recommended_rounds": self.current_rounds,
                "old_key_length": self.current_key_length,
                "old_rounds": self.current_rounds,
                "risk_level": self.current_risk_level,
                "risk_score": round(anomaly_score, 4),
                "reward": 0.0,
                "reward_security": 0.0,
                "reward_efficiency": 0.0,
                "reward_adaptability": 0.0,
                "protection_score": round(self._protection_score(self.current_key_length, self.current_rounds), 4),
                "estimated_attack_success_prob": 0.0,
                "efficiency_cost": round(current_cost, 4),
                "performance_gain": round(self.performance_gain, 2),
                "security_strength": round(current_strength, 1),
                "security_delta": 0.0,
                "cost_delta_percent": 0.0,
                "old_security_strength": round(current_strength, 1),
                "applied": False,
                "risk_change": round(abs(anomaly_score - previous_score), 3),
                "cooldown_remaining": round(cooldown_remaining, 1),
                "reason": "cooldown: wait %.0f seconds before next automatic adjustment" % cooldown_remaining,
                "stage": "cooldown",
                "policy_source": "cooldown_guard",
            }
            self.history.append(OptimizationRecord(
                timestamp=now,
                risk_level=self.current_risk_level,
                risk_score=round(anomaly_score, 4),
                cpu_usage=round(self._last_signal.get("cpu_usage", 0.3), 4),
                memory_usage=round(self._last_signal.get("memory_usage", 0.4), 4),
                model_accuracy=round(self._last_signal.get("model_accuracy", 0.95), 4),
                key_length=self.current_key_length,
                rounds=self.current_rounds,
                reward=0.0,
                performance_gain=round(self.performance_gain, 2),
                security_strength=round(current_strength, 1),
                security_delta=0.0,
                cost_delta_percent=0.0,
                old_security_strength=round(current_strength, 1),
                old_key_length=self.current_key_length,
                old_rounds=self.current_rounds,
                reason_detail=result["reason"],
                policy_source="cooldown_guard",
                stage="cooldown",
                risk_change=result["risk_change"],
                recommended_key_length=self.current_key_length,
                recommended_rounds=self.current_rounds,
                applied=False,
                protection_score=result["protection_score"],
                efficiency_cost=result["efficiency_cost"],
            ))
            self._last_decision = result
            return result

        risk_change = abs(anomaly_score - previous_score)
        self._last_anomaly_score = anomaly_score
        self._last_signal = {
            "anomaly_score": round(anomaly_score, 4),
            "cpu_usage": round(cpu_usage, 4),
            "memory_usage": round(memory_usage, 4),
            "model_accuracy": round(model_accuracy, 4),
        }

        risk_level = self._calc_risk_level(anomaly_score)
        self.current_risk_level = risk_level
        risk_level_idx = EncryptionEnv.RISK_LEVELS.index(risk_level)

        state = np.array(
            [float(risk_level_idx), float(cpu_usage), float(memory_usage), float(model_accuracy)],
            dtype=np.float32,
        )

        action, q_value = self._choose_action(state, risk_level)
        raw_kl, raw_r = self.agent.decode_action(action)
        recommended_key_length, recommended_rounds = self._smooth_action(raw_kl, raw_r)

        old_key_length = self.current_key_length
        old_rounds = self.current_rounds
        old_cost = self._calc_cost(old_key_length, old_rounds)
        old_strength = self._calc_security_strength(old_key_length, old_rounds)
        changed = (recommended_key_length != old_key_length) or (recommended_rounds != old_rounds)

        should_adjust = force or (changed and risk_change >= RISK_CHANGE_THRESHOLD)
        applied = bool(should_adjust and changed)
        key_length = recommended_key_length if should_adjust else old_key_length
        rounds = recommended_rounds if should_adjust else old_rounds

        new_cost = self._calc_cost(key_length, rounds)
        new_strength = self._calc_security_strength(key_length, rounds)
        security_delta = new_strength - old_strength
        cost_delta_percent = ((new_cost - old_cost) / old_cost) * 100 if old_cost > 0 else 0.0

        if applied:
            baseline_cost = self._calc_cost(2048, 10)
            gain = ((baseline_cost - new_cost) / baseline_cost) * 100
            self.performance_gain = max(0.0, self.performance_gain + max(0.0, gain))
            if key_length > old_key_length:
                direction = "increase"
            elif key_length < old_key_length:
                direction = "decrease"
            else:
                direction = "keep"
            detail = "risk %.2f -> %.2f, policy recommends %s to %dbit/%d rounds, applied" % (
                previous_score, anomaly_score, direction, key_length, rounds)
            self._total_saved_time_sec += abs(new_cost - old_cost) * 0.1
            logger.info(
                "encryption parameters adjusted: {}bit/{} rounds -> {}bit/{} rounds (risk={}, risk_change={:.2f})",
                old_key_length, old_rounds, key_length, rounds, risk_level, risk_change,
            )
        else:
            gain = 0.0
            if changed and risk_change < RISK_CHANGE_THRESHOLD:
                detail = "risk change %.2f below threshold %.2f; recommendation recorded but current parameters kept" % (
                    risk_change, RISK_CHANGE_THRESHOLD)
            else:
                detail = "current parameters already match policy recommendation"

        self.current_key_length = key_length
        self.current_rounds = rounds
        self._last_update = now

        reward_parts = self._calc_reward_components(risk_level_idx, anomaly_score, key_length, rounds)
        reward = reward_parts["total"]
        if applied:
            stage = "adjusted"
            action_name = "update"
        elif changed:
            stage = "threshold_blocked"
            action_name = "threshold_blocked"
        else:
            stage = "maintained"
            action_name = "maintain"
        policy_source = "q_learning" if self.agent.is_trained else "risk_rule_fallback"

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
            performance_gain=round(max(0.0, self.performance_gain), 2),
            security_strength=round(new_strength, 1),
            security_delta=round(security_delta, 1),
            cost_delta_percent=round(cost_delta_percent, 1),
            old_security_strength=round(old_strength, 1),
            old_key_length=old_key_length,
            old_rounds=old_rounds,
            reason_detail=detail,
            policy_source=policy_source,
            q_action=int(action),
            q_value=round(float(q_value), 4),
            stage=stage,
            risk_change=round(risk_change, 3),
            recommended_key_length=recommended_key_length,
            recommended_rounds=recommended_rounds,
            applied=applied,
            reward_security=round(reward_parts["security"], 4),
            reward_efficiency=round(reward_parts["efficiency"], 4),
            reward_adaptability=round(reward_parts["adaptability"], 4),
            protection_score=round(reward_parts["protection_score"], 4),
            estimated_attack_success_prob=round(reward_parts["estimated_attack_success_prob"], 4),
            efficiency_cost=round(reward_parts["efficiency_cost"], 4),
        )
        self.history.append(record)

        result = {
            "action": action_name,
            "key_length": key_length,
            "rounds": rounds,
            "recommended_key_length": recommended_key_length,
            "recommended_rounds": recommended_rounds,
            "applied": applied,
            "risk_level": risk_level,
            "risk_score": round(anomaly_score, 4),
            "reward": round(reward, 4),
            "reward_security": round(reward_parts["security"], 4),
            "reward_efficiency": round(reward_parts["efficiency"], 4),
            "reward_adaptability": round(reward_parts["adaptability"], 4),
            "protection_score": round(reward_parts["protection_score"], 4),
            "estimated_attack_success_prob": round(reward_parts["estimated_attack_success_prob"], 4),
            "efficiency_cost": round(reward_parts["efficiency_cost"], 4),
            "performance_gain": round(max(0.0, self.performance_gain), 2),
            "security_strength": round(new_strength, 1),
            "security_delta": round(security_delta, 1),
            "cost_delta_percent": round(cost_delta_percent, 1),
            "old_security_strength": round(old_strength, 1),
            "old_key_length": old_key_length,
            "old_rounds": old_rounds,
            "change_detail": detail,
            "risk_change": round(risk_change, 3),
            "cpu_usage": round(cpu_usage, 4),
            "memory_usage": round(memory_usage, 4),
            "model_accuracy": round(model_accuracy, 4),
            "q_action": int(action),
            "q_value": round(float(q_value), 4),
            "policy_source": policy_source,
            "stage": stage,
            "total_saved_time": round(self._total_saved_time_sec, 1),
            "reason": detail,
        }
        self._last_decision = result
        return result

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
            "current_risk_score": round(self._last_anomaly_score, 4),
            "last_signal": self._last_signal,
            "last_decision": self._last_decision,
            "performance_gain": round(max(0.0, self.performance_gain), 2),
            "security_strength": round(self._calc_security_strength(self.current_key_length, self.current_rounds), 1),
            "total_updates": len(self.history),
            "last_update": self._last_update,
            "agent_trained": self.agent.is_trained,
            "total_saved_time": round(self._total_saved_time_sec, 1),
            "cooldown_hits": self._total_cooldown_hits,
        }

    def next_demo_signal(self) -> Dict[str, float]:
        sequence = [
            {"anomaly_score": 0.12, "cpu_usage": 0.28, "memory_usage": 0.34, "model_accuracy": 0.96},
            {"anomaly_score": 0.24, "cpu_usage": 0.31, "memory_usage": 0.38, "model_accuracy": 0.955},
            {"anomaly_score": 0.36, "cpu_usage": 0.34, "memory_usage": 0.42, "model_accuracy": 0.95},
            {"anomaly_score": 0.52, "cpu_usage": 0.42, "memory_usage": 0.50, "model_accuracy": 0.94},
            {"anomaly_score": 0.68, "cpu_usage": 0.48, "memory_usage": 0.56, "model_accuracy": 0.93},
            {"anomaly_score": 0.82, "cpu_usage": 0.56, "memory_usage": 0.63, "model_accuracy": 0.92},
            {"anomaly_score": 0.88, "cpu_usage": 0.61, "memory_usage": 0.68, "model_accuracy": 0.91},
            {"anomaly_score": 0.74, "cpu_usage": 0.53, "memory_usage": 0.60, "model_accuracy": 0.925},
            {"anomaly_score": 0.56, "cpu_usage": 0.44, "memory_usage": 0.52, "model_accuracy": 0.94},
            {"anomaly_score": 0.38, "cpu_usage": 0.35, "memory_usage": 0.44, "model_accuracy": 0.95},
            {"anomaly_score": 0.22, "cpu_usage": 0.30, "memory_usage": 0.37, "model_accuracy": 0.958},
        ]
        signal = sequence[self._demo_index % len(sequence)]
        self._demo_index += 1
        return dict(signal)

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

    def _choose_action(self, state: np.ndarray, risk_level: str) -> Tuple[int, float]:
        if self.agent.is_trained:
            return self.agent.predict(state)
        fallback = {
            "low": (1024, 10),
            "medium": (2048, 10),
            "high": (2048, 12),
            "critical": (4096, 12),
        }
        key_length, rounds = fallback.get(risk_level, (2048, 10))
        return EncryptionEnv.encode_action(key_length, rounds), 0.0

    @staticmethod
    def _calc_cost(key_length: int, rounds: int) -> float:
        kl_cost = {1024: 1.0, 2048: 2.5, 4096: 6.0}
        r_cost = {10: 1.0, 12: 1.2, 14: 1.4}
        return kl_cost.get(key_length, 2.5) * r_cost.get(rounds, 1.0)

    @staticmethod
    def _calc_security_strength(key_length: int, rounds: int) -> float:
        key_score = {1024: 35.0, 2048: 70.0, 4096: 100.0}.get(key_length, 70.0)
        round_bonus = {10: 0.0, 12: 8.0, 14: 12.0}.get(rounds, 0.0)
        return min(100.0, key_score + round_bonus)

    @staticmethod
    def _protection_score(key_length: int, rounds: int) -> float:
        key_factor = {1024: 0.35, 2048: 0.70, 4096: 1.0}.get(key_length, 0.70)
        round_factor = {10: 0.90, 12: 1.0, 14: 1.05}.get(rounds, 0.90)
        return min(1.0, key_factor * round_factor)

    @staticmethod
    def _calc_reward_components(
        risk_level_idx: int,
        anomaly_score: float,
        key_length: int,
        rounds: int,
    ) -> Dict[str, float]:
        protection = AdaptiveOptimizer._protection_score(key_length, rounds)
        cost = AdaptiveOptimizer._calc_cost(key_length, rounds)
        attack_success_prob = max(0.01, min(0.95, anomaly_score * (1.0 - protection * 0.72)))

        # Security benefit: higher risk gives more value to reducing attack success probability.
        security = (1.0 - attack_success_prob) * (1.0 + risk_level_idx * 0.35) * 3.0

        # Efficiency term: low risk penalizes expensive configurations more strongly.
        efficiency_weight = 0.12 if risk_level_idx <= 1 else 0.06
        efficiency = -cost * efficiency_weight

        if risk_level_idx >= 2 and protection >= 0.65:
            adaptability = 1.8
        elif risk_level_idx <= 1 and key_length <= 2048:
            adaptability = 1.1
        elif risk_level_idx == 1 and protection >= 0.55:
            adaptability = 0.6
        else:
            adaptability = -0.2

        total = security + efficiency + adaptability
        return {
            "total": round(total, 4),
            "security": round(security, 4),
            "efficiency": round(efficiency, 4),
            "adaptability": round(adaptability, 4),
            "protection_score": round(protection, 4),
            "estimated_attack_success_prob": round(attack_success_prob, 4),
            "efficiency_cost": round(cost, 4),
        }

    @staticmethod
    def _calc_reward(risk_level_idx: int, anomaly_score: float, key_length: int, rounds: int) -> float:
        return AdaptiveOptimizer._calc_reward_components(
            risk_level_idx, anomaly_score, key_length, rounds
        )["total"]
