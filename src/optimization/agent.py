# -*- coding: utf-8 -*-
"""Tabular Q-learning agent for adaptive encryption parameter selection."""

import os
import random
from typing import Any, Dict, List, Tuple

import numpy as np
from loguru import logger

from src.optimization.environment import EncryptionEnv


class QLearningAgent:
    """Small tabular Q-learning agent.

    State layout: risk level x CPU bucket x memory bucket x accuracy bucket.
    The public API intentionally keeps compatibility with older tests and the
    current optimizer: 108 states and 9 actions.
    """

    BINS = [0.3, 0.7]
    N_BINS = 3

    def __init__(
        self,
        lr: float = 0.1,
        gamma: float = 0.9,
        epsilon: float = 0.1,
        learning_rate: float = None,
        epsilon_start: float = None,
        epsilon_min: float = 0.01,
        epsilon_decay: float = 0.995,
    ):
        self.lr = float(learning_rate if learning_rate is not None else lr)
        self.gamma = float(gamma)
        self.epsilon_init = float(epsilon_start if epsilon_start is not None else epsilon)
        self.epsilon = self.epsilon_init
        self.epsilon_min = float(epsilon_min)
        self.epsilon_decay = float(epsilon_decay)

        self.env = EncryptionEnv()
        self.n_actions = self.env.action_space.n
        self.n_states = 4 * self.N_BINS * self.N_BINS * self.N_BINS
        self.q_table = np.zeros((self.n_states, self.n_actions), dtype=np.float32)
        self._trained = False
        self._train_step = 0
        logger.info(
            "QLearningAgent initialized: Q-table=%dx%d (%.1fKB)",
            self.n_states,
            self.n_actions,
            self.q_table.nbytes / 1024,
        )

    def _bin_index(self, value: float, bins: List[float] = None) -> int:
        """Map a continuous value into a discrete bucket."""
        boundaries = bins if bins is not None else self.BINS
        for idx, boundary in enumerate(boundaries):
            if value <= boundary:
                return idx
        return len(boundaries)

    def discretize_state(self, state: np.ndarray) -> str:
        """Convert a 4D continuous state into a compact key."""
        risk_idx = int(np.clip(state[0], 0, 3))
        cpu_idx = self._bin_index(float(state[1]))
        mem_idx = self._bin_index(float(state[2]))
        acc_idx = self._bin_index(float(state[3]), [0.9, 0.96])
        return "%d_%d_%d_%d" % (risk_idx, cpu_idx, mem_idx, acc_idx)

    def _state_to_idx(self, state_key: str) -> int:
        risk, cpu, mem, acc = [int(x) for x in state_key.split("_")]
        return (risk * 27) + (cpu * 9) + (mem * 3) + acc

    def predict(self, state: np.ndarray, deterministic: bool = True) -> Tuple[int, float]:
        s_idx = self._state_to_idx(self.discretize_state(state))
        if not deterministic and random.random() < self.epsilon:
            action = random.randint(0, self.n_actions - 1)
        else:
            action = int(np.argmax(self.q_table[s_idx]))
        return action, float(self.q_table[s_idx, action])

    @staticmethod
    def _obs_from_reset(result):
        return result[0] if isinstance(result, tuple) else result

    @staticmethod
    def _step_parts(result):
        if len(result) == 5:
            obs, reward, terminated, truncated, info = result
            return obs, reward, bool(terminated or truncated), info
        obs, reward, done, info = result
        return obs, reward, bool(done), info

    def train(self, total_timesteps: int = 50000) -> List[float]:
        logger.info("Start Q-learning training: %d steps", total_timesteps)
        episode_rewards: List[float] = []
        total_reward = 0.0
        self.epsilon = self.epsilon_init

        obs = self._obs_from_reset(self.env.reset())
        s_idx = self._state_to_idx(self.discretize_state(obs))

        for step in range(total_timesteps):
            eps = max(self.epsilon_min, self.epsilon * self.epsilon_decay)
            self.epsilon = eps

            if random.random() < eps:
                action = self.env.action_space.sample()
            else:
                action = int(np.argmax(self.q_table[s_idx]))

            next_obs, reward, done, _ = self._step_parts(self.env.step(action))
            next_idx = self._state_to_idx(self.discretize_state(next_obs))

            best_next_q = float(np.max(self.q_table[next_idx]))
            current_q = float(self.q_table[s_idx, action])
            self.q_table[s_idx, action] = current_q + self.lr * (
                reward + self.gamma * best_next_q - current_q
            )

            total_reward += float(reward)
            self._train_step += 1
            s_idx = next_idx

            if done:
                episode_rewards.append(total_reward)
                obs = self._obs_from_reset(self.env.reset())
                s_idx = self._state_to_idx(self.discretize_state(obs))
                total_reward = 0.0

        if total_reward or not episode_rewards:
            episode_rewards.append(total_reward)
        self._trained = True
        logger.info("Q-learning training complete: %d episodes", len(episode_rewards))
        return episode_rewards

    def decode_action(self, action: int) -> Tuple[int, int]:
        return self.env._decode_action(action)

    def save(self, path: str) -> None:
        save_path = path + "_qtable.npz"
        np.savez_compressed(
            save_path,
            q_table=self.q_table,
            lr=self.lr,
            gamma=self.gamma,
            epsilon=self.epsilon,
            trained=self._trained,
        )
        logger.info("Q-table saved: %s (%d entries)", save_path, self.q_table.size)

    def load(self, path: str) -> bool:
        load_path = path + "_qtable.npz"
        try:
            data = np.load(load_path, allow_pickle=False)
            self.q_table = data["q_table"]
            self.lr = float(data["lr"])
            self.gamma = float(data["gamma"])
            self.epsilon = float(data["epsilon"])
            self._trained = bool(data["trained"])
            logger.info("Q-table loaded: %s", load_path)
            return True
        except Exception as exc:
            logger.warning("Failed to load Q-table %s: %s", load_path, exc)
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
            "min_q": float(np.min(self.q_table)),
            "epsilon": round(self.epsilon, 4),
            "trained": self._trained,
        }
