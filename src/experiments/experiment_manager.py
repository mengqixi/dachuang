# -*- coding: utf-8 -*-
"""历史运行记录中心 - SQLite 记录训练、联邦、攻击与优化任务。"""

import os
import json
import time
from typing import Dict, List, Any, Optional
from src.utils.data_storage import db


class ExperimentManager:
    """运行记录管理器 - 记录并追踪平台任务。"""

    def save_experiment(self, exp_type: str, name: str, params: Dict, result: Dict):
        """保存运行记录。"""
        try:
            conn = db._get_conn()
            conn.execute(
                "INSERT INTO model_training_history (model_type, dataset_name, accuracy, precision, recall, f1_score, epochs, samples, training_time) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                ("exp_%s" % exp_type, name,
                 result.get("accuracy", 0), result.get("precision", 0),
                 result.get("recall", 0), result.get("f1_score", 0),
                 params.get("epochs", 0), params.get("samples", 0),
                 result.get("training_time", 0))
            )
            conn.commit()
            conn.close()
            return True
        except Exception as e:
            return False

    def get_experiments(self, limit: int = 50) -> List[Dict]:
        """获取历史运行记录。"""
        from src.utils.data_storage import db
        try:
            conn = db._get_conn()
            rows = conn.execute(
                "SELECT * FROM model_training_history ORDER BY id DESC LIMIT ?", (limit,)
            ).fetchall()
            conn.close()
            return [dict(r) for r in rows]
        except Exception:
            return []

    def save_federated_round(self, node_name: str, round_num: int, metrics: Dict):
        """保存联邦训练轮次记录"""
        try:
            conn = db._get_conn()
            conn.execute(
                "INSERT INTO training_records (model_type, dataset_name, accuracy, epochs, samples) "
                "VALUES (?, ?, ?, ?, ?)",
                ("federated_%s" % node_name, "fed_round_%d" % round_num,
                 metrics.get("accuracy", 0), round_num, metrics.get("samples", 0))
            )
            conn.commit()
            conn.close()
        except Exception:
            pass

    def get_federated_history(self) -> List[Dict]:
        """获取联邦训练历史"""
        from src.utils.data_storage import db
        try:
            conn = db._get_conn()
            rows = conn.execute(
                "SELECT * FROM training_records WHERE model_type LIKE 'federated_%' ORDER BY id DESC LIMIT 50"
            ).fetchall()
            conn.close()
            return [dict(r) for r in rows]
        except Exception:
            return []


exp_manager = ExperimentManager()
