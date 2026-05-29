"""SQLite数据存储层

提供系统状态、攻击记录、优化历史、数据集元数据的持久化存储。
自动清理7天前的历史数据。
"""

import os
import sqlite3
import threading
import time
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional

from loguru import logger

DB_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "data")
DB_PATH = os.path.join(DB_DIR, "system.db")


class DataStorage:
    """SQLite数据存储管理器

    管理四张表：system_status, attack_records, optimization_history, dataset_meta
    支持自动采集、查询和清理。
    """

    def __init__(self, db_path: str = DB_PATH):
        self.db_path = db_path
        self._lock = threading.Lock()
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        self._init_db()
        self._collect_count = 0
        logger.info("DataStorage初始化完成: %s", db_path)

    def _get_conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=10)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self):
        """初始化数据库表"""
        with self._lock:
            conn = self._get_conn()
            try:
                conn.executescript("""
                    CREATE TABLE IF NOT EXISTS system_status (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                        attack_risk REAL DEFAULT 0,
                        cpu_usage REAL DEFAULT 0,
                        memory_usage REAL DEFAULT 0,
                        key_length INTEGER DEFAULT 2048,
                        encryption_rounds INTEGER DEFAULT 10,
                        encryption_time REAL DEFAULT 0,
                        throughput REAL DEFAULT 0
                    );
                    CREATE INDEX IF NOT EXISTS idx_status_ts ON system_status(timestamp);

                    CREATE TABLE IF NOT EXISTS attack_records (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                        attack_type VARCHAR(50) DEFAULT '',
                        risk_level REAL DEFAULT 0,
                        source_ip VARCHAR(50) DEFAULT '',
                        is_detected BOOLEAN DEFAULT 1
                    );
                    CREATE INDEX IF NOT EXISTS idx_attack_ts ON attack_records(timestamp);

                    CREATE TABLE IF NOT EXISTS optimization_history (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                        old_key_length INTEGER DEFAULT 2048,
                        new_key_length INTEGER DEFAULT 2048,
                        old_rounds INTEGER DEFAULT 10,
                        new_rounds INTEGER DEFAULT 10,
                        reason VARCHAR(200) DEFAULT '',
                        efficiency_gain REAL DEFAULT 0
                    );
                    CREATE INDEX IF NOT EXISTS idx_opt_ts ON optimization_history(timestamp);

                    CREATE TABLE IF NOT EXISTS dataset_meta (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        name VARCHAR(100) DEFAULT '',
                        path VARCHAR(200) DEFAULT '',
                        record_count INTEGER DEFAULT 0,
                        columns TEXT DEFAULT '',
                        created_time DATETIME DEFAULT CURRENT_TIMESTAMP
                    );

                    CREATE TABLE IF NOT EXISTS system_config (
                        key TEXT PRIMARY KEY,
                        value TEXT DEFAULT ''
                    );

                    CREATE TABLE IF NOT EXISTS training_records (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                        model_type VARCHAR(50) DEFAULT '',
                        dataset_name VARCHAR(100) DEFAULT '',
                        accuracy REAL DEFAULT 0,
                        precision REAL DEFAULT 0,
                        recall REAL DEFAULT 0,
                        f1_score REAL DEFAULT 0,
                        epochs INTEGER DEFAULT 0,
                        samples INTEGER DEFAULT 0
                    );
                """)
                conn.commit()
            finally:
                conn.close()

    # ─── 系统状态采集 ───

    def save_system_status(self, data: Dict[str, Any]):
        """保存一条系统状态记录"""
        with self._lock:
            conn = self._get_conn()
            try:
                conn.execute(
                    "INSERT INTO system_status (attack_risk, cpu_usage, memory_usage, "
                    "key_length, encryption_rounds) VALUES (?, ?, ?, ?, ?)",
                    (data.get("attack_risk", 0), data.get("cpu_usage", 0),
                     data.get("memory_usage", 0), data.get("key_length", 2048),
                     data.get("encryption_rounds", 10))
                )
                conn.commit()
            finally:
                conn.close()

    def get_system_status(self, hours: int = 24) -> List[Dict]:
        """获取指定时间范围的系统状态"""
        with self._lock:
            conn = self._get_conn()
            try:
                since = (datetime.now() - timedelta(hours=hours)).strftime("%Y-%m-%d %H:%M:%S")
                rows = conn.execute(
                    "SELECT * FROM system_status WHERE timestamp >= ? ORDER BY timestamp",
                    (since,)
                ).fetchall()
                return [dict(r) for r in rows]
            finally:
                conn.close()

    def get_latest_status(self) -> Optional[Dict]:
        """获取最新一条系统状态"""
        with self._lock:
            conn = self._get_conn()
            try:
                row = conn.execute(
                    "SELECT * FROM system_status ORDER BY id DESC LIMIT 1"
                ).fetchone()
                return dict(row) if row else None
            finally:
                conn.close()

    # ─── 攻击记录 ───

    def save_attack_record(self, data: Dict[str, Any]):
        """保存一条攻击记录"""
        with self._lock:
            conn = self._get_conn()
            try:
                conn.execute(
                    "INSERT INTO attack_records (attack_type, risk_level, source_ip, is_detected) "
                    "VALUES (?, ?, ?, ?)",
                    (data.get("attack_type", ""), data.get("risk_level", 0),
                     data.get("source_ip", ""), data.get("is_detected", 1))
                )
                conn.commit()
            finally:
                conn.close()

    def get_attack_records(self, hours: int = 24) -> List[Dict]:
        """获取指定时间范围的攻击记录"""
        with self._lock:
            conn = self._get_conn()
            try:
                since = (datetime.now() - timedelta(hours=hours)).strftime("%Y-%m-%d %H:%M:%S")
                rows = conn.execute(
                    "SELECT * FROM attack_records WHERE timestamp >= ? ORDER BY timestamp DESC",
                    (since,)
                ).fetchall()
                return [dict(r) for r in rows]
            finally:
                conn.close()

    def get_attack_statistics(self, hours: int = 24) -> Dict[str, Any]:
        """获取攻击统计数据"""
        with self._lock:
            conn = self._get_conn()
            try:
                since = (datetime.now() - timedelta(hours=hours)).strftime("%Y-%m-%d %H:%M:%S")
                total = conn.execute(
                    "SELECT COUNT(*) as c FROM attack_records WHERE timestamp >= ?",
                    (since,)
                ).fetchone()["c"]
                detected = conn.execute(
                    "SELECT COUNT(*) as c FROM attack_records WHERE timestamp >= ? AND is_detected=1",
                    (since,)
                ).fetchone()["c"]
                return {"total": total, "detected": detected, "rate": (detected / total * 100) if total else 100}
            finally:
                conn.close()

    # ─── 优化历史 ───

    def save_optimization(self, data: Dict[str, Any]):
        """保存一条优化记录"""
        with self._lock:
            conn = self._get_conn()
            try:
                conn.execute(
                    "INSERT INTO optimization_history (old_key_length, new_key_length, "
                    "old_rounds, new_rounds, reason, efficiency_gain) VALUES (?, ?, ?, ?, ?, ?)",
                    (data.get("old_key_length", 2048), data.get("new_key_length", 2048),
                     data.get("old_rounds", 10), data.get("new_rounds", 10),
                     data.get("reason", ""), data.get("efficiency_gain", 0))
                )
                conn.commit()
            finally:
                conn.close()

    def get_optimization_history(self, hours: int = 24) -> List[Dict]:
        """获取指定时间范围的优化历史"""
        with self._lock:
            conn = self._get_conn()
            try:
                since = (datetime.now() - timedelta(hours=hours)).strftime("%Y-%m-%d %H:%M:%S")
                rows = conn.execute(
                    "SELECT * FROM optimization_history WHERE timestamp >= ? ORDER BY timestamp DESC",
                    (since,)
                ).fetchall()
                return [dict(r) for r in rows]
            finally:
                conn.close()

    # ─── 数据集元数据 ───

    def save_dataset_meta(self, name: str, path: str, record_count: int, columns: str):
        """保存数据集元数据"""
        with self._lock:
            conn = self._get_conn()
            try:
                conn.execute(
                    "INSERT INTO dataset_meta (name, path, record_count, columns) VALUES (?, ?, ?, ?)",
                    (name, path, record_count, columns)
                )
                conn.commit()
            finally:
                conn.close()

    def list_datasets(self) -> List[Dict]:
        """列出所有数据集"""
        with self._lock:
            conn = self._get_conn()
            try:
                rows = conn.execute(
                    "SELECT * FROM dataset_meta ORDER BY id DESC"
                ).fetchall()
                return [dict(r) for r in rows]
            finally:
                conn.close()

    def delete_dataset(self, ds_id: int) -> bool:
        """删除数据集"""
        with self._lock:
            conn = self._get_conn()
            try:
                conn.execute("DELETE FROM dataset_meta WHERE id=?", (ds_id,))
                conn.commit()
                return True
            except Exception:
                return False
            finally:
                conn.close()

    # ─── 训练记录 ───

    def save_training_record(self, data: Dict[str, Any]):
        """保存训练记录"""
        with self._lock:
            conn = self._get_conn()
            try:
                conn.execute(
                    "INSERT INTO training_records (model_type, dataset_name, accuracy, precision, recall, f1_score, epochs, samples) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                    (data.get("model_type", ""), data.get("dataset_name", ""),
                     data.get("accuracy", 0), data.get("precision", 0),
                     data.get("recall", 0), data.get("f1_score", 0),
                     data.get("epochs", 0), data.get("samples", 0))
                )
                conn.commit()
            finally:
                conn.close()

    def get_training_records(self, limit: int = 20) -> List[Dict]:
        """获取最近的训练记录"""
        with self._lock:
            conn = self._get_conn()
            try:
                rows = conn.execute(
                    "SELECT * FROM training_records ORDER BY id DESC LIMIT ?", (limit,)
                ).fetchall()
                return [dict(r) for r in rows]
            finally:
                conn.close()

    # ─── 系统配置 ───

    def get_config(self, key: str, default: str = "") -> str:
        """获取系统配置"""
        with self._lock:
            conn = self._get_conn()
            try:
                row = conn.execute("SELECT value FROM system_config WHERE key=?", (key,)).fetchone()
                return row["value"] if row else default
            finally:
                conn.close()

    def set_config(self, key: str, value: str):
        """设置系统配置"""
        with self._lock:
            conn = self._get_conn()
            try:
                conn.execute(
                    "INSERT OR REPLACE INTO system_config (key, value) VALUES (?, ?)",
                    (key, value)
                )
                conn.commit()
            finally:
                conn.close()

    # ─── 数据采集器（后台线程） ───

    def _collector_thread(self, interval: float = 10.0):
        """后台采集线程：每10秒采集并存储系统状态"""
        while True:
            try:
                # 从当前全局状态获取数据（通过回调）
                if hasattr(self, "_status_callback") and self._status_callback:
                    data = self._status_callback()
                    if data:
                        self.save_system_status(data)
                        self._collect_count += 1

                        # 每循环100次清理一次旧数据
                        if self._collect_count % 100 == 0:
                            self._cleanup_old_data()
            except Exception:
                pass
            time.sleep(interval)

    def start_collector(self, status_callback, interval: float = 1.0):
        """启动后台数据采集器

        Args:
            status_callback: 返回系统状态字典的回调函数
            interval: 采集间隔（秒）
        """
        self._status_callback = status_callback
        import threading
        t = threading.Thread(target=self._collector_thread, args=(interval,), daemon=True)
        t.start()
        logger.info("数据采集器已启动: interval=%.1fs", interval)

    def _cleanup_old_data(self, days: int = 180):
        """清理180天前的历史数据"""
        try:
            cutoff = (datetime.now() - timedelta(days=days)).strftime("%Y-%m-%d %H:%M:%S")
            conn = self._get_conn()
            try:
                for table in ["system_status", "attack_records", "optimization_history"]:
                    conn.execute("DELETE FROM %s WHERE timestamp < ?" % table, (cutoff,))
                conn.commit()
            finally:
                conn.close()
        except Exception as e:
            logger.warning("清理旧数据失败: %s", e)

    def get_statistics(self) -> Dict[str, Any]:
        """获取综合统计数据"""
        stats = self.get_attack_statistics(24)
        opt_history = self.get_optimization_history(24)
        latest = self.get_latest_status()
        total_gain = sum(o.get("efficiency_gain", 0) for o in opt_history)

        return {
            "total_attacks": stats["total"],
            "detection_rate": round(stats["rate"], 1),
            "total_gain": round(total_gain, 2),
            "current_kv": {
                "key_length": latest["key_length"] if latest else 2048,
                "rounds": latest["encryption_rounds"] if latest else 10,
                "attack_risk": latest["attack_risk"] if latest else 0,
            } if latest else {"key_length": 2048, "rounds": 10, "attack_risk": 0},
            "latest_status": latest,
        }


# 全局单例
db = DataStorage()
